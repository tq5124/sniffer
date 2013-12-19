using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Collections;
using SharpPcap;
using System.Threading;

namespace Sniffer
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            combox1_Ini();
            this.filter_btn_apply.Enabled = false;
        }
        
        //抓包线程
        private delegate void setDataGridViewDelegate(packet Packet,int index);
        private delegate bool filterCheckDelegate(packet Packet);

        private LivePcapDevice device;
        private int readTimeoutMilliseconds;
        private string filter;
        //抓到的所有包的所有信息
        private ArrayList packets;

        private void button1_Click(object sender, EventArgs e)
        {
            //清除之前的数据
            this.packets = new ArrayList();
            this.dataGridView1.Rows.Clear();
            //读取要监听的网卡
            int eth = System.Int32.Parse(this.comboBox1.SelectedValue.ToString());
            var devices = LivePcapDeviceList.Instance;
            this.device = devices[eth];

            this.readTimeoutMilliseconds = 1000;
            this.filter = "";
            //this.filter = "ip and tcp";

            Thread newThread = new Thread(new ThreadStart(threadHandler));
            newThread.Start();
        }

        /// <summary>
        /// 关闭程序
        /// </summary>
        private void button7_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        /// <summary>
        /// 初始化下拉菜单
        /// </summary>
        private void combox1_Ini()
        {
            //初始化下拉菜单的候选值
            ArrayList cboItems1 = new ArrayList();

            var devices = LivePcapDeviceList.Instance;
            if (devices.Count < 1)
            {
                cboItems1.Add(new KeyValuePair<int, string>(-1, "找不到网络设备"));
            }
            else
            {
                int i = 0;
                foreach (LivePcapDevice dev in devices)
                {
                    cboItems1.Add(new KeyValuePair<int, string>(i, dev.Interface.FriendlyName));
                    i++;
                }
            }

            //初始化Combox.Items 
            comboBox1.ValueMember = "Key";
            comboBox1.DisplayMember = "Value";
            comboBox1.DataSource = cboItems1;
        }

        /// <summary>
        /// 抓包线程
        /// </summary>
        private void threadHandler()
        {
            this.device.Open(DeviceMode.Promiscuous, this.readTimeoutMilliseconds);
            this.device.SetFilter(this.filter);
            this.device.Mode = CaptureMode.Packets; //抓数据包
            this.device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival); //抓数据包回调事件
            //开始监听
            this.device.StartCapture();
        }

        /// <summary>
        /// 抓包方法
        /// </summary>
        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            PcapPorcessContext(e.Packet);
        }
        private void PcapPorcessContext(PacketDotNet.RawPacket pPacket)
        {
            packet temp = new packet(pPacket);
            packets.Add(temp);

            if (this.dataGridView1.InvokeRequired)
            {
                //if (temp.ip_info.Count > 0 && temp.ip_info["Version(版本)"] == "IPv6" && temp.tcp_info.Count > 0)
                //if (temp.ip_info.Count > 0 && temp.ip_info["Version(版本)"] == "IPv4" && temp.ip_info["Protocol(协议)"] == "IGMP")
                filterCheckDelegate filterDelegate = filter_check;
                IAsyncResult asyncResult = filterDelegate.BeginInvoke(temp, null, null);
                bool flag = filterDelegate.EndInvoke(asyncResult);
                if (flag)
                {
                    this.dataGridView1.BeginInvoke(new setDataGridViewDelegate(setDataGridView), new object[] { temp, packets.Count - 1 });
                }
            }
            else
            {
                int index = this.dataGridView1.Rows.Add();
                this.dataGridView1.Rows[index].DefaultCellStyle.BackColor = Color.FromName(temp.color);
                this.dataGridView1.Rows[index].Cells[0].Value = temp.time;
                this.dataGridView1.Rows[index].Cells[1].Value = temp.srcIp;
                this.dataGridView1.Rows[index].Cells[2].Value = temp.destIp;
                this.dataGridView1.Rows[index].Cells[3].Value = temp.protocol;
                this.dataGridView1.Rows[index].Cells[4].Value = temp.info;
                this.dataGridView1.Rows[index].Cells[5].Value = packets.Count - 1;

                this.dataGridView1.FirstDisplayedScrollingRowIndex = this.dataGridView1.Rows.Count - 1;
            }
        }
        /// <summary>
        /// 抓包后更新UI显示
        /// </summary>
        private void setDataGridView(packet Packet,int packet_index)  //当跨线程调用时，调用该方法进行UI界面更新
        {
            int index = this.dataGridView1.Rows.Add();
            this.dataGridView1.Rows[index].DefaultCellStyle.BackColor = Color.FromName(Packet.color);

            this.dataGridView1.Rows[index].Cells[0].Value = Packet.time;
            this.dataGridView1.Rows[index].Cells[1].Value = Packet.srcIp;
            this.dataGridView1.Rows[index].Cells[2].Value = Packet.destIp;
            this.dataGridView1.Rows[index].Cells[3].Value = Packet.protocol;
            this.dataGridView1.Rows[index].Cells[4].Value = Packet.info;
            this.dataGridView1.Rows[index].Cells[5].Value = packet_index;

            this.dataGridView1.FirstDisplayedScrollingRowIndex = this.dataGridView1.Rows.Count - 1;
        }

        /// <summary>
        /// 停止抓包
        /// </summary>
        private void button2_Click(object sender, EventArgs e)
        {
            this.device.StopCapture();
        }

        private void dataGridView_row_click(object sender, EventArgs e)
        {
            int index = int.Parse(this.dataGridView1.CurrentRow.Cells[5].Value.ToString());
            packet Packet = (packet)this.packets[index];

            // 保存tree中的选中节点信息
            string selected_path = "";
            if (this.treeView1.SelectedNode != null)
            {
                selected_path = this.treeView1.SelectedNode.FullPath;
                selected_path = selected_path.Substring(0, selected_path.LastIndexOf(" :"));
            }

            // 清空display页面的内容
            this.display_title.Text = "";
            this.display_text.Text = "";
            
            this.treeView1.Nodes.Clear();

            //物理层
            if (Packet.frame_info.Count > 0)
            {
                TreeNode frame_info = new TreeNode("Frame : ");
                foreach (KeyValuePair<string, string> item in Packet.frame_info)
                {
                    frame_info.Nodes.Add(item.Key + " : " + item.Value);
                }
                this.treeView1.Nodes.Add(frame_info);
            }
            //数据链路层
            //以太网层
            if (Packet.ethernet_info.Count > 0)
            {
                TreeNode ethernet_info = new TreeNode("Ethernet : ");
                foreach (KeyValuePair<string, string> item in Packet.ethernet_info)
                {
                    ethernet_info.Nodes.Add(item.Key + " : " + item.Value);
                }
                this.treeView1.Nodes.Add(ethernet_info);
            }
            //网络层
            //IP包
            if (Packet.ip_info.Count > 0)
            {
                TreeNode ip_info = new TreeNode("IP : ");
                foreach (KeyValuePair<string, string> item in Packet.ip_info)
                {
                    ip_info.Nodes.Add(item.Key + " : " + item.Value);
                }
                this.treeView1.Nodes.Add(ip_info);
            }
            //ARP包
            if (Packet.arp_info.Count > 0)
            {
                TreeNode arp_info = new TreeNode("ARP : ");
                foreach (KeyValuePair<string, string> item in Packet.arp_info)
                {
                    arp_info.Nodes.Add(item.Key + " : " + item.Value);
                }
                this.treeView1.Nodes.Add(arp_info);
            }
            //传输层
            //ICMP包
            if (Packet.icmp_info.Count > 0)
            {
                TreeNode icmp_info = new TreeNode("ICMP : ");
                foreach (KeyValuePair<string, string> item in Packet.icmp_info)
                {
                    icmp_info.Nodes.Add(item.Key + " : " + item.Value);
                }
                this.treeView1.Nodes.Add(icmp_info);
            }
            //IGMP包
            if (Packet.igmp_info.Count > 0)
            {
                TreeNode igmp_info = new TreeNode("IGMP : ");
                foreach (KeyValuePair<string, string> item in Packet.igmp_info)
                {
                    igmp_info.Nodes.Add(item.Key + " : " + item.Value);
                }
                this.treeView1.Nodes.Add(igmp_info);
            } 
            //TCP包
            if (Packet.tcp_info.Count > 0)
            {
                TreeNode tcp_info = new TreeNode("TCP : ");
                foreach (KeyValuePair<string, string> item in Packet.tcp_info)
                {
                    tcp_info.Nodes.Add(item.Key + " : " + item.Value);
                }
                this.treeView1.Nodes.Add(tcp_info);
            }
            //UDP包
            if (Packet.udp_info.Count > 0)
            {
                TreeNode udp_info = new TreeNode("UDP : ");
                foreach (KeyValuePair<string, string> item in Packet.udp_info)
                {
                    udp_info.Nodes.Add(item.Key + " : " + item.Value);
                }
                this.treeView1.Nodes.Add(udp_info);
            }
            //应用层包
            if (Packet.application_info.Count > 0)
            {
                TreeNode application_info = new TreeNode(Packet.application_info["ApplicationType"] + " : ");
                foreach (KeyValuePair<string, string> item in Packet.application_info)
                {
                    if (item.Key != "ApplicationType")
                    {
                        application_info.Nodes.Add(item.Key + " : " + item.Value);
                    }
                }
                this.treeView1.Nodes.Add(application_info);

                // 将应用层数据交给display控件
                display_data(Packet);
            }

            // 选中之前的某个node节点
            if (selected_path != "")
            {
                Console.Write(selected_path);
                foreach (TreeNode node in this.treeView1.Nodes)
                {
                    TreeNode item = FindNode(node, selected_path);
                    if (item != null)
                    {
                        this.treeView1.SelectedNode = item;
                        this.treeView1.Focus();
                        break;
                    }
                }
            }
        }

        // 在page页中显示application数据
        private void display_data(packet Packet){
            this.display_title.Text = Packet.application_info["ApplicationType"] + "包";
            this.display_text.Text = Packet.application_info["All"];
            
        }

        // 递归遍历treeview的所有节点
        private TreeNode FindNode(TreeNode tnParent, string strValue)
        {
            if (tnParent == null) return null;
            string item_path = tnParent.FullPath.Substring(0, tnParent.FullPath.LastIndexOf(" :"));
            if (item_path == strValue) return tnParent;
            Console.Write(item_path + '\n');
            TreeNode tnRet = null;
            foreach (TreeNode tn in tnParent.Nodes)
            {
                tnRet = FindNode(tn, strValue);
                if (tnRet != null) break;
            }
            return tnRet;
        }

        // 过滤规则的tab页
        private void filter_btn_clear_Click(object sender, EventArgs e)
        {
            this.filter_rule.Rows.Clear();
            int count = this.packets.Count;
            for (int index = 0; index < count; index++)
            {
                packet temp = (packet)this.packets[index];
                this.dataGridView1.BeginInvoke(new setDataGridViewDelegate(setDataGridView), new object[] { temp, packets.Count - 1 });
            }
        }

        private void filter_btn_apply_Click(object sender, EventArgs e)
        {
            // 向列表中添加行
            string key = this.filter_key.Text;
            string oper = this.filter_oper.Text;
            string value = this.filter_value.Text.ToUpper();
            this.filter_key.Text = "";
            this.filter_oper.Text = "";
            this.filter_value.Text = "";
            int index = this.filter_rule.Rows.Add();
            this.filter_rule.Rows[index].Cells[0].Value = key;
            this.filter_rule.Rows[index].Cells[1].Value = oper;
            this.filter_rule.Rows[index].Cells[2].Value = value;

            // 刷新包列表
            this.dataGridView1.Rows.Clear();
            if (this.packets == null)
                return;
            int count = this.packets.Count;
            for (index = 0; index < count; index++)
            {
                packet temp = (packet)this.packets[index];
                filterCheckDelegate filterDelegate = filter_check;
                IAsyncResult asyncResult = filterDelegate.BeginInvoke(temp, null, null);
                bool flag = filterDelegate.EndInvoke(asyncResult);
                if (flag)
                {
                    this.dataGridView1.BeginInvoke(new setDataGridViewDelegate(setDataGridView), new object[] { temp, index });
                }

            }
        }

        private bool filter_check(packet Packet)
        {
            bool flag = true;
            DataGridViewRowCollection rules = this.filter_rule.Rows;
            foreach (DataGridViewRow item in rules){
                string key = (string)(item.Cells[0].Value);
                string oper = (string)(item.Cells[1].Value);
                string value = (string)(item.Cells[2].Value);
                flag = flag & _filter_check(Packet, key, oper, value);
            }
            return flag;
        }

        private bool _filter_check(packet Packet, string key, string oper, string value)
        {   
            // 取出packet中对应key的value，string形式
            List<string> pac_value = new List<string>();
            switch (key)
            {
                case "ip_addr":
                    pac_value.Add(Packet.destIp);
                    pac_value.Add(Packet.srcIp);
                    break;
                case "port":
                    if (Packet.tcp_info.Count > 0)
                    {
                        pac_value.Add(Packet.tcp_info["SourcePort(源端口)"]);
                        pac_value.Add(Packet.tcp_info["DestinationPort(目的端口)"]);
                    }
                    if (Packet.udp_info.Count > 0)
                    {
                        pac_value.Add(Packet.udp_info["SourcePort(源端口)"]);
                        pac_value.Add(Packet.udp_info["DestinationPort(目的端口)"]);
                    }
                    break;
                case "ip_version":
                    if (Packet.ip_info.Count > 0)
                        pac_value.Add(Packet.ip_info["Version(版本)"]);
                    break;
                case "protocol":
                    if (Packet.ip_info.Count > 0)
                        pac_value.Add("IP");
                    if (Packet.tcp_info.Count > 0)
                        pac_value.Add("TCP");
                    if (Packet.udp_info.Count > 0)
                        pac_value.Add("UDP");
                    if (Packet.icmp_info.Count > 0)
                        pac_value.Add("ICMP");
                    if (Packet.igmp_info.Count > 0)
                        pac_value.Add("IGMP");
                    if (Packet.arp_info.Count > 0)
                        pac_value.Add("ARP");
                    if (Packet.application_info.Count > 0)
                        pac_value.Add(Packet.application_info["ApplicationType"]);
                    break;
                case "DF":
                    if (Packet.ip_info.Count > 0 && Packet.ip_info["Version(版本)"] == "IPV4")
                    {
                        pac_value.Add(Packet.ip_info["DF"]);
                    }
                    break;
                case "MF":
                    if (Packet.ip_info.Count > 0 && Packet.ip_info["Version(版本)"] == "IPV4")
                    {
                        pac_value.Add(Packet.ip_info["MF"]);
                    }
                    break;
                case "application_data":
                    if (Packet.application_info.Count > 0)
                        pac_value.Add(Packet.application_info["Data"]);
                    break;
                default:
                    break;
            }

            switch (oper)
            {
                case "==":
                    if (include_array(pac_value, value))
                    {
                        return true;
                    }
                    break;
                case "!=":
                    if (!include_array(pac_value, value))
                    {
                        return true;
                    }
                    break;
                case "包含":
                    if (include_array_like(pac_value, value))
                        return true;
                    break;
                default:
                    return true;
            }
            return false;
        }

        private bool include_array_like(List<string> arr, string find)
        {
            foreach (string i in arr)
            {
                if (i.IndexOf(find) > 0)
                    return true;
            }
            return false;
        }

        private bool include_array(List<string> arr, string find)
        {
            foreach (string i in arr){
                if (i == find)
                {
                    return true;
                }
            }
            return false;
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            CheckForIllegalCrossThreadCalls = false;
        }

        private void filter_value_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == Convert.ToChar(13) && this.filter_btn_apply.Enabled == true)
                filter_btn_apply_Click(null, null);
        }

        private void filter_key_SelectedIndexChanged(object sender, EventArgs e)
        {
            check_filter_input();
        }

        private void check_filter_input()
        {
            if (this.filter_key.Text == "" || this.filter_oper.Text == "")
                this.filter_btn_apply.Enabled = false;
            else
                this.filter_btn_apply.Enabled = true;
        }

        private void filter_oper_SelectedIndexChanged(object sender, EventArgs e)
        {
            check_filter_input();
        }

        private void check_closing(object sender, FormClosingEventArgs e)
        {
            if (MessageBox.Show("你确认要退出该程序吗？", "提示", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) == DialogResult.No)
            {
                e.Cancel = true;
            }
            else
            {
                this.device.StopCapture();
            }
        }

    }
}
