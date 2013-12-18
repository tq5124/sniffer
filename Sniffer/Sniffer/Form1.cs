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
            this.display_text.Text = Packet.application_info["Data"];
            
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
                    {
                        pac_value.Add("TCP");
                        pac_value.Add("HTTP");
                    }
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



    public class packet
    {
        public string time;
        public string srcIp;
        public string destIp;
        public string protocol;
        public string info;
        public string color;

        public PacketDotNet.LinkLayers layer;
        public PacketDotNet.Packet rPacket;

        public Dictionary<string, string> frame_info;
        public Dictionary<string, string> ethernet_info;

        public Dictionary<string,string> ip_info;
        public Dictionary<string, string> arp_info;

        public Dictionary<string, string> icmp_info;
        public Dictionary<string, string> igmp_info;
        public Dictionary<string, string> tcp_info;
        public Dictionary<string, string> udp_info;

        public Dictionary<string, string> application_info;

        public packet(PacketDotNet.RawPacket pPacket)
        {
            var timestamp = pPacket.Timeval.Date;
            this.layer = pPacket.LinkLayerType;
            this.time = timestamp.Hour.ToString() + ":" + timestamp.Minute.ToString() + ":" + timestamp.Second.ToString() + "," + timestamp.Millisecond.ToString();
            this.srcIp = "";
            this.destIp = "";
            this.protocol = "";
            this.info = "";
            this.color = "White";

            this.rPacket = PacketDotNet.Packet.ParsePacket(pPacket);

            this.frame_info = new Dictionary<string, string>();
            this.ethernet_info = new Dictionary<string, string>();

            this.ip_info = new Dictionary<string, string>();
            this.arp_info = new Dictionary<string, string>();

            this.icmp_info = new Dictionary<string, string>();
            this.igmp_info = new Dictionary<string, string>();
            this.tcp_info = new Dictionary<string, string>();
            this.udp_info = new Dictionary<string, string>();

            this.application_info = new Dictionary<string, string>();

            analysis_packet();
        }

        public void analysis_packet() 
        {
            //物理层信息
            this.frame_info.Add("Frame",this.rPacket.Bytes.Length.ToString() + " bytes");
            if (this.layer == PacketDotNet.LinkLayers.Ethernet) //以太网包
            {
                //以太网包解析
                var ethernetPacket = (PacketDotNet.EthernetPacket)this.rPacket;
                this.ethernet_info.Add("srcMac(MAC源地址)", ethernetPacket.SourceHwAddress.ToString());
                this.ethernet_info.Add("destMac(MAC目标地址)", ethernetPacket.DestinationHwAddress.ToString());
                this.ethernet_info.Add("Type(以太类型)", ethernetPacket.Type.ToString().ToUpper());


                //简易信息
                this.srcIp = ethernetPacket.SourceHwAddress.ToString();
                this.destIp = ethernetPacket.DestinationHwAddress.ToString();
                this.protocol = ethernetPacket.Type.ToString().ToUpper();
                //ICMPv6存在bug
                if (ethernetPacket.Type.ToString() != "IpV6")
                {
                    this.info = ethernetPacket.ToString();
                }
                if (ethernetPacket.Type.ToString() == "IpV4" || ethernetPacket.Type.ToString() == "IpV6")
                {
                    //IP包解析
                    var ipPacket = PacketDotNet.IpPacket.GetEncapsulated(this.rPacket);
                    if (ipPacket != null)
                    {
                        //IpV4
                        if (ipPacket.Version.ToString() == "IPv4")
                        {
                            ipPacket = PacketDotNet.IPv4Packet.GetEncapsulated(this.rPacket);
                            this.ip_info.Add("Version(版本)", ipPacket.Version.ToString().ToUpper());
                            this.ip_info.Add("Header Length(头长度)", (ipPacket.HeaderLength * 4).ToString());
                            this.ip_info.Add("Differentiated Services Field(区分服务)", "0x" + Convert.ToString(ipPacket.Bytes[1], 16).ToUpper().PadLeft(2, '0'));
                            this.ip_info.Add("Total Length(总长度)", ipPacket.TotalLength.ToString());
                            this.ip_info.Add("Identification(标识)", "0x" + Convert.ToString(ipPacket.Bytes[4], 16).ToUpper().PadLeft(2, '0') + Convert.ToString(ipPacket.Bytes[5], 16).ToUpper().PadLeft(2, '0'));
                            this.ip_info.Add("DF", ((ipPacket.Bytes[6] & 64) >> 6).ToString());
                            this.ip_info.Add("MF", ((ipPacket.Bytes[6] & 32) >> 5).ToString());
                            //分段偏移量,待测试检验
                            this.ip_info.Add("Fragment offset(分段偏移量)", ((Convert.ToInt32(ipPacket.Bytes[6] & 31) << 8) + Convert.ToInt32(ipPacket.Bytes[7])).ToString());
                            //
                            this.ip_info.Add("Time to live(生存期)", ipPacket.TimeToLive.ToString());
                            this.ip_info.Add("Protocol(协议)", ipPacket.Protocol.ToString().ToUpper());
                            this.ip_info.Add("Header checksum(头部校验和)", "0x" + Convert.ToString(ipPacket.Bytes[10], 16).ToUpper().PadLeft(2, '0') + Convert.ToString(ipPacket.Bytes[11], 16).ToUpper().PadLeft(2, '0'));
                            this.ip_info.Add("Source(源地址)", ipPacket.SourceAddress.ToString());
                            this.ip_info.Add("Destination(目的地址)", ipPacket.DestinationAddress.ToString());
                            this.ip_info.Add("Options(可选)", "to be continued");

                            //简易信息
                            this.srcIp = ipPacket.SourceAddress.ToString();
                            this.destIp = ipPacket.DestinationAddress.ToString();
                            this.protocol = ipPacket.Protocol.ToString().ToUpper();
                            this.info = ipPacket.ToString();

                            //ICMP包解析
                            if (ipPacket.Protocol.ToString() == "ICMP")
                            {
                                var icmpPacket = PacketDotNet.ICMPv4Packet.GetEncapsulated(this.rPacket);
                                this.icmp_info.Add("TypeCode(类型)",icmpPacket.TypeCode.ToString());
                                this.icmp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(icmpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.icmp_info.Add("Identifier(标识符)", icmpPacket.ID.ToString());
                                this.icmp_info.Add("Sequence(序列号)", icmpPacket.Sequence.ToString());
                                
                                //颜色
                                this.color = "Pink";
                                //简易信息
                                this.info = icmp_info["TypeCode(类型)"] + " id=" + icmp_info["Identifier(标识符)"] + ", seq=" + icmp_info["Sequence(序列号)"] + ", ttl=" + ip_info["Time to live(生存期)"]; 
                            }

                            //IGMP包解析,待完成
                            else if (ipPacket.Protocol.ToString() == "IGMP")
                            {
                                //var igmpPacket = PacketDotNet.IGMPv2Packet.ParsePacket(this.rPacket);
                                var igmpData = ipPacket.PayloadData;
                                /*
                                this.igmp_info.Add("Type(类型)",igmpPacket.Type.ToString());
                                this.igmp_info.Add("MaxResponseTime(最大响应时间)", igmpPacket.MaxResponseTime.ToString());
                                this.igmp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(igmpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.igmp_info.Add("GroupAddress(组地址)", igmpPacket.GroupAddress.ToString());
                                
                                */
                                this.igmp_info.Add("Type(类型)", "0x" + Convert.ToString(igmpData[0], 16).ToUpper().PadLeft(2, '0'));
                                this.igmp_info.Add("MaxResponseTime(最大响应时间)", "0x" + Convert.ToString(igmpData[1], 16).ToUpper().PadLeft(2, '0'));
                                this.igmp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(igmpData[2], 16).ToUpper().PadLeft(2, '0') + Convert.ToString(igmpData[3], 16).ToUpper().PadLeft(2, '0'));
                                this.igmp_info.Add("GroupAddress(组地址)", Convert.ToString(igmpData[4], 10) + "." + Convert.ToString(igmpData[5], 10).ToUpper() + "." + Convert.ToString(igmpData[6], 10).ToUpper() + "." + Convert.ToString(igmpData[7], 10).ToUpper().PadLeft(2, '0'));
                                //简易信息
                                this.info = this.igmp_info["Type(类型)"] + " " + this.igmp_info["GroupAddress(组地址)"];
                            }
                            
                            //

                            //TCP包解析
                            else if (ipPacket.Protocol.ToString() == "TCP")
                            {
                                var tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(this.rPacket);
                                this.tcp_info.Add("SourcePort(源端口)", tcpPacket.SourcePort.ToString());
                                this.tcp_info.Add("DestinationPort(目的端口)", tcpPacket.DestinationPort.ToString());
                                //与wireshark不符，应该是wireshark特有的relative功能，待确认
                                this.tcp_info.Add("SequenceNumber(序号)", tcpPacket.SequenceNumber.ToString());
                                //
                                this.tcp_info.Add("AcknowledgmentNumber(确认序号)",tcpPacket.AcknowledgmentNumber.ToString());
                                this.tcp_info.Add("DataOffset(数据偏移)", tcpPacket.DataOffset.ToString());
                                this.tcp_info.Add("URG",tcpPacket.Urg.ToString());
                                this.tcp_info.Add("ACK", tcpPacket.Ack.ToString());
                                this.tcp_info.Add("PSH", tcpPacket.Psh.ToString());
                                this.tcp_info.Add("RST", tcpPacket.Rst.ToString());
                                this.tcp_info.Add("SYN", tcpPacket.Syn.ToString());
                                this.tcp_info.Add("FIN", tcpPacket.Fin.ToString());
                                this.tcp_info.Add("WindowSize(窗口)", ((UInt16)tcpPacket.WindowSize).ToString());
                                this.tcp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(tcpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.tcp_info.Add("UrgentPointer(紧急指针)", tcpPacket.UrgentPointer.ToString());
                                this.tcp_info.Add("Option(可选部分)", "to be continued");

                                //颜色
                                this.color = "YellowGreen";
                                //简易信息
                                this.info = tcp_info["SourcePort(源端口)"] + " → " + tcp_info["DestinationPort(目的端口)"] + ((tcp_info["SYN"] == "True") ? " [SYN] " : "") + ((tcp_info["ACK"] == "True") ? " [ACK] " : "") + "Seq=" + tcp_info["SequenceNumber(序号)"] + " Ack=" + tcp_info["AcknowledgmentNumber(确认序号)"] + " Win=" + tcp_info["WindowSize(窗口)"];

                                //判断具体应用层
                                //TELNET待完善中文乱码
                                if (tcp_info["SourcePort(源端口)"] == "23")
                                {
                                    this.protocol = "TELNET";
                                    this.color = "Blue";
                                    this.info = "Telnet Data ...";

                                    this.application_info.Add("ApplicationType","TELNET");

                                    var telnetData = tcpPacket.PayloadData;
                                    //将接收到的数据转个码,顺便转成string型
                                    string sRecieved = Encoding.GetEncoding("utf-8").GetString(telnetData, 0, telnetData.Length);
                                    //声明一个字符串,用来存储解析过的字符串
                                    string m_strLine = "";
                                    //遍历接收到的字符
                                    for (int i = 0; i < telnetData.Length; i++)
                                    {
                                        Char ch = Convert.ToChar(telnetData[i]);
                                        switch (ch)
                                        {
                                            case '\r':
                                                m_strLine += Convert.ToString("\r\n");
                                                break;
                                            case '\n':
                                                break;
                                            default:
                                                m_strLine += Convert.ToString(ch);
                                                break;

                                        }
                                    }
                                    this.application_info.Add("Data",m_strLine);
                                }
                                //HTTP，待完善，存在很多空包及乱码问题
                                else if (tcp_info["SourcePort(源端口)"] == "80")
                                {
                                    this.protocol = "HTTP";
                                    this.color = "YellowGreen";
                                    //this.info = "HTTP to be continued OK";

                                    this.application_info.Add("ApplicationType", "HTTP");

                                    var httpData = tcpPacket.PayloadData;
                                    string headertext = "";
                                    string ssHeader = System.Text.Encoding.Default.GetString(httpData);
                                    if (ssHeader.IndexOf("\r\n\r\n") > 0)
                                    {
                                        headertext = ssHeader.Substring(0, ssHeader.IndexOf("\r\n\r\n"));
                                    }

                                    this.application_info.Add("Data", headertext);
                                    if (headertext.Length > 0 && headertext.IndexOf('\n') > 0 && headertext.IndexOf("HTTP") >= 0)
                                    {
                                        this.info = headertext.Substring(0, headertext.IndexOf('\n'));
                                    }
                                    else 
                                    {
                                        this.info = "Continuation or non-HTTP traffic";
                                    }
                                }
                            }
                            else if (ipPacket.Protocol.ToString() == "UDP")
                            { 
                                var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(this.rPacket);
                                this.udp_info.Add("SourcePort(源端口)", udpPacket.SourcePort.ToString());
                                this.udp_info.Add("DestinationPort(目的端口)", udpPacket.DestinationPort.ToString());
                                this.udp_info.Add("Length(报文长度)",udpPacket.Length.ToString());
                                this.udp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(udpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));

                                //颜色
                                this.color = "SkyBlue";
                                //简易信息
                                this.info = "Source port: " + udp_info["SourcePort(源端口)"] + "  Destination port: " + udp_info["DestinationPort(目的端口)"];
                            }
                        }
                        //IpV6
                        else if (ipPacket.Version.ToString() == "IPv6")
                        {
                            ipPacket = PacketDotNet.IPv6Packet.GetEncapsulated(this.rPacket);
                            this.ip_info.Add("Version(版本)", ipPacket.Version.ToString().ToUpper());
                            this.ip_info.Add("Traffic Class(通信类别)", "0x" + Convert.ToString(ipPacket.Bytes[0] & 15, 16).ToUpper().PadLeft(1, '0') + Convert.ToString((ipPacket.Bytes[1] & 240) >> 4, 16).ToUpper().PadLeft(1, '0'));
                            this.ip_info.Add("Flow Label(流标记)", "0x" + Convert.ToString(ipPacket.Bytes[1] & 15, 16).ToUpper().PadLeft(1, '0') + Convert.ToString(ipPacket.Bytes[2], 16).ToUpper().PadLeft(2, '0') + Convert.ToString(ipPacket.Bytes[3], 16).ToUpper().PadLeft(2, '0'));
                            this.ip_info.Add("Payload Length(负载长度)",ipPacket.PayloadLength.ToString());
                            this.ip_info.Add("Next Header(下一包头)",ipPacket.NextHeader.ToString());
                            this.ip_info.Add("Hop Limit(跳段数限制)",ipPacket.HopLimit.ToString());
                            this.ip_info.Add("Source Address(源地址)",ipPacket.SourceAddress.ToString());
                            this.ip_info.Add("Destination Address(目的地址)",ipPacket.DestinationAddress.ToString());

                            //简易信息
                            this.srcIp = ipPacket.SourceAddress.ToString();
                            this.destIp = ipPacket.DestinationAddress.ToString();
                            this.protocol = ipPacket.Protocol.ToString().ToUpper();
                            this.info = ipPacket.ToString();

                            if (ipPacket.Protocol.ToString() == "ICMPV6")
                            {
                                var icmpPacket = PacketDotNet.ICMPv6Packet.GetEncapsulated(this.rPacket);

                                var type = Convert.ToString(icmpPacket.Bytes[0], 10);
                                if (type != "135")
                                {
                                    //type134问题，待处理
                                    //this.icmp_info.Add("Type(类型)", icmpPacket.Type.ToString());
                                    this.icmp_info.Add("Type(类型)", type);
                                }
                                else
                                {
                                    this.icmp_info.Add("Type(类型)", "Neighbor Solicitation");
                                }
                                //
                                this.icmp_info.Add("Code(代码)", "0x" + Convert.ToString(icmpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.icmp_info.Add("Checksum(校验和)", icmpPacket.Checksum.ToString());

                                //颜色
                                this.color = "Pink";
                                //简易信息，待处理
                                this.info = (type == "135") ? ("Neighbor Solicitation" + " for " + "to be continued" + " from " + "to be contiunued") : type;
                            }

                            //IGMP包解析,待完成
                            /*
                            else if (ipPacket.Protocol.ToString() == "IGMP")
                            {
                                var tcpPacket = PacketDotNet.IGMPv2Packet.ParsePacket(this.rPacket);
                              
                                //简易信息
                             
                            }
                            */
                            //

                            else if (ipPacket.Protocol.ToString() == "TCP")
                            {
                                var tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(this.rPacket);
                                this.tcp_info.Add("SourcePort(源端口)", tcpPacket.SourcePort.ToString());
                                this.tcp_info.Add("DestinationPort(目的端口)", tcpPacket.DestinationPort.ToString());
                                //与wireshark不符，应该是wireshark特有的relative功能，待确认
                                this.tcp_info.Add("SequenceNumber(序号)", tcpPacket.SequenceNumber.ToString());
                                //
                                this.tcp_info.Add("AcknowledgmentNumber(确认序号)", tcpPacket.AcknowledgmentNumber.ToString());
                                this.tcp_info.Add("DataOffset(数据偏移)", tcpPacket.DataOffset.ToString());
                                this.tcp_info.Add("URG", tcpPacket.Urg.ToString());
                                this.tcp_info.Add("ACK", tcpPacket.Ack.ToString());
                                this.tcp_info.Add("PSH", tcpPacket.Psh.ToString());
                                this.tcp_info.Add("RST", tcpPacket.Rst.ToString());
                                this.tcp_info.Add("SYN", tcpPacket.Syn.ToString());
                                this.tcp_info.Add("FIN", tcpPacket.Fin.ToString());
                                this.tcp_info.Add("WindowSize(窗口)", ((UInt16)tcpPacket.WindowSize).ToString());
                                this.tcp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(tcpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.tcp_info.Add("UrgentPointer(紧急指针)", tcpPacket.UrgentPointer.ToString());
                                this.tcp_info.Add("Option(可选部分)", "to be continued");

                                //颜色
                                this.color = "YellowGreen";
                                //简易信息
                                this.info = tcp_info["SourcePort(源端口)"] + " → " + tcp_info["DestinationPort(目的端口)"] + ((tcp_info["SYN"] == "True") ? " [SYN] " : "") + ((tcp_info["ACK"] == "True") ? " [ACK] " : "") + "Seq=" + tcp_info["SequenceNumber(序号)"] + " Ack=" + tcp_info["AcknowledgmentNumber(确认序号)"] + " Win=" + tcp_info["WindowSize(窗口)"];

                                //判断具体应用层
                                //TELNET待完善中文乱码
                                if (tcp_info["SourcePort(源端口)"] == "23")
                                {
                                    this.protocol = "TELNET";
                                    this.color = "Blue";
                                    this.info = "Telnet Data ...";

                                    this.application_info.Add("ApplicationType", "TELNET");

                                    var telnetData = tcpPacket.PayloadData;
                                    //将接收到的数据转个码,顺便转成string型
                                    string sRecieved = Encoding.GetEncoding("utf-8").GetString(telnetData, 0, telnetData.Length);
                                    //声明一个字符串,用来存储解析过的字符串
                                    string m_strLine = "";
                                    //遍历接收到的字符
                                    for (int i = 0; i < telnetData.Length; i++)
                                    {
                                        Char ch = Convert.ToChar(telnetData[i]);
                                        switch (ch)
                                        {
                                            case '\r':
                                                m_strLine += Convert.ToString("\r\n");
                                                break;
                                            case '\n':
                                                break;
                                            default:
                                                m_strLine += Convert.ToString(ch);
                                                break;

                                        }
                                    }
                                    this.application_info.Add("Data", m_strLine);
                                }
                                //HTTP，待完善，存在很多空包及乱码问题
                                else if (tcp_info["SourcePort(源端口)"] == "80")
                                {
                                    this.protocol = "HTTP";
                                    this.color = "YellowGreen";
                                    //this.info = "HTTP to be continued OK";

                                    this.application_info.Add("ApplicationType", "HTTP");

                                    var httpData = tcpPacket.PayloadData;
                                    string headertext = "";
                                    string ssHeader = System.Text.Encoding.Default.GetString(httpData);
                                    if (ssHeader.IndexOf("\r\n\r\n") > 0)
                                    {
                                        headertext = ssHeader.Substring(0, ssHeader.IndexOf("\r\n\r\n"));
                                    }

                                    this.application_info.Add("Data", headertext);
                                    if (headertext.Length > 0 && headertext.IndexOf('\n') > 0 && headertext.IndexOf("HTTP") >= 0)
                                    {
                                        this.info = headertext.Substring(0, headertext.IndexOf('\n'));
                                    }
                                    else
                                    {
                                        this.info = "Continuation or non-HTTP traffic";
                                    }
                                }
                            }
                            else if (ipPacket.Protocol.ToString() == "UDP")
                            {
                                var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(this.rPacket);
                                this.udp_info.Add("SourcePort(源端口)", udpPacket.SourcePort.ToString());
                                this.udp_info.Add("DestinationPort(目的端口)", udpPacket.DestinationPort.ToString());
                                this.udp_info.Add("Length(报文长度)", udpPacket.Length.ToString());
                                this.udp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(udpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));

                                //颜色
                                this.color = "SkyBlue";
                                //简易信息
                                this.info = "Source port: " + udp_info["SourcePort(源端口)"] + "  Destination port: " + udp_info["DestinationPort(目的端口)"];
                            }
                        }
                    }
                }
                //ARP包解析
                else if (ethernetPacket.Type.ToString() == "Arp")
                {
                    var arpPacket = PacketDotNet.ARPPacket.GetEncapsulated(this.rPacket);  //ARP包
                    this.arp_info.Add("HardwareAddressType(硬件类型)", arpPacket.HardwareAddressType.ToString());
                    this.arp_info.Add("ProtocolAddressType(协议类型)", arpPacket.ProtocolAddressType.ToString());
                    this.arp_info.Add("HardwareAddressLength(硬件地址长度)", arpPacket.HardwareAddressLength.ToString());
                    this.arp_info.Add("ProtocolAddressLength(协议地址长度)", arpPacket.ProtocolAddressLength.ToString());
                    this.arp_info.Add("Operation(操作)", arpPacket.Operation.ToString());
                    this.arp_info.Add("SenderHardwareAddress(发送者硬件地址)", arpPacket.SenderHardwareAddress.ToString());
                    this.arp_info.Add("SenderProtocolAddress(发送者IP地址)", arpPacket.SenderProtocolAddress.ToString());
                    this.arp_info.Add("TargetHardwareAddress(目标硬件地址)", arpPacket.TargetHardwareAddress.ToString());
                    this.arp_info.Add("TargetProtocolAddress(目标IP地址)", arpPacket.TargetProtocolAddress.ToString());

                    //颜色
                    this.color = "Orange";
                    //简易信息
                    this.srcIp = arpPacket.SenderProtocolAddress.ToString();
                    this.destIp = arpPacket.TargetProtocolAddress.ToString();
                    this.info = "Who has " + arp_info["TargetProtocolAddress(目标IP地址)"] + "?  Tell " + arp_info["SenderProtocolAddress(发送者IP地址)"];
                }
            }
        }

    }
}
