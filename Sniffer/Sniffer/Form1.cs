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
        }

        //抓包线程
        private delegate void setDataGridViewDelegate(string time, string srcIp, string destIp, string protocol, string info, string color);

        private LivePcapDevice device;
        private int readTimeoutMilliseconds;
        private string filter;

        private void button1_Click(object sender, EventArgs e)
        {
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
            var timestamp = pPacket.Timeval.Date;
            var len = pPacket.Data.Length;
            var layer = pPacket.LinkLayerType;

            string time = timestamp.Hour.ToString() + ":" + timestamp.Minute.ToString() + ":" + timestamp.Second.ToString() + "," + timestamp.Millisecond.ToString();
            string srcIp = "";
            string destIp = "";
            string protocol = "";
            string info = "";
            string color = "";

            var packet = PacketDotNet.Packet.ParsePacket(pPacket); //Raw基础包对象
            Console.WriteLine(packet.Bytes.ToString());
            color = "White";

            if (layer == PacketDotNet.LinkLayers.Ethernet) //以太网包
            {
                var ethernetPacket = (PacketDotNet.EthernetPacket)packet;
                System.Net.NetworkInformation.PhysicalAddress srcMac = ethernetPacket.SourceHwAddress;
                System.Net.NetworkInformation.PhysicalAddress destMac = ethernetPacket.DestinationHwAddress;

                srcIp = srcMac.ToString();
                destIp = destMac.ToString();

                protocol = ethernetPacket.Type.ToString().ToUpper();
                if (protocol == "ARP") 
                {
                    color = "Gray";
                }
                if (ethernetPacket.Type.ToString() != "IpV6")
                {
                    info = "Ethernet packet: " + ethernetPacket.ToColoredString(false);
                }
                else 
                {
                    info = "IpV6";
                }
                 
                
            }
            var ipPacket = PacketDotNet.IpPacket.GetEncapsulated(packet);  //IP包     
            if (ipPacket != null)
            {
                srcIp = ipPacket.SourceAddress.ToString();
                destIp = ipPacket.DestinationAddress.ToString();
                protocol = ipPacket.Protocol.ToString();

                var tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(packet); //TCP包
                if (tcpPacket != null)
                {
                    int srcPort = tcpPacket.SourcePort;
                    int destPort = tcpPacket.DestinationPort;

                    protocol = "TCP";
                    protocol = (destPort == 23) ? "TELNET" : protocol;
                    protocol = (destPort == 80) ? "HTTP" : protocol;
                    protocol = (destPort == 21) ? "FTP" : protocol;
                    protocol = (destPort == 20) ? "FTP-DATA" : protocol;

                    //info = "TCP packet: " + tcpPacket.ToColoredString(false);
                    info = "TCP packet: " + tcpPacket.ToString();
                }

                var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(packet); //UDP包
                if (udpPacket != null)
                {
                    int srcPort = udpPacket.SourcePort;
                    int destPort = udpPacket.DestinationPort;

                    protocol = "UDP";
                    //info = "UDP packet: " + udpPacket.ToColoredString(false);
                    info = "UDP packet: " + udpPacket.ToString();
                }
            }

            if (this.dataGridView1.InvokeRequired)
            {
                this.label1.BeginInvoke(new setDataGridViewDelegate(setDataGridView), new object[] {time, srcIp, destIp, protocol, info, color});
            }
            else
            {
                int index = this.dataGridView1.Rows.Add();
                this.dataGridView1.Rows[index].DefaultCellStyle.BackColor = Color.FromName(color);

                this.dataGridView1.Rows[index].Cells[0].Value = time;
                this.dataGridView1.Rows[index].Cells[1].Value = srcIp;
                this.dataGridView1.Rows[index].Cells[2].Value = destIp;
                this.dataGridView1.Rows[index].Cells[3].Value = protocol;
                this.dataGridView1.Rows[index].Cells[4].Value = info;
            }
        }
        /// <summary>
        /// 抓包后更新UI显示
        /// </summary>
        private void setDataGridView(string time, string srcIp, string destIp, string protocol, string info, string color)  //当跨线程调用时，调用该方法进行UI界面更新
        {
            int index = this.dataGridView1.Rows.Add();
            this.dataGridView1.Rows[index].DefaultCellStyle.BackColor = Color.FromName(color);

            this.dataGridView1.Rows[index].Cells[0].Value = time;
            this.dataGridView1.Rows[index].Cells[1].Value = srcIp;
            this.dataGridView1.Rows[index].Cells[2].Value = destIp;
            this.dataGridView1.Rows[index].Cells[3].Value = protocol;
            this.dataGridView1.Rows[index].Cells[4].Value = info;   
        }

        /// <summary>
        /// 停止抓包
        /// </summary>
        private void button2_Click(object sender, EventArgs e)
        {
            this.device.StopCapture();
        }
    }
}
