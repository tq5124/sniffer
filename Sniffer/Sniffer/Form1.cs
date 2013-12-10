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
        private delegate void setDataGridViewDelegate(packet Packet,int index);

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
                //if (temp.ip_info.Count > 0 && temp.ip_info["Version(版本)"] == "IPv4")
                {
                    this.label1.BeginInvoke(new setDataGridViewDelegate(setDataGridView), new object[] { temp, packets.Count - 1 });
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
                this.ethernet_info.Add("Type(以太类型)", ethernetPacket.Type.ToString());


                //简易信息
                this.srcIp = ethernetPacket.SourceHwAddress.ToString();
                this.destIp = ethernetPacket.DestinationHwAddress.ToString();
                this.protocol = ethernetPacket.Type.ToString();
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
                            this.ip_info.Add("Version(版本)", ipPacket.Version.ToString());
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
                            this.ip_info.Add("Protocol(协议)", ipPacket.Protocol.ToString());
                            this.ip_info.Add("Header checksum(头部校验和)", "0x" + Convert.ToString(ipPacket.Bytes[10], 16).ToUpper().PadLeft(2, '0') + Convert.ToString(ipPacket.Bytes[11], 16).ToUpper().PadLeft(2, '0'));
                            this.ip_info.Add("Source(源地址)", ipPacket.SourceAddress.ToString());
                            this.ip_info.Add("Destination(目的地址)", ipPacket.DestinationAddress.ToString());
                            this.ip_info.Add("Options(可选)", "to be continued");

                            //简易信息
                            this.srcIp = ipPacket.SourceAddress.ToString();
                            this.destIp = ipPacket.DestinationAddress.ToString();
                            this.protocol = ipPacket.Protocol.ToString();
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
                            /*
                            else if (ipPacket.Protocol.ToString() == "IGMP")
                            {
                                var tcpPacket = PacketDotNet.IGMPv2Packet.ParsePacket(this.rPacket);
                              
                                //简易信息
                             
                            }
                            */
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
                                this.tcp_info.Add("WindowSize(窗口)", ((uint)tcpPacket.WindowSize).ToString());
                                this.tcp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(tcpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.tcp_info.Add("UrgentPointer(紧急指针)", tcpPacket.UrgentPointer.ToString());
                                this.tcp_info.Add("Option(可选部分)", "to be continued");

                                //颜色
                                this.color = "YellowGreen";
                                //简易信息
                                this.info = tcp_info["SourcePort(源端口)"] + " → " + tcp_info["DestinationPort(目的端口)"] + ((tcp_info["SYN"] == "True") ? " [SYN] " : "") + ((tcp_info["ACK"] == "True") ? " [ACK] " : "") + "Seq=" + tcp_info["SequenceNumber(序号)"] + " Ack=" + tcp_info["AcknowledgmentNumber(确认序号)"] + " Win=" + tcp_info["WindowSize(窗口)"];

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
                            this.ip_info.Add("Version(版本)", ipPacket.Version.ToString());
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
                            this.protocol = ipPacket.Protocol.ToString();
                            this.info = ipPacket.ToString();

                            if (ipPacket.Protocol.ToString() == "ICMPV6")
                            {
                                var icmpPacket = PacketDotNet.ICMPv6Packet.GetEncapsulated(this.rPacket);

                                var type = Convert.ToString(icmpPacket.Bytes[0], 10);
                                if (type != "135")
                                {
                                    //type134问题
                                    //this.icmp_info.Add("Type(类型)", icmpPacket.Type.ToString());
                                    this.icmp_info.Add("Type(类型)", "to be continued");
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
                                //简易信息
                                //this.info = icmpPacket.ToString();
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
                                this.tcp_info.Add("WindowSize(窗口)", ((uint)tcpPacket.WindowSize).ToString());
                                this.tcp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(tcpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.tcp_info.Add("UrgentPointer(紧急指针)", tcpPacket.UrgentPointer.ToString());
                                this.tcp_info.Add("Option(可选部分)", "to be continued");

                                //颜色
                                this.color = "YellowGreen";
                                //简易信息
                                this.info = tcp_info["SourcePort(源端口)"] + " → " + tcp_info["DestinationPort(目的端口)"] + ((tcp_info["SYN"] == "True") ? " [SYN] " : "") + ((tcp_info["ACK"] == "True") ? " [ACK] " : "") + "Seq=" + tcp_info["SequenceNumber(序号)"] + " Ack=" + tcp_info["AcknowledgmentNumber(确认序号)"] + " Win=" + tcp_info["WindowSize(窗口)"];
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
