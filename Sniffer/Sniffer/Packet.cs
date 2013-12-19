using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sniffer
{
    public class packet
    {
        public string time;
        public string srcIp;
        public string destIp;
        public string protocol;
        public string info;
        public string color;

        public SharpPcap.RawCapture pPacket;
        public PacketDotNet.LinkLayers layer;
        public PacketDotNet.Packet rPacket;        

        public Dictionary<string, string> frame_info;
        public Dictionary<string, string> ethernet_info;

        public Dictionary<string, string> ip_info;
        public Dictionary<string, string> arp_info;

        public Dictionary<string, string> icmp_info;
        public Dictionary<string, string> igmp_info;
        public Dictionary<string, string> tcp_info;
        public Dictionary<string, string> udp_info;

        public Dictionary<string, string> application_info;

        public packet(SharpPcap.RawCapture pPacket)
        {
            var timestamp = pPacket.Timeval.Date;
            this.layer = pPacket.LinkLayerType;
            this.time = timestamp.Hour.ToString() + ":" + timestamp.Minute.ToString() + ":" + timestamp.Second.ToString() + "," + timestamp.Millisecond.ToString();
            this.srcIp = "";
            this.destIp = "";
            this.protocol = "";
            this.info = "";
            this.color = "White";

            this.pPacket = pPacket;
            this.rPacket = PacketDotNet.Packet.ParsePacket(pPacket.LinkLayerType, pPacket.Data);
            
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
            this.frame_info.Add("Frame", this.rPacket.Bytes.Length.ToString() + " bytes");
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
                    var ipPacket = this.rPacket.Extract(typeof(PacketDotNet.IpPacket)) as PacketDotNet.IpPacket;
                    if (ipPacket != null)
                    {
                        //IpV4
                        if (ipPacket.Version.ToString() == "IPv4")
                        {
                            ipPacket = this.rPacket.Extract(typeof(PacketDotNet.IPv4Packet)) as PacketDotNet.IPv4Packet;
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
                                var icmpPacket = this.rPacket.Extract(typeof(PacketDotNet.ICMPv4Packet)) as PacketDotNet.ICMPv4Packet;
                                this.icmp_info.Add("TypeCode(类型)", icmpPacket.TypeCode.ToString());
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
                                var igmpPacket = this.rPacket.Extract(typeof(PacketDotNet.IGMPv2Packet)) as PacketDotNet.IGMPv2Packet;
                                                                
                                this.igmp_info.Add("Type(类型)",igmpPacket.Type.ToString());
                                this.igmp_info.Add("MaxResponseTime(最大响应时间)", igmpPacket.MaxResponseTime.ToString());
                                this.igmp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(igmpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.igmp_info.Add("GroupAddress(组地址)", igmpPacket.GroupAddress.ToString());

                                //简易信息
                                this.info = this.igmp_info["Type(类型)"] + " " + this.igmp_info["GroupAddress(组地址)"];
                            }

                            //

                            //TCP包解析
                            else if (ipPacket.Protocol.ToString() == "TCP")
                            {
                                var tcpPacket = this.rPacket.Extract(typeof(PacketDotNet.TcpPacket)) as PacketDotNet.TcpPacket;
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
                                this.tcp_info.Add("tcpPacket计算校验和函数计算结果", "0x" + Convert.ToString(tcpPacket.CalculateTCPChecksum(), 16).ToUpper().PadLeft(4, '0'));
                                this.tcp_info.Add("UrgentPointer(紧急指针)", tcpPacket.UrgentPointer.ToString());
                                this.tcp_info.Add("Option(可选部分)", "to be continued");

                                //颜色
                                this.color = "YellowGreen";
                                //简易信息
                                this.info = tcp_info["SourcePort(源端口)"] + " → " + tcp_info["DestinationPort(目的端口)"] + ((tcp_info["FIN"] == "True") ? " [FIN] " : "") + ((tcp_info["RST"] == "True") ? " [RST] " : "") + ((tcp_info["SYN"] == "True") ? " [SYN] " : "") + ((tcp_info["ACK"] == "True") ? " [ACK] " : "") + "Seq=" + tcp_info["SequenceNumber(序号)"] + " Ack=" + tcp_info["AcknowledgmentNumber(确认序号)"] + " Win=" + tcp_info["WindowSize(窗口)"];

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
                                else if (tcp_info["SourcePort(源端口)"] == "80" || tcp_info["DestinationPort(目的端口)"] == "80")
                                {
                                    var httpData = tcpPacket.PayloadData;
                                    string headertext = "";
                                    string datatext = "";
                                    string bytetext = "";
                                    string ssHeader = System.Text.Encoding.Default.GetString(httpData);
                                    foreach (byte i in httpData)
                                    {
                                        bytetext += Convert.ToString(i, 16).ToUpper().PadLeft(2, '0');
                                    }
                                    if (ssHeader.IndexOf("\r\n\r\n") > 0)
                                    {
                                        if (ssHeader.IndexOf("HTTP") >= 0 || ssHeader.IndexOf("GET") >= 0 || ssHeader.IndexOf("POST") >= 0)
                                        {
                                            headertext = ssHeader.Substring(0, ssHeader.IndexOf("\r\n\r\n"));
                                            int i = ssHeader.IndexOf("\r\n\r\n");
                                            if (ssHeader.IndexOf("\r\n\r\n") + "\r\n\r\n".Length < ssHeader.Length)
                                            {
                                                datatext = ssHeader.Substring(ssHeader.IndexOf("\r\n\r\n") + "\r\n\r\n".Length, ssHeader.Length - ssHeader.IndexOf("\r\n\r\n") - "\r\n\r\n".Length);

                                            }
                                        }
                                        else
                                        {
                                            datatext = ssHeader.Substring(0, ssHeader.IndexOf("\r\n\r\n"));
                                        }
                                    }


                                    //判断HTTP解析是否成功，成功则添加HTTP信息，否则则判断为TCP传送数据
                                    if (ssHeader.IndexOf("HTTP") >= 0 || ssHeader.IndexOf("GET") >= 0 || ssHeader.IndexOf("POST") >= 0)
                                    {
                                        this.protocol = "HTTP";
                                        this.color = "YellowGreen";
                                        this.info = headertext.Substring(0, (headertext.IndexOf('\n') >= 0) ? headertext.IndexOf('\n') : headertext.Length);

                                        this.application_info.Add("ApplicationType", "HTTP");
                                        this.application_info.Add("Head", headertext);
                                        this.application_info.Add("Data", datatext);
                                        this.application_info.Add("All", ssHeader);
                                        this.application_info.Add("Byte", bytetext);
                                    }
                                    else if (ssHeader.Length > 0)
                                    {
                                        this.info = "TCP segment of a reassembled PDU";
                                        this.tcp_info.Add("TCP segment data", ssHeader);
                                    }
                                }
                            }
                            else if (ipPacket.Protocol.ToString() == "UDP")
                            {
                                var udpPacket = this.rPacket.Extract(typeof(PacketDotNet.UdpPacket)) as PacketDotNet.UdpPacket;
                                this.udp_info.Add("SourcePort(源端口)", udpPacket.SourcePort.ToString());
                                this.udp_info.Add("DestinationPort(目的端口)", udpPacket.DestinationPort.ToString());
                                this.udp_info.Add("Length(报文长度)", udpPacket.Length.ToString());
                                this.udp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(udpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));

                                //颜色
                                this.color = "SkyBlue";
                                //简易信息
                                this.info = "Source port: " + udp_info["SourcePort(源端口)"] + "  Destination port: " + udp_info["DestinationPort(目的端口)"];

                                //判断具体应用层
                                //DNS待完成
                                if (udp_info["SourcePort(源端口)"] == "53")
                                {
                                    this.protocol = "DNS";
                                    this.color = "SkyBlue";
                                    this.info = "DNS to be continued";

                                    this.application_info.Add("ApplicationType", "DNS");
                                    this.application_info.Add("Data", "");
                                }
                            }
                        }
                        //IpV6
                        else if (ipPacket.Version.ToString() == "IPv6")
                        {
                            ipPacket = this.rPacket.Extract(typeof(PacketDotNet.IPv6Packet)) as PacketDotNet.IPv6Packet;
                            this.ip_info.Add("Version(版本)", ipPacket.Version.ToString().ToUpper());
                            this.ip_info.Add("Traffic Class(通信类别)", "0x" + Convert.ToString(ipPacket.Bytes[0] & 15, 16).ToUpper().PadLeft(1, '0') + Convert.ToString((ipPacket.Bytes[1] & 240) >> 4, 16).ToUpper().PadLeft(1, '0'));
                            this.ip_info.Add("Flow Label(流标记)", "0x" + Convert.ToString(ipPacket.Bytes[1] & 15, 16).ToUpper().PadLeft(1, '0') + Convert.ToString(ipPacket.Bytes[2], 16).ToUpper().PadLeft(2, '0') + Convert.ToString(ipPacket.Bytes[3], 16).ToUpper().PadLeft(2, '0'));
                            this.ip_info.Add("Payload Length(负载长度)", ipPacket.PayloadLength.ToString());
                            this.ip_info.Add("Next Header(下一包头)", ipPacket.NextHeader.ToString());
                            this.ip_info.Add("Hop Limit(跳段数限制)", ipPacket.HopLimit.ToString());
                            this.ip_info.Add("Source Address(源地址)", ipPacket.SourceAddress.ToString());
                            this.ip_info.Add("Destination Address(目的地址)", ipPacket.DestinationAddress.ToString());

                            //简易信息
                            this.srcIp = ipPacket.SourceAddress.ToString();
                            this.destIp = ipPacket.DestinationAddress.ToString();
                            this.protocol = ipPacket.Protocol.ToString().ToUpper();
                            try
                            {
                                this.info = ipPacket.ToString();
                            }
                            catch (Exception e)
                            {
                                this.info = "IPV6 to be continued";
                                System.Windows.Forms.MessageBox.Show(e.Message);
                            }
                            
                            if (ipPacket.Protocol.ToString() == "ICMPV6")
                            {
                                var icmpPacket = this.rPacket.Extract(typeof(PacketDotNet.ICMPv6Packet)) as PacketDotNet.ICMPv6Packet;
                                
                                var type = Convert.ToString(icmpPacket.Bytes[0], 10);
                                try
                                {
                                    this.icmp_info.Add("Type(类型)", icmpPacket.Type.ToString());
                                    //简易信息，待处理              
                                    this.info = icmpPacket.Type.ToString();
                                }
                                catch (Exception e)
                                {
                                    this.icmp_info.Add("Type(类型)", type);
                                    this.info = type;
                                    System.Windows.Forms.MessageBox.Show(e.Message);
                                }
                                
                                this.icmp_info.Add("Code(代码)", "0x" + Convert.ToString(icmpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.icmp_info.Add("Checksum(校验和)", icmpPacket.Checksum.ToString());

                                //颜色
                                this.color = "Pink";                                
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
                                var tcpPacket = this.rPacket.Extract(typeof(PacketDotNet.TcpPacket)) as PacketDotNet.TcpPacket;
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
                                this.info = tcp_info["SourcePort(源端口)"] + " → " + tcp_info["DestinationPort(目的端口)"] + ((tcp_info["FIN"] == "True") ? " [FIN] " : "") + ((tcp_info["RST"] == "True") ? " [RST] " : "") + ((tcp_info["SYN"] == "True") ? " [SYN] " : "") + ((tcp_info["ACK"] == "True") ? " [ACK] " : "") + "Seq=" + tcp_info["SequenceNumber(序号)"] + " Ack=" + tcp_info["AcknowledgmentNumber(确认序号)"] + " Win=" + tcp_info["WindowSize(窗口)"];

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
                                else if (tcp_info["SourcePort(源端口)"] == "80" || tcp_info["DestinationPort(目的端口)"] == "80")
                                {
                                    var httpData = tcpPacket.PayloadData;
                                    string headertext = "";
                                    string datatext = "";
                                    string bytetext = "";
                                    string ssHeader = System.Text.Encoding.Default.GetString(httpData);
                                    foreach (byte i in httpData)
                                    {
                                        bytetext += Convert.ToString(i, 16).ToUpper().PadLeft(2, '0');
                                    }
                                    if (ssHeader.IndexOf("\r\n\r\n") > 0)
                                    {
                                        if (ssHeader.IndexOf("HTTP") >= 0 || ssHeader.IndexOf("GET") >= 0 || ssHeader.IndexOf("POST") >= 0)
                                        {
                                            headertext = ssHeader.Substring(0, ssHeader.IndexOf("\r\n\r\n"));
                                            int i = ssHeader.IndexOf("\r\n\r\n");
                                            if (ssHeader.IndexOf("\r\n\r\n") + "\r\n\r\n".Length < ssHeader.Length)
                                            {
                                                datatext = ssHeader.Substring(ssHeader.IndexOf("\r\n\r\n") + "\r\n\r\n".Length, ssHeader.Length - ssHeader.IndexOf("\r\n\r\n") - "\r\n\r\n".Length);

                                            }
                                        }
                                        else
                                        {
                                            datatext = ssHeader.Substring(0, ssHeader.IndexOf("\r\n\r\n"));
                                        }
                                    }


                                    //判断HTTP解析是否成功，成功则添加HTTP信息，否则则判断为TCP传送数据
                                    if (ssHeader.IndexOf("HTTP") >= 0 || ssHeader.IndexOf("GET") >= 0 || ssHeader.IndexOf("POST") >= 0)
                                    {
                                        this.protocol = "HTTP";
                                        this.color = "YellowGreen";
                                        this.info = headertext.Substring(0, (headertext.IndexOf('\n') >= 0) ? headertext.IndexOf('\n') : headertext.Length);

                                        this.application_info.Add("ApplicationType", "HTTP");
                                        this.application_info.Add("Head", headertext);
                                        this.application_info.Add("Data", datatext);
                                        this.application_info.Add("All", ssHeader);
                                        this.application_info.Add("Byte", bytetext);
                                    }
                                    else if (ssHeader.Length > 0)
                                    {
                                        this.info = "TCP segment of a reassembled PDU";
                                        this.tcp_info.Add("TCP segment data", ssHeader);
                                    }
                                }
                            }
                            else if (ipPacket.Protocol.ToString() == "UDP")
                            {
                                var udpPacket = this.rPacket.Extract(typeof(PacketDotNet.UdpPacket)) as PacketDotNet.UdpPacket;
                                this.udp_info.Add("SourcePort(源端口)", udpPacket.SourcePort.ToString());
                                this.udp_info.Add("DestinationPort(目的端口)", udpPacket.DestinationPort.ToString());
                                this.udp_info.Add("Length(报文长度)", udpPacket.Length.ToString());
                                this.udp_info.Add("Checksum(校验和)", "0x" + Convert.ToString(udpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));

                                //颜色
                                this.color = "SkyBlue";
                                //简易信息
                                this.info = "Source port: " + udp_info["SourcePort(源端口)"] + "  Destination port: " + udp_info["DestinationPort(目的端口)"];

                                //判断具体应用层
                                //DNS待完成
                                if (udp_info["SourcePort(源端口)"] == "53")
                                {
                                    this.protocol = "DNS";
                                    this.color = "SkyBlue";
                                    this.info = "DNS to be continued";

                                    this.application_info.Add("ApplicationType", "DNS");
                                    this.application_info.Add("Data", "");
                                }
                            }
                        }
                    }
                }
                //ARP包解析
                else if (ethernetPacket.Type.ToString() == "Arp")
                {
                    var arpPacket = this.rPacket.Extract(typeof(PacketDotNet.ARPPacket)) as PacketDotNet.ARPPacket;  //ARP包
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
