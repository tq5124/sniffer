﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sniffer
{
    public class packet
    {
        //显示的简易信息部分
        //包到达时间戳
        public string time;
        //源地址，可能是IP也可能是MAC地址
        public string srcIp;
        //目标地址，可能是IP也可能是MAC地址
        public string destIp;
        //最高层使用的协议
        public string protocol;
        //简单的包内容信息
        public string info;
        //包的显示颜色
        public string color;

        //数据包详细信息
        //原始抓到的数据
        public SharpPcap.RawCapture pPacket;
        //包的层别
        public PacketDotNet.LinkLayers layer;
        //基础数据包
        public PacketDotNet.Packet rPacket;        
        //物理帧信息
        public Dictionary<string, string> frame_info;
        //以太网层信息
        public Dictionary<string, string> ethernet_info;

        //IP层信息
        public Dictionary<string, string> ip_info;
        //ARP协议解析信息
        public Dictionary<string, string> arp_info;

        //ICMP协议解析信息
        public Dictionary<string, string> icmp_info;
        //IGMP协议解析信息
        public Dictionary<string, string> igmp_info;
        //TCP协议解析信息
        public Dictionary<string, string> tcp_info;
        //UDP协议解析信息
        public Dictionary<string, string> udp_info;

        //应用层协议解析信息
        public Dictionary<string, string> application_info;
        //应用层包含的比特流数据，方便进行文件重组
        public byte[] application_byte;

        //当前开启的ftp被动模式端口，key为客户端开启的端口，value为服务端开启的端口，进行FTP-DATA协议判断时与FTP文件重组时使用
        public static Dictionary<int, int> ftp_pasv_port = new Dictionary<int, int>();

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
            this.application_byte = null;

            analysis_packet();

            // 计算校验和
            if (this.tcp_info.Count > 0 && this.tcp_info["Checksum(校验和)"] != this.tcp_info["tcpPacket计算校验和函数计算结果"])
            {
                this.color = "Red";
            }
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
                this.info = "Ethernet II";
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
                                this.color = "AntiqueWhite";
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

                                //颜色
                                this.color = "BlanchedAlmond";
                                //简易信息
                                this.info = this.igmp_info["Type(类型)"] + " " + this.igmp_info["GroupAddress(组地址)"];
                            }

                            //

                            //TCP包解析
                            else if (ipPacket.Protocol.ToString() == "TCP")
                            {
                                tcp_analysis();
                            }
                            else if (ipPacket.Protocol.ToString() == "UDP")
                            {
                                udp_analysis();
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
                            catch (Exception)
                            {
                                this.info = "IPV6";
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
                                    if (type == "136")
                                    {
                                        type = "Neighbor Advertisement";
                                        this.icmp_info.Add("Type(类型)", type);
                                        this.info = type;
                                    }
                                    else if (type == "134")
                                    {
                                        type = "Router Advertisement";
                                        this.icmp_info.Add("Type(类型)", type);
                                        this.info = type;
                                    }
                                    else
                                    {
                                        Console.WriteLine(e.Message);
                                    }
                                }
                                
                                this.icmp_info.Add("Code(代码)", "0x" + Convert.ToString(icmpPacket.Checksum, 16).ToUpper().PadLeft(4, '0'));
                                this.icmp_info.Add("Checksum(校验和)", icmpPacket.Checksum.ToString());

                                //颜色
                                this.color = "AntiqueWhite";                                
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
                                tcp_analysis();
                            }
                            else if (ipPacket.Protocol.ToString() == "UDP")
                            {
                                udp_analysis();
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
                    this.color = "BlanchedAlmond";
                    //简易信息
                    this.srcIp = arpPacket.SenderProtocolAddress.ToString();
                    this.destIp = arpPacket.TargetProtocolAddress.ToString();
                    this.info = "Who has " + arp_info["TargetProtocolAddress(目标IP地址)"] + "?  Tell " + arp_info["SenderProtocolAddress(发送者IP地址)"];
                }
            }
        }
        /// <summary>
        /// TCP解析
        /// </summary>
        public void tcp_analysis()
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
            this.color = "PaleGreen";
            
            //简易信息
            this.info = tcp_info["SourcePort(源端口)"] + " → " + tcp_info["DestinationPort(目的端口)"] + ((tcp_info["FIN"] == "True") ? " [FIN] " : "") + ((tcp_info["RST"] == "True") ? " [RST] " : "") + ((tcp_info["SYN"] == "True") ? " [SYN] " : "") + ((tcp_info["ACK"] == "True") ? " [ACK] " : "") + "Seq=" + tcp_info["SequenceNumber(序号)"] + " Ack=" + tcp_info["AcknowledgmentNumber(确认序号)"] + " Win=" + tcp_info["WindowSize(窗口)"];

            //判断具体应用层
            //TELNET待完善中文乱码
            if (tcp_info["SourcePort(源端口)"] == "23")
            {
                this.protocol = "TELNET";
                this.color = "LightSteelBlue";
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
            //HTTP，待完善
            else if (tcp_info["SourcePort(源端口)"] == "80" || tcp_info["DestinationPort(目的端口)"] == "80")
            {
                http_analysis(tcpPacket.PayloadData);
            }
            //FTP，待完善
            else if ((tcp_info["SourcePort(源端口)"] == "21" || tcp_info["DestinationPort(目的端口)"] == "21") && tcpPacket.PayloadData.Length > 0)
            {
                this.protocol = "FTP";
                this.color = "LightSteelBlue";                
                this.application_info.Add("ApplicationType", "FTP");

                string ftptext = System.Text.Encoding.Default.GetString(tcpPacket.PayloadData);
                if (tcp_info["SourcePort(源端口)"] == "21")
                {
                    this.application_info.Add("Response", ftptext);
                    this.info = "Response: " + ftptext.Substring(0,ftptext.IndexOf("\r\n"));
                    //获取被动模式端口号
                    if (ftptext.IndexOf("Entering Passive Mode") >= 0)
                    {
                        string temp_ftp_pasv_port = ftptext.Substring(ftptext.IndexOf('(') + 1, ftptext.IndexOf(')') - ftptext.IndexOf('(') - 1);
                        string[] temp = temp_ftp_pasv_port.Split(',');
                        int pasv_port = (int.Parse(temp[temp.Length - 2]) << 8) + int.Parse(temp[temp.Length - 1]);
                        try
                        {
                            ftp_pasv_port.Add(int.Parse(this.tcp_info["DestinationPort(目的端口)"]), pasv_port);
                        }
                        catch (Exception)
                        {
                            //重复包会造成键值重复
                        }
                    }
                    //传输结束标识
                    else if (ftptext.IndexOf("226") >= 0)
                    {
                        ftp_pasv_port.Remove(int.Parse(this.tcp_info["DestinationPort(目的端口)"]));
                    }
                    //传输开始标识，加入PASV端口号
                    else if (ftptext.IndexOf("150 Opening") >= 0)
                    {
                        this.application_info.Add("PASV_PORT", ftp_pasv_port[int.Parse(this.tcp_info["DestinationPort(目的端口)"])].ToString());
                    }
                }
                else
                {
                    this.application_info.Add("Request", ftptext);
                    this.info = "Request: " + ftptext.Substring(0, ftptext.IndexOf("\r\n"));
                }
            }
            //FTP-DATA，待完善
            else if ((ftp_pasv_port.ContainsValue(int.Parse(tcp_info["SourcePort(源端口)"])) || tcp_info["SourcePort(源端口)"] == "20") && tcpPacket.PayloadData.Length > 0)
            {
                this.protocol = "FTP-DATA";
                this.color = "LightSteelBlue";
                this.application_info.Add("ApplicationType", "FTP-DATA");

                string ftpdatatext = "";
                foreach (byte i in tcpPacket.PayloadData)
                {
                    ftpdatatext += Convert.ToString(i, 16).ToUpper().PadLeft(2, '0');
                }
                this.application_info.Add("Data", ftpdatatext);
                this.application_byte = new byte[tcpPacket.PayloadData.Length];
                Array.Copy(tcpPacket.PayloadData, 0, this.application_byte, 0, this.application_byte.Length);

                this.info = "FTP DATA: " + tcpPacket.PayloadData.Length.ToString() + " bytes";
            }
            //SSL,只解析头部,不保证正确
            else if (tcp_info["SourcePort(源端口)"] == "443" || tcp_info["DestinationPort(目的端口)"] == "443")
            {
                try
                {
                    SSL sslPacket = new SSL(tcpPacket.PayloadData, this.info);
                    if (sslPacket.application_info.Count > 1)
                    {
                        this.application_info = sslPacket.application_info;
                    }
                    else if (sslPacket.application_info.Count == 1)
                    {
                        this.tcp_info.Add("TCP segment data", sslPacket.application_info["Data"]);  
                    }
                    this.info = sslPacket.info;
                    this.protocol = sslPacket.protocol;
                    this.color = "LightSteelBlue";
                }
                catch
                {
                    ;
                }
            }
        }
        /// <summary>
        /// HTTP解析
        /// </summary>
        public void http_analysis(byte[] http_byte_data)
        {
            var httpData = http_byte_data;
            string headertext = "";
            string datatext = "";
            string bytetext = "";
            foreach (byte i in httpData)
            {
                bytetext += Convert.ToString(i, 16).ToUpper().PadLeft(2, '0');
            }
            if (bytetext.IndexOf("0D0A0D0A") >= 0)
            {
                headertext = System.Text.Encoding.Default.GetString(httpData);
                headertext = headertext.Substring(0, headertext.IndexOf("\r\n\r\n"));
                if (headertext.IndexOf("HTTP") == 0 || headertext.IndexOf("GET") == 0 || headertext.IndexOf("POST") == 0)
                {
                    datatext = bytetext.Substring(bytetext.IndexOf("0D0A0D0A") + "0D0A0D0A".Length, bytetext.Length - bytetext.IndexOf("0D0A0D0A") - "0D0A0D0A".Length);
                }
                else
                {
                    datatext = bytetext;
                }
            }
            else
            {
                datatext = bytetext;
            }
            //以byte数组保存数据
            if (datatext != "")
            {
                this.application_byte = new byte[datatext.Length / 2];
                Array.Copy(httpData, bytetext.IndexOf(datatext) / 2, this.application_byte, 0, this.application_byte.Length);
            }

            //判断HTTP解析是否成功，成功则添加HTTP信息，否则则判断为TCP传送数据
            if (headertext.IndexOf("HTTP") == 0 || headertext.IndexOf("GET") == 0 || headertext.IndexOf("POST") == 0)
            {
                this.protocol = "HTTP";
                this.color = "PaleGreen";
                this.info = headertext.Substring(0, headertext.IndexOf("\r\n"));

                this.application_info.Add("ApplicationType", "HTTP");
                this.application_info.Add("Head", headertext);
                this.application_info.Add("Data", datatext);
                this.application_info.Add("All", System.Text.Encoding.Default.GetString(httpData));
                this.application_info.Add("Byte", bytetext);                
            }
            else if (datatext.Length > 0)
            {
                this.info = "TCP segment of a reassembled PDU";
                this.tcp_info.Add("TCP segment data", datatext);
            }
        }
        /// <summary>
        /// UDP解析
        /// </summary>
        public void udp_analysis()
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
            //DNS待完成数据部分
            if (udp_info["SourcePort(源端口)"] == "53" || udp_info["DestinationPort(目的端口)"] == "53")
            {
                DNS dnsPacket = new DNS(udpPacket.PayloadData, "DNS");
                this.application_info = dnsPacket.application_info;
                this.info = dnsPacket.info;
                this.protocol = "DNS";
                this.color = "SkyBlue";
            }
            //LLMNR待完成数据部分
            else if (udp_info["SourcePort(源端口)"] == "5355" || udp_info["DestinationPort(目的端口)"] == "5355")
            {
                DNS llmnrPacket = new DNS(udpPacket.PayloadData, "LLMNR");
                this.application_info = llmnrPacket.application_info;
                this.info = llmnrPacket.info;
                this.protocol = "LLMNR";
                this.color = "SkyBlue";
            }
            //NBNS待完成数据部分
            else if (udp_info["SourcePort(源端口)"] == "137" && udp_info["DestinationPort(目的端口)"] == "137")
            {
                DNS nbnsPacket = new DNS(udpPacket.PayloadData, "NBNS");
                this.application_info = nbnsPacket.application_info;
                this.info = nbnsPacket.info;
                this.protocol = "NBNS";
                this.color = "Yellow";
            }
            //MDNS待完成数据部分,Additional records存在问题
            else if (((ip_info["Version(版本)"] == "IPV4" && ip_info["Destination(目的地址)"] == "224.0.0.251") || (ip_info["Version(版本)"] == "IPV6" && ip_info["Destination Address(目的地址)"].ToUpper() == "FF02::FB")) && udp_info["SourcePort(源端口)"] == "5353" && udp_info["DestinationPort(目的端口)"] == "5353")
            {
                DNS mdnsPacket = new DNS(udpPacket.PayloadData, "MDNS");
                this.application_info = mdnsPacket.application_info;
                this.info = mdnsPacket.info;
                this.protocol = "MDNS";
                this.color = "SkyBlue";
            }           
            //SSDP协议
            else if (udp_info["DestinationPort(目的端口)"] == "1900")
            {
                this.color = "PaleGreen";
                this.protocol = "SSDP";
                this.application_info.Add("ApplicationType", "SSDP");

                string ssdptext = System.Text.Encoding.Default.GetString(udpPacket.PayloadData);
                string[] ssdpdata = ssdptext.Split(new char[2] { '\r', '\n' });
                foreach (string i in ssdpdata)
                {
                    if (i != "")
                    {
                        if (i.IndexOf(':') > 0)
                        {
                            this.application_info.Add(i.Substring(0, i.IndexOf(':')), i.Substring(i.IndexOf(':') + 1, i.Length - i.IndexOf(':') - 1));
                        }
                        else
                        {
                            this.info = i;
                            this.application_info.Add("Request", i);
                        }
                    }
                }
            }
            //DB-LSP-DISC协议
            else if (udp_info["SourcePort(源端口)"] == "17500" && udp_info["DestinationPort(目的端口)"] == "17500")
            {
                this.color = "SkyBlue";
                this.protocol = "DB-LSP-DISC";
                this.application_info.Add("ApplicationType", "DB-LSP-DISC");
                this.info = "Dropbox LAN sync Discovery Procotol";

                string dldtext = System.Text.Encoding.Default.GetString(udpPacket.PayloadData);
                this.application_info.Add("TEXT", dldtext);
            }
        }
    }
}
