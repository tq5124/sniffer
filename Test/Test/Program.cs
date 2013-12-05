using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpPcap;

namespace TestConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            //显示SharpPcap版本
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap {0}", ver);

            //获取网络设备
            var devices = LivePcapDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("找不到网络设备");
                return;
            }
            Console.WriteLine();
            Console.WriteLine("以下是目前本计算机上的活动网络设备:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();
            int i = 0;
            foreach (LivePcapDevice dev in devices)
            {
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            //选择要监听的网络设备
            Console.WriteLine();
            Console.Write("-- 请选择一个需要监听的网络设备: ");
            i = int.Parse(Console.ReadLine());
            LivePcapDevice device = devices[i];

            Console.Write("-- 请选择操作：监听通讯[C/c]，多线程监听通讯[T/t]，监听统计[F/f]，发送随机数据包[S/s]? ");
            string resp = Console.ReadLine().ToUpper();

            while (!(resp.StartsWith("C") || resp.StartsWith("F") || resp.StartsWith("T") || resp.StartsWith("S")))
            {
                resp = Console.ReadLine().ToUpper();
            }

            try
            {
                if (resp.StartsWith("C") || resp.StartsWith("F") || resp.StartsWith("T"))
                {
                    //监听过滤条件
                    //string filter = "ip and tcp";
                    string filter = "";

                    //连接设备
                    System.Threading.Thread backgroundThread = null;
                    int readTimeoutMilliseconds = 1000;
                    if (resp.StartsWith("F"))
                    {
                        device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
                        device.SetFilter(filter);
                        device.Mode = CaptureMode.Statistics; //抓包统计
                        device.OnPcapStatistics += new StatisticsModeEventHandler(device_OnPcapStatistics); //抓包统计回调事件
                    }
                    else if (resp.StartsWith("C"))
                    {
                        device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
                        device.SetFilter(filter);
                        device.Mode = CaptureMode.Packets; //抓数据包
                        showDetails = resp.EndsWith("-A"); //当抓数据包时，检查是否要查看详情
                        device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival); //抓数据包回调事件
                    }
                    else
                    {
                        backgroundThread = new System.Threading.Thread(BackgroundThread);
                        backgroundThread.Start();
                        device.Open();
                        device.SetFilter(filter);
                        device.Mode = CaptureMode.Packets; //抓数据包
                        showDetails = resp.EndsWith("-A"); //当抓数据包时，检查是否要查看详情
                        device.OnPacketArrival += new PacketArrivalEventHandler(device_OnThreadPacketArrival); //抓数据包回调事件
                    }      
                    
                    Console.WriteLine();
                    Console.WriteLine("-- 当前TCPdump过滤条件: \"{0}\"", filter);
                    Console.WriteLine("-- 正在监听设备 {0}, 按 '回车' 键以停止监听...", device.Description);

                    //开始监听
                    device.StartCapture();

                    //停止监听
                    Console.ReadLine();
                    device.StopCapture();
                    Console.WriteLine("-- 停止监听.");

                    if (backgroundThread != null)
                    {
                        BackgroundThreadStop = true;
                        backgroundThread.Join();
                    }
                }
                else if (resp.StartsWith("S"))
                {
                    //连接设备
                    device.Open();

                    //生成随机数据包
                    byte[] bytes = GetRandomPacket();

                    try
                    {
                        //发送数据

                        device.SendPacket(bytes);
                        SendQueue squeue = new SendQueue(2000);
                        Console.WriteLine("-- 单个数据包发送成功.");

                        for (int j = 0; j < 10; j++)
                        {
                            if (!squeue.Add(bytes))
                            {
                                Console.WriteLine("-- 警告: 队列大小不足以存放所有数据包，将只发送部分数据包.");
                                break;
                            }
                        }
                        device.SendQueue(squeue, SendQueueTransmitModes.Synchronized);
                        Console.WriteLine("-- 数据包队列发送完毕.");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("-- " + e.Message);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("-- " + e.Message);
            }
            finally
            {
                if (device.Opened)
                {
                    //断开设备连接
                    Console.WriteLine(device.Statistics().ToString());
                    device.Close();
                    Console.WriteLine("-- 断开设备连接.");
                    Console.Write("按 '回车' 键以退出...");
                    Console.Read();
                }
            }
        }

        static bool showDetails = false; //查看详情的参数
        /// <summary>
        /// 抓包方法
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            PcapPorcessContext(e.Packet);
        }

        private static void PcapPorcessContext(PacketDotNet.RawPacket pPacket)
        {
            var time = pPacket.Timeval.Date;
            var len = pPacket.Data.Length;
            var layer = pPacket.LinkLayerType;

            Console.WriteLine("{0}:{1}:{2},{3} Len={4} Layer={5}",
                    time.Hour, time.Minute, time.Second, time.Millisecond, len, layer);

            var packet = PacketDotNet.Packet.ParsePacket(pPacket); //Raw基础包对象

            if (layer == PacketDotNet.LinkLayers.Ethernet) //以太网包
            {
                var ethernetPacket = (PacketDotNet.EthernetPacket)packet;
                System.Net.NetworkInformation.PhysicalAddress srcMac = ethernetPacket.SourceHwAddress;
                System.Net.NetworkInformation.PhysicalAddress destMac = ethernetPacket.DestinationHwAddress;

                Console.WriteLine("MAC:{0} -> {1}", srcMac, destMac);
                if (showDetails) Console.WriteLine("Ethernet packet: " + ethernetPacket.ToColoredString(false));
            }
            var ipPacket = PacketDotNet.IpPacket.GetEncapsulated(packet);  //IP包
            if (ipPacket != null)
            {
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress destIp = ipPacket.DestinationAddress;

                Console.WriteLine("IP: {0} -> {1}", srcIp, destIp);
                if (showDetails) Console.WriteLine("IP packet: " + ipPacket.ToColoredString(false));

                var tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(packet); //TCP包
                if (tcpPacket != null)
                {
                    int srcPort = tcpPacket.SourcePort;
                    int destPort = tcpPacket.DestinationPort;

                    Console.WriteLine("TCP Port: {0} -> {1}", srcPort, destPort);
                    if (showDetails) Console.WriteLine("TCP packet: " + tcpPacket.ToColoredString(false));
                }

                var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(packet); //UDP包
                if (udpPacket != null)
                {
                    int srcPort = udpPacket.SourcePort;
                    int destPort = udpPacket.DestinationPort;

                    Console.WriteLine("UDP Port: {0} -> {1}", srcPort, destPort);
                    if (showDetails) Console.WriteLine("UDP packet: " + udpPacket.ToColoredString(false));
                }
            }
        }

        static ulong oldSec = 0;
        static ulong oldUsec = 0;
        /// <summary>
        /// 抓包统计方法
        /// </summary>
        private static void device_OnPcapStatistics(object sender, StatisticsModeEventArgs e)
        {
            // 计算统计心跳间隔
            ulong delay = (e.Statistics.Timeval.Seconds - oldSec) * 1000000 - oldUsec + e.Statistics.Timeval.MicroSeconds;

            // 获取 Bits per second
            ulong bps = ((ulong)e.Statistics.RecievedBytes * 8 * 1000000) / delay;
            /*                                       ^       ^
                                                     |       |
                                                     |       | 
                                                     |       |
                            converts bytes in bits --        |
                                                             |
                        delay is expressed in microseconds --
            */

            // 获取 Packets per second
            ulong pps = ((ulong)e.Statistics.RecievedPackets * 1000000) / delay;

            // 将时间戳装换为易读格式
            var ts = e.Statistics.Timeval.Date.ToLongTimeString();

            // 输出统计结果
            Console.WriteLine("{0}: bps={1}, pps={2}", ts, bps, pps);

            //记录本次统计时间戳，以用于下次统计计算心跳间隔
            oldSec = e.Statistics.Timeval.Seconds;
            oldUsec = e.Statistics.Timeval.MicroSeconds;
        }

        /// <summary>
        /// 生成一个大小为200的随机数据包
        /// </summary>
        private static byte[] GetRandomPacket()
        {
            byte[] packet = new byte[200];
            Random rand = new Random();
            rand.NextBytes(packet);
            return packet;
        }

        /// <summary>
        /// 生成一个大小为98的数据包
        /// </summary>
        private static byte[] GetPacket()
        {
            /*
            byte[] packet = new byte[98]
            {
                0x00,0x02,0x65,0x11,0xa6,0x05,                     //srcMac
                0x00,0x1b,0x38,0xa5,0xc2,0x40,                     //destMac
                0x08,0x00,                                         //Type Ip
                0x45,                                              //Version 4
                0x00,                                              //Differentiated Services Field 分隔符
                0x00,0x54,                                         //Total Length 84
                0x43,0x08,                                         //Identification 校验位
                0x40,0x00,                                         //Fragment offset 片偏移
                0x80,                                              //Time to live 生存时间
                0x06,                                              //Protocol TCP
                0x40,0x00,                                         //Header checksum 报头校验和
                0xc0,0xa8,0x00,0x71,                               //srcIP
                0xc0,0xa8,0x00,0x6a,                               //destIP
                0x26,0x8e,                                         //srcPort
                0x04,0x04,                                         //destPort
                0x5b,0x0c,0x5e,0xc7,                               //Sequence number 序号
                0xca,0xf9,0x1b,0xb1,                               //Acknowledgement number 应答号
                0x80,                                              //Header Length 32
                0x18,                                              //Flags [PSH,ACK]
                0x41,0x10,                                         //Window size
                0x82,0x72,                                         //Checksum 校验和
                0x01,                                              //Options NOP
                0x01,                                              //Options NOP
                0x08,0x0a,0x00,0x00,0xac,0x4c,0x00,0x41,0x50,0xaa, //Options Timestamps
                0x21,                                              //Data Start 这之后是我这个项目中的服务器和终端通讯的特有的附加数据
                0x0a,                                              //Command
                0x00,0x00,                                         //CID
                0x01,0x00,0x00,0x00,                               //TID
                0x00,0x00,0x00,0x00,                               //Param1
                0x00,0x00,0x00,0x00,                               //Param2
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,           //Param3
                0x30,0x30,0x30,0x30,                               //ErrorCode
                0x00,0x00,0xec,0x00                                //ExtraData
            };
            */
            //return packet;
            return new byte[98];
        }

        private static DateTime LastStatisticsOutput = DateTime.Now;
        private static TimeSpan LastStatisticsInterval = new TimeSpan(0, 0, 2);
        private static void device_OnThreadPacketArrival(object sender, CaptureEventArgs e)
        {
            //输出设备通讯统计信息
            var Now = DateTime.Now;
            var interval = Now - LastStatisticsOutput;
            if (interval > LastStatisticsInterval)
            {
                Console.WriteLine("Device Statistics: " + ((LivePcapDevice)e.Device).Statistics());
                LastStatisticsOutput = Now;
            }

            lock (QueueLock)
            {
                PacketQueue.Add(e.Packet); //将捕获到的数据包加入处理队列
            }
        }

        /// <summary>
        /// 多线程处理数据包队列
        /// </summary>
        private static void BackgroundThread()
        {
            while (!BackgroundThreadStop)
            {
                bool shouldSleep = true;

                lock (QueueLock)
                {
                    if (PacketQueue.Count != 0)
                    {
                        shouldSleep = false;
                    }
                }

                if (shouldSleep)
                {
                    System.Threading.Thread.Sleep(250);
                }
                else //处理队列
                {
                    List<PacketDotNet.RawPacket> ourQueue; //本线程待处理队列
                    lock (QueueLock)
                    {
                        ourQueue = PacketQueue;
                        PacketQueue = new List<PacketDotNet.RawPacket>();
                    }

                    Console.WriteLine("BackgroundThread: Local Queue Count is {0}", ourQueue.Count);

                    foreach (var packet in ourQueue)
                    {
                        PcapPorcessContext(packet);
                    }
                }
            }
        }
        private static bool BackgroundThreadStop = false; //线程停止标识
        private static object QueueLock = new object(); //线程锁变量
        private static List<PacketDotNet.RawPacket> PacketQueue = new List<PacketDotNet.RawPacket>(); //待处理数据包队列
    }
}
