using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Text.RegularExpressions;
using System.Runtime.Serialization.Formatters.Binary;

namespace Sniffer
{
    public class Files
    {
        public string protocol;
        public string request_type;
        public packet packet_request;
        public packet packet_header;
        public string file_name;
        public byte[] file_data;
        public string file_type;
        public string charset;
        public string encoding;

        public Files()
        {
            this.protocol = "";
            this.request_type = "";
            this.packet_request = null;
            this.packet_header = null;
            this.file_name = "";
            this.file_data = null;
        }
        
        public void update(System.Collections.ArrayList packets, int index)
        {
            packet pck = (packet)packets[index];
            this.packet_request = pck;
            this.protocol = pck.protocol;
            // 现在只有http的两个模式和ftp，待完善
            if (pck.info.IndexOf("GET") == 0)
            {
                this.request_type = "GET";
            }
            else if (pck.info.IndexOf("POST") == 0)
            {
                this.request_type = "POST";
            }
            else if (pck.info.IndexOf("Response: 150") == 0)
            {
                this.request_type = "FTP";
            }
            else
            {
                this.request_type = "UNKNOWN";
            }
            this.packet_header = this.find_header(packets, index, pck.tcp_info["AcknowledgmentNumber(确认序号)"]);
            this.charset = this.protocol=="HTTP" ? this.find_charset() : "";
            this.encoding = this.protocol == "HTTP" ? this.find_encoding() : "";
            this.file_data = this.find_data(packets, index, this.packet_header.tcp_info["AcknowledgmentNumber(确认序号)"]);
            this.file_name = this.find_fileName(pck);
            this.file_type = this.file_name.LastIndexOf(".") > 0 ? this.file_name.Substring(this.file_name.LastIndexOf(".")+1) : "";
        }

        private packet find_header(System.Collections.ArrayList packets, int index, string ack){
            for (int i = index; i < packets.Count;i++ )
            {
                packet temp = (packet)packets[i];
                if (temp.tcp_info.Count > 0 && temp.tcp_info["SequenceNumber(序号)"] == ack)
                {
                    if (this.protocol == "HTTP" && temp.application_info.ContainsKey("Head"))
                    {
                        return temp;
                    }
                    else if (this.protocol == "FTP" && temp.info.IndexOf("Response: 150 Opening") == 0)
                    {
                        return temp;
                    }
                }
            }
            return null;
        }

        private byte[] find_data(System.Collections.ArrayList packets, int index, string ack)
        {
            Dictionary<long, byte[]> text = new Dictionary<long, byte[]>();
            List<long> text_seq = new List<long>();
            for (int i = index; i < packets.Count;i++ )
            {
                packet temp = (packet)packets[i];
                switch (this.protocol)
                {
                    case "HTTP":
                        if (temp.tcp_info.Count > 0 && temp.tcp_info["AcknowledgmentNumber(确认序号)"] == ack)
                        {
                            long seq = Convert.ToInt64(temp.tcp_info["SequenceNumber(序号)"]);
                            if (temp.tcp_info.ContainsKey("TCP segment data") && !text.ContainsKey(seq))
                            {
                                text.Add(seq, temp.application_byte);
                                text_seq.Add(seq);
                            }
                            else if (temp.application_info.ContainsKey("Data") && temp.application_info["Data"] != "" && !text.ContainsKey(seq))
                            {
                                text.Add(seq, temp.application_byte);
                                text_seq.Add(seq);
                            }
                        }
                        break;
                    case "FTP":
                        if (temp.protocol == "FTP-DATA" && temp.tcp_info["SourcePort(源端口)"] == this.packet_header.application_info["PASV_PORT"])
                        {
                            long seq = Convert.ToInt64(temp.tcp_info["SequenceNumber(序号)"]);
                            text.Add(seq, temp.application_byte);
                            text_seq.Add(seq);
                        }
                        break;
                }
            }
            text_seq.Sort();
            var data = new MemoryStream();
            foreach (long i in text_seq)
            {
                data.Write(text[i], 0, text[i].Length);
            }
            byte[] result = data.ToArray();
            if (this.encoding == "gzip")
            {
                result = this.gzip_decoding(result);
            }
            return result;
        }

        private string find_fileName(packet pkt){
            if (this.protocol == "HTTP")
            {
                string fileName = pkt.info.Split(' ')[1];
                return fileName.Substring(fileName.LastIndexOf("/") + 1);
            }
            else if (this.protocol == "FTP")
            {
                return pkt.info.Split(' ')[2];
            }
            return "";
        }

        private string find_charset()
        {
            try
            {
                string head = this.packet_header.application_info["Head"];
                Regex search_charset = new Regex(@"(?<=charset=)[a-z0-9-]+\b");
                return search_charset.Match(head).Value;
            }
            catch
            {
                return "";
            }
        }

        private string find_encoding()
        {
            try
            {
                string head = this.packet_header.application_info["Head"];
                Regex search_charset = new Regex(@"(?<=Content-Encoding: )[a-z0-9-]+\b");
                return search_charset.Match(head).Value;
            }
            catch
            {
                return "";
            }
            
        }

        private byte[] gzip_decoding(byte[] data)
        {
            int head_num=0;
            while (true)
            {
                if (data[head_num] == 0x1f && data[head_num + 1] == 0x8b)
                    break;
                head_num++;
            }
            byte[] szSource = new byte[data.Length - head_num];
            Array.Copy(data, head_num, szSource, 0, szSource.Length);
            MemoryStream msSource = new MemoryStream(szSource);
            //DeflateStream  也可以这儿
            GZipStream stream = new GZipStream(msSource, CompressionMode.Decompress);
            byte[] szTotal = new byte[40 * 1024];
            long lTotal = 0;
            byte[] buffer = new byte[8];
            int iCount = 0;
            do
            {
                iCount = stream.Read(buffer, 0, 8);
                if (szTotal.Length <= lTotal + iCount) //放大数组
                {
                    byte[] temp = new byte[szTotal.Length * 10];
                    szTotal.CopyTo(temp, 0);
                    szTotal = temp;
                }
                buffer.CopyTo(szTotal, lTotal);
                lTotal += iCount;
            } while (iCount != 0);
            byte[] szDest = new byte[lTotal];
            Array.Copy(szTotal, 0, szDest, 0, lTotal);
            return szDest;
        }
    }
}
