using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

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
            // 现在只有http的两个模式，待完善
            if (pck.info.IndexOf("GET") == 0)
            {
                this.request_type = "GET";
            }
            else if (pck.info.IndexOf("POST") == 0)
            {
                this.request_type = "POST";
            }
            else
            {
                this.request_type = "UNKNOWN";
            }
            this.packet_request = pck;
            this.packet_header = this.find_header(packets, index, pck.tcp_info["AcknowledgmentNumber(确认序号)"]);
            this.file_data = this.find_data(packets, index, this.packet_header.tcp_info["AcknowledgmentNumber(确认序号)"]);
            this.file_name = this.find_fileName(pck);
        }

        private packet find_header(System.Collections.ArrayList packets, int index, string ack){
            for (int i = index; i < packets.Count;i++ )
            {
                packet temp = (packet)packets[i];
                if (temp.tcp_info.Count > 0 && temp.tcp_info["SequenceNumber(序号)"] == ack)
                {
                    return temp;
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
                if (temp.tcp_info.Count > 0 && temp.tcp_info["AcknowledgmentNumber(确认序号)"] == ack)
                {
                    long seq = Convert.ToInt64(temp.tcp_info["SequenceNumber(序号)"]);
                    if (temp.tcp_info.ContainsKey("TCP segment data") && !text.ContainsKey(seq))
                    {
                        text.Add(seq, temp.application_byte);
                        text_seq.Add(seq);
                    }
                    else if (temp.application_info.ContainsKey("Data") && !text.ContainsKey(seq))
                    {
                        text.Add(seq, temp.application_byte);
                        text_seq.Add(seq);
                    }
                }
            }
            text_seq.Sort();
            var data = new MemoryStream();
            foreach (long i in text_seq)
            {
                data.Write(text[i], 0, text[i].Length);
            }
            return data.ToArray();
        }

        private string find_fileName(packet pkt){
            string fileName = pkt.info.Split(' ')[1];
            return fileName.Substring(fileName.LastIndexOf("/") + 1);
        }
    }
}
