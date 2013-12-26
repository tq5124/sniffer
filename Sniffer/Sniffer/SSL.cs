using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Sniffer
{
    class SSL
    {
        public Dictionary<string, string> application_info;
        public string info;
        public string protocol;
        public int length;

        /// <summary>
        /// 构造函数
        /// </summary>
        public SSL(byte[] sslData, string info)
        {

            this.application_info = new Dictionary<string, string>();
            int offset = 0;
            string data = "";
            this.info = info;
            this.protocol = "TCP";
            if (sslData.Length > 0)
            {
                while (offset < sslData.Length)
                {
                    string content_type = sslData[offset].ToString();
                    offset++;
                    string version = ((sslData[offset] << 8) + sslData[offset + 1]).ToString();
                    offset += 2;
                    string length = ((sslData[offset] << 8) + sslData[offset + 1]).ToString();
                    offset += 2;
                    offset += int.Parse(length);

                    bool is_ssl_flag = true;
                    content_type = get_content_type(content_type);
                    if (content_type == "")
                    {
                        is_ssl_flag = false;
                    }
                    version = get_version(version);
                    if (version == "")
                    {
                        is_ssl_flag = false;
                    }

                    if (is_ssl_flag)
                    {
                        this.protocol = version;
                        this.info += content_type + " ";
                        this.length = int.Parse(length);
                        /*
                        this.application_info.Add("ApplicationType", "SSL");
                        this.application_info.Add("Content Type", content_type);
                        this.application_info.Add("Version", version);
                        this.application_info.Add("Length", length);
                        */
                        data += "Content Type: " + content_type + "\r\n" + "Version: " + version + "\r\n" + "Length: " + length + "\r\n\r\n";
                    }
                    else
                    {
                        this.protocol = "TCP";
                        this.info = "TCP segment of a reassembled PDU";
                        data = "";
                        foreach (byte i in sslData)
                        {
                            data += Convert.ToString(i, 16).ToUpper().PadLeft(2, '0');
                        }
                        this.application_info.Add("Data", data);
                        return;
                    }
                }
                this.application_info.Add("ApplicationType", "SSL");
                this.application_info.Add("Data",data);
            }
        }
        /// <summary>
        /// 获取内容类型
        /// </summary>
        string get_content_type(string type)
        {
            switch (type)
                {
                    case "20":
                        return "ChangeCipherSpec";
                    case "21":
                        return "Alert";
                    case "22":
                        return "Handshake";
                    case "23":
                        return "Application";
                    default:
                        return "";
                }
        }
        /// <summary>
        /// 版本号
        /// </summary>
        string get_version(string version)
        {
            switch (version)
                {
                    case "768":
                        return "SSL 3.0";
                    case "769":
                        return "TLS 1.0";
                    case "770":
                        return "TLS 1.1";
                    case "771":
                        return "TLS 1.2";
                    default:
                        return "";
                }
        }
    }    
}
