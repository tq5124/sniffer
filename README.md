# Sniffer 项目文档

## 概述
1.	运行环境：Windows72.	编译工具：Microsoft Visual Studio 20133.	程序文件列表：Form1.cs、Packet.cs、DNS.cs、SSL.cs、Files.cs
4. 项目地址：[Github](https://github.com/tq5124/sniffer)
5. 程序员：傅雨东（5110369036）、吴天祺（5110369017）## 主要算法
### 1. 抓包
使用SharpPcap库提供的抓包功能。
### 2. 传输层及及其下各层解析
使用SharpPcap库自带的类进行信息提取，对于SharpPcap库中没有提供接口的信息，参照报文格式直接从比特流中提取相应部分。
### 3. 应用层协议解析
针对比较常见的应用层协议分类进行解析

1. `Telnet`：简单地把负载的二进制数据按UTF8编码2. `HTTP`：由于HTTP协议肯定包含”\r\n\r\n”，因此首先判断是否包含”\r\n\r\n”，如不包含则按TCP协议返回，如果包含则对第一个”\r\n\r\n”处进行切割，对切割后的第一部分数据头进行判断，是否包含”HTTP”或”GET”或”POST”，如果包含则认为成功解析为HTTP，将头部信息保存，同时将切割的后半部分按byte数组保存为数据部分，如果头部解析失败则认为是TCP数据包，将整个负载数据按byte数组保存为数据部分。3. `FTP`：将负载数据按默认编码进行编码，如果是进入被动模式的应答则将客户端端口与应答信息中的被动模式端口作为键值对保存，以进行之后的FTP-DATA判断，如果是传输完毕应答，则将该次传输保存的键值对删除。4. `FTP-DATA`：判断是否存在满足的被动模式的键值对，如果存在则判断为FTP-DATA，并将负载数据按byte数组保存为数据部分。5. `SSL`：首先尝试按SSL解析，对得到的content type和version进行分析，如果能成功分析则作为SSL协议继续解析，否则按byte数组保存为数据部分后按TCP数据包解释。作为SSL协议解析时，每次解析完后比对当前解析的长度与负载数据总长，如果未到末尾则认为有下一条SSL信息存在，继续解析。6. `DNS`：参照了http://mydnspackage.codeplex.com/的解析方法进行解析。7. `MDNS、LLMNR、NBNS`：使用wireshark抓取后发现格式与DNS一样，因此使用DNS类进行解析8. `SSDP`：简单地把负载的二进制数据按默认编码编码。9. `DB-LSP-DISC`：简单地把负载的二进制数据按默认编码编码。
### 4. 文件重组
设计一个Files类，保存每一个传输文件的所有信息，具体类接口可见下一部分“主要数据结构”。现说明文件重组主要步骤

1. `找到request packets`：通过遍历所有packets找到某些特征包，表示有一个文件传送。如HTTP文件传送的标志是“GET”开头（由于考虑更多数的情况，如图片、css和js文件，没有重组post包），FTP文件传送的标志是“Response: 150”。这些被称为请求packet
2. `找到header packets`：接下来要找从服务器返回的文件头信息包（如包含http头信息的包）。提取request包中ack字段，寻找后续包中seq=request.ack的包，作为Files的header packet
3. `从头信息中提取字段`：以http头为例，在头信息中我们提取了每个http传送的charset和content-encoding信息。这些会在后续处理中用到
4. `重组数据内容`：从header packet中提取ack字段，之后所有的tcp data的数据包的ack都与之相同。从全部的packets中得到这些数据包，提取其数据字段（由之前的协议分析中得到），重新按其包的序号排序（可能乱序到达），检查校验和剔除出错包，且得到的数据包校验和不能重复（剔除重发包）。得到文件数据的十六进制data
5. `解压缩`：在传输过程中为节省带宽，常将html等文件进行gzip压缩。如果在头信息中的content-encoding字段非空，则需要对data解压。本项目中仅实现了gzip解压（gzip压缩是现在网页文件最流行的压缩方式）。
6. `解码`：data从十六进制到string得转换，需要按照头信息中的charset字段给定的编码方式进行解码。注意：不是所有文件都是utf8编码的，所以解码函数需要根据头信息的charset字段而定。### 5. 其他
1. `规则过滤功能`：采用表达式建立过滤规则的办法，可选的键有ip地址、端口、协议类型等，操作符有相等、不等、包含三种，值是可以自行输入的。支持多条过滤规则同时作用（相互为与运算）。2. `全局关键字搜索`：将所有抓到的包全部遍历，重组出所有文件。在这些文件中搜索用户输入的关键字。
3. `树状列表显示包信息`：点击数据包后会在下方的树状结构中显示包的解析内容，点击选中某个字段后切换不同的数据包会自动选中相同的字段，方便比较；双击某个字段会在右侧显示详细内容。
4. `抓包文件保存和读取`：可以保存和读取pacp文件，文件格式和wireshark相同，可以相互读取和保存。
## 主要数据结构
说明：
* Form1.cs: 窗体类，存放所有控件函数
* Packet.cs: 为每一个到来的数据包实例化一个Packet类型
* DNS.cs: 为DNS协议分析专门建立的类
* SSL.cs: 为SSL协议分析专门建立的类
* Program.cs: 程序入口
* Files: 检测到有传输的文件则实例化一个Files进行文件重组的分析
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138845892741.png" />## 程序测试和说明
接下来说明程序的使用方法和我们进行的压力测试
### 网页抓包和文件抓取
1. 程序启动，选择网卡，再点击开始抓包
2. `刷新网页`，可以看到流量。在本例中我刷新了百度首页。等加载完成后停止抓包
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846240019.png"  style="width: 100%;"/>
3. `过滤规则`。本例中我添加了两条过滤，一个是规定协议是http，一个是包信息以get开头。
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846243911.png"  style="width: 100%;"/>
4. `包信息显示`：在左侧列表中随便选中一个数据包，可以在下方的树状结构中显示详细包信息。点击选中某个包的tcp-源端口字段，切换不同的包可以方便的对比不同包的同一字段。如果字段内容显示不完全可以双击字段。
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846246311.png"  style="width: 100%;"/>
5. `文件重组`：在右侧的选项卡中选择“数据报重组”，点击“过滤文件包”，可以看到所有的文件request包。点击某行即可看到文件重组后的内容，并且在左侧的包列表中看到相关的数据包（实际上是添加了一条关于该端口的过滤规则）
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846250942.png"  style="width: 100%;"/>6. `关键字过滤`：在右侧的选项卡中选择“全局搜索”，输入关键字，如“百度”，可以看到所有包含关键字的数据包和数据片段。提供忽略大小写的支持，提供所有中文的支持
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846264314.png"  style="width: 100%;"/>7. `保存文件`：支持将抓包文件保存成pacp格式，文件可以被wireshark等其他抓包软件读取，如图是我们保存的baidu.pacp在wireshark中打开。
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846287072.png"  style="width: 100%;"/>

### FTP和文件抓取
ftp的使用方式和网页相同，再次仅测试两个ftp客户端同时请求ftp数据时能否正确抓取两个文件
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846328898.png"  style="width: 100%;"/>

如图可见通识打开两个flashfxp进行数据下载并无冲入的问题，出现乱码是因为C#的文本框不支持编码，点击保存文件即可看到正确的文件内容
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846340049.png"  style="width: 100%;"/>

### 抓包压力测试
测试在禁用缓存的情况下刷新sina.com.cn三次，共抓到7027个包。
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846070882.png"  style="width: 100%;"/>

在压力情况下文件重组和全文搜索功能均正常
<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846083647.png"  style="width: 100%;"/>

<img src="https://pt.sjtu.edu.cn/picbucket/70426_138846088198.png"  style="width: 100%;"/>

之后我们还测试了打开Pacp文件所用时间：

* 我们的Sniffer —— 29.36s
* WireShark —— 1.08s

在性能上还是没法和wireshark相比## 遇到的主要问题和解决方法
在项目的进行过程中当然有许多困难，在此列举一些典型的问题和我们的解决方法。
1.	`开始抓包后界面卡死不能停止抓包`：使用线程将抓包和界面操作独立开。2.	`ICMPv6包type无法用类函数正常转为字符串`：对于不能正常识别的type，保持type数值方式输出。3.	`存在使用80端口但实际只是传输数据而非HTTP报文的情况`：针对使用80端口的包按HTTP协议进行解析，如果解析成功则作为HTTP包否则作为TCP数据包。4.	`存在使用443端口但实际只是传输数据而非SSL报文的情况`：针对使用443端口的包按SSL协议进行解析，如果解析成功则作为SSL包否则作为TCP数据包。5.	`DNS包中具体数据包含的域名的不定长特点与特殊格式问题，数据根据不同type的不同解析方式问题`：参照了http://mydnspackage.codeplex.com/的解析方法进行解析。6.	`抓包后发现存在完全相同的包，同时与wireshark比对后发现wireshark不存在该问题`：检查后发现是由于每次停止抓包的时候只是简单的StopCaptur而没有Close，因此再次开启抓包后会造成PacketArrivalEventHandler即包到达处理事件复制，因此同一个包会产生重复，在抓包停止处理中加入Close操作后问题解决。
7. `文件重组后的data无法直接gzip解压`：通过分析对比十六进制数据，我们发现在gzip压缩数据后会有chunked协议在数据的头和尾加上引导信息，真实的数据是以1f8b开头，00结尾的。剔除引导信息后能顺利解压gzip文件
8. `校验和出错`：我们发现从本机出去的包的校验和都是出错的，经查阅资料我们发现是本机的ip校验选项没有开启。在对比wireshark中发现这些包在wireshark中也是算作出错包，所以我们也将这些用红色的底色表示出来。
## 项目还存在的问题
本项目完成了老师在ppt中显示的2项基本内容和3项拓展内容，但还是有很多不足的地方（对比wireshark），故在此列举部分。
1. ICMPv6包的有时候SharpPcap无法检测出来，这时SharpPcap的IP包协议段显示的是IP
2. MDNS、LLMNR、NBNS的数据部分解析
3. MDNS的Additional records与DNS解析方法不同
4. 过滤协议时，诸如过滤DNS不能显示LLMNR等类似wireshark把相同作用的协议一起显示的功能
5. TreeView遇到\r\n或一行过长自动换行的功能
6. Telnet能使用不同编码解码信息
7. FTP的主动模式
8. 根据TCP包的FLAGs判断各种情况，比如重发包等
9. 数据拼接的实时性，即抓到完整的一组包的时候就能完成拼接并显示
10. 各项应用层协议的判断除MDNS外都只是简单的根据端口或尝试解析进行判断是否属于某个协议，可能发生不是该协议却被认为是的可能
11. 众多其他应用层协议的解析未涉及
12. 网络测试是宿舍网，所以可能有些协议的包是抓不到的，没法测试
13. tersmit-encoding: chunked 的解码还没有做，但出现频率不高
14. 过滤条件只能是与，应该加入或的逻辑条件
## 体会与建议
经过这次大作业的锻炼，我不仅基本掌握了C#这门新语言，而且对于各层协议的格式都有了基本的概念，同时对于应用层协议的复杂多变有了深刻的认识。在做大作业的过程中，我发现传输层及以下的各层协议的解析都是容易的，因为它们基本都有固定的报文格式，而且如果有可变部分也是在报文头的最后，但是应用层不同，应用层协议的判断本身就很复杂，有的只需要简单的端口判断，有的则还要看能否按应用层协议解析，甚至MDNS这种协议会要求固定的目标地址；而且应用层的头部信息虽然有固定格式，但是数据部分的多样变化远远超出我的想象，再加上应用层本身协议就多，解析的过程可谓是焦头烂额。但是解析之后对于很多过程都有了深入的理解，比如浏览一个网站时各种js、css、图片等的内容传输过程，ftp被动模式下的数据传输等等。
希望以后基本要求2不要包括应用层的解析，可以换成应用层协议判断，不然要考虑的可能实在太多了。并且如果要求解析应用层的数据的话，希望能够扩大这个大作业小组的人数，不然2个人完全解析常见的应用层包外加其他一些要求实在人数不够。考虑到wireshark的过滤是只过滤显示实际还在抓，我认为过滤和搜索功能其实可以合并，没必要当做两个功能提出。
    
——傅雨东