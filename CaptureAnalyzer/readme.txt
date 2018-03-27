使用该文件分析捕获的cap包（需要含完整WPA 4次握手帧，只有1次或2次的会返回空）。使用Aircrack-ng捕获的帧就可以，具体教程百度可以得到。

可以先通过WireShark软件分析你的cap，如果右边Info栏有“Key(Message of x)”，且x从1到4全部出现的时候，你就捕获到四次握手，程序会分析出以下信息：

1.SSID（WiFi名字）

2.AMAC & SMAC（无线接入点和移动终端的MAC地址）

3.ANonce & SNonce（无线接入点和移动终端在握手阶段使用的Nonce——这玩意是握手时双方各自临时生成的随机数，可以保证每次连接时使用的无线通信数据加密密钥都不一样，保证传输安全）

4.MIC（上面一堆数据加上WiFi密码通过一系列算法生成的校验码，存放在握手数据帧里，AP会根据这个MIC，判断用户输入的密码是否正确）

5.EAPOL Frame（某个802.11x帧的全部内容（除了MIC），计算生成MIC时需要使用）

执行指令：./CaptureAnalyze $CapName $Result

参数1：$CapName 你cap包的名字

参数2：$Result 输出分析结果文件名字

——————————————————————————————————————————————————————————————

We use this file to analyze our captures.

Use the Aircrack-ng to catch the data, which includes the WPA 4-handshakes

(You can check the existence and the completion by WireShark. If the infos of some frames are as "Key(Message of x)", and "x" are replaced by all numbers from 1 to 4, then you caught complete 4-handshake messages, and can be analyzed. Otherwise, returns nothing.)
