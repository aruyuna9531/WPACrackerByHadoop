准备工作：

1.安装Hadoop（流程按教程书籍或者百度都可以）

2.启动Hadoop

3.在HDFS根目录下创建目录，名为handshake
（指令：($HADOOP_HOME/bin/)hadoop fs -mkdir /handshake）——$HADOOP_HOME为hadoop安装目录，一般在环境变量里设置。根据教程的方式设置后，hadoop用户是可以直接调用hadoop指令的。如果其他用户需要执行hadoop，则需要hadoop文件的完整路径，并且hadoop文件要开放执行权限。具体操作请百度。
注意一下你创建目录时的用户和handshake目录的权限，要保证可以把分析结果上传到HDFS。

4.把隔壁CaptureAnalyzer分析出来的结果文件上传到上面handshake目录里
（指令：hadoop fs -put $Result hdfs:/handshake）——$Result为分析结果文件，就是使用旁边CaptureAnalyzer分析你的cap包后生成那个文件。
如果上传失败，请检查Hadoop是否启动，以及handshake目录权限。

5.创建BasicDictionary目录，并上传密码字典
（指令：hadoop fs -mkdir /BasicDictionary；hadoop fs -put $Dict hdfs:/BasicDictionary）
你觉得哪些密码有可能会是WiFi密码就扔进字典里，一行一个，不要空格
程序生成或网上下载也可以

6.开始破解
（指令：hadoop jar Cracker.jar -n）
后面那个-n表示如果当前有了SSID对应的pmk字典，那么不再额外生成字典而直接破解（不使用Hadoop），节省时间。如果是-y，则强制更新pmk字典，需要花时间运行Hadoop作业。当然如果本来就没有pmk字典，那么还是会先生成一个。
程序执行完后会在命令行返回破解结果。并会在当前目录下生成“result.txt"存储最后一次破解结果，同时在hdfs里Decrypted目录下存储所有进行过的破解结果（空格前面那个就是密码）。
