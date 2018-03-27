import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import java.util.Date;
import java.text.SimpleDateFormat;

public class MainClass {
	public static StringBuffer SSID = new StringBuffer("");

	/**
	 * 主函数
	 * @param args
	 *            "-Y"表示强制生成pmk字典，其他参数则若已存在字典则不生成（不存在照常生成）
	 */
	@SuppressWarnings("deprecation")
	public static void main(String[] args) {
		try {
			Configuration conf = new Configuration();
			FileSystem fs = FileSystem.get(conf);
			Path src = new Path("/handshake/handshakeAnalyze.txt");
			Path output = new Path("/Result/result.txt");
			/* 删除原来的结果文件，建立一个新的 */
			if (fs.exists(output)) {
				fs.delete(output);
			}
			FSDataOutputStream dos = fs.create(output);
			/* 没找到握手包分析结果文件，报错退出。 */
			if (fs.exists(src) == false) {
				System.err.println("Handshake capture file handshakeAnalyze.txt does not exist. Exit");
				System.exit(1);
			}
			/* 提取分析结果 */
			FSDataInputStream dis = fs.open(src);
			dis.seek(0);
			SSID.append(dis.readLine());
			/* 寻找是否已存在PMK字典 */
			Path pmk = new Path("/pmk_" + SSID + "/part-r-00000");
			boolean DictCreateSignal = false;
			if (fs.exists(pmk)) {
				/* 若存在，接收后面的指令，如果是-Y或-y就强制更新字典，否则用已有的字典 */
				if (args.length != 0 && (args[0].compareTo("-Y") == 0 || args[0].compareTo("-y") == 0)) {
					DictCreateSignal = true;
					System.out.println(
							"WARNING: Update the Dict will pay much time to wait according to the size of PSK dict, your hadoop's total CPU and RAM.");
				}
			} else {
				/* 不存在，新建字典 */
				System.out.println("Dict of SSID: " + SSID + " does not exist. Creating..");
				DictCreateSignal = true;
			}
			/* 需要新建/更新字典时 */
			if (DictCreateSignal == true) {
				/* 删除原来的字典 */
				if (fs.delete(new Path("/pmk_" + SSID), true) == false) {
					System.err.println("Warning: Delect Failed. Maybe dict does not exist.");
				}
				/* 启动Hadoop，创建字典 */
				PMKMain.PMKCreate(SSID.toString());
			}
			/* 根据HDFS内该SSID的PMK字典，寻找密码。找密码的具体请参阅Find函数。
			 * 如果找到密码，Key参数会得到这个密码，否则得到一个null。
			 *  */
			String Key = FindKey.Find("/handshake/handshakeAnalyze.txt");
			System.out.println("SSID: " + SSID + ", ");
			if (Key != null) {
				/* 找到密码时，输出该密码，并写入Result。 */
				System.out.println("Password found: " + Key);
				dos.write(("Key Found: " + Key).getBytes());
			} else {
				/* 未找到密码，提示未找到，写入Result。 */
				System.out.println("Password not found.");
				dos.write("Key not found.".getBytes());
			}
			/* 记录运行时的系统时间 */
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			dos.write(("\nLast execution at: " + dateFormat.format(new Date()) + " UTC+0. ").getBytes());
			dos.write(("\nSSID = " + SSID).getBytes());
			fs.delete(new Path("/handshake/handshakeAnalyze.txt"), true);
			// fs.copyToLocalFile(false, output, new Path("/var/www/html"));
			dos.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
