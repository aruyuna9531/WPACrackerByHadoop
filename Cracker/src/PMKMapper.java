/**
 * MapReduce生成PMK字典，Map类实现。
 * 具体请查阅MapReduce教程。
 */

import java.io.IOException;
import java.util.StringTokenizer;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Mapper;

public class PMKMapper extends Mapper<Object, Text, Text, Text>{
	private Text SSID = new Text();
	private Text Password = new Text();
	@SuppressWarnings("deprecation")
	
	public void getSSID() throws IOException{
		Configuration conf = new Configuration();
		FileSystem fs = FileSystem.get(conf);
		FSDataInputStream dis = fs.open(new Path("/handshake/handshakeAnalyze.txt"));
		SSID.set(dis.readLine());
		dis.close();
	}
	public void map(Object key, Text value, Context context) throws IOException, InterruptedException{
		/* Map输出对象：Psk（psk是key）,ssid */
		StringTokenizer stk = new StringTokenizer(value.toString());
		getSSID();
		while(stk.hasMoreTokens()){
			Password.set(stk.nextToken());
			context.write(Password, SSID);
		}
	}
}
