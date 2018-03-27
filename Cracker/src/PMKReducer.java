/**
 * MapReduce生成PMK字典，Reduce类实现。
 * 具体请查阅MapReduce教程。
 */

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Reducer;

public class PMKReducer extends Reducer<Text, Text, Text, Text>{
	private Text PMK=new Text();
	public void reduce(Text key, Iterable<Text> values, Context context) throws IOException, InterruptedException{
		//输入：PSK（Text），SSID（Text）；输出：PSK，PMK（Text）
		for(Text val:values){
				try {
					String tmp = EncryptUtils.encryptPBKDF2(val.toString(), key.toString());
					PMK.set(tmp);
				} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			//System.out.println("PMK "+key+" Created");
		}
		context.write(key, PMK);
	}
}
