
/**
 * 利用Hadoop生成PMK字典主入口。
 * 格式与普通MapReduce程序的main函数基本完全一致，只是加了一些提示文字。
 * 具体请参考Hadoop MapReduce教程。
 */

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.mapreduce.lib.input.FileInputFormat;
import org.apache.hadoop.mapreduce.lib.output.FileOutputFormat;

public class PMKMain {
	public static void PMKCreate(String ssid) throws Exception {
		Configuration conf = new Configuration();
		conf.set("fs.default.name", "hdfs://localhost:9000");
		Job job = Job.getInstance(conf, "PMK");
		job.setJarByClass(PMKMain.class);
		job.setMapperClass(PMKMapper.class);
		job.setReducerClass(PMKReducer.class);
		job.setMapOutputKeyClass(Text.class);
		job.setMapOutputValueClass(Text.class);
		job.setOutputKeyClass(Text.class);
		job.setOutputValueClass(Text.class);
		FileInputFormat.addInputPath(job, new Path("/BasicDictionary"));
		FileOutputFormat.setOutputPath(job, new Path("/pmk_" + ssid));

		System.out.println("Start PMK Dict creating for ssid:" + ssid);
		long startMili = System.currentTimeMillis();
		int successs = job.waitForCompletion(true) ? 0 : 1;
		long endMili = System.currentTimeMillis();
		if (successs == 0) {
			System.out.println("Success, PMK Dict Create Time: " + (endMili - startMili) + " ms.");
		} else
			System.out.println("Fail");
	}
}
