
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

public class HmacSHA1 {

	private static final String MAC_NAME = "HmacSHA1";

	/**
	 * SHA1加密算法
	 * 
	 * @param encryptText
	 *            加密的Text内容（生成PTK时为Pairwise...等拼接字段，生成MIC（仅限wpa2加密）为第2次握手Auth字段）
	 * @param encryptKey
	 *            加密的Key（生成PTK时使用PMK，生成MIC时使用PTK的前16字节）
	 * @return 加密后的结果（8位2进制形式存储）
	 * @throws Exception
	 *             加密模式不存在异常
	 */
	private static byte[] HmacSHA1Encrypt(byte[] encryptText, byte[] encryptKey) throws Exception {
		SecretKey secretKey = new SecretKeySpec(encryptKey, MAC_NAME);
		Mac mac = Mac.getInstance(MAC_NAME);
		mac.init(secretKey);
		return mac.doFinal(encryptText);
	}

	/**
	 * 数字转换为byte（似乎大于128的要转为负数？）
	 * 
	 * @param x
	 *            待转换数字
	 * @return 转换后的byte
	 */
	private static byte ToByte(int x) {
		if (x > 127)
			return (byte) (x - 256);
		else
			return (byte) x;
	}

	/**
	 * 将byte数组以radix进制字符串的形式存储（但如果转换后开头是0都会被去掉，因此后面需要再处理）
	 * 
	 * @param bytes
	 *            待转换byte数组
	 * @param radix
	 *            进制（2,8,16）
	 * @return 转换后的字符串
	 */
	private static String binary(byte[] bytes, int radix) {
		return new BigInteger(1, bytes).toString(radix);
	}

	/**
	 * 生成PTK时，需要拼接标签，这是拼接函数
	 * 
	 * @param a
	 *            拼接的第一部分（Label）
	 * @param b
	 *            拼接的第二部分（Seed）
	 * @param x
	 *            最后一个字符（生成PTK时LabelSeed的组合是：Label（0~21B）+0（22B）+Seed（23~98B）+i（
	 *            迭代次数-1，99B））
	 * @return 合并后的LabelSeed
	 */
	private static byte[] ByteMergeForLabelseed(byte[] a, byte[] b, int x) {
		byte[] tmp = new byte[100];
		for (int i = 0; i < a.length; i++) {
			tmp[i] = a[i];
		}
		tmp[22] = 0;
		for (int i = 0; i < b.length; i++) {
			tmp[i + 23] = b[i];
		}
		tmp[99] = (byte) x;
		return tmp;
	}

	/**
	 * 生成PTK的SHA1_PRF函数
	 * 
	 * @param secret
	 *            密钥（PMK）
	 * @param label
	 *            标签（字符串"Pairwise key expansion"，区分大小写，有空格）
	 * @param seed
	 *            种子（两个MAC先小后大拼接，后面两个Nonce先小后大拼接）
	 * @return 生成的PTK（64字节，512位）
	 * @throws Exception
	 */
	private static byte[] PTK(byte[] secret, byte[] label, byte[] seed) throws Exception {
		byte[] total = new byte[64];
		int counter = 0;
		for (int i = 0; i < 4; i++) {
			byte[] labelseed = ByteMergeForLabelseed(label, seed, i);
			byte[] a = HmacSHA1Encrypt(labelseed, secret);
			for (int j = 0; j < 20 && counter < 64; j++) {
				total[20 * i + j] = a[j];
				counter++;
			}
		}
		return total;
	}

	/**
	 * 对比MIC（返回True则这个就是正确密码）
	 * 
	 * @param MIC
	 *            真实MIC（从第2次握手中直接提取的值）
	 * @param Cal
	 *            计算出来的MIC（由PTK和握手数据生成）
	 * @return 是否一致
	 */
	private static boolean compareMic(byte[] MIC, byte[] Cal) {
		for (int i = 0; i < 16; i++) {
			if (MIC[i] != Cal[i])
				return false;
		}
		return true;
	}

	/**
	 * 入口函数：从文件中获得的pmk，seed，data, mic值计算并对比结果
	 * 
	 * @param pmkI
	 *            待对比PMK（从Hadoop生成文件中提取）
	 * @param seedI
	 *            种子（从包分析文件中提取AMAC,SMAC,ANonce,SNonce拼接）
	 * @param KeyDataI
	 *            第2次握手包的802.1X Authentication报文（从包分析文件提取）
	 * @param RealMICI
	 *            第2次握手包中提取的MIC值
	 * @return MIC是否匹配
	 * @throws Exception
	 */
	public static boolean Process(String pmkI, String seedI, String KeyDataI, String RealMICI) throws Exception {
		/* 初始化 */
		byte[] Label = "Pairwise key expansion".getBytes();
		byte[] pmk = CharToByte(pmkI.toCharArray());
		byte[] seed = CharToByte(seedI.toCharArray());
		/* 已知三项，生成PTK */
		byte[] ptk = PTK(pmk, Label, seed);
		/*
		 * PTK的前16字节为计算MIC的Key。 
		 * 其余字节在建立连接后传输数据阶段有用，但现在不需要。
		 * 若需要时可改写，增添功能。
		 * */
		byte[] MICKey = new byte[16];
		for (int i = 0; i < 16; i++)
			MICKey[i] = ptk[i];
		/* 初始化802.11x Data */
		byte[] KeyData = CharToByte(KeyDataI.toCharArray());
		/* 计算MIC，取前16字节。
		 * WPA2加密可直接使用SHA1算法，如果是WPA加密需要重新引入MD5算法计算MIC。
		 * 本工程没有MD5计算的方法，需要时可以查阅资料引用，此处从略。
		 *  */
		byte[] MICtmp = HmacSHA1Encrypt(KeyData, MICKey);
		byte[] MIC = new byte[16];
		for (int i = 0; i < 16; i++) {
			MIC[i] = MICtmp[i];
		}
		/* 比对计算出来的MIC和从包里提出来的真实MIC。 */
		char[] MICComp = new char[32];
		char[] MICchar = binary(MIC, 16).toCharArray();
		/* 不重要：由于binary方法的问题，有可能需要前置补0。具体请往上查阅binary方法。 */
		if (MICchar.length < 32) {
			for (int i = 0; i < 32 - MICchar.length; i++) {
				MICComp[i] = '0';
			}
			for (int i = 0; i < MICchar.length; i++) {
				MICComp[i + 32 - MICchar.length] = MICchar[i];
			}
		} else
			for (int i = 0; i < 32; i++) {
				MICComp[i] = MICchar[i];
			}
		byte[] RealMIC = CharToByte(RealMICI.toCharArray());
		/* 返回比对结果 */
		return compareMic(RealMIC, MIC);
	}

	private static int CharToInt(char x) throws IllegalHexException {
		switch (x) {
		case '0':
			return 0;
		case '1':
			return 1;
		case '2':
			return 2;
		case '3':
			return 3;
		case '4':
			return 4;
		case '5':
			return 5;
		case '6':
			return 6;
		case '7':
			return 7;
		case '8':
			return 8;
		case '9':
			return 9;
		case 'A':
		case 'a':
			return 10;
		case 'B':
		case 'b':
			return 11;
		case 'C':
		case 'c':
			return 12;
		case 'D':
		case 'd':
			return 13;
		case 'E':
		case 'e':
			return 14;
		case 'F':
		case 'f':
			return 15;
		default:
			throw new IllegalHexException(x + " is not a legal hex number.");
		}
	}

	private static byte SingleCharToByte(char x1, char x2) {
		int tmp = 0;
		try {
			tmp = CharToInt(x1) * 16 + CharToInt(x2);
		} catch (IllegalHexException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ToByte(tmp);
	}

	/**
	 * 十六进制字符串流转为同样长度的byte数组
	 * 
	 * @param x
	 * @return
	 */
	private static byte[] CharToByte(char[] x) {
		byte[] tmp = new byte[x.length / 2];
		for (int i = 0; i < x.length / 2; i++) {
			tmp[i] = SingleCharToByte(x[i * 2], x[i * 2 + 1]);
		}
		return tmp;
	}
}
