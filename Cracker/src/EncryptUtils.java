 
/**
 * 生成PMK算法
 * 调用：EncryptUtils.encryptPBKDF2(String ssid, char[] psw);
 * @param ssid wifi的ssid
 * @param psw 待尝试wifi密码
 * @return PMK
 * 
 */
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;  
import javax.crypto.spec.PBEKeySpec;  
 
public class EncryptUtils {  
    public static String encryptPBKDF2(String ssid, String psw) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {  
            int iterations = 4096;  
            char[] chars = psw.toCharArray(); 
            byte[] salt = ssid.getBytes();  
            
            PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 256);  
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");  
            byte[] hash = skf.generateSecret(spec).getEncoded();  
            return toHex(hash);
    }
    /**
     * 将字符数组转化为十六进制字符串
     * @param array 待转化字符数组
     * @return 各字符对应十六进制数
     */
    static String toHex(byte[] array) {  
            BigInteger bi = new BigInteger(1, array);  
            String hex = bi.toString(16);  
            int paddingLength = (array.length * 2) - hex.length();  
            if(paddingLength > 0) {  
                return String.format("%0"  +paddingLength + "d", 0) + hex;  
            }else{  
                return hex;  
            }  
        } 
    /**
     * 单纯把一个多位数字拆成字符数组
     * @param x
     * @return
     */
    static char[] intToPsw(int x){
    	char[] s = "00000000".toCharArray();
    	if(x>9999999){
    		s[0]=(char)(x/10000000+48);
    		x-=x/10000000*10000000;
    	}
    	else if(x>999999){
    		s[1]=(char)(x/1000000+48);
    		x-=x/1000000*1000000;
    	}
    	else if(x>99999){
    		s[2]=(char)(x/100000+48);
    		x-=x/100000*100000;
    	}
    	else if(x>9999){
    		s[3]=(char)(x/10000+48);
    		x-=x/10000*10000;
    	}
    	else if(x>999){
    		s[4]=(char)(x/1000+48);
    		x-=x/1000*1000;
    	}
    	else if(x>99){
    		s[5]=(char)(x/100+48);
    		x-=x/100*100;
    	}
    	else if(x>9){
    		s[6]=(char)(x/10+48);
    		x-=x/10*10;
    	}
    	s[7]=(char)(x+48);
    	return s;
    }
    
}