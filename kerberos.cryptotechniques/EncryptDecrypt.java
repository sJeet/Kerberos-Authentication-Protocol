package kerberos.cryptotechniques;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class EncryptDecrypt {
	//private static final String PBE_DES_ALGORITHM = "PBEWithMD5AndDES";
		private static Cipher ecipher;
		private static Cipher dcipher;
		public static String encrypt(SecretKey key, String plainText) throws Exception {
			
			ecipher = Cipher.getInstance("AES");
			ecipher.init(Cipher.ENCRYPT_MODE, key);
			String charSet = "UTF-8";
			byte encryptedData[] = ecipher.doFinal(plainText.getBytes(charSet));
			String encStr = new sun.misc.BASE64Encoder().encode(encryptedData);
			return encStr;
		}
		
		
		public static String decrypt(SecretKey key, String encryptedText) throws Exception {
			
			dcipher = Cipher.getInstance("AES");
			dcipher.init(Cipher.DECRYPT_MODE, key);
			/*
			 * if eclipse gives error in the below line then do this: Project
			 * Properties->Java Compilers->Errors and Warnings->check Enable Project
			 * Specific Settings->Select Deprecated and Restricted API->change it to
			 * Warning
			 */
			byte[] enc = new sun.misc.BASE64Decoder().decodeBuffer(encryptedText);
			byte[] utf8 = dcipher.doFinal(enc);
			String charSet = "UTF-8";
			String plainStr = new String(utf8, charSet);
			return plainStr;
		}
}
