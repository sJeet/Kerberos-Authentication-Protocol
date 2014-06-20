package kerberos.cryptotechniques;

import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SessionKeyGenerator {
	private static final String SECURE_RANDOM_ALGO_NAME = "SHA1PRNG";

	public static String generateSessionKey() {
		SecureRandom sr;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey key = keyGen.generateKey();
			byte[] encoded = key.getEncoded();
			//String s = encoded.toString();
			//System.out.println("\n" + s + "\n");
			String encKey = new sun.misc.BASE64Encoder().encode(encoded);
			//sr = SecureRandom.getInstance(SECURE_RANDOM_ALGO_NAME);
			//return Long.toHexString(sr.nextLong()).toUpperCase();
			return encKey;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
}
