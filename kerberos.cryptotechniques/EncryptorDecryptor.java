package kerberos.cryptotechniques;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Class to perform Encryption and Decryption of String data. PBE(Password Based
 * Encryption and Decryption) is used to generate secret keys.
 *
 */
public class EncryptorDecryptor {

	private static final String PBE_DES_ALGORITHM = "PBEWithMD5AndDES";
	Cipher ecipher;
	Cipher dcipher;
	// Iteration count
	int iterationCount = 19;

	/**
	 * Method to encrypt the given data using DES algorithm
	 *
	 * @param password
	 *            password to be used for generating secret key to encrypt data
	 * @param plainText
	 *            Plain Text input to be encrypted
	 * @return Returns encrypted text
	 */
	public String encrypt(String password, String plainText) throws Exception {
		// Key generation for encryption
		KeySpec keySpec = new PBEKeySpec(password.toCharArray(),
				getSalt(password), iterationCount);
		// Use DES to encrypt data
		SecretKey key = SecretKeyFactory.getInstance(PBE_DES_ALGORITHM)
				.generateSecret(keySpec);

		// Prepare the parameter to the ciphers
		AlgorithmParameterSpec paramSpec = new PBEParameterSpec(
				getSalt(password), iterationCount);

		// Enc process
		ecipher = Cipher.getInstance(key.getAlgorithm());
		ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
		String charSet = "UTF-8";
		byte[] in = plainText.getBytes(charSet);
		byte[] out = ecipher.doFinal(in);

		/*
		 * if eclipse gives error in the below line then do this: Project
		 * Properties->Java Compilers->Errors and Warnings->check Enable Project
		 * Specific Settings->Select Deprecated and Restricted API->change it to
		 * Warning
		 */
		String encStr = new sun.misc.BASE64Encoder().encode(out);
		System.out.println("Encrypted Data is: " + encStr);
		return encStr;
	}

	/**
	 * Get an 8 byte salt for generating the secret key.
	 *
	 * @param password
	 *            Password to generate salt for.
	 * @return A byte array of length 8 to be used as salt
	 */
	private byte[] getSalt(String password) {
		byte[] salt = new byte[8];
		if (password.length() < 8) {
			throw new IllegalArgumentException("Password too short");
		} else {
			return (password.substring(password.length() - 8).getBytes());
		}

	}

	/**
	 * @param password
	 *            Key used to decrypt data
	 * @param encryptedText
	 *            encrypted text input to decrypt
	 * @return Returns plain text after decryption
	 */
	public String decrypt(String password, String encryptedText)
			throws Exception {
		// Key generation for enc and desc
		KeySpec keySpec = new PBEKeySpec(password.toCharArray(),
				getSalt(password), iterationCount);
		SecretKey key = SecretKeyFactory.getInstance(PBE_DES_ALGORITHM)
				.generateSecret(keySpec);
		// Prepare the parameter to the ciphers
		AlgorithmParameterSpec paramSpec = new PBEParameterSpec(
				getSalt(password), iterationCount);
		// Decryption process; same key will be used for decr
		dcipher = Cipher.getInstance(key.getAlgorithm());
		dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
		/*
		 * if eclipse gives error in the below line then do this: Project
		 * Properties->Java Compilers->Errors and Warnings->check Enable Project
		 * Specific Settings->Select Deprecated and Restricted API->change it to
		 * Warning
		 */
		byte[] enc = new sun.misc.BASE64Decoder().decodeBuffer(encryptedText);
		byte[] utf8 = dcipher.doFinal(enc);
		String charSet = "UTF-8";
		String plainStr = new String(utf8);
		return plainStr;
	}
}
