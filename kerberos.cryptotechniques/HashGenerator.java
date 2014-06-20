package kerberos.cryptotechniques;

import java.security.MessageDigest;
import java.util.Formatter;

/**
 * Class to generate Hash for given messages
 */
public class HashGenerator {

	/**
	 * Method to calculate has for the given message using SHA1 algorithm
	 * 
	 * @param message
	 *            Message to generate Hash for
	 * @return Hash for the given message
	 * @throws Exception
	 */
	public static String calculateHash(String message) throws Exception {
		MessageDigest algorithm = MessageDigest.getInstance("SHA1");
		algorithm.update(message.getBytes());
		byte[] hash = algorithm.digest();

		// System.out.println(hash + "in bytes");
		return byteArray2Hex(hash);
	}

	/**
	 * Converts the given byte array to a Hex String
	 * 
	 * @param hash
	 *            Byte array to convert
	 * @return A string containing the Hex values for values in the given byte
	 *         array
	 */
	private static String byteArray2Hex(byte[] hash) {
		Formatter formatter = new Formatter();
		for (byte b : hash) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
	}
}
