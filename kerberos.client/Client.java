package kerberos.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import kerberos.cryptotechniques.EncryptDecrypt;
import kerberos.cryptotechniques.EncryptorDecryptor;
import kerberos.cryptotechniques.HashGenerator;

/**
 * Class to implement a client that communicates to Authentication server,
 * Ticket Granting Server for authentication and File server for completing a
 * request on behalf of the user
 */
public class Client {
	static String username;
	static String password;
	static EncryptDecrypt e; // TODO remove e from code and directly use static
								// method encrypt and decrypt
	static String tgt, tgsSessionKey, hashedPassword, fileServerSessionKey,
			fileServerTicket;
	static Long clientToFileServerTimestamp;

	public static void main(String[] args) throws Exception {

		String host = "localhost";
		// Port to talk to authentication server
		int authenticationServerPort = 15000;
		int ticketGrantingServerPort = 15001;
		int fileServerPort = 15002;
		InetAddress address = null;
		try {
			address = InetAddress.getByName(host);
		} catch (UnknownHostException e) {
			System.err.println(" Host Name : " + host + " not found");
			throw e;
		}

		// Communication with Authentication Server
		Socket socket = new Socket(address, authenticationServerPort);
		getUserInput();
		username = username + "\n"; // to send username through socket without
									// waiting

		// Send the message to the server
		OutputStream os = socket.getOutputStream();
		OutputStreamWriter osw = new OutputStreamWriter(os);
		BufferedWriter bw = new BufferedWriter(osw);
		bw.write(username);
		bw.flush();
		System.out.println("Message sent to the Authentication server : "
				+ username);

		// Get return message from the server
		InputStream is = socket.getInputStream();
		InputStreamReader isr = new InputStreamReader(is);
		BufferedReader br = new BufferedReader(isr);
		String message = br.readLine();
		String message1 = br.readLine();
		message += "\n" + message1;
		parseResponseFromAuthenticationServer(message, password);
		if (socket != null) {
			socket.close();
		}

		// Communication with Ticket Granting Server
		socket = new Socket(address, ticketGrantingServerPort);

		// Send the message to the server
		os = socket.getOutputStream();
		osw = new OutputStreamWriter(os);
		bw = new BufferedWriter(osw);
		String messageToTGS = sendRequestToTGS(tgsSessionKey, tgt);
		messageToTGS += "\n";
		System.out.println("Encrypted message to Ticket Granting Server: "
				+ messageToTGS);
		bw.write(messageToTGS);
		bw.flush();

		// Get the message from the Ticket Granting server
		is = socket.getInputStream();
		isr = new InputStreamReader(is);
		br = new BufferedReader(isr);
		message = br.readLine();
		message1 = br.readLine();
		message += "\n" + message1;

		System.out
				.println("Message received from the Ticket Granting Server is : "
						+ message);
		parseResponseFromTicketGrantingServer(message, tgsSessionKey);
		if (socket != null) {
			socket.close();
		}

		// Communication with File Server
		socket = new Socket(address, fileServerPort);

		// Send the message to the server
		os = socket.getOutputStream();
		osw = new OutputStreamWriter(os);
		bw = new BufferedWriter(osw);
		String messageToFileServer = sendRequestToFileServer(
				fileServerSessionKey, fileServerTicket);
		messageToFileServer += "\n";
		System.out.println("Encrypted message to File Server: "
				+ messageToFileServer);
		bw.write(messageToFileServer);
		bw.flush();

		// Get the message from the File server
		is = socket.getInputStream();
		isr = new InputStreamReader(is);
		br = new BufferedReader(isr);
		message = br.readLine();
		// message1 = br.readLine();
		// message += "\n" + message1;

		System.out.println("Message received from the File Server is : "
				+ message);
		parseResponseFromFileServer(message, fileServerSessionKey);
		if (socket != null) {
			socket.close();
		}

	}

	/**
	 * Method to parse the response received from Authentication Server. This
	 * method generates a hash of the password entered by client and uses it
	 * decrypt the message recevied from server. If the entered password is
	 * correct, then the first token received in the message would be the TGS
	 * session key.
	 * 
	 * @param message
	 *            The message received from Authentication server
	 * @param password
	 *            Password enetred by client
	 * @throws Exception
	 */
	private static void parseResponseFromAuthenticationServer(String message,
			String password) throws Exception {
		/*
		 * Check to see if there was any error while the request was handled. If
		 * an error occurred then the message would have only the error message
		 * that would start with "$$$"
		 */
		if (message.charAt(0) == '$' && message.charAt(1) == '$'
				&& message.charAt(2) == '$') {
			// System.err.println("Error occured");
			if (message.contains("Username not found in Database")) {
				System.err.println("Username and Password mismatch");
			} else {
				System.err.println(message.substring(3));
			}
		} else {
			System.out
					.println("Response received from the Authentication server : "
							+ message);
			String[] parsedMessage = message.split(";");
			String encryptedTgsSessionKey = parsedMessage[0];
			String hashedPassword = HashGenerator.calculateHash(password);
			EncryptorDecryptor ed = new EncryptorDecryptor();
			try {
				String decryptedTgsSessionKey = ed.decrypt(hashedPassword,
						encryptedTgsSessionKey);
				System.out.println("TGS Session key recovered : "
						+ decryptedTgsSessionKey);
				tgsSessionKey = decryptedTgsSessionKey;
			} catch (BadPaddingException e) {
				System.err.println("Username and Password mismatch");
			}
			tgt = parsedMessage[1];
			System.out.println("TGT is :" + tgt);

		}
	}

	/**
	 * Method to get user's input from command line
	 * 
	 * @throws IOException
	 */
	private static void getUserInput() throws IOException {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Enter username : \n");
		username = br.readLine();
		System.out.println("Enter password : \n");
		password = br.readLine();
	}

	private static String sendRequestToTGS(String tgsSessionKey, String tgt)
			throws IOException {
		// Generate the request message

		byte[] encodedKey = new sun.misc.BASE64Decoder()
				.decodeBuffer(tgsSessionKey);
		SecretKey originalKey = new SecretKeySpec(encodedKey, 0,
				encodedKey.length, "AES");

		StringBuffer authenticator = new StringBuffer("");
		Long startTime = System.currentTimeMillis();
		String timeStamp = Long.toString(startTime);
		String usrname = username;
		usrname = usrname.replace("\n", "").replace("\r", "");
		authenticator = authenticator.append(usrname).append(";")
				.append(timeStamp);
		System.out.println("Authenticator is : " + authenticator);

		// Encrypting Authenticator
		String encryptedAuthenticator = null;
		try {
			encryptedAuthenticator = e.encrypt(originalKey,
					authenticator.toString());
			System.out.println("Encrypted Authenticator is: "
					+ encryptedAuthenticator);
		} catch (Exception e) {
			System.err
					.println("Error occured during Authenticator Encryption: "
							+ e.getMessage());
			e.printStackTrace();
		}
		return encryptedAuthenticator + ";" + tgt; // TODO Add ID of the
													// requested service to
													// message
	}

	// Request for FileServer
	private static String sendRequestToFileServer(String fileServerSessionKey,
			String fileServerTicket) throws IOException {
		// Generate the request message

		byte[] encodedKey = new sun.misc.BASE64Decoder()
				.decodeBuffer(fileServerSessionKey);
		SecretKey originalKey = new SecretKeySpec(encodedKey, 0,
				encodedKey.length, "AES");

		StringBuffer authenticator = new StringBuffer("");
		clientToFileServerTimestamp = System.currentTimeMillis();
		String timeStamp = Long.toString(clientToFileServerTimestamp);
		String usrname = username;
		usrname = usrname.replace("\n", "").replace("\r", "");
		authenticator = authenticator.append(usrname).append(";")
				.append(timeStamp);
		System.out.println("Authenticator is : " + authenticator);

		// Encrypting Authenticator
		String encryptedAuthenticator = null;
		try {
			encryptedAuthenticator = e.encrypt(originalKey,
					authenticator.toString());
			System.out
					.println("Encrypted Authenticator to be sent to File Server is: "
							+ encryptedAuthenticator);
		} catch (Exception e) {
			System.err
					.println("Error occured during Authenticator Encryption: "
							+ e.getMessage());
			e.printStackTrace();
		}
		return encryptedAuthenticator + ";" + fileServerTicket;
	}

	/**
	 * Method to parse the response received from Authentication Server. This
	 * method generates a hash of the password entered by client and uses it
	 * decrypt the message recevied from server. If the entered password is
	 * correct, then the first token received in the message would be the TGS
	 * session key.
	 * 
	 * @param message
	 *            The message received from Authentication server
	 * @param tgsSessionKey
	 *            Password enetred by client
	 * @throws Exception
	 */
	private static void parseResponseFromTicketGrantingServer(String message,
			String tgsSessionKey) throws Exception {
		/*
		 * Check to see if there was any error while the request was handled. If
		 * an error occurred then the message would have only the error message
		 * that would start with "$$$"
		 */
		if (message.charAt(0) == '$' && message.charAt(1) == '$'
				&& message.charAt(2) == '$') {
			// System.err.println("Error occured");
			if (message.contains("Username not found in Database")) {
				System.err.println("Username and Password mismatch");
			} else {
				System.err.println(message.substring(3));
			}
		} else {
			String[] parsedMessage = message.split(";");
			String encryptedFileServerSessionKey = parsedMessage[0];
			fileServerTicket = parsedMessage[1];
			byte[] key = tgsSessionKey.getBytes("UTF-8");
			KeyGenerator keyGen = null;
			try {
				keyGen = KeyGenerator.getInstance("AES");
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
				return;
			}
			MessageDigest sha = null;
			try {
				sha = MessageDigest.getInstance("SHA-1");
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
				return;
			}
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit

			SecretKeySpec tgsSessionKeySpec = new SecretKeySpec(key, "AES");

			try {
				fileServerSessionKey = e.decrypt(tgsSessionKeySpec,
						encryptedFileServerSessionKey);
			} catch (Exception e) { 
				e.printStackTrace();
				return;
			}

		}
	}

	/**
	 * Method to parse the response received from Authentication Server. This
	 * method generates a hash of the password entered by client and uses it
	 * decrypt the message recevied from server. If the entered password is
	 * correct, then the first token received in the message would be the TGS
	 * session key.
	 * 
	 * @param message
	 *            The message received from Authentication server
	 * @param tgsSessionKey
	 *            Password enetred by client
	 * @throws Exception
	 */
	private static void parseResponseFromFileServer(String message,
			String fileServerSessionKey) throws Exception {
		/*
		 * Check to see if there was any error while the request was handled. If
		 * an error occurred then the message would have only the error message
		 * that would start with "$$$"
		 */
		if (message.charAt(0) == '$' && message.charAt(1) == '$'
				&& message.charAt(2) == '$') {
			// System.err.println("Error occured");
			if (message.contains("Username not found in Database")) {
				System.err.println("Username and Password mismatch");
			} else {
				System.err.println(message.substring(3));
			}
		} else {
			System.out.println("Response received from the File Server : "
					+ message);
			String encryptedTimestampFromFileServer = message;
			byte[] key = fileServerSessionKey.getBytes("UTF-8");
			KeyGenerator keyGen = null;
			try {
				keyGen = KeyGenerator.getInstance("AES");
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
				return;
			}
			MessageDigest sha = null;
			try {
				sha = MessageDigest.getInstance("SHA-1");
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
				return;
			}
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit

			SecretKeySpec fileServerSessionKeySpec = new SecretKeySpec(key,
					"AES");

			String timestamp = null;
			try {
				timestamp = e.decrypt(fileServerSessionKeySpec,
						encryptedTimestampFromFileServer);
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}

			Long timestampFromFileServer = Long.parseLong(timestamp);
			if (timestampFromFileServer == clientToFileServerTimestamp + 1) {
				System.out
						.println("File Server is authenticated to client and now the communication can be started......");
			} else {
				System.out.println("File Server authentication failed....");
			}
		}

	}
}
