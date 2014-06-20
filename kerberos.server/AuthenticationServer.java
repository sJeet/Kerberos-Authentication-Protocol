package kerberos.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


import kerberos.cryptotechniques.EncryptDecrypt;
import kerberos.cryptotechniques.EncryptorDecryptor;
import kerberos.cryptotechniques.SessionKeyGenerator;
import kerberos.database.JdbcConnection;

/**
 * Class to implement the functionality of AuthenticationServer (AS) in Kerberos
 */
public class AuthenticationServer extends Server {
	private EncryptorDecryptor ed;
	private EncryptDecrypt e;
	private final static String TGS_SECRET_KEY = "saltTGS1CS265";
	// Keep the TGS session key valid for 15 minutes
	private final static Long TICKET_VALIDITY = 15 * 60 * 1000L;
	private String clientAddress;
	private ServerSocket serverSocket;

	public AuthenticationServer(int port) {
		super(port);
		ed = new EncryptorDecryptor();

	}

	@Override
	protected List<String> parseRequest(Socket socket) throws IOException {
		List<String> inputData = new ArrayList<String>();
		InputStream is = socket.getInputStream();
		InputStreamReader isr = new InputStreamReader(is);
		BufferedReader br = new BufferedReader(isr);
		// AS only needs to read Username from the client
		String username = br.readLine();

		inputData.add(username);
		// Store the client's IP address for future use
		clientAddress = socket.getRemoteSocketAddress().toString();
		return inputData;
	}

	@Override
	protected String generateResponse(List<String> inputData) throws UnsupportedEncodingException {
		String username = inputData.get(0);
		JdbcConnection jdbc = new JdbcConnection();
		String hashedPassword = null;
		try {
			hashedPassword = jdbc.getHashedPassword(username);
		} catch (ClassNotFoundException | SQLException e) {
			System.err.println("Database connection issue: " + e.getMessage());
			return "$$$"
					+ "Database Connection issue..Please try again after sometime......";
		} catch (IllegalArgumentException iae) {
			System.err.println("Username not found : " + iae.getMessage());
			return "$$$"
					+ "Username not found in Database..Please provide valid username.........";

		}

		// Generate a random session key to be used as TGS Session key
		String tgsSessionKey = SessionKeyGenerator.generateSessionKey();
		System.out.println("Generated TGS Session Key :" + tgsSessionKey);
		Long startTime = System.currentTimeMillis();
		Long endTime = startTime + TICKET_VALIDITY;

		String encryptedTgsSessionKey;
		try {
			encryptedTgsSessionKey = ed.encrypt(hashedPassword, tgsSessionKey);
		} catch (Exception e) {
			System.err.println("Issue while encrypting TGS Session Key : "
					+ e.getMessage());
			return "$$$" + "Issue while encrypting TGS Session Key";
		}

		// Generate the response meesage
		StringBuffer tgtString = new StringBuffer("");
		tgtString = tgtString.append(username).append(";")
				.append(clientAddress).append(";").append(endTime).append(";")
				.append(tgsSessionKey);
		System.out.println("TGT is : " + tgtString);

		// Encrypting TGT
		String encryptedTgt;
		byte[] key = TGS_SECRET_KEY.getBytes("UTF-8");
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e1) {
			
			e1.printStackTrace();
		}
		MessageDigest sha = null;
		try {
			sha = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e1) {
			
			e1.printStackTrace();
		}
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16); // use only first 128 bit

		SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
		
		try {
			encryptedTgt = e.encrypt(secretKeySpec, tgtString.toString());
			System.out.println("Encrypted TGT is: " + encryptedTgt);
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Issue while encrypting TGT: " + e.getMessage());
			
			return "$$$" + "Issue while encrypting TGT";
			
		}
		
		return encryptedTgsSessionKey + ";" + encryptedTgt;
	}

	public static void main(String[] args) throws IOException {
		AuthenticationServer as = new AuthenticationServer(15000);
		try {
			as.createSocketAndListen();
		} catch (IOException e) {
			e.printStackTrace();
			throw e;
		}
	}
	
	@Override
	protected void createSocketAndListen() throws IOException {
		serverSocket = new ServerSocket(super.port);
		System.out.println("Server Socket created at port : " + port);

		Socket socket = null;
		while (true) {
			// Listening the message from the client
			System.out.println("Server now listening for client request.....");
			socket = serverSocket.accept();
			List<String> inputData = parseRequest(socket);
			System.out.println("Parsed List of client Data is :");
			for (String a : inputData) {
				System.out.println(a);
			}
			String response = generateResponse(inputData);

			sendResponse(socket, response);
			if (socket != null) {
				socket.close();
			}

		}
		
	}
	
	@Override
	protected void sendResponse(Socket socket, String response)
			throws IOException {
		OutputStream os = socket.getOutputStream();
		OutputStreamWriter osw = new OutputStreamWriter(os);
		BufferedWriter bw = new BufferedWriter(osw);
		bw.write(response);
		bw.flush();
	}
}
