package kerberos.server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.synth.SynthOptionPaneUI;

import kerberos.cryptotechniques.EncryptDecrypt;
import kerberos.cryptotechniques.HashGenerator;
import kerberos.cryptotechniques.SessionKeyGenerator;
import kerberos.tickets.Ticket;

public class FileServer extends Server {

	private EncryptDecrypt ed;
	private final static String FILE_SERVER_SECRET_KEY = "saltCTS1CS265";
	
	// Keep the TGS session key valid for 15 minutes
	private final static Long TICKET_VALIDITY = 15 * 60 * 1000L;
	private String clientAddress;
	private ServerSocket serverSocket;
	private Ticket fileServerTicketComponents = null;

	public FileServer(int port) {
		super(port);
		ed = new EncryptDecrypt();
	}

	@Override
	protected List<String> parseRequest(Socket socket) throws IOException {
		List<String> inputData = new ArrayList<String>();
		InputStream is = socket.getInputStream();
		InputStreamReader isr = new InputStreamReader(is);
		BufferedReader br = new BufferedReader(isr);

		String message = br.readLine();
		String message1 = br.readLine();
		message += "\n" + message1;

		// Store the client's IP address for future use
		//clientAddress = socket.getRemoteSocketAddress().toString();

		System.out.println("Response received from the Client : " + message);
		String[] parsedMessage = message.split(";");
		inputData = Arrays.asList(parsedMessage);
		String decryptedfileServerTicket = null;
		String encryptedAuthenticator = parsedMessage[0];
		String encryptedFileServerTicket = parsedMessage[1];

		byte[] key = FILE_SERVER_SECRET_KEY.getBytes("UTF-8");
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
			return null;
		}
		MessageDigest sha = null;
		try {
			sha = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
			return null;
		}
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16); // use only first 128 bit

		SecretKeySpec fileServerSecretKeySpec = new SecretKeySpec(key, "AES");

		try {
			decryptedfileServerTicket = ed.decrypt(fileServerSecretKeySpec, encryptedFileServerTicket);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		System.out.println("Decrypted File Server Ticket is: " + decryptedfileServerTicket);
		parsedMessage = decryptedfileServerTicket.split(";");
		fileServerTicketComponents = new Ticket(parsedMessage[0], parsedMessage[1],
				parsedMessage[2], parsedMessage[3]);
		String decryptedFileServerSessionKey = fileServerTicketComponents.getSessionKey();

		byte[] encodedKey = new sun.misc.BASE64Decoder()
				.decodeBuffer(decryptedFileServerSessionKey);
		SecretKey decryptFileServerSessionKeySpec = new SecretKeySpec(encodedKey, 0,
				encodedKey.length, "AES");
		String decryptedAuthenticator = null;

		try {
			decryptedAuthenticator = ed.decrypt(decryptFileServerSessionKeySpec, encryptedAuthenticator);
			System.out.println("Decrypted Authenticator is: "
					+ decryptedAuthenticator);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

		parsedMessage = decryptedAuthenticator.split(";");
		String authenticatorClientId = parsedMessage[0];
		Long authenticatorTimestamp = Long.parseLong(parsedMessage[1]);
		Long ticketEndTimestamp = Long.parseLong(fileServerTicketComponents.getEndTime());

		if (authenticatorTimestamp < ticketEndTimestamp) {
			// session is still valid
			System.out.println("Session is still valid");
			authenticatorTimestamp++ ;
			
			key = decryptedFileServerSessionKey.getBytes("UTF-8");
			keyGen = null;
			try {
				keyGen = KeyGenerator.getInstance("AES");
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
				return null;
			}
			sha = null;
			try {
				sha = MessageDigest.getInstance("SHA-1");
			} catch (NoSuchAlgorithmException e1) {				
				e1.printStackTrace();
				return null;
			}
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // use only first 128 bit
			SecretKeySpec encryptFileServerSessionKeySpec = new SecretKeySpec(key, "AES");

			String encryptedFileServerToClientTimestamp = null;
			try {
				encryptedFileServerToClientTimestamp = ed.encrypt(encryptFileServerSessionKeySpec, Long.toString(authenticatorTimestamp));
			} catch (Exception e) {
				System.err.println("Issue while encrypting Timestamp while sending to client : "
						+ e.getMessage());
				// return "$$$" + "Issue while encrypting TGS Session Key";
			}

			

			// send message to client

			OutputStream os = socket.getOutputStream();
			OutputStreamWriter osw = new OutputStreamWriter(os);
			BufferedWriter bw = new BufferedWriter(osw);
			String messageToClient = encryptedFileServerToClientTimestamp ;

			bw.write(messageToClient);
			bw.flush();
			System.out
					.println("Message sent to the Client: " + messageToClient);

			if (socket != null) {
				socket.close();
			}

		} else {
			// TODO send error report to the client that TGT is expired.
		}

		return inputData;
	}

	@Override
	protected String generateResponse(List<String> inputData)
			throws IOException {
		return null;
	}

	public static void main(String[] args) throws IOException {
		FileServer fs = new FileServer(15002);
		try {
			fs.createSocketAndListen();
		} catch (IOException e) {
			e.printStackTrace();
			throw e;
		}
	}

	@Override
	protected void createSocketAndListen() throws IOException {
		serverSocket = new ServerSocket(super.port);
		System.out.println("File Server Socket created at port : "
				+ super.port);

		Socket socket = null;
		while (true) {
			// Listening the message from the client
			System.out
					.println("File Server now listening for client request.....");
			socket = serverSocket.accept();
			List<String> inputData = parseRequest(socket);
			
			if (socket != null) {
				socket.close();
			}

		}

	}

	@Override
	protected void sendResponse(Socket socket, String response)
			throws IOException {
		// TODO Auto-generated method stub

	}
}
