import java.io.UnsupportedEncodingException;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class ChatServer implements ChatCallback {
	static final boolean DEBUG = true;
	static final String KEYSTORE = "server/keys";
	static final String PASS_STORE = "server/passwords";
	Scanner input;
	CryptoChat cryptoChat;
	ChatInterface server;
	ChatInterface client;
	SecurityOptions securityOptions;

	/**
	 * @param argv
	 */
	public static void main(String[] argv) {
		ChatServer chatServer = new ChatServer();
		chatServer.startServer();
	}

	/**
	 * 
	 */
	public void startServer() {
		try {
			if (System.getSecurityManager() == null) {
				System.setSecurityManager(new SecurityManager());
			}

			input = new Scanner(System.in);
			cryptoChat = new CryptoChat(input, KEYSTORE, PASS_STORE);

			setupChat();
			setupSecureConnection();

			// Wait for client to finish setting up connection
			if (client.isReady()) {
				client.removeReadyLatch();
			} else {
				server.waitForReady().await();
			}

			String msg = "[System] Secure connection established with " + client.getName() + ".";
			System.out.println(msg);

			startChat();

		} catch (Exception e) {
			System.out.println("[System] Server failed: " + e);
		}
	}

	/**
	 * @throws RemoteException
	 * @throws AlreadyBoundException
	 * @throws InterruptedException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void setupChat() throws RemoteException, AlreadyBoundException, InterruptedException,
			UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("Enter Your name and press Enter:");
		String name = input.nextLine().trim();
		securityOptions = cryptoChat.getSecurityOptionsFromUser();

		server = new Chat(name);
		server.registerCallback(this);

		if (securityOptions.confidentiality || securityOptions.integrity || securityOptions.authentication) {
			// Setup public/private keys
			cryptoChat.createKeyPair();
			cryptoChat.createAsymmetricDecryptionCipher();
		}

		Registry registry = LocateRegistry.createRegistry(2020);
		registry.bind("Chat", server);

		System.out.println("[System] Chat Remote Object is ready.");
	}

	/**
	 * @throws RemoteException
	 * @throws InterruptedException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchAlgorithmException
	 */
	public void setupSecureConnection() throws RemoteException, InterruptedException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {
		// Wait for client to connect
		server.waitForConnection().await();

		client = server.getClient();
		System.out.println("[System] " + client.getName() + " is trying to connect.");

		checkSecurityOptions();

		if (securityOptions.confidentiality || securityOptions.integrity || securityOptions.authentication) {
			// Get client's public key
			byte[] clientKeyData = client.sendRequest("getPublicKey");
			cryptoChat.createAsymmetricEncryptionCipher(clientKeyData);
		}

		if (securityOptions.confidentiality || securityOptions.integrity) {
			// Get symmetric key from client
			byte[] encryptedSecretKey = client.sendRequest("getSecretKey");

			// Decrypt the key
			byte[] secretKeyData = cryptoChat.decryptPrivate(encryptedSecretKey);
			cryptoChat.setSecretKey(secretKeyData);
			cryptoChat.createSymmetricCiphers();
		}

		if (securityOptions.integrity) {
			// ??
		}

		if (securityOptions.authentication) {
			// Authenticate the client
			boolean passwordsMatch;
			do {
				byte[] clientPassword = client.sendRequest("getPassword");
				passwordsMatch = cryptoChat.authenticateUser(client.getName(), clientPassword);
				if (!passwordsMatch) {
					client.sendMessage("Invalid password.");
				}
			} while (!passwordsMatch);
		}
	}

	/**
	 * @throws RemoteException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void startChat()
			throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		while (true) {
			String msg = input.nextLine().trim();
			if (server.getClient() != null) {
				ChatInterface client = server.getClient();
				msg = "[" + server.getName() + "] " + msg;

				if (securityOptions.confidentiality) {
					msg = new String(cryptoChat.encryptSymmetric(msg.getBytes()), "UTF-8");
				}

				client.sendMessage(msg);
			}
		}
	}

	/**
	 * @throws RemoteException
	 */
	public void createClientPassword() throws RemoteException {
		// TODO
		// Normally this would be done by some account creation
		// For the purposes of this assignment we will hardcode the password
		// First check if the password file exists already

		// Otherwise create a password
		cryptoChat.createPassword(server.getName(), "verysecretshhh");
	}

	/**
	 * @throws RemoteException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InterruptedException
	 * @throws NoSuchAlgorithmException
	 */
	public void checkSecurityOptions() throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, InterruptedException, NoSuchAlgorithmException {
		// Make sure the security options are the same
		String clientSecurityOptions = new String(client.sendRequest("getSecurityOptions"), "UTF-8");
		boolean optionsMatch = securityOptions.toString().equals(clientSecurityOptions);
		while (!optionsMatch) {
			// Let the client know options don't match
			client.sendMessage("Options don't match");

			// Request new security options from client
			clientSecurityOptions = new String(client.sendRequest("getSecurityOptions"), "UTF-8");

			optionsMatch = securityOptions.toString().equals(clientSecurityOptions);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatCallback#onMessage(byte[])
	 */
	public void onMessage(byte[] message)
			throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		if (securityOptions.confidentiality) {
			message = cryptoChat.decryptSymmetric(message);
		}

		System.out.println(new String(message, "UTF-8"));
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatCallback#onRequest(java.lang.String)
	 */
	public byte[] onRequest(String request) throws RemoteException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InterruptedException {
		if (DEBUG)
			System.out.println("DEBUG  Request: " + request);

		switch (request) {
		case "getPassword":
			return cryptoChat.hashPassword(cryptoChat.getPasswordFromUser());

		case "getPublicKey":
			return cryptoChat.getPublicKey().getEncoded();

		default:
			System.out.println("Uknown request: " + request);
			return null;
		}
	}
}
