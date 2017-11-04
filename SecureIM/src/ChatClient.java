import java.io.UnsupportedEncodingException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

public class ChatClient implements ChatCallback {
	static final boolean DEBUG = true;
	static final String KEYSTORE = "client/keys";
	static final String PASS_STORE = "client/passwords";
	Scanner input;
	ChatInterface server;
	ChatInterface client;
	CryptoChat cryptoChat;
	SecurityOptions securityOptions;

	public static void main(String[] argv) {
		ChatClient chatClient = new ChatClient();
		chatClient.startClient();
	}

	/**
	 * 
	 */
	public void startClient() {
		try {
			if (System.getSecurityManager() == null) {
				System.setSecurityManager(new SecurityManager());
			}

			input = new Scanner(System.in);
			cryptoChat = new CryptoChat(input, KEYSTORE, PASS_STORE);

			setupChat();
			setupSecureConnection();

			// Wait for server to finish setting up connection
			if (server.isReady()) {
				server.removeReadyLatch();
			} else {
				client.waitForReady().await();
			}

			String msg = "[System] Secure connection established with " + server.getName() + ".";
			System.out.println(msg);

			startChat();

		} catch (Exception e) {
			System.out.println("[System] Server failed: " + e);
		}
	}

	/**
	 * @throws RemoteException
	 * @throws NotBoundException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InterruptedException
	 * @throws NoSuchAlgorithmException
	 */
	public void setupChat() throws RemoteException, NotBoundException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InterruptedException, NoSuchAlgorithmException {
		// Get the shared Chat object
		Registry registry = LocateRegistry.getRegistry(2020);
		server = (ChatInterface) registry.lookup("Chat");

		System.out.println("Enter Your name and press Enter:");
		String name = input.nextLine().trim();
		securityOptions = cryptoChat.getSecurityOptionsFromUser();

		client = new Chat(name);
		client.registerCallback(this);
		server.setClient(client);

		System.out.println("[System] Chat Remote Object is ready.");
	}

	/**
	 * @throws RemoteException
	 * @throws NoSuchAlgorithmException
	 * @throws InterruptedException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public void setupSecureConnection() throws RemoteException, NoSuchAlgorithmException, InterruptedException,
			IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		if (securityOptions.confidentiality || securityOptions.integrity || securityOptions.authentication) {
			// Get server's public key
			byte[] serverKeyData = server.sendRequest("getPublicKey");
			cryptoChat.createAsymmetricEncryptionCipher(serverKeyData);
		}

		if (securityOptions.confidentiality || securityOptions.integrity) {
			// Create a symmetric key if no key exists yet
			if (cryptoChat.getSecretKey() == null) {
				cryptoChat.createSecretKey();
				cryptoChat.createSymmetricCiphers();
			}
		}

		if (securityOptions.integrity) {
			// ??
		}

		if (securityOptions.authentication) {
			// Authenticate the server
			boolean passwordsMatch;
			do {
				byte[] clientPassword = server.sendRequest("getPassword");
				passwordsMatch = cryptoChat.authenticateUser(client.getName(), clientPassword);
				if (!passwordsMatch) {
					server.sendMessage("Invalid password.");
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
			msg = "[" + client.getName() + "] " + msg;

			if (securityOptions.confidentiality) {
				msg = new String(cryptoChat.encryptSymmetric(msg.getBytes()), "UTF-8");
			}

			server.sendMessage(msg);
		}
	}

	/**
	 * @throws RemoteException
	 */
	public void createServerPassword() throws RemoteException {
		// TODO
		// Normally this would be done by some account creation
		// For the purposes of this assignment we will hardcode the password
		// First check if the password file exists already

		// Otherwise create a password
		cryptoChat.createPassword(server.getName(), "suchsecuremuchwow");
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
	public byte[] onRequest(String request)
			throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {
		if (DEBUG)
			System.out.println("DEBUG  Request: " + request);

		switch (request) {
		case "getNewSecurityOptions":
			return cryptoChat.getSecurityOptionsFromUser().toString().getBytes();

		case "getSecurityOptions":
			return cryptoChat.getSecurityOptions().toString().getBytes();

		case "getPassword":
			return cryptoChat.hashPassword(cryptoChat.getPasswordFromUser());

		case "getPublicKey":
			return cryptoChat.getPublicKey().getEncoded();

		case "getSecretKey":
			byte[] secretKeyData;
			SecretKey secretKey = cryptoChat.getSecretKey();
			if (secretKey == null) {
				// Create a symmetric key
				secretKeyData = cryptoChat.createSecretKey();
				cryptoChat.createSymmetricCiphers();
			} else {
				secretKeyData = secretKey.getEncoded();
			}
			byte[] encryptedKey = cryptoChat.encryptPublic(secretKeyData);
			return encryptedKey;

		default:
			System.out.println("Uknown request: " + request);
			return null;
		}
	}
}
