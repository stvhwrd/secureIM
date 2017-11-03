import java.io.UnsupportedEncodingException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.*;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.CountDownLatch;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

public class ChatClient implements ChatCallback {
	static String KEYSTORE = "client_keys";
	static String PASS_STORE = "server_passwords";
	Scanner input;
	ChatInterface server;
	ChatInterface client;
	CryptoChat cryptoChat;
	SecurityOptions securityOptions;
	
	public static void main(String[] argv) {
		ChatClient chatClient = new ChatClient();
		chatClient.startClient();
	}
	
	public void startClient() {
		try {
			if (System.getSecurityManager() == null) {
		        System.setSecurityManager(new SecurityManager());
		    }
			
		    input = new Scanner(System.in);
			cryptoChat = new CryptoChat(input, KEYSTORE, PASS_STORE);
			
			setupChat();
			setupConnection();
			startChat();

		} catch (Exception e) {
			System.out.println("[System] Server failed: " + e);
		}
	}
	
	public void setupChat() throws RemoteException, NotBoundException {
		// Get the shared Chat object
	    Registry registry = LocateRegistry.getRegistry(2020);
		server = (ChatInterface) registry.lookup("Chat");
	    
		System.out.println("Enter Your name and press Enter:");
		String name = input.nextLine().trim();
		
		client = new Chat(name);
		client.registerCallback(this);
		server.setClient(client);
		
		System.out.println("[System] Chat Remote Object is ready.");
	}
	
	public void setupConnection() throws RemoteException, NoSuchAlgorithmException, InterruptedException, IllegalBlockSizeException, BadPaddingException {
		// Make sure security options match between client and server
		boolean optionsMatch;
		CountDownLatch serverReady;
		do {
			securityOptions = cryptoChat.getSecurityOptionsFromUser();

			// Send the security options to the server
			serverReady = client.waitForServer();
			server.respondToServer(securityOptions.toString().getBytes());

			// Wait for a response from the server
			serverReady.await();
			byte[] response = client.getServerResponse();
			
			optionsMatch = (response == null);
			
			if (!optionsMatch) {
				System.out.println(response);
			}
		} while(!optionsMatch);
		
		if (securityOptions.confidentiality || securityOptions.integrity || securityOptions.authentication) {
			// Setup public/private keys
			serverReady = client.waitForServer();
			cryptoChat.createKeyPair();
			cryptoChat.createAsymmetricDecryptionCipher();
			
			// Send public key to server
			server.respondToServer(cryptoChat.getPublicKey().getEncoded());
			
			// Get server's public key
			serverReady.await();
			cryptoChat.createAsymmetricEncryptionCipher(client.getServerResponse());
		}
		
		if (securityOptions.confidentiality || securityOptions.integrity) {
	    	serverReady = client.waitForServer();
	    	
			// Create a symmetric key
	    	byte[] secretKeyData = cryptoChat.createSecretKey();
	    	cryptoChat.createSymmetricCiphers();
	    	
	    	// Encrypt the symmetric key with the server's public key
	    	byte[] encryptedKey = cryptoChat.encryptPublic(secretKeyData);
	    	
	    	// Send the encrypted key to the server
			server.respondToServer(encryptedKey);
	    }
		
		if (securityOptions.integrity) {
	    	// ??
	    }
		
		if (securityOptions.authentication) {
	    	// Authenticate to the server
			serverReady = client.waitForServer();
			boolean passwordsMatch;
			do {
				byte[] password = cryptoChat.getPasswordFromUser();
				server.respondToServer(password);
				serverReady.await();
				
				byte[] response = client.getServerResponse();
				passwordsMatch = (response == null);
				
				if (!passwordsMatch) {
					serverReady = client.waitForServer();
					System.out.println(response);
				}
			} while (!passwordsMatch);
			
			
			// Authenticate the server
			serverReady = client.waitForServer();
		    do {
		    	serverReady.await();
		    	byte[] serverPassword = client.getServerResponse();
		    	passwordsMatch = cryptoChat.authenticateUser(client.getName(), serverPassword);
		    	if (!passwordsMatch) {
		    		serverReady = client.waitForServer();
		    		server.respondToServer("Invalid password".getBytes());
		    	}
		    } while (!passwordsMatch);
	    }
	}
	
	public void startChat() throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		while (true) {
			String msg = input.nextLine().trim();
			msg = "[" + client.getName() + "] " + msg;
			
			if (securityOptions.confidentiality) {
				msg = new String(cryptoChat.encryptSymmetric(msg.getBytes()), "UTF-8");
			}
			
			server.send(msg);
		}
	}
	
	public void createServerPassword() throws RemoteException {
		// TODO
    	// Normally this would be done by some account creation
    	// For the purposes of this assignment we will hardcode the password
    	// First check if the password file exists already
    	
    	// Otherwise create a password
    	cryptoChat.createPassword(server.getName(), "suchsecuremuchwow");
    }
	
	public void onMessage(byte[] message) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
    	if (securityOptions.confidentiality) {
    		message = cryptoChat.decryptSymmetric(message);
    	}
    	
    	System.out.println(new String(message, "UTF-8"));
    }
}
