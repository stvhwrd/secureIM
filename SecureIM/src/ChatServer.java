import java.io.UnsupportedEncodingException;
import java.rmi.*;
import java.rmi.registry.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class ChatServer implements ChatCallback {
	static String KEYSTORE = "server_keys";
	static String PASS_STORE = "client_passwords";
	Scanner input;
	CryptoChat cryptoChat;
	ChatInterface server;
	ChatInterface client;
	SecurityOptions securityOptions;
	
    public static void main(String[] argv) {
        ChatServer chatServer = new ChatServer();
        chatServer.startServer();
    }
    
    public void startServer() {
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
    
    public void setupChat() throws RemoteException, AlreadyBoundException {
        securityOptions = cryptoChat.getSecurityOptionsFromUser();
        System.out.println("Enter Your name and press Enter:");
        String name = input.nextLine().trim();

        server = new Chat(name);
        server.registerCallback(this);
        
        cryptoChat.createKeyPair();

        Registry registry = LocateRegistry.createRegistry(2020);
        registry.bind("Chat", server);

        System.out.println("[System] Chat Remote Object is ready.");
    }
    
    public void setupConnection() throws RemoteException, InterruptedException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
    	// Wait for client to connect
    	server.waitForClient().await();
    	CountDownLatch clientReady = server.waitForClient();
        client = server.getClient();
        
        System.out.println("[System] " + client.getName() + " is trying to connect.");
    	
    	// Make sure the security options are the same
		boolean optionsMatch;
	    do {
	    	// Request security options from client
	    	clientReady.await();
	    	String clientSecurityOptions = new String(server.getClientResponse(), "UTF-8");
	    	optionsMatch = securityOptions.toString().equals(clientSecurityOptions);
	    	if (!optionsMatch) {
	    		// Let the client know options don't match
	    		clientReady = server.waitForClient();
	    		client.respondToClient("Options don't match".getBytes());
	    	} else {
	    		client.respondToClient(null);
	    	}
	    } while (!optionsMatch);
	    
	    if (securityOptions.confidentiality || securityOptions.integrity || securityOptions.authentication) {
			// Setup public/private keys
			clientReady = server.waitForClient();
			cryptoChat.createKeyPair();
			cryptoChat.createAsymmetricDecryptionCipher();
			
			// Send public key to client
			server.respondToClient(cryptoChat.getPublicKey().getEncoded());
			
			// Get client's public key
			clientReady.await();
			cryptoChat.createAsymmetricEncryptionCipher(server.getClientResponse());
		}
	    
	    if (securityOptions.confidentiality || securityOptions.integrity) {
	    	// Wait for client to send a symmetric key encrypted with the server's public key
	    	server.waitForClient().await();
	    	
	    	// Decrypt the key
	    	byte[] encryptedSecretKey = server.getClientResponse();
	    	byte[] secretKeyData = cryptoChat.decryptPrivate(encryptedSecretKey);
	    	cryptoChat.setSecretKey(secretKeyData);
	    	cryptoChat.createSymmetricCiphers();
	    }
	    
	    if (securityOptions.integrity) {
	    	// ??
	    }
	    
	    if (securityOptions.authentication) {
	    	// Authenticate the client
	    	clientReady = server.waitForClient();
			boolean passwordsMatch;
		    do {
		    	clientReady.await();
		    	byte[] clientPassword = server.getClientResponse();
		    	passwordsMatch = cryptoChat.authenticateUser(client.getName(), clientPassword);
		    	if (!passwordsMatch) {
		    		clientReady = server.waitForClient();
		    		client.respondToClient("Invalid password.".getBytes());
		    	}
		    } while (!passwordsMatch);
		    
			// Authenticate to the client
			clientReady = server.waitForClient();
			do {
				byte[] password = cryptoChat.getPasswordFromUser();
				client.respondToClient(password);
				clientReady.await();
				
				byte[] response = server.getClientResponse();
				passwordsMatch = (response == null);
				
				if (!passwordsMatch) {
					clientReady = client.waitForServer();
					System.out.println(response);
				}
			} while (!passwordsMatch);
	    }
	    
	    String msg = "[System] Secure connection established with ";
		client.send(msg + server.getName() + ".");
		System.out.println(msg + client.getName() + ".");
    }
    
    public void startChat() throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
    	while (true) {
            String msg = input.nextLine().trim();
            if (server.getClient() != null) {
                ChatInterface client = server.getClient();
                msg = "[" + server.getName() + "] " + msg;
                
                if (securityOptions.confidentiality) {
    				msg = new String(cryptoChat.encryptSymmetric(msg.getBytes()), "UTF-8");
    			}
                
                client.send(msg);
            }
        }
    }
    
    public void createClientPassword() throws RemoteException {
    	// TODO
    	// Normally this would be done by some account creation
    	// For the purposes of this assignment we will hardcode the password
    	// First check if the password file exists already
    	
    	// Otherwise create a password
    	cryptoChat.createPassword(server.getName(), "verysecretshhh");
    }
    
    public void onMessage(byte[] message) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
    	if (securityOptions.confidentiality) {
    		message = cryptoChat.decryptSymmetric(message);
    	}
    	
    	System.out.println(new String(message, "UTF-8"));
    }
}
