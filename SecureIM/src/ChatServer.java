import java.io.UnsupportedEncodingException;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
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

  /** @param argv */
  public static void main(String[] argv) {

    // Set JVM arguments
    //    final String dir = System.getProperty("user.dir");
    //    System.setProperty("java.security.policy", "file:" + dir + "/security.policy");
    //    System.setProperty("java.rmi.server.codebase", dir + "/bin");

    ChatServer chatServer = new ChatServer();
    chatServer.startServer();
  }

  /** */
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
      System.out.println("Line: " + e.getStackTrace()[0].getLineNumber());
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
  public void setupChat()
      throws RemoteException, AlreadyBoundException, InterruptedException,
          UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
    System.out.println(
        "Welcome to\n"
            + "                              ___ __  __ \n"
            + " ___  ___  ___ _   _ _ __ ___|_ _|  \\/  |\n"
            + "/ __|/ _ \\/ __| | | | '__/ _ \\| || |\\/| |\n"
            + "\\__ \\  __/ (__| |_| | | |  __/| || |  | |\n"
            + "|___/\\___|\\___|\\__,_|_|  \\___|___|_|  |_|\n"
            + "                                         "
            + "");
    System.out.println("Please enter your server username:");
    String name = input.nextLine().trim();
    securityOptions = cryptoChat.getSecurityOptions();

    server = new Chat(name);
    server.registerCallback(this);

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
   * @throws SignatureException
   * @throws InvalidKeyException
   * @throws InvalidKeySpecException
   */
  public void setupSecureConnection()
      throws RemoteException, InterruptedException, UnsupportedEncodingException,
          IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
          SignatureException, InvalidKeyException, InvalidKeySpecException {
    // Wait for client to connect
    server.waitForConnection().await();

    client = server.getClient();
    System.out.println("[System] " + client.getName() + " is trying to connect.");

    checkSecurityOptions();

    if (securityOptions.confidentiality) {
      cryptoChat.createAsymmetricDecryptionCipher();

      // Get symmetric key from client
      byte[] encryptedSecretKey = client.sendRequest("getSecretKey");

      // Decrypt the key
      byte[] secretKeyData = cryptoChat.decryptPrivate(encryptedSecretKey);
      cryptoChat.setSecretKey(secretKeyData);
      cryptoChat.createSymmetricCiphers();
    }

    if (securityOptions.integrity) {
      byte[] clientKeyData = client.sendRequest("getPublicKey");
      cryptoChat.createSigner();
      cryptoChat.createVerifier(clientKeyData);
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

      // Redundant doublecheck that password matches
      if (passwordsMatch) {
        System.out.println("Client has authenticated as \"" + client.getName() + "\"");
      }
    }
  }

  /**
   * @throws RemoteException
   * @throws UnsupportedEncodingException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws SignatureException
   * @throws NoSuchAlgorithmException
   */
  public void startChat()
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException, NoSuchAlgorithmException {
    while (true) {
      String msg = input.nextLine().trim();
      if (server.getClient() != null) {
        msg = "[" + server.getName() + "] " + msg;

        byte[] msgBytes = msg.getBytes();

        if (securityOptions.confidentiality) {
          msgBytes = cryptoChat.encryptSymmetric(msgBytes);
        }

        if (securityOptions.integrity) {
          byte[] sig = cryptoChat.signMessage(msgBytes);
          client.sendMessage(msgBytes, sig);
        } else {
          client.sendMessage(msgBytes);
        }
      } else {
        // Client disconnected
        System.out.println("[System] " + client.getName() + " has disconnected.");
        client = null;
        break;
      }
    }

    // Wait for new client to connect
    startServer();
  }

  //  /** @throws RemoteException */
  //  public void createClientPassword() throws RemoteException {
  //    // @todo Normally this would be done by some account creation, but for the purposes of this assignment we will hardcode the password.  First check if the password file exists already
  //
  //    // Otherwise create a password
  //    cryptoChat.createPassword(server.getName(), "verysecretshhh");
  //  }

  /**
   * @throws RemoteException
   * @throws UnsupportedEncodingException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws InterruptedException
   * @throws NoSuchAlgorithmException
   * @throws SignatureException
   */
  public void checkSecurityOptions()
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, InterruptedException, NoSuchAlgorithmException, SignatureException {
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
  public void onMessage(byte[] message, byte[] signedMessage)
      throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException,
          SignatureException {
    if (securityOptions.integrity) {
      if (!cryptoChat.verifyMessage(message, signedMessage)) {
        System.out.println("The integrity of the following message could not be verified:");
      }
    }

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
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, InterruptedException {
    if (DEBUG) System.out.println("DEBUG  Request: " + request);

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
