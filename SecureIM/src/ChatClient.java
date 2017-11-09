import java.io.File;
import java.io.UnsupportedEncodingException;
import java.rmi.NotBoundException;
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
import javax.crypto.SecretKey;

public class ChatClient implements ChatCallback {
  static final boolean DEBUG = false;
  static final String KEYSTORE = "client/keys";
  static final String PASS_STORE = "client/passwords";
  Scanner input;
  ChatInterface server;
  ChatInterface client;
  CryptoChat cryptoChat;
  SecurityOptions securityOptions;

  public static void main(String[] argv) {

    // Set JVM arguments
    //    final String dir = System.getProperty("user.dir");
    //    System.setProperty("java.security.policy", "file:" + dir + "/security.policy");
    //    System.setProperty("java.rmi.server.codebase", dir + "/bin");

    ChatClient chatClient = new ChatClient();
    chatClient.startClient();
  }

  /** */
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

      String msg = "\n[System] Secure connection established with " + server.getName() + ".";
      System.out.println(msg);

      startChat();

    } catch (Exception e) {
      System.out.println("\n[System] Client failed: " + e);
      cryptoChat.displayExceptionInfo(e);
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
  public void setupChat()
      throws RemoteException, NotBoundException, UnsupportedEncodingException,
          IllegalBlockSizeException, BadPaddingException, InterruptedException,
          NoSuchAlgorithmException {
    // Get the shared Chat object
    Registry registry = LocateRegistry.getRegistry(2020);
    server = (ChatInterface) registry.lookup("Chat");

    System.out.println(
        "Welcome to\n"
            + "                              ___ __  __ \n"
            + " ___  ___  ___ _   _ _ __ ___|_ _|  \\/  |\n"
            + "/ __|/ _ \\/ __| | | | '__/ _ \\| || |\\/| |\n"
            + "\\__ \\  __/ (__| |_| | | |  __/| || |  | |\n"
            + "|___/\\___|\\___|\\__,_|_|  \\___|___|_|  |_|\n"
            + "                                         "
            + "");
    System.out.println("Please enter your client username:");
    String name = input.nextLine().trim();
    securityOptions = cryptoChat.getSecurityOptionsFromUser();

    client = new Chat(name);
    client.registerCallback(this);
    server.setClient(client);

    System.out.println("\n[System] Chat Remote Object is ready.");
  }

  /**
   * @throws RemoteException
   * @throws NoSuchAlgorithmException
   * @throws InterruptedException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws UnsupportedEncodingException
   * @throws SignatureException
   * @throws InvalidKeyException
   * @throws InvalidKeySpecException
   */
  public void setupSecureConnection()
      throws RemoteException, NoSuchAlgorithmException, InterruptedException,
          IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
          SignatureException, InvalidKeyException, InvalidKeySpecException {
    byte[] serverKeyData = null;
    if (securityOptions.confidentiality || securityOptions.integrity) {
      // Get server's public key
      serverKeyData = server.sendRequest("getPublicKey");
    }

    if (securityOptions.confidentiality) {
      cryptoChat.createAsymmetricEncryptionCipher(serverKeyData);

      // Create a symmetric key if no key exists yet
      if (cryptoChat.getSecretKey() == null) {
        cryptoChat.createSecretKey();
        cryptoChat.createSymmetricCiphers();
      }
    }

    if (securityOptions.integrity) {
      cryptoChat.createSigner();
      cryptoChat.createVerifier(serverKeyData);
    }

    if (securityOptions.authentication) {
      // Authenticate with server
      boolean passwordsMatch;
      do {
        byte[] serverPassword = server.sendRequest("getPassword");
        passwordsMatch = cryptoChat.authenticateUser(server.getName(), serverPassword);
        if (!passwordsMatch) {
          server.sendMessage("\nIncorrect password.");
        }
      } while (!passwordsMatch);

      System.out.println("\nServer has authenticated as \"" + server.getName() + "\"");
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
      msg = "[" + client.getName() + "] " + msg;

      byte[] msgBytes = msg.getBytes();

      if (securityOptions.confidentiality) {
        msgBytes = cryptoChat.encryptSymmetric(msgBytes);
      }

      if (securityOptions.integrity) {
        byte[] sig = cryptoChat.signMessage(msgBytes);
        server.sendMessage(msgBytes, sig);
      } else {
        server.sendMessage(msgBytes);
      }
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
      throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {
    if (DEBUG) System.out.println("DEBUG  Request: " + request);

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
        if ((new File(KEYSTORE + "/secret.key")).exists()) {
          secretKeyData = cryptoChat.getSecretKey().getEncoded();
        } else {
          // Create a symmetric key
          secretKeyData = cryptoChat.createSecretKey();
        }
        cryptoChat.createSymmetricCiphers();
        System.out.println(secretKeyData.toString());
        byte[] encryptedKey = cryptoChat.encryptPublic(secretKeyData);
        return encryptedKey;

      default:
        System.out.println("Uknown request: " + request);
        return null;
    }
  }
}
