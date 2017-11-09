import java.io.UnsupportedEncodingException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.concurrent.CountDownLatch;

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

      CountDownLatch serverReady = client.waitForReady();

      // Wait for server to finish setting up connection
      serverReady.await();

      setupSecureConnection();

      // Let server know client is finished setting up connection
      server.removeReadyLatch();

      String msg =
          "\n[System] Secure connection established with "
              + server.getName()
              + ".\nType '/exit' when you wish to end the chat session.\n";
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

    if (securityOptions.confidentiality) {
      cryptoChat.createSymmetricCiphers();
    }

    if (securityOptions.integrity) {
      // Get server's public key
      byte[] serverKeyData = server.sendRequest("getPublicKey");

      cryptoChat.createSigner();
      cryptoChat.createVerifier(serverKeyData);
    }

    if (securityOptions.authentication) {
    	System.out.println("\n[System] Autenticating server... One moment.");
      if (cryptoChat.verifier == null) {
        byte[] serverKeyData = server.sendRequest("getPublicKey");
        cryptoChat.createVerifier(serverKeyData);
      }

      if (cryptoChat.asymmetricDecryptionCipher == null) {
        cryptoChat.createAsymmetricDecryptionCipher();
      }

      // Authenticate the server
      boolean passwordsMatch;
      boolean verified;
      do {
        byte[] data = server.sendRequest("getPassword");
        int passwordLength = (int) data[data.length - 1] & 0xFF;
        byte[] serverPassword = Arrays.copyOfRange(data, 0, passwordLength);
        byte[] sig = Arrays.copyOfRange(data, passwordLength, data.length - 1);
        verified = cryptoChat.verifyMessage(serverPassword, sig);
        serverPassword = cryptoChat.decryptPrivate(serverPassword);
        passwordsMatch = cryptoChat.authenticateUser(server.getName(), serverPassword);
        if (!passwordsMatch) {
          server.sendPlainMessage("\nIncorrect password.");
          if (!verified) {
            System.out.println(
                "Caution: "
                    + server.getName()
                    + " attempted to login but the message integrity could not be verified");
          }
        }
      } while (!passwordsMatch);

      System.out.println("\nClient has authenticated as \"" + client.getName() + "\"");
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
      boolean exit = false;

      if (msg.equals("/exit")) {
        exit = true;
        msg = "The client has disconnected.\nPress enter to continue";
        System.out.println("Disconnected from server");
        System.out.println("Goodbye! Come back soon");
      }
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

      if (exit) {
        server.disconnectClient();
        System.exit(0);
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
      case "getSecurityOptions":
        securityOptions = cryptoChat.getSecurityOptionsFromUser();
        return securityOptions.toString().getBytes();

      case "getPassword":
        byte[] password = cryptoChat.hashPassword(cryptoChat.getPasswordFromUser());

        // Encrypt the hashed password
        if (cryptoChat.asymmetricEncryptionCipher == null) {
          try {
            byte[] serverKeyData = server.sendRequest("getPublicKey");
            cryptoChat.createAsymmetricEncryptionCipher(serverKeyData);
          } catch (RemoteException | UnsupportedEncodingException | InterruptedException e) {
            e.printStackTrace();
          }
        }
        password = cryptoChat.encryptPublic(password);
        byte[] sig = null;

        // Sign the encrypted hashed password
        try {
          if (cryptoChat.signer == null) {
            cryptoChat.createSigner();
          }
          sig = cryptoChat.signMessage(password);
        } catch (SignatureException | UnsupportedEncodingException e1) {
          e1.printStackTrace();
        } catch (InvalidKeyException e) {
          e.printStackTrace();
        }

        byte[] ret = new byte[password.length + sig.length + 1];
        System.arraycopy(password, 0, ret, 0, password.length);
        System.arraycopy(sig, 0, ret, password.length, sig.length);
        ret[ret.length - 1] = (byte) password.length;

        return ret;

      case "getPublicKey":
        return cryptoChat.getPublicKey().getEncoded();

      case "getSecretKey":
        byte[] secretKeyData;
        SecretKey secretKey = cryptoChat.getSecretKey();

        if (secretKey == null) {
          // Create a symmetric key
          secretKeyData = cryptoChat.createSecretKey();
        } else {
          secretKeyData = secretKey.getEncoded();
        }

        if (cryptoChat.asymmetricEncryptionCipher == null) {
          try {
            byte[] serverKeyData = server.sendRequest("getPublicKey");
            cryptoChat.createAsymmetricEncryptionCipher(serverKeyData);
          } catch (RemoteException | UnsupportedEncodingException | InterruptedException e) {
            e.printStackTrace();
          }
        }

        byte[] encryptedKey = cryptoChat.encryptPublic(secretKeyData);
        return encryptedKey;

      default:
        System.out.println("Uknown request: " + request);
        return null;
    }
  }
}
