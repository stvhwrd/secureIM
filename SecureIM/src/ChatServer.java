import java.io.UnsupportedEncodingException;
import java.rmi.AlreadyBoundException;
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

public class ChatServer implements ChatCallback {
  static final boolean DEBUG = false;
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

      while (true) {
        CountDownLatch clientReady = server.waitForReady();

        setupSecureConnection();

        // Let client know server is ready
        client.removeReadyLatch();

        // Wait for client to finish setting up connection
        clientReady.await();

        String msg = "\n[System] Secure connection established with " + client.getName() + ".";
        System.out.println(msg);

        startChat();

        System.out.println("[System] Waiting for new client to connect.");
      }

    } catch (Exception e) {
      System.out.println("\n[System] Server failed: " + e);
      cryptoChat.displayExceptionInfo(e);
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
            + "                                         \n");
    System.out.println("Please enter your server username:");
    String name = input.nextLine().trim();
    securityOptions = cryptoChat.getSecurityOptions();

    server = new Chat(name);
    server.registerCallback(this);

    Registry registry = LocateRegistry.createRegistry(2020);
    registry.bind("Chat", server);

    System.out.println("\n[System] Chat Remote Object is ready.");
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
    System.out.println("\n[System] " + client.getName() + " is trying to connect.");

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
      if (cryptoChat.verifier == null) {
        byte[] clientKeyData = client.sendRequest("getPublicKey");
        cryptoChat.createVerifier(clientKeyData);
      }

      if (cryptoChat.asymmetricDecryptionCipher == null) {
        cryptoChat.createAsymmetricDecryptionCipher();
      }

      // Authenticate the client
      boolean passwordsMatch;
      boolean verified;
      do {
        byte[] data = client.sendRequest("getPassword");
        int passwordLength = (int) data[data.length - 1] & 0xFF;
        byte[] clientPassword = Arrays.copyOfRange(data, 0, passwordLength);
        byte[] sig = Arrays.copyOfRange(data, passwordLength, data.length - 1);
        verified = cryptoChat.verifyMessage(clientPassword, sig);
        clientPassword = cryptoChat.decryptPrivate(clientPassword);
        passwordsMatch = cryptoChat.authenticateUser(client.getName(), clientPassword);
        if (!passwordsMatch) {
          client.sendPlainMessage("\nIncorrect password.");
          if (!verified) {
            System.out.println(
                "Caution: "
                    + client.getName()
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
    boolean clientConnected = true;
    while (clientConnected) {
      String msg = input.nextLine().trim();
      clientConnected = server.getClient() != null;
      if (clientConnected) {
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
      }
    }
  }

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
    boolean optionsMatch;
    do {
      String clientSecurityOptions = new String(client.sendRequest("getSecurityOptions"), "UTF-8");
      optionsMatch = securityOptions.toString().equals(clientSecurityOptions);

      if (!optionsMatch) {
        // Let the client know options don't match
        client.sendPlainMessage("Options don't match server security options.");
      }
    } while (!optionsMatch);
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
        byte[] password = cryptoChat.hashPassword(cryptoChat.getPasswordFromUser());

        // Encrypt the hashed password
        if (cryptoChat.asymmetricEncryptionCipher == null) {
          try {
            byte[] serverKeyData = client.sendRequest("getPublicKey");
            cryptoChat.createAsymmetricEncryptionCipher(serverKeyData);
          } catch (RemoteException | UnsupportedEncodingException | InterruptedException e) {
            e.printStackTrace();
          } catch (NoSuchAlgorithmException e) {
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
        } catch (NoSuchAlgorithmException e) {
          e.printStackTrace();
        }

        byte[] ret = new byte[password.length + sig.length + 1];
        System.arraycopy(password, 0, ret, 0, password.length);
        System.arraycopy(sig, 0, ret, password.length, sig.length);
        ret[ret.length - 1] = (byte) password.length;

        return ret;

      case "getPublicKey":
        return cryptoChat.getPublicKey().getEncoded();

      default:
        System.out.println("Uknown request: " + request);
        return null;
    }
  }
}
