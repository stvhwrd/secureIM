import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoChat {
  static final boolean DEBUG = false;
  Scanner input;
  String keyStore; // Directory where keys are stored
  String passStore; // Directory where password hashes for the other user are stored
  SecurityOptions securityOptions;
  Cipher symmetricEncryptionCipher;
  Cipher symmetricDecryptionCipher;
  Cipher asymmetricEncryptionCipher;
  Cipher asymmetricDecryptionCipher;
  Signature signer;
  Signature verifier;

  /**
   * @param input
   * @param keyStore
   * @param passStore
   */
  public CryptoChat(Scanner input, String keyStore, String passStore) {
    this.input = input;
    this.keyStore = keyStore;
    this.passStore = passStore;
  }

  /** @return */
  public SecurityOptions getSecurityOptions() {
    if (securityOptions != null) {
      return securityOptions;
    } else {
      return getSecurityOptionsFromUser();
    }
  }

  /** @return */
  /** @return */
  public SecurityOptions getSecurityOptionsFromUser() {
    // Default to no security
    SecurityOptions securityOptions = new SecurityOptions(false, false, false);
    boolean validOptions = false;
    do {
      // Prompt user
      System.out.println("\nSecurity options:\n----");
      System.out.println(
          "Choose 'C' for Confidentiality, \n       'I' for Integrity, and \n       'A' for Authentication.");
      System.out.println("\nFor example: 'CI' will enable Confidentiality and Integrity.");
      System.out.println("\nPlease select your security options now:");

      // Parse input
      String options = input.nextLine().toUpperCase();

      if (options.length() == 0) {
        System.out.println("No security options chosen.");
        validOptions = true;

      } else if (options.length() > 3) {
        System.out.println("Maximum of 3 security options allowed. You chose " + options.length());
        validOptions = false;

      } else { // 1-3 options chosen
        String response = new String("");
        response += "\nYour chat session will be secured by:";

        if (options.indexOf("C") != -1) {
          securityOptions.confidentiality = true;
          validOptions = true;
          response += "\n - Confidentiality";
        }

        if (options.indexOf("I") != -1) {
          securityOptions.integrity = true;
          validOptions = true;
          response += "\n - Integrity";
        }

        if (options.indexOf("A") != -1) {
          securityOptions.authentication = true;
          validOptions = true;
          response += "\n - Authentication";
        }
        if (validOptions) {
          System.out.println(response);
        }
      }
    } while (!validOptions);
    this.securityOptions = securityOptions;

    return securityOptions;
  }

  /** @return */
  public byte[] getPasswordFromUser() {
    String password;
    System.out.println("\nPlease enter your password: ");
    password = input.nextLine();
    if (DEBUG) System.out.println("DEBUG  Password:" + password);

    return password.getBytes();
  }

  /** */
  public void createKeyPair() {
    String publicKeyFilepath = keyStore + "/public.key";
    String privateKeyFilepath = keyStore + "/private.key";

    // If a public/private key pair exists already, don't create a new one
    File publicKeyFile = new File(publicKeyFilepath);
    File privateKeyFile = new File(privateKeyFilepath);
    if (publicKeyFile.exists() && privateKeyFile.exists()) {
      return;
    } else {
      try {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.genKeyPair();

        byte[] publicKey = kp.getPublic().getEncoded();
        byte[] privateKey = kp.getPrivate().getEncoded();

        // Only store valid (non-null) keys
        if (publicKey == null || privateKey == null) {
          throw new UnsupportedEncodingException();
        } else {
          saveToFile(publicKey, publicKeyFilepath);
          saveToFile(privateKey, privateKeyFilepath);
        }
      } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
        System.out.println("Line: " + e.getStackTrace()[0].getLineNumber());
        e.printStackTrace();
      }
    }
  }

  /**
   * @return
   * @throws NoSuchAlgorithmException
   */
  public byte[] createSecretKey() throws NoSuchAlgorithmException {
    // Create a secret (symmetric) key:
    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SimpleEncrEx
    KeyGenerator keygen = KeyGenerator.getInstance("AES");
    SecretKey aesKey = keygen.generateKey();
    byte[] aesKeyData = aesKey.getEncoded();

    saveToFile(aesKeyData, keyStore + "/" + "secret.key");

    return aesKeyData;
  }

  /** @param secretKeyData */
  public void setSecretKey(byte[] secretKeyData) {
    saveToFile(secretKeyData, keyStore + "/" + "secret.key");
  }

  /** @return */
  public PublicKey getPublicKey() {
    String filepath = keyStore + "/" + "public.key";
    File f = new File(filepath);

    if (!f.exists()) {
      createKeyPair();
    }

    byte[] keyData = readFromFile(filepath);
    PublicKey publicKey = null;

    try {
      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(keyData);
      KeyFactory keyFactory = KeyFactory.getInstance("DSA");
      publicKey = keyFactory.generatePublic(pubKeySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      System.out.println("Line: " + e.getStackTrace()[0].getLineNumber());
      e.printStackTrace();
    }

    return publicKey;
  }

  /** @return */
  public PrivateKey getPrivateKey() {
    String filepath = keyStore + "/" + "private.key";
    File f = new File(filepath);

    if (!f.exists()) {
      createKeyPair();
    }

    byte[] keyData = readFromFile(filepath);

    PrivateKey privateKey = null;

    try {
      PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(keyData);
      KeyFactory keyFactory = KeyFactory.getInstance("DSA");
      privateKey = keyFactory.generatePrivate(privKeySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      System.out.println("Line: " + e.getStackTrace()[0].getLineNumber());
      e.printStackTrace();
    }

    return privateKey;
  }

  /**
   * Read secret key from file.
   *
   * @return secretKey
   */
  public SecretKey getSecretKey() {
    byte[] aesKeyData = readFromFile(keyStore + "/" + "secret.key");

    // Convert it to a SecretKey object:
    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SecretKeyFactory
    SecretKeySpec secretKey = new SecretKeySpec(aesKeyData, "AES");
    return secretKey;
  }

  /**
   * Returns true if hashedPass is a valid password for username
   *
   * @param username
   * @param hashedPassword
   * @return
   */
  public boolean authenticateUser(String username, byte[] hashedPassword) {
    String filename = passStore + "/" + username + ".password";
    File hashOnDisk = new File(filename);

    if (hashOnDisk.exists()) {
      byte[] storedHash = readFromFile(filename);
      return Arrays.equals(storedHash, hashedPassword);

    } else { // New user
      saveToFile(hashedPassword, filename);
      System.out.println("The other user is NEW - use caution.");
      return true;
    }
  }

  public byte[] signMessage(byte[] message)
      throws NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException {
    signer.update(message);
    return signer.sign();
  }

  public boolean verifyMessage(byte[] message, byte[] signedMessage) throws SignatureException {
    verifier.update(message);
    return verifier.verify(signedMessage);
  }

  public void createSigner() throws InvalidKeyException, NoSuchAlgorithmException {
    signer = Signature.getInstance("SHA256withDSA");

    /* Initializing the object with a private key */
    PrivateKey priv = getPrivateKey();
    signer.initSign(priv);
  }

  public void createVerifier(byte[] publicKeyData)
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyData);

    KeyFactory keyFactory = KeyFactory.getInstance("DSA");
    PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

    verifier = Signature.getInstance("SHA256withDSA");
    verifier.initVerify(pubKey);
  }

  /**
   * @param password
   * @return hash
   */
  public byte[] hashPassword(byte[] password) {
    try {
      byte[] hash = MessageDigest.getInstance("SHA-256").digest(password);
      if (DEBUG) System.out.println("DEBUG  Hash:" + hash);
      return hash;
    } catch (NoSuchAlgorithmException e) {
      System.out.println("Unable to hash password");
      System.out.println(e);
      return "".getBytes(); // @todo: guarantee a sensible return value
    }
  }

  /**
   * Hash the plaintext password
   *
   * @param username
   * @param plaintext
   */
  public void createPassword(String username, String plaintext) {
    byte[] hashedPassword = hashPassword(plaintext.getBytes());
    String filename = passStore + "/" + username + ".password";

    saveToFile(hashedPassword, filename);
  }

  /** */
  public void createSymmetricCiphers() {
    // @todo: replace ??? with algorithm
    symmetricEncryptionCipher = createCipher(getSecretKey(), "???", Cipher.ENCRYPT_MODE);
    symmetricDecryptionCipher = createCipher(getSecretKey(), "???", Cipher.DECRYPT_MODE);
  }

  /** @param otherUserPublicKey */
  public void createAsymmetricEncryptionCipher(byte[] otherUserPublicKey) {
    // @todo: Convert otherUserPublicKey to Key (or PublicKey object) and replace ??? with algorithm
    PublicKey key = null; // placeholder
    asymmetricEncryptionCipher = createCipher(key, "???", Cipher.ENCRYPT_MODE);
  }

  /** */
  public void createAsymmetricDecryptionCipher() {
    // @todo: replace ??? with algorithm
    asymmetricDecryptionCipher = createCipher(getPrivateKey(), "???", Cipher.DECRYPT_MODE);
  }

  /**
   * @param key
   * @param algorithm
   * @param cipherMode
   * @return
   */
  public Cipher createCipher(Key key, String algorithm, int cipherMode) {
    // @todo: Create a cipher using the given key and algorithm and return it. Reference: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SimpleEncrEx
    return null; // placeholder
  }

  /**
   * @param message
   * @return
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public byte[] encryptSymmetric(byte[] message)
      throws IllegalBlockSizeException, BadPaddingException {
    return symmetricEncryptionCipher.doFinal(message);
  }

  /**
   * @param encrypted
   * @return
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public byte[] decryptSymmetric(byte[] encrypted)
      throws IllegalBlockSizeException, BadPaddingException {
    return symmetricDecryptionCipher.doFinal(encrypted);
  }

  /**
   * @param message
   * @return
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public byte[] encryptPublic(byte[] message)
      throws IllegalBlockSizeException, BadPaddingException {
    return asymmetricEncryptionCipher.doFinal(message);
  }

  /**
   * @param encrypted
   * @return
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public byte[] decryptPrivate(byte[] encrypted)
      throws IllegalBlockSizeException, BadPaddingException {
    return asymmetricDecryptionCipher.doFinal(encrypted);
  }

  /**
   * @param contents
   * @param filename
   * @throws IOException
   */
  public void saveToFile(byte[] contents, String filename) {
    try {
      // Create parent directories
      (new File(filename)).getParentFile().mkdirs();

      FileOutputStream fos = new FileOutputStream(filename);
      fos.write(contents);
      fos.close();
    } catch (IOException e) {
      System.out.println("Line: " + e.getStackTrace()[0].getLineNumber());
      e.printStackTrace();
    }
  }

  /**
   * @param filename
   * @return
   */
  public byte[] readFromFile(String filename) {
    try {
      return Files.readAllBytes(new File(filename).toPath());
    } catch (NoSuchFileException e) {
      return null;
    } catch (IOException e) {
      System.out.println("Line: " + e.getStackTrace()[0].getLineNumber());
      e.printStackTrace();
      return null;
    }
  }
}
