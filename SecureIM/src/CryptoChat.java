import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoChat {
  static final boolean DEBUG = true;
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
    }

    return getSecurityOptionsFromUser();
  }

  /** @return */
  /** @return */
  public SecurityOptions getSecurityOptionsFromUser() {
    // TODO
    // Prompt the user for the security options they want enabled using the
    // Scanner object input (global object in this class)
    // They can choose from Confidentiality, Integrity, and/or Authentication

    // Placeholder which disables all three options:
    SecurityOptions securityOptions = new SecurityOptions(false, false, false);

    System.out.println(
        "Choose your security options where 1 is Confidentiality, 2 is Integrity, and 3 is Authentication: ");
    String options = input.nextLine();
    switch (options) {
      case "1":
        securityOptions = new SecurityOptions(true, false, false);
        break;
      case "2":
        securityOptions = new SecurityOptions(false, true, false);
        break;
      case "3":
        securityOptions = new SecurityOptions(false, false, true);
        break;
      case "12":
        securityOptions = new SecurityOptions(true, true, false);
        break;
      case "13":
        securityOptions = new SecurityOptions(true, false, true);
        break;
      case "23":
        securityOptions = new SecurityOptions(false, true, true);
        break;
      case "123":
        securityOptions = new SecurityOptions(true, true, true);
        break;
      case "":
        securityOptions = new SecurityOptions(false, false, false);
        break;
      default:
        throw new IllegalArgumentException("Invalid security option: " + options);
    }
    System.out.println("Your selected security options were: " + securityOptions);

    this.securityOptions = securityOptions;
    return securityOptions;
  }

  /** @return */
  public byte[] getPasswordFromUser() {
    // TODO
    // Prompt the user for their password using the
    // Scanner object input (global object in this class)
    String password;
    System.out.println("Please enter you password: ");
    password = input.nextLine();

    System.out.println(password);
    return "password".getBytes(); // placeholder
  }

  /** */
  public void createKeyPair() {
    String publicKeyFilepath = keyStore + "/public.key";
    String privateKeyFilepath = keyStore + "/private.key";

    // If a public/private key pair exists already, don't create a new one
    File publicKeyFile = new File(publicKeyFilepath);
    File privateKeyFile = new File(privateKeyFilepath);
    if (publicKeyFile.exists() && privateKeyFile.exists()) return;

    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
      kpg.initialize(1024);
      KeyPair kp = kpg.genKeyPair();

      byte[] publicKey = kp.getPublic().getEncoded();
      byte[] privateKey = kp.getPrivate().getEncoded();

      saveToFile(publicKey, publicKeyFilepath);
      saveToFile(privateKey, privateKeyFilepath);
    } catch (NoSuchAlgorithmException e) { // TODO Auto-generated catch block
      e.printStackTrace();
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
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
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
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    }

    return privateKey;
  }

  /** @return */
  public SecretKey getSecretKey() {
    byte[] aesKeyData = readFromFile(keyStore + "/" + "secret.key");

    // Convert it to a SecretKey object:
    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SecretKeyFactory
    SecretKeySpec secretKey = new SecretKeySpec(aesKeyData, "AES");
    return secretKey;
  }

  // Returns true if hashedPass is a valid password for username
  /**
   * @param username
   * @param hashedPass
   * @return
   */
  public boolean authenticateUser(String username, byte[] hashedPass) {
    // TODO
    // Check if the file which would contain the user's password exists
    // ie <passStore>/<username>.password
    // If it exists, get the contents (use readFromFile() method in this class)
    // and compare the hash with hashedPass

    return true; // placeholder
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
   * @return
   */
  public byte[] hashPassword(byte[] password) {
    // TODO hash the password and return it
    return "".getBytes(); // placeholder
  }

  public void createPassword(String username, String plaintext) {
    // Hash the plaintext password
    byte[] hashedPassword = hashPassword(plaintext.getBytes());

    String filename = passStore + "/" + username + ".passowrd";

    saveToFile(hashedPassword, filename);
  }

  /** */
  public void createSymmetricCiphers() {
    // TODO: replace ??? with algorithm
    symmetricEncryptionCipher = createCipher(getSecretKey(), "???", Cipher.ENCRYPT_MODE);
    symmetricDecryptionCipher = createCipher(getSecretKey(), "???", Cipher.DECRYPT_MODE);
  }

  /** @param otherUserPublicKey */
  public void createAsymmetricEncryptionCipher(byte[] otherUserPublicKey) {
    // TODO
    // Convert otherUserPublicKey to Key (or PublicKey object)
    // and replace ??? with algorithm
    PublicKey key = null; // placeholder
    asymmetricEncryptionCipher = createCipher(key, "???", Cipher.ENCRYPT_MODE);
  }

  /** */
  public void createAsymmetricDecryptionCipher() {
    // TODO: replace ??? with algorithm
    asymmetricDecryptionCipher = createCipher(getPrivateKey(), "???", Cipher.DECRYPT_MODE);
  }

  /**
   * @param key
   * @param algorithm
   * @param cipherMode
   * @return
   */
  public Cipher createCipher(Key key, String algorithm, int cipherMode) {
    // TODO: Create a cipher using the given key and algorithm and return it
    // Reference:
    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SimpleEncrEx
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
    } catch (IOException e) { // TODO Auto-generated catch block
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
    } catch (IOException e) { // TODO Auto-generated catch block
      e.printStackTrace();
      return null;
    }
  }
}
