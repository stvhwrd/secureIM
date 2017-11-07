import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoChat {
	Scanner input;
	String keyStore; // Directory where keys are stored
	String passStore; // Directory where password hashes for the other user are stored
	SecurityOptions securityOptions;
	Cipher symmetricEncryptionCipher;
	Cipher symmetricDecryptionCipher;
	Cipher asymmetricEncryptionCipher;
	Cipher asymmetricDecryptionCipher;

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

	/**
	 * @return
	 */
	public SecurityOptions getSecurityOptions() {
		if (securityOptions != null) {
			return securityOptions;
		}

		return getSecurityOptionsFromUser();
	}

	/**
	 * @return
	 */
	public SecurityOptions getSecurityOptionsFromUser() {
		// TODO
		// Prompt the user for the security options they want enabled using the
		// Scanner object input (global object in this class)
		// They can choose from Confidentiality, Integrity, and/or Authentication

		// Placeholder which disables all three options:
		SecurityOptions securityOptions = new SecurityOptions(false, false, false);
		
		System.out.println("Choose your security options where 1 is Confidentiality, 2 is Integrity, and 3 is Authentication: ");
		Scanner scanner = new Scanner(System.in);
	    try {
	    	String options = scanner.nextLine();
			switch( options ) {
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
				default:
					throw new IllegalArgumentException("Invalid security option: " + options);
			}
	    } finally {
	        scanner.close();
	    }
		System.out.println("Your selected security options were: " + securityOptions);
		
		this.securityOptions = securityOptions;
		return securityOptions;
	}

	/**
	 * @return
	 */
	public byte[] getPasswordFromUser() {
		// TODO
		// Prompt the user for their password using the
		// Scanner object input (global object in this class)
		/*System.out.println("Please enter your password:");
		Scanner scanner = new Scanner(System.in);
		String password = scanner.nextLine();
		System.out.println(password);*/
		return "password".getBytes(); // placeholder
	}

	/**
	 * 
	 */
	public void createKeyPair() {
		// TODO
		// Check if the files public.key and private.key exist
		// If not, create them:
		// http://esus.com/programmatically-generating-public-private-key/
		// Use saveFile(), eg: saveToFile("publickey", keyStore + "/" + "public.key")
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

	/**
	 * @param secretKeyData
	 */
	public void setSecretKey(byte[] secretKeyData) {
		saveToFile(secretKeyData, keyStore + "/" + "secret.key");
	}

	/**
	 * @return
	 */
	public PublicKey getPublicKey() {
		byte[] keyData = readFromFile(keyStore + "/" + "public.key");

		// TODO: Convert it to a PublicKey object and return it

		return null; // placeholder
	}

	/**
	 * @return
	 */
	public PrivateKey getPrivateKey() {
		byte[] keyData = readFromFile(keyStore + "/" + "private.key");

		// TODO: Convert it to a PrivateKey object and return it

		return null; // placeholder
	}

	/**
	 * @return
	 */
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

	/**
	 * 
	 */
	public void createSymmetricCiphers() {
		// TODO: replace ??? with algorithm
		symmetricEncryptionCipher = createCipher(getSecretKey(), "???", Cipher.ENCRYPT_MODE);
		symmetricDecryptionCipher = createCipher(getSecretKey(), "???", Cipher.DECRYPT_MODE);
	}

	/**
	 * @param otherUserPublicKey
	 */
	public void createAsymmetricEncryptionCipher(byte[] otherUserPublicKey) {
		// TODO
		// Convert otherUserPublicKey to Key (or PublicKey object)
		// and replace ??? with algorithm
		PublicKey key = null; // placeholder
		asymmetricEncryptionCipher = createCipher(key, "???", Cipher.ENCRYPT_MODE);
	}

	/**
	 * 
	 */
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
	public byte[] encryptSymmetric(byte[] message) throws IllegalBlockSizeException, BadPaddingException {
		return symmetricEncryptionCipher.doFinal(message);
	}

	/**
	 * @param encrypted
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] decryptSymmetric(byte[] encrypted) throws IllegalBlockSizeException, BadPaddingException {
		return symmetricDecryptionCipher.doFinal(encrypted);
	}

	/**
	 * @param message
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] encryptPublic(byte[] message) throws IllegalBlockSizeException, BadPaddingException {
		return asymmetricEncryptionCipher.doFinal(message);
	}

	/**
	 * @param encrypted
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] decryptPrivate(byte[] encrypted) throws IllegalBlockSizeException, BadPaddingException {
		return asymmetricDecryptionCipher.doFinal(encrypted);
	}

	/**
	 * @param contents
	 * @param filename
	 */
	public void saveToFile(byte[] contents, String filename) {
		// TODO
	}

	/**
	 * @param filename
	 * @return
	 */
	public byte[] readFromFile(String filename) {
		// TODO
		return "file contents".getBytes();
	}
}
