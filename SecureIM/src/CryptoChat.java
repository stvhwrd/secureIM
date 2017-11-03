import java.security.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class CryptoChat {
	Scanner input;
	String keyStore;	// Directory where keys are stored
	String passStore;	// Directory where password hashes for the other user are stored
	SecurityOptions securityOptions;
	Cipher symmetricEncryptionCipher;
	Cipher symmetricDecryptionCipher;
	Cipher asymmetricEncryptionCipher;
	Cipher asymmetricDecryptionCipher;
	
	public CryptoChat(Scanner input, String keyStore, String passStore) {
		this.input = input;
		this.keyStore = keyStore;
		this.passStore = passStore;
	}
	
	public SecurityOptions getSecurityOptions() {
		if (securityOptions != null) {
			return securityOptions;
		}
		
		return getSecurityOptionsFromUser();
	}
	
	public SecurityOptions getSecurityOptionsFromUser() {
		// TODO
		// Prompt the user for the security options they want enabled using the
		// Scanner object input (global object in this class)
		// They can choose from Confidentiality, Integrity, and/or Authentication
		
		// Placeholder which disables all three options:
		SecurityOptions securityOptions = new SecurityOptions(false, false, false);
		
		this.securityOptions = securityOptions;
		return securityOptions;
	}
	
	public byte[] getPasswordFromUser() {
		// TODO
		// Prompt the user for their password using the
		// Scanner object input (global object in this class)
		return "password".getBytes();	// placeholder
	}
	
	public void createKeyPair() {
		// TODO
		// Check if the files public.key and private.key exist
		// If not, create them: http://esus.com/programmatically-generating-public-private-key/
		// Use saveFile(), eg: saveToFile("publickey", keyStore + "/" + "public.key")
	}
	
	public byte[] createSecretKey() throws NoSuchAlgorithmException {
		// Create a secret (symmetric) key: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SimpleEncrEx
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
	    SecretKey aesKey = keygen.generateKey();
	    byte[] aesKeyData = aesKey.getEncoded();
	    
		saveToFile(aesKeyData, keyStore + "/" + "secret.key");
	    
		return aesKeyData;
	}
	
	public void setSecretKey(byte[] secretKeyData) {
		saveToFile(secretKeyData, keyStore + "/" + "secret.key");
	}
	
	public PublicKey getPublicKey() {
		byte[] keyData = readFromFile(keyStore + "/" + "public.key");
		
		// TODO: Convert it to a PublicKey object and return it
		
		return null;	// placeholder
	}
	
	public PrivateKey getPrivateKey() {
		byte[] keyData = readFromFile(keyStore + "/" + "private.key");
		
		// TODO: Convert it to a PrivateKey object and return it
		
		return null;	// placeholder
	}
	
	public SecretKey getSecretKey() {
		byte[] aesKeyData = readFromFile(keyStore + "/" + "secret.key");
		
		// Convert it to a SecretKey object: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SecretKeyFactory
	    SecretKeySpec secretKey = new SecretKeySpec(aesKeyData, "AES");
		return secretKey;
	}
	
	// Returns true if hashedPass is a valid password for username
	public boolean authenticateUser(String username, byte[] hashedPass) {
		// TODO
		// Check if the file which would contain the user's password exists
		// ie <passStore>/<username>.password
		// If it exists, get the contents (use readFromFile() method in this class)
		// and compare the hash with hashedPass
		
		return true;	// placeholder
	}
	
	public byte[] hashPassword(String password) {
		// TODO hash the password and return it
		return "".getBytes();	// placeholder
	}
	
	public void createPassword(String username, String plaintext) {
    	// Hash the plaintext password
    	byte[] hashedPassword = hashPassword(plaintext);
    	
    	String filename = passStore + "/" + username + ".passowrd";
    	
    	saveToFile(hashedPassword, filename);
	}
	
	public void createSymmetricCiphers() {
		// TODO: replace ??? with algorithm
		symmetricEncryptionCipher = createCipher(getSecretKey(), "???", Cipher.ENCRYPT_MODE);
		symmetricDecryptionCipher = createCipher(getSecretKey(), "???", Cipher.DECRYPT_MODE);
	}
	
	public void createAsymmetricEncryptionCipher(byte[] otherUserPublicKey) {
		// TODO
		// Convert otherUserPublicKey to Key (or PublicKey object)
		// and replace ??? with algorithm
		PublicKey key = null;	// placeholder
		asymmetricEncryptionCipher = createCipher(key, "???", Cipher.ENCRYPT_MODE);
	}
	
	public void createAsymmetricDecryptionCipher() {
		// TODO: replace ??? with algorithm
		asymmetricDecryptionCipher = createCipher(getPrivateKey(), "???", Cipher.DECRYPT_MODE);
	}
	
	public Cipher createCipher(Key key, String algorithm, int cipherMode) {
		// TODO: Create a cipher using the given key and algorithm and return it
		// Reference: https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#SimpleEncrEx
		return null;	// placeholder
	}
	
	public byte[] encryptSymmetric(byte[] message) throws IllegalBlockSizeException, BadPaddingException {
		return symmetricEncryptionCipher.doFinal(message);
	}
	
	public byte[] decryptSymmetric(byte[] encrypted) throws IllegalBlockSizeException, BadPaddingException {
		return symmetricDecryptionCipher.doFinal(encrypted);
	}
	
	public byte[] encryptPublic(byte[] message) throws IllegalBlockSizeException, BadPaddingException {
		return asymmetricEncryptionCipher.doFinal(message);
	}
	
	public byte[] decryptPrivate(byte[] encrypted) throws IllegalBlockSizeException, BadPaddingException {
		return asymmetricDecryptionCipher.doFinal(encrypted);
	}
	
	public void saveToFile(byte[] contents, String filename) {
		// TODO
	}
	
	public byte[] readFromFile(String filename) {
		// TODO
		return "file contents".getBytes();
	}
}
