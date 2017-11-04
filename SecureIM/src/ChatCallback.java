import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public interface ChatCallback {
	/**
	 * @param message
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void onMessage(byte[] message)
			throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;

	/**
	 * @param request
	 * @return
	 * @throws RemoteException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InterruptedException
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] onRequest(String request) throws RemoteException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InterruptedException, NoSuchAlgorithmException;
}
