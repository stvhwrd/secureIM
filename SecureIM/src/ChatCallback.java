import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public interface ChatCallback {
	public void onMessage(byte[] message)
			throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;

	public byte[] onRequest(String request) throws RemoteException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InterruptedException, NoSuchAlgorithmException;
}
