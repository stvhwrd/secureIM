import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CountDownLatch;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class Chat extends UnicastRemoteObject implements ChatInterface {

	private static final long serialVersionUID = 1L;
	public String name;
	public ChatInterface client;
	public CountDownLatch connectLatch;
	public CountDownLatch readyLatch;
	public boolean ready;
	public ChatCallback callback;

	public Chat(String n) throws RemoteException {
		this.name = n;
	}

	public String getName() throws RemoteException {
		return this.name;
	}

	public void setClient(ChatInterface c) {
		client = c;
		connectLatch.countDown();
	}

	public ChatInterface getClient() {
		return client;
	}

	public void sendMessage(String s)
			throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		if (callback == null) {
			System.out.println(s);
		} else {
			callback.onMessage(s.getBytes());
		}
	}

	public byte[] sendRequest(String request) throws RemoteException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InterruptedException, NoSuchAlgorithmException {
		return callback.onRequest(request);
	}

	public CountDownLatch waitForConnection() throws RemoteException {
		connectLatch = new CountDownLatch(1);
		return connectLatch;
	}

	public CountDownLatch waitForReady() throws RemoteException {
		readyLatch = new CountDownLatch(1);
		ready = true;
		return readyLatch;
	}

	public void removeReadyLatch() throws RemoteException {
		readyLatch.countDown();
		ready = false;
	}

	public boolean isReady() throws RemoteException {
		return ready;
	}

	public void registerCallback(ChatCallback c) throws RemoteException {
		callback = c;
	}
}
