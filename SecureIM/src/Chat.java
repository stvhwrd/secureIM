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

	/**
	 * @param n
	 * @throws RemoteException
	 */
	public Chat(String n) throws RemoteException {
		this.name = n;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#getName()
	 */
	public String getName() throws RemoteException {
		return this.name;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#setClient(ChatInterface)
	 */
	public void setClient(ChatInterface c) {
		client = c;
		connectLatch.countDown();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#getClient()
	 */
	public ChatInterface getClient() {
		return client;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#sendMessage(java.lang.String)
	 */
	public void sendMessage(String s)
			throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		if (callback == null) {
			System.out.println(s);
		} else {
			callback.onMessage(s.getBytes());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#sendRequest(java.lang.String)
	 */
	public byte[] sendRequest(String request) throws RemoteException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InterruptedException, NoSuchAlgorithmException {
		return callback.onRequest(request);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#waitForConnection()
	 */
	public CountDownLatch waitForConnection() throws RemoteException {
		connectLatch = new CountDownLatch(1);
		return connectLatch;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#waitForReady()
	 */
	public CountDownLatch waitForReady() throws RemoteException {
		readyLatch = new CountDownLatch(1);
		ready = true;
		return readyLatch;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#removeReadyLatch()
	 */
	public void removeReadyLatch() throws RemoteException {
		readyLatch.countDown();
		ready = false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#isReady()
	 */
	public boolean isReady() throws RemoteException {
		return ready;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see ChatInterface#registerCallback(ChatCallback)
	 */
	public void registerCallback(ChatCallback c) throws RemoteException {
		callback = c;
	}
}
