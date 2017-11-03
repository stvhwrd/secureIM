import java.io.UnsupportedEncodingException;
import java.rmi.*;
import java.rmi.server.*;
import java.security.PublicKey;
import java.util.concurrent.CountDownLatch;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class Chat extends UnicastRemoteObject implements ChatInterface {

	public String name;
	public ChatInterface client;
	public CountDownLatch clientLatch;
	public CountDownLatch serverLatch;
	public byte[] clientResponse;
	public byte[] serverResponse;
	public ChatCallback callback;

	public Chat(String n) throws RemoteException {
		this.name = n;
	}

	public String getName() throws RemoteException {
		return this.name;
	}

	public void setClient(ChatInterface c) {
		client = c;
		serverLatch.countDown();
	}

	public ChatInterface getClient() {
		return client;
	}

	public void send(String s) throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		if (callback == null) {
			System.out.println(s);
		} else {
			callback.onMessage(s.getBytes());
		}
	}
	
	public CountDownLatch waitForClient() throws RemoteException {
		serverLatch = new CountDownLatch(1);
		return serverLatch;
	}
	
	public void respondToServer(byte[] r) throws RemoteException {
		clientResponse = r;
		serverLatch.countDown();
	}
	
	public CountDownLatch waitForServer() throws RemoteException {
		clientLatch = new CountDownLatch(1);
		return clientLatch;
	}
	
	public void respondToClient(byte[] r) throws RemoteException {
		serverResponse = r;
		clientLatch.countDown();
	}
	
	public byte[] getClientResponse() throws RemoteException {
		return clientResponse;
	}
	
	public byte[] getServerResponse() throws RemoteException {
		return serverResponse;
	}
	
	public void registerCallback(ChatCallback c) throws RemoteException {
		callback = c;
	}
}
