import java.io.UnsupportedEncodingException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CountDownLatch;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
 
public interface ChatInterface extends Remote {
	public String getName() throws RemoteException;

	public void sendMessage(String msg) throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;

	public byte[] sendRequest(String request) throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InterruptedException, NoSuchAlgorithmException;
	
	public void setClient(ChatInterface c) throws RemoteException;

	public ChatInterface getClient() throws RemoteException;
	
	public CountDownLatch waitForConnection() throws RemoteException;
	
	public CountDownLatch waitForReady() throws RemoteException;
	
	public void removeReadyLatch() throws RemoteException;
	
	public boolean isReady() throws RemoteException;
	
	public void registerCallback(ChatCallback c) throws RemoteException;
}
