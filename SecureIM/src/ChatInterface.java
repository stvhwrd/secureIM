import java.io.UnsupportedEncodingException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.concurrent.CountDownLatch;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
 
public interface ChatInterface extends Remote {
	public String getName() throws RemoteException;

	public void send(String msg) throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;

	public void setClient(ChatInterface c) throws RemoteException;

	public ChatInterface getClient() throws RemoteException;
	
	public CountDownLatch waitForClient() throws RemoteException;
	
	public CountDownLatch waitForServer() throws RemoteException;

	public void respondToClient(byte[] r) throws RemoteException;
	
	public void respondToServer(byte[] r) throws RemoteException;
	
	public byte[] getClientResponse() throws RemoteException;
	
	public byte[] getServerResponse() throws RemoteException;
	
	public void registerCallback(ChatCallback c) throws RemoteException;
}
