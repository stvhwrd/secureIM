import java.rmi.*;

public interface ChatInterface extends Remote {
	public String getName() throws RemoteException;

	public void send(String msg) throws RemoteException;

	public void setClient(ChatInterface c) throws RemoteException;

	public ChatInterface getClient() throws RemoteException;
}
