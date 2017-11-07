import java.io.UnsupportedEncodingException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.concurrent.CountDownLatch;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public interface ChatInterface extends Remote {
  /**
   * @return
   * @throws RemoteException
   */
  public String getName() throws RemoteException;

  /**
   * @param msg
   * @throws RemoteException
   * @throws UnsupportedEncodingException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public void sendMessage(String message)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException;

  public void sendMessage(byte[] message)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException;

  public void sendMessage(String message, byte[] signedMessage)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException;

  public void sendMessage(byte[] message, byte[] signedMessage)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException;

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
  public byte[] sendRequest(String request)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, InterruptedException, NoSuchAlgorithmException;

  /**
   * @param c
   * @throws RemoteException
   */
  public void setClient(ChatInterface c) throws RemoteException;

  /**
   * @return
   * @throws RemoteException
   */
  public ChatInterface getClient() throws RemoteException;

  /**
   * @return
   * @throws RemoteException
   */
  public CountDownLatch waitForConnection() throws RemoteException;

  /**
   * @return
   * @throws RemoteException
   */
  public CountDownLatch waitForReady() throws RemoteException;

  /** @throws RemoteException */
  public void removeReadyLatch() throws RemoteException;

  /**
   * @return
   * @throws RemoteException
   */
  public boolean isReady() throws RemoteException;

  /**
   * @param c
   * @throws RemoteException
   */
  public void registerCallback(ChatCallback c) throws RemoteException;
}
