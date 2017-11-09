import java.io.UnsupportedEncodingException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
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

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#getName()
   */
  public String getName() throws RemoteException {
    return this.name;
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#setClient(ChatInterface)
   */
  public void setClient(ChatInterface c) {
    client = c;
    connectLatch.countDown();
  }

  public void disconnectClient() {
    client = null;
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#getClient()
   */
  public ChatInterface getClient() {
    return client;
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#sendMessage(java.lang.String)
   */
  public void sendMessage(String s)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException {
    if (callback == null) {
      System.out.println(s);
    } else {
      callback.onMessage(s.getBytes(), null);
    }
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#sendMessage(byte[])
   */
  public void sendMessage(byte[] s)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException {
    if (callback == null) {
      System.out.println(s);
    } else {
      callback.onMessage(s, null);
    }
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#sendMessage(java.lang.String, byte[])
   */
  public void sendMessage(String s, byte[] signedS)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException {
    if (callback == null) {
      System.out.println(s);
    } else {
      callback.onMessage(s.getBytes(), signedS);
    }
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#sendMessage(byte[], byte[])
   */
  public void sendMessage(byte[] s, byte[] signedS)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, SignatureException {
    if (callback == null) {
      System.out.println(s);
    } else {
      callback.onMessage(s, signedS);
    }
  }
  
  public void sendPlainMessage(String s) throws RemoteException {
	  System.out.println(s);
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#sendRequest(java.lang.String)
   */
  public byte[] sendRequest(String request)
      throws RemoteException, UnsupportedEncodingException, IllegalBlockSizeException,
          BadPaddingException, InterruptedException, NoSuchAlgorithmException {
    return callback.onRequest(request);
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#waitForConnection()
   */
  public CountDownLatch waitForConnection() throws RemoteException {
    connectLatch = new CountDownLatch(1);
    return connectLatch;
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#waitForReady()
   */
  public CountDownLatch waitForReady() throws RemoteException {
    readyLatch = new CountDownLatch(1);
    ready = true;
    return readyLatch;
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#removeReadyLatch()
   */
  public void removeReadyLatch() throws RemoteException {
    readyLatch.countDown();
    ready = false;
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#isReady()
   */
  public boolean isReady() throws RemoteException {
    return ready;
  }

  /**
   * (non-Javadoc)
   *
   * @see ChatInterface#registerCallback(ChatCallback)
   */
  public void registerCallback(ChatCallback c) throws RemoteException {
    callback = c;
  }
}
