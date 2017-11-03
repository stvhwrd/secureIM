import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public interface ChatCallback {
	public void onMessage(byte[] message) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException;
}
