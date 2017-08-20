package devin.encryption.stream;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import devin.encryption.symetric.interfaces.BlockCipher;

public class StreamCipherFactory {

	public static StreamCipher create(String spec, byte[] iv, byte[] key) {
		String[] spec2 = spec.toUpperCase().split("/");
		
		BlockCipher blockCipher;
		try {
			@SuppressWarnings("unchecked")
			Class<BlockCipher> algorithmClass = (Class<BlockCipher>) Class.forName("devin.encryption.symetric.ciphers." + spec2[0]);
			@SuppressWarnings("unchecked")
			Constructor<BlockCipher> c = (Constructor<BlockCipher>) algorithmClass.getConstructors()[0];
			blockCipher = c.newInstance(key);
		} catch (InvocationTargetException e) {
			throw (RuntimeException) e.getCause();
		} catch (Exception e) {
			throw new RuntimeException("No algorithm " + spec2[0], e);
		}
	
		StreamCipher streamCipher;
		try {
			@SuppressWarnings("unchecked")
			Class<StreamCipher> algorithmClass = (Class<StreamCipher>) Class.forName("devin.encryption.stream.modes." + spec2[1]);
			@SuppressWarnings("unchecked")
			Constructor<StreamCipher> c = (Constructor<StreamCipher>) algorithmClass.getConstructors()[0];
			streamCipher = c.newInstance(iv, blockCipher);
		} catch (InvocationTargetException e) {
			throw (RuntimeException) e.getCause();
		} catch (Exception e) {
			throw new RuntimeException("No mode " + spec2[1], e);
		}
		
		return streamCipher;
	}
	
}
