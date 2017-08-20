package devin.encryption.symetric;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Mode;
import devin.encryption.symetric.interfaces.Padding;

public class SymetricCipherFactory {

	public static SymetricCipher create(String spec, byte[] key) {
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
	
		Mode mode;
		try {
			@SuppressWarnings("unchecked")
			Class<Mode> algorithmClass = (Class<Mode>) Class.forName("devin.encryption.symetric.modes." + spec2[1]);
			@SuppressWarnings("unchecked")
			Constructor<Mode> c = (Constructor<Mode>) algorithmClass.getConstructors()[0];
			mode = c.newInstance(blockCipher);
		} catch (InvocationTargetException e) {
			throw (RuntimeException) e.getCause();
		} catch (Exception e) {
			throw new RuntimeException("No mode " + spec2[1], e);
		}
	
		Padding padding;
		try {
			@SuppressWarnings("unchecked")
			Class<Padding> algorithmClass = (Class<Padding>) Class.forName("devin.encryption.symetric.padding." + spec2[2]);
			@SuppressWarnings("unchecked")
			Constructor<Padding> c = (Constructor<Padding>) algorithmClass.getConstructors()[0];
			padding = c.newInstance(blockCipher);
		} catch (InvocationTargetException e) {
			throw (RuntimeException) e.getCause();
		} catch (Exception e) {
			throw new RuntimeException("No padding " + spec2[2], e);
		}
		
		return new SymetricCipher(padding, mode, blockCipher);
	}
}
