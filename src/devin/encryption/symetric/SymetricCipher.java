package devin.encryption.symetric;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Mode;
import devin.encryption.symetric.interfaces.Padding;

public class SymetricCipher {
	
	private Padding padding;
	private Mode mode;
	private BlockCipher blockCipher;
	
	protected SymetricCipher(Padding padding, Mode mode, BlockCipher blockCipher) {
		this.padding = padding;
		this.mode = mode;
		this.blockCipher = blockCipher;
	}

	public int encryptInplace(byte[] iv, byte[] data, int start, int end) {
		end = padding.pad(data, start, end);
		mode.encryptInplace(iv, data, start, end);
		return end;
	}
	
	public int decryptInplace(byte[] iv, byte[] data, int start, int end) {
		mode.decryptInplace(iv, data, start, end);
		return padding.unpad(data, start, end);
	}

	public byte[] encrypt(byte[] iv, byte[] data, int start, int end) {
		byte[] result;
		int newLen = end - start;
		if (mode.requiresPadding()) {
			int blockSize = blockCipher.getBlockSize();
			newLen = (1 + newLen/blockSize) * blockSize;
		}
		result = new byte[newLen];
		System.arraycopy(data, start, result, 0, end - start);
		padding.pad(result, 0, end-start);
		mode.encryptInplace(iv, result, 0, newLen);
		return result;
	}
	
	public byte[] decrypt(byte[] iv, byte[] data, int start, int end) {
		int len = end-start;
		byte[] result1 = new byte[len];
		System.arraycopy(data, start, result1, 0, len);
		mode.decryptInplace(iv, result1, 0, len);
		int newLen = padding.unpad(result1, 0, len);
		if (newLen == len) {
			return result1;
		}
		byte[] result2 = new byte[newLen];
		System.arraycopy(result1, 0, result2, 0, newLen);
		return result2;
	}

}
