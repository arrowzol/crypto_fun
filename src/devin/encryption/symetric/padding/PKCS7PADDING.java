package devin.encryption.symetric.padding;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Padding;

public class PKCS7PADDING implements Padding {
	
	private BlockCipher blockCipher;
	
	public PKCS7PADDING(BlockCipher blockCipher) {
		this.blockCipher = blockCipher;
	}

	@Override
	public int pad(byte[] data, int start, int end) {
		byte delta = (byte)(blockCipher.getBlockSize() - ((end-start) % blockCipher.getBlockSize()));
		int end2 = end + delta;
		for (int i = end; i < end2; i++) {
			data[i] = delta;
		}
		return end2;
	}

	@Override
	public int unpad(byte[] data, int start, int end) {
		byte delta = data[end-1];
		if (delta <= 0 || delta > blockCipher.getBlockSize()) {
			throw new RuntimeException("Bad padding");
		}
		int end2 = end - delta;
		for (int i = end2; i < end; i++) {
			if (data[i] != delta) {
				throw new RuntimeException("Bad padding");
			}
		}
		return end - delta;
	}

}
