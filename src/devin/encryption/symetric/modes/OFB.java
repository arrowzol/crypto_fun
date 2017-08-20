package devin.encryption.symetric.modes;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Mode;

public class OFB implements Mode {
	
	private final BlockCipher blockCipher;
	
	public OFB(BlockCipher blockCipher) {
		this.blockCipher = blockCipher;
	}
	
	@Override
	public void encryptInplace(byte[] iv, byte[] data, int start, int end) {
		if (start == end) {
			return;
		}
		int blockSize = blockCipher.getBlockSize();
		byte[] state = new byte[blockSize];
		System.arraycopy(iv, 0, state, 0, blockSize);

		outer: while (true) {
			blockCipher.encryptInplace(state, 0);
	    	for (int i=0; i < blockSize; i++) {
	    		data[start++] ^= state[i];
				if (start >= end) {
					break outer;
				}
	    	}
		}
	}
	
	@Override
	public void decryptInplace(byte[] iv, byte[] data, int start, int end) {
		encryptInplace(iv, data, start, end);
	}

	@Override
	public boolean requiresPadding() {
		return false;
	}

}