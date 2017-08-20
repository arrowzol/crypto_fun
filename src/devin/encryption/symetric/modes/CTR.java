package devin.encryption.symetric.modes;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Mode;

public class CTR implements Mode {
	
	private final BlockCipher blockCipher;
	
	public CTR(BlockCipher blockCipher) {
		this.blockCipher = blockCipher;
	}
	
	@Override
	public void encryptInplace(byte[] iv, byte[] data, int start, int end) {
		if (start == end) {
			return;
		}
		int blockSize = blockCipher.getBlockSize();
		byte[] state1 = new byte[blockSize];
		byte[] state2 = new byte[blockSize];
		System.arraycopy(iv, 0, state1, 0, iv.length);

		outer: while (true) {
			System.arraycopy(state1, 0, state2, 0, blockSize);
			blockCipher.encryptInplace(state2, 0);
	    	for (int i=0; i < blockSize; i++) {
	    		data[start++] ^= state2[i];
				if (start >= end) {
					break outer;
				}
	    	}
	    	for (int i=blockSize-1; i >= 0; i--) {
	    		if (++state1[i] != 0) {
	    			break;
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