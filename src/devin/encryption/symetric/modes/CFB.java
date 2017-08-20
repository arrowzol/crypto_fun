package devin.encryption.symetric.modes;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Mode;

public class CFB implements Mode {
	
	private final BlockCipher blockCipher;
	
	public CFB(BlockCipher blockCipher) {
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
			int start1 = start;
	    	for (int i=0; i < blockSize; i++) {
	    		data[start++] ^= state[i];
				if (start >= end) {
					break outer;
				}
	    	}
	    	System.arraycopy(data, start1, state, 0, blockSize);
		}
	}
	
	@Override
	public void decryptInplace(byte[] iv, byte[] data, int start, int end) {
		if (start == end) {
			return;
		}
		int blockSize = blockCipher.getBlockSize();
		byte[] state1 = new byte[blockSize];
		byte[] state2 = new byte[blockSize];
		System.arraycopy(iv, 0, state1, 0, blockSize);

		outer: while (true) {
			blockCipher.encryptInplace(state1, 0);
			if (start + blockSize <= end) {
				System.arraycopy(data, start, state2, 0, blockSize);
			}
	    	for (int i=0; i < blockSize; i++) {
	    		data[start++] ^= state1[i];
				if (start >= end) {
					break outer;
				}
	    	}
	    	
	    	// swap state1 & state2
	    	byte[] tmp = state2;
	    	state2 = state1;
	    	state1 = tmp;
		}
	}

	@Override
	public boolean requiresPadding() {
		return false;
	}

}