package devin.encryption.stream.modes;

import devin.encryption.stream.StreamCipher;
import devin.encryption.symetric.interfaces.BlockCipher;

public class CTR extends StreamCipher {
	
	private final BlockCipher blockCipher;
	private int stateIndex;
	private byte[] state1;
	private byte[] state2;
	
	public CTR(byte[] iv, BlockCipher blockCipher) {
		this.blockCipher = blockCipher;
		stateIndex = blockCipher.getBlockSize();
		state1 = new byte[stateIndex];
		state2 = new byte[stateIndex];
		System.arraycopy(iv, 0, state1, 0, stateIndex);
	}
	
	@Override
	public void encryptInplace(byte[] data, int start, int end) {
		if (start == end) {
			return;
		}
		int blockSize = blockCipher.getBlockSize();
		
    	while (start < end) {
    		if (stateIndex == blockSize) {
    			System.arraycopy(state1, 0, state2, 0, blockSize);
    			blockCipher.encryptInplace(state2, 0);
    	    	for (int i=blockSize-1; i >= 0; i--) {
    	    		if (++state1[i] != 0) {
    	    			break;
    	    		}
    	    	}
    			stateIndex = 0;
    		}
    		data[start++] ^= state2[stateIndex++];
    	}
	}

	@Override
	public void decryptInplace(byte[] data, int start, int end) {
		encryptInplace(data, start, end);
	}
	
}