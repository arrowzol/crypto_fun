package devin.encryption.stream.modes;

import devin.encryption.stream.StreamCipher;
import devin.encryption.symetric.interfaces.BlockCipher;

public class OFB extends StreamCipher {
	
	private final BlockCipher blockCipher;
	private int stateIndex;
	private byte[] state;
	
	public OFB(byte[] iv, BlockCipher blockCipher) {
		this.blockCipher = blockCipher;
		stateIndex = blockCipher.getBlockSize();
		state = new byte[stateIndex];
		System.arraycopy(iv, 0, state, 0, stateIndex);
	}
	
	@Override
	public void encryptInplace(byte[] data, int start, int end) {
		if (start == end) {
			return;
		}
		int blockSize = blockCipher.getBlockSize();
		
    	while (start < end) {
    		if (stateIndex == blockSize) {
    			blockCipher.encryptInplace(state, 0);
    			stateIndex = 0;
    		}
    		data[start++] ^= state[stateIndex++];
    	}
	}

	@Override
	public void decryptInplace(byte[] data, int start, int end) {
		encryptInplace(data, start, end);
	}
	
}