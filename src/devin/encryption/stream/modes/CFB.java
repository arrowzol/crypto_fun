package devin.encryption.stream.modes;

import devin.encryption.stream.StreamCipher;
import devin.encryption.symetric.interfaces.BlockCipher;

public class CFB extends StreamCipher {
	
	private final BlockCipher blockCipher;
	private int stateIndex;
	private byte[] state1;
	private byte[] state2;
	
	public CFB(byte[] iv, BlockCipher blockCipher) {
		this.blockCipher = blockCipher;
		stateIndex = blockCipher.getBlockSize();
		state1 = new byte[stateIndex];
		state2 = new byte[stateIndex];
		System.arraycopy(iv, 0, state2, 0, stateIndex);
	}
	
	@Override
	public void encryptInplace(byte[] data, int start, int end) {
		if (start == end) {
			return;
		}
		int blockSize = blockCipher.getBlockSize();

		while (true) {
    		if (stateIndex == blockSize) {
    			stateIndex = 0;

    			// swap state1 & state2
    	    	byte[] tmp = state2;
    	    	state2 = state1;
    	    	state1 = tmp;

    	    	blockCipher.encryptInplace(state1, 0);
    		}
    		byte b = data[start];
			b ^= state1[stateIndex];
    		state2[stateIndex++] = b;
    		data[start++] = b;
			if (start >= end) {
				break;
			}
		}
	}

	@Override
	public void decryptInplace(byte[] data, int start, int end) {
		if (start == end) {
			return;
		}
		int blockSize = blockCipher.getBlockSize();

		while (true) {
    		if (stateIndex == blockSize) {
    			stateIndex = 0;

    			// swap state1 & state2
    	    	byte[] tmp = state2;
    	    	state2 = state1;
    	    	state1 = tmp;

    	    	blockCipher.encryptInplace(state1, 0);
    		}
			
    		byte b = data[start];
    		state2[stateIndex] = b;
			b ^= state1[stateIndex++];
    		data[start++] = b;
			if (start >= end) {
				break;
			}
		}
	}
	
}