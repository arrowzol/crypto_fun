package devin.encryption.symetric.modes;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Mode;

public class PCBC implements Mode {

	private final BlockCipher blockCipher;
	
	public PCBC(BlockCipher blockCipher) {
		this.blockCipher = blockCipher;
	}
	
	@Override
	public void encryptInplace(byte[] iv, byte[] data, int start, int end) {
		int blockSize = blockCipher.getBlockSize();
		byte[] state1 = new byte[blockSize];
		byte[] state2 = null;
		System.arraycopy(iv, 0, state1, 0, blockSize);
		
		if (end - start > blockSize) {
			state2 = new byte[blockSize];
			System.arraycopy(data, start, state2, 0, blockSize);
		}
		
		while (true) {
	    	for (int i=0; i < blockSize; i++) {
	    		data[start+i] ^= state1[i];
	    	}
	    	blockCipher.encryptInplace(data, start);
	    	
			int start2 = start + blockCipher.getBlockSize();
			if (start2 >= end) {
				break;
			}

			// xor state2 into data
	    	for (int i=0; i < blockSize; i++) {
	    		state2[i] ^= data[start+i];
	    	}
	    	
	    	// swap state1 & state2
	    	byte[] tmp = state2;
	    	state2 = state1;
	    	state1 = tmp;
	    	
	    	// advance
			start = start2;
			
			// save plaintext to generate next iv
			System.arraycopy(data, start, state2, 0, blockSize);
		}
	}

	@Override
	public void decryptInplace(byte[] iv, byte[] data, int start, int end) {
		int blockSize = blockCipher.getBlockSize();
		byte[] state1 = new byte[blockSize];
		byte[] state2 = null;
		System.arraycopy(iv, 0, state1, 0, blockSize);
		
		if (end - start > blockSize) {
			state2 = new byte[blockSize];
			System.arraycopy(data, start, state2, 0, blockSize);
		}
		
		while (true) {
	    	blockCipher.decryptInplace(data, start);
	    	for (int i=0; i < blockSize; i++) {
	    		data[start+i] ^= state1[i];
	    	}

			int start2 = start + blockCipher.getBlockSize();
			if (start2 >= end) {
				break;
			}

			// xor state2 into data
	    	for (int i=0; i < blockSize; i++) {
	    		state2[i] ^= data[start+i];
	    	}
	    	
	    	// swap state1 & state2
	    	byte[] tmp = state2;
	    	state2 = state1;
	    	state1 = tmp;
	    	
	    	// advance
			start = start2;
			
			// save plaintext to generate next iv
			System.arraycopy(data, start, state2, 0, blockSize);
		}
	}

	@Override
	public boolean requiresPadding() {
		return true;
	}

}
