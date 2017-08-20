package devin.encryption.symetric.modes;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Mode;

public class ECB implements Mode {
	
	private final BlockCipher blockCipher;
	
	public ECB(BlockCipher cipher) {
		this.blockCipher = cipher;
	}

	@Override
	public void encryptInplace(byte[] iv, byte[] data, int start, int end) {
		while (start < end) {
			blockCipher.encryptInplace(data, start);
			start += blockCipher.getBlockSize();
		}
	}
	
	@Override
	public void decryptInplace(byte[] iv, byte[] data, int start, int end) {
		while (start < end) {
			blockCipher.decryptInplace(data, start);
			start += blockCipher.getBlockSize();
		}
	}

	@Override
	public boolean requiresPadding() {
		return true;
	}

}