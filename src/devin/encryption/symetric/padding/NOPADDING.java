package devin.encryption.symetric.padding;

import devin.encryption.symetric.interfaces.BlockCipher;
import devin.encryption.symetric.interfaces.Padding;

public class NOPADDING implements Padding {
	
	public NOPADDING(BlockCipher blockCipher) {
	}
	
	@Override
	public int pad(byte[] data, int start, int end) {
		return end;
	}

	@Override
	public int unpad(byte[] data, int start, int end) {
		return end;
	}

}
