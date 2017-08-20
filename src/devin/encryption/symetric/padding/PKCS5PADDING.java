package devin.encryption.symetric.padding;

import devin.encryption.symetric.interfaces.BlockCipher;

public class PKCS5PADDING extends PKCS7PADDING {

	public PKCS5PADDING(BlockCipher blockCipher) {
		super(blockCipher);
	}

}
