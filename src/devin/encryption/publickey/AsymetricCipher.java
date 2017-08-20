package devin.encryption.publickey;

import java.math.BigInteger;

public interface AsymetricCipher {

	BigInteger rawEncrypt(BigInteger pt);
	BigInteger rawDecrypt(BigInteger pt);
	
}
