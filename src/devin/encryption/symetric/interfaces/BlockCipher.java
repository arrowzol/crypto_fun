package devin.encryption.symetric.interfaces;

public interface BlockCipher {

	public void setKey(byte[] key);
	public int getBlockSize();
	public void encryptInplace(byte[] block, int start);
	public void decryptInplace(byte[] block, int start);
	
}
