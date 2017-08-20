package devin.encryption.symetric.interfaces;

public interface Mode {
	
	boolean requiresPadding();
	void encryptInplace(byte[] iv, byte[] data, int start, int end);
	void decryptInplace(byte[] iv, byte[] data, int start, int end);

}