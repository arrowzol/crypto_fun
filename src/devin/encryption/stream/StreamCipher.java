package devin.encryption.stream;

public abstract class StreamCipher {

	public void encryptInplace(byte[] data) {
		encryptInplace(data, 0, data.length);
	}
	
	public abstract void encryptInplace(byte[] data, int start, int end);
	
	public void decryptInplace(byte[] data) {
		encryptInplace(data, 0, data.length);
	}
	
	public abstract void decryptInplace(byte[] data, int start, int end);

}
