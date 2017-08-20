package devin.encryption.symetric.interfaces;

public interface Padding {
	
	int pad(byte[] data, int start, int end);
	int unpad(byte[] data, int start, int end);

}
