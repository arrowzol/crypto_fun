package devin.encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import devin.encryption.stream.StreamCipher;
import devin.encryption.stream.StreamCipherFactory;
import devin.encryption.symetric.SymetricCipher;
import devin.encryption.symetric.SymetricCipherFactory;

public class Test {
	
	private static String[] testSymetricAmps = new String[] {
			"AES/OFB/NoPadding",
			"AES/CFB/NoPadding",
			"AES/CTR/NoPadding",
			"AES/CBC/Pkcs5Padding",
			"AES/PCBC/Pkcs5Padding",
	};

	private static String[] testStreamAlgos = new String[] {
			"AES/OFB/NoPadding",
			"AES/CFB/NoPadding",
			"AES/CTR/NoPadding",
	};
	
	private static byte[] iv = convert("010203040506070810203040506070ff");
	private static String dataString = "00112233445566778899aabbccddeeff0102030405060708";
	private static byte[][] aesKeys = new byte[][] {
		convert("000102030405060708090a0b0c0d0e0f"), // AES128
		convert("000102030405060708090a0b0c0d0e0f0001020304050607"), // AES192
		convert("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"), // AES256
	};
	

    public static void main(String[] args) throws Exception {
    	testSymetric();
    	testStream();
    }

    public static void testStream() throws Exception {
    	for (String algo : testStreamAlgos) {
			for (byte[] key : aesKeys) {
				System.out.println("STREAM: " + algo + " : " + convert(key));

				SymetricCipher symetricCipher = SymetricCipherFactory.create(algo, key);
				
				byte[] data2 = convert(dataString);
				byte[] encrypted = symetricCipher.encrypt(iv, data2, 0, data2.length);
				
				for (int step = 1; step < 18; step++) {
					StreamCipher streamCipher = StreamCipherFactory.create(algo, iv, key);
					byte[] data1 = convert(dataString);

					for (int start = 0; start < data1.length; ) {
						int thisStep = step;
						if (start + step > data1.length) {
							thisStep = data1.length - start;
						}
						streamCipher.encryptInplace(data1, start, start + thisStep);
						start += thisStep;
						for (int i = 0; i < start; i++) {
							if (data1[i] != encrypted[i]) {
								System.out.println("ENC ERR " + start + "," + step);
							}
						}
						for (int i = start; i < data1.length; i++) {
							if (data1[i] != data2[i]) {
								System.out.println("DON'T ENC ERR " + start + "," + step);
							}
						}
					}

					streamCipher = StreamCipherFactory.create(algo, iv, key);
					for (int start = 0; start < data1.length; ) {
						int thisStep = step;
						if (start + step > data1.length) {
							thisStep = data1.length - start;
						}
						streamCipher.decryptInplace(data1, start, start + thisStep);
						start += thisStep;
						for (int i = 0; i < start; i++) {
							if (data1[i] != data2[i]) {
								System.out.println("DEC ERR " + start + "," + step);
							}
						}
						for (int i = start; i < data1.length; i++) {
							if (data1[i] != encrypted[i]) {
								System.out.println("DON'T DEC ERR " + start + "," + step);
							}
						}
					}
				}
			}
    	}
    }
    
    public static void testSymetric() throws Exception {
		for (String amp : testSymetricAmps) {
			for (byte[] key : aesKeys) {
				System.out.println("SYM: " + amp + " : " + convert(key));
				byte[] data = convert(dataString, 32);
				
				Cipher c = Cipher.getInstance(amp);
				SecretKey sk = new SecretKeySpec(key, "AES");
				IvParameterSpec ivSpec = new IvParameterSpec(iv);
				c.init(Cipher.ENCRYPT_MODE, sk, ivSpec);
				SymetricCipher symetricCipher = SymetricCipherFactory.create(amp, key);
	
				for (int len = 24; len >= 0; len--) {
					byte[] ct1 = c.doFinal(data, 0, len);
					String correct = convert(ct1);
					
					String test = convert(symetricCipher.encrypt(iv, data, 0, len));
					if (!correct.equals(test)) {
						System.out.println("BAD ENC1(" + len + "): " + correct + " != " + test);
					}
			
					int encLen = symetricCipher.encryptInplace(iv, data, 0, len);
					test = convert(data, encLen);
					if (!correct.equals(test)) {
						System.out.println("BAD ENC2(" + len + "): " + correct + " != " + test);
					}
					
					correct = dataString.substring(0, len*2);
					test = convert(symetricCipher.decrypt(iv, data, 0, encLen));
					if (!correct.equals(test)) {
						System.out.println("BAD DEC1(" + len + "): " + correct + " != " + test);
					}
					
					symetricCipher.decryptInplace(iv, data, 0, encLen);
					test = convert(data, len);
					if (!correct.equals(test)) {
						System.out.println("BAD DEC2(" + len + "): " + correct + " != " + test);
					}
				}
			}
		}
	}
    
    public static byte[] convert(String s) {
    	return convert(s, s.length()/2);
    }
    
    public static byte[] convert(String s, int len) {
    	byte[] bs = new byte[len];
    	for (int i=0; i < s.length() && i < len*2; i += 2) {
    		bs[i/2] = (byte) Integer.parseInt(s.substring(i, i+2), 16);
    	}
    	return bs;
    }
    
    public static String convert(byte[] bs) {
    	return convert(bs, bs.length);
    }
    
    public static String convert(byte[] bs, int len) {
    	StringBuilder sb = new StringBuilder();
    	for (int i=0; i < bs.length && i < len; i++) {
    		sb.append(Integer.toHexString(0x200 + bs[i]).substring(1));
    	}
    	return sb.toString();
    }

}
