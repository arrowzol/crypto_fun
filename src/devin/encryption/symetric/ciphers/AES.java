package devin.encryption.symetric.ciphers;

import java.nio.ByteBuffer;

import devin.encryption.symetric.interfaces.BlockCipher;

// Federal Information Processing Standards Publication 197 (FIPS PUB 197)
public class AES implements BlockCipher {
	
    // Section 5.1.1, Figure 7
	private static final byte[] sbox = {
		(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76,
		(byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0, (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0,
		(byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc, (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15,
		(byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75,
		(byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0, (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84,
		(byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b, (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf,
		(byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8,
		(byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5, (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2,
		(byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73,
		(byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb,
		(byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79,
		(byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9, (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08,
		(byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a,
		(byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e,
		(byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf,
		(byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16,
	};
	
	// Section 5.3.2, Figure 14
    private static final byte[] invSbox = {
		(byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38, (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb,
		(byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87, (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb,
		(byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d, (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e,
		(byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2, (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25,
		(byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92,
		(byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84,
		(byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a, (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06,
		(byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02, (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b,
		(byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea, (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73,
		(byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85, (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e,
		(byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89, (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b,
		(byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20, (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4,
		(byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31, (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f,
		(byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d, (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef,
		(byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0, (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61,
		(byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26, (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d,
    };
    
    // section 5.2
    private static final byte[] rcon = {
	    (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, 
	    (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39, 
	    (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a, 
	    (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8, 
	    (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, 
	    (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc, 
	    (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, 
	    (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3, 
	    (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94, 
	    (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, (byte)0x08, (byte)0x10, (byte)0x20, 
	    (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, (byte)0xc6, (byte)0x97, (byte)0x35, 
	    (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, (byte)0x61, (byte)0xc2, (byte)0x9f, 
	    (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, (byte)0x01, (byte)0x02, (byte)0x04, 
	    (byte)0x08, (byte)0x10, (byte)0x20, (byte)0x40, (byte)0x80, (byte)0x1b, (byte)0x36, (byte)0x6c, (byte)0xd8, (byte)0xab, (byte)0x4d, (byte)0x9a, (byte)0x2f, (byte)0x5e, (byte)0xbc, (byte)0x63, 
	    (byte)0xc6, (byte)0x97, (byte)0x35, (byte)0x6a, (byte)0xd4, (byte)0xb3, (byte)0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, (byte)0x39, (byte)0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, 
	    (byte)0x61, (byte)0xc2, (byte)0x9f, (byte)0x25, (byte)0x4a, (byte)0x94, (byte)0x33, (byte)0x66, (byte)0xcc, (byte)0x83, (byte)0x1d, (byte)0x3a, (byte)0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d
	};
    
	private int rounds;
	
    // (w)ords, filled in by key expansion and used by addRoundKey
	private int[] w;
	
	public void setKey(byte[] key) {
    	int Nk = key.length/4;
    	rounds = 6 + Nk;
    	w = keyExpansion(key, rounds, Nk);
	}

	/** Make a word out of 4 bytes.
	 * 
	 * @param a byte 3
	 * @param b byte 2
	 * @param c byte 1
	 * @param d byte 0
	 * @return The word containing a, b, c, and d
	 */
    private static int mkWord(byte a, byte b, byte c, byte d) {
    	return (0xFF & a) << 24 | (0xFF & b) << 16 | (0xFF & c) << 8 | (0xFF & d);
    }
    
    /** Do sbox substitution on the bytes of a word.
     *  
     * @param word The word to substitute for
     * @return The substituted results
     */
    private static int subWord(int word) {
    	return mkWord(sbox[(int)(0xFF & (word >> 24))], sbox[(int)(0xFF & (word >> 16))], sbox[(int)(0xFF & (word >> 8))], sbox[(int)(0xFF & (word))]);
    }
    
    /** Rotate work 8 bits left, wrapping.
     * 
     * @param word The word to rotate
     * @return A rotated version of the word
     */
    private static int rotWord(int word) {
    	return (word << 8) | (word >>> 24);
    }

    // Section 5.2, Figure 11
    private static int[] keyExpansion(byte[] key, int Nr, int Nk) {
    	int[] w = new int[4*(Nr+1)];
	    int temp;
	
	    int i = 0;
	    while (i < Nk) {
		    w[i] = mkWord(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
		    i += 1;
	    }
	
	    i = Nk;
	    while (i < 4 * (Nr+1)) {
		    temp = w[i-1];
		
		    if (i % Nk == 0) {
		    	temp = subWord(rotWord(temp)) ^ (rcon[i/Nk] << 24);
		    } else if (Nk > 6 && (i % Nk == 4)) {
			    temp = subWord(temp);
		    }
		
		    w[i] = w[i-Nk] ^ temp;
		    i += 1;
	    }
	    return w;
    }
    
	@Override
	public int getBlockSize() {
		return 16;
	}

    private void addRoundKey(ByteBuffer data, int start, int wStart) {
    	for (int i=0; i < 4; i++) {
    		data.putInt(start + i*4, data.getInt(start + i*4) ^ w[wStart + i]);
    	}
    }
    
    // section 5.1.1
    /** Do sbox substitution on 16 bytes.
     * 
     * @param data An array containing the data.
     * @param start The first index of the 4x4 matrix of bytes.
     */
    private static void subBytes(byte[] data, int start) {
    	for (int i=0; i < 16; i++) {
    		data[start + i] = sbox[0xFF & data[start + i]];
    	}
    }
    
    // section 5.3.2
    /** Undoes {@link #subBytes(byte[], int)}.
     * 
     * @param data An array containing the data.
     * @param start The first index of the 4x4 matrix of bytes.
     */
    private static void invSubBytes(byte[] data, int start) {
    	for (int i=0; i < 16; i++) {
    		data[start + i] = invSbox[0xFF & data[start + i]];
    	}
    }
    
    // section 5.1.2
    /** Perform the shift rows operation.
     * 
     * <p> This takes 16 bytes (indexed from start to start+15) as a 4x4 matrix and "rotates" each row. </p>
     * <p> The function {@link #invShiftRows(byte[], int)} undoes this function. </p>
     * 
     * 
     * @param data An array containing the data.
     * @param start The first index of the 4x4 matrix of bytes.
     */
    private static void shiftRows(byte[] data, int start) {
    	byte tmp;
    	
    	// 13 -> 9 -> 5 -> 1 -> 13
    	tmp = data[start + 1];
    	data[start + 1] = data[start + 5];
    	data[start + 5] = data[start + 9];
    	data[start + 9] = data[start + 13];
    	data[start + 13] = tmp;
    	
    	// 14 -> 6 -> 14
    	// 10 -> 2 -> 10
    	tmp = data[start + 2];
    	data[start + 2] = data[start + 10];
    	data[start + 10] = tmp;
    	tmp = data[start + 6];
    	data[start + 6] = data[start + 14];
    	data[start + 14] = tmp;
    	
    	// 3 -> 7 -> 11 -> 15 -> 3
    	tmp = data[start + 15];
    	data[start + 15] = data[start + 11];
    	data[start + 11] = data[start + 7];
    	data[start + 7] = data[start + 3];
    	data[start + 3] = tmp;
    }
    
    // section 5.3.1
    /** Undoes {@link #shiftRows(byte[], int)}.
     * 
     * @param data An array containing the data.
     * @param start The first index of the 4x4 matrix of bytes.
     */
    private static void invShiftRows(byte[] data, int start) {
    	byte tmp;
    	
    	// 13 <- 9 <- 5 <- 1 <- 13
    	tmp = data[start + 13];
    	data[start + 13] = data[start + 9];
    	data[start + 9] = data[start + 5];
    	data[start + 5] = data[start + 1];
    	data[start + 1] = tmp;
    	
    	// 14 -> 6 -> 14
    	// 10 -> 2 -> 10
    	tmp = data[start + 2];
    	data[start + 2] = data[start + 10];
    	data[start + 10] = tmp;
    	tmp = data[start + 6];
    	data[start + 6] = data[start + 14];
    	data[start + 14] = tmp;
    	
    	// 3 <- 7 <- 11 <- 15 <- 3
    	tmp = data[start + 3];
    	data[start + 3] = data[start + 7];
    	data[start + 7] = data[start + 11];
    	data[start + 11] = data[start + 15];
    	data[start + 15] = tmp;
    }
    
    // section 4.2.1
    private static byte xtime(byte b) {
    	return (byte)((b << 1) ^ ((b >> 7) & 0x1b));
    }
    // section 4.2
    private static byte mul(byte b1, byte b2) {
    	byte accum = 0;
    	byte x = b2;
    	while (b1 != 0) {
    		if ((b1 & 1) == 1) {
    			accum ^= x;
    		}
    		b1 >>>= 1;
            x = xtime(x);
    	}
    	return accum;
    }
    // section 4.3
    /** Matrix multiply two 4x4 matrices.
     * The mul operation is in GF(2**8) with a modulus of x**8 + x**4 + x**3 + x + 1.
     * 
     * @param m
     * @param vec
     * @param start
     */
    private static void mul(byte[] m, byte[] vec, int start) {
    	for (int v = 0; v < 16; v += 4) {
    		byte[] aa = new byte[4];
	    	for (int r = 0; r < 16; r += 4) {
	    		byte a = 0;
	    		for (int c = 0; c < 4; c++) {
	    			a ^= mul(m[r+c], vec[start + v + c]);
	    		}
	    		aa[r/4] = a;
	    	}
	    	System.arraycopy(aa, 0, vec, start + v, 4);
    	}
    }
    
    // section 5.1.3
    private static byte[] matrix = new byte[] {
		0x02, 0x03, 0x01, 0x01,
		0x01, 0x02, 0x03, 0x01,
		0x01, 0x01, 0x02, 0x03,
		0x03, 0x01, 0x01, 0x02,
    };
    private static void mixColumns(byte[] r, int start) {
    	mul(matrix, r, start);
    }
    
    private static byte[] invMatrix = new byte[] {
		0x0e, 0x0b, 0x0d, 0x09,
		0x09, 0x0e, 0x0b, 0x0d,
		0x0d, 0x09, 0x0e, 0x0b,
		0x0b, 0x0d, 0x09, 0x0e,
    };
    private static void invMixColumns(byte[] r, int start) {
    	mul(invMatrix, r, start);
    }

    
    @Override
	public void encryptInplace(byte[] block, int start) {
    	/*
    	Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
		begin
			byte state[4,Nb]
			
			state = in
			
			AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4
			
			for round = 1 step 1 to Nr–1
				SubBytes(state) // See Sec. 5.1.1
				ShiftRows(state) // See Sec. 5.1.2
				MixColumns(state) // See Sec. 5.1.3
				AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
			end for
			
			SubBytes(state)
			ShiftRows(state)
			AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
			
			out = state
		end
    	 */
    	
    	ByteBuffer bbBlock = ByteBuffer.wrap(block);
    	addRoundKey(bbBlock, start, 0);
    	int round = 1;
    	while (true) {
    		subBytes(block, start);
    		shiftRows(block, start);
    		if (round == rounds) {
    			break;
    		}
    		mixColumns(block, start);
    		addRoundKey(bbBlock, start, round*4);
    		round++;
    	}
    	addRoundKey(bbBlock, start, rounds*4);
	}

	@Override
	public void decryptInplace(byte[] block, int start) {
		/* pg 21 (25)
		InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
		begin
			byte state[4,Nb]

			state = in

			AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4

			for round = Nr-1 step -1 downto 1
				InvShiftRows(state) // See Sec. 5.3.1
				InvSubBytes(state) // See Sec. 5.3.2
				AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
				InvMixColumns(state) // See Sec. 5.3.3
			end for

			InvShiftRows(state)
			InvSubBytes(state)
			AddRoundKey(state, w[0, Nb-1])

			out = state
		end
		*/
		
    	ByteBuffer bbBlock = ByteBuffer.wrap(block);
    	addRoundKey(bbBlock, start, rounds*4);
    	int round = rounds;
    	while (true) {
    		invShiftRows(block, start);
    		invSubBytes(block, start);
    		round--;
    		addRoundKey(bbBlock, start, round*4);
    		if (round <= 0) {
    			break;
    		}
    		invMixColumns(block, start);
    	}
	}

}
