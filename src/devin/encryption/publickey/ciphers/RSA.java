package devin.encryption.publickey.ciphers;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import devin.encryption.publickey.AsymetricCipher;
import devin.encryption.utils.Primes;

public class RSA implements AsymetricCipher {
	
	private static SecureRandom random = new SecureRandom();

	private BigInteger n;
	private BigInteger d;
	private static BigInteger e = BigInteger.valueOf(0x10001);
	
	public RSA(byte[] pri, byte[] pub) {
		if (pri != null) {
			n = new BigInteger(pub);
		}
		
		if (pub != null) {
			byte[] nBytes = new byte[pri.length/2];
			System.arraycopy(pri, 0, nBytes, 0, nBytes.length);
			n = new BigInteger(nBytes);
			System.arraycopy(pri, nBytes.length, nBytes, 0, nBytes.length);
			d = new BigInteger(nBytes);
		}
	}
	
	public RSA(int bits) {
		int one = random.nextInt(1);
		BigInteger p = Primes.nextPrime(Primes.randomSigned(random, (bits+1-one)/2));
		BigInteger q = Primes.nextPrime(Primes.randomSigned(random, (bits+one)/2));
		n = p.multiply(q);
		BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e = BigInteger.valueOf(0x10001);
		d = Primes.modMulInv(e, phi);
		
		if (phi.remainder(e).equals(BigInteger.ZERO)) {
			throw new RuntimeException("Bad key");
		}
	}

	public byte[][] getKeyPair() {
		byte[] nBytes = n.toByteArray();
		byte[] dBytes = d.toByteArray();
		
		byte[] pub = new byte[nBytes.length];
		System.arraycopy(nBytes, 0, pub, 0, nBytes.length);
		
		byte[] pri = new byte[nBytes.length + dBytes.length];
		System.arraycopy(nBytes, 0, pri, 0, nBytes.length);
		System.arraycopy(dBytes, 0, pri, nBytes.length, dBytes.length);
		return new byte[][] {pub, pri};
	}
	
	public BigInteger rawEncrypt(BigInteger plainText) {
		return plainText.modPow(e, n);
	}
	
	public BigInteger rawDecrypt(BigInteger data) {
		return data.modPow(d, n);
	}
	
	public static void main(String[] args) throws IOException {
		RSA rsa = new RSA(17);
		byte[][] keys = rsa.getKeyPair();
		
		OutputStream pubFile = new FileOutputStream("key.pub");
		pubFile.write(keys[0]);
		pubFile.close();
		
		OutputStream priFile = new FileOutputStream("key.pri");
		priFile.write(keys[1]);
		priFile.close();
		
		// BigInteger pt = new BigInteger("123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789");
		BigInteger pt = new BigInteger("123");
		BigInteger ct = rsa.rawEncrypt(pt);
		BigInteger pt2 = rsa.rawDecrypt(ct);
		
		System.out.println("enc: " + ct);
		System.out.println("dec: " + pt2);
	}
}
