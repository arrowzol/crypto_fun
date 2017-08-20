package devin.encryption.keyexchange;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import devin.encryption.utils.Primes;

public class DiffieHellman {

	private static SecureRandom random = new SecureRandom();

	public static void main(String[] args) throws IOException {
		int bits = 2048;
		BigInteger G = Primes.nextSafePrime(Primes.randomSigned(random, bits));
		BigInteger g = BigInteger.valueOf(2);
		
		BigInteger a = Primes.randomSigned(random, bits);
		while (a.subtract(G).signum() > 0) {
			a = a.subtract(G);
			System.out.println("a");
		}
		BigInteger b = Primes.randomSigned(random, bits);
		while (b.subtract(G).signum() > 0) {
			b = b.subtract(G);
			System.out.println("b");
		}
		
		BigInteger aG = g.modPow(a, G);
		BigInteger bG = g.modPow(b, G);
		
		BigInteger s1 = aG.modPow(b, G);
		BigInteger s2 = bG.modPow(a, G);
		
		System.out.println(G.toString());
		System.out.println(s1.toString());
		System.out.println(s2.toString());

		OutputStream pubFile = new FileOutputStream("G");
		pubFile.write(G.toByteArray());
		pubFile.close();

	}
}
