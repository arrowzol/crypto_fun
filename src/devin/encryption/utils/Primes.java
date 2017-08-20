package devin.encryption.utils;

import java.math.BigInteger;
import java.util.Random;

public class Primes {
	
	private static final int[] tests = new int[] {3, 5, 7, 11, 13, 17, 19, 23, 31, 37, 43, 47, 53, 59, 61, 67};
	private static final BigInteger TWO = BigInteger.valueOf(2);
	
	public static boolean probablyPrime(BigInteger odd) {
		BigInteger even = odd.clearBit(0);
		boolean pass = true;
		for (int test : tests) {
			BigInteger x = BigInteger.valueOf(test).modPow(even, odd);
			if (x.intValue() != 1) {
				pass = false;
				break;
			}
		}
		return pass;
	}
	
	public static BigInteger nextPrime(BigInteger start) {
		BigInteger even = start.clearBit(0);
		BigInteger odd = start.setBit(0);
		while (true) {
			boolean pass = true;
			for (int test : tests) {
				BigInteger x = BigInteger.valueOf(test).modPow(even, odd);
				if (x.intValue() != 1) {
					pass = false;
					break;
				}
			}
			if (pass) {
				return odd;
			}
			even = even.add(TWO);
			odd = odd.add(TWO);
		}
	}
	
	public static BigInteger nextSafePrime(BigInteger start) {
		BigInteger candidate;
		BigInteger safeCandidate;
		while (true) {
			candidate = nextPrime(start);
			safeCandidate = candidate.shiftLeft(2).add(BigInteger.ONE);
			if (probablyPrime(safeCandidate)) {
				break;
			}
			start = candidate.add(TWO);
			break;
		}
		return safeCandidate;
	}
	
	public static BigInteger randomSigned(Random random, int bits) {
		byte[] bs = new byte[bits/8 + 1];
		random.nextBytes(bs);
		int lastByte = bits/8 - (bits-1)/8;
		int lastBit = (bits-1)%8;
		bs[lastByte] |= 1 << lastBit;
		bs[lastByte] &= (1 << (lastBit+1))-1;
		if (lastByte == 1) {
			bs[0] = 0;
		}
		return new BigInteger(bs);
	}
	
	public static BigInteger modMulInv(BigInteger a, BigInteger n) {
    	BigInteger t  = BigInteger.ZERO;
        BigInteger nt = BigInteger.ONE;
        BigInteger r = n;
        BigInteger nr = a.remainder(n);
        if (n.signum() < 0) {
        	n = n.negate();
        }
        if (a.signum() < 0){
        	a = n.subtract((a.negate().remainder(n)));
        }
    	while (nr.signum() != 0) {
    		BigInteger quot= (r.divide(nr)); // | 0;
    		BigInteger tmp = nt;  nt = t.subtract(quot.multiply(nt));  t = tmp;
    		tmp = nr;  nr = r.subtract(quot.multiply(nr));  r = tmp;
    	}
    	if (r.subtract(BigInteger.ONE).signum() > 0) {
    		return null;
		}
    	if (t.signum() < 0) {
    		t = t.add(n);
		}
    	return t;
	}
}
