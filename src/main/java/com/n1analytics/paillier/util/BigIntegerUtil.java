package com.n1analytics.paillier.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public class BigIntegerUtil {
	/**
	 * Minimum long value as a BigInteger;
	 */
	public static final BigInteger LONG_MIN_VALUE =
			BigInteger.valueOf(Long.MIN_VALUE);

	/**
	 * Maximum long value as a BigInteger.
	 */
	public static final BigInteger LONG_MAX_VALUE =
		BigInteger.valueOf(Long.MAX_VALUE);

	public static boolean positive(BigInteger n) {
		return n.signum() > 0;
	}

	public static boolean nonNegative(BigInteger n) {
		return n.signum() >= 0;
	}

	public static boolean negative(BigInteger n) {
		return n.signum() < 0;
	}

	public static boolean nonPositive(BigInteger n) {
		return n.signum() <= 0;
	}

	public static boolean greater(BigInteger a, BigInteger b) {
		return a.compareTo(b) > 0;
	}

	public static boolean greaterOrEqual(BigInteger a, BigInteger b) {
		return a.compareTo(b) >= 0;
	}

	public static boolean less(BigInteger a, BigInteger b) {
		return a.compareTo(b) < 0;
	}

	public static boolean lessOrEqual(BigInteger a, BigInteger b) {
		return a.compareTo(b) <= 0;
	}

	/**
	 * Return a random strictly positive number less than n.
	 * @param n
	 * @return
	 */
	public static BigInteger randomPositiveNumber(final BigInteger n) {
		if(lessOrEqual(n, BigInteger.ONE))
			throw new IllegalArgumentException("n must be strictly greater than one");
		
		int bits = n.bitLength();
		SecureRandom random = new SecureRandom();
		for(;;) {
			BigInteger r = new BigInteger(bits, random);
			if(less(r, BigInteger.ONE) || greaterOrEqual(r, n))
				continue;
			return r;
		}
	}

	/**
	 * The number of bits required to represent <pre>abs(n)</pre>, excluding the
	 * sign bit. This is useful because 
	 * <pre>absBitLength(n) == absBitLength(n.negate)</pre> whereas the same is
	 * not necessarily true of <pre>n.bitLength()</pre> and
	 * <pre>n.negate().bitLength()</pre>.
	 * 
	 * @param n
	 * @return
	 */
	public static int absBitLength(BigInteger n) {
		return n.abs().bitLength();
	}
	
	/**
	 * Converts a BigInteger to a <code>long</code>. Throws an
	 * <code>ArithmeticException</code> if the conversion can not be done
	 * exactly.
	 * @return The converted value.
	 * @throws ArithmeticException If <code>n</code> cannot be exactly
	 * represented as a <code>long</code>
	 */
	public static long longValueExact(BigInteger n) throws ArithmeticException {
		// TODO optimisation?
		if(n.compareTo(LONG_MIN_VALUE) < 0)
			throw new ArithmeticException("Cannot represent exactly");
		if(n.compareTo(LONG_MAX_VALUE) > 0)
			throw new ArithmeticException("Cannot represent exactly");
		return n.longValue();
	}
}