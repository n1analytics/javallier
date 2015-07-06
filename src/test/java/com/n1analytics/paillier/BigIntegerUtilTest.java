package com.n1analytics.paillier;

import com.n1analytics.paillier.util.BigIntegerUtil;
import org.junit.Test;

import java.math.BigInteger;
import java.util.HashSet;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.*;

public class BigIntegerUtilTest {
	final private BigInteger BigOne = BigInteger.ONE;
	final private BigInteger BigZero = BigInteger.ZERO;
	final private BigInteger BigNegativeOne = BigInteger.ONE.negate();

	@Test
	public void testRandomPositiveNumberInvalidParameters() {
		int[] invalidParameters = new int[]{-1, 0, 1};
		for(int i: invalidParameters) {
			try {
				BigIntegerUtil.randomPositiveNumber(BigInteger.valueOf(i));
				fail("Expected IllegalArgumentException");
			} catch(IllegalArgumentException e) {
			}
		}
	}
	
	@Test
	public void testRandomPositiveNumberSmallRanges() {
		for(int i = 2; i < 32; ++i) {
			HashSet<Integer> sampled = new HashSet<Integer>();
			for(int j = 0; j < 1000*i; ++j) {
				int k = BigIntegerUtil.randomPositiveNumber(BigInteger.valueOf(i)).intValue();
				assertTrue(1 <= k && k < i);
				sampled.add(k);
			}
			assertTrue("Missing samples (NON-DETERMINISTIC TEST)", sampled.size() == i - 1);
		}
	}

	@Test
	public void testBigIntegerSignum() throws Exception {
		assertTrue(BigIntegerUtil.positive(BigOne));
		assertTrue(BigIntegerUtil.nonNegative(BigOne));
		assertFalse(BigIntegerUtil.negative(BigOne));
		assertFalse(BigIntegerUtil.nonPositive(BigOne));

		assertTrue(BigIntegerUtil.nonNegative(BigZero));
		assertTrue(BigIntegerUtil.nonPositive(BigZero));

		assertTrue(BigIntegerUtil.negative(BigNegativeOne));
		assertTrue(BigIntegerUtil.nonPositive(BigNegativeOne));
		assertFalse(BigIntegerUtil.positive(BigNegativeOne));
		assertFalse(BigIntegerUtil.nonNegative(BigNegativeOne));
	}

	@Test
	public void testComparison() throws Exception {
		assertTrue(BigIntegerUtil.greater(BigOne, BigNegativeOne));
		assertTrue(BigIntegerUtil.greaterOrEqual(BigOne, BigNegativeOne));
		assertTrue(BigIntegerUtil.greaterOrEqual(BigOne, BigOne));

		assertTrue(BigIntegerUtil.less(BigNegativeOne, BigOne));
		assertTrue(BigIntegerUtil.lessOrEqual(BigNegativeOne, BigOne));
		assertTrue(BigIntegerUtil.lessOrEqual(BigNegativeOne, BigNegativeOne));

		assertFalse(BigIntegerUtil.greater(BigNegativeOne, BigOne));
		assertFalse(BigIntegerUtil.greaterOrEqual(BigNegativeOne, BigOne));

		assertFalse(BigIntegerUtil.less(BigOne, BigNegativeOne));
		assertFalse(BigIntegerUtil.lessOrEqual(BigOne, BigNegativeOne));
	}

	@Test
	public void testAbsBitLength() throws Exception {
		assertEquals(BigOne.bitLength(), BigIntegerUtil.absBitLength(BigOne));
		assertEquals(BigOne.bitLength(), BigIntegerUtil.absBitLength(BigOne.negate()));

		assertEquals(BigZero.bitLength(), BigIntegerUtil.absBitLength(BigZero));
		assertEquals(BigZero.bitLength(), BigIntegerUtil.absBitLength(BigZero.negate()));

		assertEquals(BigOne.bitLength(), BigIntegerUtil.absBitLength(BigNegativeOne));
	}
}