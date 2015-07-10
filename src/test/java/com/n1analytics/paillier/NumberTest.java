/**
 * Copyright 2015 NICTA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.n1analytics.paillier;

import com.n1analytics.paillier.util.FloatingPointUtil;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

import static com.n1analytics.paillier.TestUtil.randomFiniteDouble;
import static com.n1analytics.paillier.util.BigIntegerUtil.LONG_MAX_VALUE;
import static com.n1analytics.paillier.util.BigIntegerUtil.LONG_MIN_VALUE;
import static org.junit.Assert.*;

public class NumberTest {
	// Epsilon value for comparing floating point numbers
	private static final double EPSILON = 1e-3;

	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TEN = BigInteger.TEN;

	private static final double operand1 = 1.7;
	private static final long operandLong = 2;
	private static final double operandDouble = 2.0;
	private static final BigInteger operandBigInteger = new BigInteger("2");

    public static double prevDouble(double value) {
    	return Math.nextAfter(value, Double.NEGATIVE_INFINITY);
    }
    
    public static double nextDouble(double value) {
    	return Math.nextAfter(value, Double.POSITIVE_INFINITY);
    }

	@Test
	public void testConstructor() throws Exception {
		Number number = null;

		try {
			number = new Number(null, 0);
			fail("Successfully create a Number with null significand");
		} catch (NullPointerException e) {
		}
	    assertNull(number);

		number = new Number(ONE, 0);
        // Check whether the number is not null
        assertNotNull(number);
        // Check whether the significand is not null and is correct
        assertNotNull(number.getSignificand());
        assertEquals(ONE, number.getSignificand());
        // Check whether the exponent is correct
        assertEquals(0, number.getExponent());
	}

    // Test signum(), abs() and negate()
    @Test
    public void testSignificandSign() throws Exception {
        Number zero = Number.encode(0);
        Number one = Number.encode(1);

        // Check for positive number
        assertEquals(1, one.signum());
        one = one.abs();
        assertEquals(1, one.signum());

        // Check for 0
        assertEquals(0, zero.signum());
        zero = zero.abs();
        assertEquals(0, zero.signum());

        // Check for negative number
        one = one.negate();
        assertEquals(-1, one.signum());
        one = one.abs();
        assertEquals(1, one.signum());
    }

    // Test zero() and zero(int)
    @Test
	public void testZero() throws Exception {
		Number zero = Number.encode(0);

		assertEquals(zero, Number.zero());
        assertEquals(zero, Number.zero(0));
		assertEquals(zero, Number.zero(1));
		assertEquals(zero, Number.zero(2));
		assertEquals(zero, Number.zero(10));
		assertEquals(zero, Number.zero(1000));
		assertEquals(zero, Number.zero(-1));
		assertEquals(zero, Number.zero(-2));
		assertEquals(zero, Number.zero(-10));
		assertEquals(zero, Number.zero(-1000));
	}

    // Test one() and one(int)
	@Test
	public void testOne() throws Exception {
		Number one = Number.encode(1);

		assertEquals(one, Number.one());
        assertEquals(one, Number.one(0));
		assertEquals(one, Number.one(-1));
		assertEquals(one, Number.one(-10));
		assertEquals(one, Number.one(-1000));

		try {
			Number illegalOne = Number.one(1);
            fail("Successfully encode 1 with a positive exponent");
		} catch (IllegalArgumentException e) {
		}
	}

    @Test
    public void testPositiveEpsilon() throws Exception {
        assertEquals(Math.pow(2.0, -100.0), Number.positiveEpsilon(-100).decodeDouble(), EPSILON);
        assertEquals(Math.pow(2.0, -10.0), Number.positiveEpsilon(-10).decodeDouble(), EPSILON);
        assertEquals(Math.pow(2.0, -1.0), Number.positiveEpsilon(-1).decodeDouble(), EPSILON);
        assertEquals(Math.pow(2.0, 0.0), Number.positiveEpsilon(0).decodeDouble(), EPSILON);
        assertEquals(Math.pow(2.0, 1.0), Number.positiveEpsilon(1).decodeDouble(), EPSILON);
        assertEquals(Math.pow(2.0, 10.0), Number.positiveEpsilon(10).decodeDouble(), EPSILON);
        assertEquals(Math.pow(2.0, 100.0), Number.positiveEpsilon(100).decodeDouble(), EPSILON);
    }

    @Test
    public void testNegativeEpsilon() throws Exception {
        assertEquals(-1 * Math.pow(2.0, -100.0), Number.negativeEpsilon(-100).decodeDouble(), EPSILON);
        assertEquals(-1 * Math.pow(2.0, -10.0), Number.negativeEpsilon(-10).decodeDouble(), EPSILON);
        assertEquals(-1 * Math.pow(2.0, -1.0), Number.negativeEpsilon(-1).decodeDouble(), EPSILON);
        assertEquals(-1 * Math.pow(2.0, 0.0), Number.negativeEpsilon(0).decodeDouble(), EPSILON);
        assertEquals(-1 * Math.pow(2.0, 1.0), Number.negativeEpsilon(1).decodeDouble(), EPSILON);
        assertEquals(-1 * Math.pow(2.0, 10.0), Number.negativeEpsilon(10).decodeDouble(), EPSILON);
        assertEquals(-1 * Math.pow(2.0, 100.0), Number.negativeEpsilon(100).decodeDouble(), EPSILON);
    }

    // Test encode() and encodeToExponent() (for BigInteger, encode() calls encodeToExponent())
    @Test
    public void testEncodeBigInteger() throws Exception {
        Number numberBigInteger = null;

        // Test when value's lowest set bit is negative
        numberBigInteger = Number.encode(ZERO);
        assertNotNull(numberBigInteger);
        assertEquals(0, numberBigInteger.getExponent());
        assertEquals(ZERO, numberBigInteger.getSignificand());
        assertEquals(ZERO, numberBigInteger.decodeBigInteger());

        // Test when value's lowest set bit is non-negative
        numberBigInteger = Number.encode(TEN);
        assertNotNull(numberBigInteger);
        assertEquals(1, numberBigInteger.getExponent());
        assertEquals(new BigInteger("5"), numberBigInteger.getSignificand());
        assertEquals(TEN, numberBigInteger.decodeBigInteger());

        // Test when value is negative
        BigInteger BigNegativeOne = ONE.negate();
        numberBigInteger = Number.encode(BigNegativeOne);
        assertNotNull(numberBigInteger);
        assertEquals(0, numberBigInteger.getExponent());
        assertEquals(BigNegativeOne, numberBigInteger.getSignificand());
        assertEquals(BigNegativeOne, numberBigInteger.decodeBigInteger());
    }

    @Test
	public void testEncodeToPrecisionBigInteger() throws Exception {
        Number numberBigInteger = null;

        // Test illegal input
        try {
			numberBigInteger = Number.encodeToPrecision(ONE, 0);
            fail("Successfully encode a number with negative precision");
		} catch (IllegalArgumentException e) {
		}
        assertNull(numberBigInteger);

        // Test when value.signum == 0
        int precision = 1;
        numberBigInteger = Number.encodeToPrecision(ZERO, precision);
        assertNotNull(numberBigInteger);
        assertEquals(ZERO, numberBigInteger.getSignificand());
        assertEquals(0, numberBigInteger.getExponent());
        assertEquals(ZERO, numberBigInteger.decodeBigInteger());

        // The value's (bit length - precision) is greater than the lowest set bit
        // NOTE: the Number is losing precision, therefore the decoded BigInteger is not the same as the original input
        precision = 2;
        int shiftMagnitude = TEN.bitLength() - precision;
        numberBigInteger = Number.encodeToPrecision(TEN, precision);
        assertNotNull(numberBigInteger);
        assertEquals(TEN.shiftRight(shiftMagnitude), numberBigInteger.getSignificand());
        assertEquals(shiftMagnitude, numberBigInteger.getExponent());
        assertNotEquals(TEN, numberBigInteger.decodeBigInteger());
        assertEquals(TEN.shiftRight(shiftMagnitude).shiftLeft(shiftMagnitude), numberBigInteger.decodeBigInteger());

        // The value's lowest set bit is greater than (bit length - precision)
        precision = 3;
        BigInteger BigTwentyFour = new BigInteger("24");
        shiftMagnitude = BigTwentyFour.getLowestSetBit();
        numberBigInteger = Number.encodeToPrecision(BigTwentyFour, precision);
        assertNotNull(numberBigInteger);
        assertEquals(BigTwentyFour.shiftRight(shiftMagnitude), numberBigInteger.getSignificand());
        assertEquals(shiftMagnitude, numberBigInteger.getExponent());
        assertEquals(BigTwentyFour, numberBigInteger.decodeBigInteger());
	}

    // Test encode() and encodeToExponent() (for long, encode() calls encodeToExponent())
    @Test
    public void testEncodeLong() throws Exception {
        Number numberBigInteger = null;

        // Test when value's lowest set bit is negative
        numberBigInteger = Number.encode(ZERO);
        assertNotNull(numberBigInteger);
        assertEquals(0, numberBigInteger.getExponent());
        assertEquals(ZERO, numberBigInteger.getSignificand());
        assertEquals(ZERO, numberBigInteger.decodeBigInteger());

        // Test when value's lowest set bit is non-negative
        numberBigInteger = Number.encode(TEN);
        assertNotNull(numberBigInteger);
        assertEquals(1, numberBigInteger.getExponent());
        assertEquals(new BigInteger("5"), numberBigInteger.getSignificand());
        assertEquals(TEN, numberBigInteger.decodeBigInteger());

        // Test when value is negative
        BigInteger BigNegativeOne = ONE.negate();
        numberBigInteger = Number.encode(BigNegativeOne);
        assertNotNull(numberBigInteger);
        assertEquals(0, numberBigInteger.getExponent());
        assertEquals(BigNegativeOne, numberBigInteger.getSignificand());
        assertEquals(BigNegativeOne, numberBigInteger.decodeBigInteger());
    }

    @Test
    public void testIllegalEncodeToPrecisionLong() throws Exception {
        Number numberLong = null;
        try {
            numberLong = Number.encodeToPrecision(1, 0);
            fail("Successfully encode a number with negative precision");
        } catch (IllegalArgumentException e) {
        }
        assertNull(numberLong);

        int precision = 1;
        numberLong = Number.encodeToPrecision(0, precision);
        assertNotNull(numberLong);
        assertEquals(ZERO, numberLong.getSignificand());
        assertEquals(0, numberLong.getExponent());
        assertEquals(0, numberLong.decodeLong());

        // The value's (bit length - precision) is greater than the lowest set bit
        // NOTE: the Number is losing precision, therefore the decoded BigInteger is not the same as the original input
        precision = 2;
        int shiftMagnitude = TEN.bitLength() - precision;
        numberLong = Number.encodeToPrecision(TEN, precision);
        assertNotNull(numberLong);
        assertEquals(TEN.shiftRight(shiftMagnitude), numberLong.getSignificand());
        assertEquals(shiftMagnitude, numberLong.getExponent());
        assertNotEquals(10, numberLong.decodeLong());
        assertEquals(TEN.shiftRight(shiftMagnitude).shiftLeft(shiftMagnitude).longValue(), numberLong.decodeLong());

        // The value's lowest set bit is greater than (bit length - precision)
        precision = 3;
        BigInteger BigTwentyFour = new BigInteger("24");
        shiftMagnitude = BigTwentyFour.getLowestSetBit();
        numberLong = Number.encodeToPrecision(BigTwentyFour, precision);
        assertNotNull(numberLong);
        assertEquals(BigTwentyFour.shiftRight(shiftMagnitude), numberLong.getSignificand());
        assertEquals(shiftMagnitude, numberLong.getExponent());
        assertEquals(24, numberLong.decodeLong());
    }

    // Only test illegal input. Rigorous encode/decode tests are in the bottom of this class
    @Test
    public void testIllegalEncodeToPrecisionDouble() throws Exception {
        Number numberDouble = null;
        try {
            numberDouble = Number.encodeToPrecision(1.0, -1);
            fail("Successfully encode a number with negative precision");
        } catch (IllegalArgumentException e) {
        }
        assertNull(numberDouble);

        try {
            numberDouble = Number.encodeToPrecision(Double.POSITIVE_INFINITY, 1);
            fail("Successfully encode a positive infinity");
        } catch (EncodeException e) {
        }
        assertNull(numberDouble);

        try {
            numberDouble = Number.encodeToPrecision(Double.NEGATIVE_INFINITY, 1);
            fail("Successfully encode a negative infinity");
        } catch (EncodeException e) {
        }
        assertNull(numberDouble);

        try {
            numberDouble = Number.encodeToPrecision(Double.NaN, 1);
            fail("Successfully encode a NaN");
        } catch (EncodeException e) {
        }
        assertNull(numberDouble);
    }

    // TODO test encodedToExponent(double, int)

    @Test
	public void testIllegalExactDecoding() throws Exception {
		Number numberBigInteger = new Number(new BigInteger("17"), -100);

		try {
			BigInteger decoded = numberBigInteger.decodeBigInteger();
            fail("Should not be able to decode exactly");
		} catch (ArithmeticException e) {
		}
	}

	@Test
	public void testInfinityDouble() throws Exception {
		Number veryLargeNegativeNumber = Number.encode(Double.MAX_VALUE)
				.subtract(Double.MAX_VALUE)
				.subtract(Double.MAX_VALUE)
				.subtract(Double.MAX_VALUE);
		assertEquals(Double.NEGATIVE_INFINITY, veryLargeNegativeNumber.decodeApproximateDouble(), EPSILON);

		Number veryLargePositiveNumber = Number.encode(Double.MAX_VALUE)
				.add(Double.MAX_VALUE)
				.add(Double.MAX_VALUE)
				.add(Double.MAX_VALUE);
		assertEquals(Double.POSITIVE_INFINITY, veryLargePositiveNumber.decodeApproximateDouble(), EPSILON);
	}

	@Test
	public void testDecodeVerySmallNumber() throws Exception {
		Number number = Number.encode(Double.MIN_VALUE).divide(10);
		double decodedNumber;

		try {
			decodedNumber = number.decodeDouble();
            fail("Should not be able to decode a vert small number");
		} catch (ArithmeticException e) {
		}

		decodedNumber = number.decodeApproximateDouble();
		assertEquals(0.0, decodedNumber, EPSILON);
	}

	@Test
	public void testAddLongToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.add(operandLong);
		assertEquals(3.7, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testAddDoubleToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.add(operandDouble);
		assertEquals(3.7, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testAddBigIntegerToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.add(operandBigInteger);
		assertEquals(3.7, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testSubtractLongToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.subtract(operandLong);
		assertEquals(-0.3, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testSubtractDoubleToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.subtract(operandDouble);
		assertEquals(-0.3, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testSubtractBigIntegerToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.subtract(operandBigInteger);
		assertEquals(-0.3, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testMultiplyLongToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.multiply(operandLong);
		assertEquals(3.4, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testMultiplyDoubleToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.multiply(operandDouble);
		assertEquals(3.4, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testMultiplyBigIntegerToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.multiply(operandBigInteger);
		assertEquals(3.4, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testDivideLongToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.divide(operandLong);
		assertEquals(0.85, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testDivideDoubeToNumber() throws Exception {
		Number number1 = Number.encode(operand1);
		Number number2 = number1.divide(operandDouble);
		assertEquals(0.85, number2.decodeDouble(), EPSILON);
	}

	@Test
	public void testToString() throws Exception {
		Number numberNegativeOne = Number.encode(-1);
		Number numberZero = Number.zero();
		Number numberOne = Number.one();
		Number numberSeventeen = Number.encode(17);

		assertEquals("Number(exponent=0, significand=-1)", numberNegativeOne.toString());
		assertEquals("Number(exponent=0, significand=0)", numberZero.toString());
		assertEquals("Number(exponent=0, significand=1)", numberOne.toString());
		assertEquals("Number(exponent=0, significand=11)", numberSeventeen.toString());
	}

    /**
     * Test whether encoding a double produces the desired result for all
     * exponents between Number.DOUBLE_MIN_VALUE_EXPONENT and
     * Number.DOUBLE_MAX_VALUE_EXPONENT inclusive.
     * @param value The value to test encoding of.
     * @param expectedSignificand The expected significand when encoding with
     * an exponent of Number.DOUBLE_MIN_VALUE_EXPONENT.
     */
    public static void testEncodeDouble(
    	double value,
    	BigInteger expectedSignificand)
    {
		Number expected = new Number(
			expectedSignificand,
			Number.DOUBLE_MIN_VALUE_EXPONENT);
		int min = Number.DOUBLE_MIN_VALUE_EXPONENT;
		int max = Number.DOUBLE_MAX_VALUE_EXPONENT;
		for(int i = min; i <= max; ++i) {
			Number result = Number.encodeToExponent(value, i);
			assertEquals(expected, result);
			expected = new Number(
				expected.getSignificand().shiftRight(1),
				expected.getExponent() + 1);
		}    	
    }

	public void testEncodeToExponentDecodeDouble(double value, int exponent) {
		double decodedResult = Number.encodeToExponent(value, exponent).decodeApproximateDouble();
		if(decodedResult > value)
			fail("Error: the value of the decoded result should be less than or equal to the original value");
	}

	public void testEncodeToPrecisionDecodeDouble(double value) {
		int normalPrecision = FloatingPointUtil.DOUBLE_FRACTION_BITS + 1;
		int min = normalPrecision - 2;
		int max = normalPrecision + 2;

		for(int i = min; i <= max; ++i) {
			double decodedResult = Number.encodeToPrecision(value, i).decodeApproximateDouble();
			assertEquals(value, decodedResult, 0.1 * Math.pow(2.0, Math.getExponent(decodedResult)));
		}
	}

	public void testEncodeDecodeDouble(double value) {
    	assertEquals(value, Number.encode(value).decodeApproximateDouble(), 0.0);
    }
	
	@Test
	public void testDoubleConstants() {
		testEncodeDecodeDouble(-Double.MAX_VALUE);
		testEncodeDecodeDouble(-nextDouble(1.0));
		testEncodeDecodeDouble(-1.0);
		testEncodeDecodeDouble(-prevDouble(1.0));
		testEncodeDecodeDouble(-nextDouble(Double.MIN_NORMAL));
		testEncodeDecodeDouble(-Double.MIN_NORMAL);
		testEncodeDecodeDouble(-prevDouble(Double.MIN_NORMAL));
		testEncodeDecodeDouble(-Double.MIN_VALUE);
		testEncodeDecodeDouble(-0.0);
		testEncodeDecodeDouble(0.0);
		testEncodeDecodeDouble(Double.MIN_VALUE);
		testEncodeDecodeDouble(prevDouble(Double.MIN_NORMAL));
		testEncodeDecodeDouble(Double.MIN_NORMAL);
		testEncodeDecodeDouble(nextDouble(Double.MIN_NORMAL));
		testEncodeDecodeDouble(prevDouble(1.0));
		testEncodeDecodeDouble(1.0);
		testEncodeDecodeDouble(nextDouble(1.0));
		testEncodeDecodeDouble(Double.MAX_VALUE);

		testEncodeDouble(
			-Double.MAX_VALUE,
			BigInteger
			.valueOf(0x1FFFFFFFFFFFFFL)
			.shiftLeft(Double.MAX_EXPONENT - Double.MIN_EXPONENT)
			.negate());
		testEncodeDouble(
			-prevDouble(Double.MAX_VALUE),
			BigInteger
			.valueOf(0x1FFFFFFFFFFFFEL)
			.shiftLeft(Double.MAX_EXPONENT - Double.MIN_EXPONENT)
			.negate());
		testEncodeDouble(-nextDouble(Double.MIN_NORMAL), BigInteger.valueOf((1L << 52) + 1L).negate());
		testEncodeDouble(-Double.MIN_NORMAL, BigInteger.valueOf(1L << 52).negate());
		testEncodeDouble(-prevDouble(Double.MIN_NORMAL), BigInteger.valueOf((1L << 52) - 1L).negate());
		testEncodeDouble(-Double.MIN_VALUE, BigInteger.ONE.negate());
		testEncodeDouble(-0.0, BigInteger.ZERO);
		testEncodeDouble(0.0, BigInteger.ZERO);
		testEncodeDouble(Double.MIN_VALUE, BigInteger.ONE);
		testEncodeDouble(prevDouble(Double.MIN_NORMAL), BigInteger.valueOf((1L << 52) - 1L));
		testEncodeDouble(Double.MIN_NORMAL, BigInteger.valueOf(1L << 52));
		testEncodeDouble(nextDouble(Double.MIN_NORMAL), BigInteger.valueOf((1L << 52) + 1L));
		testEncodeDouble(
				prevDouble(Double.MAX_VALUE),
				BigInteger
				.valueOf(0x1FFFFFFFFFFFFEL)
				.shiftLeft(Double.MAX_EXPONENT - Double.MIN_EXPONENT));
		testEncodeDouble(
			Double.MAX_VALUE,
			BigInteger
			.valueOf(0x1FFFFFFFFFFFFFL)
			.shiftLeft(Double.MAX_EXPONENT - Double.MIN_EXPONENT));
	}

	@Test
	public void testDoubleRandom() {
		Random random = new Random();
		for(int i = 0; i < 1000000; ++i)
			testEncodeDecodeDouble(randomFiniteDouble());
	}

	@Test
	public void testDoubleIllegalParameters() {
		double[] invalidValues = new double[] {
				Double.NaN,
				Double.NEGATIVE_INFINITY,
				Double.POSITIVE_INFINITY};
		for(double invalidValue: invalidValues) {
			try {
				Number.encode(invalidValue);
				fail("Expected IllegalArgumentException");
			} catch(EncodeException e) {
			}
		}
	}

	@Test
	public void testEncodeToExponentDecodeDoubleConstants() {
		int min = Number.DOUBLE_MIN_VALUE_EXPONENT;
		int max = Number.DOUBLE_MAX_VALUE_EXPONENT;

		double[] constants = {-Double.MAX_VALUE, -nextDouble(1.0), -1.0, -prevDouble(1.0),
				-nextDouble(Double.MIN_NORMAL), -Double.MIN_NORMAL, -prevDouble(Double.MIN_NORMAL), -Double.MIN_VALUE,
				-0.0, 0.0, Double.MIN_VALUE, prevDouble(Double.MIN_NORMAL), Double.MIN_NORMAL,
				nextDouble(Double.MIN_NORMAL), prevDouble(1.0), 1.0, nextDouble(1.0), Double.MAX_VALUE};

		for(int i = 0; i < constants.length; ++i) {
			for (int j = min; j <= max; ++j)
				testEncodeToExponentDecodeDouble(constants[i], j);
		}
	}

	@Test
	public void testEncodeToExponentDecodeDoubleRandom() {
		int min = Number.DOUBLE_MIN_VALUE_EXPONENT;
		int max = Number.DOUBLE_MAX_VALUE_EXPONENT;

		Random random = new Random();
		for(int i = 0; i < 10000; ++i) {
			for(int j = min; j <= max; ++j )
				testEncodeToExponentDecodeDouble(randomFiniteDouble(), j);
		}
	}

	@Test
	public void testEncodeToPrecisionDecodeDoubleConstants() {
		double[] constants = {-Double.MAX_VALUE, -nextDouble(1.0), -1.0, -prevDouble(1.0),
				-nextDouble(Double.MIN_NORMAL), -Double.MIN_NORMAL, -prevDouble(Double.MIN_NORMAL), -Double.MIN_VALUE,
				-0.0, 0.0, Double.MIN_VALUE, prevDouble(Double.MIN_NORMAL), Double.MIN_NORMAL,
				nextDouble(Double.MIN_NORMAL), prevDouble(1.0), 1.0, nextDouble(1.0), Double.MAX_VALUE};

		for(int i = 0; i < constants.length; ++i) {
			testEncodeToPrecisionDecodeDouble(constants[i]);
		}
	}

	@Test
	public void testEncodeToPrecisionDecodeDoubleRandom() {
		Random random = new Random();
		for(int i = 0; i < 10000; ++i) {
			testEncodeToPrecisionDecodeDouble(randomFiniteDouble());
		}
	}

	// BIG INTEGER
	public BigInteger generateRandomBigInteger(Random random, int bitLength) {
		BigInteger value = new BigInteger(bitLength, random);

		int i = random.nextInt(2);
		if(i % 2 == 0) {
			return value;
		} else {
			return value.negate();
		}
	}

	public void testEncodeBigInteger(BigInteger value, BigInteger expectedSignificand) {
		Number expected = new Number(expectedSignificand, 0);
		int min = 0;
		int max = 1000;
		for(int i = min; i <= max; ++i) {
			Number result = Number.encodeToExponent(value, i);
			assertEquals(expected, result);
			expected = new Number(
					expected.getSignificand().shiftRight(1),
					expected.getExponent() + 1);
		}
	}

	public void testEncodeDecodeBigInteger(BigInteger value) {
		assertEquals(value, Number.encode(value).decodeApproximateBigInteger());
	}

	public void testEncodeToExponentDecodeBigInteger(BigInteger value, int exponent) {
		BigInteger decodedResult = Number.encodeToExponent(value, exponent).decodeApproximateBigInteger();
		if(decodedResult.compareTo(value) > 0)
			fail("Error: the value of the decoded result should be less than or equal to the original value");
	}

	public void testEncodeToPrecisionDecodeBigInteger(BigInteger value) {
		int valueBitLength = value.abs().bitLength();
		int valueLSB = value.getLowestSetBit();
		int valueMaxPrec = valueBitLength - valueLSB;
		int min = valueMaxPrec > 2 ? valueMaxPrec - 2 : 1;
		int max = valueMaxPrec + 2;

		for(int i = max; i >= min; i--) {
			Number valueEncode = Number.encodeToPrecision(value, i);
			BigInteger valueEncodeDecode = valueEncode.decodeApproximateBigInteger();
			if(i >= valueMaxPrec && valueEncodeDecode.compareTo(value) != 0)
				fail("Error: the value of the decoded result must be equal to the original value");
			if(valueEncodeDecode.compareTo(value) > 0)
				fail("Error: the value of the decoded result must be less than or equal to the original value");
		}
	}

	@Test
	public void testBigIntegerConstants() throws Exception {
		testEncodeDecodeBigInteger(LONG_MIN_VALUE);
		testEncodeDecodeBigInteger(LONG_MIN_VALUE.add(ONE));
		testEncodeDecodeBigInteger(TEN.negate());
		testEncodeDecodeBigInteger(ONE.negate());
		testEncodeDecodeBigInteger(ZERO);
		testEncodeDecodeBigInteger(ONE);
		testEncodeDecodeBigInteger(TEN);
		testEncodeDecodeBigInteger(LONG_MAX_VALUE.subtract(ONE));
		testEncodeDecodeBigInteger(LONG_MAX_VALUE);

		testEncodeBigInteger(LONG_MIN_VALUE, LONG_MIN_VALUE);
		testEncodeBigInteger(LONG_MIN_VALUE.add(ONE), LONG_MIN_VALUE.add(ONE));
		testEncodeBigInteger(TEN.negate(), TEN.negate());
		testEncodeBigInteger(ONE.negate(), ONE.negate());
		testEncodeBigInteger(ZERO, ZERO);
		testEncodeBigInteger(ONE, ONE);
		testEncodeBigInteger(TEN, TEN);
		testEncodeBigInteger(LONG_MAX_VALUE.subtract(ONE), LONG_MAX_VALUE.subtract(ONE));
		testEncodeBigInteger(LONG_MAX_VALUE, LONG_MAX_VALUE);
	}

	@Test
	public void testBigIntegerRandom() throws Exception {
		int[] bitLengths = {16, 32, 64, 128, 256};

		Random random = new Random();
		for(int i = 0; i < bitLengths.length; ++i) {
			for(int j = 0; j < 100000; ++j)
				testEncodeDecodeBigInteger(generateRandomBigInteger(random, bitLengths[i]));
		}
	}

	@Test
	public void testEncodeToExponentDecodeBigIntegerConstants() throws Exception {
		BigInteger[] constants = {LONG_MIN_VALUE, LONG_MIN_VALUE.add(ONE), TEN.negate(), ONE.negate(),
				ZERO, ONE, TEN, LONG_MAX_VALUE.subtract(ONE), LONG_MAX_VALUE};
		for(int i = 0; i < constants.length; ++i) {
			for (int j = 0; j <= 1000; ++j)
				testEncodeToExponentDecodeBigInteger(constants[i], j);
		}
	}

	@Test
	public void testEncodeToExponentDecodeBigIntegerRandom() throws Exception {
		int[] bitLengths = {16, 32, 64, 128, 256};

		Random random = new Random();
		for(int i = 0; i < bitLengths.length; ++i) {
			for(int j = 0; j < 2000; ++j) {
				for(int k = 0; k <= 1000; ++k)
					testEncodeToExponentDecodeBigInteger(generateRandomBigInteger(random, bitLengths[i]), k);
			}
		}
	}

	@Test
	public void testEncodeToPrecisionBigIntegerConstants() throws Exception {
		BigInteger[] constants = {LONG_MIN_VALUE, LONG_MIN_VALUE.add(ONE), TEN.negate(), ONE.negate(),
				ZERO, ONE, TEN, LONG_MAX_VALUE.subtract(ONE), LONG_MAX_VALUE};
		for(int i = 0; i < constants.length; ++i) {
			testEncodeToPrecisionDecodeBigInteger(constants[i]);
		}
	}

	@Test
	public void testEncodeToPrecisionDecodeBigIntegerRandom() throws Exception {
		int[] bitLengths = {16, 32, 64, 128, 256};

		Random random = new Random();
		for(int i = 0; i < bitLengths.length; ++i) {
			for(int j = 0; j < 20000; ++j)
				testEncodeToPrecisionDecodeBigInteger(generateRandomBigInteger(random, bitLengths[i]));
		}
	}

	// LONG
	public void testEncodeLong(long value, BigInteger expectedSignificand) {
		Number expected = new Number(expectedSignificand, 0);
		int min = 0;
		int max = 63;
		for(int i = min; i <= max; ++i) {
			Number result = Number.encodeToExponent(value, i);
			assertEquals(expected, result);
			expected = new Number(
					expected.getSignificand().shiftRight(1),
					expected.getExponent() + 1);
		}
	}

	public void testEncodeToExponentDecodeLong(long value, int exponent) {
		long decodedResult = Number.encodeToExponent(value, exponent).decodeApproximateLong();
		if(decodedResult > value)
			fail("Error: the value of the decoded result should be less than or equal to the original value");
	}

	public void testEncodeToPrecisionDecodeLong(long value) {
		int valueBitLength = BigInteger.valueOf(value).abs().bitLength();
		int valueLSB = BigInteger.valueOf(value).getLowestSetBit();
		int valueMaxPrec = valueBitLength - valueLSB;
		int min = valueMaxPrec > 2 ? valueMaxPrec - 2 : 1;
		int max = valueMaxPrec + 2;

		for(int i = max; i >= min; i--) {
			Number valueEncode = Number.encodeToPrecision(value, i);
			long valueEncodeDecode = valueEncode.decodeApproximateLong();
			if(i >= valueMaxPrec && valueEncodeDecode != value)
				fail("Error: the value of the decoded result must be equal to the original value");
			if(valueEncodeDecode > value)
				fail("Error: the value of the decoded result must be less than or equal to the original value");
		}
	}

	public void testEncodeDecodeLong(long value) {
		assertEquals(value, Number.encode(value).decodeApproximateLong());
	}

	@Test
	public void testLongConstants() throws Exception {
		testEncodeDecodeLong(Long.MIN_VALUE);
		testEncodeDecodeLong(Long.MIN_VALUE + 1);
		testEncodeDecodeLong(-1);
		testEncodeDecodeLong(0);
		testEncodeDecodeLong(1);
		testEncodeDecodeLong(Long.MAX_VALUE - 1);
		testEncodeDecodeLong(Long.MAX_VALUE);

		testEncodeLong(Long.MIN_VALUE, LONG_MIN_VALUE);
		testEncodeLong(Long.MIN_VALUE + 1, LONG_MIN_VALUE.add(ONE));
		testEncodeLong(-1, ONE.negate());
		testEncodeLong(0, ZERO);
		testEncodeLong(1, ONE);
		testEncodeLong(Long.MAX_VALUE - 1, LONG_MAX_VALUE.subtract(ONE));
		testEncodeLong(Long.MAX_VALUE, LONG_MAX_VALUE);
	}


	@Test
	public void testLongRandom() throws Exception {
		Random random = new Random();
		for(int i = 0; i < 1000000; ++i)
			testEncodeDecodeLong(random.nextLong());
	}

	@Test
	public void testEncodeToExponentDecodeLongConstants() throws Exception {
		long [] constants = {Long.MIN_VALUE, Long.MIN_VALUE + 1, -1, 0, 1, Long.MAX_VALUE - 1, Long.MAX_VALUE};
		for(int i = 0; i < constants.length; ++i) {
			for (int j = 0; j <= 63; ++j)
				testEncodeToExponentDecodeLong(constants[i], j);
		}
	}

	@Test
	public void testEncodeToExponentDecodeLongRandom() throws Exception {
		Random random = new Random();
		for(int i = 0; i < 1000000; ++i) {
			for(int j = 0; j <= 63; ++j)
				testEncodeToExponentDecodeLong(random.nextLong(), j);
		}
	}

	@Test
	public void testEncodeToPrecisionDecodeLongConstants() throws Exception {
		long [] constants = {Long.MIN_VALUE, Long.MIN_VALUE + 1, -1, 0, 1, Long.MAX_VALUE - 1, Long.MAX_VALUE};
		for(int i = 0; i < constants.length; ++i) {
				testEncodeToPrecisionDecodeLong(constants[i]);
		}
	}

	@Test
	public void testEncodeToPrecisiontDecodeLongRandom() throws Exception {
		Random random = new Random();
		for(int i = 0; i < 1000000; ++i) {
			testEncodeToPrecisionDecodeLong(random.nextLong());
		}
	}
}
