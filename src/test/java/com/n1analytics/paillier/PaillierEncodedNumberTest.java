package com.n1analytics.paillier;

import com.n1analytics.paillier.util.BigIntegerUtil;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

import static com.n1analytics.paillier.PaillierContextTest.testEncodable;
import static com.n1analytics.paillier.PaillierContextTest.testUnencodable;
import static com.n1analytics.paillier.TestConfiguration.*;
import static com.n1analytics.paillier.TestUtil.randomFiniteDouble;
import static com.n1analytics.paillier.TestUtil.randomNaNDouble;
import static org.junit.Assert.*;

public class PaillierEncodedNumberTest {
	// Epsilon value for comparing floating point numbers
	private static final double EPSILON = 1e-3;

    public static final Random random = new Random();

    public static final TestConfiguration defConfig = CONFIGURATION_DOUBLE;
    public static final PaillierPrivateKey defPrivateKey = defConfig.privateKey();
    public static final PaillierPublicKey defPublicKey = defPrivateKey.getPublicKey();
    public static final PaillierContext defContext = defConfig.context();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    	// Reference all the test configurations before starting so that they
    	// are created before the tests start.
    	for(TestConfiguration[] confs: CONFIGURATIONS)
    		for(TestConfiguration conf: confs)
    			;
    }

	@Test
	public void testConstructor() throws Exception {
		EncodedNumber encodedNumber = null;

		try {
			encodedNumber = new EncodedNumber(null, BigInteger.ONE, 0);
			fail("Successfully create an encoded number with null context");
		} catch (IllegalArgumentException e) {
		}
		assertNull(encodedNumber);

		try {
			encodedNumber = new EncodedNumber(defContext, null, 0);
			fail("Successfully create an encoded number with null value");
		} catch (IllegalArgumentException e) {
		}
        assertNull(encodedNumber);

		try {
			encodedNumber = new EncodedNumber(defContext, BigInteger.ONE.negate(), 0);
			fail("Successfully create an encoded number with negative value");
		} catch (IllegalArgumentException e) {
		}
        assertNull(encodedNumber);

		try {
			encodedNumber = new EncodedNumber(defContext, defContext.getPublicKey().getModulus(), 0);
			fail("Successfully create an encoded number with value equal to modulus");
		} catch (IllegalArgumentException e) {
		}
        assertNull(encodedNumber);

        encodedNumber = new EncodedNumber(defContext, BigInteger.ONE, 0);
        assertNotNull(encodedNumber);
        assertEquals(BigInteger.ONE, encodedNumber.getValue());
        assertEquals(0, encodedNumber.getExponent());
	}

	public void testLong(TestConfiguration conf, long value) {
    	Number valueFixed = Number.encode(value);
    	BigInteger valueBig = BigInteger.valueOf(value);
    	double valueDouble = (double)value;
    	
		// Attempt to encode and decode the long. If the number is
    	// less than zero and the encoding is unsigned then it must
    	// throw an ArithmeticException.
		try {
			EncodedNumber encoded = conf.context().encode(value);
			if(value < 0 && conf.unsigned())
				fail("ERROR: Successfully encoded negative integer with unsigned encoding");
			assertEquals(conf.context(), encoded.getContext());
			BigInteger expected = valueBig.shiftRight(valueFixed.getExponent());
			if(value < 0)
				expected = conf.modulus().add(expected);
			assertEquals(expected, encoded.getValue());
			// TODO check against fixed point?
			assertEquals(value, encoded.decodeApproximateLong());
			assertEquals(value, encoded.decodeLong());
			assertEquals(valueFixed, encoded.decode());
    		assertEquals(valueBig, encoded.decodeApproximateBigInteger());
    		assertEquals(valueBig, encoded.decodeBigInteger());
    		// NOTE: If value has 11 or less leading zeros then it is not exactly
    		//      representable as a float and the various rounding modes come
    		//      into play. We should aim for exact binary compatibility with
    		//      whatever the rounding mode is.
    		//if(valueDouble != encoded.decode().decodeDouble()) {
    		//	System.out.format(
    		//		"value:           %d\n" +
    		//		"value.hex:       %016X\n" +
    		//		"valueDouble.hex: %016X\n" +
    		//		"decoded.hex:     %016X\n\n",
    		//		value,
    		//		value,
    		//		Double.doubleToLongBits(valueDouble),
    		//		Double.doubleToLongBits(encoded.decode().decodeDouble()));
    		//}
    		if(Long.numberOfLeadingZeros(value) > 10) {
    			assertEquals(valueDouble, encoded.decodeApproximateDouble(), 0);
    			assertEquals(valueDouble, encoded.decodeDouble(), 0);
    		} else {
    			// NOTE for the moment we allow the least significant bit of the
    			//      decoded double to differ:
    			double delta = (double)(1 << (11 - Long.numberOfLeadingZeros(value)));
    			assertEquals(valueDouble, encoded.decodeApproximateDouble(), delta);
    			assertEquals(valueDouble, encoded.decodeDouble(), delta);
    		}
		} catch(EncodeException e) {
			if(value >= 0 || conf.signed())
				throw e;
		}
    }
    
    @Test
    public void testLongSmall() {
    	for(TestConfiguration conf: CONFIGURATION)
    		for(long i = -1024; i <= 1024; ++i)
    			testLong(conf, i);
    }
    
    @Test
    public void testLongLarge() {
    	for(TestConfiguration conf: CONFIGURATION) {
    		testLong(conf, Long.MAX_VALUE);
    		testLong(conf, Long.MIN_VALUE);
    	}
    }
    
    @Test
    public void testLongRandom() {
    	for(TestConfiguration conf: CONFIGURATION)
    		for(int i = 0; i < 100000; ++i)
    			testLong(conf, random.nextLong());
    }
    
    public void testDouble(TestConfiguration conf, double value) {
    	Number valueFixed = Number.encode(value);
    	BigInteger valueBig = valueFixed.getSignificand().shiftLeft(valueFixed.getExponent());
    	long valueLong = valueBig.longValue();
    	
    	try {
    		EncodedNumber encoded = conf.context().encode(value);
    		if(value < 0 && conf.unsigned())
    			fail("ERROR: Successfully encoded negative double with unsigned encoding");
    		
    		BigInteger expected = Number.encode(value).getSignificand();
    		if(value < 0)
    			expected = conf.modulus().add(expected);
    		
    		assertEquals(conf.context(), encoded.getContext());
    		assertEquals(expected, encoded.getValue());
    		assertEquals(value, encoded.decodeApproximateDouble(), 0);
    		assertEquals(valueFixed, encoded.decode());
    		assertEquals(valueBig, encoded.decodeApproximateBigInteger());
    		assertEquals(valueLong, encoded.decodeApproximateLong());
    	} catch(ArithmeticException e) {
    		if(value >= 0 || conf.signed())
    			throw e;
    	}
    }
    
    @Test
    public void testDoubleConstants() {
    	TestConfiguration conf = CONFIGURATION_DOUBLE;
		testDouble(conf, Double.MAX_VALUE);
		testDouble(conf, Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
		testDouble(conf, 1.0);
		testDouble(conf, Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
		testDouble(conf, Double.MIN_NORMAL);
		testDouble(conf, Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
		testDouble(conf, Double.MIN_VALUE);
		testDouble(conf, 0.0);
		testDouble(conf, -0.0);
		testDouble(conf, -Double.MIN_VALUE);
		testDouble(conf, -Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
		testDouble(conf, -Double.MIN_NORMAL);
		testDouble(conf, -Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
		testDouble(conf, -1.0);
		testDouble(conf, -Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
		testDouble(conf, -Double.MAX_VALUE);
    }
        
    @Test
    public void testDoubleRandom() {
    	TestConfiguration conf = CONFIGURATION_DOUBLE;
    	for(int i = 0; i < 100000; ++i)
    		testDouble(conf, randomFiniteDouble());
    }
    
    @Test
    public void testDoubleNonFinite() {
    	// Test constants
    	double[] nonFinite = {
    		Double.NEGATIVE_INFINITY,
    		Double.POSITIVE_INFINITY,
    		Double.NaN
    	};
    	TestConfiguration conf = CONFIGURATION_DOUBLE;
		for(double value: nonFinite) {
			try {
				conf.context().encode(value);
				fail("ERROR: Successfully encoded non-finite double");
			} catch(EncodeException e) {
			}
    	}
    	
    	// Test random NaNs
		for(int i = 0; i < 1000; ++i) {
			try {
				conf.context().encode(randomNaNDouble());
				fail("ERROR: Successfully encoded non-finite double");
			} catch(EncodeException e) {
			}
    	}
    }
    
    public void testRange(TestConfiguration configuration) {
    	BigInteger ZERO = BigInteger.ZERO;
    	BigInteger ONE = BigInteger.ONE;
    	PaillierContext context = configuration.context();
    	BigInteger modulus = context.getPublicKey().getModulus();
    	int exponent = 0;
    	int precision = context.getPrecision();
    	if(configuration.unsignedFullPrecision()) {
    		BigInteger max = modulus.subtract(ONE);
    		
    		assertEquals(new Number(max, exponent), context.getMax(0));
    		assertEquals(new Number(ZERO, exponent), context.getMin(0));
    		
    		assertEquals(max.shiftLeft(exponent), context.getMaxBigInteger(0));
    		assertEquals(ZERO, context.getMinBigInteger(0));
    		
    		// TODO long and double
			long maxLong = max.shiftLeft(exponent).compareTo(BigIntegerUtil.LONG_MAX_VALUE) >= 0
					? Long.MAX_VALUE
					: max.shiftLeft(exponent).longValue();
			assertEquals(maxLong, context.getMaxLong(0));
			assertEquals(ZERO.longValue(), context.getMinLong(0));

			assertEquals(max.doubleValue(), context.getMaxDouble(0), EPSILON * context.getMaxDouble(0));
			assertEquals(ZERO.doubleValue(), context.getMinDouble(0), 0.0);

    		// TODO encode/decode
    		
    	} else if(configuration.unsignedPartialPrecision()) {
    		BigInteger max = ONE.shiftLeft(precision).subtract(ONE);
    		
    		assertEquals(new Number(max, exponent), context.getMax(0));
    		assertEquals(new Number(ZERO, exponent), context.getMin(0));
    		
    		assertEquals(max.shiftLeft(exponent), context.getMaxBigInteger(0));
    		assertEquals(ZERO, context.getMinBigInteger(0));

			long maxLong = max.shiftLeft(exponent).compareTo(BigIntegerUtil.LONG_MAX_VALUE) >= 0
					? Long.MAX_VALUE
					: max.shiftLeft(exponent).longValue();
			assertEquals(maxLong, context.getMaxLong(0));
			assertEquals(ZERO.longValue(), context.getMinLong(0));

			assertEquals(max.doubleValue(), context.getMaxDouble(0), EPSILON * context.getMaxDouble(0));
			assertEquals(ZERO.doubleValue(), context.getMinDouble(0), 0.0);
    	} else if(configuration.signedFullPrecision()) {
    		BigInteger max = context.getPublicKey().getModulus().shiftRight(1);
    		BigInteger min = max.negate();
    		
    		assertEquals(new Number(max, exponent), context.getMax(0));
    		assertEquals(new Number(min, exponent), context.getMin(0));
    		
    		assertEquals(max.shiftLeft(exponent), context.getMaxBigInteger(0));
    		assertEquals(min.shiftLeft(exponent), context.getMinBigInteger(0));

			long maxLong = max.shiftLeft(exponent).compareTo(BigIntegerUtil.LONG_MAX_VALUE) >= 0
					? Long.MAX_VALUE
					: max.shiftLeft(exponent).longValue();
			assertEquals(maxLong, context.getMaxLong(0));
			long minLong = min.shiftLeft(exponent).compareTo(BigIntegerUtil.LONG_MIN_VALUE) <= 0
					? Long.MIN_VALUE
					: min.shiftLeft(exponent).longValue();
			assertEquals(minLong, context.getMinLong(0));

			assertEquals(max.doubleValue(), context.getMaxDouble(0), EPSILON * context.getMaxDouble(0));
			assertEquals(min.doubleValue(), context.getMinDouble(0), EPSILON * Math.abs(context.getMinDouble(0)));
    	} else if(configuration.signedPartialPrecision()) {
    		BigInteger max = ONE.shiftLeft(precision-1).subtract(ONE);
    		BigInteger min = max.negate();
    		
    		assertEquals(new Number(max, exponent), context.getMax(0));
    		assertEquals(new Number(min, exponent), context.getMin(0));
    		
    		assertEquals(max.shiftLeft(exponent), context.getMaxBigInteger(0));
    		assertEquals(min.shiftLeft(exponent), context.getMinBigInteger(0));

			long maxLong = max.shiftLeft(exponent).compareTo(BigIntegerUtil.LONG_MAX_VALUE) >= 0
					? Long.MAX_VALUE
					: max.shiftLeft(exponent).longValue();
			assertEquals(maxLong, context.getMaxLong(0));
			long minLong = min.shiftLeft(exponent).compareTo(BigIntegerUtil.LONG_MIN_VALUE) <= 0
					? Long.MIN_VALUE
					: min.shiftLeft(exponent).longValue();
			assertEquals(minLong, context.getMinLong(0));

			assertEquals(max.doubleValue(), context.getMaxDouble(0), EPSILON * context.getMaxDouble(0));
			assertEquals(min.doubleValue(), context.getMinDouble(0), EPSILON * Math.abs(context.getMinDouble(0)));
    	} else {
    		fail("Invalid defConfig!");
    	}
    }
    
    @Test
    public void testRange() {
    	for(TestConfiguration[] confs: CONFIGURATIONS) {
    		for(TestConfiguration conf: confs) {
    			testRange(conf);
    		}
    	}
    }
    
	@Test
	public void testMaxEncodableNumber() throws Exception {
		for(TestConfiguration[] confs: CONFIGURATIONS) {
			for(TestConfiguration conf: confs) {
				Number maxNumber = Number.encode(conf.maxSignificand());
				testEncodable(conf.context(), maxNumber);
			}
		}
	}

	@Test
	public void testMinEncodableNumber() throws Exception {
		for(TestConfiguration[] confs: CONFIGURATIONS) {
			for(TestConfiguration conf: confs) {
				Number minNumber = Number.encode(conf.minSignificand());
				testEncodable(conf.context(), minNumber);
			}
		}
	}

	@Test
	public void testInvalidLargeMaxNumber() throws Exception {
		for(TestConfiguration[] confs: CONFIGURATIONS) {
			for(TestConfiguration conf: confs) {
				BigInteger humongous = conf.context().getMaxSignificand().add(BigInteger.ONE);
				Number humongousNumber = new Number(humongous, 0);
				testUnencodable(conf.context(), humongousNumber);
			}
		}
	}

	@Test
	public void testInvalidLargeMinNumber() throws Exception {
		for(TestConfiguration[] confs: CONFIGURATIONS) {
			for(TestConfiguration conf: confs) {
				BigInteger negHumongous = conf.context().getMinSignificand().subtract(BigInteger.ONE);
				Number negHumongousNumber = new Number(negHumongous, 0);
				testUnencodable(conf.context(), negHumongousNumber);
			}
		}
	}

	public void testUndecodable(EncodedNumber encodedNumber) throws Exception {
		try {
			Number decodedNumber = encodedNumber.decode();
			fail("Error: successfully decode invalid number.");
		} catch (DecodeException e) {
		} catch (ArithmeticException e) {
		}
	}

	// NOTE: decodeException only applies to partial precision
	@Test
	public void testDecodeInvalidPositiveNumbers() throws Exception {
		for(TestConfiguration[] confs: CONFIGURATIONS) {
			for (TestConfiguration conf : confs) {
				if(conf.isPartialPrecision()) {
					EncodedNumber encodedNumber = new EncodedNumber(conf.context(),
							conf.maxEncoded().add(BigInteger.ONE), 0);
					testUndecodable(encodedNumber);
				}
			}
		}
	}

	@Test
	public void testDecodeInvalidNegativeNumbers() throws Exception {
		for(TestConfiguration[] confs: CONFIGURATIONS) {
			for (TestConfiguration conf : confs) {
				if(conf.signedPartialPrecision()) {
					EncodedNumber encodedNumber = new EncodedNumber(conf.context(),
							conf.minEncoded().subtract(BigInteger.ONE), 0);
					testUndecodable(encodedNumber);
				}
			}
		}
	}

	@Test
	public void testEncrypt() throws Exception {
		EncodedNumber encodedNumber = defContext.encode(1.0);
		EncryptedNumber encryptedNumber = encodedNumber.encrypt();

		EncryptedNumber contextEncryptedNumber = defContext.encrypt(1.0);

		assertTrue(encryptedNumber.equals(contextEncryptedNumber));
	}

	@Test
	public void testCheckSameContextEncryptedNumber() throws Exception {
		PaillierContext otherContext = SIGNED_FULL_PRECISION_1024.context();

		EncodedNumber encodedNumber1 = defContext.encode(1.0);
		EncryptedNumber ciphertext2 = defContext.encrypt(2.0);
		EncryptedNumber ciphertext3 = otherContext.encrypt(2.0);

		EncryptedNumber check = encodedNumber1.checkSameContext(ciphertext2);
		try {
			check = encodedNumber1.checkSameContext(ciphertext3);
			fail("ciphertext1 and ciphertext3 have different context");
		} catch (PaillierContextMismatchException e) {
		}
	}

	@Test
	public void testCheckSameContextEncodedNumber() throws Exception {
		PaillierContext otherContext = SIGNED_FULL_PRECISION_1024.context();

		EncodedNumber encodedNumber1 = defContext.encode(1.0);
		EncodedNumber encodedNumber2 = defContext.encode(2.0);
		EncodedNumber encodedNumber3 = otherContext.encode(2.0);

		EncodedNumber check = encodedNumber1.checkSameContext(encodedNumber2);
		try {
			check = encodedNumber1.checkSameContext(encodedNumber3);
			fail("encodedNumber1 and encodedNumber3 have different context");
		} catch (PaillierContextMismatchException e) {
		}
	}

	@Test
	public void testChangeContext() throws Exception {
		PaillierContext otherContext = SIGNED_FULL_PRECISION_1024.context();

		EncodedNumber encodedNumberContext1 = defContext.encode(1.7);
		EncodedNumber encodedNumberContext2 = encodedNumberContext1.changeContext(otherContext);

		assertEquals(encodedNumberContext1.decodeDouble(), encodedNumberContext2.decodeDouble(), 0.0);
	}

	@Test
	public void testIsEncodedNumberValid() throws Exception {
		EncodedNumber encodedNumber1 = new EncodedNumber(defContext, defContext.getMaxEncoded(), 0);
		EncodedNumber encodedNumber2 = new EncodedNumber(defContext, defContext.getMinEncoded(), 0);
		EncodedNumber encodedNumber3 = new EncodedNumber(defContext, defContext.getMaxEncoded().add(BigInteger.ONE), 0);

		assertEquals(true, encodedNumber1.isValid());
		assertEquals(true, encodedNumber2.isValid());
		assertEquals(false, encodedNumber3.isValid());
	}

	@Test
	public void testAddLongToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(1.7);
		EncodedNumber encodedNumber2 = encodedNumber1.add(2);
		assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
	}

	@Test
	public void testAddDoubleToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(1.7);
		EncodedNumber encodedNumber2 = encodedNumber1.add(2.0);
		assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
	}

	@Test
	public void testAddBigIntegerToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(1.7);
		EncodedNumber encodedNumber2 = encodedNumber1.add(new BigInteger("2"));
		assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
	}

	@Test
	public void testSubtractLongToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(17);
		EncodedNumber encodedNumber2 = encodedNumber1.subtract(2);
		assertEquals(15, encodedNumber2.decodeDouble(), 0.0);
	}

	@Test
	public void testSubtractDoubleToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(17);
		EncodedNumber encodedNumber2 = encodedNumber1.subtract(2.0);
		assertEquals(15, encodedNumber2.decodeDouble(), 0.0);
	}

	@Test
	public void testSubtractBigIntegerToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(17);
		EncodedNumber encodedNumber2 = encodedNumber1.subtract(new BigInteger("2"));
		assertEquals(15, encodedNumber2.decodeDouble(), 0.0);
	}

	@Test
	public void testMultiplyLongToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(1.7);
		EncodedNumber encodedNumber2 = encodedNumber1.multiply(2);
		assertEquals(3.4, encodedNumber2.decodeDouble(), 0.0);
	}

	@Test
	public void testMultiplyDoubleToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(1.7);
		EncodedNumber encodedNumber2 = encodedNumber1.multiply(2.0);
		assertEquals(3.4, encodedNumber2.decodeDouble(), 0.0);
	}

	@Test
	public void testMultiplyBigIntegerToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(1.7);
		EncodedNumber encodedNumber2 = encodedNumber1.multiply(new BigInteger("2"));
		assertEquals(3.4, encodedNumber2.decodeDouble(), 0.0);
	}

	@Test
	public void testDivideLongToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(1.7);
		EncodedNumber encodedNumber2 = encodedNumber1.divide(2);
		assertEquals(0.85, encodedNumber2.decodeDouble(), 0.0);
	}

	@Test
	public void testDivideDoubleToEncodedNumber() throws Exception {
		EncodedNumber encodedNumber1 = defContext.encode(1.7);
		EncodedNumber encodedNumber2 = encodedNumber1.divide(2.0);
		assertEquals(0.85, encodedNumber2.decodeDouble(), 0.0);
	}

    @Test
    public void testEquals() throws Exception {
        EncodedNumber encodedNumber = defContext.encode(17);

        assertTrue(encodedNumber.equals(encodedNumber));
        assertFalse(encodedNumber.equals(defPrivateKey));

        EncodedNumber otherEncodedNumber = null;

        // Check when the other public key hasn't been initialised (ie, is null)
        assertFalse(defPublicKey.equals(otherEncodedNumber));

        otherEncodedNumber = defContext.encode(3);

        // Check after the other private key has been initialised (ie, is not null)
        assertFalse(defPublicKey.equals(otherEncodedNumber));

        assertFalse(defPublicKey.equals(null));
    }
}

