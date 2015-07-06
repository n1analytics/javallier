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

//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

/**
 * Test cases for EncodedNumber class.
 */
public class PaillierEncodedNumberTest {
	// Epsilon value for comparing floating point numbers
	private static final double EPSILON = 1e-3;

//    final static Logger logger = LoggerFactory.getLogger(PaillierEncodedNumberTest.class);
    
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
//			assertEquals(max.shiftLeft(exponent).doubleValue(), context.getMaxDouble(0), 0.0);
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
//			assertEquals(max.shiftLeft(exponent).doubleValue(), context.getMaxDouble(0), 0.0);
//			assertEquals(min.doubleValue(), context.getMinDouble(0), 0.0);
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
    
    // TODO test the maximum/minimum encodable numbers for each defConfig
    // TODO test whether an exception is raised for numbers that are too large
    //      or too negative to encode properly
    // TODO test that decoding invalid numbers raises an exception (for the min
    //      and max as well as randomly within that range)
    

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

//	@Test
//    public void testEncodeIntDecodeInt4() throws Exception {
////        logger.debug("Running phe test: Encode/decode the largest positive BigInteger.");
//
//        EncodedNumber enc = defContext.encode(defContext.getMaxSignificand());
//        assertEquals(0, enc.getExponent());
//        BigInteger dec = enc.decodeBigInteger();
//        assertEquals(defContext.getMaxSignificand().toString(), dec.toString());
//    }
//
//    @Test
//    public void testEncodeIntDecodeInt5() throws Exception {
////        logger.debug("Running phe test: Encode/decode the largest negative BigInteger.");
//
//        EncodedNumber enc = defContext.encode(defContext.getMinSignificand());
//        BigInteger dec = enc.decodeBigInteger();
//        assertEquals(defContext.getMinSignificand().toString(), dec.toString());
//    }

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

	// NOTE: Need to check how to make humongous2 works!!
//    @Test
//    public void testEncodeIntTooLargePositive() throws Exception {
////        logger.debug("Running phe test: Check whether exception is raised on too large a positive input.");
//
//        BigInteger humongous1 = defContext.getMaxSignificand().add(BigInteger.ONE);
//        BigInteger humongous2 = (new BigInteger("2")).pow(defPublicKey.getModulus().bitLength());
//
//        Number humongousNumber1 = Number.encodeToExponent(humongous1, 0);
//        Number humongousNumber2 = Number.encodeToExponent(humongous2, 0);
//
//        exception.expect(EncodeException.class);
//        EncodedNumber enc = defContext.encode(humongousNumber1);
//        EncodedNumber enc2 = defContext.encode(humongousNumber2);
//
//    }

//    @Test
//    public void testEncodeIntTooLargeNegative() throws Exception {
////        logger.debug("Running phe test: Check whether exception is raised on too large a negative input.");
//
//        BigInteger negHumongous1 = defContext.getMinSignificand().subtract(BigInteger.ONE);
//        BigInteger negHumongous2 = (new BigInteger("-2")).pow(defPublicKey.getModulus().bitLength());
//
//        Number negHumongousNumber1 = Number.encodeToExponent(negHumongous1, 0);
//        Number neghumongousNumber2 = Number.encodeToExponent(negHumongous2, 0);
//
//        exception.expect(EncodeException.class);
//        EncodedNumber enc = defContext.encode(negHumongousNumber1);
//        EncodedNumber enc2 = defContext.encode(neghumongousNumber2);
//    }

// NOTE: The test is not valid. For arithmetic operations between EncryptedNumber and primitive data type, the methods
//      check whether both operands are valid (i.e., the values are between minSignificand and maxSignificand).
//    @Test
//    public void testDecodeCorruptEncodedNumber() throws Exception {
//        logger.debug("Running phe test: Check exception is raised when attempting to decode corrupt encoded number.");
//
//        EncodedNumber enc = defContext.encode(10);
//
////        enc = new EncodedNumber(
////        	defContext,
////        	enc.getValue().add(defPublicKey.getModulus()),
////        	enc.getExponent());
//
//        exception.expect(ArithmeticException.class);
//        long dec = enc.decodeLong();
//    }

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
					EncodedNumber encodedNumber = new EncodedNumber(conf.context(), conf.maxEncoded().add(BigInteger.ONE), 0);
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
					EncodedNumber encodedNumber = new EncodedNumber(conf.context(), conf.minEncoded().subtract(BigInteger.ONE), 0);
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

//    @Test
//    public void testDecodeWithOverflowEncodedNumber() {
////        logger.debug("Running phe test: Check exception is raised when attempting to decode overflow encoded number.");
//
//        EncodedNumber enc = defContext.encode(10);
//        enc = enc.add(defContext.getMaxEncoded().subtract(new BigInteger("10")));
//
//        exception.expect(ArithmeticException.class);
//        long dec = enc.decodeLong();
//    }

// NOTE: Encode/decode floating point numbers are done in testDouble
//    @Test
//    public void testEncodeFloat0() throws Exception {
//        logger.debug("Running phe test: Encode a small positive double.");
//
//        EncodedNumber enc = EncodedNumber.encode(publicKey, 15.1);
//
//        // BASE^exponent * encoding
//        double dec = Math.pow((double)2, (double) enc.getExponent()) * enc.getEncoded().doubleValue();
//        assertEquals((new BigDecimal(15.1)).toString(), (new BigDecimal(dec)).toString());
//    }
//
//    @Test
//    public void testEncodeFloatDecodeFloat0() throws Exception {
////        logger.debug("Running phe test: Encode/decode a small positive double.");
//
//        EncodedNumber enc = defContext.encode(15.1);
////        EncodedNumber enc = EncodedNumber.encode(publicKey, 15.1);
//        double dec = enc.decodeDouble();
//        assertEquals(15.1, dec, 0.0);
//    }
//
//    @Test
//    public void testEncodeFloatDecodeFloat1() throws Exception {
//        logger.debug("Running phe test: Encode/decode a small negative double.");
//
//        EncodedNumber enc = EncodedNumber.encode(publicKey, -15.1);
//        assertEquals((new BigDecimal(-15.1)).toString(), (new BigDecimal(enc.decodeDouble())).toString());
//    }
//
//    @Test
//    public void testEncryptFloatDecryptFloat2() throws Exception {
////        logger.debug("Running phe test: Encode/decode a large positive double.");
//
//        EncodedNumber enc = defContext.encode(Math.pow(2.1,20.0));
//        assertEquals(Math.pow(2.1,20.0), enc.decodeDouble(), 0.0);
//    }
//
//    @Test
//    public void testEncryptFloatDecryptFloat3() throws Exception {
////        logger.debug("Running phe test: Encode/decode a large negative double.");
//
//        EncodedNumber enc = defContext.encode(Math.pow(-2.1,63));
//        assertEquals(Math.pow(-2.1, 63.0), enc.decodeDouble(), 0.0);
//    }

// NOTE: Encoding to specific precision or exponent are done in Number.
//    @Test
//    public void testManualPrecision0() throws Exception {
//        logger.debug("Running phe test: Check that the encoded positive number is precise enough.");
//
//        double val = 3.171234 * Math.pow(10,-7);
//        double prec = Math.pow(10, -8);
//
//        EncodedNumber enc = EncodedNumber.encode(publicKey, val, prec);
//        double dec = enc.decodeDouble();
//
////        Original code: self.assertInRange(decoded, val - prec, val + prec)
//        if(dec < val - prec || dec > val + prec){
//            fail("decoded number < val - prec or decoded number > val + prec");
//        }
//
//        EncodedNumber enc2 = EncodedNumber.encode(publicKey, dec + 0.500001 * prec, prec);
//        double dec2 = enc2.decodeDouble();
//        assertNotEquals(dec, dec2);
//
////        Original code: self.assertInRange(dec2, val - prec/2, val + prec*1.5001)
//        if(dec2 < val - prec / 2 || dec2 > val + prec * 1.5001){
//            fail("(decoded number < val - prec / 2) OR (decode number > val + prec * 1.5001)");
//        }
//
//        double val3 = dec + prec / 2;
//        EncodedNumber enc3 = EncodedNumber.encode(publicKey, val3, prec);
//        double dec3 = enc3.decodeDouble();
//        assertEquals((new BigDecimal(String.valueOf(dec))).toString(), (new BigDecimal(String.valueOf(dec3))).toString());
//    }
//
//    @Test
//    public void testManualPrecision1(){
//        logger.debug("Running phe test: Check that the encoded -ve number is precise enough.");
//
//        double val = -3.171234 * Math.pow(10,-7);
//        double prec = Math.pow(10, -8);
//
//        EncodedNumber enc = EncodedNumber.encode(publicKey, val, prec);
//        double dec = enc.decodeDouble();
//
////        Original code: self.assertInRange(decoded, val - prec, val + prec)
//        if(dec < val - prec || dec > val + prec){
//            fail("decoded number < val - prec or decoded number > val + prec");
//        }
//
//        EncodedNumber enc2 = EncodedNumber.encode(publicKey, dec + 0.500001 * prec, prec);
//        double dec2 = enc2.decodeDouble();
//        assertNotEquals(dec, dec2);
//
////        Original code: self.assertInRange(decoded2, val, val + prec)
//        if(dec2 < val || dec2 > val + prec){
//            fail("decoded number < val OR decoded number > val + prec");
//        }
//
//        double val3 = dec + prec / 2;
//        EncodedNumber enc3 = EncodedNumber.encode(publicKey, val3, prec);
//        double dec3 = enc3.decodeDouble();
//        assertEquals((new BigDecimal(String.valueOf(dec))).toString(), (new BigDecimal(String.valueOf(dec3))).toString());
//    }
//
//    @Test
//    public void testAutomaticPrecisionAgreesWithEpsilon() throws Exception {
//        logger.debug("Running phe test: Check that automatic precision is equivalent to the machine epsilon");
//
//        double eps = Math.ulp(1.0);
//
//        double floorHappy = Math.ceil(Math.log((double)2)/ Math.log(2.0)) * 2;
//
//        for(double i = -floorHappy; i <= floorHappy; i++){
//            EncodedNumber enc1 = EncodedNumber.encode(publicKey, Math.pow(2.0, i));
//            EncodedNumber enc2 = EncodedNumber.encode(publicKey, Math.pow(2.0, i), (eps * Math.pow(2.0, i)));
//            assertEquals(String.valueOf(i), enc1.getExponent(), enc2.getExponent());
//
//            double realEps = eps * Math.pow(2.0, (i - 1));
//            double val = Math.pow(2.0, i) - realEps;
//            assert val != Math.pow(2.0, i);
//
//            EncodedNumber enc3 = EncodedNumber.encode(publicKey, val);
//            EncodedNumber enc4 = EncodedNumber.encode(publicKey, val, realEps);
//            assertEquals(String.valueOf(i), enc3.getExponent(), enc4.getExponent());
//        }
//    }
//
//    @Test
//    public void testEncodedDecreaseExponentTo0() throws Exception {
//        logger.debug("Running phe test: Check that decreaseExponentTo does what it says to positive double.");
//
//        EncodedNumber enc1 = EncodedNumber.encode(publicKey, 3.14);
//        assert -30 < enc1.getExponent();
//        EncodedNumber enc2 = enc1.decreaseExponentTo(-30);
//
//        if(enc1.getExponent() < -30){
//            fail("-30 < enc1.getExponent()");
//        }
//        assertEquals(-30, enc2.getExponent());
//        double dec = enc2.decodeDouble();
//        assertEquals(3.14, dec, 0.01);
//    }
//
//    @Test
//    public void testEncodedDecreaseExponentTo1() throws Exception {
//        logger.debug("Running phe test: Check that decreaseExponentTo does what it says to negative double.");
//
//        EncodedNumber enc1 = EncodedNumber.encode(publicKey, -3.14);
//        assert -30 < enc1.getExponent();
//        EncodedNumber enc2 = enc1.decreaseExponentTo(-30);
//
//        if(enc1.getExponent() < -30){
//            fail("-30 < enc1.getExponent()");
//        }
//        assertEquals(-30, enc2.getExponent());
//        double dec = enc2.decodeDouble();
//        assertEquals(-3.14, dec, 0.01);
//    }
//
//    @Test
//    public void testEncodedDecreaseInvalidExponent(){
//        logger.debug("Running phe test: Check that decreaseExponentTo catch invalid exponent.");
//
//        EncodedNumber enc1 = EncodedNumber.encode(publicKey, 3.14);
//        assert enc1.getExponent() < -10;
//
//        exception.expect(IllegalArgumentException.class);
//        enc1.decreaseExponentTo(-10);
//    }
}

