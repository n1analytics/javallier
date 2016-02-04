/**
 * Copyright 2015 NICTA
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
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
import static com.n1analytics.paillier.TestUtil.EPSILON;
import static org.junit.Assert.*;

public class PaillierEncodedNumberTest {
  public static final Random random = new Random();

  private static final PaillierContext defaultSignedContext = SIGNED_FULL_PRECISION.context();
  private static final PaillierContext defaultUnsignedContext = UNSIGNED_FULL_PRECISION.context();
  private static final PaillierContext defaultPartialSignedContext = SIGNED_PARTIAL_PRECISION.context();

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    // Reference all the test configurations before starting so that they
    // are created before the tests start.
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        ;
      }
    }
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
      encodedNumber = new EncodedNumber(defaultSignedContext, null, 0);
      fail("Successfully create an encoded number with null value");
    } catch (IllegalArgumentException e) {
    }
    assertNull(encodedNumber);

    try {
      encodedNumber = new EncodedNumber(defaultSignedContext, BigInteger.ONE.negate(), 0);
      fail("Successfully create an encoded number with negative value");
    } catch (IllegalArgumentException e) {
    }
    assertNull(encodedNumber);

    try {
      encodedNumber = new EncodedNumber(defaultSignedContext,
              defaultSignedContext.getPublicKey().getModulus(), 0);
      fail("Successfully create an encoded number with value equal to modulus");
    } catch (IllegalArgumentException e) {
    }
    assertNull(encodedNumber);

    encodedNumber = new EncodedNumber(defaultSignedContext, BigInteger.ONE, 0);
    assertNotNull(encodedNumber);
    assertEquals(BigInteger.ONE, encodedNumber.getValue());
    assertEquals(0, encodedNumber.getExponent());
  }

  public void testLong(TestConfiguration conf, long value) {
    BigInteger valueBig = BigInteger.valueOf(value);
    double valueDouble = (double) value;

    // Attempt to encode and decode the long. If the number is
    // less than zero and the encoding is unsigned then it must
    // throw an ArithmeticException.
    try {
//      Number valueFixed = Number.encode(value);
      EncodedNumber encoded = conf.context().encode(value);
      if (value < 0 && conf.unsigned()) {
        fail("ERROR: Successfully encoded negative integer with unsigned encoding");
      }
      assertEquals(conf.context(), encoded.getContext());
      BigInteger expected = valueBig.shiftRight(encoded.getExponent());
      if (value < 0) {
        expected = conf.modulus().add(expected);
      }
      assertEquals(expected, encoded.getValue());
//      assertEquals(value, encoded.decodeApproximateLong());
      assertEquals(value, encoded.decodeLong());
//      assertEquals(valueFixed, encoded.decode());
//      assertEquals(valueBig, encoded.decodeApproximateBigInteger());
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
      if (Long.numberOfLeadingZeros(value) > 10) {
//        assertEquals(valueDouble, encoded.decodeApproximateDouble(), 0);
        assertEquals(valueDouble, encoded.decodeDouble(), 0);
      } else {
        // NOTE for the moment we allow the least significant bit of the
        //      decoded double to differ:
        double delta = (double) (1 << (11 - Long.numberOfLeadingZeros(value)));
//        assertEquals(valueDouble, encoded.decodeApproximateDouble(), delta);
        assertEquals(valueDouble, encoded.decodeDouble(), delta);
      }
    } catch (EncodeException e) {
      if (value >= 0 || conf.signed()) {
        throw e;
      }
    }
  }

  @Test
  public void testLongSmall() {
    for (TestConfiguration conf : CONFIGURATION) {
      for (long i = -1024; i <= 1024; ++i) {
        testLong(conf, i);
      }
    }
  }

  @Test
  public void testLongLarge() {
    for (TestConfiguration conf : CONFIGURATION) {
      testLong(conf, Long.MAX_VALUE);
      testLong(conf, Long.MIN_VALUE);
    }
  }

  @Test
  public void testLongRandom() {
    for (TestConfiguration conf : CONFIGURATION) {
      for (int i = 0; i < 100000; ++i) {
        testLong(conf, random.nextLong());
      }
    }
  }

  public void testDouble(TestConfiguration conf, double value) {
    try {
//      Number valueFixed = Number.encode(value);
//      BigInteger valueBig = valueFixed.getSignificand().shiftLeft(valueFixed.getExponent());
//      long valueLong = valueBig.longValue();

      EncodedNumber encoded = conf.context().encode(value);
      if (value < 0 && conf.unsigned()) {
        fail("ERROR: Successfully encoded negative double with unsigned encoding");
      }

//      BigInteger expected = Number.encode(value).getSignificand();
//      if (value < 0) {
//        expected = conf.modulus().add(expected);
//      }
      BigInteger expected = conf.context().encode(value).getValue();

      assertEquals(conf.context(), encoded.getContext());
      assertEquals(expected, encoded.getValue());
      assertEquals(value, encoded.decodeDouble(), EPSILON);
//      assertEquals(valueFixed, encoded.decode());
//      assertEquals(valueBig, encoded.decodeBigInteger());
//      assertEquals(valueLong, encoded.decodeLong());
    } catch (ArithmeticException e) {
      if (value >= 0 || conf.signed()) {
        throw e;
      }
    }
  }

  @Test
  public void testDoubleConstants() {
//    TestConfiguration conf = CONFIGURATION_DOUBLE;
    TestConfiguration conf = SIGNED_FULL_PRECISION_2048;
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
    for (int i = 0; i < 100000; ++i) {
      testDouble(conf, randomFiniteDouble());
    }
  }

  @Test
  public void testDoubleNonFinite() {
    // Test constants
    double[] nonFinite = {Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, Double.NaN};
    TestConfiguration conf = CONFIGURATION_DOUBLE;
    for (double value : nonFinite) {
      try {
        conf.context().encode(value);
        fail("ERROR: Successfully encoded non-finite double");
      } catch (EncodeException e) {
      }
    }

    // Test random NaNs
    for (int i = 0; i < 1000; ++i) {
      try {
        conf.context().encode(randomNaNDouble());
        fail("ERROR: Successfully encoded non-finite double");
      } catch (EncodeException e) {
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
    if (configuration.unsignedFullPrecision()) {
      BigInteger max = modulus.subtract(ONE);

//      assertEquals(new Number(max, exponent), context.getMax(0));
//      assertEquals(new Number(ZERO, exponent), context.getMin(0));

      assertEquals(max.shiftLeft(exponent), context.getMaxSignificand());
      assertEquals(ZERO, context.getMinSignificand());

      long maxLong = max.shiftLeft(exponent).compareTo(
              BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
              exponent).longValue();
      long actualMaxLong = context.getMaxSignificand().compareTo(
              BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
              exponent).longValue();
      assertEquals(maxLong, actualMaxLong);
      assertEquals(ZERO.longValue(), context.getMinSignificand().longValue());

      assertEquals(max.doubleValue(), context.getMaxSignificand().doubleValue(),
                   EPSILON * context.getMaxSignificand().doubleValue());
      assertEquals(ZERO.doubleValue(), context.getMinSignificand().doubleValue(), 0.0);

      // TODO Issue #15: encode/decode

    } else if (configuration.unsignedPartialPrecision()) {
      BigInteger max = ONE.shiftLeft(precision).subtract(ONE);

//      assertEquals(new Number(max, exponent), context.getMax(0));
//      assertEquals(new Number(ZERO, exponent), context.getMin(0));

      assertEquals(max.shiftLeft(exponent), context.getMaxSignificand());
      assertEquals(ZERO, context.getMinSignificand());

      long maxLong = max.shiftLeft(exponent).compareTo(
              BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
              exponent).longValue();
      long actualMaxLong = context.getMaxSignificand().compareTo(
              BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
              exponent).longValue();
      assertEquals(maxLong, actualMaxLong);
      assertEquals(ZERO.longValue(), context.getMinSignificand().longValue());

      assertEquals(max.doubleValue(), context.getMaxSignificand().doubleValue(),
                   EPSILON * context.getMaxSignificand().doubleValue());
      assertEquals(ZERO.doubleValue(), context.getMinSignificand().doubleValue(), 0.0);
    } else if (configuration.signedFullPrecision()) {
      BigInteger max = context.getPublicKey().getModulus().shiftRight(1);
      BigInteger min = max.negate();

//      assertEquals(new Number(max, exponent), context.getMax(0));
//      assertEquals(new Number(min, exponent), context.getMin(0));

      assertEquals(max.shiftLeft(exponent), context.getMaxSignificand());
      assertEquals(min.shiftLeft(exponent), context.getMinSignificand());

      long maxLong = max.shiftLeft(exponent).compareTo(
              BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
              exponent).longValue();
      long actualMaxLong = context.getMaxSignificand().compareTo(
              BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
              exponent).longValue();
      assertEquals(maxLong, actualMaxLong);
      long minLong = min.shiftLeft(exponent).compareTo(
              BigIntegerUtil.LONG_MIN_VALUE) <= 0 ? Long.MIN_VALUE : min.shiftLeft(
              exponent).longValue();
      long actualMinLong = context.getMinSignificand().compareTo(
              BigIntegerUtil.LONG_MIN_VALUE) <= 0 ? Long.MIN_VALUE : min.shiftLeft(
              exponent).longValue();
      assertEquals(minLong, actualMinLong);


      assertEquals(max.doubleValue(), context.getMaxSignificand().doubleValue(),
                   EPSILON * context.getMaxSignificand().doubleValue());
      assertEquals(min.doubleValue(), context.getMinSignificand().doubleValue(),
                   EPSILON * Math.abs(context.getMinSignificand().doubleValue()));
    } else if (configuration.signedPartialPrecision()) {
      BigInteger max = ONE.shiftLeft(precision - 1).subtract(ONE);
      BigInteger min = max.negate();

//      assertEquals(new Number(max, exponent), context.getMax(0));
//      assertEquals(new Number(min, exponent), context.getMin(0));

      assertEquals(max.shiftLeft(exponent), context.getMaxSignificand());
      assertEquals(min.shiftLeft(exponent), context.getMinSignificand());

      long maxLong = max.shiftLeft(exponent).compareTo(
              BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
              exponent).longValue();
      long actualMaxLong = context.getMaxSignificand().compareTo(
              BigIntegerUtil.LONG_MAX_VALUE) >= 0 ? Long.MAX_VALUE : max.shiftLeft(
              exponent).longValue();
      assertEquals(maxLong, actualMaxLong);
      long minLong = min.shiftLeft(exponent).compareTo(
              BigIntegerUtil.LONG_MIN_VALUE) <= 0 ? Long.MIN_VALUE : min.shiftLeft(
              exponent).longValue();
      long actualMinLong = context.getMinSignificand().compareTo(
              BigIntegerUtil.LONG_MIN_VALUE) <= 0 ? Long.MIN_VALUE : min.shiftLeft(
              exponent).longValue();
      assertEquals(minLong, actualMinLong);

      assertEquals(max.doubleValue(), context.getMaxSignificand().doubleValue(),
                   EPSILON * context.getMaxSignificand().doubleValue());
      assertEquals(min.doubleValue(), context.getMinSignificand().doubleValue(),
                   EPSILON * Math.abs(context.getMinSignificand().doubleValue()));
    } else {
      fail("Invalid defConfig!");
    }
  }

  @Test
  public void testRange() {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        testRange(conf);
      }
    }
  }

  @Test
  public void testMaxEncodableNumber() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        EncodedNumber maxNumber = conf.context().encode(conf.maxSignificand());
        testEncodable(conf.context(), maxNumber);
      }
    }
  }

  @Test
  public void testMinEncodableNumber() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        EncodedNumber minNumber = conf.context().encode(conf.minSignificand());
        testEncodable(conf.context(), minNumber);
      }
    }
  }

  @Test
  public void testInvalidLargeMaxNumber() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        BigInteger humongous = conf.context().getMaxSignificand().add(BigInteger.ONE);
        testUnencodable(conf.context(), humongous);
      }
    }
  }

  @Test
  public void testInvalidLargeMinNumber() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        BigInteger negHumongous = conf.context().getMinSignificand().subtract(
                BigInteger.ONE);
        testUnencodable(conf.context(), negHumongous);
      }
    }
  }

  public void testUndecodable(EncodedNumber encodedNumber) throws Exception {
    try {
      double decodedNumber = encodedNumber.decodeDouble();
      fail("Error: successfully decode invalid number.");
    } catch (DecodeException e) {
    } catch (ArithmeticException e) {
    }
  }

  // NOTE: decodeException only applies to partial precision
  @Test
  public void testDecodeInvalidPositiveNumbers() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        if (conf.isPartialPrecision()) {
          EncodedNumber encodedNumber = new EncodedNumber(conf.context(),
                                                          conf.maxEncoded().add(
                                                                  BigInteger.ONE), 0);
          testUndecodable(encodedNumber);
        }
      }
    }
  }

  @Test
  public void testDecodeInvalidNegativeNumbers() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        if (conf.signedPartialPrecision()) {
          EncodedNumber encodedNumber = new EncodedNumber(conf.context(),
                                                          conf.minEncoded().subtract(
                                                                  BigInteger.ONE), 0);
          testUndecodable(encodedNumber);
        }
      }
    }
  }

  @Test
  public void testEncrypt() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber = conf.context().encode(1.0);
      EncryptedNumber encryptedNumber = encodedNumber.encrypt();

      EncryptedNumber contextEncryptedNumber = conf.context().encrypt(1.0);

      assertTrue(encryptedNumber.equals(contextEncryptedNumber));
    }
  }

  @Test
  public void testCheckSameContextEncryptedNumber() throws Exception {
    EncodedNumber encodedNumber1 = defaultSignedContext.encode(1.0);
    EncryptedNumber ciphertext2 = defaultSignedContext.encrypt(2.0);
    EncryptedNumber ciphertext3 = defaultPartialSignedContext.encrypt(2.0);

    EncryptedNumber check = encodedNumber1.checkSameContext(ciphertext2);
    try {
      check = encodedNumber1.checkSameContext(ciphertext3);
      fail("ciphertext1 and ciphertext3 have different context");
    } catch (PaillierContextMismatchException e) {
    }
  }

  @Test
  public void testCheckSameContextEncodedNumber() throws Exception {
    EncodedNumber encodedNumber1 = defaultSignedContext.encode(1.0);
    EncodedNumber encodedNumber2 = defaultSignedContext.encode(2.0);
    EncodedNumber encodedNumber3 = defaultUnsignedContext.encode(2.0);

    EncodedNumber check = encodedNumber1.checkSameContext(encodedNumber2);
    try {
      check = encodedNumber1.checkSameContext(encodedNumber3);
      fail("encodedNumber1 and encodedNumber3 have different context");
    } catch (PaillierContextMismatchException e) {
    }
  }

  @Test
  public void testChangeContext() throws Exception {
    EncodedNumber encodedDoubleContext1 = defaultSignedContext.encode(1.7);
    EncodedNumber encodedDoubleContext2 = encodedDoubleContext1.changeContext(
            defaultPartialSignedContext);

    assertEquals(encodedDoubleContext1.decodeDouble(),
                 encodedDoubleContext2.decodeDouble(), 0.0);

    EncodedNumber encodedBigIntegerContext1 = defaultSignedContext.encode(17);
    EncodedNumber encodedBigIntegerContext2 = encodedBigIntegerContext1.changeContext(
            defaultPartialSignedContext);

    assertEquals(encodedBigIntegerContext1.decodeDouble(),
            encodedBigIntegerContext2.decodeDouble(), 0.0);

  }

  @Test
  public void testIsEncodedNumberValid() throws Exception {
    EncodedNumber encodedNumber1 = new EncodedNumber(defaultPartialSignedContext,
            defaultPartialSignedContext.getMaxEncoded(), 0);
    EncodedNumber encodedNumber2 = new EncodedNumber(defaultPartialSignedContext,
            defaultPartialSignedContext.getMinEncoded(), 0);
    EncodedNumber encodedNumber3 = new EncodedNumber(defaultPartialSignedContext,
            defaultPartialSignedContext.getMaxEncoded().add(BigInteger.ONE), 0);

    assertEquals(true, encodedNumber1.isValid());
    assertEquals(true, encodedNumber2.isValid());
    assertEquals(false, encodedNumber3.isValid());
  }

  @Test
  public void testAddLongToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.add(2);
      assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testAddDoubleToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.add(2.0);
      assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testAddBigIntegerToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.add(new BigInteger("2"));
      assertEquals(3.7, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testSubtractLongToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(17);
      EncodedNumber encodedNumber2 = encodedNumber1.subtract(2);
      assertEquals(15, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testSubtractDoubleToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(17);
      EncodedNumber encodedNumber2 = encodedNumber1.subtract(2.0);
      assertEquals(15, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testSubtractBigIntegerToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(17);
      EncodedNumber encodedNumber2 = encodedNumber1.subtract(new BigInteger("2"));
      assertEquals(15, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testMultiplyLongToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.multiply(2);
      assertEquals(3.4, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testMultiplyDoubleToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.multiply(2.0);
      assertEquals(3.4, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testMultiplyBigIntegerToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.multiply(new BigInteger("2"));
      assertEquals(3.4, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testDivideLongToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.divide(2);
      assertEquals(0.85, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testDivideDoubleToEncodedNumber() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber encodedNumber1 = conf.context().encode(1.7);
      EncodedNumber encodedNumber2 = encodedNumber1.divide(2.0);
      assertEquals(0.85, encodedNumber2.decodeDouble(), EPSILON);
    }
  }

  @Test
  public void testEquals() throws Exception {
    EncodedNumber encodedNumber = defaultSignedContext.encode(17);

    assertTrue(encodedNumber.equals(encodedNumber)); // Compare to itself
    assertFalse(encodedNumber.equals(defaultSignedContext)); // Compare to other object
    assertFalse(encodedNumber.equals(null)); // Compare to null

    EncodedNumber otherEncodedNumber = null;
    assertFalse(encodedNumber.equals(otherEncodedNumber)); // Compare to an uninitialised encoded number
    otherEncodedNumber = defaultSignedContext.encode(3);
    assertFalse(encodedNumber.equals(otherEncodedNumber)); // Compare to an encoded number with different value

    otherEncodedNumber = defaultPartialSignedContext.encode(17);
    assertFalse(encodedNumber.equals(otherEncodedNumber)); // Compare to an encoded number with different context
  }

  @Test
  public void testPositiveEncodedDecreaseExponentTo() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      EncodedNumber number1 = conf.context().encode(3.14);
      int originalExp = number1.getExponent();
      int newExp = originalExp - 20;
      EncodedNumber number2 = number1.decreaseExponentTo(newExp);

      if(originalExp < number2.getExponent()){
        fail("Fail to decrease the encoded number's exponent");
      }
      assertEquals(newExp, number2.getExponent());
      double decodedNumber = number2.decodeDouble();
      assertEquals(3.14, decodedNumber, EPSILON);
    }
  }

  @Test
  public void testNegativeEncodedDecreaseExponentTo() throws Exception {
    for (TestConfiguration conf : CONFIGURATION) {
      if(conf.signed()) {
        EncodedNumber number1 = conf.context().encode(-3.14);
        int originalExp = number1.getExponent();
        int newExp = originalExp - 20;
        EncodedNumber number2 = number1.decreaseExponentTo(newExp);

        if(originalExp < number2.getExponent()){
          fail("Fail to decrease the encoded number's exponent");
        }
        assertEquals(newExp, number2.getExponent());
        double decodedNumber = number2.decodeDouble();
        assertEquals(-3.14, decodedNumber, EPSILON);
      }
    }
  }

  // NOTE: Due to rounding error/limited precision, reducing the exponent of an EncodedNumber affects its precision.
  //       Once decoded, it's possible that the value of the EncodedNumber is slightly changed (e.g., from 3.14 to
  //       3.1399999999999999023003738329862243016303180218865632677037090457780224)
  @Test
  public void testEncodedDecreaseExponentTo0() throws Exception {
    EncodedNumber number1 = defaultSignedContext.encode(3.14);
    assert -30 < number1.getExponent();
    EncodedNumber number2 = number1.decreaseExponentTo(-30);

    if(number1.getExponent() < -30){
      fail("-30 < number1.getExponent()");
    }
    assertEquals(-30, number2.getExponent());
    double decodedNumber = number2.decodeDouble();
    assertEquals(3.14, decodedNumber, EPSILON);
  }

  @Test
  public void testEncodedDecreaseExponentTo1() throws Exception {
    EncodedNumber number1 = defaultSignedContext.encode(-3.14);
    assert -30 < number1.getExponent();
    EncodedNumber number2 = number1.decreaseExponentTo(-30);

    if(number1.getExponent() < -30){
      fail("-30 < number1.getExponent()");
    }
    assertEquals(-30, number2.getExponent());
    double decodedNumber = number2.decodeDouble();
    assertEquals(-3.14, decodedNumber, EPSILON);
  }

  @Test
  public void testEncodedDecreaseInvalidExponent() throws Exception {
    EncodedNumber enc1 = defaultSignedContext.encode(3.14);
    assert enc1.getExponent() < -10;

    try {
      enc1.decreaseExponentTo(-10);
    } catch (IllegalArgumentException e) {
    }
  }

  @Test
  public void testManualPrecisionPositiveDouble() throws Exception {
    double originalNumber = 3.171234e-7;
    double precision = 1e-8;

    EncodedNumber number = defaultSignedContext.encode(originalNumber, precision);
    double decodedNumber = number.decodeDouble();
    if(decodedNumber < originalNumber - precision || decodedNumber > originalNumber + precision) {
      fail("decodedNumber: " + decodedNumber + " is not in the correct range.");
    }

    EncodedNumber number2 = defaultSignedContext.encode(decodedNumber + 0.500001 * precision, precision);
    double decodedNumber2 = number2.decodeDouble();
    if(decodedNumber == decodedNumber2)
      fail("decodedNumber: " + decodedNumber + " should not be the same as decodedNumber2: " + decodedNumber2);

    if(decodedNumber2 < originalNumber - precision / 2 || decodedNumber2 > originalNumber + precision * 1.5001)
      fail("decodedNumber2: " + decodedNumber2 + "is not in the correct range.");

    double value = decodedNumber + precision / 16;
    EncodedNumber number3 = defaultSignedContext.encode(value, precision);
    double decodedNumber3 = number3.decodeDouble();
    assertEquals(decodedNumber, decodedNumber3, EPSILON);
  }

  @Test
  public void testManualPrecisionNegativeDouble() throws Exception {
    double originalNumber = -3.171234e-7;
    double precision = 1e-8;

    EncodedNumber number = defaultSignedContext.encode(originalNumber, precision);
    double decodedNumber = number.decodeDouble();
    if(decodedNumber < originalNumber - precision || decodedNumber > originalNumber + precision) {
      fail("decodedNumber: " + decodedNumber + " is not in the correct range.");
    }

    EncodedNumber number2 = defaultSignedContext.encode(decodedNumber + 0.500001 * precision, precision);
    double decodedNumber2 = number2.decodeDouble();
    if(decodedNumber == decodedNumber2)
      fail("decodedNumber: " + decodedNumber + " should not be the same as decodedNumber2: " + decodedNumber2);

    if(decodedNumber2 < originalNumber - precision / 2 || decodedNumber2 > originalNumber + precision * 1.5001)
      fail("decodedNumber2: " + decodedNumber2 + "is not in the correct range.");

    double value = decodedNumber + precision / 16;
    EncodedNumber number3 = defaultSignedContext.encode(value, precision);
    double decodedNumber3 = number3.decodeDouble();
    assertEquals(decodedNumber, decodedNumber3, EPSILON);
  }

  @Test
  public void testInvalidNumber() throws Exception {
    try {
      defaultSignedContext.encode(Double.NaN);
      fail("Successfully encode a NaN");
    } catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(Double.POSITIVE_INFINITY);
      fail("Successfully encode positive infinity");
    } catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(Double.NEGATIVE_INFINITY);
      fail("Successfully encode negative infinity");
    } catch (EncodeException e) {
    }

    try {
      defaultUnsignedContext.encode(-1.0);
      fail("Successfully encode a negative number using an unsigned Paillier context");
    } catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(Double.NaN, 1);
      fail("Successfully encode a NaN with a specific exponent");
    } catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(Double.POSITIVE_INFINITY, 1);
      fail("Successfully encode positive infinity with a specific exponent");
    } catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(Double.NEGATIVE_INFINITY, 1);
      fail("Successfully encode negative infinity with a specific exponent");
    } catch (EncodeException e) {
    }

    try {
      defaultUnsignedContext.encode(-1.0, 1);
      fail("Successfully encode a negative number with a specific exponent using an unsigned Paillier context");
    } catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(Double.NaN, 1e-3);
      fail("Successfully encode a NaN with a specific precision");
    } catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(Double.POSITIVE_INFINITY, 1e-3);
      fail("Successfully encode positive infinity with a specific precision");
    } catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(Double.NEGATIVE_INFINITY, 1e-3);
      fail("Successfully encode negative infinity with a specific precision");
    }catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(-1.0, -1e-3);
      fail("Successfully encode a number with invalid precision");
    }catch (EncodeException e) {
    }

    try {
      defaultSignedContext.encode(-1.0, 1e3);
      fail("Successfully encode a number with invalid precision");
    }catch (EncodeException e) {
    }

    try {
      defaultUnsignedContext.encode(-1.0, 1e-3);
      fail("Successfully encode a negative number using an unsigned Paillier context");
    }catch (EncodeException e) {
    }
  }
}

