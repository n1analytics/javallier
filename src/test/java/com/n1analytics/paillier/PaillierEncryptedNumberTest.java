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

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.math.BigInteger;
import java.util.Random;

import static com.n1analytics.paillier.TestConfiguration.*;
import static com.n1analytics.paillier.TestUtil.randomFiniteDouble;
import static com.n1analytics.paillier.util.BigIntegerUtil.LONG_MAX_VALUE;
import static com.n1analytics.paillier.util.BigIntegerUtil.LONG_MIN_VALUE;
import static org.junit.Assert.*;

public class PaillierEncryptedNumberTest {

  // Epsilon value for comparing floating point numbers
  private static final double EPSILON = 1e-5;

  static final Random random = new Random();

  static private PaillierPublicKey publicKey;
  static private PaillierPrivateKey privateKey;
  static private PaillierContext context;

  static private PaillierPublicKey partialPublicKey;
  static private PaillierPrivateKey partialPrivateKey;
  static private PaillierContext partialContext;

  static private PaillierPublicKey otherPublicKey;
  static private PaillierPrivateKey otherPrivateKey;
  static private PaillierContext otherContext;

  static private BigInteger plaintextList[];
  static private EncryptedNumber encryptionList[];

  @Rule
  public ExpectedException exception = ExpectedException.none();

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        ;
      }
    }

    context = SIGNED_FULL_PRECISION_1024.context();
    privateKey = SIGNED_FULL_PRECISION_1024.privateKey();
    publicKey = SIGNED_FULL_PRECISION_1024.publicKey();

    partialContext = SIGNED_PARTIAL_PRECISION_1024.context();
    partialPrivateKey = SIGNED_PARTIAL_PRECISION_1024.privateKey();
    partialPublicKey = SIGNED_PARTIAL_PRECISION_1024.publicKey();

    otherPrivateKey = PaillierPrivateKey.create(1024);
    otherPublicKey = otherPrivateKey.getPublicKey();
    otherContext = createSignedFullPrecision(otherPrivateKey).context();

    plaintextList = new BigInteger[]{new BigInteger("123456789"), new BigInteger(
            "314159265359"), new BigInteger("271828182846"), new BigInteger(
            "-987654321"), new BigInteger("-161803398874"), new BigInteger(
            "1414213562373095")};

    encryptionList = new EncryptedNumber[plaintextList.length];

    for (int i = 0; i < plaintextList.length; i++) {
      encryptionList[i] = context.encrypt(plaintextList[i]);
    }
  }

  @Test
  public void testConstructor() throws Exception {
    EncryptedNumber encryptedNumber = null;

    try {
      encryptedNumber = new EncryptedNumber(null, BigInteger.ONE, 0);
      fail("Successfully created an encrypted number with null context");
    } catch (IllegalArgumentException e) {
    }
    assertNull(encryptedNumber);

    try {
      encryptedNumber = new EncryptedNumber(context, null, 0);
      fail("Successfully created an encrypted number with null ciphertext");
    } catch (IllegalArgumentException e) {
    }
    assertNull(encryptedNumber);

    try {
      encryptedNumber = new EncryptedNumber(context, BigInteger.ONE.negate(), 0);
      fail("Successfully created an encrypted number with negative ciphertext");
    } catch (IllegalArgumentException e) {
    }
    assertNull(encryptedNumber);

    try {
      encryptedNumber = new EncryptedNumber(context,
                                            context.getPublicKey().getModulusSquared().add(
                                                    BigInteger.ONE), 0);
      fail("Successfully created an encrypted number with ciphertext greater than modulus squared");
    } catch (IllegalArgumentException e) {
    }
    assertNull(encryptedNumber);
  }

  @Test
  public void testCantEncryptDecryptIntWithDifferentKey() throws Exception {
    long data = 1564;
    EncryptedNumber ciphertext = context.encrypt(data);

    exception.expect(PaillierKeyMismatchException.class);
    otherPrivateKey.decrypt(ciphertext).decodeLong();
  }

  @Test
  public void testCantEncryptDecryptIntWithDifferentSizeKey() throws Exception {
    PaillierPrivateKey aPrivateKey = PaillierPrivateKey.create(128);
    PaillierPublicKey aPublicKey = aPrivateKey.getPublicKey();
    PaillierContext aContext = aPublicKey.createSignedContext();

    long data = 1564;
    EncryptedNumber ciphertext = aContext.encrypt(data);

    exception.expect(PaillierKeyMismatchException.class);
    privateKey.decrypt(ciphertext).decodeLong();
  }

  @Test
  public void testCantAddWithDifferentKey() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-15);
    EncryptedNumber ciphertext2 = otherContext.encrypt(1);

    exception.expect(PaillierContextMismatchException.class);
    EncryptedNumber result = ciphertext1.add(ciphertext2);
  }

  @Test
  public void testCantAddEncodedWithDifferentKey() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-15);
    EncodedNumber ciphertext2 = new EncodedNumber(otherContext, BigInteger.ONE,
                                                  ciphertext1.getExponent());

    exception.expect(PaillierContextMismatchException.class);
    EncryptedNumber result = ciphertext1.add(ciphertext2);
  }

  @Test
  public void testEncryptIntPositiveOverflowAdd() throws Exception {
    EncryptedNumber ciphertext1 = partialContext.encrypt(
            partialContext.getMaxSignificand());
    EncryptedNumber ciphertext2 = partialContext.encrypt(BigInteger.ONE);

    EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

    exception.expect(DecodeException.class);
    BigInteger result = partialPrivateKey.decrypt(ciphertext3).decodeBigInteger();
  }

  @Test
  public void testEncryptIntNegativeOverflowAdd() throws Exception {
    EncryptedNumber ciphertext1 = partialContext.encrypt(
            partialContext.getMinSignificand());
    EncryptedNumber ciphertext2 = partialContext.encrypt(BigInteger.ONE.negate());

    EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

    exception.expect(DecodeException.class);
    BigInteger result = partialPrivateKey.decrypt(ciphertext3).decodeBigInteger();
  }

  @Test
  public void testAutomaticPrecision0() throws Exception {
    double eps = Math.ulp(1.0d);
    double onePlusEps = 1.0d + eps;
    assert onePlusEps > 1;

    EncryptedNumber ciphertext1 = context.encrypt(onePlusEps);
    double decryption1 = privateKey.decrypt(ciphertext1).decodeDouble();
    assertEquals(String.valueOf(onePlusEps), String.valueOf(decryption1));

    EncryptedNumber ciphertext2 = ciphertext1.add(eps);
    double decryption2 = privateKey.decrypt(ciphertext2).decodeDouble();
    assertEquals(String.valueOf(onePlusEps + eps), String.valueOf(decryption2));

    EncryptedNumber ciphertext3 = ciphertext1.add(eps / 5.0d);
    double decryption3 = privateKey.decrypt(ciphertext3).decodeDouble();
    assertEquals(String.valueOf(onePlusEps), String.valueOf(decryption3));

    EncryptedNumber ciphertext4 = ciphertext3.add(eps * 4.0d / 5.0d);
    double decryption4 = privateKey.decrypt(ciphertext4).decodeDouble();
    assertNotEquals(onePlusEps, decryption4, 0.0d);
    assertEquals(String.valueOf(onePlusEps + eps), String.valueOf(decryption4));
  }

  @Test
  public void testMulZero() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(3.);
    EncryptedNumber ciphertext2 = ciphertext1.multiply(0);

    assertEquals(0.0, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testMulZeroRight() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(3.);
    EncryptedNumber ciphertext2 = context.encode(0).multiply(ciphertext1);
    assertEquals(0.0, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  public void testEncryptDecryptLong(TestConfiguration conf, long value) {
    PaillierContext thisContext = conf.context();
    PaillierPrivateKey thisPrivateKey = conf.privateKey();

    try {
      EncryptedNumber ciphertext = thisContext.encrypt(value);
      if (value < 0 && conf.unsigned()) {
        fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
      }
      assertEquals(value, ciphertext.decrypt(thisPrivateKey).decodeLong());
    } catch (EncodeException e) {

    }
  }

  @Test
  public void testLongConstants() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        testEncryptDecryptLong(conf, Long.MAX_VALUE);
        testEncryptDecryptLong(conf, Long.MIN_VALUE);
      }
    }
  }

  @Test
  public void testLongRandom() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        for (int i = 0; i < 100; ++i) {
          testEncryptDecryptLong(conf, random.nextLong());
        }
      }
    }
  }

  public void testEncryptDecryptDouble(TestConfiguration conf, double value) {
    PaillierContext thisContext = conf.context();
    PaillierPrivateKey thisPrivateKey = conf.privateKey();

    try {
      EncryptedNumber ciphertext = thisContext.encrypt(value);
      if (value < 0 && conf.unsigned()) {
        fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
      }

      double tolerance;
      double result = ciphertext.decrypt(thisPrivateKey).decodeDouble();
      if (Math.getExponent(result) > 0) {
        tolerance = EPSILON * Math.pow(2.0, Math.getExponent(result));
      } else {
        tolerance = EPSILON;
      }

      assertEquals(value, result, tolerance);
    } catch (EncodeException e) {
    }
  }

  @Test
  public void testDoubleConstants() throws Exception {
    TestConfiguration conf = CONFIGURATION_DOUBLE;
    testEncryptDecryptDouble(conf, Double.MAX_VALUE);
    testEncryptDecryptDouble(conf,
                             Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
    testEncryptDecryptDouble(conf, 1.0);
    testEncryptDecryptDouble(conf,
                             Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
    testEncryptDecryptDouble(conf, Double.MIN_NORMAL);
    testEncryptDecryptDouble(conf,
                             Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
    testEncryptDecryptDouble(conf, Double.MIN_VALUE);
    testEncryptDecryptDouble(conf, 0.0);
    testEncryptDecryptDouble(conf, -0.0);
    testEncryptDecryptDouble(conf, -Double.MIN_VALUE);
    testEncryptDecryptDouble(conf, -Math.nextAfter(Double.MIN_NORMAL,
                                                   Double.NEGATIVE_INFINITY));
    testEncryptDecryptDouble(conf, -Double.MIN_NORMAL);
    testEncryptDecryptDouble(conf, -Math.nextAfter(Double.MIN_NORMAL,
                                                   Double.POSITIVE_INFINITY));
    testEncryptDecryptDouble(conf, -1.0);
    testEncryptDecryptDouble(conf,
                             -Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
    testEncryptDecryptDouble(conf, -Double.MAX_VALUE);
  }

  @Test
  public void testDoubleRandom() throws Exception {
    TestConfiguration conf = CONFIGURATION_DOUBLE;
    for (int i = 0; i < 100; ++i) {
      testEncryptDecryptDouble(conf, randomFiniteDouble());
    }
  }

  public BigInteger generateRandomBigInteger(Random random, int bitLength) {
    BigInteger value = new BigInteger(bitLength, random);

    int i = random.nextInt(2);
    if (i % 2 == 0) {
      return value;
    } else {
      return value.negate();
    }
  }

  public void testEncryptDecryptBigInteger(TestConfiguration conf, BigInteger value) {
    PaillierContext thisContext = conf.context();
    PaillierPrivateKey thisPrivateKey = conf.privateKey();

    try {
      EncryptedNumber ciphertext = thisContext.encrypt(value);
      if (value.compareTo(BigInteger.ZERO) < 0 && conf.unsigned()) {
        fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
      }
      assertEquals(value,
                   ciphertext.decrypt(thisPrivateKey).decodeBigInteger());
    } catch (EncodeException e) {

    }
  }

  @Test
  public void testBigIntegerConstants() throws Exception {
    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        testEncryptDecryptBigInteger(conf, conf.context().getMinSignificand());
        testEncryptDecryptBigInteger(conf, LONG_MIN_VALUE);
        testEncryptDecryptBigInteger(conf, LONG_MIN_VALUE.add(BigInteger.ONE));
        testEncryptDecryptBigInteger(conf, BigInteger.TEN.negate());
        testEncryptDecryptBigInteger(conf, BigInteger.ONE.negate());
        testEncryptDecryptBigInteger(conf, BigInteger.ZERO);
        testEncryptDecryptBigInteger(conf, BigInteger.ONE);
        testEncryptDecryptBigInteger(conf, BigInteger.ZERO);
        testEncryptDecryptBigInteger(conf, LONG_MAX_VALUE.subtract(BigInteger.ONE));
        testEncryptDecryptBigInteger(conf, LONG_MAX_VALUE);
        testEncryptDecryptBigInteger(conf, conf.context().getMaxSignificand());
      }
    }
  }

  @Test
  public void testBigIntegerRandom() throws Exception {
    int[] bitLengths = {16, 32, 64, 128, 256};

    for (TestConfiguration[] confs : CONFIGURATIONS) {
      for (TestConfiguration conf : confs) {
        for (int i = 0; i < bitLengths.length; ++i) {
          for (int j = 0; j < 20; ++j) {
            testEncryptDecryptBigInteger(conf,
                                         generateRandomBigInteger(random, bitLengths[i]));
          }
        }
      }
    }
  }

  @Test
  public void testMultipleAddWithEncryptDecryptInt0() throws Exception {
    EncryptedNumber ciphertext = (encryptionList[0].add(encryptionList[1])).add(
            encryptionList[2]);
    BigInteger decryption = privateKey.decrypt(ciphertext).decodeBigInteger();

    BigInteger expectedResult = (plaintextList[0].add(plaintextList[1])).add(
            plaintextList[2]);
    assertEquals(expectedResult, decryption);
  }

  @Test
  public void testMultipleAddWithEncryptDecryptInt1() throws Exception {
    EncryptedNumber ciphertext = (encryptionList[3].add(encryptionList[4])).add(
            encryptionList[5]);
    BigInteger decryption = privateKey.decrypt(ciphertext).decodeBigInteger();

    BigInteger expectedResult = (plaintextList[3].add(plaintextList[4])).add(
            plaintextList[5]);
    assertEquals(expectedResult, decryption);
  }

  @Test
  public void testMultipleAddWithEncryptDecryptInt2() throws Exception {
    EncryptedNumber ciphertext1 = (encryptionList[0].add(encryptionList[1])).add(
            encryptionList[2]);
    EncryptedNumber ciphertext2 = encryptionList[3].add(encryptionList[4]);
    EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
    BigInteger decryption = privateKey.decrypt(ciphertext3).decodeBigInteger();

    BigInteger expectedResult1 = (plaintextList[0].add(plaintextList[1])).add(
            plaintextList[2]);
    BigInteger expectedResult2 = plaintextList[3].add(plaintextList[4]);
    BigInteger expectedResult3 = expectedResult1.add(expectedResult2);

    assertEquals(expectedResult3, decryption);
  }

  @Test
  public void testMultipleAddWithEncryptDecryptInt3() throws Exception {
    EncryptedNumber ciphertext1 = (encryptionList[0].add(encryptionList[1])).add(
            encryptionList[2]);
    EncryptedNumber ciphertext2 = (encryptionList[3].add(encryptionList[4])).add(
            encryptionList[5]);
    EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
    BigInteger decryption = privateKey.decrypt(ciphertext3).decodeBigInteger();

    BigInteger expectedResult1 = (plaintextList[0].add(plaintextList[1])).add(
            plaintextList[2]);
    BigInteger expectedResult2 = (plaintextList[3].add(plaintextList[4])).add(
            plaintextList[5]);
    BigInteger expectedResult3 = expectedResult1.add(expectedResult2);

    assertEquals(expectedResult3, decryption);
  }

  @Test
  public void testMultipleAddWithEncryptDecryptIntLimits() throws Exception {
    BigInteger sum3Pos2Neg1 = (plaintextList[0].add(plaintextList[1])).add(
            plaintextList[2]);
    BigInteger sum3Pos2Neg2 = plaintextList[3].add(plaintextList[4]);
    BigInteger sum3Pos2Neg3 = sum3Pos2Neg1.add(sum3Pos2Neg2);

    BigInteger sum3Pos3Neg1 = (plaintextList[0].add(plaintextList[1])).add(
            plaintextList[2]);
    BigInteger sum3Pos3Neg2 = (plaintextList[3].add(plaintextList[4])).add(
            plaintextList[5]);
    BigInteger sum3Pos3Neg3 = sum3Pos3Neg1.add(sum3Pos3Neg2);

    EncryptedNumber ciphertextSum3Pos2Neg1 = (encryptionList[0].add(
            encryptionList[1])).add(encryptionList[2]);
    EncryptedNumber ciphertextSum3Pos2Neg2 = encryptionList[3].add(encryptionList[4]);
    EncryptedNumber ciphertextSum3Pos2Neg3 = ciphertextSum3Pos2Neg1.add(
            ciphertextSum3Pos2Neg2);


    EncryptedNumber ciphertextSum3Pos3Neg1 = (encryptionList[0].add(
            encryptionList[1])).add(encryptionList[2]);
    EncryptedNumber ciphertextSum3Pos3Neg2 = (encryptionList[3].add(
            encryptionList[4])).add(encryptionList[5]);
    EncryptedNumber ciphertextSum3Pos3Neg3 = ciphertextSum3Pos3Neg1.add(
            ciphertextSum3Pos3Neg2);

//        Add many positive and negative numbers to reach maxInt.
    EncryptedNumber ciphertext1 = context.encrypt(
            context.getMaxSignificand().subtract(sum3Pos2Neg3));
    EncryptedNumber ciphertext2 = ciphertextSum3Pos2Neg3.add(ciphertext1);
    BigInteger decryption = privateKey.decrypt(ciphertext2).decodeBigInteger();
    assertEquals(context.getMaxSignificand(), decryption);

//        Add many positive and negative numbers to reach -maxInt.
    EncryptedNumber ciphertext3 = context.encrypt(
            (context.getMinSignificand()).add(sum3Pos3Neg3));
    EncryptedNumber ciphertext4 = ciphertext3.subtract(ciphertextSum3Pos3Neg3);
    BigInteger decryption2 = privateKey.decrypt(
            ciphertext4).decodeBigInteger();
    assertEquals(context.getMinSignificand(), decryption2);
  }

  @Test
  public void testAddWithEncryptedIntAndEncodedNumberDiffExp0() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(15);
    EncodedNumber encoded2 = context.encode(Number.encode(1, 50));
    assert encoded2.getExponent() > 200;
    assert ciphertext1.getExponent() > 200;

    EncodedNumber encoded3 = context.encode(Number.encode(1, 200));
    EncryptedNumber ciphertext3 = ciphertext1.add(encoded3);
    double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
    assertEquals(16, (long) decryption);
  }

  @Test
  public void testAddWithEncryptedIntAndEncodedNumberDiffExp1() throws Exception {
    EncodedNumber encoded1 = context.encode(Number.encode(1, 10));
    EncryptedNumber ciphertext1 = context.encrypt(Number.encode(15, 100));
    assert encoded1.getExponent() == 10;
    assert ciphertext1.getExponent() == 100;

    EncryptedNumber ciphertext2 = ciphertext1.add(encoded1);
    assertEquals(16, privateKey.decrypt(ciphertext2).decodeLong());
  }

  @Test
  public void testAddWithDifferentPrecisionFloat4() throws Exception {
    Number number1 = Number.encode(0.1, 1e-3);
    Number number2 = Number.encode(0.2, 1e-20);

    EncryptedNumber ciphertext1 = context.encrypt(number1);
    EncryptedNumber ciphertext2 = context.encrypt(number2);

    assertNotEquals(ciphertext1.getExponent(), ciphertext2.getExponent());
    int oldExponent = ciphertext1.getExponent();

    EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
    assertEquals(ciphertext2.getExponent(), ciphertext3.getExponent());
    assertEquals(oldExponent, ciphertext1.getExponent());

    double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
    assertEquals(0.3, decryption, 1e-3);
  }

  @Test
  public void testSubWithDifferentPrecisionFloat0() throws Exception {
    Number number1 = Number.encode(0.1, 1e-3);
    Number number2 = Number.encode(0.2, 1e-20);

    EncryptedNumber ciphertext1 = context.encrypt(number1);
    EncryptedNumber ciphertext2 = context.encrypt(number2);

    assertNotEquals(ciphertext1.getExponent(), ciphertext2.getExponent());

    EncryptedNumber ciphertext3 = ciphertext1.subtract(ciphertext2);
    assertEquals(ciphertext2.getExponent(), ciphertext3.getExponent());

    double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
    assertEquals(-0.1, decryption, 1e-3);
  }

  @Test
  public void testCiphertextObfuscation1() throws Exception {
    EncryptedNumber encryptedNumber = context.encrypt(10.0);

    BigInteger unsafeCiphertext = encryptedNumber.ciphertext;
    BigInteger safeCiphertext = encryptedNumber.calculateCiphertext();

    assertNotNull(safeCiphertext);
    assertNotEquals(unsafeCiphertext, safeCiphertext);
  }

  @Test
  public void testCiphertextObfuscation2() throws Exception {
    EncryptedNumber encryptedNumber = context.encrypt(10.0);

    EncryptedNumber obfuscatedEncryptedNumber = encryptedNumber.obfuscate();

    assertNotNull(obfuscatedEncryptedNumber);
    assertNotEquals(encryptedNumber, obfuscatedEncryptedNumber);
  }

  @Test
  public void testCheckSameContextEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(1.0);
    EncryptedNumber ciphertext2 = context.encrypt(2.0);
    EncryptedNumber ciphertext3 = otherContext.encrypt(2.0);

    EncryptedNumber check = ciphertext1.checkSameContext(ciphertext2);

    try {
      check = ciphertext1.checkSameContext(ciphertext3);
      fail("ciphertext1 and ciphertext3 have different context");
    } catch (PaillierContextMismatchException e) {
    }
  }

  @Test
  public void testCheckSameContextEncodedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(1.0);
    EncodedNumber encodedNumber2 = context.encode(2.0);
    EncodedNumber encodedNumber3 = otherContext.encode(2.0);

    EncodedNumber check = ciphertext1.checkSameContext(encodedNumber2);

    try {
      check = ciphertext1.checkSameContext(encodedNumber3);
      fail("encodedNumber1 and encodedNumber3 have different context");
    } catch (PaillierContextMismatchException e) {
    }
  }

  @Test
  public void testAddLongToEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.add(4);
    assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testAddDoubleToEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.add(4.0);
    assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testAddBigIntegerToEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.add(new BigInteger("4"));
    assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testSubtractLongFromEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.subtract(-4);
    assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testSubtractDoubleFromEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.subtract(-4.0);
    assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testSubtractBigIntegerFromEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.subtract(new BigInteger("-4"));
    assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testMultiplyLongByEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.multiply(4);
    assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testMultiplyDoubleByEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.multiply(4.0);
    assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testMultiplyBigIntegerByEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.multiply(new BigInteger("4"));
    assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testDivideLongByEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.divide(4);
    assertEquals(-0.495, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }

  @Test
  public void testDivideDoubleByEncryptedNumber() throws Exception {
    EncryptedNumber ciphertext1 = context.encrypt(-1.98);
    EncryptedNumber ciphertext2 = ciphertext1.divide(4.0);
    assertEquals(-0.495, privateKey.decrypt(ciphertext2).decodeDouble(), 0.0);
  }
}