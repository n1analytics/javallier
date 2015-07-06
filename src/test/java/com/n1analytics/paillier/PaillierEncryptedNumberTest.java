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

/**
 * Test cases for the EncryptedNumber class.
 */
public class PaillierEncryptedNumberTest {
	// Epsilon value for comparing floating point numbers
	private static final double EPSILON = 1e-3;
	
//    final static Logger logger = LoggerFactory.getLogger(PaillierEncryptedNumberTest.class);
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
        for(TestConfiguration[] confs: CONFIGURATIONS)
            for(TestConfiguration conf: confs)
                ;

        context = SIGNED_FULL_PRECISION_1024.context();
        privateKey = SIGNED_FULL_PRECISION_1024.privateKey();
        publicKey = SIGNED_FULL_PRECISION_1024.publicKey();

        partialContext = SIGNED_PARTIAL_PRECISION_1024.context();
        partialPrivateKey = SIGNED_PARTIAL_PRECISION_1024.privateKey();
        partialPublicKey = SIGNED_PARTIAL_PRECISION_1024.publicKey();

        otherPrivateKey = PaillierPrivateKey.create(1024);
        otherPublicKey = otherPrivateKey.getPublicKey();
        otherContext = createSignedFullPrecision(otherPrivateKey).context();

        plaintextList = new BigInteger[]{new BigInteger("123456789"), new BigInteger("314159265359"),
                new BigInteger("271828182846"), new BigInteger("-987654321"),
                new BigInteger("-161803398874"), new BigInteger("1414213562373095")};

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
                    context.getPublicKey().getModulusSquared().add(BigInteger.ONE), 0);
            fail("Successfully created an encrypted number with ciphertext greater than modulus squared");
        } catch (IllegalArgumentException e) {
        }
        assertNull(encryptedNumber);
    }

    @Test
    public void testCantEncryptDecryptIntWithDifferentKey() throws Exception {
//        logger.debug("Running phe test: Attempted to decrypt with a different key.");

        long data = 1564;
        EncryptedNumber ciphertext = context.encrypt(data);

        exception.expect(PaillierKeyMismatchException.class);
        otherPrivateKey.decrypt(ciphertext).decodeApproximateLong();
    }

    @Test
    public void testCantEncryptDecryptIntWithDifferentSizeKey() throws Exception {
//        logger.debug("Running phe test: Attempted to decrypt with a different key with different size.");

        PaillierPrivateKey aPrivateKey = PaillierPrivateKey.create(128);
        PaillierPublicKey aPublicKey = aPrivateKey.getPublicKey();
        PaillierContext aContext = aPublicKey.createSignedContext();

        long data = 1564;
        EncryptedNumber ciphertext = aContext.encrypt(data);

        exception.expect(PaillierKeyMismatchException.class);
        privateKey.decrypt(ciphertext).decodeApproximateLong();
    }

    @Test
    public void testCantAddWithDifferentKey() throws Exception {
//        logger.debug("Running phe test: Attempted to add two ciphertext encrypted with different keys.");

        EncryptedNumber ciphertext1 = context.encrypt(-15);
        EncryptedNumber ciphertext2 = otherContext.encrypt(1);

        exception.expect(PaillierContextMismatchException.class);
        EncryptedNumber result = ciphertext1.add(ciphertext2);
    }

    @Test
    public void testCantAddEncodedWithDifferentKey() throws Exception {
//        logger.debug("Running phe test: Attempted to add two ciphertext encoded with different keys.");

        EncryptedNumber ciphertext1 = context.encrypt(-15);
        EncodedNumber ciphertext2 = new EncodedNumber(otherContext, BigInteger.ONE, ciphertext1.getExponent());

        exception.expect(PaillierContextMismatchException.class);
        EncryptedNumber result = ciphertext1.add(ciphertext2);
    }

    @Test
    public void testEncryptIntPositiveOverflowAdd() throws Exception {
//        logger.debug("Running phe test: Receive positive overflow as a result of adding.");

        EncryptedNumber ciphertext1 = partialContext.encrypt(partialContext.getMaxBigInteger(0));
        EncryptedNumber ciphertext2 = partialContext.encrypt(BigInteger.ONE);

        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

        exception.expect(DecodeException.class);
        BigInteger result = partialPrivateKey.decrypt(ciphertext3).decodeBigInteger();
    }

    @Test
    public void testEncryptIntNegativeOverflowAdd() throws Exception {
//        logger.debug("Running phe test: Receive negative overflow as a result of adding.");

        EncryptedNumber ciphertext1 = partialContext.encrypt(partialContext.getMaxBigInteger(0).negate());
        EncryptedNumber ciphertext2 = partialContext.encrypt(BigInteger.ONE.negate());

        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);

        exception.expect(DecodeException.class);
        BigInteger result = partialPrivateKey.decrypt(ciphertext3).decodeBigInteger();
    }

    @Test
    public void testAutomaticPrecision0() throws Exception {
//        logger.debug("Running phe test: Test automatic precision.");

        double eps = Math.ulp(1.0d);
        double onePlusEps = 1.0d + eps;
        assert onePlusEps > 1;

        EncryptedNumber ciphertext1 = context.encrypt(onePlusEps);
        double decryption1 = privateKey.decrypt(ciphertext1).decodeApproximateDouble();
        assertEquals(String.valueOf(onePlusEps), String.valueOf(decryption1));

        EncryptedNumber ciphertext2 = ciphertext1.add(eps);
        double decryption2 = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
        assertEquals(String.valueOf(onePlusEps + eps), String.valueOf(decryption2));

        EncryptedNumber ciphertext3 = ciphertext1.add(eps / 5.0d);
        double decryption3 = privateKey.decrypt(ciphertext3).decodeApproximateDouble();
        assertEquals(String.valueOf(onePlusEps), String.valueOf(decryption3));

        EncryptedNumber ciphertext4 = ciphertext3.add(eps * 4.0d / 5.0d);
        double decryption4 = privateKey.decrypt(ciphertext4).decodeApproximateDouble();
        assertNotEquals(onePlusEps, decryption4, 0.0d);
        assertEquals(String.valueOf(onePlusEps + eps), String.valueOf(decryption4));
    }

    @Test
    public void testMulZero() throws Exception {
//        logger.debug("Running phe test: Check that multiplying by zero does something sensible.");

        EncryptedNumber ciphertext1 = context.encrypt(3.);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(0);

        assertEquals(0.0, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testMulZeroRight() throws Exception {
//        logger.debug("Running phe test: Check that multiplying by zero does something sensible.");

        EncryptedNumber ciphertext1 = context.encrypt(3.);
        EncryptedNumber ciphertext2 = context.encode(0).multiply(ciphertext1);
        assertEquals(0.0, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

// NOTE: Write fuzz tests to encrypt/decrypt random long, double and BigInteger
    public void testEncryptDecryptLong(TestConfiguration conf, long value) {
        PaillierContext thisContext = conf.context();
        PaillierPrivateKey thisPrivateKey = conf.privateKey();

        try {
            EncryptedNumber ciphertext = thisContext.encrypt(value);
            if(value < 0 && conf.unsigned())
                fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
            assertEquals(value, ciphertext.decrypt(thisPrivateKey).decodeApproximateLong());
        } catch (EncodeException e) {

        }
    }

    @Test
    public void testLongConstants() throws Exception {
        for(TestConfiguration[] confs: CONFIGURATIONS) {
            for(TestConfiguration conf: confs) {
                testEncryptDecryptLong(conf, Long.MAX_VALUE);
                testEncryptDecryptLong(conf, Long.MIN_VALUE);
            }
        }
    }

    @Test
    public void testLongRandom() throws Exception {
        for(TestConfiguration[] confs: CONFIGURATIONS) {
            for(TestConfiguration conf: confs) {
                for(int i = 0; i < 100; ++i)
                    testEncryptDecryptLong(conf, random.nextLong());
            }
        }
    }

    public void testEncryptDecryptDouble(TestConfiguration conf, double value) {
        PaillierContext thisContext = conf.context();
        PaillierPrivateKey thisPrivateKey = conf.privateKey();

        try {
            EncryptedNumber ciphertext = thisContext.encrypt(value);
            if(value < 0 && conf.unsigned())
                fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
            assertEquals(value, ciphertext.decrypt(thisPrivateKey).decodeApproximateDouble(), 0.0);
        } catch (EncodeException e) {

        }
    }

    @Test
    public void testDoubleConstants() throws Exception {
        TestConfiguration conf = CONFIGURATION_DOUBLE;
        testEncryptDecryptDouble(conf, Double.MAX_VALUE);
        testEncryptDecryptDouble(conf, Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
        testEncryptDecryptDouble(conf, 1.0);
        testEncryptDecryptDouble(conf, Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
        testEncryptDecryptDouble(conf, Double.MIN_NORMAL);
        testEncryptDecryptDouble(conf, Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
        testEncryptDecryptDouble(conf, Double.MIN_VALUE);
        testEncryptDecryptDouble(conf, 0.0);
        testEncryptDecryptDouble(conf, -0.0);
        testEncryptDecryptDouble(conf, -Double.MIN_VALUE);
        testEncryptDecryptDouble(conf, -Math.nextAfter(Double.MIN_NORMAL, Double.NEGATIVE_INFINITY));
        testEncryptDecryptDouble(conf, -Double.MIN_NORMAL);
        testEncryptDecryptDouble(conf, -Math.nextAfter(Double.MIN_NORMAL, Double.POSITIVE_INFINITY));
        testEncryptDecryptDouble(conf, -1.0);
        testEncryptDecryptDouble(conf, -Math.nextAfter(Double.MAX_VALUE, Double.NEGATIVE_INFINITY));
        testEncryptDecryptDouble(conf, -Double.MAX_VALUE);
    }

    @Test
    public void testDoubleRandom() throws Exception {
        TestConfiguration conf = CONFIGURATION_DOUBLE;
        for(int i = 0; i < 100; ++i)
            testEncryptDecryptDouble(conf, randomFiniteDouble());
    }

    public BigInteger generateRandomBigInteger(Random random, int bitLength) {
        BigInteger value = new BigInteger(bitLength, random);

        int i = random.nextInt(2);
        if(i % 2 == 0) {
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
            if(value.compareTo(BigInteger.ZERO) < 0 && conf.unsigned())
                fail("ERROR: Successfully encrypted negative integer with unsigned encoding");
            assertEquals(value, ciphertext.decrypt(thisPrivateKey).decodeApproximateBigInteger());
        } catch (EncodeException e) {

        }
    }

    @Test
    public void testBigIntegerConstants() throws Exception {
        for(TestConfiguration[] confs: CONFIGURATIONS) {
            for(TestConfiguration conf: confs) {
                testEncryptDecryptBigInteger(conf, conf.context().getMinBigInteger(0));
                testEncryptDecryptBigInteger(conf, LONG_MIN_VALUE);
                testEncryptDecryptBigInteger(conf, LONG_MIN_VALUE.add(BigInteger.ONE));
                testEncryptDecryptBigInteger(conf, BigInteger.TEN.negate());
                testEncryptDecryptBigInteger(conf, BigInteger.ONE.negate());
                testEncryptDecryptBigInteger(conf, BigInteger.ZERO);
                testEncryptDecryptBigInteger(conf, BigInteger.ONE);
                testEncryptDecryptBigInteger(conf, BigInteger.ZERO);
                testEncryptDecryptBigInteger(conf, LONG_MAX_VALUE.subtract(BigInteger.ONE));
                testEncryptDecryptBigInteger(conf, LONG_MAX_VALUE);
                testEncryptDecryptBigInteger(conf, conf.context().getMaxBigInteger(0));
            }
        }
    }

    @Test
    public void testBigIntegerRandom() throws Exception {
        int[] bitLengths = {16, 32, 64, 128, 256};

        for(TestConfiguration[] confs: CONFIGURATIONS) {
            for (TestConfiguration conf : confs) {
                for(int i = 0; i < bitLengths.length; ++i) {
                    for(int j = 0; j < 20; ++j) {
                        testEncryptDecryptBigInteger(conf, generateRandomBigInteger(random, bitLengths[i]));
                    }
                }
            }
        }
    }

    @Test
    public void testMultipleAddWithEncryptDecryptInt0() throws Exception {
//        logger.debug("Running phe test: add many positive numbers.");

        EncryptedNumber ciphertext = (encryptionList[0].add(encryptionList[1])).add(encryptionList[2]);
        BigInteger decryption = privateKey.decrypt(ciphertext).decodeApproximateBigInteger();

        BigInteger expectedResult = (plaintextList[0].add(plaintextList[1])).add(plaintextList[2]);
        assertEquals(expectedResult, decryption);
    }

    @Test
    public void testMultipleAddWithEncryptDecryptInt1() throws Exception {
//        logger.debug("Running phe test: add many negative numbers.");

        EncryptedNumber ciphertext = (encryptionList[3].add(encryptionList[4])).add(encryptionList[5]);
        BigInteger decryption = privateKey.decrypt(ciphertext).decodeApproximateBigInteger();

        BigInteger expectedResult = (plaintextList[3].add(plaintextList[4])).add(plaintextList[5]);
        assertEquals(expectedResult, decryption);
    }

    @Test
    public void testMultipleAddWithEncryptDecryptInt2() throws Exception {
//        logger.debug("Running phe test: Add many positive and negative numbers with aggregate being positive.");

        EncryptedNumber ciphertext1 = (encryptionList[0].add(encryptionList[1])).add(encryptionList[2]);
        EncryptedNumber ciphertext2 = encryptionList[3].add(encryptionList[4]);
        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
        BigInteger decryption = privateKey.decrypt(ciphertext3).decodeApproximateBigInteger();

        BigInteger expectedResult1 = (plaintextList[0].add(plaintextList[1])).add(plaintextList[2]);
        BigInteger expectedResult2 = plaintextList[3].add(plaintextList[4]);
        BigInteger expectedResult3 = expectedResult1.add(expectedResult2);

        assertEquals(expectedResult3, decryption);
    }

    @Test
    public void testMultipleAddWithEncryptDecryptInt3() throws Exception {
//        logger.debug("Running phe test: Add many positive and negative numbers with aggregate being positive.");

        EncryptedNumber ciphertext1 = (encryptionList[0].add(encryptionList[1])).add(encryptionList[2]);
        EncryptedNumber ciphertext2 = (encryptionList[3].add(encryptionList[4])).add(encryptionList[5]);
        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
        BigInteger decryption = privateKey.decrypt(ciphertext3).decodeApproximateBigInteger();

        BigInteger expectedResult1 = (plaintextList[0].add(plaintextList[1])).add(plaintextList[2]);
        BigInteger expectedResult2 = (plaintextList[3].add(plaintextList[4])).add(plaintextList[5]);
        BigInteger expectedResult3 = expectedResult1.add(expectedResult2);

        assertEquals(expectedResult3, decryption);
    }

    // NOTE: Modified the following test so that the test passes.
    // In the original version, the -maxInt test didn't work because |-maxInt - sum3pos3neg3| > maxInt, which
    // trigger an exception in EncodedNumber.
    // To get around it without getting rid of the exception in EncodedNumber, I modified the -maxInt test, to:
    //      ciphertext3 = encrypt(-maxInt + sum3pos3neg3);
    //      ciphertext4 = ciphertext3 - ciphertextSum3Pos3Neg3;
    // . This gives us -maxInt, without triggering th exception.
    @Test
    public void testMultipleAddWithEncryptDecryptIntLimits() throws Exception {
//        logger.debug("Running phe test: Add many positive and negative numbers that reach maxInt.");

        BigInteger sum3Pos2Neg1 = (plaintextList[0].add(plaintextList[1])).add(plaintextList[2]);
        BigInteger sum3Pos2Neg2 = plaintextList[3].add(plaintextList[4]);
        BigInteger sum3Pos2Neg3 = sum3Pos2Neg1.add(sum3Pos2Neg2);

        BigInteger sum3Pos3Neg1 = (plaintextList[0].add(plaintextList[1])).add(plaintextList[2]);
        BigInteger sum3Pos3Neg2 = (plaintextList[3].add(plaintextList[4])).add(plaintextList[5]);
        BigInteger sum3Pos3Neg3 = sum3Pos3Neg1.add(sum3Pos3Neg2);

        EncryptedNumber ciphertextSum3Pos2Neg1 = (encryptionList[0].add(encryptionList[1])).add(encryptionList[2]);
        EncryptedNumber ciphertextSum3Pos2Neg2 = encryptionList[3].add(encryptionList[4]);
        EncryptedNumber ciphertextSum3Pos2Neg3 = ciphertextSum3Pos2Neg1.add(ciphertextSum3Pos2Neg2);


        EncryptedNumber ciphertextSum3Pos3Neg1 = (encryptionList[0].add(encryptionList[1])).add(encryptionList[2]);
        EncryptedNumber ciphertextSum3Pos3Neg2 = (encryptionList[3].add(encryptionList[4])).add(encryptionList[5]);
        EncryptedNumber ciphertextSum3Pos3Neg3 = ciphertextSum3Pos3Neg1.add(ciphertextSum3Pos3Neg2);

//        Add many positive and negative numbers to reach maxInt.
        EncryptedNumber ciphertext1 = context.encrypt(context.getMaxBigInteger(0).subtract(sum3Pos2Neg3));
        EncryptedNumber ciphertext2 = ciphertextSum3Pos2Neg3.add(ciphertext1);
        BigInteger decryption = privateKey.decrypt(ciphertext2).decodeApproximateBigInteger();
        assertEquals(context.getMaxBigInteger(0), decryption);

//        Add many positive and negative numbers to reach -maxInt.
        EncryptedNumber ciphertext3 = context.encrypt((context.getMaxBigInteger(0).negate()).add(sum3Pos3Neg3));
        EncryptedNumber ciphertext4 = ciphertext3.subtract(ciphertextSum3Pos3Neg3);
        BigInteger decryption2 = privateKey.decrypt(ciphertext4).decodeApproximateBigInteger();
        assertEquals(context.getMaxBigInteger(0).negate(), decryption2);
    }

    @Test
    public void testAddWithEncryptedIntAndEncodedNumberDiffExp0() throws Exception {
//        logger.debug("Running phe test: Add encoded 1 to a small positive number with different exponent.");

        EncryptedNumber ciphertext1 = context.encrypt(15);
        EncodedNumber encoded2 = context.encode(Number.encodeToExponent(1, -50));
        assert encoded2.getExponent() > -200;
        assert ciphertext1.getExponent() > -200;

        EncodedNumber encoded3 = context.encode(Number.encodeToExponent(1, -200));
        EncryptedNumber ciphertext3 = ciphertext1.add(encoded3);
        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(16, (long) decryption);
    }

// NOTE: The following test is updated as above
//    @Test
//    public void testAddWithEncryptedIntAndEncodedNumberDiffExp0() throws Exception {
//        logger.debug("Running phe test: Add encoded 1 to a small positive number with different exponent.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(15);
//        EncodedNumber encoded2 = context.encode(publicKey, 1, -50);
//        assert encoded2.getExponent() > -200;
//        assert ciphertext1.getExponent() > -200;
//
//        EncodedNumber encoded3 = encoded2.decreaseExponentTo(-200);
//        EncryptedNumber ciphertext3 = ciphertext1.add(encoded3);
//        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
//        assertEquals(16, (long) decryption);
//    }

    @Test
    public void testAddWithEncryptedIntAndEncodedNumberDiffExp1() throws Exception {
        EncodedNumber encoded1 = context.encode(Number.encodeToExponent(1, -10));
        EncryptedNumber ciphertext1 = context.encrypt(Number.encodeToExponent(15, -100));
        assert encoded1.getExponent() == -10;
        assert ciphertext1.getExponent() == -100;

        EncryptedNumber ciphertext2 = ciphertext1.add(encoded1);
        assertEquals(16, privateKey.decrypt(ciphertext2).decodeLong());
    }

// NOTE: The following test is updated as above
//    @Test
//    public void testAddWithEncryptedIntAndEncodedNumberDiffExp1() throws Exception {
//        logger.debug("Running phe test: Try with the EncryptedNumber having the smaller exponent.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(15);
//        EncryptedNumber ciphertext2 = ciphertext1.decreaseExponentTo(-10);
//        EncodedNumber encoded1 = EncodedNumber.encode(publicKey, 1);
//        EncodedNumber encoded2 = encoded1.decreaseExponentTo(-10);
//        EncryptedNumber ciphertext = ciphertext1.decreaseExponentTo(-200);
//        assert encoded2.getExponent() == -10;
//        assert ciphertext.getExponent() == -200;
//        ciphertext2 = ciphertext.add(encoded2);
//
//        assertEquals(16, (long) privateKey.decrypt(ciphertext2).decodeDouble());
//        // The following doesn't work because BigDecimal.longValue() discard the fraction.
//        // assertEquals(16, privateKey.decryptBigDecimal(ciphertext2).longValue());
//        // The following doesn't work because the ciphertext is too big, decryptLong interprets it as 0
//        // assertEquals(16, privateKey.decryptLong(ciphertext2));
//        // The following doesn't work because the exponent is negative (BigInteger cannot compute negative exponent).
//        // assertEquals(16, privateKey.decryptBigInteger(ciphertext2));
//    }

    @Test
    public void testAddWithDifferentPrecisionFloat4() throws Exception {
//        logger.debug("Running phe test: Add two floats with different precisions.");

        Number number1 = Number.encodeToPrecision(0.1, 10);
        Number number2 = Number.encodeToPrecision(0.2, 1000);

        EncryptedNumber ciphertext1 = context.encrypt(number1);
        EncryptedNumber ciphertext2 = context.encrypt(number2);

        assertNotEquals(ciphertext1.getExponent(), ciphertext2.getExponent());
        int oldExponent = ciphertext1.getExponent();

        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
        assertEquals(ciphertext2.getExponent(), ciphertext3.getExponent());
        assertEquals(oldExponent, ciphertext1.getExponent());

        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(0.3, decryption, EPSILON);

    }

    @Test
    public void testSubWithDifferentPrecisionFloat0() throws Exception {
//        logger.debug("Running phe test: Subtract two floats with different precisions.");

        Number number1 = Number.encodeToPrecision(0.1, 10);
        Number number2 = Number.encodeToPrecision(0.2, 1000);

        EncryptedNumber ciphertext1 = context.encrypt(number1);
        EncryptedNumber ciphertext2 = context.encrypt(number2);

        assertNotEquals(ciphertext1.getExponent(), ciphertext2.getExponent());

        EncryptedNumber ciphertext3 = ciphertext1.subtract(ciphertext2);
        assertEquals(ciphertext2.getExponent(), ciphertext3.getExponent());

        double decryption = privateKey.decrypt(ciphertext3).decodeDouble();
        assertEquals(-0.1, decryption, EPSILON);
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
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testAddDoubleToEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.add(4.0);
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testAddBigIntegerToEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.add(new BigInteger("4"));
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testSubtractLongFromEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.subtract(-4);
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testSubtractDoubleFromEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.subtract(-4.0);
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testSubtractBigIntegerFromEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.subtract(new BigInteger("-4"));
        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testMultiplyLongByEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(4);
        assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testMultiplyDoubleByEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(4.0);
        assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testMultiplyBigIntegerByEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.multiply(new BigInteger("4"));
        assertEquals(-7.92, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testDivideLongByEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.divide(4);
        assertEquals(-0.495, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

    @Test
    public void testDivideDoubleByEncryptedNumber() throws Exception {
        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
        EncryptedNumber ciphertext2 = ciphertext1.divide(4.0);
        assertEquals(-0.495, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
    }

//    @Test
//    public void testAddScalarWithEncryptDecryptFloat0() throws Exception {
////        logger.debug("Running phe test: Add a positive integer to an encrypted negative double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
//        EncryptedNumber ciphertext2 = ciphertext1.add(4);
//
//        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
//    }
//
//    @Test
//    public void testAddScalarWithEncryptDecryptFloat0Right() throws Exception {
////        logger.debug("Running phe test: Add a negative integer (encrypted) to an encoded positive integer.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
//        EncodedNumber encoded1 = context.encode(4);
//        EncryptedNumber ciphertext2 = encoded1.add(ciphertext1);
//
//        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
//    }
//
//    @Test
//    public void testAddScalarWithEncryptDecryptFloat3() throws Exception {
////        logger.debug("Running phe test: Add a negative integer to a positive double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(3.9);
//        EncryptedNumber ciphertext2 = ciphertext1.add(-40);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(-36.1, decryption, EPSILON);
//    }
//
//    @Test
//    public void testSubScalarWithEncryptDecryptFloat0() throws Exception {
////        logger.debug("Running phe test: Add a negative integer from a negative double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
//        EncryptedNumber ciphertext2 = ciphertext1.subtract(-4);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(2.02, decryption, 0.0);
//    }
//
//    @Test
//    public void testSubScalarWithEncryptDecryptFloat3() throws Exception {
////        logger.debug("Running phe test: Subtract a positive integer from a positive double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(3.9);
//        EncryptedNumber ciphertext2 = ciphertext1.subtract(40);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(-36.1, decryption, EPSILON);
//    }

//    @Test
//    public void testEncryptIntDecryptInt0() throws Exception {
////        logger.debug("Running phe test: Encrypt/decrypt a small positive number.");
//
//        EncryptedNumber ciphertext = context.encrypt(15);
//        long decryption = privateKey.decrypt(ciphertext).decodeApproximateLong();
//        assertEquals(15, decryption);
//    }
//
//    @Test
//    public void testEncryptIntDecryptInt1() throws Exception {
////        logger.debug("Running phe test: Encrypt/decrypt a small negative number.");
//
//        EncryptedNumber ciphertext = context.encrypt(-15);
//        long decryption = privateKey.decrypt(ciphertext).decodeApproximateLong();
//        assertEquals(-15, decryption);
//    }
//
//    @Test
//    public void testEncryptIntDecryptInt4() throws Exception {
////        logger.debug("Running phe test: Encrypt/decrypt the largest positive number.");
//
//        EncryptedNumber ciphertext = context.encrypt(context.getMaxBigInteger(0));
//        BigInteger decryption = privateKey.decrypt(ciphertext).decodeApproximateBigInteger();
//        assertEquals(context.getMaxBigInteger(0).toString(), decryption.toString());
//
//    }
//
//    @Test
//    public void testEncryptIntDecryptInt5() throws Exception {
////        logger.debug("Running phe test: Encrypt/decrypt the largest negative number.");
//
//        EncryptedNumber ciphertext = context.encrypt(context.getMaxBigInteger(0).negate());
//        BigInteger decryption = privateKey.decrypt(ciphertext).decodeApproximateBigInteger();
//        assertEquals(context.getMaxBigInteger(0).negate().toString(), decryption.toString());
//    }
//
//    @Test
//    public void testEncryptFloatDecryptFloat4() throws Exception {
////        logger.debug("Running phe test: A small positive float.");
//
//        EncryptedNumber ciphertext = context.encrypt(0.005743);
//        double decryption = privateKey.decrypt(ciphertext).decodeApproximateDouble();
//
//        assertEquals("0.005743", String.valueOf(decryption));
//    }
//
//    @Test
//    public void testEncryptFloatDecryptFloat5() throws Exception {
////        logger.debug("Running phe test: A small negative float.");
//
//        EncryptedNumber  ciphertext = context.encrypt(-0.05743);
//        double decryption = privateKey.decrypt(ciphertext).decodeApproximateDouble();
//
//        assertEquals("-0.05743", String.valueOf(decryption));
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddWithEncryptDecryptInt0() throws Exception {
////        logger.debug("Running phe test: Add 1 to a small negative number.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-15);
//        EncryptedNumber ciphertext2 = context.encrypt(1);
//
//        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
//
//        long additionResult = privateKey.decrypt(ciphertext3).decodeApproximateLong();
//
//        assertEquals(-14, additionResult);
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddWithEncryptDecryptInt1() throws Exception {
////        logger.debug("Running phe test: Add 1 to a small negative number.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(15);
//        EncryptedNumber ciphertext2 = context.encrypt(1);
//
//        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
//
//        long additionResult = privateKey.decrypt(ciphertext3).decodeApproximateLong();
//
//        assertEquals(16, additionResult);
//    }

// NOTE: See SubtractionTest
//    @Test
//    public void testAddWithEncryptDecryptInt2() throws Exception {
////        logger.debug("Running phe test: Add -1 to a small negative number.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-15);
//        EncryptedNumber ciphertext2 = context.encrypt(-1);
//
//        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
//
//        long additionResult = privateKey.decrypt(ciphertext3).decodeApproximateLong();
//
//        assertEquals(-16, additionResult);
//    }

// NOTE: See SubtractionTest
//    @Test
//    public void testSubWithEncryptDecryptInt0() throws Exception {
////        logger.debug("Running phe test: Subtract two encrypted numbers.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(15);
//        EncryptedNumber ciphertext2 = context.encrypt(1);
//
//        EncryptedNumber ciphertext3 = ciphertext1.subtract(ciphertext2);
//
//        long decryption = privateKey.decrypt(ciphertext3).decodeApproximateLong();
//
//        assertEquals(14, decryption);
//    }

// NOTE: See SubtractionTest
//    @Test
//    public void testSubScalarWithEncryptDecryptInt0() throws Exception {
////        logger.debug("Running phe test: Subtract a scalar from an encrypted number.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(15);
//        EncryptedNumber ciphertext2 = ciphertext1.subtract(2);
//
//        long decryption = privateKey.decrypt(ciphertext2).decodeApproximateLong();
//
//        assertEquals(13, decryption);
//    }

// NOTE: See SubtractionTest
//    @Test
//    public void testSubScalarWithEncryptDecryptInt0Right() throws Exception {
////        logger.debug("Running phe test: Subtract an encrypted number from an encoded scalar.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(15);
//        EncryptedNumber ciphertext2 = (context.encode(20)).subtract(ciphertext1);
//
//        long decryption = privateKey.decrypt(ciphertext2).decodeApproximateLong();
//
//        assertEquals(5, decryption);
//
//    }

//    @Test
//    public void testUndetectableAddOverflow() throws Exception {
//        logger.debug("Running phe test: Prove the ring does wrap.");
//
//        EncryptedNumber cipherSum = context.encrypt(0);
//        EncryptedNumber ciphertext = context.encrypt(context.getMaxSignificand());
//
//        EncodedNumber tempEnc = null;
//        BigInteger tempResult = null;
//
//        BigInteger inBetweenRange = context.getMinEncoded().subtract(context.getMaxEncoded());
//        BigInteger iteration = inBetweenRange.divide(inBetweenRange);
//
//        System.out.println("Iteration " + iteration.intValue() +". Inbetween range: " + inBetweenRange.toString());
//
//        for(int i = 0; i < (iteration.intValue() + 2); i++) {
//            cipherSum = cipherSum.add(ciphertext);
//
//            tempEnc = cipherSum.decrypt(privateKey);
//            try {
//                tempResult = tempEnc.decodeBigInteger();
//            } catch(DecodeException e) {
//                System.out.println("Summation result is in the inbetween area");
//            }
//        }
//
//        if(tempResult != null)
//            assertEquals(-1, tempResult.signum());
//
////        EncryptedNumber ciphertext1 = context.encrypt(0);
////        EncryptedNumber ciphertext2 = context.encrypt(context.getMaxBigInteger(0));
////        EncryptedNumber ciphertext3 = context.encrypt(context.getMaxBigInteger(0));
////        EncryptedNumber ciphertext4 = context.encrypt(context.getMaxBigInteger(0));
////        EncryptedNumber cipherSum = ((ciphertext1.add(ciphertext2).add(ciphertext3)).add(ciphertext4));
////
////        BigInteger plainSum = privateKey.decrypt(cipherSum).decodeBigInteger();
////
////        //Original comments: plain_sum = 3 * max_int = 3 * ((n//3) - 1)
////        //                   due to residues of the // function,
////        //                   -5 < plain_sum < -3 (modulo n)
////        assert plainSum.compareTo(new BigInteger("-5")) >= 0;
////        assert plainSum.compareTo(new BigInteger("-3")) <= 0;
//    }

// NOTE: Does not implement testCantAddWithDifferentKeys() as the publicKey variable is private and
// the setter method for it is undefined.

// NOTE: See AdditionTest
//    @Test
//    public void testAddWithEncryptedIntAndEncodedNumber() throws Exception {
////        logger.debug("Running phe test: Add encoded 1 to a small positive number.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(15);
//        EncodedNumber encoded2 = context.encode(1);
//        EncryptedNumber ciphertext3 = ciphertext1.add(encoded2);
//        long decryption = privateKey.decrypt(ciphertext3).decodeApproximateLong();
//        assertEquals(16, decryption);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulWithEncryptedIntAndEncodedNumber() throws Exception {
////        logger.debug("Running phe test: Multiply two negative integers.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-3);
//        EncodedNumber encoded2 = context.encode(-25);
//        EncryptedNumber ciphertext3 = ciphertext1.multiply(encoded2);
//        long decryption = privateKey.decrypt(ciphertext3).decodeApproximateLong();
//
//        assertEquals(75, decryption);
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddWithEncryptDecryptFloat0() throws Exception {
////        logger.debug("Running phe test:  Add 1 to a small negative double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-15.);
//        EncryptedNumber ciphertext2 = context.encrypt(1.0);
//        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
//
//        double decryption = privateKey.decrypt(ciphertext3).decodeApproximateDouble();
//        assertEquals("-14.0", String.valueOf(decryption));
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddWithEncryptDecryptFloat0Right() throws Exception {
////        logger.debug("Running phe test:  Add 1 to a small negative double (reverse order).");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-15.);
//        EncryptedNumber ciphertext2 = context.encrypt(1.0);
//        EncryptedNumber ciphertext3 = ciphertext2.add(ciphertext1);
//
//        double decryption = privateKey.decrypt(ciphertext3).decodeApproximateDouble();
//        assertEquals("-14.0", String.valueOf(decryption));
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddWithEncryptDecryptFloat1() throws Exception {
////        logger.debug("Running phe test:  Add 1 to a small positive double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(15.);
//        EncryptedNumber ciphertext2 = context.encrypt(1.0);
//        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
//
//        double decryption = privateKey.decrypt(ciphertext3).decodeApproximateDouble();
//        assertEquals("16.0", String.valueOf(decryption));
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddWithEncryptDecryptFloat2() throws Exception {
////        logger.debug("Running phe test:  Add -1 to a small negative double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-15.);
//        EncryptedNumber ciphertext2 = context.encrypt(-1.0);
//        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
//
//        double decryption = privateKey.decrypt(ciphertext3).decodeApproximateDouble();
//        assertEquals("-16.0", String.valueOf(decryption));
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddWithEncryptDecryptFloat3() throws Exception {
////        logger.debug("Running phe test: Add two floats with the same precision.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(1.3842);
//        EncryptedNumber ciphertext2 = context.encrypt(-0.4);
//        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
//
//        double decryption = privateKey.decrypt(ciphertext3).decodeApproximateDouble();
//        assertEquals(0.9842, decryption, 0.01);
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddScalarWithEncryptDecryptFloat1() throws Exception {
////        logger.debug("Running phe test: Add two positive doubles.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(1.98);
//        EncryptedNumber ciphertext2 = ciphertext1.add(4.3);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(6.28, decryption, EPSILON);
//
//    }

// NOTE: See AdditionTest
//    @Test
//    public void testAddScalarWithEncryptDecryptFloat2() throws Exception {
////        logger.debug("Running phe test: Add a negative float to a positive double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(240.9);
//        EncryptedNumber ciphertext2 = ciphertext1.add(-40.8);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(200.1, decryption, 0.0);
//    }

// NOTE: See SubtractionTest
//    @Test
//    public void testSubScalarWithEncryptDecryptFloat0Right() throws Exception {
////        logger.debug("Running phe test: Subtract a positive double (encrypted) from a positive double (encoded).");
//
//        EncryptedNumber ciphertext1 = context.encrypt(1.98);
//        EncryptedNumber ciphertext2 = context.encode(4).subtract(ciphertext1);
//
//        assertEquals(2.02, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
//    }

// NOTE: See SubtractionTest
//    @Test
//    public void testSubScalarWithEncryptDecryptFloat1() throws Exception {
////        logger.debug("Running phe test: Subtract a negative double from a positive double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(1.98);
//        EncryptedNumber ciphertext2 = ciphertext1.subtract(-4.3);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(6.28, decryption, EPSILON);
//    }

// NOTE: See SubtractionTest
//    @Test
//    public void testSubScalarWithEncryptDecryptFloat1Right() throws Exception {
////        logger.debug("Running phe test: Subtract a negative double (encrypted) from a positive double (encoded).");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-1.98);
//        EncryptedNumber ciphertext2 = context.encode(4.3).subtract(ciphertext1);
//
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(6.28, decryption, EPSILON);
//    }

// NOTE: See SubtractionTest
//    @Test
//    public void testSubScalarWithEncryptDecryptFloat2() throws Exception {
////        logger.debug("Running phe test: Subtract a positive double from a positive double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(240.9);
//        EncryptedNumber ciphertext2 = ciphertext1.subtract(40.8);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(200.1, decryption, 0.0);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulWithEncryptDecryptFloat0() throws Exception {
////        logger.debug("Running phe test: Multiply a negative double by 1.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-1.3);
//        EncryptedNumber ciphertext2 = ciphertext1.multiply(1.0);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(-1.3, decryption, 0.0);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulWithEncryptDecryptFloat1() throws Exception {
////        logger.debug("Running phe test: Multiply a positive double by 2.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(2.3);
//        EncryptedNumber ciphertext2 = ciphertext1.multiply(2.0);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(4.6, decryption, 0.0);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulWithEncryptDecryptFloat2() throws Exception {
////        logger.debug("Running phe test: Multiply a negative double by a positive double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-0.1);
//        EncryptedNumber ciphertext2 = ciphertext1.multiply(31.4);
//
//        assertEquals(-3.14, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 1e-10);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulWithEncryptDecryptFloat4() throws Exception {
////        logger.debug("Running phe test: Multiply a negative double by a negative double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-1.3);
//        EncryptedNumber ciphertext2 = ciphertext1.multiply(-1.0);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(1.3, decryption, 0.0);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulWithEncryptDecryptFloat5() throws Exception {
////        logger.debug("Running phe test: Multiply a negative double by a -2.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(2.3);
//        EncryptedNumber ciphertext2 = ciphertext1.multiply(-2.0);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(-4.6, decryption, 0.0);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulWithEncryptDecryptFloat6() throws Exception {
////        logger.debug("Running phe test: Multiply a negative double by a negative double.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-0.1);
//        EncryptedNumber ciphertext2 = ciphertext1.multiply(-31.4);
//        double decryption = privateKey.decrypt(ciphertext2).decodeApproximateDouble();
//
//        assertEquals(3.14, decryption, 1e-10);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulRight() throws Exception {
////        logger.debug("Running phe test: Check that it doesn't matter which side the real float is on.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(0.1);
//        EncryptedNumber ciphertext2 = ciphertext1.multiply(31.4);
//        EncryptedNumber ciphertext3 = (context.encode(31.4)).multiply(ciphertext1);
//
//        assertEquals(privateKey.decrypt(ciphertext3).decodeApproximateDouble(), privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
//        assertEquals(3.14, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 1e-10);
//    }

// NOTE: At the moment this test is irrelevant
//    @Test
//    public void testMultiplicativeInverse() {
//    	EncodedNumber TWO = context.encode(2);
//    	EncodedNumber HALF = context.encode(0.5);
//    	EncodedNumber TWO_INVERSE = context.multiplicativeInverse(TWO);
//    	assertEquals(HALF, TWO_INVERSE);
//    }

// NOTE: See DivisionTest
//    @Test
//    public void testDiv() throws Exception {
////        logger.debug("Running phe test: Check division works as well as multiplication does.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(6.28);
//        EncryptedNumber ciphertext2 = ciphertext1.divide(2);
//        assertEquals(3.14, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 0.0);
//
//        EncryptedNumber ciphertext3 = ciphertext1.divide(3.14);
//        assertEquals(2., privateKey.decrypt(ciphertext3).decodeApproximateDouble(), EPSILON);
//    }

// NOTE: See MultiplicationTest
//    @Test
//    public void testMulWithEncryptedFloatAndEncodedNumber() throws Exception {
////        logger.debug("Running phe test: Multiply two doubles with different precisions.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(-0.1);
//        EncodedNumber encoded1 = context.encode(-31.4);
//        EncryptedNumber ciphertext2 = ciphertext1.multiply(encoded1);
//
//        assertEquals(3.14, privateKey.decrypt(ciphertext2).decodeApproximateDouble(), 1e-10);
//    }

// NOTE: These tests are not valid as the obfuscation are done automatically
//    @Test
//    public void testObfuscate() throws Exception {
//        logger.debug("Running phe test: Test isObfuscate states.");
//
//        EncryptedNumber ciphertext = context.encrypt(3.14);
//        assertEquals(ciphertext.getIsObfuscated(), true);
//        BigInteger c1 = ciphertext.getCiphertext(false);
//        ciphertext.obfuscate();
//        assertEquals(ciphertext.getIsObfuscated(), true);
//        BigInteger c2 = ciphertext.getCiphertext(false);
//        assertNotEquals(c1.toString(), c2.toString());
//        BigInteger c3 = ciphertext.getCiphertext(true);
//        assertEquals(c2, c3);
//    }
//
//    @Test
//    public void testNotObfuscated() throws Exception {
//        logger.debug("Running phe test: Test isObfuscate states - take 2.");
//
//        EncryptedNumber ciphertext = context.encrypt(3.14, new BigInteger("103"));
//        assertEquals(ciphertext.getIsObfuscated(), false);
//        BigInteger c1 = ciphertext.getCiphertext(false);
//        assertEquals(ciphertext.getIsObfuscated(), false);
//        BigInteger c2 = ciphertext.getCiphertext(true);
//        assertEquals(ciphertext.getIsObfuscated(), true);
//        BigInteger c3 = ciphertext.getCiphertext(false);
//        assertEquals(ciphertext.getIsObfuscated(), true);
//        BigInteger c4 = ciphertext.getCiphertext(true);
//        assertEquals(ciphertext.getIsObfuscated(), true);
//
//        assertNotEquals(c1, c2);
//        assertEquals(c2, c3);
//        assertEquals(c3, c4);
//        // Note: decodeDouble() returns 3.13999, which is very close to 3.14.
//        double dec = privateKey.decrypt(ciphertext).decodeDouble();
//        assertEquals(3.14, dec, 0.001);
//    }
//
//    @Test
//    public void testAddObfuscated() throws Exception {
//        logger.debug("Running phe test: Add and obfuscate numbers.");
//
//        EncryptedNumber ciphertext1 = context.encrypt(94.5);
//        EncryptedNumber ciphertext2 = context.encrypt(107.3);
//        assertEquals(ciphertext1.getIsObfuscated(), true);
//        assertEquals(ciphertext2.getIsObfuscated(), true);
//        EncryptedNumber ciphertext3 = ciphertext1.add(ciphertext2);
//        assertEquals(ciphertext3.getIsObfuscated(), false);
//        ciphertext3.getCiphertext();
//        assertEquals(ciphertext3.getIsObfuscated(), true);
//    }

// NOTE: See SubtractTest
//    @Test
//    public void testSubtractEncodedNumber() throws Exception {
////        logger.debug("Running test: subtract an encoded number from an encrypted number.");
//
//        EncryptedNumber num = context.encrypt(10);
//        EncodedNumber enc = context.encode(5);
//
//        EncryptedNumber encryptedResult = num.subtract(enc);
//
//        long result = privateKey.decrypt(encryptedResult).decodeApproximateLong();
//
//        assertEquals(5, result);
//    }

// NOTE: See SubtractTest
//    @Test
//    public void testSubtractBigInteger() throws Exception {
////        logger.debug("Running test: subtract a scalar of type BigInteger from an encrypted number.");
//
//        EncryptedNumber num = context.encrypt(10);
//
//        EncryptedNumber encryptedResult = num.subtract(new BigInteger("5"));
//
//        long result = privateKey.decrypt(encryptedResult).decodeApproximateLong();
//
//        assertEquals(5, result);
//    }

// NOTE: test is irrelevant (we don't have decreaseToExponent method anymore)
//    @Test
//    public void testDecreaseExponentTo() throws Exception {
//        logger.debug("Running phe test:  Decrease an exponent to -30 without affecting the plaintext number");
//
//        EncryptedNumber ciphertext1 = context.encrypt(1.01, Math.pow(1.0, -8));
//        assert -30 < ciphertext1.getExponent();
//        EncryptedNumber ciphertext2 = ciphertext1.decreaseExponentTo(-30);
//
//        assert -30 < ciphertext1.getExponent();
//        assertEquals(-30, ciphertext2.getExponent());
//        assertEquals(1.01, privateKey.decrypt(ciphertext2).decodeDouble(), Math.pow(1.0, -8));
//    }

// NOTE: test is irrelevant (we don't have decreaseToExponent method anymore)
//    @Test
//    public void testDecreaseInvalidExponent() throws Exception {
//        logger.debug("Running phe test:  Decrease to invalid exponent.");
//
//        EncryptedNumber ciphertext = context.encrypt(1.01, 1e-8);
//        assert ciphertext.getExponent() < 20;
//
//        exception.expect(IllegalArgumentException.class);
//        ciphertext.decreaseExponentTo(20);
//    }


//    @Test
//    public void testDataTypesEncryptDecrypt() throws Exception {
//        logger.debug("Running test: various encryption options for different data types.");
//
//        BigInteger randomNumber = new BigInteger("7");
//        double numDouble = 5.0;
//        long numLong = 5;
//        BigInteger numBigInt = new BigInteger("5");
//
//        EncryptedNumber cipherDouble1 = context.encrypt(numDouble, -2, randomNumber);
//        EncryptedNumber cipherDouble2 = context.encrypt(numDouble, -2);
//        EncryptedNumber cipherDouble3 = context.encrypt(numDouble, randomNumber);
//
//        double decryptDouble1 = privateKey.decrypt(cipherDouble1).decodeDouble();
//        double decryptDouble2 = privateKey.decrypt(cipherDouble2).decodeDouble();
//        double decryptDouble3 = privateKey.decrypt(cipherDouble3).decodeDouble();
//
//        // Check if all the decrypted ciphertext are equal to the original plaintext
//        assertEquals(numDouble, decryptDouble1, 0);
//        assertEquals(decryptDouble1, decryptDouble2, 0);
//        assertEquals(decryptDouble2, decryptDouble3, 0);
//
//        EncryptedNumber cipherLong1 = context.encrypt(numLong, -2, randomNumber);
//        EncryptedNumber cipherLong2 = context.encrypt(numLong, -2);
//        EncryptedNumber cipherLong3 = context.encrypt(numLong, randomNumber);
//
//        long decryptLong1 = privateKey.decrypt(cipherLong1).decodeLong();
//        long decryptLong2 = privateKey.decrypt(cipherLong2).decodeLong();
//        long decryptLong3 = privateKey.decrypt(cipherLong3).decodeLong();
//
//        // Check if all the decrypted ciphertext are equal to the original plaintext
//        assertEquals(numLong, decryptLong1);
//        assertEquals(decryptLong1, decryptLong2);
//        assertEquals(decryptLong2, decryptLong3);
//
//        EncryptedNumber cipherBigInt1 = context.encrypt(numBigInt, -2, randomNumber);
//        EncryptedNumber cipherBigInt2 = context.encrypt(numBigInt, -2);
//        EncryptedNumber cipherBigInt3 = context.encrypt(numBigInt, randomNumber);
//
//        BigInteger decryptBigInt1 = privateKey.decrypt(cipherBigInt1).decodeBigInteger();
//        BigInteger decryptBigInt2 = privateKey.decrypt(cipherBigInt2).decodeBigInteger();
//        BigInteger decryptBigInt3 = privateKey.decrypt(cipherBigInt3).decodeBigInteger();
//
//        // Check if all the decrypted ciphertext are equal to the original plaintext
//        assertEquals(numBigInt.toString(), decryptBigInt1.toString());
//        assertEquals(decryptBigInt1.toString(), decryptBigInt2.toString());
//        assertEquals(decryptBigInt2.toString(), decryptBigInt3.toString());
//    }
}