package com.n1analytics.paillier;

import org.junit.experimental.categories.Category;

/**
 * Timing tests for key generation, encryption/decryption and arithmetic operations.
 */
@Category(SlowTests.class)
public class PaillierTimingTest {
//    final static Logger logger = LoggerFactory.getLogger(PaillierTimingTest.class);
//
//    private static PaillierPublicKey publicKey;
//    private static PaillierPrivateKey privateKey;
//    private static PaillierContext context;
//
//    private static int SHORT_ITERATION = 5;
//    private static int MEDIUM_ITERATION = 20;
//    private static int LONG_ITERATION = 100;
//    private static int VERY_LONG_ITERATION = 1000;
//
//    private static int[] keySizes = {8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
//
//    private Random randomGenerator = new Random();
//
//    @Rule
//    public ExpectedException exception = ExpectedException.none();
//
//    @BeforeClass
//    public static void setUpBeforeClass() throws Exception {
//        privateKey = PaillierPrivateKey.create(1024);
//        publicKey = privateKey.getPublicKey();
//        context = publicKey.createSignedIntegerContext();
//    }
//
//    /**
//     * Tests whether the implementation can generate Paillier keypairs with different key sizes.
//     *
//     * Highest key size that can be generated is 4096
//     */
//    @Test
//    public void testDifferentLengthKeypairTime() throws Exception {
//        logger.info("Running timing test: Generate keypairs with different length.");
//
//        long startTime, elapsedTime, cumulativeTime;
//        PaillierPrivateKey thisPrivateKey = null;
//
//        for(int i = 0; i < keySizes.length; i++){
//            cumulativeTime = 0;
//            for(int j = 0; j <SHORT_ITERATION; j++){
//                startTime = System.nanoTime();
//                thisPrivateKey = PaillierPrivateKey.create(keySizes[i]);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//
//                logger.info("Test {} / iteration {} - {} bits of keypair takes {} s.", (i+1), (j+1), keySizes[i], elapsedTime/Math.pow(10, 9));
//            }
//            logger.info("Total time for {} iterations to generate {} bits of keypair: {} s.", SHORT_ITERATION, keySizes[i], cumulativeTime/Math.pow(10, 9));
//            logger.info("\tAverage time to generate {} bits of keypair: {} s.", keySizes[i], (cumulativeTime/Math.pow(10, 9))/SHORT_ITERATION);
//        }
//    }
//
//    @Test
//    public void testEncryptDecryptLongTime() throws Exception {
//        logger.info("Running timing test: Encrypt/decrypt plaintext of type long with different key size.");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTimeEncrypt, elapsedTimeEncrypt, cumulativeTimeEncrypt;
//        long startTimeDecrypt, elapsedTimeDecrypt, cumulativeTimeDecrypt;
//
//        long numLong = 0;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++) {
//            cumulativeTimeEncrypt = 0;
//            cumulativeTimeDecrypt = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    numLong = randomGenerator.nextLong();
//                } while (numLong > thisContext.getMaxBigInteger().longValue());
//
//                startTimeEncrypt = System.nanoTime();
//                EncryptedNumber ciphertext = thisContext.encrypt(numLong);
//                elapsedTimeEncrypt = System.nanoTime() - startTimeEncrypt;
//
//                cumulativeTimeEncrypt += elapsedTimeEncrypt;
//
//                startTimeDecrypt = System.nanoTime();
//                long decryption = thisPrivateKey.decrypt(ciphertext).decodeLong();
//                elapsedTimeDecrypt = System.nanoTime() - startTimeDecrypt;
//
//                cumulativeTimeDecrypt += elapsedTimeDecrypt;
//            }
//
//            double averageEncryptTime = (cumulativeTimeEncrypt / Math.pow(10, 9)) / MEDIUM_ITERATION;
//            double averageDecryptTime = (cumulativeTimeDecrypt / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time to encrypt a long (in second): {}.",
//                    thisKeySizes[i], averageEncryptTime);
//            logger.info("Key size (in bits): {} - Average time to decrypt a long (in second): {}.",
//                    thisKeySizes[i], averageDecryptTime);
//        }
//    }
//
//    @Test
//    public void testEncryptDecryptDoubleTime() throws Exception {
//        logger.info("Running timing test: Encrypt/decrypt plaintext of type double with different key size.");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTimeEncrypt, elapsedTimeEncrypt, cumulativeTimeEncrypt;
//        long startTimeDecrypt, elapsedTimeDecrypt, cumulativeTimeDecrypt;
//
//        double numDouble = 0;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++) {
//            cumulativeTimeEncrypt = 0;
//            cumulativeTimeDecrypt = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    numDouble = randomGenerator.nextDouble();
//                } while (numDouble > thisContext.getMaxBigInteger().doubleValue());
//
//                startTimeEncrypt = System.nanoTime();
//                EncryptedNumber ciphertext = thisContext.encrypt(numDouble);
//                elapsedTimeEncrypt = System.nanoTime() - startTimeEncrypt;
//
//                cumulativeTimeEncrypt += elapsedTimeEncrypt;
//
//                startTimeDecrypt = System.nanoTime();
//                double decryption = thisPrivateKey.decrypt(ciphertext).decodeDouble();
//                elapsedTimeDecrypt = System.nanoTime() - startTimeDecrypt;
//
//                cumulativeTimeDecrypt += elapsedTimeDecrypt;
//            }
//
//            double averageEncryptTime = (cumulativeTimeEncrypt / Math.pow(10, 9)) / MEDIUM_ITERATION;
//            double averageDecryptTime = (cumulativeTimeDecrypt / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time to encrypt a double (in second): {}.",
//                    thisKeySizes[i], averageEncryptTime);
//            logger.info("Key size (in bits): {} - Average time to decrypt a double (in second): {}.",
//                    thisKeySizes[i], averageDecryptTime);
//        }
//    }
//
//    @Test
//    public void testEncryptDecryptBigIntegerTime() throws Exception {
//        logger.info("Running timing test: Encrypt/decrypt plaintext of type BigInteger with different key size.");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTimeEncrypt, elapsedTimeEncrypt, cumulativeTimeEncrypt;
//        long startTimeDecrypt, elapsedTimeDecrypt, cumulativeTimeDecrypt;
//
//        BigInteger numBigInt = BigInteger.ZERO;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++) {
//            cumulativeTimeEncrypt = 0;
//            cumulativeTimeDecrypt = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    numBigInt = new BigInteger(thisKeySizes[i], randomGenerator);
//                } while (numBigInt.compareTo(thisContext.getMaxBigInteger()) == 1);
//
//                startTimeEncrypt = System.nanoTime();
//                EncryptedNumber ciphertext = thisContext.encrypt(numBigInt);
//                elapsedTimeEncrypt = System.nanoTime() - startTimeEncrypt;
//
//                cumulativeTimeEncrypt += elapsedTimeEncrypt;
//
//                startTimeDecrypt = System.nanoTime();
//                BigInteger decryption = thisPrivateKey.decrypt(ciphertext).decodeBigInteger();
//                elapsedTimeDecrypt = System.nanoTime() - startTimeDecrypt;
//
//                cumulativeTimeDecrypt += elapsedTimeDecrypt;
//            }
//
//            double averageEncryptTime = (cumulativeTimeEncrypt / Math.pow(10, 9)) / MEDIUM_ITERATION;
//            double averageDecryptTime = (cumulativeTimeDecrypt / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time to encrypt a BigInteger (in second): {}.",
//                    thisKeySizes[i], averageEncryptTime);
//            logger.info("Key size (in bits): {} - Average time to decrypt a BigInteger (in second): {}.",
//                    thisKeySizes[i], averageDecryptTime);
//        }
//    }
//
//    @Test
//    public void testAddEncrypted() throws Exception {
//        logger.info("Running timing test: Add two encrypted numbers (using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxLong() || num2 > thisContext.getMaxLong());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//                EncryptedNumber ciphertext2 = thisContext.encrypt(num2);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = ciphertext1.add(ciphertext2);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time for (encryption1 + encryption2) (in second): {}.",
//                    thisKeySizes[i], averageTime);
//        }
//    }
//
//    @Test
//    public void testAddEncoded() throws Exception {
//        logger.info("Running timing test: Add an encrypted and an encoded number (using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxLong() || num2 > thisContext.getMaxLong());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = ciphertext1.add(num2);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {}  - Average time for (encryption + encoded) (in second): {}.",
//                        thisKeySizes[i], averageTime);
//        }
//    }
//
//    @Test
//    public void testMulEncoded() throws Exception {
//        logger.info("Running timing test: Multiply an encrypted number with an encode number (using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxLong() || num2 > thisContext.getMaxLong());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = ciphertext1.multiply(num2);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time (encryption * encoded) (in second): {}.",
//                    thisKeySizes[i], averageTime);
//        }
//    }
//
//    @Test
//    public void testSubtractEncrypted() throws Exception {
//        logger.info("Running timing test: Subtract an encrypted number from another encrypted number " +
//                "(using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxLong() || num2 > thisContext.getMaxLong());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//                EncryptedNumber ciphertext2 = thisContext.encrypt(num2);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = ciphertext1.subtract(ciphertext2);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time for (encrypton1 - encryption2) (in second): {}.",
//                    thisKeySizes[i], averageTime);
//        }
//    }
//
//    @Test
//    public void testSubtractEncoded() throws Exception {
//        logger.info("Running timing test: Subtract an encoded number from an encrypted number " +
//                "(using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxLong() || num2 > thisContext.getMaxLong());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = ciphertext1.subtract(num2);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time for (encryption - encoded) (in second): {}.",
//                    thisKeySizes[i], averageTime);
//        }
//    }
//
//    @Test
//    public void testDivideEncoded() throws Exception {
//        logger.info("Running timing test: Divide an encrypted number with a scalar " +
//                "(using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxLong() || num2 > thisContext.getMaxLong());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = ciphertext1.divide(num2);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time for (encryption / encoded) (in second): {}.",
//                    thisKeySizes[i], averageTime);
//        }
//    }
//
//
//    @Test
//    public void testAddEncodedRight() throws Exception {
//        logger.info("Running timing test: Subtract an encrypted number from an encoded number " +
//                "(using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxLong() || num2 > thisContext.getMaxLong());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//                EncodedNumber encode2 = thisContext.encode(num2);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = encode2.add(ciphertext1);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time for (encoded - encryption) (in second): {}.",
//                    thisKeySizes[i], averageTime);
//        }
//    }
//
//    @Test
//    public void testSubtractEncodedRight() throws Exception {
//        logger.info("Running timing test: Subtract an encrypted number from an encoded number " +
//                "(using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxLong() || num2 > thisContext.getMaxLong());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//                EncodedNumber encode2 = thisContext.encode(num2);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = encode2.subtract(ciphertext1);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time for (encoded - encrypted) (in second): {}.",
//                    thisKeySizes[i], averageTime);
//        }
//    }
//
//    @Test
//    public void testMultiplyEncodedRight() throws Exception {
//        logger.info("Running timing test: Multiply an encoded number with an encrypted number " +
//                "(using different key sizes).");
//
//        int[] thisKeySizes = Arrays.copyOfRange(keySizes, 6, 9);
//
//        long startTime, elapsedTime, cumulativeTime;
//
//        long num1, num2;
//
//        PaillierPrivateKey thisPrivateKey;
//        PaillierPublicKey thisPublicKey;
//        PaillierContext thisContext;
//
//        for(int i = 0; i < thisKeySizes.length; i++){
//            cumulativeTime = 0;
//
//            thisPrivateKey = PaillierPrivateKey.create(thisKeySizes[i]);
//            thisPublicKey = thisPrivateKey.getPublicKey();
//            thisContext = thisPublicKey.createSignedIntegerContext();
//
//            for(int j = 0; j < MEDIUM_ITERATION; j++) {
//                do {
//                    num1 = randomGenerator.nextLong();
//                    num2 = randomGenerator.nextLong();
//                } while (num1 > thisContext.getMaxBigInteger().longValue() || num2 > thisContext.getMaxBigInteger().longValue());
//
//                EncryptedNumber ciphertext1 = thisContext.encrypt(num1);
//                EncodedNumber encode2 = thisContext.encode(num2);
//
//                startTime = System.nanoTime();
//                EncryptedNumber cipherResult = encode2.multiply(ciphertext1);
//                elapsedTime = System.nanoTime() - startTime;
//
//                cumulativeTime += elapsedTime;
//            }
//
//            double averageTime = (cumulativeTime / Math.pow(10, 9)) / MEDIUM_ITERATION;
//
//            logger.info("Key size (in bits): {} - Average time for (encoded - encryption) (in second): {}.",
//                    thisKeySizes[i], averageTime);
//        }
//    }
}

