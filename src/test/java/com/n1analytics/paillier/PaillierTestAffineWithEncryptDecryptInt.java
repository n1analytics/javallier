package com.n1analytics.paillier;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

/**
 * Test encrypt/decrypt for a large range of int.
 */
@Category(SlowTests.class)
public class PaillierTestAffineWithEncryptDecryptInt {
//    final static Logger logger = LoggerFactory.getLogger(PaillierTestAffineWithEncryptDecryptInt.class);

    static private PaillierPublicKey publicKey;
    static private PaillierPrivateKey privateKey;
    static private PaillierContext context;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        privateKey = PaillierPrivateKey.create(1024);
        publicKey = privateKey.getPublicKey();
        context = publicKey.createSignedContext();
    }

//        Original test:
//        logging.debug('Running testAffineWithEncryptDecryptInt method.')
//        plaintext1 = 123456789123456789123456789123456789
//        for plaintext in (plaintext1, -plaintext1):
//        ciphertext1 = self.public_key.encrypt(plaintext)
//        # tests a = 2
//        a = 2
//        b = 111111110111111110111111110111111110
//        ciphertext3 = ciphertext1 * a + b
//        decryption3 = self.private_key.decrypt(ciphertext3)
//        self.assertEqual(a * plaintext + b, decryption3)
//        # tests a = 0
//        ciphertext4 = ciphertext1 * 0 + b
//        decryption4 = self.private_key.decrypt(ciphertext4)
//        self.assertEqual(b, decryption4)
//        # tests a = 1
//        ciphertext5 = ciphertext1 * 1 + b
//        decryption5 = self.private_key.decrypt(ciphertext5)
//        self.assertEqual(plaintext + b, decryption5)
//        # tests b = 0
//        ciphertext6 = ciphertext1 * 2 + 0
//        decryption6 = self.private_key.decrypt(ciphertext6)
//        self.assertEqual(2 * plaintext, decryption6)
//        # tests a=0, b = 0
//        ciphertext7 = ciphertext1 * 0 + 0
//        decryption7 = self.private_key.decrypt(ciphertext7)
//        self.assertEqual(0, decryption7)

//     Note: At the moment the loop is limited to +/-123.
    @Test
    public void testAffineWithEncryptDecryptInt() throws Exception {
//        logger.debug("Running phe test: testAffineWithEncryptDecryptInt.");

        BigInteger plaintext1 = new BigInteger("123");
        BigInteger plaintext = plaintext1.negate();
        while (plaintext.compareTo(plaintext1) <= 0){
            EncryptedNumber ciphertext1 = context.encrypt(plaintext);
            BigInteger a = new BigInteger("2");
            BigInteger b = new BigInteger("111111110111111110111111110111111110");

            EncryptedNumber ciphertext3 = (ciphertext1.multiply(a)).add(b);
            BigInteger decryption3 = privateKey.decrypt(ciphertext3).decodeApproximateBigInteger();
            assertEquals((a.multiply(plaintext)).add(b), decryption3);

            EncryptedNumber ciphertext4 = (ciphertext1.multiply(0)).add(b);
            BigInteger decryption4 = privateKey.decrypt(ciphertext4).decodeApproximateBigInteger();
            assertEquals(b, decryption4);

            EncryptedNumber ciphertext5 = (ciphertext1.multiply(1)).add(b);
            BigInteger decryption5 = privateKey.decrypt(ciphertext5).decodeApproximateBigInteger();
            assertEquals(plaintext.add(b), decryption5);

            EncryptedNumber ciphertext6 = (ciphertext1.multiply(2)).add(0);
            BigInteger decryption6 = privateKey.decrypt(ciphertext6).decodeApproximateBigInteger();
            assertEquals(plaintext.multiply(new BigInteger("2")).toString(), decryption6.toString());

            EncryptedNumber ciphertext7 = (ciphertext1.multiply(0)).add(0);
            BigInteger decryption7 = privateKey.decrypt(ciphertext7).decodeApproximateBigInteger();
            assertEquals(BigInteger.ZERO, decryption7);

            plaintext = plaintext.add(BigInteger.ONE);
        }

    }
}