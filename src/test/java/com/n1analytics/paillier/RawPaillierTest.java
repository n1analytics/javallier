package com.n1analytics.paillier;

import org.junit.BeforeClass;
import org.junit.Test;

import com.n1analytics.paillier.util.BigIntegerUtil;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class RawPaillierTest {

  static PaillierPrivateKey privateKey;
  static PaillierPublicKey publicKey;
  static final int maxIterations = TestConfiguration.MAX_ITERATIONS;
  
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    privateKey = PaillierPrivateKey.create(TestConfiguration.DEFAULT_KEY_SIZE);
    publicKey = privateKey.getPublicKey();
  }
  
  @Test
  public void testEncryptionDecryption(){
    for (int i = 0; i < maxIterations; i++) {
      BigInteger plaintext = BigIntegerUtil.randomPositiveNumber(publicKey.getModulus());
      BigInteger ciphertext = publicKey.raw_encrypt(plaintext);
      assertNotEquals(plaintext, ciphertext);
      assertEquals(plaintext, privateKey.raw_decrypt(ciphertext));
    }
  }
  
  @Test
  public void testAdd(){
    for (int i = 0; i < maxIterations; i++) {
      BigInteger a = BigIntegerUtil.randomPositiveNumber(publicKey.getModulus());
      BigInteger b = BigIntegerUtil.randomPositiveNumber(publicKey.getModulus());
      BigInteger ciphertext = publicKey.raw_add(publicKey.raw_encrypt(a), publicKey.raw_encrypt(b));
      assertEquals(privateKey.raw_decrypt(ciphertext), a.add(b).mod(publicKey.getModulus()));
    }
  }
  
  @Test
  public void testMul(){
    for (int i = 0; i < maxIterations; i++) {
      BigInteger a = BigIntegerUtil.randomPositiveNumber(publicKey.getModulus());
      BigInteger k = BigInteger.ONE;
      BigInteger ciphertext = publicKey.raw_multiply(publicKey.raw_encrypt(a), k);
      assertEquals(privateKey.raw_decrypt(ciphertext), a);
      k = BigIntegerUtil.randomPositiveNumber(BigInteger.valueOf(1000));
      ciphertext = publicKey.raw_multiply(publicKey.raw_encrypt(a), k);
      assertEquals(privateKey.raw_decrypt(ciphertext), a.multiply(k).mod(publicKey.getModulus()));     
    }
  }
  
  @Test
  public void testObfuscate(){
    for (int i= 0; i < maxIterations; i++) {
      BigInteger a = BigIntegerUtil.randomPositiveNumber(publicKey.getModulus());
      BigInteger ciphertext = publicKey.raw_encrypt(a);
      BigInteger obuscatedCiphertext = publicKey.raw_obfuscate(ciphertext);
      assertNotEquals(ciphertext, obuscatedCiphertext);
      assertEquals(privateKey.raw_decrypt(obuscatedCiphertext), a);
    }
  }
  
}
