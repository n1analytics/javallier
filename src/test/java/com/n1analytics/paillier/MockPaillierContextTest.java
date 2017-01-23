package com.n1analytics.paillier;

import org.junit.BeforeClass;
import org.junit.Test;


import static org.junit.Assert.*;

public class MockPaillierContextTest {

  static MockPaillierPrivateKey key;
  static PaillierPublicKey publicKey;
  static PaillierContext mockContext;
  
  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    key = MockPaillierPrivateKey.create(2048);
    publicKey = key.getPublicKey();
    mockContext = new PaillierContext(publicKey, new StandardEncodingScheme(publicKey, true));
  }

  @Test
  public void testMockPublicKey() throws Exception {
    assertTrue(publicKey instanceof MockPaillierPublicKey);
  }
  
  @Test
  public void testForMockEncryptedNumbers() {
    EncryptedNumber e = mockContext.encrypt(42);
    assertTrue(e instanceof MockEncryptedNumber);
    e = mockContext.encode(42).encrypt();
    assertTrue(e instanceof MockEncryptedNumber);
  }
  
  @Test
  public void testObfuscate(){
    EncryptedNumber n = mockContext.encrypt(0);
    EncryptedNumber m = n.obfuscate();
    assertEquals(n.ciphertext, m.ciphertext);
    assertEquals(n.exponent, m.exponent);
    assertEquals(n.encoding, m.encoding);
    assertEquals(n.isSafe, m.isSafe);
  }
  
  @Test
  public void testEncrypt(){
    EncodedNumber n = mockContext.encode(42.42);
    EncryptedNumber m = mockContext.encrypt(n);
    assertEquals(n.value, m.ciphertext);
    assertEquals(n.exponent,m.exponent);
  }
  
  @Test
  public void testAdd(){
    EncodedNumber n = mockContext.encode(42.42e-120);
    EncodedNumber m = mockContext.encode(123);
    EncryptedNumber nplusm = mockContext.encrypt(n).add(mockContext.encrypt(m));
    EncodedNumber nplusm_e = n.add(m);
    assertEquals(nplusm.ciphertext, nplusm_e.value);
    assertEquals(nplusm.exponent, nplusm_e.exponent);

    EncodedNumber n2 = mockContext.encode(123);
    EncodedNumber m2 = mockContext.encode(42.42e-120);
    EncryptedNumber nplusm2 = mockContext.encrypt(n2).add(mockContext.encrypt(m2));
    EncodedNumber nplusm_e2 = n2.add(m2);
    assertEquals(nplusm2.ciphertext, nplusm_e2.value);
    assertEquals(nplusm2.exponent, nplusm_e2.exponent);
  }
  
  @Test
  public void testAdditiveInverse(){
    EncodedNumber n = mockContext.encode(123.456);
    EncodedNumber minusN = n.additiveInverse();
    assertEquals(minusN.decodeDouble(), n.decodeDouble()*-1, 1e-100);
    EncryptedNumber en = mockContext.encrypt(n);
    EncryptedNumber minusEN = en.additiveInverse();
    assertEquals(en.add(minusEN).decrypt(key).decodeDouble(), 0.0, 1e-100);
    EncodedNumber zero = mockContext.encode(0);
    EncodedNumber minusZero = zero.additiveInverse();
    assertEquals(zero, minusZero);
    assertEquals(0, zero.decodeLong());
  }
  
  @Test
  public void testMultiply(){
    EncodedNumber n = mockContext.encode(-987.654321);
    EncodedNumber m = mockContext.encode(462435.80712);
    EncryptedNumber nm = mockContext.encrypt(n).multiply(m);
    assertEquals(nm.decrypt(key), n.multiply(m));
  }

  @Test
  public void testEquals() {
    PaillierPrivateKey pkey = PaillierPrivateKey.create(512);
    PaillierPublicKey ppublicKey = pkey.getPublicKey();
    assertNotEquals(ppublicKey, new MockPaillierPublicKey(ppublicKey.getModulus()));
    PaillierPrivateKey nkey = new MockPaillierPrivateKey(ppublicKey, pkey.p, pkey.q);
    assertNotEquals(pkey, nkey);
  }
}
