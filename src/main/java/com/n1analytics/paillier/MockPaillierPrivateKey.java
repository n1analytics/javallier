package com.n1analytics.paillier;

import java.math.BigInteger;

public class MockPaillierPrivateKey extends PaillierPrivateKey {

  public MockPaillierPrivateKey(PaillierPublicKey publicKey, BigInteger totient) {
    super(new MockPaillierPublicKey(publicKey.modulus), totient);
  }

  protected MockPaillierPrivateKey(PaillierPublicKey publicKey, BigInteger p, BigInteger q) {
    super(new MockPaillierPublicKey(publicKey.modulus), p, q);
  }

  public static MockPaillierPrivateKey create(int modulusLength) {
    PaillierPrivateKey key = PaillierPrivateKey.create(modulusLength);
    return new MockPaillierPrivateKey(key.getPublicKey(), key.p, key.q);
  }

  /* no encryption in mocking mode */
  public BigInteger raw_decrypt(BigInteger ciphertext) {
    return ciphertext;
  }

  @Override
  public boolean equals(Object o) {
    return o == this || (o != null && o.getClass() == MockPaillierPrivateKey.class
        && publicKey.equals(((PaillierPrivateKey) o).publicKey));
  }

}
