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

import com.n1analytics.paillier.util.HashChain;

import java.math.BigInteger;

/**
 * A class representing encrypted number.
 */
public final class EncryptedNumber {

  public static interface Serializer {

    void serialize(PaillierContext context, BigInteger value, int exponent);
  }

  /**
   * The Paillier context used to encrypt this number.
   */
  protected final PaillierContext context;

  /**
   * The ciphertext.
   */
  protected final transient BigInteger ciphertext;

  /**
   * The exponent of the encrypted number.
   */
  protected final int exponent;

  /**
   * Indicates whether the encrypted number has been obfuscated.
   */
  protected final boolean isSafe;

  /**
   * Constructs an encrypted number given the Paillier context used to encrypt this
   * number, the ciphertext and the exponent representing the precision of the
   * ciphertext.
   *
   * @param context PaillierContext used to encrypt this encrypted number.
   * @param ciphertext the encrypted representation of the encoded number.
   * @param exponent the exponent of the encrypted number.
   * @param isSafe set to true if ciphertext is obfuscated.
   */
  public EncryptedNumber(PaillierContext context, BigInteger ciphertext, int exponent,
                         boolean isSafe) {
    if (context == null) {
      throw new IllegalArgumentException("context must not be null");
    }
    if (ciphertext == null) {
      throw new IllegalArgumentException("unsafeCiphertext must not be null");
    }
    if (ciphertext.signum() < 0) {
      throw new IllegalArgumentException("unsafeCiphertext must be non-negative");
    }
    if (ciphertext.compareTo(context.getPublicKey().getModulusSquared()) >= 0) {
      throw new IllegalArgumentException(
              "unsafeCiphertext must be less than modulus squared");
    }
    this.context = context;
    this.ciphertext = ciphertext;
    this.exponent = exponent;
    this.isSafe = isSafe;
  }

  /**
   * Constructs an encrypted number given the public key used to encrypt this
   * encrypted number, the ciphertext (ie, the encrypted representation of the
   * encoded number) and the exponent representing the precision of the
   * ciphertext.
   *
   * @param context PaillierContext used to encrypt this encrypted number.
   * @param ciphertext the encrypted representation of the encoded number.
   * @param exponent the exponent of the ciphertext.
   */
  public EncryptedNumber(PaillierContext context, BigInteger ciphertext, int exponent) {
    this(context, ciphertext, exponent, false);
  }

  /**
   * Returns the context with which this EncryptedNumber is encrypted.
   *
   * @return the Paillier context.
   */
  public PaillierContext getContext() {
    return context;
  }

  /**
   * Returns the ciphertext.
   *
   * @return ciphertext.
   */
  public BigInteger calculateCiphertext() {
    return isSafe ? ciphertext : obfuscate().ciphertext;
  }

  /**
   * Returns the exponent.
   *
   * @return exponent.
   */
  public int getExponent() {
    return exponent;
  }

  /**
   * Checks whether another EncryptedNumber has the same context as this EncryptedNuber.
   *
   * @param other EncryptedNumber to compare to.
   * @return {@code other}.
   * @throws PaillierContextMismatchException if the context is different.
   */
  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws PaillierContextMismatchException {
    return context.checkSameContext(other);
  }

  /**
   * Checks whether an EncodedNumber has the same context as this EncryptedNUmber.
   *
   * @param other EncodedNumber to compare to.
   * @return {@code other}.
   * @throws PaillierContextMismatchException if the context is different.
   */
  public EncodedNumber checkSameContext(EncodedNumber other) throws PaillierContextMismatchException {
    return context.checkSameContext(other);
  }

  /**
   * Decrypts this EncryptedNumber using a private key.
   *
   * @param key private key to decrypt.
   * @return the decryption result.
   */
  public EncodedNumber decrypt(PaillierPrivateKey key) {
    return key.decrypt(this);
  }

  /**
   * Obfuscates this EncryptedNumber by multiplying it with {@code r<sup>n</sup>},
   * where {@code n} is the modulus of the public key and {@code r} is a random positive
   * number less than {@code n}.
   *
   * @return an obfuscated version of this encrypted number.
   */
  public EncryptedNumber obfuscate() {
    return context.obfuscate(this);
  }

  /**
   * Adds another EncryptedNumber to this EncryptedNumber.
   *
   * @param other EncryptedNumber to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(EncryptedNumber other) {
    return context.add(this, other);
  }

  /**
   * Adds an EncodedNumber to this EncryptedNumber.
   *
   * @param other EncodedNumber to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(EncodedNumber other) {
    return context.add(this, other);
  }

  /**
   * Adds a Number to this EncryptedNumber.
   *
   * @param other Number to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(Number other) {
    return add(context.encode(other));
  }

  /**
   * Adds a BigInteger to this EncryptedNumber.
   *
   * @param other BigInteger to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(BigInteger other) {
    return add(context.encode(other));
  }

  /**
   * Adds a double to this EncryptedNumber.
   *
   * @param other double to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(double other) {
    return add(context.encode(other));
  }

  /**
   * Adds a long to this EncryptedNumber.
   *
   * @param other long to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(long other) {
    return add(context.encode(other));
  }

  /**
   * Returns the additive inverse of <code>this</code>.
   *
   * @return the additive inverse of this.
   */
  public EncryptedNumber additiveInverse() {
    return context.additiveInverse(this);
  }

  /**
   * Subtracts another EncryptedNumber from this EncryptedNumber.
   *
   * @param other EncryptedNumber to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(EncryptedNumber other) {
    return context.subtract(this, other);
  }

  /**
   * Subtracts an EncodedNumber from this EncryptedNumber.
   *
   * @param other EncodedNumber to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(EncodedNumber other) {
    return context.subtract(this, other);
  }

  /**
   * Subtracts a Number from this EncryptedNumber.
   *
   * @param other Number to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(Number other) {
    return subtract(context.encode(other));
  }

  /**
   * Subtracts a BigInteger from this EncryptedNumber.
   *
   * @param other BigInteger to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(BigInteger other) {
    return subtract(context.encode(other));
  }

  /**
   * Subtracts a double from this EncryptedNumber.
   *
   * @param other double to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(double other) {
    return subtract(context.encode(other));
  }

  /**
   * Subtracts a long from this EncryptedNumber.
   *
   * @param other long to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(long other) {
    return subtract(context.encode(other));
  }

  /**
   * Multiplies an EncodedNumber with this EncryptedNumber.
   *
   * @param other EncodedNumber to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(EncodedNumber other) {
    return context.multiply(this, other);
  }

  /**
   * Multiplies a Number with this EncryptedNumber.
   *
   * @param other Number to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(Number other) {
    return multiply(context.encode(other));
  }

  /**
   * Multiplies a BigInteger with this EncryptedNumber.
   *
   * @param other BigInteger to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(BigInteger other) {
    return multiply(context.encode(other));
  }

  /**
   * Multiplies a double with this EncryptedNumber.
   *
   * @param other double to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(double other) {
    return multiply(context.encode(other));
  }

  /**
   * Multiplies a long with this EncryptedNumber.
   *
   * @param other long to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(long other) {
    return multiply(context.encode(other));
  }

  // TODO Issue #10
    /*
    public EncryptedNumber divide(EncodedNumber other) {
    	return context.divide(this, other);
    }

    public EncryptedNumber divide(Number other) {
    	return divide(context.encode(other));
    }

    public EncryptedNumber divide(BigInteger other) {
    	return divide(context.encode(other));
    }
    */

  /**
   * Divides this EncryptedNumber with a double.
   *
   * @param other double to divide this with.
   * @return the division result.
   */
  public EncryptedNumber divide(double other) {
    return multiply(context.encode(1.0 / other)); // TODO Issue #10: unhack
  }

  /**
   * Divides this EncryptedNumber with a long.
   *
   * @param other long to divide this with.
   * @return the division result.
   */
  public EncryptedNumber divide(long other) {
    return multiply(context.encode(1.0 / other)); // TODO Issue #10: unhack
  }

  public void serialize(Serializer serializer) {
    serializer.serialize(context, calculateCiphertext(), exponent);
  }

  @Override
  public int hashCode() {
    return new HashChain().chain(context).chain(ciphertext).hashCode();
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o == null || o.getClass() != EncryptedNumber.class) {
      return false;
    }
    EncryptedNumber number = (EncryptedNumber) o;
    return context.equals(number.context) && ciphertext.equals(number.ciphertext);
  }

  public boolean equals(EncryptedNumber o) {
    return o == this || (o != null &&
            context.equals(o.context) &&
            ciphertext.equals(o.ciphertext));
  }
}
