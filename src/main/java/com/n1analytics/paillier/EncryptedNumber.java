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

import java.math.BigInteger;

import com.n1analytics.paillier.util.HashChain;

/**
 * Immutable class representing encrypted number and arithmetic operations that can be computed on the encrypted number.
 *
 * The attributes stored in this class are:
 * <ul>
 *     <li> public key: the Paillier public key use to encrypt this EncryptedNumber </li>
 *     <li> ciphertext: the encrypted representation of the EncodedNumber </li>
 *     <li> exponent: the exponent of the encrypted EncodedNumber </li>
 *     <li> isObfuscated: indicates whether this EncryptedNumber has been obfuscated with a random number </li>
 * </ul>
 *
 * This class provides a method to obfuscate this EncryptedNumber with a random number. It also contains a number of
 * arithmetic operations that can be computed between this EncryptedNumber and other EncryptedNumber or
 * a non-encrypted number (EncodedNumber, double, long or BigInteger). The supported arithmetic operations are:
 * <ul>
 *     <li> Addition of two encrypted numbers </li>
 *     <li> Addition of an encrypted number with a non-encrypted number </li>
 *     <li> Multiplication of an encrypted number with a non-encrypted number </li>
 *     <li> Subtraction of an encrypted number from another encrypted number </li>
 *     <li> Subtraction of an non-encrypted number from an encrypted number </li>
 *     <li> Division of an encrypted number by a double/long </li>
 * </ul>
 * The arithmetic operations can only be performed when both operands have the same exponent, as a result this class
 * also provides a method to decrase the exponent of the operand with the higher exponent.
 *
 * Examples:
 * <ul>
 *     <li>
 *         To obfuscate an EncryptedNumber, <code>encryptedNumber</code>:
 *         <br>
 *         <code>EncryptedNumber obfuscatedEncrypion = encryptedNumber.obfuscate();</code>
 *     </li>
 *     <li>
 *         To decrease the exponent of an EncryptedNumber, <code>encryptedNumber</code>, to -20:
 *         <br>
 *         <code>EncryptedNumber decreasedExponent = encryptedNumber.decreaseExponentTo(-20);</code>
 *     </li>
 *     <li>
 *         To add two EncryptedNumbers, <code>encryption1 + encryption2</code>:
 *         <br>
 *         <code>EncryptedNumber additionResult = encryption1.add(encryption2);</code>
 *     </li>
 *     <li>
 *         To add an EncryptedNumber and an EncodedNumber, <code>encryption + encoded</code>:
 *         <br>
 *         <code>EncryptedNumber additionResult = encryption.add(encoded);</code>
 *     </li>
 *     <li>
 *         To subtract an EncryptedNumber from another EncryptedNumber, <code>encryption1 - encryption2</code>:
 *         <br>
 *         <code>EncryptedNumber subtractionResult = encryption1.subtract(encryption2);</code>
 *     </li>
 *     <li>
 *         To subtract an EncodedNumber from an EncryptedNumber, <code>encryption - encoded</code>:
 *         <br>
 *         <code>EncryptedNumber subtractionResult = encryption.subtract(encoded);</code>
 *     </li>
 *     <li>
 *         To multiply an EncryptedNumber with an EncodedNumber, <code>encryption * encoded</code>:
 *         <br>
 *         <code>EncryptedNumber multiplicationResult = encryption.multiply(encoded);</code>
 *     </li>
 *     <li>
 *         To divide an EncryptedNumber by a double, <code>encryption / numDouble</code>:
 *         <br>
 *         <code>EncryptedNumber divisionResult = encryption.divide(numDouble);</code>
 *     </li>
 * </ul>
 */
public final class EncryptedNumber {

  public static interface Serializer {

    void serialize(PaillierContext context, BigInteger value, int exponent);
  }

  protected final PaillierContext context;
  protected final transient BigInteger ciphertext;
  protected final int exponent;
  protected final boolean isSafe;

  /**
   * Constructs an encrypted number given the public key used to encrypt this
   * encrypted number, the ciphertext (ie, the encrypted representation of the
   * encoded number) and the exponent representing the precision of the
   * ciphertext.
   *
   * @param context PaillierContext used to encrypt this encrypted number.
   * @param ciphertext the encrypted representation of the encoded number.
   * @param exponent the exponent of the ciphertext.
   * @param isSafe set to true if cypertext is obfuscated
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

  public PaillierContext getContext() {
    return context;
  }

  /**
   * Gets the ciphertext.
   *
   * @return ciphertext.
   */
  public BigInteger calculateCiphertext() {
    return isSafe ? ciphertext : obfuscate().ciphertext;
  }

  public int getExponent() {
    return exponent;
  }

  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws ArithmeticException {
    return context.checkSameContext(other);
  }

  public EncodedNumber checkSameContext(EncodedNumber other) {
    return context.checkSameContext(other);
  }

  public EncodedNumber decrypt(PaillierPrivateKey key) {
    return key.decrypt(this);
  }

  /**
   * Obfuscates the encrypted number by multiplying it with r<sup>n</sup>,
   * where n is the modulus of the public key and r is a random positive
   * number less than n.
   * @return An obfuscated version of this encrypted number.
   */
  public EncryptedNumber obfuscate() {
    return context.obfuscate(this);
  }

  public EncryptedNumber add(EncryptedNumber other) {
    return context.add(this, other);
  }

  public EncryptedNumber add(EncodedNumber other) {
    return context.add(this, other);
  }

  public EncryptedNumber add(Number other) {
    return add(context.encode(other));
  }

  public EncryptedNumber add(BigInteger other) {
    return add(context.encode(other));
  }

  public EncryptedNumber add(double other) {
    return add(context.encode(other));
  }

  public EncryptedNumber add(long other) {
    return add(context.encode(other));
  }

  public EncryptedNumber additiveInverse() {
    return context.additiveInverse(this);
  }

  public EncryptedNumber subtract(EncryptedNumber other) {
    return context.subtract(this, other);
  }

  public EncryptedNumber subtract(EncodedNumber other) {
    return context.subtract(this, other);
  }

  public EncryptedNumber subtract(Number other) {
    return subtract(context.encode(other));
  }

  public EncryptedNumber subtract(BigInteger other) {
    return subtract(context.encode(other));
  }

  public EncryptedNumber subtract(double other) {
    return subtract(context.encode(other));
  }

  public EncryptedNumber subtract(long other) {
    return subtract(context.encode(other));
  }

  public EncryptedNumber multiply(EncodedNumber other) {
    return context.multiply(this, other);
  }

  public EncryptedNumber multiply(Number other) {
    return multiply(context.encode(other));
  }

  public EncryptedNumber multiply(BigInteger other) {
    return multiply(context.encode(other));
  }

  public EncryptedNumber multiply(double other) {
    return multiply(context.encode(other));
  }

  public EncryptedNumber multiply(long other) {
    return multiply(context.encode(other));
  }

  // TODO
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

  public EncryptedNumber divide(double other) {
    return multiply(context.encode(1.0 / other)); // TODO unhack
  }

  public EncryptedNumber divide(long other) {
    return multiply(context.encode(1.0 / other)); // TODO unhack
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
