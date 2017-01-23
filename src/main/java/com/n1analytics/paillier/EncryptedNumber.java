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
import com.n1analytics.paillier.util.HashChain;

import java.math.BigInteger;

/**
 * A class representing encrypted number. The attributes of this class are:
 * <ul>
 *     <li>A PaillierContext <code>context</code> associated to this encrypted number.</li>
 *     <li>A BigInteger <code>ciphertext</code>.</li>
 *     <li>An integer <code>exponent</code> of the encrypted number.</li>
 *     <li>A boolean <code>isSafe</code> that denotes whether the encrypted number has been obfuscated.</li>
 * </ul>
 *
 * This class defines the methods:
 * <ul>
 *     <li>
 *         To check whether the PaillierContext of an EncodedNumber or an EncryptedNumber
 *         is the same as this PaillierContext
 *     </li>
 *     <li>
 *         To decrypt this encrypted number
 *     </li>
 *     <li>
 *         To perform arithmetic operations computation (support addition, subtraction,
 *         limited multiplication and limited division)
 *     </li>
 * </ul>
 */
public class EncryptedNumber {
  /**
   * A serializer interface for {@code EncryptedNumber}.
   */
  public static interface Serializer {

    void serialize(EncodingScheme encoding, BigInteger value, int exponent);
  }

  /**
   * The Paillier context associated to this encrypted number.
   */
  protected final EncodingScheme encoding;

  /**
   * The ciphertext.
   */
  protected final transient BigInteger ciphertext;

  /**
   * The exponent of the encrypted number.
   */
  protected final int exponent;

  /**
   * Denotes whether the encrypted number has been obfuscated.
   */
  protected final boolean isSafe;

  /**
   * Constructs an encrypted number given the Paillier context used to encrypt this
   * number, the ciphertext and the exponent representing the precision of the
   * ciphertext.
   *
   * @param context PaillierContext associated to this encrypted number.
   * @param ciphertext the encrypted representation of the encoded number.
   * @param exponent of the encrypted number.
   * @param isSafe set to true if ciphertext is obfuscated, false otherwise.
   */
  public EncryptedNumber(EncodingScheme encoding, BigInteger ciphertext, int exponent,
                         boolean isSafe) {
    if (encoding == null) {
      throw new IllegalArgumentException("encoding must not be null");
    }
    if (ciphertext == null) {
      throw new IllegalArgumentException("unsafeCiphertext must not be null");
    }
    if (ciphertext.signum() < 0) {
      throw new IllegalArgumentException("unsafeCiphertext must be non-negative");
    }
    if (ciphertext.compareTo(encoding.getPublicKey().getModulusSquared()) >= 0) {
      throw new IllegalArgumentException(
              "unsafeCiphertext must be less than modulus squared");
    }
    this.encoding = encoding;
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
   * @param context PaillierContext associated to this encrypted number.
   * @param ciphertext the encrypted representation of the encoded number.
   * @param exponent the exponent of the encrypted number.
   */
  public EncryptedNumber(EncodingScheme encoding, BigInteger ciphertext, int exponent) {
    this(encoding, ciphertext, exponent, false);
  }

  /**
   * @return the associated Paillier {@code context}.
   */
  public EncodingScheme getEncodingScheme() {
    return encoding;
  }
  
  /**
   * Obfuscates this number only if necessary.
   * @return a version of this encrypted number which is guaranteed to be safe.
   */
  public EncryptedNumber getSafeEncryptedNumber() {
      return new EncryptedNumber(encoding, calculateCiphertext(), exponent, true);
  }

  /**
   * @return the {@code ciphertext}.
   */
  public BigInteger calculateCiphertext() {
    return isSafe ? ciphertext : obfuscate().ciphertext;
  }

  /**
   * @return the {@code exponent}.
   */
  public int getExponent() {
    return exponent;
  }

  /**
   * Checks whether another {@code EncryptedNumber} has the same context as this {@code EncryptedNumber}.
   *
   * @param other {@code EncryptedNumber} to compare to.
   * @return {@code other} provided the contexts match, else PaillierContextMismatchException is thrown.
   * @throws PaillierContextMismatchException if the context is different.
   */
  public EncryptedNumber checkSameEncoding(EncryptedNumber other)
          throws PaillierContextMismatchException {
    if (!encoding.equals(other.encoding)) {
        throw new PaillierContextMismatchException("EncryptedNumber 'other' has different encoding scheme.");
    }
      return other;
  }

  /**
   * Checks whether an {@code EncodedNumber} has the same context as this {@code EncryptedNumber}.
   *
   * @param other {@code EncodedNumber} to compare to.
   * @return {@code other} if the {@code PaillierContext} match, else PaillierContextMismatchException is thrown.
   * @throws PaillierContextMismatchException if the context is different.
   */
  public EncodedNumber checkSameEncoding(EncodedNumber other) throws PaillierContextMismatchException {
      if (!encoding.equals(other.encoding)) {
          throw new PaillierContextMismatchException("EncryptedNumber 'other' has different encoding scheme.");
      }
        return other;
  }

  /**
   * Decrypts this {@code EncryptedNumber} using a private key. 
   *
   * @param key private key to decrypt.
   * @return the decryption result.
   */
  public EncodedNumber decrypt(PaillierPrivateKey key) throws PaillierKeyMismatchException{
      if (!encoding.getPublicKey().equals(key.getPublicKey())) {
          throw new PaillierKeyMismatchException();
      }
      return new EncodedNumber(encoding, key.raw_decrypt(ciphertext), exponent);
  }

  /**
   * Obfuscates this {@code EncryptedNumber} by multiplying it with <code>r<sup>n</sup></code>,
   * where {@code n} is the modulus of the public key and {@code r} is a random positive
   * number less than {@code n}.
   *
   * @return the obfuscated {@code EncryptedNumber}.
   */
  public EncryptedNumber obfuscate() {
    final BigInteger obfuscated = encoding.getPublicKey().raw_obfuscate(ciphertext);
    return new EncryptedNumber(encoding, obfuscated, getExponent(), true);
  }

  /**
   * Decreases the exponent of this {@code EncryptedNumber} to {@code newExp}, if {@code newExp} is less than
   * the current {@code exponent}.
   * See {@link com.n1analytics.paillier.PaillierContext#decreaseExponentTo(EncryptedNumber, int)} for details.
   *
   * @param newExp the new {@code exponent}, must be less than the current {@code exponent}.
   * @return an {@code EncryptedNumber} representing the same value with {@code exponent} equals to {@code newExp}.
   */
  public EncryptedNumber decreaseExponentTo(int newExp) {
    if(newExp > exponent){
      throw new IllegalArgumentException("New exponent: "+ newExp +
              "has to be smaller than old exponent: " + exponent + ".");
    }
    int expDiff = exponent - newExp;
    BigInteger bigFactor = encoding.getRescalingFactor(expDiff);
    BigInteger newEnc = encoding.getPublicKey().raw_multiply(ciphertext, bigFactor);
    return new EncryptedNumber(encoding, newEnc, newExp, isSafe);
  }
  

  /**
   * Adds another {@code EncryptedNumber} to this {@code EncryptedNumber}. See
   * {@link com.n1analytics.paillier.PaillierContext#add(EncryptedNumber, EncryptedNumber)} for more details.
   *
   * @param other {@code EncryptedNumber} to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(EncryptedNumber other) {
    checkSameEncoding(other);
    BigInteger value1 = ciphertext;
    BigInteger value2 = other.ciphertext;
    int exponent1 = getExponent();
    int exponent2 = other.getExponent();
    if (exponent1 > exponent2) {
      value1 = encoding.getPublicKey().raw_multiply(value1, encoding.getRescalingFactor(exponent1 - exponent2));
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = encoding.getPublicKey().raw_multiply(value2, encoding.getRescalingFactor(exponent2 - exponent1));
    } // else do nothing
    final BigInteger result = encoding.getPublicKey().raw_add(value1, value2);
    return new EncryptedNumber(encoding, result, exponent1, isSafe && other.isSafe);
  }

  /**
   * Adds an {@code EncodedNumber} to this {@code EncryptedNumber}. See
   * {@link com.n1analytics.paillier.PaillierContext#add(EncryptedNumber, EncodedNumber)} for more details.
   *
   * @param other {@code EncodedNumber} to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(EncodedNumber other) {
    checkSameEncoding(other);
    //addition only works if both numbers have the same exponent. Adjusting the exponent of an 
    //encrypted number can only be done with an encrypted multiplication (internally, this is
    //done with a modular exponentiation). 
    //It is going to be computationally much cheaper to adjust the encoded number before the 
    //encryption as we only need to do a modular multiplication.
    int exponent1 = exponent;
    int exponent2 = other.getExponent();
    BigInteger value2 = other.value;
    if(exponent1 < exponent2){
      value2 = value2.multiply(encoding.getRescalingFactor(exponent2-exponent1)).mod(encoding.getPublicKey().getModulus());
      return add(new EncodedNumber(encoding, value2, exponent1).encrypt());
    }
    if(exponent1 > exponent2 && other.signum() == 1){
      //test if we can shift value2 to the right without loosing information
      //Note, this only works for positive values.
      boolean canShift = value2.mod(encoding.getRescalingFactor(exponent1-exponent2)).equals(BigInteger.ZERO);
      if(canShift){
        value2 = value2.divide(encoding.getRescalingFactor(exponent1-exponent2));
        return add(new EncodedNumber(encoding, value2, exponent1).encrypt());
      }
    }
    return add(other.encrypt());
  }

  /**
   * Adds a {@code BigInteger} to this {@code EncryptedNumber}.
   *
   * @param other {@code BigInteger} to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(BigInteger other) {
    return add(encoding.encode(other));
  }

  /**
   * Adds a {@code double} to this {@code EncryptedNumber}.
   *
   * @param other {@code double} to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(double other) {
    return add(encoding.encode(other));
  }

  /**
   * Adds a {@code long} to this {@code EncryptedNumber}.
   *
   * @param other {@code long} to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(long other) {
    return add(encoding.encode(other));
  }

  /**
   * @return the additive inverse of this.
   */
  public EncryptedNumber additiveInverse() {
    return new EncryptedNumber(encoding, BigIntegerUtil.modInverse(ciphertext, encoding.getPublicKey().getModulusSquared()),
                               getExponent(), isSafe);
  }

  /**
   * Subtracts another {@code EncryptedNumber} from this {@code EncryptedNumber}.
   *
   * @param other {@code EncryptedNumber} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(EncryptedNumber other) {
    return add(other.additiveInverse());
  }

  /**
   * Subtracts an {@code EncodedNumber} from this {@code EncryptedNumber}.
   *
   * @param other {@code EncodedNumber} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(EncodedNumber other) {
    return add(other.additiveInverse().encrypt());
  }

  /**
   * Subtracts a {@code BigInteger} from this {@code EncryptedNumber}.
   *
   * @param other {@code BigInteger} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(BigInteger other) {
    return subtract(encoding.encode(other));
  }

  /**
   * Subtracts a {@code double} from this {@code EncryptedNumber}.
   *
   * @param other {@code double} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(double other) {
    return subtract(encoding.encode(other));
  }

  /**
   * Subtracts a {@code long} from this {@code EncryptedNumber}.
   *
   * @param other {@code long} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(long other) {
    return subtract(encoding.encode(other));
  }

  /**
   * Multiplies an {@code EncodedNumber} with this {@code EncryptedNumber}.
   *
   * @param other {@code EncodedNumber} to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(EncodedNumber other) {
    checkSameEncoding(other);
    final BigInteger result = encoding.getPublicKey().raw_multiply(ciphertext, other.getValue());
    final int exponent = getExponent() + other.getExponent();
    return new EncryptedNumber(encoding, result, exponent);
  }

  /**
   * Multiplies a {@code BigInteger} with this {@code EncryptedNumber}.
   *
   * @param other {@code BigInteger} to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(BigInteger other) {
    return multiply(encoding.encode(other));
  }

  /**
   * Multiplies a {@code double} with this {@code EncryptedNumber}.
   *
   * @param other {@code double} to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(double other) {
    return multiply(encoding.encode(other));
  }

  /**
   * Multiplies a {@code long} with this {@code EncryptedNumber}.
   *
   * @param other {@code long} to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(long other) {
    return multiply(encoding.encode(other));
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
   * Divides this {@code EncryptedNumber} with a {@code double}.
   *
   * @param other {@code double} to divide this with.
   * @return the division result.
   */
  public EncryptedNumber divide(double other) {
    return multiply(encoding.encode(1.0 / other)); // TODO Issue #10: unhack
  }

  /**
   * Divides this {@code EncryptedNumber} with a {@code long}.
   *
   * @param other {@code long} to divide this with.
   * @return the division result.
   */
  public EncryptedNumber divide(long other) {
    return multiply(encoding.encode(1.0 / other)); // TODO Issue #10: unhack
  }

  /**
   * Serializes the {@code EncryptedNumber}.
   *
   * @param serializer to serialize the {@code EncryptedNumber}.
   */
  public void serialize(Serializer serializer) {
    serializer.serialize(encoding, calculateCiphertext(), exponent);
  }

  @Override
  public int hashCode() {
    return new HashChain().chain(encoding).chain(ciphertext).hashCode();
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
    return encoding.equals(number.encoding) 
            && ciphertext.equals(number.ciphertext)
            && exponent == number.exponent;
  }

  public boolean equals(EncryptedNumber o) {
    return o == this || (o != null &&
            encoding.equals(o.encoding) 
            && ciphertext.equals(o.ciphertext)
            && exponent == o.exponent);
  }
}
