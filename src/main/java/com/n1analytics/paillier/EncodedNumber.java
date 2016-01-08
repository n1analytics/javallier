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
 * A class representing encoded numbers, which enables Paillier to operate on
 * negative integers and floating point numbers as well as non-negative
 * integers.
 */
public final class EncodedNumber {

  /**
   * The Paillier context used to encode this number.
   */
  protected final PaillierContext context;

  /**
   * The value of the encoded number.
   */
  protected final BigInteger value;

  /**
   * The exponent of the encoded number.
   */
  protected final int exponent;

  /**
   * Constructs an encoded number given an encoding and an encoded value. The
   * encoded value must be a non-negative integer less than
   * {@code context.getModulus()}.
   *
   * @param context the context used to encode value.
   * @param value BigInteger to encode
   * @param exponent exponent to use
   */
  protected EncodedNumber(PaillierContext context, BigInteger value, int exponent) {
    if (context == null) {
      throw new IllegalArgumentException("context must not be null");
    }
    if (value == null) {
      throw new IllegalArgumentException("value must not be null");
    }
    if (value.signum() < 0) {
      throw new IllegalArgumentException("value must be non-negative");
    }
    if (value.compareTo(context.getPublicKey().getModulus()) >= 0) {
      throw new IllegalArgumentException("value must be less than modulus");
    }
    this.context = context;
    this.value = value;
    this.exponent = exponent;
  }

  /**
   * Returns the context with which this number is encoded.
   *
   * @return the context.
   */
  public PaillierContext getContext() {
    return context;
  }

  /**
   * Returns the encoded value.
   *
   * @return the encoded value.
   */
  public BigInteger getValue() {
    return value;
  }

  /**
   * Get the exponent.
   *
   * @return exponent.
   */
  public int getExponent() {
    return exponent;
  }

  /**
   * Checks whether this EncdoedNumber is valid.
   *
   * @return true if EncodedNumber is valid, false otherwise.
   */
  public boolean isValid() {
    return context.isValid(this);
  }

  /**
   * Checks whether an EncryptedNumber has the same context as this EncodedNumber.
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
   * Checks whether another EncodedNumber has the same context as this EncodedNumber.
   *
   * @param other EncodedNumber to compare to.
   * @return {@code other}.
   * @throws PaillierContextMismatchException if the context is different.
   */
  public EncodedNumber checkSameContext(EncodedNumber other) throws ArithmeticException {
    return context.checkSameContext(other);
  }

  /**
   * Decodes this EncodedNumber to a fixed point representation.
   *
   * @return the decoded number.
   */
  public Number decode() throws ArithmeticException {
    return context.decode(this);
  }

  /**
   * Decodes this EncodedNumber to an approximated BigInteger representation.
   *
   * @return the decoded number.
   */
  public BigInteger decodeApproximateBigInteger() {
    return decode().decodeApproximateBigInteger();
  }

  /**
   * Decodes this EncodedNumber to a BigInteger representation. Throws an ArithmeticException
   * if this EncodedNumber cannot be represented as a BigInteger.
   *
   * @return the decoded number.
   * @throws ArithmeticException if the number cannot be decoded exactly.
   */
  public BigInteger decodeBigInteger() throws ArithmeticException {
    return decode().decodeBigInteger();
  }

  /**
   * Decodes this EncodedNumber to the approximated double representation.
   * @return the decoded number.
   */
  public double decodeApproximateDouble() {
    return decode().decodeApproximateDouble();
  }

  /**
   * Decodes this EncodedNumber to a double representation. Throws an ArithmeticException
   * if this EncodedNumber cannot be represented as a valid double.
   *
   * @return the decoded number.
   * @throws ArithmeticException if the number cannot be decoded exactly.
   */
  public double decodeDouble() throws ArithmeticException {
    return decode().decodeDouble();
  }

  /**
   * Decodes this EncodedNumber to an approximated long representation. If the number
   * cannot be represented exactly as a long, it is converted to the long representation
   * of the lowest 64 bits.
   *
   * @return the decoded number.
   */
  public long decodeApproximateLong() {
    return decode().decodeApproximateLong();
  }

  /**
   * Decodes this EncodedNumber to a long representation. Throws an ArithmeticException
   * if this cannot be represented as a valid double.
   *
   * @return the decoded number.
   * @throws ArithmeticException if the number cannot be decoded exactly
   */
  public long decodeLong() throws ArithmeticException {
    return decode().decodeLong();
  }

  /**
   * Re-encodes this number with the specified context.
   *
   * @param context the context to re-encode with.
   * @return the re-encoded number.
   */
  public EncodedNumber changeContext(PaillierContext context) {
    return context.encode(decode());
  }

  /**
   * Encrypts this EncodedNumber.
   * @return encrypted number.
   */
  public EncryptedNumber encrypt() {
    return context.encrypt(this);
  }

  /**
   * Adds an EncryptedNumber to this EncodedNumber.
   *
   * @param other EncryptedNumber to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(EncryptedNumber other) {
    return context.add(this, other);
  }

  /**
   * Adds another EncodedNumber to this EncodedNumber.
   *
   * @param other EncodedNumber to be added.
   * @return the addition result.
   */
  public EncodedNumber add(EncodedNumber other) {
    return context.add(this, other);
  }

  /**
   * Adds a Number to this EncodedNumber.
   *
   * @param other EncodedNumber to be added.
   * @return the addition result.
   */
  public EncodedNumber add(Number other) {
    return add(context.encode(other));
  }

  /**
   * Adds a BigInteger to this EncodedNumber.
   *
   * @param other EncodedNumber to be added.
   * @return the addition result.
   */
  public EncodedNumber add(BigInteger other) {
    return add(context.encode(other));
  }

  /**
   * Adds a double to this EncodedNumber.
   *
   * @param other double to be added.
   * @return the addition result.
   */
  public EncodedNumber add(double other) {
    return add(context.encode(other));
  }

  /**
   * Adds a long to this EncodedNumber.
   *
   * @param other long to be added.
   * @return the addition result.
   */
  public EncodedNumber add(long other) {
    return add(context.encode(other));
  }

  /**
   * Returns the additive inverse of this EncodedNumber.
   *
   * @return additive inverse of this EncodedNumber.
   */
  public EncodedNumber additiveInverse() {
    return context.additiveInverse(this);
  }

  /**
   * Subtracts an EncryptedNumber from this EncodedNumber.
   *
   * @param other EncryptedNumber to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(EncryptedNumber other) {
    return context.subtract(this, other);
  }

  /**
   * Subtracts another EncodedNumber from this EncodedNumber.
   *
   * @param other EncodedNumber to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(EncodedNumber other) {
    return context.subtract(this, other);
  }

  /**
   * Subtracts a Number from this EncodedNumber.
   *
   * @param other Number to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(Number other) {
    return subtract(context.encode(other));
  }

  /**
   * Subtracts a BigInteger from this EncodedNumber.
   *
   * @param other BigInteger to be subtracted from this EncodedNumber.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(BigInteger other) {
    return subtract(context.encode(other));
  }

  /**
   * Subtracts a double from this EncodedNumber.
   *
   * @param other double to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(double other) {
    return subtract(context.encode(other));
  }

  /**
   * Subtracts a long from this EncodedNumber.
   *
   * @param other long to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(long other) {
    // NOTE it would be nice to do add(context.encode(-other)) however this
    //      would fail if other == Long.MIN_VALUE since it has no
    //      corresponding positive value.
    return subtract(context.encode(other));
  }

  /**
   * Multiplies an EncryptedNumber with this EncodedNumber.
   *
   * @param other EncryptedNumber to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(EncryptedNumber other) {
    return context.multiply(this, other);
  }

  /**
   * Multiplies another EncodedNumber with this EncodedNumber.
   *
   * @param other EncodedNumber to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(EncodedNumber other) {
    return context.multiply(this, other);
  }

  /**
   * Multiplies a Number with this EncodedNumber.
   *
   * @param other Number to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(Number other) {
    return multiply(context.encode(other));
  }

  /**
   * Multiplies a BigInteger with this EncodedNumber.
   *
   * @param other BigIntger to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(BigInteger other) {
    return multiply(context.encode(other));
  }

  /**
   * Multiplies a double with this EncodedNumber.
   *
   * @param other double to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(double other) {
    return multiply(context.encode(other));
  }

  /**
   * Multiplies a long with this EncodedNumber.
   *
   * @param other long to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(long other) {
    return multiply(context.encode(other));
  }

  // TODO Issue #10
    /*
    public EncodedNumber multiplicativeInverse() {
    	return context.multiplicativeInverse(this);
    }

    public EncodedNumber divide(EncodedNumber other) {
    	return context.divide(this, other);
    }

    public EncodedNumber divide(Number other) {
    	return divide(context.encode(other));
    }

    public EncodedNumber divide(BigInteger other) {
    	return divide(context.encode(other));
    }
    */

  /**
   * Divides this EncodedNumber with a double.
   *
   * @param other double to divide this with.
   * @return the division result.
   */
  public EncodedNumber divide(double other) {
    return multiply(context.encode(1.0 / other)); // TODO Issue #10: unhack
  }

  /**
   * Divides this EncodedNumber with a long.
   *
   * @param other long to divide this with.
   * @return the division result.
   */
  public EncodedNumber divide(long other) {
    return multiply(context.encode(1.0 / other)); // TODO Issue #10: unhack
  }

  @Override
  public int hashCode() {
    return new HashChain().chain(context).chain(value).hashCode();
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o == null || o.getClass() != EncodedNumber.class) {
      return false;
    }
    EncodedNumber number = (EncodedNumber) o;
    return context.equals(number.context) && value.equals(number.value);
  }

  public boolean equals(EncodedNumber o) {
    return o == this || (o != null &&
            context.equals(o.context) &&
            value.equals(o.value));
  }
}
