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
 * A class representing encoded numbers, which enables Paillier to operate on
 * negative integers and floating point numbers as well as non-negative
 * integers.
 */
public final class EncodedNumber {

  protected final PaillierContext context;
  protected final BigInteger value;
  protected final int exponent;

  /**
   * Construct an encoded number given an encoding and an encoded value. The
   * encoded value must be a non-negative integer less than
   * <code>context.getModulus()</code>.
   * @param context The context used to encode <code>value</code>.
   * @param value The encoded value.
   *
   * @param context Paillier context for this instance
   * @param value value to encode
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
   * Get the context with which this number is encoded.
   * @return The context.
   */
  public PaillierContext getContext() {
    return context;
  }

  /**
   * Get the encoded value.
   * @return The encoded value.
   */
  public BigInteger getValue() {
    return value;
  }

  public int getExponent() {
    return exponent;
  }

  public boolean isValid() {
    return context.isValid(this);
  }

    /* TODO what is an appropriate value for invalid numbers?
    public int signum() {
    	if(value.equals(BigInteger.ZERO))
    		return 0;
    	if(context.isUnsigned())
    		return 1;
    	return (value.compareTo(getModulusHalved()) <= 0) ? 1 : -1;
    }
    */

  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws ArithmeticException {
    return context.checkSameContext(other);
  }

  public EncodedNumber checkSameContext(EncodedNumber other) throws ArithmeticException {
    return context.checkSameContext(other);
  }

  /**
   * Decode this number to a fixed point representation.
   * @return The decoded number.
   */
  public Number decode() throws ArithmeticException {
    return context.decode(this);
  }

  public BigInteger decodeApproximateBigInteger() throws ArithmeticException {
    return decode().decodeApproximateBigInteger();
  }

  public BigInteger decodeBigInteger() throws ArithmeticException {
    return decode().decodeBigInteger();
  }

  public double decodeApproximateDouble() throws ArithmeticException {
    return decode().decodeApproximateDouble();
  }

  public double decodeDouble() throws ArithmeticException {
    return decode().decodeDouble();
  }

  public long decodeApproximateLong() throws ArithmeticException {
    return decode().decodeApproximateLong();
  }

  public long decodeLong() throws ArithmeticException {
    return decode().decodeLong();
  }

  /**
   * Re-encode this number with the specified context.
   * @param context The context to re-encode with.
   * @return The re-encoded number.
   */
  public EncodedNumber changeContext(PaillierContext context) {
    return context.encode(decode());
  }

  public EncryptedNumber encrypt() {
    return context.encrypt(this);
  }

  public EncryptedNumber add(EncryptedNumber other) {
    return context.add(this, other);
  }

  public EncodedNumber add(EncodedNumber other) {
    return context.add(this, other);
  }

  public EncodedNumber add(Number other) {
    return add(context.encode(other));
  }

  public EncodedNumber add(BigInteger other) {
    return add(context.encode(other));
  }

  public EncodedNumber add(double other) {
    return add(context.encode(other));
  }

  public EncodedNumber add(long other) {
    return add(context.encode(other));
  }

  public EncodedNumber additiveInverse() {
    return context.additiveInverse(this);
  }

  public EncryptedNumber subtract(EncryptedNumber other) {
    return context.subtract(this, other);
  }

  public EncodedNumber subtract(EncodedNumber other) {
    return context.subtract(this, other);
  }

  public EncodedNumber subtract(Number other) {
    return subtract(context.encode(other));
  }

  public EncodedNumber subtract(BigInteger other) {
    return subtract(context.encode(other));
  }

  public EncodedNumber subtract(double other) {
    return subtract(context.encode(other));
  }

  public EncodedNumber subtract(long other) {
    // NOTE it would be nice to do add(context.encode(-other)) however this
    //      would fail if other == Long.MIN_VALUE since it has no
    //      corresponding positive value.
    return subtract(context.encode(other));
  }

    /*
    public EncryptedNumber subtractUnobfuscated(EncryptedNumber other) {
        // TODO be careful not to use negate() otherwise it won't work when
        //      isSigned() == false
    }
    */

  public EncryptedNumber multiply(EncryptedNumber other) {
    return context.multiply(this, other);
  }

  public EncodedNumber multiply(EncodedNumber other) {
    return context.multiply(this, other);
  }

  public EncodedNumber multiply(Number other) {
    return multiply(context.encode(other));
  }

  public EncodedNumber multiply(BigInteger other) {
    return multiply(context.encode(other));
  }

  public EncodedNumber multiply(double other) {
    return multiply(context.encode(other));
  }

  public EncodedNumber multiply(long other) {
    return multiply(context.encode(other));
  }

  // TODO
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

  public EncodedNumber divide(double other) {
    return multiply(context.encode(1.0 / other)); // TODO unhack
  }

  public EncodedNumber divide(long other) {
    return multiply(context.encode(1.0 / other)); // TODO unhack
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
