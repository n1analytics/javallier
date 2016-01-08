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
import com.n1analytics.paillier.util.FloatingPointUtil;
import com.n1analytics.paillier.util.HashChain;

import java.math.BigInteger;

// TODO Issue #7: maybe limit range of valid exponents so we don't blow up memory
// TODO Issue #16: take a RoundingMode maybe?

public final class Number {

  /**
   * Minimum exponent a non-zero subnormal double may have:
   *   Double.MIN_VALUE = 2^-1074.
   */
  public static final int DOUBLE_MIN_VALUE_EXPONENT = -1074;

  /**
   * Minimum exponent a normalised double may have:
   *   Double.MIN_NORMAL = 2^-1022.
   */
  public static final int DOUBLE_MIN_NORMAL_EXPONENT = -1022;

  /**
   * Maximum exponent a finite double may have:
   *   Double.MAX_VALUE = (2-(2^-52)) * 2^1023.
   */
  public static final int DOUBLE_MAX_VALUE_EXPONENT = 1023;

  /**
   * Number of bits in the two's-complement representation of Double.MAX_VALUE
   * when encode with DOUBLE_MIN_VALUE_EXPONENT.
   */
  public static final int DOUBLE_MAX_PRECISION = 2098;

  /**
   * The significand of this Number.
   */
  protected final BigInteger significand;

  /**
   * The exponent of this Number.
   */
  protected final int exponent;

  /**
   * Constructs a Number with a significand and an exponent.
   *
   * @param significand of this Number.
   * @param exponent of this Number.
   */
  public Number(BigInteger significand, int exponent) {
    if (significand == null) {
      throw new NullPointerException("significand must not be null");
    }
    this.significand = significand;
    this.exponent = exponent;
  }

  /**
   * Returns the significand of this number.
   *
   * @return the significand.
   */
  public BigInteger getSignificand() {
    return significand;
  }

  /**
   * Returns the exponent of this number.
   *
   * @return the exponent.
   */
  public int getExponent() {
    return exponent;
  }

  /**
   * Returns the signum function of this Number.
   *
   * @return -1, 0, or 1 as the value of this Number is negative, zero, or
   * positive.
   */
  public int signum() {
    return significand.signum();
  }

  /**
   * The number zero with respect to {@code exponent}.
   *
   * @param exponent the exponent of the fixed-point representation.
   * @return {@code Number(0, exponent)}.
   */
  public static Number zero(int exponent) {
    return new Number(BigInteger.ZERO, exponent);
  }

  /**
   * The number zero with respect to exponent 0.
   *
   * @return {@code Number(0, 0)}.
   */
  public static Number zero() {
    return new Number(BigInteger.ZERO, 0);
  }

  /**
   * The smallest positive fixed point number that can be encoded with respect
   * to the specified exponent.
   *
   * @param exponent the exponent of the fixed-point representation.
   * @return {@code Number(2<sup>exponent</sup>, exponent)}.
   */
  public static Number positiveEpsilon(int exponent) {
    return new Number(BigInteger.ONE, exponent);
  }

  /**
   * The negative fixed point number closest to zero that can be encoded with
   * respect to the specified exponent.
   *
   * @param exponent the exponent of the fixed-point representation.
   * @return {@code Number(-1 * 2<sup>exponent</sup>, exponent)}.
   */
  public static Number negativeEpsilon(int exponent) {
    return new Number(BigInteger.ONE.negate(), exponent);
  }

  /**
   * The number one with respect to {@code exponent}.
   *
   * Results in a Number object whose significand is
   * {@code 2<sup>-exponent</sup>} and whose exponent is {@code exponent}.
   *
   * @param exponent The exponent of the fixed-point representation.
   * @return {@code Number(2<sup>-exponent</sup>, exponent)}.
   * @throws IllegalArgumentException if {@code exponent} is greater than
   * zero.
   */
  public static Number one(int exponent) throws IllegalArgumentException {
    if (exponent > 0) {
      throw new IllegalArgumentException("Cannot represent one with a positive exponent");
    }
    return new Number(BigInteger.ONE.shiftRight(exponent), exponent);
  }

  /**
   * The number one represented with the minimal significand.
   *
   * @return {@code Number(1, 0)}.
   */
  public static Number one() {
    return new Number(BigInteger.ONE, 0);
  }

  /**
   * Encodes a BigInteger {@code value} to its minimal fixed-point
   * representation.
   *
   * The minimal fixed-point representation is the one with the highest
   * exponent that exactly represents {@code value}.
   *
   * @param value the value to encode.
   * @return the encoded value.
   */
  public static Number encode(BigInteger value) {
    return encodeToExponent(value, Math.max(0, value.getLowestSetBit()));
  }

  /**
   * Encodes a BigInteger as a fixed-point number with the supplied
   * {@code exponent}.
   *
   * Note that if {@code exponent} is too large then some (or all) of the
   * significant bits of {@code value} will be lost.
   *
   * @param value the value to encode.
   * @param exponent the exponent of the fixed-point representation.
   * @return the encoded number.
   */
  public static Number encodeToExponent(BigInteger value, int exponent) {
    return new Number(value.shiftRight(exponent), exponent);
  }

  /**
   * Encodes a BigInteger as a fixed-point Number using at
   * most {@code precision} bits for the significand.
   *
   * If the number of significant bits in {@code value} is less than or equal
   * to {@code precision} then it will be encoded exactly in its minimal form.
   * If the number of significant bits is greater then {@code precision} most
   * significant bits of {@code value} will become the significand and the
   * exponent will be chosen accordingly.
   *
   * @param value the value to encode.
   * @param precision the maximum number of binary digits in the significand.
   * @return the encoded number.
   * @throws IllegalArgumentException if {@code precision} is less than 1.
   */
  public static Number encodeToPrecision(BigInteger value, int precision)
          throws IllegalArgumentException {
    if (precision < 1) {
      throw new IllegalArgumentException("precision must be at least 1");
    }
    if (value.signum() == 0) {
      return new Number(value, 0);
    }
    final int lsb = value.getLowestSetBit();
    final int bitLength = value.abs().bitLength();
    final int exponent = Math.max(lsb, bitLength - precision);
    return new Number(value.shiftRight(exponent), exponent);
  }

  /**
   * Encodes a long to its minimal fixed-point representation.
   *
   * The minimal representation is the one with the highest exponent that
   * exactly represent {@code value}
   *
   * @param value the value to encode.
   * @return the encoded value.
   */
  public static Number encode(long value) {
    // TODO Issue #8: optimise
    return encode(BigInteger.valueOf(value));
  }

  /**
   * Encodes a long as a fixed-point Number with the supplied exponent.
   *
   * Note that if {@code exponent} is too large then some (or all) of the
   * significant bits of {@code value} will be lost.
   *
   * @param value the value to encode
   * @param exponent the exponent of the fixed-point representation.
   * @return the encoded number.
   */
  public static Number encodeToExponent(long value, int exponent) {
    // TODO Issue #8: optimise
    return encodeToExponent(BigInteger.valueOf(value), exponent);
  }

  /**
   * Encodes a long as a fixed-point Number using at most
   * {@code precision} bits for the significand.
   *
   * If the number of significant bits in {@code value} is less than or equal
   * to {@code precision} then it will be encoded exactly in its minimal form.
   * If the number of significant bits is greater then {@code precision} most
   * significant bits of {@code value} will become the significand and the
   * exponent will be chosen accordingly.
   *
   * @param value the value to encode.
   * @param precision the maximum number of binary digits in the significand.
   * @return the encoded number.
   * @throws IllegalArgumentException if {@code precision} is less than 1.
   */
  public static Number encodeToPrecision(long value, int precision)
          throws IllegalArgumentException {
    // TODO Issue #8: optimise
    return encodeToPrecision(BigInteger.valueOf(value), precision);
  }

  /**
   * Encodes a double {@code value} to its minimal fixed-point
   * representation.
   *
   * The minimal fixed-point representation is the one with the highest
   * exponent that exactly represents {@code value}.
   *
   * @param value the value to encode.
   * @return the encoded value.
   */
  public static Number encode(double value) throws EncodeException {
    return encodeToPrecision(value, FloatingPointUtil.DOUBLE_FRACTION_BITS + 1);
  }

  /**
   * Encodes a double as a fixed-point Number with the supplied exponent.
   *
   * Note that if {@code exponent} is too large then some (or all) of the
   * significant bits of {@code value} will be lost.
   *
   * @param value the value to encode
   * @param exponent the exponent of the fixed-point representation.
   * @return The encoded number.
   */
  public static Number encodeToExponent(double value, int exponent) {
    Number n = encode(value);
    return new Number(n.significand.shiftLeft(n.getExponent() - exponent), exponent);
  }

  /**
   * Encodes a double as a fixed-point Number using at most
   * {@code precision} bits for the significand.
   *
   * If the number of significant bits in {@code value} is less than or equal
   * to {@code precision} then it will be encoded exactly in its minimal form.
   * If the number of significant bits is greater then {@code precision} most
   * significant bits of {@code value} will become the significand and the
   * exponent will be chosen accordingly.
   *
   * Note that double-precision floating point numbers have at most 53
   * significant binary digits.
   *
   * @param value the value to encode.
   * @param precision the maximum number of binary digits in the significand.
   * @return the encoded number.
   * @throws EncodeException if {@code value} is infinite or NaN.
   * @throws IllegalArgumentException if {@code precision} is less than 1.
   */
  public static Number encodeToPrecision(double value, int precision)
          throws EncodeException, IllegalArgumentException {
    if (precision < 1) {
      throw new IllegalArgumentException("precision must be at least 1");
    }
    if (Double.isInfinite(value)) {
      throw new EncodeException("Cannot encode infinity");
    }
    if (Double.isNaN(value)) {
      throw new EncodeException("Cannot encode NaN");
    }

    // Extract the sign, exponent, and significand
    final long bits = Double.doubleToLongBits(value);
    final int sign = ((bits >> 63) == 0) ? 1 : -1;
    int exponent = (int) ((bits >> 52) & 0x7FFL);
    long significand = 0x000FFFFFFFFFFFFFL & bits;

    // Adjust the significand and exponent based on whether it is a
    // normalised or subnormal number. Return immediately if it is zero.
    if (exponent > 0) {
      significand |= 0x0010000000000000L;    // Normalised double
      exponent += DOUBLE_MIN_VALUE_EXPONENT - 1;
    } else if (significand > 0) {
      exponent += DOUBLE_MIN_VALUE_EXPONENT; // Subnormal double
    } else {
      return new Number(BigInteger.ZERO, 0); // Zero
    }

    // Increase the exponent so as to remove any trailing zeros
    final int trailingZeros = Long.numberOfTrailingZeros(significand);
    significand >>= trailingZeros;
    exponent += trailingZeros;

    // If necessary, remove the least significant bits of the significand
    // so that it does not exceed the desired precision.
    final int leadingZeros = Long.numberOfLeadingZeros(significand);
    final int significantBits = Long.SIZE - leadingZeros;
    final int excessBits = significantBits - precision;
    if (excessBits > 0) {
      significand >>= excessBits;
      exponent += excessBits;
    }

    // Return the encoded number
    return new Number(BigInteger.valueOf(sign * significand), exponent);
  }

  /**
   * Decodes this Number to the exact BigInteger representation. Throws ArithmeticException
   * if this Number cannot be represented as a BigInteger.
   *
   * @return the decoded number.
   * @throws ArithmeticException if this Number cannot be represented as a BigInteger.
   */

  public BigInteger decodeBigInteger() throws ArithmeticException {
    if (significand.equals(BigInteger.ZERO)) {
      return BigInteger.ZERO;
    }
    if (significand.getLowestSetBit() + exponent < 0) {
      throw new ArithmeticException("Cannot decode exactly");
    }
    return significand.shiftLeft(exponent);
  }

  /**
   * Decodes this Number to the approximate BigInteger representation.
   *
   * @return the decoded number.
   */
  public BigInteger decodeApproximateBigInteger() {
    return significand.shiftLeft(exponent);
  }

  /**
   * Decodes this Number to the exact long representation. Throws ArithmeticException
   * if this Number cannot be represented as a long.
   *
   * @return the decoded number.
   * @throws ArithmeticException if this Number cannot be represented as a long.
   */
  public long decodeLong() throws ArithmeticException {
    return BigIntegerUtil.longValueExact(decodeBigInteger());
  }

  /**
   * Decodes this Number to the approximate long representation.
   * If the number cannot be represented exactly as a long, it is converted
   * to the long representation of the lowest 64 bits.
   *
   * @return the decoded number.
   */
  public long decodeApproximateLong() {
    return decodeApproximateBigInteger().longValue();
  }

  // TODO Issue #6: maybe some isFiniteFloat, isFiniteDouble, etc.
  //      * isRepresentableAsLong
  //      * isValidLong
  //      * isFiniteDouble
  //

  /**
   * Decodes this Number to the exact double representation. Throws ArithmeticException
   * if this Number cannot be represented as a double.
   *
   * @return the decoded number.
   * @throws ArithmeticException if this cannot be represented as a @code double.
   */
  public double decodeDouble() throws ArithmeticException {
    return decodeDoubleImpl(true);
  }

  /**
   * Decodes this Number to the approximate double representation.
   *
   * @return the decoded number.
   */
  public double decodeApproximateDouble() {
    return decodeDoubleImpl(false);
  }

  /**
   * Implements the actual decoding to double.
   *
   * @param exact whether this Number needs to be decoded exactly or not.
   * @return the decoded number.
   */
  private double decodeDoubleImpl(boolean exact) {
    int signum = significand.signum();
    BigInteger absSignificand = significand.abs();
    int absSignificandLength = absSignificand.bitLength();
    int mostSignificantBitExponent = exponent + absSignificandLength - 1;

    // Handle zero
    if (signum == 0) {
      return 0.0;
    }

    // Handle very small values
    if (mostSignificantBitExponent < DOUBLE_MIN_VALUE_EXPONENT) {
      if (exact) {
        throw new ArithmeticException("Cannot decode exactly");
      }
      return 0.0;
    }

    // Handle very large values
    if (mostSignificantBitExponent > DOUBLE_MAX_VALUE_EXPONENT) {
      if (exact) {
        throw new ArithmeticException("Cannot decode exactly");
      }
      if (signum < 0) {
        return Double.NEGATIVE_INFINITY;
      } else {
        return Double.POSITIVE_INFINITY;
      }
    }

    long decodedSignum = (signum < 0) ? 1 : 0;
    long decodedExponent;
    long decodedSignificand;
    if (mostSignificantBitExponent < DOUBLE_MIN_NORMAL_EXPONENT) {
      // Handle subnormal number
      decodedExponent = 0;
      decodedSignificand = absSignificand.shiftLeft(
              exponent - DOUBLE_MIN_VALUE_EXPONENT).longValue();
    } else {
      // Handle normalised number
      decodedExponent = mostSignificantBitExponent - DOUBLE_MIN_NORMAL_EXPONENT + 1;
      decodedSignificand = ~0x0010000000000000L & absSignificand.shiftRight(
              absSignificandLength - 53).longValue();
    }

    long decodedBits = (decodedSignum << 63) |
            (decodedExponent << 52) |
            decodedSignificand;
    return Double.longBitsToDouble(decodedBits);
  }

  /**
   * Returns a Number whose value is the absolute value of this Number.
   *
   * @return {@code abs(this)}
   */
  public Number abs() {
    return signum() < 0 ? negate() : this;
  }

  /**
   * Adds an EncryptedNumber to this Number.
   *
   * @param other EncryptedNumber to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(EncryptedNumber other) {
    return other.add(this);
  }

  /**
   * Adds an EncodedNumber to this Number.
   *
   * @param other EncodedNumber to be added.
   * @return the addition result.
   */

  public EncodedNumber add(EncodedNumber other) {
    return other.add(this);
  }

  /**
   * Adds another Number to this NUmber. If the two Numbers have different exponents,
   * reduce the higher exponent to match with the lower exponent.
   *
   * @param other Number to be added.
   * @return the addition result.
   */
  public Number add(Number other) {
    if (exponent == other.exponent) {
      return new Number(significand.add(other.significand), exponent);
    }
    if (exponent < other.exponent) {
      return new Number(
              significand.add(other.significand.shiftLeft(other.exponent - exponent)),
              exponent);
    }
    return new Number(
            other.significand.add(significand.shiftLeft(exponent - other.exponent)),
            other.exponent);
  }

  /**
   * Adds a BigInteger to this Number.
   *
   * @param other BigInteger to be added.
   * @return the addition result.
   */
  public Number add(BigInteger other) {
    return add(Number.encode(other));
  }

  /**
   * Adds a double to this Number.
   *
   * @param other double to be added.
   * @return the addition result.
   */
  public Number add(double other) {
    return add(Number.encode(other));
  }

  /**
   * Adds a long to this Number.
   *
   * @param other long to be added.
   * @return the addition result.
   */
  public Number add(long other) {
    return add(Number.encode(other));
  }

  /**
   * Negates this Number, return a Number whose significand's value is {@code (-significand)}.
   *
   * @return {@code (-this)}
   */
  public Number negate() {
    return new Number(significand.negate(), exponent);
  }

  /**
   * Subtracts an EncryptedNumber from this Number.
   *
   * @param other EncryptedNumber to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(EncryptedNumber other) {
    return add(other.additiveInverse()); // TODO Issue #9: optimisation?
  }

  /**
   * Subtracts an EncodedNumber from this Number.
   *
   * @param other EncodedNumber to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(EncodedNumber other) {
    return add(other.additiveInverse()); // TODO Issue #9: optimisation?
  }

  /**
   * Subtracts a Number from this Number.
   *
   * @param other Number to be subtracted from this.
   * @return the subtraction result.
   */
  public Number subtract(Number other) {
    return add(other.negate()); // TODO Issue #9: optimise
  }

  /**
   * Subtracts a BigInteger from this Number.
   *
   * @param other BigInteger to be subtracted from this.
   * @return the subtraction result.
   */
  public Number subtract(BigInteger other) {
    return subtract(encode(other));
  }

  /**
   * Subtracts a double from this Number.
   *
   * @param other double to be subtracted from this.
   * @return the subtraction result.
   */
  public Number subtract(double other) {
    return subtract(encode(other));
  }

  /**
   * Subtracts a  long  from this Number.
   *
   * @param other long to be subtracted from this.
   * @return the subtraction result.
   */
  public Number subtract(long other) {
    // NOTE we don't do add(Number.encode(-value)) since
    //      Long.MIN_VALUE has no corresponding positive value.
    return subtract(encode(other));
  }

  /**
   * Multiplies an EncryptedNumber with this.
   *
   * @param other EncryptedNumber to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(EncryptedNumber other) {
    return other.multiply(this);
  }

  /**
   * Multiplies an EncodedNumber with this Number.
   *
   * @param other EncodedNumber to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(EncodedNumber other) {
    return other.multiply(this);
  }

  /**
   * Multiplies another Number with this Number.
   *
   * @param other Number to be multiplied with.
   * @return the multiplication result.
   */
  public Number multiply(Number other) {
    return new Number(significand.multiply(other.significand), exponent + other.exponent);
  }

  /**
   * Multiplies a BigInteger with this Number.
   *
   * @param other BigInteger to be multiplied with.
   * @return the multiplication result.
   */
  public Number multiply(BigInteger other) {
    return multiply(encode(other));
  }

  /**
   * Multiplies a double with this Number.
   *
   * @param other double to be multiplied with.
   * @return the multiplication result.
   */
  public Number multiply(double other) {
    return multiply(encode(other));
  }

  /**
   * Multiplies a long with this Number.
   *
   * @param other long to be multiplied with.
   * @return the multiplication result.
   */
  public Number multiply(long other) {
    return multiply(encode(other));
  }

  // TODO  Issue #10: - potentially dangerous
  /*
	public Number multiplicativeInverse() {
	    final BigInteger result = BigInteger.ONE
	    	.shiftRight(2 * exponent)
	    	.divide(significand);
	    return new Number(result, exponent);
	}
	
	public Number divide(Number other) {
		checkSameExponent(other);
		final BigInteger result = significand
			.shiftRight(exponent)
			.divide(other.significand);
		return new Number(result, exponent);
	}
	
	public Number divide(BigInteger other) {
		return divide(encode(other, exponent));
	}
	*/

  /**
   * Divides this Number with a double.
   *
   * @param other double to divide this with.
   * @return the division result.
   */
  public Number divide(double other) {
    return multiply(encode(1.0 / other)); // TODO Issue #10: unhack
  }

  /**
   * Divides this Number with a long.
   *
   * @param other long to divide this with.
   * @return the division result.
   */
  public Number divide(long other) {
    return multiply(encode(1.0 / (double) other)); // TODO Issue #10: unhack
  }
	
	/*
	public Number invert() {
		return Number.one(exponent).divide(this);
	}
	*/

  @Override
  public String toString() {
    return String.format("Number(exponent=%d, significand=%X)", exponent, significand);
  }

  @Override
  public int hashCode() {
    return new HashChain().chain(significand).chain(exponent).hashCode();
  }

  @Override
  public boolean equals(Object o) {
    return o == this || (o != null &&
            o.getClass() == Number.class &&
            equalsImpl((Number) o));
  }

  public boolean equals(Number o) {
    return o == this || (o != null && equalsImpl(o));
  }

  private boolean equalsImpl(Number o) {
    BigInteger s1 = significand;
    BigInteger s2 = o.significand;
    if (exponent > o.exponent) {
      s1 = s1.shiftLeft(exponent - o.exponent);
    } else if (exponent < o.exponent) {
      s2 = s2.shiftLeft(o.exponent - exponent);
    }
    return s1.equals(s2);
  }
}
