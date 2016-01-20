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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;

// TODO Issue #7: maybe limit range of valid exponents so we don't blow up memory
// TODO Issue #16: take a RoundingMode maybe?

/**
 * A class representing fixed-point numbers. The attributes of this class are:
 * <ul>
 *     <li>A BigInteger <code>significand</code> that represents the significand of the fixed-point number.</li>
 *     <li>An integer <code>exponent</code> that represents the exponent of the fixed-point number.</li>
 * </ul>
 *
 * This class defines the methods:
 * <ul>
 *     <li>To generate the fixed-point representation of zero and one</li>
 *     <li>To generate the smallest positive and negative fixed-point number that can be encoded
 *     with respect to the specified exponent</li>
 *     <li>To encode a BigInteger, long or double to a fixed-point number</li>
 *     <li>To decode to a BigInteger, long or double</li>
 *     <li>To perform arithmetic operations computation (support addition, subtraction, multiplication and division)</li>
 * </ul>
 */
public final class Number {

  /**
   * Minimum exponent a non-zero subnormal double may have:
   *   <code>Double.MIN_VALUE = 2<sup>-1074</sup></code>.
   */
  public static final int DOUBLE_MIN_VALUE_EXPONENT = -1074;

  /**
   * Minimum exponent a normalised double may have:
   *   <code>Double.MIN_NORMAL = 2<sup>-1022</sup></code>.
   */
  public static final int DOUBLE_MIN_NORMAL_EXPONENT = -1022;

  /**
   * Maximum exponent a finite double may have:
   *   <code>Double.MAX_VALUE = (2-(2<sup>-52</sup>)) * 2<sup>1023</sup></code>.
   */
  public static final int DOUBLE_MAX_VALUE_EXPONENT = 1023;

  /**
   * Number of bits in the two's-complement representation of <code>Double.MAX_VALUE</code>
   * when encode with <code>DOUBLE_MIN_VALUE_EXPONENT</code>.
   */
  public static final int DOUBLE_MAX_PRECISION = 2098;

  /**
   * The significand of this fixed-point number.
   */
  protected final BigInteger significand;

  /**
   * The exponent of this fixed-point number.
   */
  protected final int exponent;

  /**
   * Constructs a fixed-point number with a significand and an exponent.
   *
   * @param significand of this fixed-point number.
   * @param exponent of this fixed-point number.
   */
  public Number(BigInteger significand, int exponent) {
    if (significand == null) {
      throw new NullPointerException("significand must not be null");
    }
    this.significand = significand;
    this.exponent = exponent;
  }

  /**
   * Returns the {@code significand} of this fixed-point number.
   *
   * @return the {@code significand}.
   */
  public BigInteger getSignificand() {
    return significand;
  }

  /**
   * Returns the {@code exponent} of this fixed-point number.
   *
   * @return the {@code exponent}.
   */
  public int getExponent() {
    return exponent;
  }

  /**
   * Returns the signum function of this fixed-point number.
   *
   * @return -1, 0, or 1 as the value of this {@code Number} is negative, zero, or
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
   * The smallest positive fixed-point number that can be encoded with respect
   * to the specified exponent.
   *
   * @param exponent the exponent of the fixed-point representation.
   * @return <code>Number(2<sup>exponent</sup>, exponent)</code>.
   */
  public static Number positiveEpsilon(int exponent) {
    return new Number(BigInteger.ONE, exponent);
  }

  /**
   * The negative fixed-point number closest to zero that can be encoded with
   * respect to the specified exponent.
   *
   * @param exponent the exponent of the fixed-point representation.
   * @return <code>Number(-1 * 2<sup>exponent</sup>, exponent)</code>.
   */
  public static Number negativeEpsilon(int exponent) {
    return new Number(BigInteger.ONE.negate(), exponent);
  }

  /**
   * The number one with respect to {@code exponent}.
   *
   * Results in a {@code Number} object whose significand is
   * <code>2<sup>-exponent</sup></code> and whose exponent is {@code exponent}.
   *
   * @param exponent The exponent of the fixed-point representation.
   * @return <code>Number(2<sup>-exponent</sup>, exponent)</code>.
   * @throws IllegalArgumentException if {@code exponent} is greater than zero.
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

//  /**
//   * Encodes a {@code BigInteger} {@code value} to its minimal fixed-point
//   * representation.
//   *
//   * The minimal fixed-point representation is the one with the highest
//   * exponent that exactly represents {@code value}.
//   *
//   * @param value the value to encode.
//   * @return the encoded value.
//   */
//  public static Number encode(BigInteger value) {
//    return encodeToExponent(value, Math.max(0, value.getLowestSetBit()));
//  }
//
//  /**
//   * Encodes a {@code BigInteger} as a fixed-point {@code Number} with the supplied
//   * {@code exponent}.
//   *
//   * Note that if {@code exponent} is too large then some (or all) of the
//   * significant bits of {@code value} will be lost.
//   *
//   * @param value the value to encode.
//   * @param exponent the exponent of the fixed-point representation.
//   * @return the encoded number.
//   */
//  public static Number encodeToExponent(BigInteger value, int exponent) {
//    return new Number(value.shiftRight(exponent), exponent);
//  }
//
//  /**
//   * Encodes a {@code BigInteger} as a fixed-point {@code Number} using at
//   * most {@code precision} bits for the significand.
//   *
//   * If the number of significant bits in {@code value} is less than or equal
//   * to {@code precision} then it will be encoded exactly in its minimal form.
//   * If the number of significant bits is greater then {@code precision} most
//   * significant bits of {@code value} will become the significand and the
//   * exponent will be chosen accordingly.
//   *
//   * @param value the value to encode.
//   * @param precision the maximum number of binary digits in the significand.
//   * @return the encoded number.
//   * @throws IllegalArgumentException if {@code precision} is less than 1.
//   */
//  public static Number encodeToPrecision(BigInteger value, int precision)
//          throws IllegalArgumentException {
//    if (precision < 1) {
//      throw new IllegalArgumentException("precision must be at least 1");
//    }
//    if (value.signum() == 0) {
//      return new Number(value, 0);
//    }
//    final int lsb = value.getLowestSetBit();
//    final int bitLength = value.abs().bitLength();
//    final int exponent = Math.max(lsb, bitLength - precision);
//    return new Number(value.shiftRight(exponent), exponent);
//  }
//
//  /**
//   * Encodes a {@code long} to its minimal fixed-point representation.
//   *
//   * The minimal representation is the one with the highest exponent that
//   * exactly represent {@code value}
//   *
//   * @param value the value to encode.
//   * @return the encoded value.
//   */
//  public static Number encode(long value) {
//    // TODO Issue #8: optimise
//    return encode(BigInteger.valueOf(value));
//  }
//
//  /**
//   * Encodes a {@code long} as a fixed-point {@code Number} with the supplied exponent.
//   *
//   * Note that if {@code exponent} is too large then some (or all) of the
//   * significant bits of {@code value} will be lost.
//   *
//   * @param value the value to encode
//   * @param exponent the exponent of the fixed-point representation.
//   * @return the encoded number.
//   */
//  public static Number encodeToExponent(long value, int exponent) {
//    // TODO Issue #8: optimise
//    return encodeToExponent(BigInteger.valueOf(value), exponent);
//  }
//
//  /**
//   * Encodes a {@code long} as a fixed-point {@code Number} using at most
//   * {@code precision} bits for the significand.
//   *
//   * If the number of significant bits in {@code value} is less than or equal
//   * to {@code precision} then it will be encoded exactly in its minimal form.
//   * If the number of significant bits is greater then {@code precision} most
//   * significant bits of {@code value} will become the significand and the
//   * exponent will be chosen accordingly.
//   *
//   * @param value the value to encode.
//   * @param precision the maximum number of binary digits in the significand.
//   * @return the encoded number.
//   * @throws IllegalArgumentException if {@code precision} is less than 1.
//   */
//  public static Number encodeToPrecision(long value, int precision)
//          throws IllegalArgumentException {
//    // TODO Issue #8: optimise
//    return encodeToPrecision(BigInteger.valueOf(value), precision);
//  }
//
//  /**
//   * Encodes a {@code double} {@code value} to its minimal fixed-point
//   * representation.
//   *
//   * The minimal fixed-point representation is the one with the highest
//   * exponent that exactly represents {@code value}.
//   *
//   * @param value the value to encode.
//   * @return the encoded value.
//   */
//  public static Number encode(double value) throws EncodeException {
//    return encodeToPrecision(value, FloatingPointUtil.DOUBLE_FRACTION_BITS + 1);
//  }
//
//  /**
//   * Encodes a {@code double} as a fixed-point {@code Number} with the supplied exponent.
//   *
//   * Note that if {@code exponent} is too large then some (or all) of the
//   * significant bits of {@code value} will be lost.
//   *
//   * @param value the value to encode
//   * @param exponent the exponent of the fixed-point representation.
//   * @return The encoded number.
//   */
//  public static Number encodeToExponent(double value, int exponent) {
//    Number n = encode(value);
//    return new Number(n.significand.shiftLeft(n.getExponent() - exponent), exponent);
//  }
//
//  /**
//   * Encodes a {@code double} as a fixed-point {@code Number} using at most
//   * {@code precision} bits for the significand.
//   *
//   * If the number of significant bits in {@code value} is less than or equal
//   * to {@code precision} then it will be encoded exactly in its minimal form.
//   * If the number of significant bits is greater then {@code precision} most
//   * significant bits of {@code value} will become the significand and the
//   * exponent will be chosen accordingly.
//   *
//   * Note that double-precision floating point numbers have at most 53
//   * significant binary digits.
//   *
//   * @param value the value to encode.
//   * @param precision the maximum number of binary digits in the significand.
//   * @return the encoded number.
//   * @throws EncodeException if {@code value} is infinite or NaN.
//   * @throws IllegalArgumentException if {@code precision} is less than 1.
//   */
//  public static Number encodeToPrecision(double value, int precision)
//          throws EncodeException, IllegalArgumentException {
//    if (precision < 1) {
//      throw new IllegalArgumentException("precision must be at least 1");
//    }
//    if (Double.isInfinite(value)) {
//      throw new EncodeException("Cannot encode infinity");
//    }
//    if (Double.isNaN(value)) {
//      throw new EncodeException("Cannot encode NaN");
//    }
//
//    // Extract the sign, exponent, and significand
//    final long bits = Double.doubleToLongBits(value);
//    final int sign = ((bits >> 63) == 0) ? 1 : -1;
//    int exponent = (int) ((bits >> 52) & 0x7FFL);
//    long significand = 0x000FFFFFFFFFFFFFL & bits;
//
//    // Adjust the significand and exponent based on whether it is a
//    // normalised or subnormal number. Return immediately if it is zero.
//    if (exponent > 0) {
//      significand |= 0x0010000000000000L;    // Normalised double
//      exponent += DOUBLE_MIN_VALUE_EXPONENT - 1;
//    } else if (significand > 0) {
//      exponent += DOUBLE_MIN_VALUE_EXPONENT; // Subnormal double
//    } else {
//      return new Number(BigInteger.ZERO, 0); // Zero
//    }
//
//    // Increase the exponent so as to remove any trailing zeros
//    final int trailingZeros = Long.numberOfTrailingZeros(significand);
//    significand >>= trailingZeros;
//    exponent += trailingZeros;
//
//    // If necessary, remove the least significant bits of the significand
//    // so that it does not exceed the desired precision.
//    final int leadingZeros = Long.numberOfLeadingZeros(significand);
//    final int significantBits = Long.SIZE - leadingZeros;
//    final int excessBits = significantBits - precision;
//    if (excessBits > 0) {
//      significand >>= excessBits;
//      exponent += excessBits;
//    }
//
//    // Return the encoded number
//    return new Number(BigInteger.valueOf(sign * significand), exponent);
//  }

    /** The base for the encoded number */
  private static final int BASE = 16;

  private static final double LOG_2_BASE = Math.log((double) BASE)/ Math.log(2.0);

  // Source: http://docs.oracle.com/javase/specs/jls/se7/html/jls-4.html#jls-4.2.3
  private static final int DOUBLE_MANTISSA_BITS = 53;

  public static Number encode(BigInteger scalar) {
    return innerEncode(new BigDecimal(scalar), 0);
  }

  public static Number encode(BigInteger scalar, int maxExponent) {
    if(maxExponent >= 0)
      return innerEncode(new BigDecimal(scalar), getExponent(0, maxExponent));

    throw new EncodeException("maxExponent must be a positive integer");
  }

  public static Number encode(BigInteger scalar, double precision) {
    if(precision >= 1)
      return innerEncode(new BigDecimal(scalar), getPrecExponent(precision));

    throw new EncodeException("maxExponent must be greater than 1");
  }

  public static Number encode(long scalar) {
    return innerEncode(new BigDecimal(scalar), 0);
  }

  public static Number encode(long scalar, int maxExponent) {
    return encode(BigInteger.valueOf(scalar), maxExponent);
  }

  public static Number encode(long scalar, double precision) {
    return encode(BigInteger.valueOf(scalar), precision);
  }

  public static Number encode(double scalar) {
    return innerEncode(new BigDecimal(String.valueOf(scalar)), getDoublePrecExponent(scalar));
  }

  public static Number encode(double scalar, int maxExponent) {
    return innerEncode(new BigDecimal(String.valueOf(scalar)),
            getExponent(getDoublePrecExponent(scalar), maxExponent));
  }

  public static Number encode(double scalar, double precision) {
    return innerEncode(new BigDecimal(String.valueOf(scalar)), getPrecExponent(precision));
  }

  private static int getPrecExponent(double precision) {
    return (int) Math.floor(Math.log(precision) / Math.log((double) BASE));
  }

  private static int getDoublePrecExponent(double scalar) {
    int binFltExponent = Math.getExponent(scalar) + 1;
//        System.out.println("\t ENC - binFltExponent: " + binFltExponent);
    int binLsbExponent = binFltExponent - DOUBLE_MANTISSA_BITS;
//        System.out.println("\t ENC - binLsbExponent: " + binLsbExponent);
    return (int) Math.floor((double) binLsbExponent / LOG_2_BASE);
  }

  private static int getExponent(int precExponent, int maxExponent){
    return Math.min(precExponent, maxExponent);
  }

  private static Number innerEncode(BigDecimal scalar, int exponent) {
    // Compute BASE^(-exponent)
    BigDecimal bigDecBaseExponent = (new BigDecimal(BASE)).pow(-exponent, MathContext.DECIMAL128);
//    System.out.println("bigDecBaseExponent: " + bigDecBaseExponent.toString());

    // Compute the integer representation, ie, scalar * (BASE^-exponent)
    BigInteger bigIntRep =
            ((scalar.multiply(bigDecBaseExponent)).setScale(0, BigDecimal.ROUND_HALF_UP)).toBigInteger();
//    System.out.println("bigIntRep: " + (scalar.multiply(bigDecBaseExponent)).toString());

    return new Number(bigIntRep, exponent);
  }

//  /**
//   * Decodes this {@code Number} to the exact {@code BigInteger} representation. Throws ArithmeticException
//   * if this {@code Number} cannot be represented as a {@code BigInteger} (i.e., if {@code exponent < 0} and
//   * the {@code significand.getLowestSetBit() < abs(exponent)}).
//   *
//   * @return the decoded number.
//   * @throws ArithmeticException if this {@code Number} cannot be represented as a {@code BigInteger}.
//   */
//
//  public BigInteger decodeBigInteger() throws ArithmeticException {
//    if (significand.equals(BigInteger.ZERO)) {
//      return BigInteger.ZERO;
//    }
//    if (significand.getLowestSetBit() + exponent < 0) {
//      throw new ArithmeticException("Cannot decode exactly");
//    }
//    return significand.shiftLeft(exponent);
//  }
//
//  /**
//   * Decodes this {@code Number} to the approximate {@code BigInteger} representation.
//   *
//   * @return the decoded number.
//   */
//  public BigInteger decodeApproximateBigInteger() {
//    return significand.shiftLeft(exponent);
//  }
//
//  /**
//   * Decodes this {@code Number} to the exact {@code long} representation. Throws ArithmeticException
//   * if this {@code Number} cannot be represented as a {@code long} (i.e., if the {@code BigInteger}
//   * representation of the decoded number is not between {@code Long.MIN_VALUE} and
//   * the {@code Long.MAX_VALUE}).
//   *
//   * @return the decoded number.
//   * @throws ArithmeticException if this {@code Number} cannot be represented as a {@code long}.
//   */
//  public long decodeLong() throws ArithmeticException {
//    return BigIntegerUtil.longValueExact(decodeBigInteger());
//  }
//
//  /**
//   * Decodes this {@code Number} to the approximate {@code long} representation.
//   * If the number cannot be represented exactly as a {@code long}, it is converted
//   * to the {@code long} representation of the lowest 64 bits.
//   *
//   * @return the decoded number.
//   */
//  public long decodeApproximateLong() {
//    return decodeApproximateBigInteger().longValue();
//  }
//
//  // TODO Issue #6: maybe some isFiniteFloat, isFiniteDouble, etc.
//  //      * isRepresentableAsLong
//  //      * isValidLong
//  //      * isFiniteDouble
//  //
//
//  /**
//   * Decodes this {@code Number} to the exact {@code double} representation. Throws ArithmeticException
//   * if this {@code Number} cannot be represented as a {@code double} (i.e., if the number is less than
//   * {@code Double.MIN_VALUE} or greater than {@code Double.MAX_VALUE}).
//   *
//   * @return the decoded number.
//   * @throws ArithmeticException if this cannot be represented as a @code {@code double}.
//   */
//  public double decodeDouble() throws ArithmeticException {
//    return decodeDoubleImpl(true);
//  }
//
//  /**
//   * Decodes this {@code Number} to the approximate {@code double} representation. Returns 0 if the number is
//   * less than {@code Double.MIN_VALUE}. Returns {@code Double.NEGATIVE_INFINITY} or
//   * {@code Double.POSITIVE_INFINITY} if the number is greater than {@code Double.MAX_VALUE}.
//   *
//   * @return the decoded number.
//   */
//  public double decodeApproximateDouble() {
//    return decodeDoubleImpl(false);
//  }
//
//  /**
//   * Implements the actual decoding to {@code double}.
//   *
//   * @param exact whether this {@code Number} needs to be decoded exactly or not.
//   * @return the decoded number.
//   */
//  private double decodeDoubleImpl(boolean exact) {
//    int signum = significand.signum();
//    BigInteger absSignificand = significand.abs();
//    int absSignificandLength = absSignificand.bitLength();
//    int mostSignificantBitExponent = exponent + absSignificandLength - 1;
//
//    // Handle zero
//    if (signum == 0) {
//      return 0.0;
//    }
//
//    // Handle very small values
//    if (mostSignificantBitExponent < DOUBLE_MIN_VALUE_EXPONENT) {
//      if (exact) {
//        throw new ArithmeticException("Cannot decode exactly");
//      }
//      return 0.0;
//    }
//
//    // Handle very large values
//    if (mostSignificantBitExponent > DOUBLE_MAX_VALUE_EXPONENT) {
//      if (exact) {
//        throw new ArithmeticException("Cannot decode exactly");
//      }
//      if (signum < 0) {
//        return Double.NEGATIVE_INFINITY;
//      } else {
//        return Double.POSITIVE_INFINITY;
//      }
//    }
//
//    long decodedSignum = (signum < 0) ? 1 : 0;
//    long decodedExponent;
//    long decodedSignificand;
//    if (mostSignificantBitExponent < DOUBLE_MIN_NORMAL_EXPONENT) {
//      // Handle subnormal number
//      decodedExponent = 0;
//      decodedSignificand = absSignificand.shiftLeft(
//              exponent - DOUBLE_MIN_VALUE_EXPONENT).longValue();
//    } else {
//      // Handle normalised number
//      decodedExponent = mostSignificantBitExponent - DOUBLE_MIN_NORMAL_EXPONENT + 1;
//      decodedSignificand = ~0x0010000000000000L & absSignificand.shiftRight(
//              absSignificandLength - 53).longValue();
//    }
//
//    long decodedBits = (decodedSignum << 63) |
//            (decodedExponent << 52) |
//            decodedSignificand;
//    return Double.longBitsToDouble(decodedBits);
//  }

  public Number decreaseExponentTo(int newExp) {
    if(newExp > exponent){
      throw new IllegalArgumentException("New exponent: "+ newExp +
              "should be more negative than old exponent: " + exponent + ".");
    }

    int expDiff = exponent - newExp;
    BigInteger bigFactor = getRescalingFactor(expDiff);
    BigInteger newEnc = significand.multiply(bigFactor);
    return new Number(newEnc, newExp);
  }

  public static BigInteger getRescalingFactor(int expDiff) {
    return (new BigInteger(String.valueOf(BASE))).pow(expDiff);
  }

  public BigInteger decodeBigInteger() {
    return significand.multiply((new BigInteger(String.valueOf(BASE))).pow(exponent));
  }

  public long decodeLong() {
    BigInteger decoded = decodeBigInteger();
    if(BigIntegerUtil.less(decoded, BigIntegerUtil.LONG_MIN_VALUE) ||
            BigIntegerUtil.greater(decoded, BigIntegerUtil.LONG_MAX_VALUE)) {
      throw new DecodeException("Decoded value cannot be represented as long.");
    }
    return decoded.longValue();
  }

  public double decodeDouble() {
    double decoded = significand.doubleValue() * Math.pow((double) BASE, (double) exponent);
    if(Double.isInfinite(decoded) || Double.isNaN(decoded)) {
      throw new DecodeException("Decoded value cannot be represented as double.");
    }
    return decoded;
  }

  /**
   * Returns a {@code Number} whose value is the absolute value of this {@code Number}.
   *
   * @return {@code abs(this)}
   */
  public Number abs() {
    return signum() < 0 ? negate() : this;
  }

  /**
   * Adds an {@code EncryptedNumber} to this {@code Number}.
   *
   * @param other {@code EncryptedNumber} to be added.
   * @return the addition result.
   */
  public EncryptedNumber add(EncryptedNumber other) {
    return other.add(this);
  }

  /**
   * Adds an {@code EncodedNumber} to this {@code Number}.
   *
   * @param other {@code EncodedNumber} to be added.
   * @return the addition result.
   */

  public EncodedNumber add(EncodedNumber other) {
    return other.add(this);
  }

//  /**
//   * Adds another {@code Number} to this {@code Number}.
//   *
//   * If the two {@code Number}s have the same exponent, returns a new {@code Number} where
//   * {@code significand = this.significand + other.significand} and {@code exponent = this.exponent}.
//   * If this {@code Number}'s exponent is less than the {@code other}'s exponent,
//   * re-encode the {@code other} with this {@code exponent} before performing the addition.
//   * If the {@code other}'s exponent is less than this {@code Number}'s exponent,
//   * re-encode this {@code Number} with the {@code other}'s  {@code exponent} before performing
//   * the addition.
//   *
//   * @param other {@code Number} to be added.
//   * @return the addition result.
//   */
//  public Number add(Number other) {
//    if (exponent == other.exponent) {
//      return new Number(significand.add(other.significand), exponent);
//    }
//    if (exponent < other.exponent) {
//      return new Number(
//              significand.add(other.significand.shiftLeft(other.exponent - exponent)),
//              exponent);
//    }
//    return new Number(
//            other.significand.add(significand.shiftLeft(exponent - other.exponent)),
//            other.exponent);
//  }

  public Number add(Number other) {
    BigInteger significand1 = significand;
    BigInteger significand2 = other.getSignificand();
    int exponent1 = exponent;
    int exponent2 = other.getExponent();

    if(exponent1 < exponent2) {
      return new Number(significand1.add(significand2.multiply(getRescalingFactor(exponent2 - exponent1))), exponent1);
    } else if(exponent1 > exponent2) {
      return new Number(significand2.add(significand1.multiply(getRescalingFactor(exponent1 - exponent2))), exponent2);
    } else {
      return new Number(significand1.add(significand2), exponent1);
    }
  }

  /**
   * Adds a {@code BigInteger} to this {@code Number}.
   *
   * @param other {@code BigInteger} to be added.
   * @return the addition result.
   */
  public Number add(BigInteger other) {
    return add(Number.encode(other));
  }

  /**
   * Adds a {@code double} to this {@code Number}.
   *
   * @param other {@code double} to be added.
   * @return the addition result.
   */
  public Number add(double other) {
    return add(Number.encode(other));
  }

  /**
   * Adds a {@code long} to this {@code Number}.
   *
   * @param other {@code long} to be added.
   * @return the addition result.
   */
  public Number add(long other) {
    return add(Number.encode(other));
  }

  /**
   * Negates this {@code Number}, return a {@code Number} whose significand's value is {@code (-significand)}.
   *
   * @return {@code (-this)}
   */
  public Number negate() {
    return new Number(significand.negate(), exponent);
  }

  /**
   * Subtracts an {@code EncryptedNumber} from this {@code Number}.
   *
   * @param other {@code EncryptedNumber} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncryptedNumber subtract(EncryptedNumber other) {
    return add(other.additiveInverse()); // TODO Issue #9: optimisation?
  }

  /**
   * Subtracts an {@code EncodedNumber} from this {@code Number}.
   *
   * @param other {@code EncodedNumber} to be subtracted from this.
   * @return the subtraction result.
   */
  public EncodedNumber subtract(EncodedNumber other) {
    return add(other.additiveInverse()); // TODO Issue #9: optimisation?
  }

  /**
   * Subtracts a {@code Number} from this {@code Number}.
   *
   * @param other Number to be subtracted from this.
   * @return the subtraction result.
   */
  public Number subtract(Number other) {
    return add(other.negate()); // TODO Issue #9: optimise
  }

  /**
   * Subtracts a {@code BigInteger} from this {@code Number}.
   *
   * @param other {@code BigInteger} to be subtracted from this.
   * @return the subtraction result.
   */
  public Number subtract(BigInteger other) {
    return subtract(encode(other));
  }

  /**
   * Subtracts a {@code double} from this {@code Number}.
   *
   * @param other {@code double} to be subtracted from this.
   * @return the subtraction result.
   */
  public Number subtract(double other) {
    return subtract(encode(other));
  }

  /**
   * Subtracts a {@code long} from this {@code Number}.
   *
   * @param other {@code long} to be subtracted from this.
   * @return the subtraction result.
   */
  public Number subtract(long other) {
    // NOTE we don't do add(Number.encode(-value)) since
    //      Long.MIN_VALUE has no corresponding positive value.
    return subtract(encode(other));
  }

  /**
   * Multiplies an {@code EncryptedNumber} with this.
   *
   * @param other {@code EncryptedNumber} to be multiplied with.
   * @return the multiplication result.
   */
  public EncryptedNumber multiply(EncryptedNumber other) {
    return other.multiply(this);
  }

  /**
   * Multiplies an {@code EncodedNumber} with this {@code Number}.
   *
   * @param other {@code EncodedNumber} to be multiplied with.
   * @return the multiplication result.
   */
  public EncodedNumber multiply(EncodedNumber other) {
    return other.multiply(this);
  }

  /**
   * Multiplies another {@code Number} with this {@code Number}.
   * Returns a new {@code Number} where {@code significand = this.significand * other.significand}
   * and {@code exponent = this.exponent + other.exponent}.
   *
   * @param other Number to be multiplied with.
   * @return the multiplication result.
   */
  public Number multiply(Number other) {
    return new Number(significand.multiply(other.significand), exponent + other.exponent);
  }

  /**
   * Multiplies a {@code BigInteger} with this {@code Number}.
   *
   * @param other {@code BigInteger} to be multiplied with.
   * @return the multiplication result.
   */
  public Number multiply(BigInteger other) {
    return multiply(encode(other));
  }

  /**
   * Multiplies a {@code double} with this {@code Number}.
   *
   * @param other {@code double} to be multiplied with.
   * @return the multiplication result.
   */
  public Number multiply(double other) {
    return multiply(encode(other));
  }

  /**
   * Multiplies a {@code long} with this {@code Number}.
   *
   * @param other {@code long} to be multiplied with.
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
   * Divides this {@code Number} with a {@code double}.
   *
   * @param other {@code double} to divide this with.
   * @return the division result.
   */
  public Number divide(double other) {
    return multiply(encode(1.0 / other)); // TODO Issue #10: unhack
  }

  /**
   * Divides this {@code Number} with a {@code long}.
   *
   * @param other {@code long} to divide this with.
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
