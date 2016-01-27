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

/**
 * Represents an encoding scheme that allows signed fractional numbers to be
 * used in the Paillier cryptosystem. There are several attributes that define
 * an encoding scheme:
 * <ul>
 *   <li>
 *     A <code>PaillierPublicKey</code> used to generate this PaillierContext.
 *   </li>
 *   <li>
 *     A boolean <code>signed</code> that denotes whether the numbers
 *     represented are signed or unsigned.
 *   </li>
 *   <li>
 *     An integer <code>precision</code> that denotes the number of bits
 *     used to represent valid numbers that can be encrypted using
 *     the associated <code>PaillierPublicKey</code>. Setting this equal to the number
 *     of bits in the modulus results in the entire range of encoded numbers
 *     being valid, while setting it less than this results in a range of
 *     <code>(2<sup>precision</sup> + 1)</code> valid encoded numbers and
 *     <code>(modulus - 2<sup>precision</sup>)</code> invalid encoded numbers
 *     than can be used to (non-deterministically) detect overflows.
 *   </li>
 * </ul>
 *
 * PaillierContext defines the methods:
 * <ul>
 *     <li>To check whether another PaillierContext is the same as this PaillierContext</li>
 *     <li>To check whether a BigInteger, long, double, Number or EncodedNumber is valid</li>
 *     <li>To encode a BigInteger, long, double and Number to an EncodedNumber</li>
 *     <li>To decode an EncodedNumber to a Number, BigInteger, long or double</li>
 *     <li>To encrypt a BigInteger, long, double, Number and EncodedNumber</li>
 *     <li>To perform arithmetic computation (support addition, subtraction,
 *     limited multiplication and limited division)</li>
 * </ul>
 *
 * Note you can create a PaillierContext directly from the create methods
 * on a PaillierPublicKey e.g., createSignedContext.
 */
public class PaillierContext {

  /** The base for the encoded number */
  private static final int DEFAULT_BASE = 16;

//  private static final double LOG_2_BASE = Math.log((double) BASE)/ Math.log(2.0);

  // Source: http://docs.oracle.com/javase/specs/jls/se7/html/jls-4.html#jls-4.2.3
  private static final int DOUBLE_MANTISSA_BITS = 53;

  /**
   * The public key associated with this PaillierContext.
   */
  private final PaillierPublicKey publicKey;

  /**
   * The signed of this PaillierContext, denotes whether
   * the numbers represented are signed or unsigned.
   */
  private final boolean signed;

  /**
   * The precision of this PaillierContext, denotes the number of bits used to represent valid numbers
   * that can be encrypted using the associated {@code publicKey}.
   */
  private final int precision;

  /**
   * The maximum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the associated {@code publicKey}.
   */
  private final BigInteger maxEncoded;

  /**
   * The minimum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the associated {@code publicKey}.
   */
  private final BigInteger minEncoded;

  /**
   * The maximum {@code significand} of the {@code Number} that can be encrypted using
   * the associated {@code publicKey}.
   */
  private final BigInteger maxSignificand;

  /**
   * The minimum {@code significand} of the {@code Number} that can be encrypted using
   * the associated {@code publicKey}.
   */
  private final BigInteger minSignificand;

  private final int base;

  private final double log2Base;

  /**
   * Constructs a Paillier context based on a {@code PaillierPublicKey}, a boolean {@code signed}
   * to denote whether the context supports signed or unsigned numbers, and a {@code precision}
   * to denote the number of bits used to represent valid numbers.
   *
   * The method also derives the minimum/maximum {@code value} of {@code EncodedNumber} and
   * the minimum/maximum {@code significand} of {@code Number} that can be encrypted using the {@code PaillierPublicKey}.
   *
   * @param publicKey associated with this PaillierContext.
   * @param signed to denote whether this PaillierContext supports signed or unsigned numbers.
   * @param precision to denote the number of bits used to represent valid numbers.
   */
  public PaillierContext(PaillierPublicKey publicKey, boolean signed, int precision, int base) {
    if (publicKey == null) {
      throw new NullPointerException("publicKey must not be null");
    }
    if (precision < 1) {
      throw new IllegalArgumentException("Precision must be greater than zero");
    }
    if (signed && precision < 2) {
      throw new IllegalArgumentException(
              "Precision must be greater than one when signed is true");
    }

    final int modulusBitLength = publicKey.getModulus().bitLength();
    if (precision > modulusBitLength) {
      throw new IllegalArgumentException(
              "Precision must be less than or equal to the number of bits in the modulus");
    }

    this.publicKey = publicKey;
    this.signed = signed;
    this.precision = precision;
    this.base = base;
    this.log2Base = Math.log((double) base)/ Math.log(2.0);

    // Determines the appropriate values for maxEncoded, minEncoded,
    // maxSignificand, and minSignificand based on the signedness and
    // precision of the encoding scheme
    final boolean fullPrecision = precision == modulusBitLength;
    if (signed) {
      if (fullPrecision) {
        maxEncoded = publicKey.getModulus().shiftRight(1);
      } else {
        maxEncoded = BigInteger.ONE.shiftLeft(precision - 1).subtract(BigInteger.ONE);
      }
      minEncoded = publicKey.getModulus().subtract(maxEncoded);
      maxSignificand = maxEncoded;
      minSignificand = maxEncoded.negate();
    } else {
      if (fullPrecision) {
        maxEncoded = publicKey.getModulus().subtract(BigInteger.ONE);
      } else {
        maxEncoded = BigInteger.ONE.shiftLeft(precision).subtract(BigInteger.ONE);
      }
      minEncoded = BigInteger.ZERO;
      maxSignificand = maxEncoded;
      minSignificand = BigInteger.ZERO;
    }
  }

  public PaillierContext(PaillierPublicKey publicKey, boolean signed, int precision) {
    this(publicKey, signed, precision, DEFAULT_BASE);
  }

  /**
   * Returns the public key of this PaillierContext.
   *
   * @return public key.
   */
  public PaillierPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Checks whether this PaillierContext support signed numbers.
   *
   * @return true if this PaillierContext support signed numbers, false otherwise.
   */
  public boolean isSigned() {
    return signed;
  }

  /**
   * Checks whether this PaillierContext support unsigned numbers.
   *
   * @return true if this PaillierContext support unsigned numbers, false otherwise.
   */
  public boolean isUnsigned() {
    return !signed;
  }

  /**
   * Returns the precision of this PaillierContext.
   *
   * @return the precision.
   */
  public int getPrecision() {
    return precision;
  }

  /**
   * Checks whether this PaillierContext has full precision.
   *
   * @return true if this PaillierContext has full precision, false otherwise.
   */
  public boolean isFullPrecision() {
    return precision == publicKey.getModulus().bitLength();
  }

  /**
   * Returns the maximum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey}.
   *
   * @return the maximum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey}.
   */
  public BigInteger getMaxEncoded() {
    return maxEncoded;
  }

  /**
   * Returns the minimum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey}.
   *
   * @return the minimum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey}.
   */
  public BigInteger getMinEncoded() {
    return minEncoded;
  }

  /**
   * Returns the maximum {@code significand} of the {@code Number} that can be encrypted using
   * the {@code PaillierPublicKey}.
   *
   * @return the maximum {@code significand} of the {@code Number} that can be encrypted using
   * the {@code PaillierPublicKey}.
   */
  public BigInteger getMaxSignificand() {
    return maxSignificand;
  }

  /**
   * Returns the minimum {@code significand} of the {@code Number} that can be encrypted using
   * the {@code PaillierPublicKey}.
   *
   * @return the minimum {@code significand} of the {@code Number} that can be encrypted using
   * the {@code PaillierPublicKey}.
   */
  public BigInteger getMinSignificand() {
    return minSignificand;
  }

//  /**
//   * Returns the maximum {@code Number} for a given {@code exponent}, where the {@code Number}'s {@code significand}
//   * equals to the {@code maxSignificand}.
//   *
//   * @param exponent input.
//   * @return the maximum {@code Number} for a given {@code exponent}.
//   */
//  public Number getMax(int exponent) {
//    return new Number(maxSignificand, exponent);
//  }

//  /**
//   * Returns the maximum approximated {@code BigInteger} representation of the maximum {@code Number}
//   * for a given {@code exponent}.
//   *
//   * @param exponent input.
//   * @return the maximum {@code BigInteger} representation of the maximum {@code Number}
//   * for a given {@code exponent}.
//   */
//  public BigInteger getMaxBigInteger(int exponent) {
//    return getMax(exponent).decodeApproximateBigInteger();
//  }
//
//  /**
//   * Returns the maximum approximated {@code double} representation of the maximum {@code Number}
//   * for a given {@code exponent}.
//   *
//   * @param exponent input.
//   * @return the maximum approximated {@code double} representation of the maximum {@code Number}
//   * for a given {@code exponent}.
//   */
//  public double getMaxDouble(int exponent) {
//    return getMax(exponent).decodeApproximateDouble();
//  }
//
//  /**
//   * Returns the maximum approximated {@code long} representation of the maximum {@code Number}
//   * for a given {@code exponent}.
//   *
//   * @param exponent input.
//   * @return the maximum approximated {@code long} representation of the maximum {@code Number}
//   * for a given {@code exponent}.
//   */
//  public long getMaxLong(int exponent) {
//    BigInteger max = getMaxBigInteger(exponent);
//    if (max.compareTo(BigIntegerUtil.LONG_MAX_VALUE) >= 0) {
//      return Long.MAX_VALUE;
//    }
//    return max.longValue();
//  }

//  /**
//   * Returns the minimum {@code Number} for a given {@code exponent}, where the {@code Number}'s {@code significand}
//   * equals to the {@code minSignificand}.
//   *
//   * @param exponent input.
//   * @return the minimum {@code Number} for a given {@code exponent}, where the {@code Number}'s {@code significand}
//   * equals to the {@code minSignificand}.
//   */
//  public Number getMin(int exponent) {
//    return new Number(minSignificand, exponent);
//  }

//  /**
//   * Returns the minimum approximated {@code BigInteger} representation of the minimum {@code Number}
//   * for a given {@code exponent}.
//   *
//   * @param exponent input.
//   * @return the minimum approximated {@code BigInteger} representation of the minimum {@code Number}
//   * for a given {@code exponent}.
//   */
//  public BigInteger getMinBigInteger(int exponent) {
//    return getMin(exponent).decodeApproximateBigInteger();
//  }
//
//  /**
//   * Returns the minimum approximated {@code double} representation of the minimum {@code Number}
//   * for a given {@code exponent}.
//   *
//   * @param exponent input.
//   * @return the minimum approximated {@code double} representation of the minimum {@code Number}
//   * for a given {@code exponent}.
//   */
//  public double getMinDouble(int exponent) {
//    return getMin(exponent).decodeApproximateDouble();
//  }
//
//  /**
//   * Returns the minimum approximated {@code long} representation of the minimum {@code Number}
//   * for a given {@code exponent}.
//   *
//   * @param exponent input.
//   * @return the minimum approximated {@code long} representation of the minimum {@code Number}
//   * for a given {@code exponent}.
//   */
//  public long getMinLong(int exponent) {
//    BigInteger min = getMinBigInteger(exponent);
//    if (min.compareTo(BigIntegerUtil.LONG_MIN_VALUE) <= 0) {
//      return Long.MIN_VALUE;
//    }
//    return min.longValue();
//  }

  /**
   * Checks whether another {@code PaillierContext} is the same as this {@code PaillierContext}.
   *
   * @param context the {@code PaillierContext} to be compared to.
   * @throws PaillierContextMismatchException if the other {@code context} is not the same
   * as this {@code PaillierContext}.
   */
  public void checkSameContext(PaillierContext context)
          throws PaillierContextMismatchException {
    if (this == context) {
      return;
    }
    if (!publicKey.equals(context.publicKey)) {
      throw new PaillierContextMismatchException();
    }
    if (signed != context.signed) {
      throw new PaillierContextMismatchException();
    }
    if (precision != context.precision) {
      throw new PaillierContextMismatchException();
    }
  }

  /**
   * Checks whether an {@code EncryptedNumber} has the same context as this {@code PaillierContext}.
   * Throws an ArithmeticException if that is not the case.
   * Returns the unmodified {@code EncryptedNumber} so that it can be called inline.
   *
   * @param other the {@code EncryptedNumber} to compare to.
   * @return {@code other}.
   * @throws PaillierContextMismatchException If {@code other} has a
   * different context to this {@code PaillierContext}.
   */
  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws PaillierContextMismatchException {
    checkSameContext(other.getContext());
    return other;
  }

  /**
   * Checks whether an {@code EncodedNumber} has the same context as this {@code PaillierContext}.
   * Throws an ArithmeticException if that is not the case. Returns
   * the unmodified {@code EncodedNumber} so that it can be called inline.
   *
   * @param encoded the {@code EncodedNumber} to compare to.
   * @return {@code encoded}
   * @throws PaillierContextMismatchException If{@code encoded} has a
   * different context to this {@code PaillierContext}.
   */
  public EncodedNumber checkSameContext(EncodedNumber encoded)
          throws PaillierContextMismatchException {
    checkSameContext(encoded.getContext());
    return encoded;
  }

  /**
   * Checks whether an {@code EncodedNumber}'s {@code value} is valid, that is the {@code value}
   * can be encrypted using the associated {@code publicKey}. For an unsigned {@code PaillierContext},
   * a valid {@code value} is less than or equal to {@code maxEncoded}. While for a signed
   * {@code PaillierContext}, a valid {@code value} is less than or equal to {@code maxEncoded}
   * (for positive numbers) or is greater than or equal to {@code minEncoded} (for negative numbers).
   *
   * @param encoded the {@code EncodedNumber} to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(EncodedNumber encoded) {
    // NOTE signed == true implies minEncoded > maxEncoded
    if (!equals(encoded.getContext())) {
      return false;
    }
    if (encoded.getValue().compareTo(maxEncoded) <= 0) {
      return true;
    }
    if (signed && encoded.getValue().compareTo(minEncoded) >= 0) {
      return true;
    }
    return false;
  }

//  /**
//   * Checks whether a {@code Number}'s {@code significand} is valid, that is the {@code significand}
//   * can be encrypted using the associated {@code publicKey}. A valid {@code significand} is between
//   * {@code minSignificand} and {@code maxSignificand}.
//   *
//   * @param value the {@code Number} to be checked.
//   * @return true if it is valid, false otherwise.
//   */
//  public boolean isValid(Number value) {
//    if (value.getSignificand().compareTo(maxSignificand) > 0) {
//      return false;
//    }
//    if (value.getSignificand().compareTo(minSignificand) < 0) {
//      return false;
//    }
//    return true;
//  }

  /**
   * Checks whether a {@code BigInteger} is valid.
   *
   * @param value the {@code BigInteger} to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(BigInteger value) {
    // TODO Issue #12: optimise
//    return isValid(Number.encode(value));
    if (value.compareTo(maxSignificand) <= 0 && value.compareTo(minSignificand) >= 0) {
      return true;
    }
    return false;
  }

  /**
   * Checks whether a {@code double} is valid.
   *
   * @param value the {@code double} to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(double value) {
    // TODO Issue #12: optimise
    if(Double.isInfinite(value) || Double.isNaN(value))
      return false;

    BigInteger significand = innerEncode(new BigDecimal(value), getDoublePrecExponent(value));
    if((value > 0 && BigIntegerUtil.greater(significand, maxEncoded)) ||
            (value < 0 && BigIntegerUtil.less(significand, minEncoded))) {
//      System.out.println(value + " should be unencodable");
      return false;
    }

    return true;
  }

  /**
   * Checks whether a {@code long} is valid.
   *
   * @param value the {@code long} to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(long value) {
    // TODO Issue #12: optimise
//    return isValid(Number.encode(value));
    return isValid(encode(value));
  }

//  /**
//   * Encodes a {@code Number} using this {@code PaillierContext}.
//   *
//   * Checks whether the {@code Number} to be encoded is valid, throws an EncodeException if the {@code Number}
//   * is not valid. All {@code EncodedNumber}'s {@code value} must be between 0 and {@code publicKey.modulus - 1}.
//   * Hence, if the {@code Number}'s {@code significand} is negative, add {@code publicKey.getModulus()}
//   * to the {@code significand}.
//   *
//   * @param value the {@code Number} to be encoded.
//   * @return the encoding result.
//   * @throws EncodeException if the {@code value} is not valid.
//   */
//  public EncodedNumber encode(Number value) throws EncodeException {
//    if (!isValid(value)) {
//      throw new EncodeException();
//    }
//
//    BigInteger significand = value.getSignificand();
//    if (significand.signum() < 0) {
//      significand = significand.add(publicKey.getModulus());
//    }
//    return new EncodedNumber(this, significand, value.getExponent());
//  }

  /**
   * Encodes a {@code BigInteger} using this {@code PaillierContext}. Throws EncodeException if
   * the {@code Number} representation of the {@code BigInteger} to be encoded is not valid.
   *
   * @param value the {@code BigInteger} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(BigInteger value) throws EncodeException {
//    return encode(Number.encode(value));
    if (!isValid(value))
      throw new EncodeException();
    if (value.signum() < 0 && !isSigned()) {
      throw new EncodeException();
    }
    int exponent = 0;

    BigInteger significand = innerEncode(new BigDecimal(value), exponent);
//    if((value.signum() > 0 && BigIntegerUtil.greater(significand, maxEncoded)) ||
//            (value.signum() < 0 && BigIntegerUtil.less(significand, minEncoded))) {
//      System.out.println(value + " should be unencodable");
//    }
//    if(significand.signum() < 0)
//      System.out.println("Odd, why does the significand < 0?");
    return new EncodedNumber(this, significand, exponent);
  }

//  public EncodedNumber encode(BigInteger value, int maxExponent) {
//    if (!isValid(value))
//      throw new EncodeException();
//    if(maxExponent < 0)
//      throw new EncodeException("Max exponent must be >= 0.");
//    int exponent = getExponent(0, maxExponent);
//    return new EncodedNumber(this, innerEncode(new BigDecimal(value), exponent), exponent);
//  }

//  public EncodedNumber encode(BigInteger scalar, double precision) {
//    if(precision > 1 || precision <= 0)
//      throw new EncodeException("Precision must be 10^-i where i > 0.");
//    return innerEncode(new BigDecimal(scalar), getPrecExponent(precision));
//  }

  /**
   * Encodes a {@code double} using this {@code PaillierContext}. Throws an EncodeException if
   * the {@code Number} representation of the {@code double} to be encoded is not valid.
   *
   * @param value the {@code double} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(double value) throws EncodeException {
//    return encode(Number.encode(value));
    if (!isValid(value))
      throw new EncodeException();

    if (value < 0 && !isSigned()) {
      throw new EncodeException();
    }
    if (Double.isInfinite(value) || Double.isNaN(value))
      throw new EncodeException("Input value cannot be encoded.");

    int exponent = getDoublePrecExponent(value);
    return new EncodedNumber(this, innerEncode(new BigDecimal(value), exponent), exponent);
  }

  public EncodedNumber encode(double value, int maxExponent) {
    if (!isValid(value))
      throw new EncodeException();

    if (Double.isInfinite(value) || Double.isNaN(value))
      throw new EncodeException("Input value cannot be encoded.");

    if (maxExponent < 0)
      throw new EncodeException("Max exponent must be >= 0.");

    int exponent = getExponent(getDoublePrecExponent(value), maxExponent);
    return new EncodedNumber(this, innerEncode(new BigDecimal(value),
            getExponent(getDoublePrecExponent(value), maxExponent)), exponent);
  }

  public EncodedNumber encode(double value, double precision) {
    if (!isValid(value))
      throw new EncodeException();

    if (Double.isInfinite(value) || Double.isNaN(value))
      throw new EncodeException("Input value cannot be encoded.");

    if (precision > 1 || precision <= 0)
      throw new EncodeException("Precision  " + precision + ", it must be 10^-i where i > 0.");

    int exponent = getPrecExponent(precision);
    return new EncodedNumber(this, innerEncode(new BigDecimal(value), exponent), exponent);
  }

  /**
   * Encodes a {@code long} using this {@code PaillierContext}. Throws an EncodeException if
   * the {@code Number} representation of the {@code long} to be encoded is not valid.
   *
   * @param value the {@code long} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(long value) throws EncodeException {
//    return encode(Number.encode(value));
    if (value < 0 && !isSigned()) {
      throw new EncodeException();
    }

    return encode(BigInteger.valueOf(value));
  }

//  public EncodedNumber encode(long value, int maxExponent) {
//    if (maxExponent < 0)
//      throw new EncodeException("Max exponent must be >= 0.");
//    return encode(BigInteger.valueOf(value), maxExponent);
//  }

//  public EncodedNumber encode(long scalar, double precision) {
//    if (precision > 1 || precision <= 0)
//      throw new EncodeException("Precision must be 10^-i where i > 0.");
//    return encode(BigInteger.valueOf(scalar), precision);
//  }

  private int getPrecExponent(double precision) {
    return (int) Math.floor(Math.log(precision) / Math.log((double) base));
  }

  private int getDoublePrecExponent(double scalar) {
    int binFltExponent = Math.getExponent(scalar) + 1;
//        System.out.println("\t ENC - binFltExponent: " + binFltExponent);
    int binLsbExponent = binFltExponent - DOUBLE_MANTISSA_BITS;
//        System.out.println("\t ENC - binLsbExponent: " + binLsbExponent);
    return (int) Math.floor((double) binLsbExponent / log2Base);
  }

  private int getExponent(int precExponent, int maxExponent){
    return Math.min(precExponent, maxExponent);
  }

  private BigInteger innerEncode(BigDecimal scalar, int exponent) {
    // Compute BASE^(-exponent)
    BigDecimal bigDecBaseExponent = (new BigDecimal(base)).pow(-exponent, MathContext.DECIMAL128);
//    System.out.println("bigDecBaseExponent: " + bigDecBaseExponent.toString());

    // Compute the integer representation, ie, scalar * (BASE^-exponent)
    BigInteger bigIntRep =
            ((scalar.multiply(bigDecBaseExponent)).setScale(0, BigDecimal.ROUND_HALF_UP)).toBigInteger();
//    System.out.println("bigIntRep: " + (scalar.multiply(bigDecBaseExponent)).toString());

//    if(scalar.equals(BigDecimal.ONE.negate()))
//      System.out.println("original bigIntRep: " + bigIntRep);

    if (bigIntRep.signum() < 0) {
      bigIntRep = bigIntRep.add(publicKey.getModulus());
    }

//    if(scalar.equals(BigDecimal.ONE.negate()))
//      System.out.println("modified bigIntRep: " + bigIntRep);

    return bigIntRep;
  }

  // TODO test this
  public BigInteger getRescalingFactor(int expDiff) {
    return (new BigInteger(String.valueOf(base))).pow(expDiff);
  }

  // TODO test this
  public EncodedNumber decreaseExponentTo(EncodedNumber encodedNumber, int newExp) {
    BigInteger significand = encodedNumber.getValue();
    int exponent = encodedNumber.getExponent();
    if(newExp > exponent){
      throw new IllegalArgumentException("New exponent: "+ newExp +
              "should be more negative than old exponent: " + exponent + ".");
    }

    int expDiff = exponent - newExp;
    BigInteger bigFactor = getRescalingFactor(expDiff);
    BigInteger newEnc = significand.multiply(bigFactor);
    return new EncodedNumber(this, newEnc, newExp);
  }

//  /**
//   * Decodes to a {@code Number}.
//   *
//   * Checks whether the {@code EncodedNumber}'s {@code context} is the same as this {@code PaillierContext}.
//   * Decodes the {@code EncodedNumber} if the {@code value} is less than or equal to {@code maxEncoded}
//   * (for positive numbers) or if the {@code value} is greater than or equal to {@code minEncoded}
//   * (for negative numbers). Throws a DecodeException if the {@code EncodedNumber} cannot be decoded.
//   *
//   * @param encoded the {@code EncodedNumber} to be decoded.
//   * @return the decoding result.
//   * @throws DecodeException if the {@code encoded} cannot be decoded.
//   */
//  public Number decode(EncodedNumber encoded) throws DecodeException {
//    checkSameContext(encoded);
//    final BigInteger value = encoded.getValue();
//
//    // Non-negative
//    if (value.compareTo(maxEncoded) <= 0) {
//      return new Number(value, encoded.getExponent());
//    }
//
//    // Negative - note that negative encoded numbers are greater than
//    // non-negative encoded numbers and hence minEncoded > maxEncoded
//    if (signed && value.compareTo(minEncoded) >= 0) {
//      final BigInteger modulus = publicKey.getModulus();
//      return new Number(value.subtract(modulus), encoded.getExponent());
//    }
//
//    throw new DecodeException();
//  }

  private BigInteger getSignificand(EncodedNumber encoded) {
    checkSameContext(encoded);
    final BigInteger value = encoded.getValue();

    // Non-negative
    if (value.compareTo(maxEncoded) <= 0) {
      return value;
    }

    // Negative - note that negative encoded numbers are greater than
    // non-negative encoded numbers and hence minEncoded > maxEncoded
    if (signed && value.compareTo(minEncoded) >= 0) {
      final BigInteger modulus = publicKey.getModulus();
      return value.subtract(modulus);
    }

    throw new DecodeException();
  }

  /**
   * Decodes to the exact {@code BigInteger} representation. Throws a DecodeException
   * if the {@code EncodedNumber} cannot be decoded.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public BigInteger decodeBigInteger(EncodedNumber encoded) throws DecodeException {
//    return decode(encoded).decodeBigInteger();
    BigInteger significand = getSignificand(encoded);
    return significand.multiply((new BigInteger(String.valueOf(base))).pow(encoded.getExponent()));
  }

//  /**
//   * Decodes to the approximated {@code BigInteger} representation.Throws a DecodeException
//   * if the {@code EncodedNumber} cannot be decoded.
//   *
//   * @param encoded the {@code EncodedNumber} to be decoded.
//   * @return the decoding result.
//   * @throws DecodeException if the {@code encoded} cannot be decoded.
//   */
//  public BigInteger decodeApproximateBigInteger(EncodedNumber encoded)
//          throws DecodeException {
//    return decode(encoded).decodeApproximateBigInteger();
//  }

  /**
   * Decodes to the exact {@code double} representation.Throws a DecodeException
   * if the {@code EncodedNumber} cannot be decoded.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public double decodeDouble(EncodedNumber encoded) throws DecodeException {
//    return decode(encoded).decodeDouble();
    BigInteger significand = getSignificand(encoded);
    double decoded = significand.doubleValue() * Math.pow((double) base, (double) encoded.getExponent());

    if(Double.isInfinite(decoded) || Double.isNaN(decoded)) {
      throw new DecodeException("Decoded value cannot be represented as double.");
    }
    return decoded;
  }

//  /**
//   * Decodes to the approximated {@code double} representation. Throws a DecodeException
//   * if the {@code EncodedNumber} cannot be decoded.
//   *
//   * @param encoded the {@code EncodedNumber} to be decoded.
//   * @return the decoding result.
//   * @throws DecodeException if the {@code encoded} cannot be decoded.
//   */
//  public double decodeApproximateDouble(EncodedNumber encoded) throws DecodeException {
//    return decode(encoded).decodeApproximateDouble();
//  }

  /**
   * Decodes to the exact {@code long} representation. Throws a DecodeException
   * if the {@code EncodedNumber} cannot be decoded.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public long decodeLong(EncodedNumber encoded) throws DecodeException {
//    return decode(encoded).decodeLong();
    BigInteger decoded = decodeBigInteger(encoded);
    if(BigIntegerUtil.less(decoded, BigIntegerUtil.LONG_MIN_VALUE) ||
            BigIntegerUtil.greater(decoded, BigIntegerUtil.LONG_MAX_VALUE)) {
      throw new DecodeException("Decoded value cannot be represented as long.");
    }
    return decoded.longValue();

  }

//  /**
//   * Decodes to the approximated {@code long} representation. Throws a DecodeException
//   * if the {@code EncodedNumber} cannot be decoded.
//   *
//   * @param encoded the {@code EncodedNumber} to be decoded.
//   * @return the decoding result.
//   * @throws DecodeException if the {@code encoded} cannot be decoded.
//   */
//  public long decodeApproximateLong(EncodedNumber encoded) throws DecodeException {
//    return decode(encoded).decodeApproximateLong();
//  }

  /**
   * Obfuscates an {@code EncryptedNumber}.
   *
   * @param encrypted the {@code EncryptedNumber} to be obfuscated.
   * @return the obfuscated {@code EncryptedNumber}.
   */
  public EncryptedNumber obfuscate(EncryptedNumber encrypted) {
    checkSameContext(encrypted);
    final BigInteger obfuscated = publicKey.raw_obfuscate(encrypted.ciphertext);
    return new EncryptedNumber(this, obfuscated, encrypted.getExponent(), true);
  }

  /**
   * Encrypts an {@code EncodedNumber}.
   *
   * Checks whether the {@code EncodedNumber} to be encrypted has the same context as this {@code PaillierContext}.
   * Encrypts the {@code EncodedNumber}'s {@code value}. Note that the {@code exponent} is not encrypted and
   * the result {@code EncryptedNumber} is not obfuscated.
   *
   * @param encoded the {@code EncodedNumber} to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(EncodedNumber encoded) {
    checkSameContext(encoded);
    final BigInteger value = encoded.getValue();
    final BigInteger ciphertext = publicKey.raw_encrypt_without_obfuscation(value);
    return new EncryptedNumber(this, ciphertext, encoded.getExponent(), false);
  }

//  /**
//   * Encrypts a {@code Number}.
//   *
//   * @param value to be encrypted.
//   * @return the encryption result.
//   */
//  public EncryptedNumber encrypt(Number value) {
//    return encrypt(encode(value));
//  }

  /**
   * Encrypts a {@code BigInteger}.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(BigInteger value) {
    return encrypt(encode(value));
  }

  /**
   * Encrypts a {@code double}.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(double value) {
    return encrypt(encode(value));
  }

  /**
   * Encrypts a {@code long}.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(long value) {
    return encrypt(encode(value));
  }

//  /**
//   * Adds two EncryptedNumbers. Checks whether the {@code PaillierContext} of {@code operand1}
//   * and {@code operand2} are the same as this {@code PaillierContext}. If the operands' exponents
//   * are not the same, reduce the higher exponent to match with the lower exponent.
//   *
//   * @param operand1 first {@code EncryptedNumber}.
//   * @param operand2 second {@code EncryptedNumber}.
//   * @return the addition result.
//   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
//   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
//   */
//  public EncryptedNumber add(EncryptedNumber operand1, EncryptedNumber operand2)
//          throws PaillierContextMismatchException {
//    checkSameContext(operand1);
//    checkSameContext(operand2);
//    BigInteger value1 = operand1.ciphertext;
//    BigInteger value2 = operand2.ciphertext;
//    int exponent1 = operand1.getExponent();
//    int exponent2 = operand2.getExponent();
//    if (exponent1 > exponent2) {
//      value1 = publicKey.raw_multiply(value1, BigInteger.ONE.shiftLeft(exponent1 - exponent2));
//      exponent1 = exponent2;
//    } else if (exponent1 < exponent2) {
//      value2 = publicKey.raw_multiply(value2, BigInteger.ONE.shiftLeft(exponent2 - exponent1));
//      exponent2 = exponent1;
//    } // else do nothing
//    final BigInteger result = publicKey.raw_add(value1, value2);
//    return new EncryptedNumber(this, result, exponent1, operand1.isSafe && operand2.isSafe);
//  }

  public EncryptedNumber add(EncryptedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    BigInteger value1 = operand1.ciphertext;
    BigInteger value2 = operand2.ciphertext;
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    if (exponent1 > exponent2) {
      value1 = publicKey.raw_multiply(value1, getRescalingFactor(exponent1 - exponent2));
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = publicKey.raw_multiply(value2, getRescalingFactor(exponent2 - exponent1));
    } // else do nothing
    final BigInteger result = publicKey.raw_add(value1, value2);
    return new EncryptedNumber(this, result, exponent1, operand1.isSafe && operand2.isSafe);
  }

  /**
   * Adds an {@code EncryptedNumber} and an {@code EncodedNumber}. Encrypts the {@code EncodedNumber}
   * before adding them together.
   *
   * @param operand1 an {@code EncryptedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this PaillirContext.
   */
  public EncryptedNumber add(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, encrypt(operand2));
  }

  /**
   * Adds an {@code EncodedNumber} and an {@code EncryptedNumber}. Encrypts the {@code EncodedNumber}
   * before adding them together.
   *
   * @param operand1 an {@code EncodedNumber}.
   * @param operand2 an {@code EncryptedNumber}.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this PaillirContext.
   */
  public EncryptedNumber add(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return add(encrypt(operand1), operand2);
  }

//  /**
//   * Adds two {@code EncodedNumber}s. Checks whether the {@code PaillierContext} of {@code operand1}
//   * and {@code operand2} are the same as this {@code PaillierContext}. If the operands' exponents
//   * are not the same, reduce the higher exponent to match with the lower exponent.
//   *
//   * @param operand1 first {@code EncodedNumber}.
//   * @param operand2 second {@code EncodedNumber}.
//   * @return the addition result.
//   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
//   * {@code operand1} or {@code operand2} does not match this{@code PaillierContext}.
//   */
//  public EncodedNumber add(EncodedNumber operand1, EncodedNumber operand2)
//          throws PaillierContextMismatchException {
//    checkSameContext(operand1);
//    checkSameContext(operand2);
//    final BigInteger modulus = publicKey.getModulus();
//    BigInteger value1 = operand1.getValue();
//    BigInteger value2 = operand2.getValue();
//    int exponent1 = operand1.getExponent();
//    int exponent2 = operand2.getExponent();
//    if (exponent1 > exponent2) {
//      value1 = value1.shiftLeft(exponent1 - exponent2);
////			if(value1.compareTo(publicKey.getModulus()) > 0)
////				throw new ArithmeticException(); // TODO Issue #11: better ways to detect
//      exponent1 = exponent2;
//    } else if (exponent1 < exponent2) {
//      value2 = value2.shiftLeft(exponent2 - exponent1);
////			if(value2.compareTo(publicKey.getModulus()) > 0)
////				throw new ArithmeticException(); // TODO Issue #11: better ways to detect
//      exponent2 = exponent1;
//    } // else do nothing
//    // TODO Issue #11: check that nothing overflows
//    final BigInteger result = value1.add(value2).mod(modulus);
//    return new EncodedNumber(this, result, exponent1);
//  }

  public EncodedNumber add(EncodedNumber operand1, EncodedNumber operand2)
  throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger modulus = publicKey.getModulus();
    BigInteger value1 = operand1.getValue();
    BigInteger value2 = operand2.getValue();
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    if (exponent1 > exponent2) {
      value1 = value1.multiply(getRescalingFactor(exponent1 - exponent2));
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = value2.multiply(getRescalingFactor(exponent2 - exponent1));
    }
    final BigInteger result = value1.add(value2).mod(modulus);
    return new EncodedNumber(this, result, exponent1);
  }

  /**
   * Returns the additive inverse of {@code EncryptedNumber}.
   *
   * @param operand1 input.
   * @return the additive inverse result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of {@code operand1}
   * is not the same as this {@code PaillierContext}.
   */
  public EncryptedNumber additiveInverse(EncryptedNumber operand1)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    return new EncryptedNumber(operand1.getContext(), operand1.ciphertext.modInverse(
            operand1.getContext().getPublicKey().getModulusSquared()),
                               operand1.getExponent(), operand1.isSafe);
  }

  /**
   * Returns the additive inverse of an {@code EncodedNumber}.
   *
   * @param operand1 input.
   * @return the additive inverse.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of {@code operand1}
   * is not the same as this {@code PaillierContext}.
   */
  public EncodedNumber additiveInverse(EncodedNumber operand1)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    if (operand1.getValue().signum() == 0) {
      return operand1;
    }
    final BigInteger modulus = publicKey.getModulus();
    final BigInteger value1 = operand1.getValue();
    final BigInteger result = modulus.subtract(value1);
    return new EncodedNumber(this, result, operand1.getExponent());
  }

  /**
   * Subtracts an {@code EncryptedNumber} ({@code operand2}) from another {@code EncryptedNumber} ({@code operand1}).
   *
   * @param operand1 first {@code EncryptedNumber}.
   * @param operand2 second {@code EncryptedNumber}.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber subtract(EncryptedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    // TODO Issue #9: optimise
    checkSameContext(operand1);
    checkSameContext(operand2);
    return add(operand1, additiveInverse(operand2));
  }

  /**
   * Subtracts an {@code EncodedNumber} ({@code operand2}) from an {@code EncryptedNumber} ({@code operand1}).
   *
   * @param operand1 an {@code EncryptedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber subtract(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, encrypt(operand2.additiveInverse()));
  }

  /**
   * Subtracts an {@code EncryptedNumber} ({@code operand2}) from an {@code EncodedNumber} ({@code operand1}).
   *
   * @param operand1 an {@code EncodedNumber}.
   * @param operand2 an {@code EncryptedNumber}.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber subtract(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return subtract(encrypt(operand1), operand2);
  }

  /**
   * Subtracts an {@code EncodedNumber} ({@code operand2}) from another {@code EncodedNumber} ({@code operand1}).
   *
   * @param operand1 first {@code EncodedNumber}.
   * @param operand2 second {@code EncodedNumber}.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncodedNumber subtract(EncodedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, operand2.additiveInverse());
  }

  /**
   * Multiplies an EncyptedNumber with an {@code EncodedNumber}.
   *
   * @param operand1 an {@code EncryptedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the multiplication result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber multiply(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger value1 = operand1.ciphertext;
    final BigInteger value2 = operand2.getValue();
    final BigInteger result = publicKey.raw_multiply(value1, value2);
    final int exponent = operand1.getExponent() + operand2.getExponent();
    return new EncryptedNumber(this, result, exponent);
  }

  /**
   * Multiplies an {@code EncodedNumber} with an {@code EncryptedNumber}.
   *
   * @param operand1 an {@code EncodedNumber}.
   * @param operand2 an {@code EncryptedNumber}.
   * @return the multiplication result.
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncryptedNumber multiply(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return multiply(operand2, operand1);
  }

  /**
   * Multiplies two {@code EncodedNumber}s.
   *
   * @param operand1 an {@code EncodedNumber}.
   * @param operand2 an {@code EncodedNumber}.
   * @return the multiplication result
   * @throws PaillierContextMismatchException if the {@code PaillierContext} of either
   * {@code operand1} or {@code operand2} does not match this {@code PaillierContext}.
   */
  public EncodedNumber multiply(EncodedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger modulus = publicKey.getModulus();
    final BigInteger value1 = operand1.getValue();
    final BigInteger value2 = operand2.getValue();
    final BigInteger result = value1.multiply(value2).mod(modulus);
    final int exponent = operand1.getExponent() + operand2.getExponent();
    return new EncodedNumber(this, result, exponent);
  }

  // TODO Issue #10
  /*
	public EncodedNumber multiplicativeInverse(EncodedNumber operand1) throws
		PaillierContextMismatchException
	{
		checkSameContext(operand1);
		return encode(operand1.decode().multiplicativeInverse());
	}

	public EncryptedNumber divide(
		EncryptedNumber operand1,
		EncodedNumber operand2) throws
		PaillierContextMismatchException
	{
		return divideUnsafe(operand1, operand2).obfuscate();
	}

	public EncodedNumber divide(
		EncodedNumber operand1,
		EncodedNumber operand2) throws
		PaillierContextMismatchException
	{
		return multiply(operand1, multiplicativeInverse(operand2));
	}

	EncryptedNumber divideUnsafe(
		EncryptedNumber operand1,
		EncodedNumber operand2) throws
		PaillierContextMismatchException
	{
		checkSameContext(operand1);
		checkSameContext(operand2);
		return multiplyUnsafe(operand1, multiplicativeInverse(operand2));
	}
	*/

  @Override
  public int hashCode() {
    return new HashChain().chain(publicKey).chain(signed).chain(precision).hashCode();
  }

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o == null || o.getClass() != PaillierContext.class) {
      return false;
    }
    PaillierContext context = (PaillierContext) o;
    return publicKey.equals(context.publicKey) &&
            signed == context.signed &&
            precision == context.precision;
  }

  public boolean equals(PaillierContext o) {
    return o == this || (o != null &&
            publicKey.equals(o.publicKey) &&
            signed == o.signed &&
            precision == o.precision);
  }
}
