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
 * Represents an encoding scheme that allows signed fractional numbers to be
 * used in the Paillier cryptosystem. There are several attributes that define
 * an encoding scheme:
 * <ul>
 *   <li>
 *     A <code>PaillierPublicKey</code> used to geneate this PaillierContext.
 *   </li>
 *   <li>
 *     A boolean <code>signed</code> that denotes whether the numbers
 *     represented are signed or unsigned.
 *   </li>
 *   <li>
 *     An integer <code>precision</code> that denotes the number of bits
 *     used to represent valid numbers. Setting this equal to the number of
 *     bits in the modulus results in the entire range of encoded numbers
 *     being valid while setting it less than this results in a range of
 *     <code>2<sup>precision</sup> + 1</code> valid encoded numbers and
 *     <code>modulus - 2<sup>precision</sup></code> invalid encoded numbers
 *     than can be used to (non-deterministically) detect overflows.
 *   </li>
 * </ul>
 *
 * Note you can create a PaillierContext directly from the create methods
 * on a PaillierPublicKey e.g., createSignedContext
 */
public class PaillierContext {

  private final PaillierPublicKey publicKey;
  private final boolean signed;
  private final int precision;

  private final BigInteger maxEncoded;
  private final BigInteger minEncoded;
  private final BigInteger maxSignificand;
  private final BigInteger minSignificand;

  /**
   * Constructs an encoding scheme, Paillier context, using a Paillier public key.
   *
   * @param publicKey of this Paillier context.
   * @param signed to indicate whether it supports signed numbers.
   * @param precision of the encodings scheme.
   */
  public PaillierContext(PaillierPublicKey publicKey, boolean signed, int precision) {
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

    // Determine the appropriate values for maxEncoded, minEncoded,
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

  /**
   * Returns the public key of this Paillier context.
   *
   * @return public key.
   */
  public PaillierPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Checks whether this encoding scheme is signed.
   *
   * @return true if this encoding scheme is signed, false otherwise.
   */
  public boolean isSigned() {
    return signed;
  }

  /**
   * Checks whether this encoding scheme is unsigned.
   *
   * @return true if this encoding scheme is unsigned, false otherwise.
   */
  public boolean isUnsigned() {
    return !signed;
  }

  /**
   * Returns the precision of this Paillier context.
   *
   * @return the precision.
   */
  public int getPrecision() {
    return precision;
  }

  /**
   * Checks whether this encoding scheme has full precision.
   *
   * @return true if this encoding scheme has full precision, false otherwise.
   */
  public boolean isFullPrecision() {
    return precision == publicKey.getModulus().bitLength();
  }

  /**
   * Returns the maximum number that can be encoded using this encoding scheme.
   *
   * @return the maximum encodable number.
   */
  public BigInteger getMaxEncoded() {
    return maxEncoded;
  }

  /**
   * Returns the minimum number that can be encoded using this encoding scheme.
   *
   * @return the minimum encodable number.
   */
  public BigInteger getMinEncoded() {
    return minEncoded;
  }

  /**
   * Returns the maximum significand value that can be supported by this encoding scheme
   *
   * @return the maximum siginificand supported.
   */
  public BigInteger getMaxSignificand() {
    return maxSignificand;
  }

  /**
   * Returns the minimum siginificand value that can be supported by this encoding scheme.
   *
   * @return the minimum siginificand supported.
   */
  public BigInteger getMinSignificand() {
    return minSignificand;
  }

  /**
   * Returns the maximum Number for a given exponent.
   *
   * @param exponent input.
   * @return the maximum Number.
   */
  public Number getMax(int exponent) {
    return new Number(maxSignificand, exponent);
  }

  /**
   * Returns the maximum BigInteger value for a given exponent.
   *
   * @param exponent input.
   * @return the maximum BigInteger.
   */
  public BigInteger getMaxBigInteger(int exponent) {
    return getMax(exponent).decodeApproximateBigInteger();
  }

  /**
   * Returns the maximum double value for a given exponent.
   *
   * @param exponent input.
   * @return the maximum double.
   */
  public double getMaxDouble(int exponent) {
    return getMax(exponent).decodeApproximateDouble();
  }

  /**
   * Returns the maximum long value for a given exponent.
   *
   * @param exponent input.
   * @return the maximum long.
   */
  public long getMaxLong(int exponent) {
    BigInteger max = getMaxBigInteger(exponent);
    if (max.compareTo(BigIntegerUtil.LONG_MAX_VALUE) >= 0) {
      return Long.MAX_VALUE;
    }
    return max.longValue();
  }

  /**
   * Returns the minimum Number for a given exponent.
   *
   * @param exponent input.
   * @return the minimum Number.
   */
  public Number getMin(int exponent) {
    return new Number(minSignificand, exponent);
  }

  /**
   * Returns the minimum BigInteger for a given exponent.
   *
   * @param exponent input.
   * @return the minimum BigInteger
   */
  public BigInteger getMinBigInteger(int exponent) {
    return getMin(exponent).decodeApproximateBigInteger();
  }

  /**
   * Returns the minimum double for a given exponent.
   *
   * @param exponent input.
   * @return the minimum double.
   */
  public double getMinDouble(int exponent) {
    return getMin(exponent).decodeApproximateDouble();
  }

  /**
   * Returns the minimum long for a give exponent.
   *
   * @param exponent input.
   * @return the minimum long.
   */
  public long getMinLong(int exponent) {
    BigInteger min = getMinBigInteger(exponent);
    if (min.compareTo(BigIntegerUtil.LONG_MIN_VALUE) <= 0) {
      return Long.MIN_VALUE;
    }
    return min.longValue();
  }

  /**
   * Checks whether another PaillierContext is the same as this PaillierContext.
   *
   * @param context the PaillierContext to be compared to.
   * @throws PaillierContextMismatchException if the other {@code context} is not the same
   * as this PaillierContext.
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
   * Checks if an EncryptedNumber has the same context as this PaillierContext.
   * Throws an ArithmeticException if that is not the case.
   * Returns the unmodified EncryptedNumber so that it can be called inline.
   *
   * @param other the EncryptedNumber to compare to.
   * @return {@code other}.
   * @throws PaillierContextMismatchException If {@code other} has a
   * different context to this PaillierContext.
   */
  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws PaillierContextMismatchException {
    checkSameContext(other.getContext());
    return other;
  }

  /**
   * Checks if an EncodedNumber has the same context as this PaillierContext.
   * Throws an ArithmeticException if that is not the case. Returns
   * the unmodified EncodedNumber so that it can be called inline.
   *
   * @param encoded the EncodedNumber to compare to.
   * @return {@code encoded}
   * @throws PaillierContextMismatchException If{@code encoded} has a
   * different context to this PaillierContext.
   */
  public EncodedNumber checkSameContext(EncodedNumber encoded)
          throws PaillierContextMismatchException {
    checkSameContext(encoded.getContext());
    return encoded;
  }

  /**
   * Checks whether an EncodedNumber is valid in this encoding scheme.
   *
   * @param encoded the EncodedNumber to be checked.
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

  /**
   * Checks whether a Number is valid in this encoding scheme.
   *
   * @param value the Number to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(Number value) {
    if (value.getSignificand().compareTo(maxSignificand) > 0) {
      return false;
    }
    if (value.getSignificand().compareTo(minSignificand) < 0) {
      return false;
    }
    return true;
  }

  /**
   * Checks whether a BigInteger is valid in this encoding scheme.
   *
   * @param value the BigInteger to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(BigInteger value) {
    // TODO Issue #12: optimise
    return isValid(Number.encode(value));
  }

  /**
   * Checks whether a double is valid in this encoding scheme.
   *
   * @param value the double to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(double value) {
    // TODO Issue #12: optimise
    try {
      return isValid(Number.encode(value));
    } catch (EncodeException e) {
      return false;
    }
  }

  /**
   * Checks whether a long is valid in this encodings scheme.
   *
   * @param value the long to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(long value) {
    // TODO Issue #12: optimise
    return isValid(Number.encode(value));
  }

  /**
   * Encodes a Number using this Paillier context.
   *
   * @param value the Number to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(Number value) throws EncodeException {
    if (!isValid(value)) {
      throw new EncodeException();
    }

    BigInteger significand = value.getSignificand();
    if (significand.signum() < 0) {
      significand = significand.add(publicKey.getModulus());
    }
    return new EncodedNumber(this, significand, value.getExponent());
  }

  /**
   * Encodes a BigInteger using this Paillier context.
   *
   * @param value the BigInteger to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(BigInteger value) throws EncodeException {
    return encode(Number.encode(value));
  }

  /**
   * Encodes a double using this Paillier context.
   *
   * @param value the double to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(double value) throws EncodeException {
    return encode(Number.encode(value));
  }

  /**
   * Encodes a long using this Paillier context.
   *
   * @param value the long to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(long value) throws EncodeException {
    return encode(Number.encode(value));
  }

  /**
   * Decodes an EncodedNumber to a Number.
   *
   * @param encoded the EncodedNumber to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public Number decode(EncodedNumber encoded) throws DecodeException {
    checkSameContext(encoded);
    final BigInteger value = encoded.getValue();

    // Non-negative
    if (value.compareTo(maxEncoded) <= 0) {
      return new Number(value, encoded.getExponent());
    }

    // Negative - note that negative encoded numbers are greater than
    // non-negative encoded numbers and hence minEncoded > maxEncoded
    if (signed && value.compareTo(minEncoded) >= 0) {
      final BigInteger modulus = publicKey.getModulus();
      return new Number(value.subtract(modulus), encoded.getExponent());
    }

    throw new DecodeException();
  }

  /**
   * Decodes an EncodedNumber to the exact BigInteger.
   *
   * @param encoded the EncodedNumber to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public BigInteger decodeBigInteger(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeBigInteger();
  }

  /**
   * Decodes an EncodedNumber to the approximated BigInteger.
   *
   * @param encoded the EncodedNumber to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public BigInteger decodeApproximateBigInteger(EncodedNumber encoded)
          throws DecodeException {
    return decode(encoded).decodeApproximateBigInteger();
  }

  /**
   * Decodes an EncodedNumber to the exact double.
   *
   * @param encoded the EncodedNumber to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public double decodeDouble(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeDouble();
  }

  /**
   * Decodes an EncodedNumber to the approximated double.
   *
   * @param encoded the EncodedNumber to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public double decodeApproximateDouble(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeApproximateDouble();
  }

  /**
   * Decodes an EncodedNumber to the exact long.
   *
   * @param encoded the EncodedNumber to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public long decodeLong(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeLong();
  }

  /**
   * Decodes an EncodedNumber to the approximated long.
   *
   * @param encoded the EncodedNumber to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public long decodeApproximateLong(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeApproximateLong();
  }

  /**
   * Obfuscates an EncryptedNumber.
   *
   * @param encrypted the EncryptedNumber to be obfuscated.
   * @return the obfuscated EncryptedNumber.
   */
  public EncryptedNumber obfuscate(EncryptedNumber encrypted) {
    checkSameContext(encrypted);
    final BigInteger obfuscated = publicKey.raw_obfuscate(encrypted.ciphertext);
    return new EncryptedNumber(this, obfuscated, encrypted.getExponent(), true);
  }

  /**
   * Encrypts an EncodedNumber.
   *
   * @param encoded the EncodedNumber to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(EncodedNumber encoded) {
    checkSameContext(encoded);
    final BigInteger modulus = publicKey.getModulus();
    final BigInteger modulusSquared = publicKey.getModulusSquared();
    final BigInteger value = encoded.getValue();
    final BigInteger ciphertext = publicKey.raw_encrypt_without_obfuscation(value);
    return new EncryptedNumber(this, ciphertext, encoded.getExponent(), false);
  }

  /**
   * Encrypts a Number.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(Number value) {
    return encrypt(encode(value));
  }

  /**
   * Encrypts a BigInteger.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(BigInteger value) {
    return encrypt(encode(value));
  }

  /**
   * Encrypts a double.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(double value) {
    return encrypt(encode(value));
  }

  /**
   * Encrypts a long.
   *
   * @param value to be encrypted.
   * @return the encryption result.
   */
  public EncryptedNumber encrypt(long value) {
    return encrypt(encode(value));
  }

  /**
   * Adds two EncryptedNumbers. Checks whether the PaillierContext of {@code operand1}
   * and {@code operand2} are the same as this PaillierContext. If the operands' exponents
   * are not the same, reduce the higher exponent to match with the lower exponent.
   *
   * @param operand1 first EncryptedNumber.
   * @param operand2 second EncryptedNumber.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillirContext.
   */
  public EncryptedNumber add(EncryptedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    BigInteger value1 = operand1.ciphertext;
    BigInteger value2 = operand2.ciphertext;
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    if (exponent1 > exponent2) {
      value1 = publicKey.raw_multiply(value1, BigInteger.ONE.shiftLeft(exponent1 - exponent2));
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = publicKey.raw_multiply(value2, BigInteger.ONE.shiftLeft(exponent2 - exponent1));
      exponent2 = exponent1;
    } // else do nothing
    final BigInteger result = publicKey.raw_add(value1, value2);
    return new EncryptedNumber(this, result, exponent1);
  }

  /**
   * Adds an EncryptedNumber and an EncodedNumber. Encrypts the EncodedNumber before adding
   * them together.
   *
   * @param operand1 an EncryptedNumber.
   * @param operand2 an EncodedNumber.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillirContext.
   */
  public EncryptedNumber add(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, encrypt(operand2));
  }

  /**
   * Adds an EncryptedNumber and an EncodedNumber. Encrypts the EncodedNumber before adding
   * them together.
   *
   * @param operand1 an EncodedNumber.
   * @param operand2 an EncryptedNumber.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillirContext.
   */
  public EncryptedNumber add(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return add(encrypt(operand1), operand2);
  }

  /**
   * Adds two EncodedNumbers. Checks whether the PaillierContext of {@code operand1}
   * and {@code operand2} are the same as this PaillierContext. If the operands' exponents
   * are not the same, reduce the higher exponent to match with the lower exponent.
   *
   * @param operand1 first EncodedNumber.
   * @param operand2 second EncodedNumber.
   * @return the addition result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillirContext.
   * @throws EncodeException
   */
  public EncodedNumber add(EncodedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException, EncodeException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger modulus = publicKey.getModulus();
    BigInteger value1 = operand1.getValue();
    BigInteger value2 = operand2.getValue();
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    if (exponent1 > exponent2) {
      value1 = value1.shiftLeft(exponent1 - exponent2);
//			if(value1.compareTo(publicKey.getModulus()) > 0)
//				throw new ArithmeticException(); // TODO Issue #11: better ways to detect
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = value2.shiftLeft(exponent2 - exponent1);
//			if(value2.compareTo(publicKey.getModulus()) > 0)
//				throw new ArithmeticException(); // TODO Issue #11: better ways to detect
      exponent2 = exponent1;
    } // else do nothing
    // TODO Issue #11: check that nothing overflows
    final BigInteger result = value1.add(value2).mod(modulus);
    return new EncodedNumber(this, result, exponent1);
  }

  /**
   * Returns the additive inverse of EncryptedNumber.
   *
   * @param operand1 input.
   * @return the additive inverse.
   * @throws PaillierContextMismatchException if the PaillierContext of {@code operand1}
   * is not the same as this PaillierContext.
   */
  public EncryptedNumber additiveInverse(EncryptedNumber operand1)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    return new EncryptedNumber(operand1.getContext(), operand1.ciphertext.modInverse(
            operand1.getContext().getPublicKey().getModulusSquared()),
                               operand1.getExponent());
  }

  /**
   * Returns the additive inverse of an EncodedNumber.
   *
   * @param operand1 input.
   * @return the additive inverse.
   * @throws PaillierContextMismatchException if the PaillierContext of {@code operand1}
   * is not the same as this PaillierContext.
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
   * Subtracts an EncryptedNumber ({@code operand2}) from another EncryptedNumber ({@code operand1}).
   *
   * @param operand1 first EncryptedNumber.
   * @param operand2 second EncryptedNumber.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillierContext.
   */
  public EncryptedNumber subtract(EncryptedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    // TODO Issue #9: optimise
    checkSameContext(operand1);
    checkSameContext(operand2);
    return add(operand1, additiveInverse(operand2));
  }

  /**
   * Subtracts an EncodedNumber ({@code operand2}) from an EncryptedNumber ({@code operand1}).
   *
   * @param operand1 an EncryptedNumber.
   * @param operand2 an EncodedNumber.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillierContext.
   */
  public EncryptedNumber subtract(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, encrypt(operand2.additiveInverse()));
  }

  /**
   * Subtracts an EncryptedNumber ({@code operand2}) from an EncodedNumber ({@code operand1}).
   *
   * @param operand1 an EncodedNumber.
   * @param operand2 an EncryptedNumber.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillierContext.
   */
  public EncryptedNumber subtract(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return subtract(encrypt(operand1), operand2);
  }

  /**
   * Subtracts an EncodedNumber ({@code operand2}) from an EncodedNumber ({@code operand1}).
   *
   * @param operand1 first EncodedNumber.
   * @param operand2 second EncodedNumber.
   * @return the subtraction result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillierContext.
   */
  public EncodedNumber subtract(EncodedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, operand2.additiveInverse());
  }

  /**
   * Multiplies an EncyptedNumber with an EncodedNumber.
   *
   * @param operand1 an EncryptedNumber.
   * @param operand2 an EncodedNumber.
   * @return the multiplication result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillierContext.
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
   * Multiplies an EncodedNumber with an EncryptedNumber.
   *
   * @param operand1 an EncodedNumber.
   * @param operand2 an EncryptedNumber.
   * @return the multiplication result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillierContext.
   */
  public EncryptedNumber multiply(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return multiply(operand2, operand1);
  }

  /**
   * Multiplies two EncodedNumbers.
   *
   * @param operand1 an EncodedNumber.
   * @param operand2 an EncodedNumber.
   * @return the multiplication result.
   * @throws PaillierContextMismatchException if the PaillierContext of either
   * {@code operand1} or {@code operand2} does not match this PaillierContext.
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
