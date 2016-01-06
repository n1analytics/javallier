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

import com.n1analytics.paillier.util.BigIntegerUtil;
import com.n1analytics.paillier.util.HashChain;

/**
 * Represents an encoding scheme that allows signed fractional numbers to be
 * used in the Paillier cryptosystem. There are several attributes that define
 * an encoding scheme:
 * <ul>
 *   <li>
 *     A BigInteger <code>modulus</code> that defines the set of possible
 *     encoded values: <code>0, 1, 2, ..., modulus - 1</code>. This must be
 *     the modulus of a <code>PaillierPublicKey</code> -- meaning that it is
 *     the product of two prime numbers and hence is also an odd number
 *     (assuming both constituent primes are greater than 2).
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
 *   <li>
 *     An integer <code>exponent</code> that denotes where the decimal
 *     point lies with respect to the encoded number.
 *   </li>
 * </ul>
 */
public class PaillierContext {

  private final PaillierPublicKey publicKey;
  private final boolean signed;
  private final int precision;

  private final BigInteger maxEncoded;
  private final BigInteger minEncoded;
  private final BigInteger maxSignificand;
  private final BigInteger minSignificand;

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

  public PaillierPublicKey getPublicKey() {
    return publicKey;
  }

  public boolean isSigned() {
    return signed;
  }

  public boolean isUnsigned() {
    return !signed;
  }

  public int getPrecision() {
    return precision;
  }

  public boolean isFullPrecision() {
    return precision == publicKey.getModulus().bitLength();
  }

  public BigInteger getMaxEncoded() {
    return maxEncoded;
  }

  public BigInteger getMinEncoded() {
    return minEncoded;
  }

  public BigInteger getMaxSignificand() {
    return maxSignificand;
  }

  public BigInteger getMinSignificand() {
    return minSignificand;
  }

  public Number getMax(int exponent) {
    return new Number(maxSignificand, exponent);
  }

  public BigInteger getMaxBigInteger(int exponent) {
    return getMax(exponent).decodeApproximateBigInteger();
  }

  public double getMaxDouble(int exponent) {
    return getMax(exponent).decodeApproximateDouble();
  }

  public long getMaxLong(int exponent) {
    BigInteger max = getMaxBigInteger(exponent);
    if (max.compareTo(BigIntegerUtil.LONG_MAX_VALUE) >= 0) {
      return Long.MAX_VALUE;
    }
    return max.longValue();
  }

  public Number getMin(int exponent) {
    return new Number(minSignificand, exponent);
  }

  public BigInteger getMinBigInteger(int exponent) {
    return getMin(exponent).decodeApproximateBigInteger();
  }

  public double getMinDouble(int exponent) {
    return getMin(exponent).decodeApproximateDouble();
  }

  public long getMinLong(int exponent) {
    BigInteger min = getMinBigInteger(exponent);
    if (min.compareTo(BigIntegerUtil.LONG_MIN_VALUE) <= 0) {
      return Long.MIN_VALUE;
    }
    return min.longValue();
  }

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
   * Check if <code>encrypted</code> has the same context as
   * <code>this</code>. Throws an ArithmeticException if that is not the case.
   * Returns <code>encrypted</code> unmodified so that it can be called
   * inline.
   *
   * @param other Number to compare to
   * @return <code>other</code>
   * @throws PaillierContextMismatchException If <code>other</code> has a
   * different context to <code>this</code>.
   */
  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws PaillierContextMismatchException {
    checkSameContext(other.getContext());
    return other;
  }

  /**
   * Check if <code>encoded</code> has the same context as <code>this</code>.
   * Throws an ArithmeticException if that is not the case. Returns
   * <code>encoded</code> unmodified so that it can be called inline.
   * @param encoded Number to compare to
   * @return <code>encoded</code>
   * @throws PaillierContextMismatchException If <code>encrypted</code> has a
   * different context to <code>this</code>.
   */
  public EncodedNumber checkSameContext(EncodedNumber encoded)
          throws PaillierContextMismatchException {
    checkSameContext(encoded.getContext());
    return encoded;
  }

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

  public boolean isValid(Number value) {
    if (value.getSignificand().compareTo(maxSignificand) > 0) {
      return false;
    }
    if (value.getSignificand().compareTo(minSignificand) < 0) {
      return false;
    }
    return true;
  }

  public boolean isValid(BigInteger value) {
    // TODO optimise
    return isValid(Number.encode(value));
  }

  public boolean isValid(double value) {
    // TODO optimise
    try {
      return isValid(Number.encode(value));
    } catch (EncodeException e) {
      return false;
    }
  }

  public boolean isValid(long value) {
    // TODO optimise
    return isValid(Number.encode(value));
  }

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

  public EncodedNumber encode(BigInteger value) throws EncodeException {
    return encode(Number.encode(value));
  }

  public EncodedNumber encode(double value) throws EncodeException {
    return encode(Number.encode(value));
  }

  public EncodedNumber encode(long value) throws EncodeException {
    return encode(Number.encode(value));
  }

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

  public BigInteger decodeBigInteger(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeBigInteger();
  }

  public BigInteger decodeApproximateBigInteger(EncodedNumber encoded)
          throws DecodeException {
    return decode(encoded).decodeApproximateBigInteger();
  }

  public double decodeDouble(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeDouble();
  }

  public double decodeApproximateDouble(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeApproximateDouble();
  }

  public long decodeLong(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeLong();
  }

  public long decodeApproximateLong(EncodedNumber encoded) throws DecodeException {
    return decode(encoded).decodeApproximateLong();
  }

  public EncryptedNumber obfuscate(EncryptedNumber encrypted) {
    checkSameContext(encrypted);
    //final BigInteger modulus = publicKey.getModulus();
    //final BigInteger modulusSquared = publicKey.getModulusSquared();
    //final BigInteger value = encrypted.ciphertext;
    final BigInteger obfuscated = publicKey.raw_obfuscate(encrypted.ciphertext);
    //final BigInteger obfuscated = randomPositiveNumber(modulus).modPow(modulus,
    //                                                                   modulusSquared).multiply(
    //       value).mod(modulusSquared);
    return new EncryptedNumber(this, obfuscated, encrypted.getExponent(), true);
  }

  public EncryptedNumber encrypt(EncodedNumber encoded) {

    checkSameContext(encoded);
    final BigInteger modulus = publicKey.getModulus();
    final BigInteger modulusSquared = publicKey.getModulusSquared();
    final BigInteger value = encoded.getValue();
    //the following encryption only works if the generator is chosen to be modulus+1.
    //Luckily, the PublicKey definition in this library ensures this property. 
    final BigInteger result = modulus.multiply(value).add(BigInteger.ONE).mod(modulusSquared);
    return new EncryptedNumber(this, result, encoded.getExponent());
  }

  public EncryptedNumber encrypt(Number value) {
    return encrypt(encode(value));
  }

  public EncryptedNumber encrypt(BigInteger value) {
    return encrypt(encode(value));
  }

  public EncryptedNumber encrypt(double value) {
    return encrypt(encode(value));
  }

  public EncryptedNumber encrypt(long value) {
    return encrypt(encode(value));
  }

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

  public EncryptedNumber add(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, encrypt(operand2));
  }

  public EncryptedNumber add(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return add(encrypt(operand1), operand2);
  }

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
//				throw new ArithmeticException(); // TODO better ways to detect
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = value2.shiftLeft(exponent2 - exponent1);
//			if(value2.compareTo(publicKey.getModulus()) > 0)
//				throw new ArithmeticException(); // TODO better ways to detect
      exponent2 = exponent1;
    } // else do nothing
    // TODO check that nothing overflows
    final BigInteger result = value1.add(value2).mod(modulus);
    return new EncodedNumber(this, result, exponent1);
  }

  public EncryptedNumber additiveInverse(EncryptedNumber operand1)
          throws PaillierContextMismatchException {
    checkSameContext(operand1);
    return new EncryptedNumber(operand1.getContext(), operand1.ciphertext.modInverse(
            operand1.getContext().getPublicKey().getModulusSquared()),
                               operand1.getExponent());
  }

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

  public EncryptedNumber subtract(EncryptedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    // TODO optimise
    checkSameContext(operand1);
    checkSameContext(operand2);
    return add(operand1, additiveInverse(operand2));
  }

  public EncryptedNumber subtract(EncryptedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, encrypt(operand2.additiveInverse()));
  }

  public EncryptedNumber subtract(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return subtract(encrypt(operand1), operand2);
  }

  public EncodedNumber subtract(EncodedNumber operand1, EncodedNumber operand2)
          throws PaillierContextMismatchException {
    return add(operand1, operand2.additiveInverse());
  }

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

  public EncryptedNumber multiply(EncodedNumber operand1, EncryptedNumber operand2)
          throws PaillierContextMismatchException {
    return multiply(operand2, operand1);
  }

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

  // TODO
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
