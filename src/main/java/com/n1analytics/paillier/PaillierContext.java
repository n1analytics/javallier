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


import java.math.BigDecimal;
import java.math.BigInteger;

import com.n1analytics.paillier.util.BigIntegerUtil;
import com.n1analytics.paillier.util.HashChain;

/**
 * The PaillierContext combines an encoding scheme and a public key.
 * 
 * The encoding scheme used to convert numbers into unsigned 
 * integers for use in the Paillier cryptosystem.
 * 
 * There are several attributes that define an encoding scheme:
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
 * PaillierContext defines methods:
 * <ul>
 *     <li>To check whether a BigInteger, long, double, Number or EncodedNumber is valid</li>
 *     <li>To encode a BigInteger, long, double and Number to an EncodedNumber</li>
 *     <li>To decode an EncodedNumber to a Number, BigInteger, long or double</li>
 *     <li>To encrypt a BigInteger, long, double, Number and EncodedNumber</li>
 *     <li>To perform arithmetic computation (support addition, subtraction,
 *     limited multiplication and limited division)</li>
 *     <li>To check whether another PaillierContext is the same as this PaillierContext</li>
 * </ul>
 *
 * Note you can create a PaillierContext directly from the create methods
 * on a PaillierPublicKey e.g., {@link PaillierPublicKey#createSignedContext()}.
 */
public class PaillierContext {


  /**
   * The public key associated with this PaillierContext.
   */
  private final PaillierPublicKey publicKey;

  /**
   * The encoding scheme associated with this PaillierContext.
   */
  private final EncodingScheme encoding;

  
  /**
   * Constructs a Paillier context using the  {@code DEFAULT_BASE}.
   *
   * @param publicKey associated with this PaillierContext.
   * @param signed to denote whether this PaillierContext supports signed or unsigned numbers.
   * @param precision to denote the number of bits used to represent valid numbers.
   */
  public PaillierContext(PaillierPublicKey publicKey, EncodingScheme encoding) {
    if (publicKey == null) {
      throw new NullPointerException("publicKey must not be null");
    }
    if (encoding == null) {
      throw new NullPointerException("encoding must not be null");
    }
    if (!publicKey.equals(encoding.getPublicKey())) {
      throw new PaillierKeyMismatchException("the provided public key does not match the key of the encoding scheme");
    }
    this.publicKey = publicKey;
    this.encoding = encoding;
  }
  

  /**
   * @return public key of this PaillierContext.
   */
  public PaillierPublicKey getPublicKey() {
    return publicKey;
  }
  
  /**
   * @return the encoding scheme of this PaillierContext
   */
  public EncodingScheme getEncodingScheme() {
    return encoding;
  }

  /**
   * @return encoding base used in this PaillierContext.
   */
  public int getBase() { return encoding.getBase(); }

  /**
   * Checks whether this PaillierContext supports signed numbers.
   *
   * @return true if this PaillierContext support signed numbers, false otherwise.
   */
  public boolean isSigned() {
    
    return encoding.isSigned();
  }

  /**
   * Checks whether this PaillierContext supports unsigned numbers.
   *
   * @return true if this PaillierContext support unsigned numbers, false otherwise.
   */
  public boolean isUnsigned() {
    return !isSigned();
  }

  /**
   * @return the precision of this PaillierContext.
   */
  public int getPrecision() {
    return encoding.getPrecision();
  }

  /**
   * Checks whether this PaillierContext has full precision.
   *
   * @return true if this PaillierContext has full precision, false otherwise.
   */
  public boolean isFullPrecision() {
    return getPrecision() == publicKey.getModulus().bitLength();
  }

  /**
   * @return the maximum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey} associated with this context.
   */
  public BigInteger getMaxEncoded() {
    return encoding.getMaxEncoded();
  }

  /**
   * @return the minimum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey} associated with this context.
   */
  public BigInteger getMinEncoded() {
    return encoding.getMinEncoded();
  }

  /**
   * @return the maximum value that can be encoded and encrypted using the {@code PaillierPublicKey}
   * associated with this context.
   */
  public BigInteger getMaxSignificand() {
    return encoding.getMaxSignificand();
  }

  /**
   * @return the minimum value that can be encoded and encrypted using the {@code PaillierPublicKey}
   * associated with this context.
   */
  public BigInteger getMinSignificand() {
    return encoding.getMinSignificand();
  }

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
      throw new PaillierContextMismatchException("These PaillierContexts have diffenent public keys");
    }
    if (!encoding.equals(context.encoding)) {
      throw new PaillierContextMismatchException("These PaillierContexts have diffenent encoding schemes");
    }
  }

  /**
   * Checks whether an {@code EncryptedNumber} has the same context as this {@code PaillierContext}.
   * Returns the unmodified {@code EncryptedNumber} so that it can be called inline.
   *
   * @param other the {@code EncryptedNumber} to compare to.
   * @return {@code other}.
   * @throws PaillierContextMismatchException If {@code other} has a
   * different context to this {@code PaillierContext}.
   */
  public EncryptedNumber checkSameContext(EncryptedNumber other)
          throws PaillierContextMismatchException {
      if (!encoding.equals(other.encoding)) {
          throw new PaillierContextMismatchException("This encrypted number has a diffenent encoding scheme.");
        }
    return other;
  }

  /**
   * Checks whether an {@code EncodedNumber} has the same context as this {@code PaillierContext}.
   * Returns the unmodified {@code EncodedNumber} so that it can be called inline.
   *
   * @param encoded the {@code EncodedNumber} to compare to.
   * @return {@code encoded}
   * @throws PaillierContextMismatchException If{@code encoded} has a
   * different context to this {@code PaillierContext}.
   */
  public EncodedNumber checkSameContext(EncodedNumber encoded)
          throws PaillierContextMismatchException {
    if (!encoding.equals(encoded.getEncodingScheme())) {
      throw new PaillierContextMismatchException("The encoding scheme of 'encoded' does not match the encoding of this context");
    }
    return encoded;
  }


  /**
   * Encodes a {@code BigInteger} using this {@code PaillierContext}. Throws EncodeException if the input
   * value is greater than {@code maxSignificand} or is less than {@code minSignificand}.
   *
   * @param value the {@code BigInteger} to be encoded.
   * @return the encoding result - {@code EncodedNumber}
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(BigInteger value) throws EncodeException {
    return encoding.encode(value);
  }

  /**
   * Encodes a {@code double} using this {@code PaillierContext}. If the input value is not valid (that is
   * if {@code value} is infinite, is a NaN, or is negative when this context is unsigned) then throw
   * EncodeException.
   *
   * @param value the {@code double} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(double value) throws EncodeException {
    return encoding.encode(value);
  }

  /**
   * Encodes a {@code double} given a {@code maxExponent} using this {@code PaillierContext}.
   *
   * @param value the {@code double} to be encoded.
   * @param maxExponent the maximum exponent to encode the {@code value} with. The exponent of
   *                    the resulting {@code EncodedNumber} will be at most equal to {@code maxExponent}.
   * @return the encoding results.
   * @throws EncodeException if the {@code value} and/or {@code maxExponent} is not valid.
   */
  public EncodedNumber encode(double value, int maxExponent) throws EncodeException {
    return encoding.encode(value, maxExponent);
  }

  /**
   * Encodes a {@code double} given a {@code precision} using this {@code PaillierContext}.
   *
   * @param value the {@code double} to be encoded.
   * @param precision denotes how different is the {@code value} from 0,
   *                  {@code precision}'s value is between 0 and 1.
   * @return the encoding results.
   * @throws EncodeException if the {@code value} and/or {@code maxExponent} is not valid.
   */
  public EncodedNumber encode(double value, double precision) throws EncodeException{
    return encoding.encode(value, precision);
  }

  /**
   * Encodes a {@code long} using this {@code PaillierContext}.
   *
   * @param value the {@code long} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(long value) throws EncodeException {
    return encode(BigInteger.valueOf(value));
  }
  
  public EncodedNumber encode(BigDecimal value) throws EncodeException {
    return encoding.encode(value);
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
    return encoded.encrypt();
  }

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


  /**
   * returns a random {@code EncodedNumber}, consisting of a significant, chosen uniformly 
   * at random out of the message space and an exponent specified in parameter (@code exponent}.
   * @param exponent
   * @return a random EncodedNumber
   */
  public EncodedNumber randomEncodedNumber(int exponent){
    return new EncodedNumber(encoding, BigIntegerUtil.randomPositiveNumber(publicKey.getModulus()), exponent);
  }


  @Override
  public int hashCode() {
    return new HashChain().chain(publicKey).chain(encoding).hashCode();
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
            encoding.equals(context.encoding);
  }

  public boolean equals(PaillierContext o) {
    return o == this || (o != null &&
            publicKey.equals(o.publicKey) &&
            encoding.equals(o.encoding));
  }
}
