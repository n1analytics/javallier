package com.n1analytics.paillier;

import java.math.BigDecimal;
import java.math.BigInteger;

public interface EncodingScheme {

  /**
   * the relative error of an encoded BigDecimal is always smaller than 10^-BIG_DECIMAL_ENCODING_PRECISION
   */
  public static final int BIG_DECIMAL_ENCODING_PRECISION = 34;
  
  /**
   * @return encoding base used in this Encoding Scheme.
   */
  public int getBase();
  
  /**
   * Checks whether this EncodingScheme supports signed numbers.
   *
   * @return true if this EncodingScheme support signed numbers, false otherwise.
   */
  public boolean isSigned();
  
  /**
   * @return the precision of this EncodingScheme.
   */
  public int getPrecision();
  
  /**
   * @return the maximum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey} associated with this EncodingScheme.
   */
  public BigInteger getMaxEncoded();

  /**
   * @return the minimum {@code value} of the {@code EncodedNumber} that can be encrypted using
   * the {@code PaillierPublicKey} associated with this EncodingScheme.
   */
  public BigInteger getMinEncoded();

  /**
   * @return the maximum value that can be encoded and encrypted using the {@code PaillierPublicKey}
   * associated with this EncodingScheme.
   */
  public BigInteger getMaxSignificand();

  /**
   * @return the minimum value that can be encoded and encrypted using the {@code PaillierPublicKey}
   * associated with this EncodingScheme.
   */
  public BigInteger getMinSignificand();
  
  /**
   * Checks whether an {@code EncodedNumber}'s {@code value} is valid, that is the {@code value}
   * can be encrypted using the associated {@code publicKey}. 
   * 
   * For an unsigned {@code EncodingScheme}, a valid {@code value} is less than or equal 
   * to {@code maxEncoded}. While for a signed {@code EncodingScheme}, a valid {@code value} 
   * is less than or equal to {@code maxEncoded} (for positive numbers) or is greater than or 
   * equal to {@code minEncoded} (for negative numbers).
   *
   * @param encoded the {@code EncodedNumber} to be checked.
   * @return true if it is valid, false otherwise.
   */
  public boolean isValid(EncodedNumber encoded);
  
  /**
   * Encodes a {@code BigInteger} using this {@code EncodingScheme}. Throws EncodeException if the input
   * value is greater than {@code maxSignificand} or is less than {@code minSignificand}.
   *
   * @param value the {@code BigInteger} to be encoded.
   * @return the encoding result - {@code EncodedNumber}
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(BigInteger value) throws EncodeException;

  /**
   * Encodes a {@code double} using this {@code EncodingScheme}. If the input value is not valid (that is
   * if {@code value} is infinite, is a NaN, or is negative when this context is unsigned) then throw
   * EncodeException.
   *
   * @param value the {@code double} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(double value) throws EncodeException;

  /**
   * Encodes a {@code double} given a {@code maxExponent} using this {@code EncodingScheme}.
   *
   * @param value the {@code double} to be encoded.
   * @param maxExponent the maximum exponent to encode the {@code value} with. The exponent of
   *                    the resulting {@code EncodedNumber} will be at most equal to {@code maxExponent}.
   * @return the encoding results.
   * @throws EncodeException if the {@code value} and/or {@code maxExponent} is not valid.
   */
  public EncodedNumber encode(double value, int maxExponent) throws EncodeException;

  /**
   * Encodes a {@code double} given a {@code precision} using this {@code EncodingScheme}.
   *
   * @param value the {@code double} to be encoded.
   * @param precision denotes how different is the {@code value} from 0,
   *                  {@code precision}'s value is between 0 and 1.
   * @return the encoding results.
   * @throws EncodeException if the {@code value} and/or {@code maxExponent} is not valid.
   */
  public EncodedNumber encode(double value, double precision) throws EncodeException;

  /**
   * Encodes a {@code long} using this {@code EncodingScheme}.
   *
   * @param value the {@code long} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(long value) throws EncodeException;
  
  /**
   * Encodes a {@code BigDecimal} using this {@code EncodingScheme}. The
   * maximum relative error of the encoded number will be smaller than
   * 10 ^ -precision.
   *
   * @param value the {@code BigDecimal} to be encoded.
   * @param precision defines the maximum relative error of the approximation
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(BigDecimal value, int precision) throws EncodeException;
  
  /**
   * Encodes a {@code BigDecimal} using this {@code EncodingScheme}. Uses the 
   * default precision as defined in {@code BIG_DECIMAL_ENCODING_PRECISION}.
   *
   * @param value the {@code BigDecimal} to be encoded.
   * @return the encoding result.
   * @throws EncodeException if the {@code value} is not valid.
   */
  public EncodedNumber encode(BigDecimal value) throws EncodeException;
  
  /**
   * Returns the signum function of this EncodedNumber.
   * @return -1, 0 or 1 as the value of this EncodedNumber is negative, zero or positive.
   */
  public int signum(EncodedNumber number);
  
  /**
   * Decodes to the exact {@code BigInteger} representation.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public BigInteger decodeBigInteger(EncodedNumber encoded) throws DecodeException;

  /**
   * Decodes to the exact {@code double} representation. Throws DecodeException if the decoded result
   * is {@link java.lang.Double#POSITIVE_INFINITY}, {@link java.lang.Double#NEGATIVE_INFINITY} or
   * {@link java.lang.Double#NaN}.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public double decodeDouble(EncodedNumber encoded) throws DecodeException;

  /**
   * Decodes to the exact {@code long} representation. Throws DecodeException if the decoded result
   * is greater than {@link java.lang.Long#MAX_VALUE} or less than {@link java.lang.Long#MIN_VALUE}.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public long decodeLong(EncodedNumber encoded) throws DecodeException;
  
  /**
   * Decodes to an approximate {@code BigDecimal} representation. The relative error of the approximation
   * is smaller than 10 ^ -precision.
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @param precision upper bound for relative decoding error
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public BigDecimal decodeBigDecimal(EncodedNumber encoded, int precision) throws DecodeException;
  
  /**
   * Decodes to an approximate {@code BigDecimal} representation using the default precision as 
   * defined in {@code BIG_DECIMAL_ENCODING_PRECISION}
   *
   * @param encoded the {@code EncodedNumber} to be decoded.
   * @return the decoding result.
   * @throws DecodeException if the {@code encoded} cannot be decoded.
   */
  public BigDecimal decodeBigDecimal(EncodedNumber encoded) throws DecodeException;

  /**
   * Returns the rescaling factor to re-encode an {@code EncodedNumber} using the same {@code base}
   * but with a different {@code exponent}. The rescaling factor is computed as <code>base</code><sup>expDiff</sup>.
   *
   * @param expDiff the exponent to for the new rescaling factor.
   * @return the rescaling factor.
   */
  public BigInteger getRescalingFactor(int expDiff);
}


