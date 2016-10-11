package com.n1analytics.paillier;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.logging.Logger;

import com.n1analytics.paillier.util.BigIntegerUtil;

public class FixedPointEncodingScheme implements EncodingScheme {
  
  private static Logger logger = Logger.getLogger("com.n1analytics.paillier");

  private final PaillierContext context;
  private final int scale;
  private final int BASE = 2;
  private final BigInteger maxEncoded;
  private final BigInteger minEncoded;
  private final BigInteger maxSignificand;
  private final BigInteger minSignificand;
  
  public FixedPointEncodingScheme(PaillierContext context, int scale) {
    this.context = context;
    this.scale = scale;
    BigInteger modulus = context.getPublicKey().getModulus();
    maxEncoded = modulus.add(BigInteger.ONE).shiftRight(1).subtract(BigInteger.ONE);   
    minEncoded = modulus.subtract(maxEncoded);
    maxSignificand = maxEncoded;
    minSignificand = maxEncoded.negate();
  }
  
  @Override
  public int getBase() {
    return BASE;
  }

  @Override
  public boolean isSigned() {
    return true;
  }

  @Override
  public int getPrecision() {
    // we ignore precision
    return -1;
  }

  @Override
  public BigInteger getMaxEncoded() {
    return maxEncoded;
  }

  @Override
  public BigInteger getMinEncoded() {
    return minEncoded;
  }

  @Override
  public BigInteger getMaxSignificand() {
    return maxSignificand;
  }

  @Override
  public BigInteger getMinSignificand() {
    return minSignificand;
  }

  @Override
  public boolean isValid(EncodedNumber encoded) {
    // we ignore that, too
    return true;
  }

  @Override
  public EncodedNumber encode(BigInteger value) throws EncodeException {
    if (scale < 0) {
      value = value.multiply(BigInteger.valueOf(BASE).pow(-scale));
    } else {
      BigInteger fac = BigInteger.valueOf(BASE).pow(scale);
      if (value.mod(fac).compareTo(BigInteger.ZERO) != 0) {
        logger.warning("cannot encode '" + value.toString() + "' without precision loss");
      }
      value = value.divide(fac);
    } 
    if (BigIntegerUtil.greater(value, maxSignificand) || BigIntegerUtil.less(value, minSignificand)) {
      throw new EncodeException("Input value cannot be encoded.");
    }
    if(value.signum() < 0)
      value = value.add(context.getPublicKey().getModulus()); 
    return new EncodedNumber(context, value, scale);
  }

  @Override
  public EncodedNumber encode(double value) throws EncodeException {
    if(Double.isInfinite(value) || Double.isNaN(value))
      throw new EncodeException("Input value cannot be encoded.");

    return new EncodedNumber(context, innerEncode(new BigDecimal(value), scale), scale);
  }

  @Override
  public EncodedNumber encode(double value, int maxExponent) throws EncodeException {
    logger.warning("The exponent of this encoding scheme is fixed to: " + scale);
    return encode(value);
  }

  @Override
  public EncodedNumber encode(double value, double precision) throws EncodeException {
    logger.warning("The precision within this encoding scheme depends on the chosen 'scale'");
    return encode(value);
  }

  @Override
  public EncodedNumber encode(long value) throws EncodeException {
    return encode(BigInteger.valueOf(value));
  }

  @Override
  public EncodedNumber encode(BigDecimal value, int precision) throws EncodeException {
    return new EncodedNumber(context, innerEncode(value, scale), scale);
  }

  @Override
  public EncodedNumber encode(BigDecimal value) throws EncodeException {
    return encode(value, 0);
  }

  @Override
  public int signum(EncodedNumber number) {
    if(number.value.equals(BigInteger.ZERO)){
      return 0;
    }
    //if this context is signed, then a negative significant is strictly greater 
    //than modulus/2.
    BigInteger halfModulus = context.getPublicKey().modulus.shiftRight(1);
    return number.value.compareTo(halfModulus) > 0 ? -1 : 1;
  }

  @Override
  public BigInteger decodeBigInteger(EncodedNumber encoded) throws DecodeException {
    BigInteger significand = getSignificand(encoded);
    if (encoded.exponent < 0) {
      BigInteger exp = BigInteger.valueOf(BASE).pow(-encoded.getExponent());
      BigInteger[] res = significand.divideAndRemainder(exp);
      if (res[1].compareTo(BigInteger.ZERO) != 0) {
        logger.warning("cannot decode without precision loss");
      }
      return res[0];
    } else {
      return significand.multiply(BigInteger.valueOf(BASE).pow(encoded.getExponent()));
    }
    
  }

  @Override
  public double decodeDouble(EncodedNumber encoded) throws DecodeException {
    BigInteger significand = getSignificand(encoded);
    BigDecimal exp = BigDecimal.valueOf(BASE).pow(Math.abs(encoded.getExponent()));
    BigDecimal bigDecoded;
    if (encoded.getExponent() < 0) {
      bigDecoded = new BigDecimal(significand).divide(exp, MathContext.DECIMAL128);
    } else {
      bigDecoded = new BigDecimal(significand).multiply(exp, MathContext.DECIMAL128);
    }
    //double decoded = significand.doubleValue() * Math.pow((double) base, (double) encoded.getExponent());
    double decoded = bigDecoded.doubleValue();
    if(Double.isInfinite(decoded) || Double.isNaN(decoded)) {
      throw new DecodeException("Decoded value cannot be represented as double.");
    }
    return decoded;
  }

  @Override
  public long decodeLong(EncodedNumber encoded) throws DecodeException {
    BigInteger decoded = decodeBigInteger(encoded);
    if(BigIntegerUtil.less(decoded, BigIntegerUtil.LONG_MIN_VALUE) ||
            BigIntegerUtil.greater(decoded, BigIntegerUtil.LONG_MAX_VALUE)) {
      throw new DecodeException("Decoded value cannot be represented as long.");
    }
    return decoded.longValue();
  }

  @Override
  public BigDecimal decodeBigDecimal(EncodedNumber encoded, int precision) throws DecodeException {
    BigInteger significant = getSignificand(encoded);
    if (BASE == 10) {
      return new BigDecimal(significant, -encoded.getExponent());
    }
    MathContext mc = new MathContext(precision + 1, RoundingMode.HALF_EVEN);
    BigDecimal exp = BigDecimal.valueOf(BASE).pow(encoded.getExponent(), mc);
    return exp.multiply(new BigDecimal(significant), mc);
  }

  @Override
  public BigDecimal decodeBigDecimal(EncodedNumber encoded) throws DecodeException {
    return decodeBigDecimal(encoded, 25 * BIG_DECIMAL_ENCODING_PRECISION);
  }

  @Override
  public BigInteger getRescalingFactor(int expDiff) {
    throw new UnsupportedOperationException("FixedPointEncoding does not support rescaling.");
  }
  
  /**
   * Returns an integer ({@code BigInteger}) representation of a floating point number.
   * The integer representation is computed as <code>value * base<sup>exponent</sup></code> for non-negative
   * numbers and <code>modulus + (value * base<sup>exponent</sup>)</code> for negative numbers.
   *
   * @param value a floating point number to be encoded.
   * @param exponent the exponent to encode the number.
   * @return the integer representation of the input floating point number.
   */
  private BigInteger innerEncode(BigDecimal value, int exponent) {
    // Compute BASE^(-exponent)
    BigDecimal bigDecBaseExponent = (new BigDecimal(BASE)).pow(-exponent, MathContext.DECIMAL128);

    // Compute the integer representation, ie, value * (BASE^-exponent)
    BigInteger bigIntRep =
            ((value.multiply(bigDecBaseExponent)).setScale(0, BigDecimal.ROUND_HALF_UP)).toBigInteger();

    if(BigIntegerUtil.greater(bigIntRep, maxSignificand) ||
            (value.signum() < 0 && BigIntegerUtil.less(bigIntRep, minSignificand))) {
      throw new EncodeException("Input value cannot be encoded.");
    }

    if (bigIntRep.signum() < 0) {
      bigIntRep = bigIntRep.add(context.getPublicKey().getModulus());
    }

    return bigIntRep;
  }
  
  private BigInteger getSignificand(EncodedNumber encoded) {
    context.checkSameContext(encoded);
    final BigInteger value = encoded.getValue();

    if(value.compareTo(context.getPublicKey().getModulus()) > 0)
      throw new DecodeException("The significand of the encoded number is corrupted");

    // Non-negative
    if (value.compareTo(maxEncoded) <= 0) {
      return value;
    } else {
    // Negative - note that negative encoded numbers are greater than
    // non-negative encoded numbers and hence minEncoded > maxEncoded
      final BigInteger modulus = context.getPublicKey().getModulus();
      return value.subtract(modulus);
    }
  }

}
