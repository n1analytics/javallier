package com.n1analytics.paillier;

import java.math.BigInteger;
import java.util.logging.Logger;


public class MockEncryptedNumber extends EncryptedNumber {

    private static Logger logger = Logger.getLogger("com.n1analytics.paillier");
    
    public MockEncryptedNumber(EncodingScheme encoding, BigInteger ciphertext, int exponent) {
        super(encoding, ciphertext, exponent);
    }
    
    public MockEncryptedNumber(EncodingScheme encoding, BigInteger ciphertext, int exponent, boolean isSafe) {
        super(encoding, ciphertext, exponent, isSafe);
    }
    
    /* we are going to mock all the bits of the encryption from now on... */
    @Override
    public EncryptedNumber obfuscate() {
      return this;
    }
    
    /**
     * Performs "mock" addition between two {@code EncryptedNumber}s.
     *
     * @param operand1
     *            first {@code EncryptedNumber}.
     * @param operand2
     *            second {@code EncryptedNumber}.
     * @return the "mock" addition result.
     * @throws PaillierContextMismatchException
     *             if {@code operand1}'s mock context is not the same as
     *             {@code operand2}'s mock context.
     */
    @Override
    public EncryptedNumber add(EncryptedNumber other) throws PaillierContextMismatchException {
        checkSameEncoding(other);
        final BigInteger modulus = encoding.getPublicKey().getModulus();
        BigInteger value = ciphertext;
        BigInteger otherValue = other.ciphertext;
        int thisExponent = exponent;
        int otherExponent = other.getExponent();
        if (exponent > otherExponent) {
            value = value.multiply(encoding.getRescalingFactor(exponent - otherExponent)).mod(modulus);
            thisExponent = otherExponent;
        } else if (exponent < otherExponent) {
            otherValue = otherValue.multiply(encoding.getRescalingFactor(otherExponent - exponent)).mod(modulus);
        } // else: both exponents are the same, no need for adjusting values.
        //now we can add the values
        BigInteger result = value.add(otherValue);
        // this tests for overflows
        BigInteger posValue1 = (encoding.isSigned() && value.compareTo(encoding.getMinEncoded()) >= 0)
                ? value.subtract(modulus) : value;
        BigInteger posValue2 = (encoding.isSigned() && otherValue.compareTo(encoding.getMinEncoded()) >= 0)
                ? otherValue.subtract(modulus) : otherValue;

        if (posValue1.add(posValue2).compareTo(modulus) != -1) {
            logger.warning("Overflow occured in add()");
        }
        return new MockEncryptedNumber(encoding, result.mod(modulus), thisExponent);
    }
    
    /**
     * @return the additive inverse of this.
     */
    @Override
    public EncryptedNumber additiveInverse() {
      return new MockEncryptedNumber(encoding, encoding.getPublicKey().getModulus().subtract(ciphertext),
                                 getExponent(), isSafe);
    }
    
    /**
     * Performs "mock" multiplication between an {@code EncodedNumber} and this {@code MockEncryptedNumber}.
     *
     * @param other {@code EncodedNumber} to be multiplied with.
     * @return the multiplication result.
     */
    @Override
    public EncryptedNumber multiply(EncodedNumber other) {
      checkSameEncoding(other);
      final BigInteger result = ciphertext.multiply(other.value);
      BigInteger modulus = encoding.getPublicKey().getModulus();
      
    //this tests for overflows
      BigInteger posValue1 = (encoding.isSigned() && ciphertext.compareTo(encoding.getMinEncoded())>=0)
                              ? ciphertext.subtract(modulus) : ciphertext;
      BigInteger posValue2 = (encoding.isSigned() && other.value.compareTo(encoding.getMinEncoded())>=0)
                              ? other.value.subtract(modulus) : other.value;
      if(posValue1.multiply(posValue2).compareTo(modulus) != -1){
        logger.warning("Overflow occured in multiply()");
      }
      return new MockEncryptedNumber(encoding, result.mod(modulus), exponent+other.getExponent());
    }
    
    /**
     * Decrypts this {@code EncryptedNumber} using a private key. See
     * {@link com.n1analytics.paillier.PaillierPrivateKey#decrypt(EncryptedNumber)} for more details.
     *
     * @param key private key to decrypt.
     * @return the decryption result.
     */
    @Override
    public EncodedNumber decrypt(PaillierPrivateKey key) {
      return new EncodedNumber(encoding, ciphertext, exponent);
    }
    
    @Override
    public boolean equals(Object o) {
        return o != null && o instanceof MockEncryptedNumber && super.equals(o);
    }

}
