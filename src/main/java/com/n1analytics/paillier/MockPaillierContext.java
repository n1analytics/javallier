package com.n1analytics.paillier;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * This is a mock version of the PaillierContext.
 * 
 * !!! THIS IS FOR DEBUGGING PURPOSES ONLY !!!
 * 
 * It emulates the arithmetic of the PaillierContext without the expensive encryption operations.
 * Thus, no values get actually encrypted. Everything is in the clear!
 * 
 * @author whenecka
 *
 */
public class MockPaillierContext extends PaillierContext {

  private static Logger logger = Logger.getLogger("com.n1analytics.paillier");
  
  public MockPaillierContext(PaillierPublicKey publicKey, boolean signed, int precision) {
    super(publicKey, signed, precision);
    logger.warning("You are using the MockPaillierContext. Are you sure? This is NOT secure/private!");
  }

  public EncryptedNumber obfuscate(EncryptedNumber encrypted) {
    //we skip this
    return encrypted;
  }
  
  public EncryptedNumber encrypt(EncodedNumber encoded) {
    //we don't actually encrypt. 
    checkSameContext(encoded);
    final BigInteger modulus = getPublicKey().getModulus();
    final BigInteger value = encoded.getValue();
    return new EncryptedNumber(this, value.mod(modulus), encoded.getExponent());
  }
  
  public EncryptedNumber add(EncryptedNumber operand1, EncryptedNumber operand2)
      throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger modulus = getPublicKey().getModulus();
    BigInteger value1 = operand1.ciphertext;
    BigInteger value2 = operand2.ciphertext;
    int exponent1 = operand1.getExponent();
    int exponent2 = operand2.getExponent();
    if (exponent1 > exponent2) {
      value1 = value1.multiply(BigInteger.ONE.shiftLeft(exponent1 - exponent2)).mod(modulus);
      exponent1 = exponent2;
    } else if (exponent1 < exponent2) {
      value2 = value2.multiply(BigInteger.ONE.shiftLeft(exponent2 - exponent1)).mod(modulus);
      exponent2 = exponent1;
    } // else do nothing
    BigInteger result = value1.add(value2);
    if(result.compareTo(modulus) != -1){
      logger.warning("Overflow occured in add()");
    }
    return new EncryptedNumber(this, result.mod(modulus), exponent1);
  }
  
  public EncryptedNumber additiveInverse(EncryptedNumber operand1) throws PaillierContextMismatchException {
    checkSameContext(operand1);
    return new EncryptedNumber(operand1.getContext(),
        getPublicKey().modulus.subtract(operand1.ciphertext),
        operand1.getExponent());
  }

  public EncodedNumber additiveInverse(EncodedNumber operand1) throws PaillierContextMismatchException {
    checkSameContext(operand1);
    if (operand1.getValue().signum() == 0) {
      return operand1;
    }
    final BigInteger modulus = getPublicKey().getModulus();
    final BigInteger value1 = operand1.getValue();
    final BigInteger result = modulus.subtract(value1);
    return new EncodedNumber(this, result, operand1.getExponent());
  }
  
  public EncryptedNumber multiply(EncryptedNumber operand1, EncodedNumber operand2)
      throws PaillierContextMismatchException {
    checkSameContext(operand1);
    checkSameContext(operand2);
    final BigInteger value1 = operand1.ciphertext;
    final BigInteger value2 = operand2.getValue();
    final BigInteger result = value1.multiply(value2);
    if(result.compareTo(getPublicKey().getModulus()) != -1){
      logger.warning("Overflow occured in multiply()");
    }
    final int exponent = operand1.getExponent() + operand2.getExponent();
    return new EncryptedNumber(this, result.mod(getPublicKey().getModulus()), exponent);
  }
  
  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    }
    if (o == null || o.getClass() != MockPaillierContext.class) {
      return false;
    }
    MockPaillierContext context = (MockPaillierContext) o;
    return getPublicKey().equals(context.getPublicKey()) &&
            isSigned() == context.isSigned() &&
            getPrecision() == context.getPrecision();
  }

  public boolean equals(MockPaillierContext o) {
    return o == this || (o != null &&
            getPublicKey().equals(o.getPublicKey()) &&
            isSigned() == o.isSigned() &&
            getPrecision() == o.getPrecision());
  }
}
