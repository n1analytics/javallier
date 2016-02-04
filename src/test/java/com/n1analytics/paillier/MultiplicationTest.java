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

import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.math.BigInteger;

import static com.n1analytics.paillier.TestConfiguration.SIGNED_FULL_PRECISION;
import static com.n1analytics.paillier.TestUtil.*;
import static org.junit.Assert.assertEquals;

@Category(SlowTests.class)
public class MultiplicationTest {
  static private PaillierContext context = SIGNED_FULL_PRECISION.context();
  static private PaillierPrivateKey privateKey = SIGNED_FULL_PRECISION.privateKey();

  static private int bigIntegerBitLength = PaillierContext.DEFAULT_BASE / 2 - 1;

  static private int maxIteration = 100;

  interface BinaryMultiplier1
          extends TwoInputsFunction<EncryptedNumber, EncodedNumber, EncryptedNumber> {

    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2);
  }

  interface BinaryMultiplier3
          extends TwoInputsFunction<EncodedNumber, EncodedNumber, EncodedNumber> {

    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
  }

  BinaryMultiplier1 binaryMultipliers1[] = new BinaryMultiplier1[]{new BinaryMultiplier1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return arg1.multiply(arg2);
    }
  }, new BinaryMultiplier1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return arg2.multiply(arg1);
    }
  }, new BinaryMultiplier1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return context.multiply(arg1, arg2);
    }
  }, new BinaryMultiplier1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return context.multiply(arg2, arg1);
    }
  }};

  BinaryMultiplier3 binaryMultipliers3[] = new BinaryMultiplier3[]{new BinaryMultiplier3() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg1.multiply(arg2);
    }
  }, new BinaryMultiplier3() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg2.multiply(arg1);
    }
  }, new BinaryMultiplier3() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.multiply(arg1, arg2);
    }
  }, new BinaryMultiplier3() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.multiply(arg2, arg1);
    }
  }};

  void testDoubleMultiplication(BinaryMultiplier1 multiplier) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = a * b;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = multiplier.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeDouble();

        if (Math.getExponent(decodedResult) > 0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
        } else {
          tolerance = EPSILON;
        }

        if (!Double.isInfinite(plainResult)) {
          assertEquals(plainResult, decodedResult, tolerance);
        }
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testLongMultiplication(BinaryMultiplier1 multiplier) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = a * b;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = multiplier.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerMultiplication(BinaryMultiplier1 multiplier) {
    BigInteger a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = new BigInteger(bigIntegerBitLength, random);
      b = new BigInteger(bigIntegerBitLength, random);

      // The random generator above only generates positive BigIntegers, the following code
      // negates some inputs.
      if (i % 4 == 1) {
        b = b.negate();
      } else if (i % 4 == 2) {
        a = a.negate();
      } else if (i % 4 == 3) {
        a = a.negate();
        b = b.negate();
      }

      plainResult = a.multiply(b);

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = multiplier.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testDoubleMultiplication(BinaryMultiplier3 multiplier) {
    double a, b, plainResult, decodedResult, tolerance;
    EncodedNumber encodedNumberA, encodedNumberB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = a * b;

      encodedNumberA = context.encode(a);
      encodedNumberB = context.encode(b);

      encodedResult = multiplier.eval(encodedNumberA, encodedNumberB);

      try {
        decodedResult = encodedResult.decodeDouble();

        if (Math.getExponent(decodedResult) > 0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
        } else {
          tolerance = EPSILON;
        }

        if (!Double.isInfinite(plainResult)) {
          assertEquals(plainResult, decodedResult, tolerance);
        }
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testLongMultiplication(BinaryMultiplier3 multiplier) {
    long a, b, plainResult, decodedResult;
    EncodedNumber encodedNumberA, encodedNumberB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = a * b;

      encodedNumberA = context.encode(a);
      encodedNumberB = context.encode(b);

      encodedResult = multiplier.eval(encodedNumberA, encodedNumberB);

      try {
        decodedResult = encodedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerMultiplication(BinaryMultiplier3 multiplier) {
    BigInteger a, b, plainResult, decodedResult;
    EncodedNumber encodedNumberA, encodedNumberB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = new BigInteger(bigIntegerBitLength, random);
      b = new BigInteger(bigIntegerBitLength, random);

      // The random generator above only generates positive BigIntegers, the following code
      // negates some inputs.
      if (i % 4 == 1) {
        b = b.negate();
      } else if (i % 4 == 2) {
        a = a.negate();
      } else if (i % 4 == 3) {
        a = a.negate();
        b = b.negate();
      }

      plainResult = a.multiply(b);

      encodedNumberA = context.encode(a);
      encodedNumberB = context.encode(b);

      encodedResult = multiplier.eval(encodedNumberA, encodedNumberB);

      try {
        decodedResult = encodedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void testMultiplicationEncryptedNumbers1() throws Exception {
    for (BinaryMultiplier1 multiplier : binaryMultipliers1) {
      testDoubleMultiplication(multiplier);
      testLongMultiplication(multiplier);
      testBigIntegerMultiplication(multiplier);
    }
  }

  @Test
  public void testMultiplicationEncryptedNumbers3() throws Exception {
    for (BinaryMultiplier3 multiplier : binaryMultipliers3) {
      testDoubleMultiplication(multiplier);
      testLongMultiplication(multiplier);
      testBigIntegerMultiplication(multiplier);
    }
  }
}
