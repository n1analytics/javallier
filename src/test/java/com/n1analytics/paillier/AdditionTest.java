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

import static com.n1analytics.paillier.TestConfiguration.DEFAULT_KEY_SIZE;
import static com.n1analytics.paillier.TestUtil.*;
import static org.junit.Assert.assertEquals;
import static com.n1analytics.paillier.TestConfiguration.SIGNED_FULL_PRECISION;

@Category(SlowTests.class)
public class AdditionTest {
  static private PaillierContext context = SIGNED_FULL_PRECISION.context();
  static private PaillierPrivateKey privateKey = SIGNED_FULL_PRECISION.privateKey();

  static private int bigIntegerBitLength = DEFAULT_KEY_SIZE / 2 - 1;

  static private int maxIteration = 100;

  interface BinaryAdder1
          extends TwoInputsFunction<EncryptedNumber, EncryptedNumber, EncryptedNumber> {

    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2);
  }

  interface BinaryAdder2
          extends TwoInputsFunction<EncryptedNumber, EncodedNumber, EncryptedNumber> {

    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2);
  }

  interface BinaryAdder4
          extends TwoInputsFunction<EncodedNumber, EncodedNumber, EncodedNumber> {

    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
  }

  BinaryAdder1 binaryAdders1[] = new BinaryAdder1[]{new BinaryAdder1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return arg1.add(arg2);
    }
  }, new BinaryAdder1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return arg2.add(arg1);
    }
  }, new BinaryAdder1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return context.add(arg1, arg2);
    }
  }, new BinaryAdder1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return context.add(arg2, arg1);
    }
  }};

  BinaryAdder2 binaryAdders2[] = new BinaryAdder2[]{new BinaryAdder2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return arg1.add(arg2);
    }
  }, new BinaryAdder2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return arg2.add(arg1);
    }
  }, new BinaryAdder2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return context.add(arg1, arg2);
    }
  }, new BinaryAdder2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return context.add(arg2, arg1);
    }
  }};

  BinaryAdder4 binaryAdders4[] = new BinaryAdder4[]{new BinaryAdder4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg1.add(arg2);
    }
  }, new BinaryAdder4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg2.add(arg1);
    }
  }, new BinaryAdder4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.add(arg1, arg2);
    }
  }, new BinaryAdder4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.add(arg2, arg1);
    }
  }};

  void testDoubleAddition(BinaryAdder1 adder) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = a + b;
      if(Double.isInfinite(plainResult))
        continue;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = adder.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      if (!context.isValid(context.encode(a).add(context.encode(b)))) {
        continue;
      }

      try {
        decodedResult = decryptedResult.decodeDouble();

        if (Math.getExponent(decodedResult) > 0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
        } else {
          tolerance = EPSILON;
        }

        if (!Double.isNaN(decodedResult)) {
          if (!Double.isInfinite(decodedResult)) {
            assertEquals(plainResult, decodedResult, tolerance);
          }
        }
      } catch (DecodeException e) {
      }
    }
  }

  void testLongAddition(BinaryAdder1 adder) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = a + b;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = adder.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerAddition(BinaryAdder1 adder) {
    BigInteger a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

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

      plainResult = a.add(b);

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = adder.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      if (!context.isValid(context.encode(a).add(context.encode(b)))) {
        continue;
      }

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testDoubleAddition(BinaryAdder2 adder) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = a + b;
      if(Double.isInfinite(plainResult))
        continue;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = adder.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      if (!context.isValid(context.encode(a).add(context.encode(b)))) {
        continue;
      }

      try {
        decodedResult = decryptedResult.decodeDouble();

        if (Math.getExponent(decodedResult) > 0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
        } else {
          tolerance = EPSILON;
        }

        if (!Double.isNaN(decodedResult)) {
          if (!Double.isInfinite(decodedResult)) {
            assertEquals(plainResult, decodedResult, tolerance);
          }
        }
      } catch (DecodeException e) {
      }
    }
  }

  void testLongAddition(BinaryAdder2 adder) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = a + b;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = adder.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerAddition(BinaryAdder2 adder) {
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

      plainResult = a.add(b);

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = adder.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      if (!context.isValid(context.encode(a).add(context.encode(b)))) {
        continue;
      }

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testDoubleAddition(BinaryAdder4 adder) {
    double a, b, plainResult, decodedResult, tolerance;
    EncodedNumber encodedA, encodedB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = a + b;
      if(Double.isInfinite(plainResult))
        continue;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

      if (!context.isValid(context.encode(a).add(context.encode(b)))) {
        continue;
      }

      try {
        encodedResult = adder.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeDouble();

        if (Math.getExponent(decodedResult) > 0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
        } else {
          tolerance = EPSILON;
        }

        if (!Double.isNaN(decodedResult)) {
          if (!Double.isInfinite(decodedResult)) {
            assertEquals(plainResult, decodedResult, tolerance);
          }
        }
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

  void testLongAddition(BinaryAdder4 adder) {
    long a, b, plainResult, decodedResult;
    EncodedNumber encodedA, encodedB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = a + b;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

      try {
        encodedResult = adder.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerAddition(BinaryAdder4 adder) {
    BigInteger a, b, plainResult, decodedResult;
    EncodedNumber encodedA, encodedB, encodedResult;

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

      plainResult = a.add(b);

      encodedA = context.encode(a);
      encodedB = context.encode(b);

      if (!context.isValid(context.encode(a).add(context.encode(b)))) {
        continue;
      }

      try {
        encodedResult = adder.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void testAdditionEncryptedNumbers1() throws Exception {
    for (BinaryAdder1 adder : binaryAdders1) {
      testDoubleAddition(adder);
      testLongAddition(adder);
      testBigIntegerAddition(adder);
    }
  }

  @Test
  public void testAdditionEncryptedNumbers2() throws Exception {
    for (BinaryAdder2 adder : binaryAdders2) {
      testDoubleAddition(adder);
      testLongAddition(adder);
      testBigIntegerAddition(adder);
    }
  }

  @Test
  public void testAdditionEncodedNumbers1() throws Exception {
    for (BinaryAdder4 adder : binaryAdders4) {
      testDoubleAddition(adder);
      testLongAddition(adder);
      testBigIntegerAddition(adder);
    }
  }

}
