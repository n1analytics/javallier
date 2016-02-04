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
public class SubtractionTest {
  static private PaillierContext context = SIGNED_FULL_PRECISION.context();
  static private PaillierPrivateKey privateKey = SIGNED_FULL_PRECISION.privateKey();

  static private int bigIntegerBitLength = PaillierContext.DEFAULT_BASE / 2 - 1;

  static private int maxIteration = 100;

  interface BinarySubtractor1
          extends TwoInputsFunction<EncryptedNumber, EncryptedNumber, EncryptedNumber> {

    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2);
  }

  interface BinarySubtractor2
          extends TwoInputsFunction<EncryptedNumber, EncodedNumber, EncryptedNumber> {

    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2);
  }

  interface BinarySubtractor4
          extends TwoInputsFunction<EncodedNumber, EncodedNumber, EncodedNumber> {

    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
  }

  BinarySubtractor1 binarySubtractors1[] = new BinarySubtractor1[]{new BinarySubtractor1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return arg1.subtract(arg2);
    }
  }, new BinarySubtractor1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return context.subtract(arg1, arg2);
    }
  }};

  BinarySubtractor1 binarySubtractorsRight1[] = new BinarySubtractor1[]{new BinarySubtractor1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return arg2.subtract(arg1);
    }
  }, new BinarySubtractor1() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
      return context.subtract(arg2, arg1);
    }
  }};

  BinarySubtractor2 binarySubtractors2[] = new BinarySubtractor2[]{new BinarySubtractor2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return arg1.subtract(arg2);
    }
  }, new BinarySubtractor2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return context.subtract(arg1, arg2);
    }
  }};

  BinarySubtractor2 binarySubtractorsRight2[] = new BinarySubtractor2[]{new BinarySubtractor2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return arg2.subtract(arg1);
    }
  }, new BinarySubtractor2() {
    @Override
    public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
      return context.subtract(arg2, arg1);
    }
  }};

  BinarySubtractor4 binarySubtractors4[] = new BinarySubtractor4[]{new BinarySubtractor4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg1.subtract(arg2);
    }
  }, new BinarySubtractor4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.subtract(arg1, arg2);
    }
  }};

  BinarySubtractor4 binarySubtractorsRight4[] = new BinarySubtractor4[]{new BinarySubtractor4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return arg2.subtract(arg1);
    }
  }, new BinarySubtractor4() {
    @Override
    public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
      return context.subtract(arg2, arg1);
    }
  }};

  void testDoubleSubtraction(BinarySubtractor1 subtractor) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = a - b;
      if(Double.isInfinite(plainResult))
        continue;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

        if (!context.isValid(context.encode(a).subtract(context.encode(b)))) {
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

  void testDoubleSubtractionRight(BinarySubtractor1 subtractor) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = b - a;
      if(Double.isInfinite(plainResult))
        continue;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      if (!context.isValid(context.encode(b).subtract(context.encode(a)))) {
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

  void testLongSubtraction(BinarySubtractor1 subtractor) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = a - b;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testLongSubtractionRight(BinarySubtractor1 subtractor) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = b - a;

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerSubtraction(BinarySubtractor1 subtractor) {
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

      plainResult = a.subtract(b);

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

        if (!context.isValid(context.encode(a).subtract(context.encode(b)))) {
            continue;
        }

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testBigIntegerSubtractionRight(BinarySubtractor1 subtractor) {
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

      plainResult = b.subtract(a);

      ciphertTextA = context.encrypt(a);
      ciphertTextB = context.encrypt(b);

      encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
      decryptedResult = encryptedResult.decrypt(privateKey);

        if (!context.isValid(context.encode(b).subtract(context.encode(a)))) {
            continue;
        }

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testDoubleSubtraction(BinarySubtractor2 subtractor) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = a - b;
      if(Double.isInfinite(plainResult))
        continue;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = subtractor.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

        if (!context.isValid(context.encode(a).subtract(context.encode(b)))) {
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

  void testDoubleSubtractionRight(BinarySubtractor2 subtractor) {
    double a, b, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = b - a;
      if(Double.isInfinite(plainResult))
        continue;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = subtractor.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

        if (!context.isValid(context.encode(b).subtract(context.encode(a)))) {
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

  void testLongSubtraction(BinarySubtractor2 subtractor) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = a - b;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = subtractor.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testLongSubtractionRight(BinarySubtractor2 subtractor) {
    long a, b, plainResult, decodedResult;
    EncryptedNumber ciphertTextA, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = b - a;

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = subtractor.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

      try {
        decodedResult = decryptedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerSubtraction(BinarySubtractor2 subtractor) {
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

      plainResult = a.subtract(b);

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = subtractor.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

        if (!context.isValid(context.encode(a).subtract(context.encode(b)))) {
            continue;
        }

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testBigIntegerSubtractionRight(BinarySubtractor2 subtractor) {
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

      plainResult = b.subtract(a);

      ciphertTextA = context.encrypt(a);
      encodedB = context.encode(b);

      encryptedResult = subtractor.eval(ciphertTextA, encodedB);
      decryptedResult = encryptedResult.decrypt(privateKey);

        if (!context.isValid(context.encode(b).subtract(context.encode(a)))) {
            continue;
        }

      try {
        decodedResult = decryptedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testDoubleSubtraction(BinarySubtractor4 subtractor) {
    double a, b, plainResult, decodedResult, tolerance;
    EncodedNumber encodedA, encodedB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = a - b;
      if(Double.isInfinite(plainResult))
        continue;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

        if (!context.isValid(context.encode(a).subtract(context.encode(b)))) {
            continue;
        }

      try {
        encodedResult = subtractor.eval(encodedA, encodedB);
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

  void testDoubleSubtractionRight(BinarySubtractor4 subtractor) {
    double a, b, plainResult, decodedResult, tolerance;
    EncodedNumber encodedA, encodedB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      plainResult = b - a;
      if(Double.isInfinite(plainResult))
        continue;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

        if (!context.isValid(context.encode(b).subtract(context.encode(a)))) {
            continue;
        }

      try {
        encodedResult = subtractor.eval(encodedA, encodedB);
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

  void testLongSubtraction(BinarySubtractor4 subtractor) {
    long a, b, plainResult, decodedResult;
    EncodedNumber encodedA, encodedB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = a - b;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

      try {
        encodedResult = subtractor.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testLongSubtractionRight(BinarySubtractor4 subtractor) {
    long a, b, plainResult, decodedResult;
    EncodedNumber encodedA, encodedB, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();

      plainResult = b - a;

      encodedA = context.encode(a);
      encodedB = context.encode(b);

      try {
        encodedResult = subtractor.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeLong();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  void testBigIntegerSubtraction(BinarySubtractor4 subtractor) {
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

      plainResult = a.subtract(b);

      encodedA = context.encode(a);
      encodedB = context.encode(b);

        if (!context.isValid(context.encode(a).subtract(context.encode(b)))) {
            continue;
        }

      try {
        encodedResult = subtractor.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  void testBigIntegerSubtractionRight(BinarySubtractor4 subtractor) {
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

      plainResult = b.subtract(a);

      encodedA = context.encode(a);
      encodedB = context.encode(b);

        if (!context.isValid(context.encode(b).subtract(context.encode(a)))) {
            continue;
        }

      try {
        encodedResult = subtractor.eval(encodedA, encodedB);
        decodedResult = encodedResult.decodeBigInteger();

        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void testSubtractionEncryptedNumbers1() throws Exception {
    for (BinarySubtractor1 subtractor : binarySubtractors1) {
      testDoubleSubtraction(subtractor);
      testLongSubtraction(subtractor);
      testBigIntegerSubtraction(subtractor);
    }

    for (BinarySubtractor1 subtractor : binarySubtractorsRight1) {
      testDoubleSubtractionRight(subtractor);
      testLongSubtractionRight(subtractor);
      testBigIntegerSubtractionRight(subtractor);
    }
  }

  @Test
  public void testSubtractionEncryptedNumbers2() throws Exception {
    for (BinarySubtractor2 subtractor : binarySubtractors2) {
      testDoubleSubtraction(subtractor);
      testLongSubtraction(subtractor);
      testBigIntegerSubtraction(subtractor);
    }

    for (BinarySubtractor2 subtractor : binarySubtractorsRight2) {
      testDoubleSubtractionRight(subtractor);
      testLongSubtractionRight(subtractor);
      testBigIntegerSubtractionRight(subtractor);
    }
  }

  @Test
  public void testSubtractionEncodedNumbers1() throws Exception {
    for (BinarySubtractor4 subtractor : binarySubtractors4) {
      testDoubleSubtraction(subtractor);
      testLongSubtraction(subtractor);
      testBigIntegerSubtraction(subtractor);
    }

    for (BinarySubtractor4 subtractor : binarySubtractorsRight4) {
      testDoubleSubtractionRight(subtractor);
      testLongSubtractionRight(subtractor);
      testBigIntegerSubtractionRight(subtractor);
    }
  }

}
