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
import static com.n1analytics.paillier.TestConfiguration.SIGNED_FULL_PRECISION;
import static com.n1analytics.paillier.TestUtil.*;
import static org.junit.Assert.assertEquals;

@Category(SlowTests.class)
public class FuzzTest {
  static private PaillierContext context = SIGNED_FULL_PRECISION.context();
  static private PaillierPrivateKey privateKey = SIGNED_FULL_PRECISION.privateKey();

  static private int bigIntegerBitLength = DEFAULT_KEY_SIZE / 2 - 1;


  static private int maxIteration = 100;

  @Test
  public void fuzzDoubleMixOperations1() throws Exception {
    double a, b, c, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertextA, ciphertextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();
      c = randomFiniteDouble();

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);

      plainResult = (a + b) * c;
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult = (ciphertextA.add(ciphertextB)).multiply(c);
      decryptedResult = privateKey.decrypt(encryptedResult);

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
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzDoubleMixOperations2() throws Exception {
    double a, b, c, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertextA, ciphertextC, encryptedResult1, encryptedResult2;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();
      c = randomFiniteDouble();

      ciphertextA = context.encrypt(a);
      ciphertextC = context.encrypt(c);

      plainResult = a * b + c;
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult1 = ciphertextA.multiply(b);
      encryptedResult2 = encryptedResult1.add(ciphertextC);
      decryptedResult = privateKey.decrypt(encryptedResult2);

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
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzDoubleMixOperations3() throws Exception {
    double a, b, c, d, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertextA, ciphertextB, encryptedResult1, encryptedResult2;
    EncodedNumber encodedC, encodedD, additionResult, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();
      c = randomFiniteDouble();
      d = randomFiniteDouble();

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);
      encodedC = context.encode(c);
      encodedD = context.encode(d);

      plainResult = a + b * (c + d);
      if(isResultValid(context, plainResult))
        continue;

      additionResult = encodedC.add(encodedD);
      encryptedResult1 = ciphertextB.multiply(additionResult);
      encryptedResult2 = ciphertextA.add(encryptedResult1);

      decryptedResult = privateKey.decrypt(encryptedResult2);

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
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzDoubleMixOperations4() throws Exception {
    double a, b, c, d, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertextA, ciphertextB, encryptedResult1, encryptedResult2, encryptedResult3;
    EncodedNumber encodedC, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();
      c = randomFiniteDouble();
      d = randomFiniteDouble();

      if (Double.isInfinite(1 / d) || Double.isNaN(1/d)) {
        continue;
      }

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);
      encodedC = context.encode(c);

      plainResult = (a + (b * c)) / d;
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult1 = ciphertextB.multiply(encodedC);
      encryptedResult2 = ciphertextA.add(encryptedResult1);
      encryptedResult3 = encryptedResult2.divide(d);

      decryptedResult = privateKey.decrypt(encryptedResult3);

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
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzDoubleMixOperations5() throws Exception {
    double a, b, c, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertextA, ciphertextB, ciphertextC, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();
      c = randomFiniteDouble();

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);
      ciphertextC = context.encrypt(c);

      plainResult = a + b + c;
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult = ciphertextA.add(ciphertextB).add(ciphertextC);

      decryptedResult = privateKey.decrypt(encryptedResult);

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
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzDoubleMixOperations6() throws Exception {
    double a, b, c, plainResult, decodedResult, tolerance;
    EncryptedNumber ciphertextA, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();
      c = randomFiniteDouble();

      ciphertextA = context.encrypt(a);

      plainResult = a * b * c;
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult = ciphertextA.multiply(b).multiply(c);

      decryptedResult = privateKey.decrypt(encryptedResult);

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
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzLongMixOperations1() throws Exception {
    long a, b, c, plainResult, decodedResult;
    EncryptedNumber ciphertextA, ciphertextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();
      c = random.nextLong();

      plainResult = (a + b) * c;

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);

      encryptedResult = (ciphertextA.add(ciphertextB)).multiply(c);
      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeLong();
        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  @Test
  public void fuzzLongMixOperations2() throws Exception {
    long a, b, c, plainResult, decodedResult;
    EncryptedNumber ciphertextA, ciphertextC, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();
      c = random.nextLong();

      ciphertextA = context.encrypt(a);
      ciphertextC = context.encrypt(c);

      plainResult = a * b + c;

      encryptedResult = ciphertextA.multiply(b).add(ciphertextC);
      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeLong();
        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  @Test
  public void fuzzLongMixOperations3() throws Exception {
    long a, b, c, d, plainResult, decodedResult;
    EncryptedNumber ciphertextA, ciphertextB, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();
      c = random.nextLong();
      d = random.nextLong();

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);

      plainResult = a + b * (c + d);

      encryptedResult = ciphertextA.add(ciphertextB.multiply(c + d));
      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeLong();
        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      } catch (DecodeException e) {
      }
    }
  }

  @Test
  public void fuzzLongMixOperations5() throws Exception {
    long a, b, c, plainResult, decodedResult;
    EncryptedNumber ciphertextA, ciphertextB, ciphertextC, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();
      c = random.nextLong();

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);
      ciphertextC = context.encrypt(c);

      plainResult = a + b + c;

      encryptedResult = ciphertextA.add(ciphertextB).add(ciphertextC);

      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeLong();
        assertEquals(plainResult, decodedResult);
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzLongMixOperations6() throws Exception {
    long a, b, c, plainResult, decodedResult;
    EncryptedNumber ciphertextA, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = random.nextLong();
      b = random.nextLong();
      c = random.nextLong();

      ciphertextA = context.encrypt(a);

      plainResult = a * b * c;

      encryptedResult = ciphertextA.multiply(b).multiply(c);

      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeLong();
        assertEquals(plainResult, decodedResult);
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzBigIntegerMixOperations1() throws Exception {
    BigInteger a, b, c, plainResult, decodedResult;
    EncryptedNumber ciphertextA, ciphertextB, encryptedResult;
    EncodedNumber encodedC, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = new BigInteger(bigIntegerBitLength, random);
      b = new BigInteger(bigIntegerBitLength, random);
      c = new BigInteger(bigIntegerBitLength, random);

      plainResult = (a.add(b)).multiply(c);
      if(!isResultValid(context, plainResult))
        continue;

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);
      encodedC = context.encode(c);

      encryptedResult = (ciphertextA.add(ciphertextB)).multiply(encodedC);

      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeBigInteger();
        assertEquals(plainResult.toString(), decodedResult.toString());
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzBigIntegerMixOperations2() throws Exception {
    BigInteger a, b, c, plainResult, decodedResult;
    EncryptedNumber ciphertextA, ciphertextC, encryptedResult;
    EncodedNumber encodedB, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = new BigInteger(bigIntegerBitLength, random);
      b = new BigInteger(bigIntegerBitLength, random);
      c = new BigInteger(bigIntegerBitLength, random);

      ciphertextA = context.encrypt(a);
      encodedB = context.encode(b);
      ciphertextC = context.encrypt(c);

      plainResult = a.multiply(b).add(c);
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult = ciphertextA.multiply(encodedB).add(ciphertextC);

      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeBigInteger();
        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzBigIntegerMixOperations3() throws Exception {
    BigInteger a, b, c, d, plainResult, decodedResult;
    EncryptedNumber ciphertextA, ciphertextB, encryptedResult;
    EncodedNumber encodedC, encodedD, decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = new BigInteger(bigIntegerBitLength, random);
      b = new BigInteger(bigIntegerBitLength, random);
      c = new BigInteger(bigIntegerBitLength, random);
      d = new BigInteger(bigIntegerBitLength, random);

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);
      encodedC = context.encode(c);
      encodedD = context.encode(d);

      plainResult = a.add(b.multiply(c.add(d)));
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult = ciphertextA.add(ciphertextB.multiply(encodedC.add(encodedD)));

      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeBigInteger();
        assertEquals(plainResult, decodedResult);
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzBigIntegerMixOperations5() throws Exception {
    BigInteger a, b, c, plainResult, decodedResult;
    EncryptedNumber ciphertextA, ciphertextB, ciphertextC, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = new BigInteger(bigIntegerBitLength, random);
      b = new BigInteger(bigIntegerBitLength, random);
      c = new BigInteger(bigIntegerBitLength, random);

      ciphertextA = context.encrypt(a);
      ciphertextB = context.encrypt(b);
      ciphertextC = context.encrypt(c);

      plainResult = a.add(b).add(c);
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult = ciphertextA.add(ciphertextB).add(ciphertextC);

      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeBigInteger();
        assertEquals(plainResult, decodedResult);
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void fuzzBigIntegerMixOperations6() throws Exception {
    BigInteger a, b, c, plainResult, decodedResult;
    EncryptedNumber ciphertextA, encryptedResult;
    EncodedNumber decryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = new BigInteger(bigIntegerBitLength, random);
      b = new BigInteger(bigIntegerBitLength, random);
      c = new BigInteger(bigIntegerBitLength, random);

      ciphertextA = context.encrypt(a);

      plainResult = a.multiply(b).multiply(c);
      if(!isResultValid(context, plainResult))
        continue;

      encryptedResult = ciphertextA.multiply(b).multiply(c);

      decryptedResult = privateKey.decrypt(encryptedResult);

      try {
        decodedResult = decryptedResult.decodeBigInteger();
        assertEquals(plainResult, decodedResult);
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

}
