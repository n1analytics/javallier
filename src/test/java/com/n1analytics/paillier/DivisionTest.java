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

import static com.n1analytics.paillier.TestUtil.random;
import static com.n1analytics.paillier.TestUtil.randomFiniteDouble;
import static org.junit.Assert.assertEquals;

@Category(SlowTests.class)
public class DivisionTest {

  static private final double EPSILON = 0.1;

  static private final int keySize = 2104;

  static private PaillierPrivateKey privateKey = PaillierPrivateKey.create(keySize);
  static private PaillierPublicKey publicKey = privateKey.getPublicKey();
  static private PaillierContext context = publicKey.createSignedContext();

  static private int maxIteration = 100;

  @Test
  public void testDivideEncryptedNumber1() throws Exception {
    double a, b, invertedB, plainResult, decodedResult, tolerance;
    EncryptedNumber cipherTextA, encryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      invertedB = 1 / b;
      if (Double.isInfinite(invertedB)) {
        continue;
      }

      plainResult = a / b;

      cipherTextA = context.encrypt(a);

      encryptedResult = cipherTextA.divide(b);

      if (!context.isValid(context.encode(a).divide(b))) {
        continue;
      }

      try {
        decodedResult = encryptedResult.decrypt(privateKey).decodeDouble();

        if (Math.getExponent(decodedResult) > 0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
        } else {
          tolerance = EPSILON;
        }

        if (!Double.isInfinite(plainResult)) {
          assertEquals(plainResult, decodedResult, tolerance);
        }
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void testDivideEncryptedNumber2() throws Exception {
    long b;
    double a, invertedB, plainResult, decodedResult, tolerance;
    EncryptedNumber cipherTextA, encryptedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = random.nextLong();

      invertedB = 1 / (double) b;
      if (Double.isInfinite(invertedB)) {
        continue;
      }

      plainResult = a / (double) b;

      cipherTextA = context.encrypt(a);

      encryptedResult = cipherTextA.divide(b);

      if (!context.isValid(context.encode(a).divide(b))) {
        continue;
      }

      try {
        decodedResult = encryptedResult.decrypt(privateKey).decodeDouble();

        if (Math.getExponent(decodedResult) > 0) {
          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
        } else {
          tolerance = EPSILON;
        }

        if (!Double.isInfinite(plainResult)) {
          assertEquals(plainResult, decodedResult, tolerance);
        }
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void testDivideEncodedNumber1() throws Exception {
    double a, b, invertedB, plainResult, decodedResult, tolerance;
    EncodedNumber encodedNumberA, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = randomFiniteDouble();

      invertedB = 1 / b;
      if (Double.isInfinite(invertedB)) {
        continue;
      }

      plainResult = a / b;

      encodedNumberA = context.encode(a);

      encodedResult = encodedNumberA.divide(b);

      if (!context.isValid(context.encode(a).divide(b))) {
        continue;
      }

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
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

  @Test
  public void testDivideEncodedNumber2() throws Exception {
    long b;
    double a, invertedB, plainResult, decodedResult, tolerance;
    EncodedNumber encodedNumberA, encodedResult;

    for (int i = 0; i < maxIteration; i++) {
      a = randomFiniteDouble();
      b = random.nextLong();

      invertedB = 1 / (double) b;
      if (Double.isInfinite(invertedB)) {
        continue;
      }

      plainResult = a / (double) b;

      encodedNumberA = context.encode(a);

      encodedResult = encodedNumberA.divide(b);

      if (!context.isValid(context.encode(a).divide(b))) {
        continue;
      }

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
      } catch (DecodeException e) {
      } catch (ArithmeticException e) {
      }
    }
  }

//  @Test
//  public void testDivideNumber1() throws Exception {
//    double a, b, invertedB, plainResult, decodedResult, tolerance;
//    Number numberA, numberResult;
//
//    for (int i = 0; i < maxIteration; i++) {
//      a = randomFiniteDouble();
//      b = randomFiniteDouble();
//
//      invertedB = 1 / b;
//      if (Double.isInfinite(invertedB)) {
//        continue;
//      }
//
//      plainResult = a / b;
//
//      numberA = Number.encode(a);
//
//      numberResult = numberA.divide(b);
//
//      if (!context.isValid(numberResult)) {
//        continue;
//      }
//
//      try {
//        decodedResult = numberResult.decodeDouble();
//
//        if (Math.getExponent(decodedResult) > 0) {
//          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
//        } else {
//          tolerance = EPSILON;
//        }
//
//        if (!Double.isInfinite(plainResult)) {
//          assertEquals(plainResult, decodedResult, tolerance);
//        }
//      } catch (DecodeException e) {
//      } catch (ArithmeticException e) {
//      }
//    }
//  }

//  @Test
//  public void testDivideNumber2() throws Exception {
//    long b;
//    double a, invertedB, plainResult, decodedResult, tolerance;
//    Number numberA, numberResult;
//
//    for (int i = 0; i < maxIteration; i++) {
//      a = randomFiniteDouble();
//      b = random.nextLong();
//
//      invertedB = 1 / (double) b;
//      if (Double.isInfinite(invertedB)) {
//        continue;
//      }
//
//      plainResult = a / (double) b;
//
//      numberA = Number.encode(a);
//
//      numberResult = numberA.divide(b);
//
//      if (!context.isValid(numberResult)) {
//        continue;
//      }
//
//      try {
//        decodedResult = numberResult.decodeDouble();
//
//        if (Math.getExponent(decodedResult) > 0) {
//          tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
//        } else {
//          tolerance = EPSILON;
//        }
//
//        if (!Double.isInfinite(plainResult)) {
//          assertEquals(plainResult, decodedResult, tolerance);
//        }
//      } catch (DecodeException e) {
//      } catch (ArithmeticException e) {
//      }
//    }
//  }
}
