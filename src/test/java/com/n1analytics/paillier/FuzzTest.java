/**
 * Copyright 2015 NICTA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.n1analytics.paillier;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.math.BigInteger;

import static com.n1analytics.paillier.TestUtil.random;
import static com.n1analytics.paillier.TestUtil.randomFiniteDouble;
import static org.junit.Assert.assertEquals;

@Category(SlowTests.class)
public class FuzzTest {
    static private final double EPSILON = 0.1;

    static private final int keySize = 2104;

    static private int bigIntegerBitLength = keySize / 2 - 1;

    static private PaillierPrivateKey privateKey = PaillierPrivateKey.create(keySize);
    static private PaillierPublicKey publicKey = privateKey.getPublicKey();
    static private PaillierContext signedContext = publicKey.createSignedContext();

    static private int maxIteration = 100;

    @Test
    public void fuzzDoubleMixOperations1() throws Exception {
        double a, b, c, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertextA, ciphertextB, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberC, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();
            c = randomFiniteDouble();

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);
            numberC = Number.encode(c);

            // Check if the computation would result in overflow
            numberResult = (Number.encode(a).add(Number.encode(b))).multiply(numberC);
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = (a + b) * c;

            encryptedResult = (ciphertextA.add(ciphertextB)).multiply(numberC);
            decryptedResult = privateKey.decrypt(encryptedResult);

            try {
                decodedResult = decryptedResult.decodeDouble();

                if (Math.getExponent(decodedResult) > 0) {
                    tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
                } else {
                    tolerance = EPSILON;
                }

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
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
        Number numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();
            c = randomFiniteDouble();

            ciphertextA = signedContext.encrypt(a);
            numberB = Number.encode(b);
            ciphertextC = signedContext.encrypt(c);

            // Check if the computation would result in overflow
            numberResult = Number.encode(a).multiply(numberB).add(Number.encode(c));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = a * b + c;

            encryptedResult1 = ciphertextA.multiply(numberB);
            encryptedResult2 = encryptedResult1.add(ciphertextC);
            decryptedResult = privateKey.decrypt(encryptedResult2);

            try {
                decodedResult = decryptedResult.decodeDouble();

                if (Math.getExponent(decodedResult) > 0) {
                    tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
                } else {
                    tolerance = EPSILON;
                }

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
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
        EncodedNumber decryptedResult;
        Number numberC, numberD, additionResult, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();
            c = randomFiniteDouble();
            d = randomFiniteDouble();

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);
            numberC = Number.encode(c);
            numberD = Number.encode(d);

            numberResult = Number.encode(a).add(Number.encode(b).multiply(numberC.add(numberD)));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = a + b * (c + d);

            additionResult = numberC.add(numberD);
            encryptedResult1 = ciphertextB.multiply(additionResult);
            encryptedResult2 = ciphertextA.add(encryptedResult1);

            decryptedResult = privateKey.decrypt(encryptedResult2);
            if(!signedContext.isValid(decryptedResult.decode()))
                continue;

            try {
                decodedResult = decryptedResult.decodeDouble();

                if (Math.getExponent(decodedResult) > 0) {
                    tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
                } else {
                    tolerance = EPSILON;
                }

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
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
        EncodedNumber decryptedResult;
        Number numberC, numberInverseD, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();
            c = randomFiniteDouble();
            d = randomFiniteDouble();

            if(Double.isInfinite(1 / d)) {
                continue;
            }

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);
            numberC = Number.encode(c);
            numberInverseD = Number.encode(1 / d);

            numberResult = Number.encode(a).add(Number.encode(b).multiply(numberC)).divide(d);
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = (a + (b * c)) / d;

            encryptedResult1 = ciphertextB.multiply(numberC);
            encryptedResult2 = ciphertextA.add(encryptedResult1);
            encryptedResult3 = encryptedResult2.divide(d);

            decryptedResult = privateKey.decrypt(encryptedResult3);
            if(!signedContext.isValid(decryptedResult.decode()))
                continue;

            try {
                decodedResult = decryptedResult.decodeDouble();

                if (Math.getExponent(decodedResult) > 0) {
                    tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
                } else {
                    tolerance = EPSILON;
                }

                if(!Double.isInfinite(plainResult))
                    assertEquals(plainResult, decodedResult, tolerance);
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
        Number numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();
            c = randomFiniteDouble();

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);
            ciphertextC = signedContext.encrypt(c);

            // Check if the computation would result in overflow
            numberResult = Number.encode(a).add(Number.encode(b)).add(Number.encode(c));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = a + b + c;

            encryptedResult = ciphertextA.add(ciphertextB).add(ciphertextC);

            decryptedResult = privateKey.decrypt(encryptedResult);

            try {
                decodedResult = decryptedResult.decodeDouble();

                if (Math.getExponent(decodedResult) > 0) {
                    tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
                } else {
                    tolerance = EPSILON;
                }

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
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
        Number numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();
            c = randomFiniteDouble();

            ciphertextA = signedContext.encrypt(a);

            // Check if the computation would result in overflow
            numberResult = Number.encode(a).multiply(Number.encode(b)).multiply(Number.encode(c));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = a * b * c;

            encryptedResult = ciphertextA.multiply(b).multiply(c);

            decryptedResult = privateKey.decrypt(encryptedResult);

            try {
                decodedResult = decryptedResult.decodeDouble();

                if (Math.getExponent(decodedResult) > 0) {
                    tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
                } else {
                    tolerance = EPSILON;
                }

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
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

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();
            c = random.nextLong();

            plainResult = (a + b) * c;

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);

            encryptedResult = (ciphertextA.add(ciphertextB)).multiply(c);
            decryptedResult = privateKey.decrypt(encryptedResult);

            try {
                decodedResult = decryptedResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    @Test
    public void fuzzLongMixOperations2() throws Exception {
        long a, b, c, plainResult, decodedResult;
        EncryptedNumber ciphertextA, ciphertextC, encryptedResult;
        EncodedNumber decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();
            c = random.nextLong();

            ciphertextA = signedContext.encrypt(a);
            ciphertextC = signedContext.encrypt(c);

            plainResult = a * b + c;

            encryptedResult = ciphertextA.multiply(b).add(ciphertextC);
            decryptedResult = privateKey.decrypt(encryptedResult);

            try{
                decodedResult = decryptedResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch(ArithmeticException e) {
            }
        }
    }

    @Test
    public void fuzzLongMixOperations3() throws Exception {
        long a, b, c, d, plainResult, decodedResult;
        EncryptedNumber ciphertextA, ciphertextB, encryptedResult;
        EncodedNumber decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();
            c = random.nextLong();
            d = random.nextLong();

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);

            plainResult = a + b * (c + d);

            encryptedResult = ciphertextA.add(ciphertextB.multiply(c + d));
            decryptedResult = privateKey.decrypt(encryptedResult);

            try {
                decodedResult = decryptedResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch(ArithmeticException e) {
            }
        }
    }

    @Test
    public void fuzzLongMixOperations5() throws Exception {
        long a, b, c, plainResult, decodedResult;
        EncryptedNumber ciphertextA, ciphertextB, ciphertextC, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();
            c = random.nextLong();

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);
            ciphertextC = signedContext.encrypt(c);

            // Check if the computation would result in overflow
            numberResult = Number.encode(a).add(Number.encode(b)).add(Number.encode(c));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

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
        Number numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();
            c = random.nextLong();

            ciphertextA = signedContext.encrypt(a);

            // Check if the computation would result in overflow
            numberResult = Number.encode(a).multiply(Number.encode(b)).multiply(Number.encode(c));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

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
        EncodedNumber decryptedResult;
        Number numberC, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);
            c = new BigInteger(bigIntegerBitLength, random);

            plainResult = (a.add(b)).multiply(c);

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);
            numberC = Number.encode(c);

            // Check if the computation would result in overflow
            numberResult = (Number.encode(a).add(Number.encode(b))).multiply(numberC);
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            encryptedResult = (ciphertextA.add(ciphertextB)).multiply(numberC);

            decryptedResult = privateKey.decrypt(encryptedResult);
            if(!signedContext.isValid(decryptedResult.decode()))
                continue;

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
        EncodedNumber decryptedResult;
        Number numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);
            c = new BigInteger(bigIntegerBitLength, random);

            ciphertextA = signedContext.encrypt(a);
            numberB = Number.encode(b);
            ciphertextC = signedContext.encrypt(c);

            // Check if the computation would result in overflow
            numberResult = Number.encode(a).multiply(numberB).add(Number.encode(c));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = a.multiply(b).add(c);

            encryptedResult = ciphertextA.multiply(numberB).add(ciphertextC);

            decryptedResult = privateKey.decrypt(encryptedResult);

            if(!signedContext.isValid(decryptedResult.decode()))
                continue;

            try{
                decodedResult = decryptedResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch(ArithmeticException e) {
            }
        }
    }

    @Test
    public void fuzzBigIntegerMixOperations3() throws Exception {
        BigInteger a, b, c, d, plainResult, decodedResult;
        EncryptedNumber ciphertextA, ciphertextB, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberC, numberD, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);
            c = new BigInteger(bigIntegerBitLength, random);
            d = new BigInteger(bigIntegerBitLength, random);

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);
            numberC = Number.encode(c);
            numberD = Number.encode(d);

            numberResult = Number.encode(a).add(Number.encode(b).multiply(numberC.add(numberD)));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = a.add(b.multiply(c.add(d)));

            encryptedResult = ciphertextA.add(ciphertextB.multiply(numberC.add(numberD)));

            decryptedResult = privateKey.decrypt(encryptedResult);

            if(!signedContext.isValid(decryptedResult.decode()))
                continue;

            try {
                decodedResult = decryptedResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch(ArithmeticException e) {
            }
        }
    }

    @Test
    public void fuzzBigIntegerMixOperations5() throws Exception {
        BigInteger a, b, c, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertextA, ciphertextB, ciphertextC, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);
            c = new BigInteger(bigIntegerBitLength, random);

            ciphertextA = signedContext.encrypt(a);
            ciphertextB = signedContext.encrypt(b);
            ciphertextC = signedContext.encrypt(c);

            // Check if the computation would result in overflow
            numberResult = Number.encode(a).add(Number.encode(b)).add(Number.encode(c));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = a.add(b).add(c);

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
        BigInteger a, b, c, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertextA, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);
            c = new BigInteger(bigIntegerBitLength, random);

            ciphertextA = signedContext.encrypt(a);

            // Check if the computation would result in overflow
            numberResult = Number.encode(a).multiply(Number.encode(b)).multiply(Number.encode(c));
            if(!signedContext.isValid(numberResult)) {
                continue;
            }

            plainResult = a.multiply(b).multiply(c);

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
