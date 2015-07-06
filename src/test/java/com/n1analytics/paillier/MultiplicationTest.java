package com.n1analytics.paillier;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.math.BigInteger;

import static com.n1analytics.paillier.TestUtil.random;
import static com.n1analytics.paillier.TestUtil.randomFiniteDouble;
import static org.junit.Assert.assertEquals;

// TODO Check if there is a better way to generate random BigInteger
@Category(SlowTests.class)
public class MultiplicationTest {
    static private final double EPSILON = 0.1;

    static private final int keySize = 2104;

    static private PaillierPrivateKey privateKey = PaillierPrivateKey.create(keySize);
    static private PaillierPublicKey publicKey = privateKey.getPublicKey();
    static private PaillierContext context = publicKey.createSignedContext();

    static private int bigIntegerBitLength = keySize / 2 - 1;
//    static private int maxExpDifference = 634;

    static private int maxIteration = 100;

    interface BinaryMultiplier1 extends TwoInputsFunction<EncryptedNumber, EncodedNumber, EncryptedNumber> {
        public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2);
    }

    interface BinaryMultiplier2 extends TwoInputsFunction<EncryptedNumber, Number, EncryptedNumber> {
        public EncryptedNumber eval(EncryptedNumber arg1, Number arg2);
    }

    interface BinaryMultiplier3 extends TwoInputsFunction<EncodedNumber, EncodedNumber, EncodedNumber> {
        public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
    }

    interface BinaryMultiplier4 extends TwoInputsFunction<EncodedNumber, Number, EncodedNumber> {
        public EncodedNumber eval(EncodedNumber arg1, Number arg2);
    }

    interface BinaryMultiplier5 extends TwoInputsFunction<Number, Number, Number> {
        public Number eval(Number arg1, Number arg2);
    }

    BinaryMultiplier1 binaryMultipliers1[] = new BinaryMultiplier1[] {
        new BinaryMultiplier1() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
                return arg1.multiply(arg2);
            }
        },
        new BinaryMultiplier1() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
                return arg2.multiply(arg1);
            }
        },
        new BinaryMultiplier1() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
                return context.multiply(arg1, arg2);
            }
        },
        new BinaryMultiplier1() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
                return context.multiply(arg2, arg1);
            }
        }
    };

    BinaryMultiplier2 binaryMultipliers2[] = new BinaryMultiplier2[] {
        new BinaryMultiplier2() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1, Number arg2) {
                return arg1.multiply(arg2);
            }
        },
        new BinaryMultiplier2() {
            @Override
            public EncryptedNumber eval(EncryptedNumber arg1, Number arg2) {
                return arg2.multiply(arg1);
            }
        }
    };

    BinaryMultiplier3 binaryMultipliers3[] = new BinaryMultiplier3[] {
        new BinaryMultiplier3() {
            @Override
            public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
                return arg1.multiply(arg2);
            }
        },
        new BinaryMultiplier3() {
            @Override
            public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
                return arg2.multiply(arg1);
            }
            },
        new BinaryMultiplier3() {
            @Override
            public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
                return context.multiply(arg1, arg2);
                }
            },
        new BinaryMultiplier3() {
            @Override
                public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
                return context.multiply(arg2, arg1);
            }
        }
    };

    BinaryMultiplier4 binaryMultipliers4[] = new BinaryMultiplier4[]{
            new BinaryMultiplier4() {
                @Override
                public EncodedNumber eval(EncodedNumber arg1, Number arg2) {
                    return arg1.multiply(arg2);
                }
            },
            new BinaryMultiplier4() {
                @Override
                public EncodedNumber eval(EncodedNumber arg1, Number arg2) {
                    return arg2.multiply(arg1);
                }
            }
    };

    BinaryMultiplier5 binaryMultipliers5[] = new BinaryMultiplier5[]{
        new BinaryMultiplier5() {
            @Override
            public Number eval(Number arg1, Number arg2) {
                    return arg1.multiply(arg2);
                }
        },
        new BinaryMultiplier5() {
            @Override
            public Number eval(Number arg1, Number arg2) {
                    return arg2.multiply(arg1);
                }
        }
    };

    void testDoubleMultiplication(BinaryMultiplier1 multiplier) {
        double a, b, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber encodedB, decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
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

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
                }
            } catch (ArithmeticException e) {
            }
        }
    }

    void testLongMultiplication(BinaryMultiplier1 multiplier) {
        long a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber encodedB, decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
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
            }
        }
    }

    void testBigIntegerMultiplication(BinaryMultiplier1 multiplier) {
        BigInteger a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber encodedB, decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);

            // The random generator above only generates positive BigIntegers, the following code
            // negates some inputs.
            if(i % 4 == 1) {
                b = b.negate();
            } else if(i % 4 == 2) {
                a = a.negate();
            } else if(i % 4 == 3) {
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

    void testDoubleMultiplication(BinaryMultiplier2 multiplier) {
        double a, b, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a * b;

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = multiplier.eval(ciphertTextA, numberB);
            decryptedResult = encryptedResult.decrypt(privateKey);

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
            } catch (ArithmeticException e) {
            }
        }
    }

    void testLongMultiplication(BinaryMultiplier2 multiplier) {
        long a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = a * b;

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = multiplier.eval(ciphertTextA, numberB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            try {
                decodedResult = decryptedResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerMultiplication(BinaryMultiplier2 multiplier) {
        BigInteger a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);

            // The random generator above only generates positive BigIntegers, the following code
            // negates some inputs.
            if(i % 4 == 1) {
                b = b.negate();
            } else if(i % 4 == 2) {
                a = a.negate();
            } else if(i % 4 == 3) {
                a = a.negate();
                b = b.negate();
            }

            plainResult = a.multiply(b);

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = multiplier.eval(ciphertTextA, numberB);
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

        for(int i = 0; i < maxIteration; i++) {
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

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
                }
            } catch (ArithmeticException e) {
            }
        }
    }

    void testLongMultiplication(BinaryMultiplier3 multiplier) {
        long a, b, plainResult, decodedResult;
        EncodedNumber encodedNumberA, encodedNumberB, encodedResult;

        for(int i = 0; i < maxIteration; i++) {
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
            }
        }
    }

    void testBigIntegerMultiplication(BinaryMultiplier3 multiplier) {
        BigInteger a, b, plainResult, decodedResult;
        EncodedNumber encodedNumberA, encodedNumberB, encodedResult;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);

            // The random generator above only generates positive BigIntegers, the following code
            // negates some inputs.
            if(i % 4 == 1) {
                b = b.negate();
            } else if(i % 4 == 2) {
                a = a.negate();
            } else if(i % 4 == 3) {
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

    void testDoubleMultiplication(BinaryMultiplier4 multiplier) {
        double a, b, plainResult, decodedResult, tolerance;
        EncodedNumber encodedNumberA, encodedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a * b;

            encodedNumberA = context.encode(a);
            numberB = Number.encode(b);

            encodedResult = multiplier.eval(encodedNumberA, numberB);

            try {
                decodedResult = encodedResult.decodeDouble();

                if (Math.getExponent(decodedResult) > 0) {
                    tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
                } else {
                    tolerance = EPSILON;
                }

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
                }
            } catch (ArithmeticException e) {
            }
        }
    }

    void testLongMultiplication(BinaryMultiplier4 multiplier) {
        long a, b, plainResult, decodedResult;
        EncodedNumber encodedNumberA, encodedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = a * b;

            encodedNumberA = context.encode(a);
            numberB = Number.encode(b);

            encodedResult = multiplier.eval(encodedNumberA, numberB);

            try {
                decodedResult = encodedResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerMultiplication(BinaryMultiplier4 multiplier) {
        BigInteger a, b, plainResult, decodedResult;
        EncodedNumber encodedNumberA, encodedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);

            // The random generator above only generates positive BigIntegers, the following code
            // negates some inputs.
            if(i % 4 == 1) {
                b = b.negate();
            } else if(i % 4 == 2) {
                a = a.negate();
            } else if(i % 4 == 3) {
                a = a.negate();
                b = b.negate();
            }

            plainResult = a.multiply(b);

            encodedNumberA = context.encode(a);
            numberB = Number.encode(b);

            encodedResult = multiplier.eval(encodedNumberA, numberB);

            try {
                decodedResult = encodedResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testDoubleMultiplication(BinaryMultiplier5 multiplier) {
        double a, b, plainResult, decodedResult, tolerance;
        Number numberA, numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a * b;

            numberA = Number.encode(a);
            numberB = Number.encode(b);

            numberResult = multiplier.eval(numberA, numberB);

            try {
                decodedResult = numberResult.decodeDouble();

                if (Math.getExponent(decodedResult) > 0) {
                    tolerance = EPSILON * Math.pow(2.0, Math.getExponent(decodedResult));
                } else {
                    tolerance = EPSILON;
                }

                if(!Double.isInfinite(plainResult)) {
                    assertEquals(plainResult, decodedResult, tolerance);
                }
            } catch (ArithmeticException e) {
            }
        }
    }

    void testLongMultiplication(BinaryMultiplier5 multiplier) {
        long a, b, plainResult, decodedResult;
        Number numberA, numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = a * b;

            numberA = Number.encode(a);
            numberB = Number.encode(b);

            numberResult = multiplier.eval(numberA, numberB);

            try {
                decodedResult = numberResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerMultiplication(BinaryMultiplier5 multiplier) {
        BigInteger a, b, plainResult, decodedResult;
        Number numberA, numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = new BigInteger(bigIntegerBitLength, random);
            b = new BigInteger(bigIntegerBitLength, random);

            // The random generator above only generates positive BigIntegers, the following code
            // negates some inputs.
            if(i % 4 == 1) {
                b = b.negate();
            } else if(i % 4 == 2) {
                a = a.negate();
            } else if(i % 4 == 3) {
                a = a.negate();
                b = b.negate();
            }

            plainResult = a.multiply(b);

            numberA = Number.encode(a);
            numberB = Number.encode(b);

            numberResult = multiplier.eval(numberA, numberB);

            try {
                decodedResult = numberResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    @Test
    public void testMultiplicationEncryptedNumbers1() throws Exception {
        for(BinaryMultiplier1 multiplier: binaryMultipliers1) {
            testDoubleMultiplication(multiplier);
            testLongMultiplication(multiplier);
            testBigIntegerMultiplication(multiplier);
        }
    }

    @Test
    public void testMultiplicationEncryptedNumbers2() throws Exception {
        for(BinaryMultiplier2 multiplier: binaryMultipliers2) {
            testDoubleMultiplication(multiplier);
            testLongMultiplication(multiplier);
            testBigIntegerMultiplication(multiplier);
        }
    }

    @Test
    public void testMultiplicationEncryptedNumbers3() throws Exception {
        for(BinaryMultiplier3 multiplier: binaryMultipliers3) {
            testDoubleMultiplication(multiplier);
            testLongMultiplication(multiplier);
            testBigIntegerMultiplication(multiplier);
        }
    }

    @Test
    public void testMultiplicationEncryptedNumbers4() throws Exception {
        for(BinaryMultiplier4 multiplier: binaryMultipliers4) {
            testDoubleMultiplication(multiplier);
            testLongMultiplication(multiplier);
            testBigIntegerMultiplication(multiplier);
        }
    }

    @Test
    public void testMultiplicationEncryptedNumbers5() throws Exception {
        for(BinaryMultiplier5 multiplier: binaryMultipliers5) {
            testDoubleMultiplication(multiplier);
            testLongMultiplication(multiplier);
            testBigIntegerMultiplication(multiplier);
        }
    }
}
