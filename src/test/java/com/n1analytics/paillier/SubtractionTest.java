package com.n1analytics.paillier;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.math.BigInteger;

import static com.n1analytics.paillier.TestUtil.random;
import static com.n1analytics.paillier.TestUtil.randomFiniteDouble;
import static org.junit.Assert.assertEquals;

// TODO Check if there is a better way to generate random BigInteger
@Category(SlowTests.class)
public class SubtractionTest {
    static private final double EPSILON = 0.1;

////    Key size of 1024 bits gives incorrect result when the difference of the exponents of two EncryptedNumbers are
////    greater than or equal to 977.
    static private final int keySize = 2104;

    static private PaillierPrivateKey privateKey = PaillierPrivateKey.create(keySize);
    static private PaillierPublicKey publicKey = privateKey.getPublicKey();
    static private PaillierContext context = publicKey.createSignedContext();

    static private int bigIntegerBitLength = keySize / 2 - 1;

//// maxExpDifference represents the maximum exponent difference between two encrypted numbers that does not result
//// in error when subtraction is performed on the encrypted numbers. maxExpDifference only applies to BigInteger.
//// At the moment, the number is derived from a simple experiment.
//    static private int maxExpDifference = 634;

    static private int maxIteration = 100;

    interface BinarySubtractor1 extends TwoInputsFunction<EncryptedNumber, EncryptedNumber, EncryptedNumber> {
        public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2);
    };

    interface BinarySubtractor2 extends TwoInputsFunction<EncryptedNumber, EncodedNumber, EncryptedNumber> {
        public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2);
    };

    interface BinarySubtractor3 extends TwoInputsFunction<EncryptedNumber, Number, EncryptedNumber> {
        public EncryptedNumber eval(EncryptedNumber arg1, Number arg2);
    };

    interface BinarySubtractor4 extends TwoInputsFunction<EncodedNumber, EncodedNumber, EncodedNumber> {
        public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2);
    };

    interface BinarySubtractor5 extends TwoInputsFunction<EncodedNumber, Number, EncodedNumber> {
        public EncodedNumber eval(EncodedNumber arg1, Number arg2);
    };

    interface BinarySubtractor6 extends TwoInputsFunction<Number, Number, Number> {
        public Number eval(Number arg1, Number arg2);
    };

    BinarySubtractor1 binarySubtractors1[] = new BinarySubtractor1[] {
            new BinarySubtractor1() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
                    return arg1.subtract(arg2);
                }
            },
            new BinarySubtractor1() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
                    return context.subtract(arg1, arg2);
                }
            }
    };

    BinarySubtractor1 binarySubtractorsRight1[] = new BinarySubtractor1[] {
            new BinarySubtractor1() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
                    return arg2.subtract(arg1);
                }
            },
            new BinarySubtractor1() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, EncryptedNumber arg2) {
                    return context.subtract(arg2, arg1);
                }
            }
    };

    BinarySubtractor2 binarySubtractors2[] = new BinarySubtractor2[] {
            new BinarySubtractor2() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
                    return arg1.subtract(arg2);
                }
            },
            new BinarySubtractor2() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
                    return context.subtract(arg1, arg2);
                }
            }
    };

    BinarySubtractor2 binarySubtractorsRight2[] = new BinarySubtractor2[] {
            new BinarySubtractor2() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
                    return arg2.subtract(arg1);
                }
            },
            new BinarySubtractor2() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, EncodedNumber arg2) {
                    return context.subtract(arg2, arg1);
                }
            }
    };

    BinarySubtractor3 binarySubtractors3[] = new BinarySubtractor3[] {
            new BinarySubtractor3() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, Number arg2) {
                    return arg1.subtract(arg2);
                }
            }
    };

    BinarySubtractor3 binarySubtractorsRight3[] = new BinarySubtractor3[] {
            new BinarySubtractor3() {
                @Override
                public EncryptedNumber eval(EncryptedNumber arg1, Number arg2) {
                    return arg2.subtract(arg1);
                }
            }
    };

    BinarySubtractor4 binarySubtractors4[] = new BinarySubtractor4[] {
            new BinarySubtractor4() {
                @Override
                public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
                    return arg1.subtract(arg2);
                }
            },
            new BinarySubtractor4() {
                @Override
                public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
                    return context.subtract(arg1, arg2);
                }
            }
    };

    BinarySubtractor4 binarySubtractorsRight4[] = new BinarySubtractor4[] {
            new BinarySubtractor4() {
                @Override
                public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
                    return arg2.subtract(arg1);
                }
            },
            new BinarySubtractor4() {
                @Override
                public EncodedNumber eval(EncodedNumber arg1, EncodedNumber arg2) {
                    return context.subtract(arg2, arg1);
                }
            }
    };

    BinarySubtractor5 binarySubtractors5[] = new BinarySubtractor5[] {
            new BinarySubtractor5() {
                @Override
                public EncodedNumber eval(EncodedNumber arg1, Number arg2) {
                    return arg1.subtract(arg2);
                }
            }
    };

    BinarySubtractor5 binarySubtractorsRight5[] = new BinarySubtractor5[] {
            new BinarySubtractor5() {
                @Override
                public EncodedNumber eval(EncodedNumber arg1, Number arg2) {
                    return arg2.subtract(arg1);
                }
            }
    };

    BinarySubtractor6 binarySubtractors6[] = new BinarySubtractor6[] {
            new BinarySubtractor6() {
                @Override
                public Number eval(Number arg1, Number arg2) {
                    return arg1.subtract(arg2);
                }
            }
    };

    BinarySubtractor6 binarySubtractorsRight6[] = new BinarySubtractor6[] {
            new BinarySubtractor6() {
                @Override
                public Number eval(Number arg1, Number arg2) {
                    return arg2.subtract(arg1);
                }
            }
    };

    void testDoubleSubtraction(BinarySubtractor1 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
        EncodedNumber decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a - b;

            ciphertTextA = context.encrypt(a);
            ciphertTextB = context.encrypt(b);

            encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(a).subtract(Number.encode(b))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = ciphertTextB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= 971)
//                continue;

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
            }
        }
    }

    void testDoubleSubtractionRight(BinarySubtractor1 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
        EncodedNumber decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = b - a;

            ciphertTextA = context.encrypt(a);
            ciphertTextB = context.encrypt(b);

            encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(b).subtract(Number.encode(a))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = ciphertTextB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= 971)
//                continue;

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
            }
        }
    }

    void testLongSubtraction(BinarySubtractor1 subtractor) {
        long a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
        EncodedNumber decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
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
            }
        }
    }

    void testLongSubtractionRight(BinarySubtractor1 subtractor) {
        long a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
        EncodedNumber decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
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
            }
        }
    }

    void testBigIntegerSubtraction(BinarySubtractor1 subtractor) {
        BigInteger a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, ciphertTextB, encryptedResult;
        EncodedNumber decryptedResult;

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

            plainResult = a.subtract(b);

            ciphertTextA = context.encrypt(a);
            ciphertTextB = context.encrypt(b);

            encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(a).subtract(Number.encode(b))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = ciphertTextB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

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

            plainResult = b.subtract(a);

            ciphertTextA = context.encrypt(a);
            ciphertTextB = context.encrypt(b);

            encryptedResult = subtractor.eval(ciphertTextA, ciphertTextB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(b).subtract(Number.encode(a))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = ciphertTextB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

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

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a - b;

            ciphertTextA = context.encrypt(a);
            encodedB = context.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, encodedB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(a).subtract(Number.encode(b))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = encodedB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= 971)
//                continue;

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
            }
        }
    }

    void testDoubleSubtractionRight(BinarySubtractor2 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber encodedB, decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = b - a;

            ciphertTextA = context.encrypt(a);
            encodedB = context.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, encodedB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(b).subtract(Number.encode(a))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = encodedB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= 971)
//                continue;

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
            }
        }
    }

    void testLongSubtraction(BinarySubtractor2 subtractor) {
        long a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber encodedB, decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
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
            }
        }
    }

    void testLongSubtractionRight(BinarySubtractor2 subtractor) {
        long a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber encodedB, decryptedResult;

        for(int i = 0; i < maxIteration; i++) {
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
            }
        }
    }

    void testBigIntegerSubtraction(BinarySubtractor2 subtractor) {
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

            plainResult = a.subtract(b);

            ciphertTextA = context.encrypt(a);
            encodedB = context.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, encodedB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(a).subtract(Number.encode(b))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = encodedB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

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

            plainResult = b.subtract(a);

            ciphertTextA = context.encrypt(a);
            encodedB = context.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, encodedB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(b).subtract(Number.encode(a))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = encodedB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;
//
            try {
                decodedResult = decryptedResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testDoubleSubtraction(BinarySubtractor3 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a - b;

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, numberB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(a).subtract(numberB)))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = numberB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= 971)
//                continue;

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
            }
        }
    }

    void testDoubleSubtractionRight(BinarySubtractor3 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = b - a;

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, numberB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(numberB.subtract(Number.encode(a))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = numberB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= 971)
//                continue;

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
            }
        }
    }

    void testLongSubtraction(BinarySubtractor3 subtractor) {
        long a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = a - b;

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, numberB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            try {
                decodedResult = decryptedResult.decodeLong();
                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testLongSubtractionRight(BinarySubtractor3 subtractor) {
        long a, b, plainResult, decodedResult;
        EncryptedNumber ciphertTextA, encryptedResult;
        EncodedNumber decryptedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = b - a;

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, numberB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            try {
                decodedResult = decryptedResult.decodeLong();
                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerSubtraction(BinarySubtractor3 subtractor) {
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

            plainResult = a.subtract(b);

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, numberB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(Number.encode(a).subtract(numberB)))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = numberB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

            try {
                decodedResult = decryptedResult.decodeBigInteger();
                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerSubtractionRight(BinarySubtractor3 subtractor) {
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

            plainResult = b.subtract(a);

            ciphertTextA = context.encrypt(a);
            numberB = Number.encode(b);

            encryptedResult = subtractor.eval(ciphertTextA, numberB);
            decryptedResult = encryptedResult.decrypt(privateKey);

            if(!context.isValid(numberB.subtract(Number.encode(a))))
                continue;

//            int expA = ciphertTextA.getExponent(), expB = numberB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

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

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a - b;

            encodedA = context.encode(a);
            encodedB = context.encode(b);

            if(!context.isValid(Number.encode(a).subtract(Number.encode(b))))
                continue;

            try {
                encodedResult = subtractor.eval(encodedA, encodedB);
                decodedResult = encodedResult.decodeDouble();

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

    void testDoubleSubtractionRight(BinarySubtractor4 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        EncodedNumber encodedA, encodedB, encodedResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = b - a;

            encodedA = context.encode(a);
            encodedB = context.encode(b);

            if(!context.isValid(Number.encode(b).subtract(Number.encode(a))))
                continue;

            try {
                encodedResult = subtractor.eval(encodedA, encodedB);
                decodedResult = encodedResult.decodeDouble();

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

    void testLongSubtraction(BinarySubtractor4 subtractor) {
        long a, b, plainResult, decodedResult;
        EncodedNumber encodedA, encodedB, encodedResult;

        for(int i = 0; i < maxIteration; i++) {
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
            }
        }
    }

    void testLongSubtractionRight(BinarySubtractor4 subtractor) {
        long a, b, plainResult, decodedResult;
        EncodedNumber encodedA, encodedB, encodedResult;

        for(int i = 0; i < maxIteration; i++) {
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
            }
        }
    }

    void testBigIntegerSubtraction(BinarySubtractor4 subtractor) {
        BigInteger a, b, plainResult, decodedResult;
        EncodedNumber encodedA, encodedB, encodedResult;

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

            plainResult = a.subtract(b);

            encodedA = context.encode(a);
            encodedB = context.encode(b);

            if(!context.isValid(Number.encode(a).subtract(Number.encode(b))))
                continue;

//            int expA = encodedA.getExponent(), expB = encodedB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

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

            plainResult = b.subtract(a);

            encodedA = context.encode(a);
            encodedB = context.encode(b);

            if(!context.isValid(Number.encode(b).subtract(Number.encode(a))))
                continue;

//            int expA = encodedA.getExponent(), expB = encodedB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

            try {
                encodedResult = subtractor.eval(encodedA, encodedB);
                decodedResult = encodedResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testDoubleSubtraction(BinarySubtractor5 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        EncodedNumber encodedA, encodedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a - b;

            encodedA = context.encode(a);
            numberB = Number.encode(b);

            if(!context.isValid(Number.encode(a).subtract(numberB)))
                continue;

            try {
                encodedResult = subtractor.eval(encodedA, numberB);
                decodedResult = encodedResult.decodeDouble();

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

    void testDoubleSubtractionRight(BinarySubtractor5 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        EncodedNumber encodedA, encodedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = b - a;

            encodedA = context.encode(a);
            numberB = Number.encode(b);

            if(!context.isValid(numberB.subtract(Number.encode(a))))
                continue;

            try {
                encodedResult = subtractor.eval(encodedA, numberB);
                decodedResult = encodedResult.decodeDouble();

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

    void testLongSubtraction(BinarySubtractor5 subtractor) {
        long a, b, plainResult, decodedResult;
        EncodedNumber encodedA, encodedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = a - b;

            encodedA = context.encode(a);
            numberB = Number.encode(b);

            try {
                encodedResult = subtractor.eval(encodedA, numberB);
                decodedResult = encodedResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testLongSubtractionRight(BinarySubtractor5 subtractor) {
        long a, b, plainResult, decodedResult;
        EncodedNumber encodedA, encodedResult;
        Number numberB;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = b - a;

            encodedA = context.encode(a);
            numberB = Number.encode(b);

            try {
                encodedResult = subtractor.eval(encodedA, numberB);
                decodedResult = encodedResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerSubtraction(BinarySubtractor5 subtractor) {
        BigInteger a, b, plainResult, decodedResult;
        EncodedNumber encodedA, encodedResult;
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

            plainResult = a.subtract(b);

            encodedA = context.encode(a);
            numberB = Number.encode(b);

            if(!context.isValid(Number.encode(a).subtract(numberB)))
                continue;

//            int expA = encodedA.getExponent(), expB = numberB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

            try {
                encodedResult = subtractor.eval(encodedA, numberB);
                decodedResult = encodedResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerSubtractionRight(BinarySubtractor5 subtractor) {
        BigInteger a, b, plainResult, decodedResult;
        EncodedNumber encodedA, encodedResult;
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

            plainResult = b.subtract(a);

            encodedA = context.encode(a);
            numberB = Number.encode(b);

            if(!context.isValid(numberB.subtract(Number.encode(a))))
                continue;

//            int expA = encodedA.getExponent(), expB = numberB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

            try {
                encodedResult = subtractor.eval(encodedA, numberB);
                decodedResult = encodedResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testDoubleSubtraction(BinarySubtractor6 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        Number numberA, numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = a - b;

            numberA = Number.encode(a);
            numberB = Number.encode(b);

            if(!context.isValid(numberA.subtract(numberB)))
                continue;

            try {
                numberResult = subtractor.eval(numberA, numberB);
                decodedResult = numberResult.decodeDouble();

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

    void testDoubleSubtractionRight(BinarySubtractor6 subtractor) {
        double a, b, plainResult, decodedResult, tolerance;
        Number numberA, numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = randomFiniteDouble();
            b = randomFiniteDouble();

            plainResult = b - a;

            numberA = Number.encode(a);
            numberB = Number.encode(b);

            if(!context.isValid(numberB.subtract(numberA)))
                continue;

            try {
                numberResult = subtractor.eval(numberA, numberB);
                decodedResult = numberResult.decodeDouble();

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

    void testLongSubtraction(BinarySubtractor6 subtractor) {
        long a, b, plainResult, decodedResult;
        Number numberA, numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = a - b;

            numberA = Number.encode(a);
            numberB = Number.encode(b);

            try {
                numberResult = subtractor.eval(numberA, numberB);
                decodedResult = numberResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testLongSubtractionRight(BinarySubtractor6 subtractor) {
        long a, b, plainResult, decodedResult;
        Number numberA, numberB, numberResult;

        for(int i = 0; i < maxIteration; i++) {
            a = random.nextLong();
            b = random.nextLong();

            plainResult = b - a;

            numberA = Number.encode(a);
            numberB = Number.encode(b);

            try {
                numberResult = subtractor.eval(numberA, numberB);
                decodedResult = numberResult.decodeLong();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerSubtraction(BinarySubtractor6 subtrator) {
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

            plainResult = a.subtract(b);

            numberA = Number.encode(a);
            numberB = Number.encode(b);

//            int expA = numberA.getExponent(), expB = numberB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;
//
            if(!context.isValid(numberA.subtract(numberB)))
                continue;

            try {
                numberResult = subtrator.eval(numberA, numberB);
                decodedResult = numberResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    void testBigIntegerSubtractionRight(BinarySubtractor6 subtractor) {
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

            plainResult = b.subtract(a);

            numberA = Number.encode(a);
            numberB = Number.encode(b);

//            int expA = numberA.getExponent(), expB = numberB.getExponent(), absDiff = Math.abs(expA - expB);
//            if(absDiff >= maxExpDifference)
//                continue;

            if(!context.isValid(numberB.subtract(numberA)))
                continue;

            try {
                numberResult = subtractor.eval(numberA, numberB);
                decodedResult = numberResult.decodeBigInteger();

                assertEquals(plainResult, decodedResult);
            } catch (ArithmeticException e) {
            }
        }
    }

    @Test
    public void testSubtractionEncryptedNumbers1() throws Exception {
        for(BinarySubtractor1 subtractor: binarySubtractors1) {
            testDoubleSubtraction(subtractor);
            testLongSubtraction(subtractor);
            testBigIntegerSubtraction(subtractor);
        }
//        System.out.println("EncryptedNumbers subtraction - left operation");

        for(BinarySubtractor1 subtractor: binarySubtractorsRight1) {
            testDoubleSubtractionRight(subtractor);
            testLongSubtractionRight(subtractor);
            testBigIntegerSubtractionRight(subtractor);
        }
//        System.out.println("EncryptedNumbers subtraction - right operation");
    }

    @Test
    public void testSubtractionEncryptedNumbers2() throws Exception {
        for(BinarySubtractor2 subtractor: binarySubtractors2) {
            testDoubleSubtraction(subtractor);
            testLongSubtraction(subtractor);
            testBigIntegerSubtraction(subtractor);
        }
//        System.out.println("EncryptedNumber/EncodedNumber subtraction - left operation");

        for(BinarySubtractor2 subtractor: binarySubtractorsRight2) {
            testDoubleSubtractionRight(subtractor);
            testLongSubtractionRight(subtractor);
            testBigIntegerSubtractionRight(subtractor);
        }
//        System.out.println("EncryptedNumber/EncodedNumber subtraction - right operation");
    }

    @Test
    public void testSubtractionEncryptedNumbers3() throws Exception {
        for(BinarySubtractor3 subtractor: binarySubtractors3) {
            testDoubleSubtraction(subtractor);
            testLongSubtraction(subtractor);
            testBigIntegerSubtraction(subtractor);
        }
//        System.out.println("EncryptedNumber/Number subtraction - left operation");

        for(BinarySubtractor3 subtractor: binarySubtractorsRight3) {
            testDoubleSubtractionRight(subtractor);
            testLongSubtractionRight(subtractor);
            testBigIntegerSubtractionRight(subtractor);
        }
//        System.out.println("EncryptedNumber/Number subtraction - right operation");
    }

    @Test
    public void testSubtractionEncodedNumbers1() throws Exception {
        for(BinarySubtractor4 subtractor: binarySubtractors4) {
            testDoubleSubtraction(subtractor);
            testLongSubtraction(subtractor);
            testBigIntegerSubtraction(subtractor);
        }
//        System.out.println("EncodedNumbers subtraction - left operation");

        for(BinarySubtractor4 subtractor: binarySubtractorsRight4) {
            testDoubleSubtractionRight(subtractor);
            testLongSubtractionRight(subtractor);
            testBigIntegerSubtractionRight(subtractor);
        }
//        System.out.println("EncodedNumbers subtraction - right operation");
    }

    @Test
    public void testSubtractionEncodedNumbers2() throws Exception {
        for(BinarySubtractor5 subtractor: binarySubtractors5) {
            testDoubleSubtraction(subtractor);
            testLongSubtraction(subtractor);
            testBigIntegerSubtraction(subtractor);
        }
//        System.out.println("EncodedNumber/Number subtraction - left operation");

        for(BinarySubtractor5 subtractor: binarySubtractorsRight5) {
            testDoubleSubtractionRight(subtractor);
            testLongSubtractionRight(subtractor);
            testBigIntegerSubtractionRight(subtractor);
        }
//        System.out.println("EncodedNumber/Number subtraction - right operation");
    }

    @Test
    public void testSubtractionNumbers1() throws Exception {
        for(BinarySubtractor6 subtractor: binarySubtractors6) {
            testDoubleSubtraction(subtractor);
            testLongSubtraction(subtractor);
            testBigIntegerSubtraction(subtractor);
        }
//        System.out.println("Numbers subtraction - left operation");

        for(BinarySubtractor6 subtractor: binarySubtractorsRight6) {
            testDoubleSubtractionRight(subtractor);
            testLongSubtractionRight(subtractor);
            testBigIntegerSubtractionRight(subtractor);
        }
//        System.out.println("Numbers subtraction - right operation");
    }

}
