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
package com.n1analytics.paillier.util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A class containing utility methods for BigInteger manipulation.
 */
public class BigIntegerUtil {

  /**
   * Minimum long value as a BigInteger;
   */
  public static final BigInteger LONG_MIN_VALUE = BigInteger.valueOf(Long.MIN_VALUE);

  /**
   * Maximum long value as a BigInteger.
   */
  public static final BigInteger LONG_MAX_VALUE = BigInteger.valueOf(Long.MAX_VALUE);

  /**
   * Checks whether {@code n} is positive.
   *
   * @param n number to check.
   * @return true if {@code n} is positive, false otherwise.
   */
  public static boolean positive(BigInteger n) {
    return n.signum() > 0;
  }

  /**
   * Checks whether {@code n} is non-negative.
   *
   * @param n number to check.
   * @return true if {@code n} is positive or {@code n} is equal to 0, false otherwise.
   */
  public static boolean nonNegative(BigInteger n) {
    return n.signum() >= 0;
  }

  /**
   * Checks whether {@code n} is negative.
   *
   * @param n number to check.
   * @return true if {@code n} is negative, false otherwise.
   */
  public static boolean negative(BigInteger n) {
    return n.signum() < 0;
  }

  /**
   * Checks whether {@code n} is non-positive.
   *
   * @param n number to check.
   * @return true if {@code n} is negative or {@code n} is equal to 0, false otherwise.
   */
  public static boolean nonPositive(BigInteger n) {
    return n.signum() <= 0;
  }

  /**
   * Checks whether {@code a} is greater than {@code b}.
   *
   * @param a first number.
   * @param b second number.
   * @return true if {@code a} is greater than {@code b}, false otherwise.
   */
  public static boolean greater(BigInteger a, BigInteger b) {
    return a.compareTo(b) > 0;
  }

  /**
   * Checks whether {@code a} is greater than or equal to {@code b}.
   *
   * @param a first number.
   * @param b second number.
   * @return true if {@code a} is greater than or equal to {@code b}, false otherwise.
   */
  public static boolean greaterOrEqual(BigInteger a, BigInteger b) {
    return a.compareTo(b) >= 0;
  }

  /**
   * Checks whether {@code a} is less than {@code b}.
   *
   * @param a first number.
   * @param b second number.
   * @return true if a is less than {@code b}, false otherwise.
   */
  public static boolean less(BigInteger a, BigInteger b) {
    return a.compareTo(b) < 0;
  }

  /**
   * Checks whether {@code a} is less than or equal to {@code b}.
   *
   * @param a first number.
   * @param b second number.
   * @return true if {@code a} is less than or equal to {@code b}, false otherwise.
   */
  public static boolean lessOrEqual(BigInteger a, BigInteger b) {
    return a.compareTo(b) <= 0;
  }

  /**
   * Returns a random strictly positive number less than {@code n}.
   *
   * @param n upper bound.
   * @return a random number less than {@code n}.
   */
  public static BigInteger randomPositiveNumber(final BigInteger n) {
    if (lessOrEqual(n, BigInteger.ONE)) {
      throw new IllegalArgumentException("n must be strictly greater than one");
    }

    int bits = n.bitLength();
    SecureRandom random = new SecureRandom();
    for (; ; ) {
      BigInteger r = new BigInteger(bits, random);
      if (less(r, BigInteger.ONE) || greaterOrEqual(r, n)) {
        continue;
      }
      return r;
    }
  }

  /**
   * The number of bits required to represent {@code abs(n)}, excluding the
   * sign bit. This is useful because {@code absBitLength(n) == absBitLength(n.negate)}
   * whereas the same is not necessarily true of {@code n.bitLength()} and
   * {@code n.negate().bitLength()}.
   *
   * @param n input.
   * @return number of bits.
   */
  public static int absBitLength(BigInteger n) {
    return n.abs().bitLength();
  }

  /**
   * Converts a BigInteger to a long. Throws an ArithmeticException
   * if the conversion can not be done exactly.
   *
   * @param n Number to convert.
   * @return The converted value.
   * @throws ArithmeticException If {@code n} cannot be exactly.
   * represented as a long.
   */
  public static long longValueExact(BigInteger n) throws ArithmeticException {
    // TODO Issue #13: optimisation?
    if (n.compareTo(LONG_MIN_VALUE) < 0) {
      throw new ArithmeticException("Cannot represent exactly");
    }
    if (n.compareTo(LONG_MAX_VALUE) > 0) {
      throw new ArithmeticException("Cannot represent exactly");
    }
    return n.longValue();
  }

  /**
   * Computes the Integer part of the square root of BigInteger {@code n}.
   * This code is adapted from Faruk Akgul's code found at:
   * http://faruk.akgul.org/blog/javas-missing-algorithm-biginteger-sqrt/
   *
   * @param n number to square root.
   * @return the integer part of the square root of {@code n}.
   */
  public static BigInteger sqrt(BigInteger n) {
    BigInteger a = BigInteger.ONE;
    BigInteger b = n.shiftRight(5).add(BigInteger.valueOf(8));
    while (b.compareTo(a) >= 0) {
      BigInteger mid = a.add(b).shiftRight(1);
      if (mid.multiply(mid).compareTo(n) > 0)
        b = mid.subtract(BigInteger.ONE);
      else
        a = mid.add(BigInteger.ONE);
    }
    return a.subtract(BigInteger.ONE);
  }
  
}
