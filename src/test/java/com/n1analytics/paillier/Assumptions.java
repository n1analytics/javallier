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

import java.math.BigInteger;

import static com.n1analytics.paillier.util.FloatingPointUtil.*;
import static org.junit.Assert.assertEquals;

public class Assumptions {
  // TODO modulus of public key is always odd (and greater than 4...)

  public static class NamedDouble {

    public final String name;
    public final double value;

    public NamedDouble(String name, double value) {
      this.name = name;
      this.value = value;
    }
  }

  public static final NamedDouble[] namedDoubles = {new NamedDouble(" NaN",
                                                                    Double.NaN), new NamedDouble(
          " INIFINITY", Double.POSITIVE_INFINITY), new NamedDouble(" MAX_VALUE",
                                                                   Double.MAX_VALUE), new NamedDouble(
          " MAX_VALUE / 2", Double.MAX_VALUE / 2), new NamedDouble(" MAX_INT * 2",
                                                                   DOUBLE_MAX_INT * 2), new NamedDouble(
          " MAX_INT", DOUBLE_MAX_INT), new NamedDouble(" MAX_INT - 1",
                                                       DOUBLE_MAX_INT - 1), new NamedDouble(
          " MAX_INT / 2", DOUBLE_MAX_INT / 2), new NamedDouble(" 2", 2f), new NamedDouble(
          " 1", 1f), new NamedDouble(" MIN_NORMAL", Double.MIN_NORMAL), new NamedDouble(
          " MAX_SUBNORMAL", nextNegative(Double.MIN_NORMAL)), new NamedDouble(
          " MIN_NORMAL / 2", Double.MIN_NORMAL / 2), new NamedDouble(" MIN_VALUE * 2",
                                                                     Double.MIN_VALUE * 2), new NamedDouble(
          " MIN_VALUE", Double.MIN_VALUE), new NamedDouble(" 0", 0f), new NamedDouble(
          "-0", -0f), new NamedDouble("-MIN_VALUE", -Double.MIN_VALUE), new NamedDouble(
          "-MIN_VALUE * 2", -Double.MIN_VALUE * 2), new NamedDouble("-MIN_NORMAL / 2",
                                                                    -Double.MIN_NORMAL / 2), new NamedDouble(
          "-MAX_SUBNORMAL", -nextNegative(Double.MIN_NORMAL)), new NamedDouble(
          "-MIN_NORMAL", -Double.MIN_NORMAL), new NamedDouble("-1", -1f), new NamedDouble(
          "-2", -2f), new NamedDouble("-MAX_INT/2", -DOUBLE_MAX_INT / 2), new NamedDouble(
          "-MAX_INT+1", -DOUBLE_MAX_INT + 1), new NamedDouble("-MAX_INT",
                                                              -DOUBLE_MAX_INT), new NamedDouble(
          "-MAX_INT * 2", -DOUBLE_MAX_INT * 2), new NamedDouble("-MAX_VALUE / 2",
                                                                -Double.MAX_VALUE / 2), new NamedDouble(
          "-MAX_VALUE", -Double.MAX_VALUE), new NamedDouble("-INFINITY",
                                                            Double.NEGATIVE_INFINITY)};

  public void printDoubleInfo() {
    System.out.println(
            "+-----------------+--------------------------+------------------+------+----------+---------------+\n" +
                    "| number          | value                    | bits             | sign | exponent | fraction      |\n" +
                    "+-----------------+--------------------------+------------------+------+----------+---------------+");
    for (NamedDouble namedDouble : namedDoubles) {
      if (isFinite(namedDouble.value)) {
        System.out.format(
                "| %-15s | %s0x%01d.%013Xp%-+5d | %016X | %01X    | %03X      | %013X |\n",
                namedDouble.name, sign(namedDouble.value) < 0 ? "-" : " ",
                isNormal(namedDouble.value) ? 1 : 0, fraction(namedDouble.value),
                isNormal(namedDouble.value) ? exponent(namedDouble.value) : -1022,
                bits(namedDouble.value), signBitsShifted(namedDouble.value),
                exponentBitsShifted(namedDouble.value), fraction(namedDouble.value));
      } else {
        System.out.format(
                "| %-15s |                          | %016X | %01X    | %03X      | %013X |\n",
                namedDouble.name, bits(namedDouble.value),
                signBitsShifted(namedDouble.value),
                exponentBitsShifted(namedDouble.value), fraction(namedDouble.value));
      }
    }
    System.out.println(
            "+-----------------+--------------------------+------------------+------+----------+---------------+");
  }

  @Test
  public void floatTest() {
//		printFloatInfo();
    printDoubleInfo();
  }

  @Test
  public void testBitLength() {
    assertEquals(4, BigInteger.valueOf(8).bitLength());
    assertEquals(3, BigInteger.valueOf(7).bitLength());
    assertEquals(3, BigInteger.valueOf(6).bitLength());
    assertEquals(3, BigInteger.valueOf(5).bitLength());
    assertEquals(3, BigInteger.valueOf(4).bitLength());
    assertEquals(2, BigInteger.valueOf(3).bitLength());
    assertEquals(2, BigInteger.valueOf(2).bitLength());
    assertEquals(1, BigInteger.valueOf(1).bitLength());
    assertEquals(0, BigInteger.valueOf(0).bitLength());
    assertEquals(0, BigInteger.valueOf(-1).bitLength());
    assertEquals(1, BigInteger.valueOf(-2).bitLength());
    assertEquals(2, BigInteger.valueOf(-3).bitLength());
    assertEquals(2, BigInteger.valueOf(-4).bitLength());
    assertEquals(3, BigInteger.valueOf(-5).bitLength());
    assertEquals(3, BigInteger.valueOf(-6).bitLength());
    assertEquals(3, BigInteger.valueOf(-7).bitLength());
    assertEquals(3, BigInteger.valueOf(-8).bitLength());
    assertEquals(4, BigInteger.valueOf(-9).bitLength());
  }

  @Test
  public void testLongNumberOfLeadingZeros() {
    assertEquals(62, Long.numberOfLeadingZeros(2));
    assertEquals(63, Long.numberOfLeadingZeros(1));
    assertEquals(64, Long.numberOfLeadingZeros(0));
    assertEquals(0, Long.numberOfLeadingZeros(-1));
  }

  @Test
  public void testLongHighestOneBit() {
    assertEquals(4, Long.highestOneBit(4));
    assertEquals(2, Long.highestOneBit(3));
    assertEquals(2, Long.highestOneBit(2));
    assertEquals(1, Long.highestOneBit(1));
    assertEquals(0, Long.highestOneBit(0));
    assertEquals(0x8000000000000000L, Long.highestOneBit(-1));
  }


}
