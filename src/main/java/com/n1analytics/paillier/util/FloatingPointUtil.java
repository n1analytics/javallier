///**
// * Copyright 2015 NICTA
// *
// * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
// * file except in compliance with the License. You may obtain a copy of the License at
// *
// * http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software distributed under
// * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// * KIND, either express or implied. See the License for the specific language governing
// * permissions and limitations under the License.
// */
//package com.n1analytics.paillier.util;
//
///**
// * A class containing the common methods to manipulate floating point numbers according to
// * the IEEE 754 floating-point "double format" bit layout, including:
// * <ul>
// *     <li>The methods to obtain the sign, significand and the exponent of a floating point number </li>
// *     <li>The methods to check the properties of a floating point number, i.e., {@code isNormal}} etc</li>
// *     <li>The methods adjacent positive and negative floating point number</li>
// * </ul>
// */
//public class FloatingPointUtil {
//
//  /**
//   * The number of bits that represents the significand in a {@code double}.
//   */
//  public static final int DOUBLE_FRACTION_BITS = 52;
//
//  /**
//   * The number of bits that represents the exponent in {@code double}.
//   */
//  public static final int DOUBLE_EXPONENT_BITS = 11;
//
//  /**
//   * The number of bits that represents the sign in {@code double}.
//   */
//  public static final int DOUBLE_SIGN_BITS = 1;
//
//  /**
//   * The number of bit shift required to obtain the significand component of a {@code double}.
//   */
//  public static final int DOUBLE_FRACTION_SHIFT = 0;
//
//  /**
//   * The number of bit shift required to obtain the exponent component of a {@code double}.
//   */
//  public static final int DOUBLE_EXPONENT_SHIFT = 52;
//
//  /**
//   * The number of bit shift required to obtain the sign component of a {@code double}.
//   */
//  public static final int DOUBLE_SIGN_SHIFT = 63;
//
//  /**
//   * The exponent bias of a {@code double}.
//   */
//  public static final long DOUBLE_EXPONENT_BIAS = 1023;
//
//  /**
//   * The mask required to obtain the significand component from a {@code double}.
//   */
//  public static final long DOUBLE_FRACTION_MASK = 0x000FFFFFFFFFFFFFL;
//
//  /**
//   * The mask required to obtain the exponent component from a {@code double}.
//   */
//  public static final long DOUBLE_EXPONENT_MASK = 0x7FF0000000000000L;
//
//  /**
//   * The mask required to obtain the sign component from a {@code double}.
//   */
//  public static final long DOUBLE_SIGN_MASK = 0x8000000000000000L;
//
//  /**
//   * The maximum integer that can be represented in a {@code double}, i.e., <code>2<sup>53</sup></code>
//   */
//  public static final long DOUBLE_MAX_INT = 0x001FFFFFFFFFFFFFL;

////	public static final int FLOAT_FRACTION_BITS = 23;
////	public static final int FLOAT_EXPONENT_BITS = 8;
////	public static final int FLOAT_SIGN_BITS = 1;
////	public static final int FLOAT_FRACTION_SHIFT = 0;
////	public static final int FLOAT_EXPONENT_SHIFT = 23;
////	public static final int FLOAT_SIGN_SHIFT = 31;
////	public static final int FLOAT_EXPONENT_BIAS = 127;
////	public static final int FLOAT_FRACTION_MASK = 0x007FFFFF;
////	public static final int FLOAT_SIGN_MASK = 0x80000000;
////	public static final int FLOAT_EXPONENT_MASK = 0x7F800000;
////	public static final int FLOAT_MAX_INT = 0x00FFFFFF;
//
//  /**
//   * Returns a bit representation of the value according to the IEEE 754 floating-point "double format" bit layout.
//   *
//   * @param value input.
//   * @return bit representation of the value.
//   */
//  public static long bits(double value) {
//    return Double.doubleToLongBits(value);
//  }
//
////	public static int bits(float value) {
////		return Float.floatToIntBits(value);
////	}
//
//  /**
//   * Returns the significand component of the bit representation of the value.
//   *
//   * @param value input.
//   * @return fraction component of the bit representation.
//   */
//  public static long fraction(double value) {
//    return bits(value) & DOUBLE_FRACTION_MASK;
//  }
//
////	public static int fraction(float value) {
////		return bits(value) & FLOAT_FRACTION_MASK;
////	}
//
//  /**
//   * Returns the exponent component of the bit representation of the value.
//   *
//   * @param value input.
//   * @return exponent component of the bit representation.
//   */
//  public static long exponentBits(double value) {
//    return bits(value) & DOUBLE_EXPONENT_MASK;
//  }
//
////	public static int exponentBits(float value) {
////		return bits(value) & FLOAT_EXPONENT_MASK;
////	}
//
//  /**
//   * Returns the unsigned right shifted exponent of the value.
//   *
//   * @param value input.
//   * @return unsigned right shifted exponent of the value.
//   */
//  public static long exponentBitsShifted(double value) {
//    return exponentBits(value) >>> DOUBLE_EXPONENT_SHIFT;
//  }
//
////	public static int exponentBitsShifted(float value) {
////		return exponentBits(value) >>> FLOAT_EXPONENT_SHIFT;
////	}
//
//  /**
//   * Returns the exponent of the value.
//   *
//   * @param value input.
//   * @return exponent of the value.
//   */
//  public static long exponent(double value) {
//    return exponentBitsShifted(value) - DOUBLE_EXPONENT_BIAS;
//  }
//
////	public static int exponent(float value) {
////		return exponentBitsShifted(value) - FLOAT_EXPONENT_BIAS;
////	}
//
//  /**
//   * Returns the sign bit of the value.
//   *
//   * @param value input.
//   * @return sign bit of the value.
//   */
//  public static long signBits(double value) {
//    return bits(value) & DOUBLE_SIGN_MASK;
//  }
//
////	public static int signBits(float value) {
////		return bits(value) & FLOAT_SIGN_MASK;
////	}
//
//  /**
//   * Returns the unsigned right shifted sign bit of the value.
//   *
//   * @param value input.
//   * @return unsigned right shifted bit of the value.
//   */
//  public static long signBitsShifted(double value) {
//    return signBits(value) >>> DOUBLE_SIGN_SHIFT;
//  }
//
////	public static int signBitsShifted(float value) {
////		return signBits(value) >>> FLOAT_SIGN_SHIFT;
////	}
//
//  /**
//   * Returns the sign of the value.
//   *
//   * @param value input.
//   * @return sign of the value.
//   */
//  public static long sign(double value) {
//    return signBits(value) == 0L ? 1 : -1;
//  }
//
////	public static int sign(float value) {
////		return signBits(value) == 0 ? 1 : -1;
////	}
//
//  /**
//   * Check if the value is a NaN.
//   *
//   * @param value input.
//   * @return true if value is NaN, false otherwise.
//   */
//  public static boolean isNaN(double value) {
//    return Double.isNaN(value);
//  }
//
////	public static boolean isNaN(float value) {
////		return Float.isNaN(value);
////	}
//
//  /**
//   * Check if the value is infinite.
//   *
//   * @param value input.
//   * @return true of value is infinite, false otherwise.
//   */
//  public static boolean isInfinite(double value) {
//    return Double.isInfinite(value);
//  }
//
////	public static boolean isInfinite(float value) {
////		return Float.isInfinite(value);
////	}
//
//  /**
//   * Check if the value is finite.
//   *
//   * @param value input.
//   * @return true of value is finite, false otherwise.
//   */
//  public static boolean isFinite(double value) {
//    return !isNaN(value) && !isInfinite(value);
//  }
//
////	public static boolean isFinite(float value) {
////		return !isNaN(value) && !isInfinite(value);
////	}
//
//  /**
//   * Check if the value is subnormal.
//   *
//   * @param value input.
//   * @return true of value is subnormal, false otherwise.
//   */
//
//  public static boolean isSubnormal(double value) {
//    return exponentBits(value) == 0L;
//  }
//
////	public static boolean isSubnormal(float value) {
////		return exponentBits(value) == 0;
////	}
//
//  /**
//   * Check if the value is normal.
//   *
//   * @param value input.
//   * @return true of value is normal, false otherwise.
//   */
//  public static boolean isNormal(double value) {
//    return isFinite(value) && !isSubnormal(value);
//  }
//
////	public static boolean isNormal(float value) {
////		return isFinite(value) && !isSubnormal(value);
////	}
//
//  /**
//   * Returns the adjacent positive floating-point number.
//   *
//   * @param value input.
//   * @return adjacent positive floating-point number.
//   */
//  public static double nextPositive(double value) {
//    return Math.nextAfter(value, Double.POSITIVE_INFINITY);
//  }
//
////	public static float nextPositive(float value) {
////		return Math.nextAfter(value, Float.POSITIVE_INFINITY);
////	}
//
//  /**
//   * Returns the adjacent negative floating-point number.
//   *
//   * @param value input.
//   * @return adjacent negative floating-point number.
//   */
//  public static double nextNegative(double value) {
//    return Math.nextAfter(value, Double.NEGATIVE_INFINITY);
//  }
//
//	public static float nextNegative(float value) {
//		return Math.nextAfter(value, Float.NEGATIVE_INFINITY);
//	}
//}
