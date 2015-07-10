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

public class FloatingPointUtil {

  public static final int DOUBLE_FRACTION_BITS = 52;
  public static final int DOUBLE_EXPONENT_BITS = 11;
  public static final int DOUBLE_SIGN_BITS = 1;
  public static final int DOUBLE_FRACTION_SHIFT = 0;
  public static final int DOUBLE_EXPONENT_SHIFT = 52;
  public static final int DOUBLE_SIGN_SHIFT = 63;
  public static final long DOUBLE_EXPONENT_BIAS = 1023;
  public static final long DOUBLE_FRACTION_MASK = 0x000FFFFFFFFFFFFFL;
  public static final long DOUBLE_EXPONENT_MASK = 0x7FF0000000000000L;
  public static final long DOUBLE_SIGN_MASK = 0x8000000000000000L;
  public static final long DOUBLE_MAX_INT = 0x001FFFFFFFFFFFFFL;
//	public static final int FLOAT_FRACTION_BITS = 23;
//	public static final int FLOAT_EXPONENT_BITS = 8;
//	public static final int FLOAT_SIGN_BITS = 1;
//	public static final int FLOAT_FRACTION_SHIFT = 0;
//	public static final int FLOAT_EXPONENT_SHIFT = 23;
//	public static final int FLOAT_SIGN_SHIFT = 31;
//	public static final int FLOAT_EXPONENT_BIAS = 127;
//	public static final int FLOAT_FRACTION_MASK = 0x007FFFFF;
//	public static final int FLOAT_SIGN_MASK = 0x80000000;
//	public static final int FLOAT_EXPONENT_MASK = 0x7F800000;
//	public static final int FLOAT_MAX_INT = 0x00FFFFFF;

  public static long bits(double value) {
    return Double.doubleToLongBits(value);
  }

//	public static int bits(float value) {
//		return Float.floatToIntBits(value);
//	}

  public static long fraction(double value) {
    return bits(value) & DOUBLE_FRACTION_MASK;
  }

//	public static int fraction(float value) {
//		return bits(value) & FLOAT_FRACTION_MASK;
//	}

  public static long exponentBits(double value) {
    return bits(value) & DOUBLE_EXPONENT_MASK;
  }

//	public static int exponentBits(float value) {
//		return bits(value) & FLOAT_EXPONENT_MASK;
//	}

  public static long exponentBitsShifted(double value) {
    return exponentBits(value) >>> DOUBLE_EXPONENT_SHIFT;
  }

//	public static int exponentBitsShifted(float value) {
//		return exponentBits(value) >>> FLOAT_EXPONENT_SHIFT;
//	}

  public static long exponent(double value) {
    return exponentBitsShifted(value) - DOUBLE_EXPONENT_BIAS;
  }

//	public static int exponent(float value) {
//		return exponentBitsShifted(value) - FLOAT_EXPONENT_BIAS;
//	}

  public static long signBits(double value) {
    return bits(value) & DOUBLE_SIGN_MASK;
  }

//	public static int signBits(float value) {
//		return bits(value) & FLOAT_SIGN_MASK;
//	}

  public static long signBitsShifted(double value) {
    return signBits(value) >>> DOUBLE_SIGN_SHIFT;
  }

//	public static int signBitsShifted(float value) {
//		return signBits(value) >>> FLOAT_SIGN_SHIFT;
//	}

  public static long sign(double value) {
    return signBits(value) == 0L ? 1 : -1;
  }

//	public static int sign(float value) {
//		return signBits(value) == 0 ? 1 : -1;
//	}

  public static boolean isNaN(double value) {
    return Double.isNaN(value);
  }

//	public static boolean isNaN(float value) {
//		return Float.isNaN(value);
//	}

  public static boolean isInfinite(double value) {
    return Double.isInfinite(value);
  }

//	public static boolean isInfinite(float value) {
//		return Float.isInfinite(value);
//	}

  public static boolean isFinite(double value) {
    return !isNaN(value) && !isInfinite(value);
  }

//	public static boolean isFinite(float value) {
//		return !isNaN(value) && !isInfinite(value);
//	}

  public static boolean isSubnormal(double value) {
    return exponentBits(value) == 0L;
  }

//	public static boolean isSubnormal(float value) {
//		return exponentBits(value) == 0;
//	}

  public static boolean isNormal(double value) {
    return isFinite(value) && !isSubnormal(value);
  }

//	public static boolean isNormal(float value) {
//		return isFinite(value) && !isSubnormal(value);
//	}

  public static double nextPositive(double value) {
    return Math.nextAfter(value, Double.POSITIVE_INFINITY);
  }

//	public static float nextPositive(float value) {
//		return Math.nextAfter(value, Float.POSITIVE_INFINITY);
//	}

  public static double nextNegative(double value) {
    return Math.nextAfter(value, Double.NEGATIVE_INFINITY);
  }

//	public static float nextNegative(float value) {
//		return Math.nextAfter(value, Float.NEGATIVE_INFINITY);
//	}
}
