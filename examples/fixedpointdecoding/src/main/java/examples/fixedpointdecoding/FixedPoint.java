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
package examples.fixedpointdecoding;

import java.math.BigInteger;

public class FixedPoint {
	/**
	 * Minimum exponent a subnormal double may have:
	 *   Double.MIN_VALUE == 2^-1074
	 */
	public static final int DOUBLE_MIN_VALUE_EXPONENT = -1074;
	/**
	 * Minimum exponent a normalised double may have:
	 *   Double.MIN_NORMAL == 2^-1022 
	 */
	public static final int DOUBLE_MIN_NORMAL_EXPONENT = -1022;
	/**
	 * Maximum exponent a finite double may have:
	 *   Double.MAX_VALUE = (2-2^-52) * 2^1023
	 */
	public static final int DOUBLE_MAX_VALUE_EXPONENT = 1023;
	/**
	 * Number of bits in the two's-complement representation of Double.MAX_VALUE
	 * when encode with DOUBLE_MIN_EXPONENT.
	 */
	public static final int DOUBLE_MAX_PRECISION = 2098;
	public final BigInteger significand;
	public final int exponent;
	
	public FixedPoint(BigInteger significand, int exponent) {
		this.significand = significand;
		this.exponent = exponent;
	}
	
	public static FixedPoint encode(double value) {
		return encode(value, DOUBLE_MIN_VALUE_EXPONENT);
	}
	
	public static FixedPoint encode(double value, int exponent) {
		if(exponent < FixedPoint.DOUBLE_MIN_VALUE_EXPONENT) // Should this be an error?
			throw new IllegalArgumentException("exponent must be greater than or equal to DOUBLE_MIN_EXPONENT");
		if(exponent > FixedPoint.DOUBLE_MAX_VALUE_EXPONENT)
			throw new IllegalArgumentException("exponent must be less than or equal to DOUBLE_MAX_EXPONENT");
		if(Double.isInfinite(value))
			throw new ArithmeticException("Cannot encode infinity");
		if(Double.isNaN(value))
			throw new ArithmeticException("Cannot encode NaN");
		
		// Extract the sign, exponent, and significand from the IEE754
		// representation of value
		long bits = Double.doubleToLongBits(value);
		int valueSign = ((bits >> 63) == 0) ? 1 : -1;
		int valueExponent = (int)((bits >> 52) & 0x7FFL);
		long valueSignificand = 0x000FFFFFFFFFFFFFL & bits;
		
		//assert(valueExponent < 0x7FF); // Guaranteed by isInfinite and isNaN checks
	
		// Encode number and check that it can be represented with the
		// specified precision
		BigInteger encoding;
		if(valueExponent > 0) {
			// Normalised number
			encoding = BigInteger
				.valueOf(valueSign * (valueSignificand |  0x0010000000000000L))
				.shiftLeft(DOUBLE_MIN_VALUE_EXPONENT + valueExponent - exponent - 1);
		} else if(valueSignificand > 0) {
			// Subnormal number
			encoding = BigInteger
				.valueOf(valueSign * valueSignificand)
				.shiftLeft(DOUBLE_MIN_VALUE_EXPONENT - exponent);
		} else {
			// Zero
			encoding = BigInteger.ZERO;
		}
		
		return new FixedPoint(encoding, exponent);
	}
	
	public double decodeDouble() {
		int signum = significand.signum();
		BigInteger absSignificand = significand.abs();
		int absSignificandLength = absSignificand.bitLength();
		int mostSignificantBitExponent = exponent + absSignificandLength - 1;
		
		// Handle zero
		if(mostSignificantBitExponent < DOUBLE_MIN_VALUE_EXPONENT)
			return 0.0;
		
		// Handle infinity
		if(mostSignificantBitExponent > DOUBLE_MAX_VALUE_EXPONENT) {
			if(signum < 0)
				return Double.NEGATIVE_INFINITY;
			else
				return Double.POSITIVE_INFINITY;
		}
		
		long decodedSignum = (signum < 0) ? 1 : 0;
		long decodedExponent;
		long decodedSignificand;
		if(mostSignificantBitExponent < DOUBLE_MIN_NORMAL_EXPONENT) {
			// Handle subnormal number
			decodedExponent = 0;
			decodedSignificand =
				absSignificand
				.shiftLeft(exponent - DOUBLE_MIN_VALUE_EXPONENT)
				.longValue();
		} else {
			// Handle normalised number
			decodedExponent = mostSignificantBitExponent - DOUBLE_MIN_NORMAL_EXPONENT + 1;
			decodedSignificand = ~0x0010000000000000L &
				absSignificand
				.shiftRight(absSignificandLength - 53)
				.longValue();
		}
		
		long decodedBits =
			(decodedSignum << 63) |
			(decodedExponent << 52) |
			decodedSignificand;
		return Double.longBitsToDouble(decodedBits);
	}
	
	// TODO public decodeExactDouble()
	
	public FixedPoint changeExponent(int newExponent) {
		return new FixedPoint(
			significand.shiftRight(newExponent - exponent),
			newExponent);
	}
}
