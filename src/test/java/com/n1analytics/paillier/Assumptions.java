package com.n1analytics.paillier;

import org.junit.Test;

import java.math.BigInteger;

import static com.n1analytics.paillier.util.FloatingPointUtil.*;
import static org.junit.Assert.assertEquals;

public class Assumptions {
	// TODO modulus of public key is always odd (and greater than 4...)
	
//	public static class NamedFloat {
//		public final String name;
//		public final float value;
//		public NamedFloat(String name, float value) {
//			this.name = name;
//			this.value = value;
//		}
//	}
	
	public static class NamedDouble {
		public final String name;
		public final double value;
		public NamedDouble(String name, double value) {
			this.name = name;
			this.value = value;
		}
	}
	
//	public static final NamedFloat[] namedFloats = {
//		new NamedFloat(" NaN", Float.NaN),
//		new NamedFloat(" INIFINITY", Float.POSITIVE_INFINITY),
//		new NamedFloat(" MAX_VALUE", Float.MAX_VALUE),
//		new NamedFloat(" MAX_VALUE / 2", Float.MAX_VALUE / 2),
//		new NamedFloat(" MAX_INT * 2", FLOAT_MAX_INT * 2),
//		new NamedFloat(" MAX_INT", FLOAT_MAX_INT),
//		new NamedFloat(" MAX_INT - 1", FLOAT_MAX_INT - 1),
//		new NamedFloat(" MAX_INT / 2", FLOAT_MAX_INT / 2),
//		new NamedFloat(" 2", 2f),
//		new NamedFloat(" 1", 1f),
//		new NamedFloat(" MIN_NORMAL", Float.MIN_NORMAL),
//		new NamedFloat(" MAX_SUBNORMAL", nextNegative(Float.MIN_NORMAL)),
//		new NamedFloat(" MIN_NORMAL / 2", Float.MIN_NORMAL / 2),
//		new NamedFloat(" MIN_VALUE * 2", Float.MIN_VALUE * 2),
//		new NamedFloat(" MIN_VALUE", Float.MIN_VALUE),
//		new NamedFloat(" 0", 0f),
//		new NamedFloat("-0", -0f),
//		new NamedFloat("-MIN_VALUE", -Float.MIN_VALUE),
//		new NamedFloat("-MIN_VALUE * 2", -Float.MIN_VALUE * 2),
//		new NamedFloat("-MIN_NORMAL / 2", -Float.MIN_NORMAL / 2),
//		new NamedFloat("-MAX_SUBNORMAL", -nextNegative(Float.MIN_NORMAL)),
//		new NamedFloat("-MIN_NORMAL", -Float.MIN_NORMAL),
//		new NamedFloat("-1", -1f),
//		new NamedFloat("-2", -2f),
//		new NamedFloat("-MAX_INT/2", -FLOAT_MAX_INT / 2),
//		new NamedFloat("-MAX_INT+1", -FLOAT_MAX_INT + 1),
//		new NamedFloat("-MAX_INT", -FLOAT_MAX_INT),
//		new NamedFloat("-MAX_INT * 2", -FLOAT_MAX_INT * 2),
//		new NamedFloat("-MAX_VALUE / 2", -Float.MAX_VALUE / 2),
//		new NamedFloat("-MAX_VALUE", -Float.MAX_VALUE),
//		new NamedFloat("-INFINITY", Float.NEGATIVE_INFINITY)
//	};
	
	public static final NamedDouble[] namedDoubles = {
		new NamedDouble(" NaN", Double.NaN),
		new NamedDouble(" INIFINITY", Double.POSITIVE_INFINITY),
		new NamedDouble(" MAX_VALUE", Double.MAX_VALUE),
		new NamedDouble(" MAX_VALUE / 2", Double.MAX_VALUE / 2),
		new NamedDouble(" MAX_INT * 2", DOUBLE_MAX_INT * 2),
		new NamedDouble(" MAX_INT", DOUBLE_MAX_INT),
		new NamedDouble(" MAX_INT - 1", DOUBLE_MAX_INT - 1),
		new NamedDouble(" MAX_INT / 2", DOUBLE_MAX_INT / 2),
		new NamedDouble(" 2", 2f),
		new NamedDouble(" 1", 1f),
		new NamedDouble(" MIN_NORMAL", Double.MIN_NORMAL),
		new NamedDouble(" MAX_SUBNORMAL", nextNegative(Double.MIN_NORMAL)),
		new NamedDouble(" MIN_NORMAL / 2", Double.MIN_NORMAL / 2),
		new NamedDouble(" MIN_VALUE * 2", Double.MIN_VALUE * 2),
		new NamedDouble(" MIN_VALUE", Double.MIN_VALUE),
		new NamedDouble(" 0", 0f),
		new NamedDouble("-0", -0f),
		new NamedDouble("-MIN_VALUE", -Double.MIN_VALUE),
		new NamedDouble("-MIN_VALUE * 2", -Double.MIN_VALUE * 2),
		new NamedDouble("-MIN_NORMAL / 2", -Double.MIN_NORMAL / 2),
		new NamedDouble("-MAX_SUBNORMAL", -nextNegative(Double.MIN_NORMAL)),
		new NamedDouble("-MIN_NORMAL", -Double.MIN_NORMAL),
		new NamedDouble("-1", -1f),
		new NamedDouble("-2", -2f),
		new NamedDouble("-MAX_INT/2", -DOUBLE_MAX_INT / 2),
		new NamedDouble("-MAX_INT+1", -DOUBLE_MAX_INT + 1),
		new NamedDouble("-MAX_INT", -DOUBLE_MAX_INT),
		new NamedDouble("-MAX_INT * 2", -DOUBLE_MAX_INT * 2),
		new NamedDouble("-MAX_VALUE / 2", -Double.MAX_VALUE / 2),
		new NamedDouble("-MAX_VALUE", -Double.MAX_VALUE),
		new NamedDouble("-INFINITY", Double.NEGATIVE_INFINITY)
	};
	
//	public void printFloatInfo() {
//		System.out.println(
//			"+-----------------+------------------+----------+------+----------+----------+\n" +
//			"| number          | value            | bits     | sign | exponent | fraction |\n" +
//			"+-----------------+------------------+----------+------+----------+----------+");
//		for(NamedFloat namedFloat: namedFloats) {
//			if(isFinite(namedFloat.value)){
//				System.out.format(
//					"| %-15s | %s0x%01d.%06Xp%-+4d | %08X | %01X    | %02X       | %06X   |\n",
//					namedFloat.name,
//					sign(namedFloat.value) < 0 ? "-" : " ",
//					isNormal(namedFloat.value) ? 1 : 0,
//					fraction(namedFloat.value) << 1,
//					isNormal(namedFloat.value) ? exponent(namedFloat.value) : -126,
//					bits(namedFloat.value),
//					signBitsShifted(namedFloat.value),
//					exponentBitsShifted(namedFloat.value),
//					fraction(namedFloat.value));
//			} else {
//				System.out.format(
//					"| %-15s |                  | %08X | %01X    | %02X       | %06X   |\n",
//					namedFloat.name,
//					bits(namedFloat.value),
//					signBitsShifted(namedFloat.value),
//					exponentBitsShifted(namedFloat.value),
//					fraction(namedFloat.value));
//			}
//		}
//		System.out.println("+-----------------+------------------+----------+------+----------+----------+");
//	}
	
	public void printDoubleInfo() {
		System.out.println(
			"+-----------------+--------------------------+------------------+------+----------+---------------+\n" + 
			"| number          | value                    | bits             | sign | exponent | fraction      |\n" +
			"+-----------------+--------------------------+------------------+------+----------+---------------+");
		for(NamedDouble namedDouble: namedDoubles) {
			if(isFinite(namedDouble.value)){ 
				System.out.format(
					"| %-15s | %s0x%01d.%013Xp%-+5d | %016X | %01X    | %03X      | %013X |\n",
					namedDouble.name,
					sign(namedDouble.value) < 0 ? "-" : " ",
					isNormal(namedDouble.value) ? 1 : 0,
					fraction(namedDouble.value),
					isNormal(namedDouble.value) ? exponent(namedDouble.value) : -1022,
					bits(namedDouble.value),
					signBitsShifted(namedDouble.value),
					exponentBitsShifted(namedDouble.value),
					fraction(namedDouble.value));
			} else {
				System.out.format(
					"| %-15s |                          | %016X | %01X    | %03X      | %013X |\n",
					namedDouble.name,
					bits(namedDouble.value),
					signBitsShifted(namedDouble.value),
					exponentBitsShifted(namedDouble.value),
					fraction(namedDouble.value));
			}
		}
		System.out.println("+-----------------+--------------------------+------------------+------+----------+---------------+");
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
