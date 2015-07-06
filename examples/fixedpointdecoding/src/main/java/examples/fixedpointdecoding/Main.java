package examples.fixedpointdecoding;

import java.math.BigInteger;
import java.util.Random;

public class Main {
	
	// Double.MIN_VALUE = 2^-1074
	public static final int DOUBLE_MIN_VALUE_EXPONENT = -1074;
	
	// Double.MIN_NORMAL = 2^-1022
	public static final int DOUBLE_MIN_NORMAL_EXPONENT = -1022;
	
	// Double.MAX_VALUE = 2^1024-2^(1025-53) = 2^1024-2^971
	public static final int DOUBLE_MAX_VALUE_EXPONENT = 1023;
	
	public static void print(String name, double value) {
		long bits = Double.doubleToLongBits(value);
		long bitsSign = bits & 0x8000000000000000L;
		long bitsSignShifted = bitsSign >> 63;
		long bitsExponent = bits & 0x7ff0000000000000L;
		long bitsExponentShifted = bitsExponent >> 52;
		long bitsSignificand = bits & 0x000fffffffffffffL;
		long bitsSignificandExplicit = bitsSignificand | (
			(0L < bitsExponentShifted && bitsExponentShifted < 0x7FFL) ?
			0x0010000000000000L :
			0L);
		FixedPoint encoded = FixedPoint.encode(value);
		BigInteger significand = encoded.significand;
		int exponent = encoded.exponent;
		int signum = significand.signum();
		BigInteger absSignificand = significand.abs();
		int absSignificandLength = absSignificand.bitLength();
		int mostSignificantBitExponent = exponent + absSignificandLength - 1;
		long decodedExponentShifted;
		long decodedSignificand;
		long decodedSignificandExplicit;
		if(mostSignificantBitExponent < DOUBLE_MIN_NORMAL_EXPONENT) {
			decodedExponentShifted = 0;
			decodedSignificandExplicit = absSignificand
				.shiftLeft(exponent - DOUBLE_MIN_VALUE_EXPONENT)
				.longValue();
			decodedSignificand = decodedSignificandExplicit;
		} else {
			decodedExponentShifted = mostSignificantBitExponent - DOUBLE_MIN_NORMAL_EXPONENT + 1;
			decodedSignificandExplicit =
				absSignificand
				.shiftRight(absSignificandLength - 53)
				.longValue();
			decodedSignificand = decodedSignificandExplicit & ~0x0010000000000000L;
		}
		long decodedSignShifted = (signum < 0) ? 1 : 0;
		long decodedSign = decodedSignShifted << 63;
		long decodedExponent = decodedExponentShifted << 52;
		long decodedBits = decodedSign | decodedExponent | decodedSignificand;
		
		System.out.format(
			"%s:\n" +
			"\tbits:                         %016X\n" +
			"\tbits.sign:                    %016X\n" +
			"\tbits.sign.shifted:            %016X\n" +
			"\tbits.exponent:                %016X\n" +
			"\tbits.exponent.shifted:        %016X\n" +
			"\tbits.significand:             %016X\n" +
			"\tbits.significand.explicit:    %016X\n" +
			"\n" +
			"\tdecoded.bits:                 %016X\n" +
			"\tdecoded.sign:                 %016X\n" +
			"\tdecoded.sign.shifted:         %016X\n" +
			"\tdecoded.exponent:             %016X\n" +
			"\tdecoded.exponent.shifted:     %016X\n" +
			"\tdecoded.significand:          %016X\n" +
			"\tdecoded.significand.explicit: %016X\n" +
			"\n" +
			"\tencoded.decodeDouble():       %016X\n" +
			"\tencoded.absSignificandLength: %d\n" +
			"\tencoded.msbExponent:          %d\n" +
			"\tencoded.exponent:             %d\n" +
			"\tencoded.significand:          %s\n",
			name,
			bits,
			bitsSign,
			bitsSignShifted,
			bitsExponent,
			bitsExponentShifted,
			bitsSignificand,
			bitsSignificandExplicit,
			decodedBits,
			decodedSign,
			decodedSignShifted,
			decodedExponent,
			decodedExponentShifted,
			decodedSignificand,
			decodedSignificandExplicit,
			Double.doubleToLongBits(encoded.decodeDouble()),
			absSignificandLength,
			mostSignificantBitExponent,
			exponent,
			significand.toString(16));
	}
	
	public static void test(double value) {
		FixedPoint encoded = FixedPoint.encode(value);
		double decoded = encoded.decodeDouble();
		if(value != decoded)
			throw new RuntimeException(String.format("%f does not equal %f", value, decoded));
	}
	
	public static double prevDouble(double d) {
		return Math.nextAfter(d, Double.NEGATIVE_INFINITY);
	}
	
	public static double nextDouble(double d) {
		return Math.nextAfter(d, Double.POSITIVE_INFINITY);
	}

	public static void main(String[] args) {
		print("minValue", Double.MIN_VALUE);
		print("minValueNext", nextDouble(Double.MIN_VALUE));
		print("minNormalPrev", prevDouble(Double.MIN_NORMAL));
		print("minNormal", Double.MIN_NORMAL);
		print("minNormalNext", nextDouble(Double.MIN_NORMAL));
		print("onePrev", prevDouble(1.0));
		print("one", 1.0);
		print("oneNext", nextDouble(1.0));
		print("maxValuePrev", prevDouble(Double.MAX_VALUE));
		print("maxValue", Double.MAX_VALUE);
		
		// 6 seconds to encode 100,000,000 doubles
		// 9.5 seconds to encode and decode 100,000,000 doubles 
		
		Random random = new Random();
		long start = System.currentTimeMillis();
		for(int i = 0; i < 100000000; ++i)
			FixedPoint.encode(random.nextDouble());
		System.out.println(System.currentTimeMillis() - start);
		
		start = System.currentTimeMillis();
		for(int i = 0; i < 100000000; ++i)
			test(random.nextDouble());
		System.out.println(System.currentTimeMillis() - start);
	}

}
