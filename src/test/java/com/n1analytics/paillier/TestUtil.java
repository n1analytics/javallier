package com.n1analytics.paillier;

import java.util.Random;

public class TestUtil {
	public static final Random random = new Random();
	
	public static double randomDouble() {
		return Double.longBitsToDouble(random.nextLong());
	}
	
	public static double randomFiniteDouble() {
		for(;;) {
			double value = randomDouble();
			if(!(Double.isInfinite(value) || Double.isNaN(value)))
				return value;
		}
	}
	
	public static double randomNaNDouble() {
		for(;;) {
			// Generate a random NaN/infinity
			double value = Double.longBitsToDouble(
				0x7FF000000000000L | random.nextLong());
			if(Double.isNaN(value))
				return value;
		}
	}
	
	public static double randomNormalDouble() {
		for(;;) {
			double value = randomFiniteDouble();
			if(value >= Double.MIN_NORMAL)
				return value;
		}
	}
	
	public static double randomSubnormalDouble() {
		return Double.longBitsToDouble(0x800FFFFFFFFFFFFL & random.nextLong());
	}
}
