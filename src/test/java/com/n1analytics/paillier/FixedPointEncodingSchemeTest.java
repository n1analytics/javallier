package com.n1analytics.paillier;

import static org.junit.Assert.*;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Random;

import org.junit.BeforeClass;
import org.junit.Test;

import com.n1analytics.paillier.util.BigIntegerUtil;

public class FixedPointEncodingSchemeTest {
  
  private static PaillierPrivateKey privateKey;
  private static final int DEFAULT_SCALE = -100;
  private static FixedPointEncodingScheme encoding;
  private static final int maxIterations = TestConfiguration.MAX_ITERATIONS;
  private static Random rnd;

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    privateKey = PaillierPrivateKey.create(TestConfiguration.DEFAULT_KEY_SIZE);
    PaillierContext context = new PaillierContext(privateKey.publicKey, new FixedPointEncodingScheme(privateKey.publicKey, DEFAULT_SCALE));
    encoding = (FixedPointEncodingScheme)context.getEncodingScheme();
    rnd = new Random();
  }

  @Test
  public void testConstructor() {
    FixedPointEncodingScheme newScheme = new FixedPointEncodingScheme(privateKey.getPublicKey(), DEFAULT_SCALE);
    assertEquals(2, newScheme.getBase());
    assertTrue(newScheme.isSigned());
    assertEquals(TestConfiguration.DEFAULT_KEY_SIZE, newScheme.getPrecision());
    assertEquals(privateKey.getPublicKey(), newScheme.getPublicKey());
  }
  
  @Test
  public void testEncodeBigInteger() {
    for (int i = 0; i < maxIterations; i++) {
      BigInteger value = BigIntegerUtil.randomPositiveNumber(BigInteger.ONE.shiftLeft(TestConfiguration.DEFAULT_KEY_SIZE + DEFAULT_SCALE - 2));
      if (rnd.nextBoolean()) {
        value = value.negate();
      }
      EncodedNumber number = encoding.encode(value);
      assertEquals(encoding.decodeBigInteger(number), value);
    }
  }
  
  @Test
  public void testEncodeDouble() {
    double epsilon = Math.pow(encoding.getBase(), DEFAULT_SCALE);
    for (int i = 0; i < maxIterations; i++) {
      double value = TestUtil.randomFiniteDouble();
      EncodedNumber number = encoding.encode(value);
      assertEquals(encoding.decodeDouble(number), value, epsilon);
    }
  }
  
  @Test
  public void testEncodeLong() {
    for (int i = 0; i < maxIterations; i++) {
      long value = rnd.nextLong();
      EncodedNumber number = encoding.encode(value);
      assertEquals(encoding.decodeLong(number), value);
    }
  }
  
  @Test
  public void testEncodeBigDecimal() {
    for (int i = 0; i < maxIterations; i++) {
      BigDecimal value = new BigDecimal(TestUtil.randomFiniteDouble());
      EncodedNumber number = encoding.encode(value);
      BigInteger bi = number.decodeBigInteger();
      BigDecimal diff = encoding.decodeBigDecimal(number).subtract(value);
      assertTrue(diff.abs().compareTo(new BigDecimal(Math.pow(encoding.getBase(), DEFAULT_SCALE))) < 0);
    }
  }
  
  @Test
  public void testSignum() {
    EncodedNumber number = encoding.encode(BigInteger.ZERO);
    assertEquals(0, number.signum());
    number = encoding.encode(-42);
    assertEquals(-1, number.signum());
    number = encoding.encode(42);
    assertEquals(1, number.signum());
  }

}
