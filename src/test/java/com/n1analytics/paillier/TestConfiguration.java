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

import java.math.BigInteger;

public class TestConfiguration {
//	// A set of test configurations which are just big enough to encode all
//	// floating point values exactly. The modulus key length is chosen to be
//	// 280 since a Number representation of Float.MAX_VALUE with respect to
//	// the exponent Number.FLOAT_MIN_VALUE_EXPONENT uses 277 bits. We add
//	// one bit for negative numbers and another for room underneath the public
//	// key modulus then round up to the nearest multiple of 8.
//	public static final PaillierPrivateKey PRIVATE_KEY_FLOAT =
//		PaillierPrivateKey.create(280);
//	public static final TestConfiguration CONFIGURATION_FLOAT =
//		create(
//			PRIVATE_KEY_FLOAT,
//			true,
//			1+Number.FLOAT_MAX_PRECISION);

  // A test configurations which are just big enough to encode all
  // floating point values exactly. The modulus key length is chosen to be
  // 2104 since a Number representation of Double.MAX_VALUE with respect
  // to the exponent Number.DOUBLE_MIN_VALUE_EXPONENT uses 2098 bits. We
  // add one bit for negative numbers and another for room underneath the
  // public key modulus then round up to the nearest multiple of 8.
  public static final PaillierPrivateKey PRIVATE_KEY_DOUBLE = PaillierPrivateKey.create(
          2104);
  public static final TestConfiguration CONFIGURATION_DOUBLE = create(PRIVATE_KEY_DOUBLE,
                                                                      true,
                                                                      1 + Number.DOUBLE_MAX_PRECISION);

  public static final PaillierPrivateKey PRIVATE_KEY_512 = PaillierPrivateKey.create(512);
  public static final TestConfiguration UNSIGNED_FULL_PRECISION_512 = createUnsignedFullPrecision(
          PRIVATE_KEY_512);
  public static final TestConfiguration UNSIGNED_PARTIAL_PRECISION_512 = createUnsignedPartialPrecision(
          PRIVATE_KEY_512);
  public static final TestConfiguration SIGNED_FULL_PRECISION_512 = createSignedFullPrecision(
          PRIVATE_KEY_512);
  public static final TestConfiguration SIGNED_PARTIAL_PRECISION_512 = createSignedPartialPrecision(
          PRIVATE_KEY_512);
  public static final TestConfiguration[] CONFIGURATION_512 = {UNSIGNED_FULL_PRECISION_512, UNSIGNED_PARTIAL_PRECISION_512, SIGNED_FULL_PRECISION_512, SIGNED_PARTIAL_PRECISION_512};

  public static final PaillierPrivateKey PRIVATE_KEY_1024 = PaillierPrivateKey.create(
          1024);
  public static final TestConfiguration UNSIGNED_FULL_PRECISION_1024 = createUnsignedFullPrecision(
          PRIVATE_KEY_1024);
  public static final TestConfiguration UNSIGNED_PARTIAL_PRECISION_1024 = createUnsignedPartialPrecision(
          PRIVATE_KEY_1024);
  public static final TestConfiguration SIGNED_FULL_PRECISION_1024 = createSignedFullPrecision(
          PRIVATE_KEY_1024);
  public static final TestConfiguration SIGNED_PARTIAL_PRECISION_1024 = createSignedPartialPrecision(
          PRIVATE_KEY_1024);
  public static final TestConfiguration[] CONFIGURATION_1024 = {UNSIGNED_FULL_PRECISION_1024, UNSIGNED_PARTIAL_PRECISION_1024, SIGNED_FULL_PRECISION_1024, SIGNED_PARTIAL_PRECISION_1024};

  public static final PaillierPrivateKey PRIVATE_KEY_2048 = PaillierPrivateKey.create(
          2048);
  public static final TestConfiguration UNSIGNED_FULL_PRECISION_2048 = createUnsignedFullPrecision(
          PRIVATE_KEY_2048);
  public static final TestConfiguration UNSIGNED_PARTIAL_PRECISION_2048 = createUnsignedPartialPrecision(
          PRIVATE_KEY_2048);
  public static final TestConfiguration SIGNED_FULL_PRECISION_2048 = createSignedFullPrecision(
          PRIVATE_KEY_2048);
  public static final TestConfiguration SIGNED_PARTIAL_PRECISION_2048 = createSignedPartialPrecision(
          PRIVATE_KEY_2048);
  public static final TestConfiguration[] CONFIGURATION_2048 = {UNSIGNED_FULL_PRECISION_2048, UNSIGNED_PARTIAL_PRECISION_2048, SIGNED_FULL_PRECISION_2048, SIGNED_PARTIAL_PRECISION_2048};

	/*
	public static final PaillierPrivateKey PRIVATE_KEY_4096 =
		PaillierPrivateKey.create(4096);
	public static final TestConfiguration UNSIGNED_FULL_PRECISION_4096 =
		createUnsignedFullPrecision(PRIVATE_KEY_4096);
	public static final TestConfiguration UNSIGNED_PARTIAL_PRECISION_4096 =
		createUnsignedPartialPrecision(PRIVATE_KEY_4096);
	public static final TestConfiguration SIGNED_FULL_PRECISION_4096 =
		createSignedFullPrecision(PRIVATE_KEY_4096);
	public static final TestConfiguration SIGNED_PARTIAL_PRECISION_4096 =
		createSignedPartialPrecision(PRIVATE_KEY_4096);
	public static final TestConfiguration[] CONFIGURATION_4096 = {
		UNSIGNED_FULL_PRECISION_4096,
		UNSIGNED_PARTIAL_PRECISION_4096,
		SIGNED_FULL_PRECISION_4096,
		SIGNED_PARTIAL_PRECISION_4096
	};
	*/

  // Default configurations
  public static final TestConfiguration UNSIGNED_FULL_PRECISION = UNSIGNED_FULL_PRECISION_1024;
  public static final TestConfiguration UNSIGNED_PARTIAL_PRECISION = UNSIGNED_PARTIAL_PRECISION_1024;
  public static final TestConfiguration SIGNED_FULL_PRECISION = SIGNED_FULL_PRECISION_1024;
  public static final TestConfiguration SIGNED_PARTIAL_PRECISION = SIGNED_PARTIAL_PRECISION_1024;
  public static final TestConfiguration[] CONFIGURATION = CONFIGURATION_1024;

  public static final TestConfiguration[][] CONFIGURATIONS = {
//		new TestConfiguration[] {CONFIGURATION_FLOAT},
          new TestConfiguration[]{CONFIGURATION_DOUBLE}, CONFIGURATION_512, CONFIGURATION_1024, CONFIGURATION_2048};

  private final PaillierPrivateKey privateKey;
  private final PaillierContext context;

  public TestConfiguration(PaillierPrivateKey privateKey, PaillierContext context) {
    this.privateKey = privateKey;
    this.context = context;
  }

  public static TestConfiguration create(int modulusLength, boolean signed,
                                         int precision) {
    PaillierPrivateKey privateKey = PaillierPrivateKey.create(modulusLength);
    PaillierContext context = new PaillierContext(privateKey.getPublicKey(), signed,
                                                  precision);
    return new TestConfiguration(privateKey, context);
  }

  public static TestConfiguration create(PaillierPrivateKey privateKey, boolean signed,
                                         int precision) {
    PaillierContext context = new PaillierContext(privateKey.getPublicKey(), signed,
                                                  precision);
    return new TestConfiguration(privateKey, context);
  }

  public static TestConfiguration createUnsignedFullPrecision(int modulusLength) {
    return create(modulusLength, false, modulusLength);
  }

  public static TestConfiguration createUnsignedFullPrecision(
          PaillierPrivateKey privateKey) {
    int modulusLength = privateKey.getPublicKey().getModulus().bitLength();
    return create(privateKey, false, modulusLength);
  }

  public static TestConfiguration createUnsignedPartialPrecision(int modulusLength) {
    return create(modulusLength, false, modulusLength - 2);
  }

  public static TestConfiguration createUnsignedPartialPrecision(
          PaillierPrivateKey privateKey) {
    int modulusLength = privateKey.getPublicKey().getModulus().bitLength();
    return create(modulusLength, false, modulusLength - 2);
  }

  public static TestConfiguration createSignedFullPrecision(int modulusLength) {
    return create(modulusLength, true, modulusLength);
  }

  public static TestConfiguration createSignedFullPrecision(
          PaillierPrivateKey privateKey) {
    int modulusLength = privateKey.getPublicKey().getModulus().bitLength();
    return create(modulusLength, true, modulusLength);
  }

  public static TestConfiguration createSignedPartialPrecision(int modulusLength) {
    return create(modulusLength, true, modulusLength - 2);
  }

  public static TestConfiguration createSignedPartialPrecision(
          PaillierPrivateKey privateKey) {
    int modulusLength = privateKey.getPublicKey().getModulus().bitLength();
    return create(modulusLength, true, modulusLength - 2);
  }

  public PaillierPrivateKey privateKey() {
    return privateKey;
  }

  public PaillierPublicKey publicKey() {
    return privateKey.getPublicKey();
  }

  public PaillierContext context() {
    return context;
  }

  public BigInteger totient() {
    return privateKey.getTotient();
  }

  public BigInteger totientInverse() {
    return privateKey.getTotientInverse();
  }

  public BigInteger modulus() {
    return context.getPublicKey().getModulus();
  }

  public int modulusLength() {
    return modulus().bitLength();
  }

  public BigInteger modulusSquared() {
    return context.getPublicKey().getModulusSquared();
  }

  public BigInteger maxSignificand() {
    return context.getMaxSignificand();
  }

  public BigInteger minSignificand() {
    return context.getMinSignificand();
  }

  public BigInteger maxEncoded() {
    return context.getMaxEncoded();
  }

  public BigInteger minEncoded() {
    return context.getMinEncoded();
  }

  public BigInteger generator() {
    return context.getPublicKey().getGenerator();
  }

  public boolean signed() {
    return context.isSigned();
  }

  public boolean unsigned() {
    return !signed();
  }

  public int precision() {
    return context.getPrecision();
  }

  public boolean isFullPrecision() {
    return context.isFullPrecision();
  }

  public boolean isPartialPrecision() {
    return !isFullPrecision();
  }

  public boolean unsignedFullPrecision() {
    return unsigned() && isFullPrecision();
  }

  public boolean unsignedPartialPrecision() {
    return unsigned() && isPartialPrecision();
  }

  public boolean signedFullPrecision() {
    return signed() && isFullPrecision();
  }

  public boolean signedPartialPrecision() {
    return signed() && isPartialPrecision();
  }
}
