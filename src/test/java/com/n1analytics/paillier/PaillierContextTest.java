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
package com.n1analytics.paillier;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class PaillierContextTest {
	private final static PaillierContext signedFull = TestConfiguration.SIGNED_FULL_PRECISION_1024.context();
	private final static PaillierContext unsignedFull = TestConfiguration.UNSIGNED_FULL_PRECISION_1024.context();
	private final static PaillierContext signedPartial = TestConfiguration.SIGNED_PARTIAL_PRECISION_1024.context();
	private final static PaillierContext unsignedPartial = TestConfiguration.UNSIGNED_PARTIAL_PRECISION_1024.context();

	@Test
	public void testConstructor() throws Exception {
        PaillierPublicKey publicKey = TestConfiguration.SIGNED_FULL_PRECISION_1024.publicKey();
		PaillierContext context = null;

		try {
			context = new PaillierContext(null, false, 10);
			fail("Successfully created a context with null public key");
		} catch (NullPointerException e) {
		}
        assertNull(context);

		try {
			context = new PaillierContext(publicKey, false, 0);
			fail("Successfully created a context with precision less than one");
		} catch (IllegalArgumentException e) {
		}
        assertNull(context);

		try {
			context = new PaillierContext(publicKey, true, 1);
			fail("Successfully created a context with precision less than one when signed is true");
		} catch (IllegalArgumentException e) {
		}
        assertNull(context);

		try {
			context = new PaillierContext(publicKey, true, 1032);
			fail("Successfully created a context with precision greater than the public key's modulus bit length");
		} catch (IllegalArgumentException e) {
		}
        assertNull(context);

        context = new PaillierContext(publicKey, true, 1024);
        assertNotNull(context);
        // Check public key
        assertNotNull(context.getPublicKey());
        assertEquals(publicKey, context.getPublicKey());
        // Check signed
        assertTrue(context.isSigned());
        // Check precision
        assertNotNull(context.getPrecision());
        assertEquals(1024, context.getPrecision());
	}

	@Test
	public void testContextProperty() throws Exception {
		assertEquals(true, signedFull.isSigned());
		assertEquals(false, signedFull.isUnsigned());
		assertEquals(true, signedFull.isFullPrecision());

		assertEquals(false, unsignedFull.isSigned());
		assertEquals(true, unsignedFull.isUnsigned());
		assertEquals(true, unsignedFull.isFullPrecision());

		assertEquals(true, signedPartial.isSigned());
		assertEquals(false, signedPartial.isUnsigned());
		assertEquals(false, signedPartial.isFullPrecision());

		assertEquals(false, unsignedPartial.isSigned());
		assertEquals(true, unsignedPartial.isUnsigned());
		assertEquals(false, unsignedPartial.isFullPrecision());
	}

	@Test
	public void testAdditiveInverse() throws Exception {
		EncodedNumber encodedNumber = signedFull.encode(1);
		assertEquals(-1, encodedNumber.additiveInverse().decodeLong());

		encodedNumber = signedFull.encode(0);
		assertEquals(0, encodedNumber.additiveInverse().decodeLong());

		encodedNumber = signedFull.encode(-1);
		assertEquals(1, encodedNumber.additiveInverse().decodeLong());
	}

	@Test
	public void testEncodeDecode() throws Exception {
		EncodedNumber encodedNumber = signedFull.encode(10.0);

		assertEquals(10, signedFull.decodeLong(encodedNumber));
		assertEquals(10, signedFull.decodeApproximateLong(encodedNumber));

		assertEquals(new BigInteger("10"), signedFull.decodeBigInteger(encodedNumber));
		assertEquals(new BigInteger("10"), signedFull.decodeApproximateBigInteger(encodedNumber));

		assertEquals(10.0, signedFull.decodeDouble(encodedNumber), 0.0);
		assertEquals(10.0, signedFull.decodeApproximateDouble(encodedNumber), 0.0);
	}

	@Test
	public void testCheckSameContext() throws Exception {
		PaillierContext context = signedFull;

		// Raise Exception because the two contexts have different public key
		try {
			context.checkSameContext(TestConfiguration.SIGNED_FULL_PRECISION_512.context());
		} catch (PaillierContextMismatchException e) {
		}

		// Shouldn't raise exception
		context.checkSameContext(signedFull);


		// Raise Exception because the two contexts have different signed
		PaillierContext unsignedClonedContext = context.getPublicKey().createUnsignedContext();
		try {
			context.checkSameContext(unsignedClonedContext);
		} catch (PaillierContextMismatchException e) {
		}

		// Raise Exception because the two contexts have different precision
		PaillierContext partialClonedContext = context.getPublicKey().createSignedContext(1022);
		try {
			context.checkSameContext(partialClonedContext);
		} catch (PaillierContextMismatchException e) {
		}

		PaillierContext clonedContext = context.getPublicKey().createSignedContext();
		context.checkSameContext(clonedContext);
	}

	@Test
	public void testIsLongValid() throws Exception {
		assertTrue(signedFull.isValid(17));
	}

	@Test
	public void testIsDoubleValid() throws Exception {
		assertTrue(signedFull.isValid(17.1));

		assertFalse(signedFull.isValid(Double.POSITIVE_INFINITY));
	}

	@Test
	public void testIsBigIntegerValid() throws Exception {
		assertTrue(signedFull.isValid(new BigInteger("17")));
	}

	@Test
	public void testIsEncodedNumberValid() throws Exception {
		// Valid EncodedNumbers
		assertTrue(signedFull.isValid(new EncodedNumber(signedFull, signedFull.getMaxEncoded(), 0)));
		assertTrue(signedFull.isValid(new EncodedNumber(signedFull, signedFull.getMinEncoded(), 0)));

		// Non valid EncodedNumbers
		assertFalse(signedFull.isValid(unsignedFull.encode(17)));
		assertFalse(signedPartial.isValid(new EncodedNumber(signedPartial,
				signedPartial.getMaxEncoded().add(BigInteger.TEN), 0)));
		assertFalse(unsignedPartial.isValid(new EncodedNumber(unsignedPartial,
                unsignedPartial.getMaxEncoded().add(BigInteger.ONE), 0)));
	}

	// NOTE: the other getMax() and getMin() methods are tested in PaillierEncodedNumberTest
	@Test
	public void testGetMaxLong() throws Exception {
		PaillierPrivateKey privateKey = PaillierPrivateKey.create(32);
		PaillierPublicKey publicKey = privateKey.getPublicKey();
		PaillierContext context = publicKey.createUnsignedContext();

		// Note: the context is created such that the max long value is within the range of long
		assertEquals(context.getMaxLong(0), publicKey.getModulus().subtract(BigInteger.ONE).longValue());
	}

    @Test
    public void testEquals() throws Exception {
        assertTrue(signedFull.equals(signedFull));
        assertFalse(signedFull.equals(signedFull.getPublicKey()));

        PaillierContext otherContext = null;

        // Check when the other public key hasn't been initialised (ie, is null)
        assertFalse(signedFull.equals(otherContext));

        otherContext = new PaillierContext(unsignedFull.getPublicKey(), false, 1024);

        // Check after the other private key has been initialised (ie, is not null)
        assertFalse(signedFull.equals(otherContext));

        assertFalse(signedFull.equals(null));

    }

	public static void testEncodable(PaillierContext context, Number number) {
		assertTrue(context.isValid(number));
		assertEquals(number, context.decode(context.encode(number)));
	}

	public static void testEncodable(PaillierContext context, double number) {
		assertTrue(context.isValid(number));
		assertEquals(number, context.decode(context.encode(number)).decodeDouble(), 0.0);
	}

	public static void testEncodable(PaillierContext context, long number) {
		assertTrue(context.isValid(number));
		assertEquals(number, context.decode(context.encode(number)).decodeLong());
	}

	public static void testUnencodable(PaillierContext context, Number number) {
		assertFalse(context.isValid(number));
		try {
			context.encode(number);
			fail("Should not be able to encode number");
		} catch(EncodeException e) {
		}
	}

	public static void testUnencodable(PaillierContext context, double number) {
		assertFalse(context.isValid(number));
		try {
			context.encode(number);
			fail("Should not be able to encode number");
		} catch(EncodeException e) {
		}
	}

	public static void testUnencodable(PaillierContext context, long number) {
		assertFalse(context.isValid(number));
		try {
			context.encode(number);
			fail("Should not be able to encode number");
		} catch(EncodeException e) {
		}
	}

}
