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

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Immutable class representing Paillier private key.
 * 
 * A private key (and it's corresponding public key) are generated via the
 * following procedure, given a public key length <code>modulusLength</code>:
 * <ol>
 *   <li>
 *     Generate two primes <code>p, q</code>, each of bit length
 *     <code>modulusLength/2</code> and with a product <code>p * q</code> of bit
 *     length <code>modulusLength</code>.
 *   </li>
 *   <li>
 *     Calculate <code>modulus = p * q</code>.
 *   </li>
 *   <li>
 *     Calculate <code>generator = modulus + 1</code>.
 *   </li>
 *   <li>
 *     Calculate the totient function of <code>modulus</code>:
 *     <code>totient = (p-1)*(q-1)</code>. This represents the number of
 *     positive integers less than or equal to <code>modulus</code> which
 *     are relatively prime to <code>modulus</code>.
 *   </li>
 *   <li>
 *     Calculate the inverse of <code>totient</code> modulo <code>modulus</code>.
 *   </li>
 * <ul>
 * 
 * The result of this procedure is a public key comprising a
 * <code>modulus</code>, its square <code>modulusSquared</code> and a
 * <code>generator</code> as well as  a private key comprising a reference to
 * the <code>publicKey</code>, the <code>totient</code>, and its modular inverse
 * <code>totientInverse</code>.
 * 
 * Examples:
 * <ul>
 *   <li>
 *     <p>To create a 1024 bit keypair:</p>
 *     <p><code>PaillierPrvateKey privateKey = PaillierPrivateKey.create(1024);</code></p>
 *   </li>
 *   <li>
 *     <p>To decrypt an encrypted number <code>encryption</code>:</p>
 *     <p><code>EncodedNumber encodedNumber = privateKey.decrypt(encryption);</code></p>
 *   </li>
 *   <li>
 *     <p>
 *       To decrypt an encrypted number <code>encryption</code> and obtain the
 *       (double) value of the decryption:
 *     </p>
 *     <p>
 *       <code>double plaintext = privateKey.decrypt(encryption).decodeDouble();</code>
 *     </p>
 *   </li>
 * </ul>
 */
public final class PaillierPrivateKey {
    
    static interface Serializer {
    	// NOTE don't need to serialise totientInverse
        void serialize(PaillierPublicKey publickey, BigInteger totient);
    }

    protected final PaillierPublicKey publicKey;
    protected final BigInteger totient;
    protected final BigInteger totientInverse;
    
    public PaillierPrivateKey(PaillierPublicKey publicKey, BigInteger totient) {
    	// Some basic error checking. Note though that passing these tests does
    	// not guarantee that the private key is valid.
    	if(publicKey == null)
    		throw new IllegalArgumentException("publicKey must not be null");
    	if(totient == null)
    		throw new IllegalArgumentException("totient must not be null");
    	if(totient.signum() < 0)
    		throw new IllegalArgumentException("totient must be non-negative");
    	if(totient.compareTo(publicKey.getModulus()) >= 0)
    		throw new IllegalArgumentException("totient must be less than public key modulus");
    	
    	this.publicKey = publicKey;
    	this.totient = totient;
    	this.totientInverse = totient.modInverse(publicKey.getModulus());
    }
    
    /**
     * Constructs a Paillier private key given an associated public key and the
     * private key, totient and totientInverse.
     * @param publicKey Public key associated with this private key.
     * @param totient Private key, totient.
     * @param totientInverse Private key, totientInverse.
     */
    private PaillierPrivateKey(
    	PaillierPublicKey publicKey,
    	BigInteger totient,
    	BigInteger totientInverse)
    {
        this.publicKey = publicKey;
        this.totient = totient;
        this.totientInverse = totientInverse;
    }

    /**
     * Creates a Paillier keypair of the specified modulus key length.
     * @param modulusLength the length of the public key modulus. Must be a
     * positive multiple of 8.
     * @return private key with the associated public key (keypair).
     * @throws IllegalArgumentException
     */
    public static PaillierPrivateKey create(int modulusLength) {
        if(modulusLength < 8 || modulusLength % 8 != 0)
        	throw new IllegalArgumentException("modulusLength must be a multiple of 8");

        // Find two primes p and q whose multiple has the same number of bits
        // as modulusLength
        BigInteger p, q, modulus;
        int primeLength = modulusLength / 2;
        SecureRandom random = new SecureRandom();
        do {
            p = BigInteger.probablePrime(primeLength, random);
            q = BigInteger.probablePrime(primeLength, random);
            modulus = p.multiply(q);
        } while(modulus.bitLength() != modulusLength);

        final PaillierPublicKey publicKey = new PaillierPublicKey(modulus);
        final BigInteger totient = modulus.add(BigInteger.ONE.subtract(p).subtract(q));
        final BigInteger totientInverse = totient.modInverse(modulus);
        return new PaillierPrivateKey(publicKey, totient, totientInverse);
    }

    /**
     * Gets the public key associated with this private key.
     * @return the associated public key.
     */
    public PaillierPublicKey getPublicKey() {
        return publicKey;
    }
    
    public BigInteger getTotient() {
    	return totient;
    }
    
    public BigInteger getTotientInverse() {
    	return totientInverse;
    }

    /**
     * Returns a decrypted encrypted number (which is still encoded).
     * @param encrypted number to be decrypted.
     * @return the decrypted encoded number.
     * @throws PaillierKeyMismatchException If the encrypted number was not
     * encoded with the appropriate public key.
     */
    public EncodedNumber decrypt(EncryptedNumber encrypted) throws
    	PaillierKeyMismatchException
    {
        if(!publicKey.equals(encrypted.getContext().getPublicKey()))
            throw new PaillierKeyMismatchException();

        BigInteger decrypted = encrypted
        	.ciphertext
        	.modPow(totient, publicKey.getModulusSquared())
        	.subtract(BigInteger.ONE)
        	.divide(publicKey.getModulus())
        	.multiply(totientInverse)
        	.mod(publicKey.getModulus());
        return new EncodedNumber(
        	encrypted.getContext(),
        	decrypted,
        	encrypted.getExponent());
    }

    public void serialize(Serializer serializer) {
    	serializer.serialize(publicKey, totient);
    }
    
    @Override
    public int hashCode() {
    	return publicKey.hashCode();
    	// NOTE we don't need to hash totient or totientInverse since they are
    	//      are uniquely determined by publicKey
    }
    
    @Override
    public boolean equals(Object o) {
    	return o == this || (
    		o != null &&
    		o.getClass() == PaillierPrivateKey.class &&
    		publicKey.equals(((PaillierPrivateKey)o).publicKey));
    	// NOTE we don't need to compare totient or totientInverse since they
    	//      are uniquely determined by publicKey
    }
    
    public boolean equals(PaillierPrivateKey o) {
    	return o == this || (o != null && publicKey.equals(o.publicKey));
    	// NOTE we don't need to compare totient or totientInverse since they
    	//      are uniquely determined by publicKey
    }
}
