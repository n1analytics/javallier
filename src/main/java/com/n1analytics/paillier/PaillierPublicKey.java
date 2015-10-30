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

/**
 * Immutable class representing Paillier public key.
 *
 * The attributes stored in the class are:
 * <ul>
 *     <li> n: the first parameter of the public key </li>
 *     <li> g: the second parameter of the public key </li>
 *     <li> maxInt: the maximum number that can be encrypted using this public key </li>
 *     <li> n<sup>2</sup>: the square of n, that is often used in Paillier computation </li>
 * </ul>
 *
 * Besides storing Paillier public key, the class contains the encryption method for input data of type double, long
 * and BigInteger. It also provides a mean to obtain a random number that is safe to use with this public key.
 *
 * Examples:
 * <ul>
 *     <li>
 *         To encrypt a long, <code>numLong</code>, using PaillierPublicKey, <code>publicKey</code>:
 *         <br>
 *         <code>EncryptedNumber encryptedNumber = publicKey.encrypted(numLong);</code>
 *     </li>
 *     <li>
 *         To encrypt a long, <code>numLong</code>, with a specified random number, <code>random</code>, to obfuscate
 *         the resulting EncryptedNumber, using PaillierPublicKey, <code>publicKey</code>:
 *         <br>
 *         <code>EncryptedNumber encryptedNumber = publicKey.encrypted(numLong, random);</code>
 *     </li>
 *     <li>
 *         To obtain a safe random number that can be used to obfuscate an EncryptedNumber:
 *         <code>BigInteger random = publicKey.getSafeRandom();</code>
 *     </li>
 * </ul>
 */
public final class PaillierPublicKey {

  protected final BigInteger modulus;
  protected final BigInteger modulusSquared;
  protected final BigInteger generator;

  public static interface Serializer {

    void serialize(BigInteger modulus);
  }

  /**
   * Construct a Paillier public key.
   * @param modulus Modules for key
   */
  public PaillierPublicKey(BigInteger modulus) {
    if (modulus == null) {
      throw new NullPointerException("modulus must not be null");
    }
    this.modulus = modulus;
    this.modulusSquared = modulus.multiply(modulus);
    //the generator is always set to modulus+1, as this allows a 
    //significantly more efficient encryption function.
    this.generator = modulus.add(BigInteger.ONE);
  }

  /**
   * Gets the public key, modulus.
   *
   * @return public key modulus.
   */
  public BigInteger getModulus() {
    return modulus;
  }

  /**
   * Gets modulus<sup>2</sup>.
   *
   * @return modulus<sup>2</sup>.
   */
  public BigInteger getModulusSquared() {
    return modulusSquared;
  }

  /**
   * Gets the public key generator.
   *
   * @return public key generator.
   */
  public BigInteger getGenerator() {
    return generator;
  }

  public void serialize(Serializer serializer) {
    serializer.serialize(modulus);
  }

  public PaillierContext createUnsignedContext() {
    return new PaillierContext(this, false, modulus.bitLength());
  }

  public PaillierContext createUnsignedContext(int precision)
          throws IllegalArgumentException {
    return new PaillierContext(this, false, precision);
  }

  public PaillierContext createSignedContext() {
    return new PaillierContext(this, true, modulus.bitLength());
  }

  public PaillierContext createSignedContext(int precision) {
    return new PaillierContext(this, true, precision);
  }
  
  public MockPaillierContext createMockUnsignedContext() {
    return new MockPaillierContext(this, false, modulus.bitLength());
  }

  public MockPaillierContext createMockUnsignedContext(int precision)
          throws IllegalArgumentException {
    return new MockPaillierContext(this, false, precision);
  }

  public MockPaillierContext createMockSignedContext() {
    return new MockPaillierContext(this, true, modulus.bitLength());
  }

  public MockPaillierContext createMockSignedContext(int precision) {
    return new MockPaillierContext(this, true, precision);
  }

  @Override
  public int hashCode() {
    return modulus.hashCode();
    // NOTE we don't need to hash modulusSquared or generator since they
    //      are uniquely determined by modulus
  }

  @Override
  public boolean equals(Object o) {
    return o == this || (o != null &&
            o.getClass() == PaillierPublicKey.class &&
            modulus.equals(((PaillierPublicKey) o).modulus));
    // NOTE we don't need to compare modulusSquared or generator since they
    //      are uniquely determined by modulus
  }

  public boolean equals(PaillierPublicKey o) {
    return o == this || (o != null && modulus.equals(o.modulus));
    // NOTE we don't need to compare modulusSquared or generator since they
    //      are uniquely determined by modulus
  }
}
