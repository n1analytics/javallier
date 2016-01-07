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

import static com.n1analytics.paillier.util.BigIntegerUtil.randomPositiveNumber;

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
  
  /**
   * Implements the encryption function of the Paillier encryption scheme.
   * @param plaintext to be encrypted.
   * @return corresponding ciphertext.
   */
  public BigInteger raw_encrypt(BigInteger plaintext){
    return raw_obfuscate(raw_encrypt_without_obfuscation(plaintext));
  }
  
  /**
   * The encryption function of the Paillier encryption scheme can be divided into 
   * two parts:
   *  - The first part, as implemented here, maps the plaintext into the encrypted space.
   *    But be aware, that this function is invertible, that is, the ciphertext is not yet 
   *    secure.
   *  - Only after the second part, the 'raw_obfuscate' function, the ciphertext is secure 
   *    and the corresponding plaintext can't be recovered without the secret key.
   * The reason we split the encryption is that the second part is computationally significantly
   * more expensive than the first part and since the obfuscation has to be done only once
   * before you can securely share the generated ciphertext, there are scenarios, where
   * obfuscating at encryption is unnecessary. 
   *  
   * @param plaintext to be encrypted.
   * @return corresponding unobfuscated ciphertext.
   */
  public BigInteger raw_encrypt_without_obfuscation(BigInteger plaintext){
    return modulus.multiply(plaintext).add(BigInteger.ONE).mod(modulusSquared);
  }
  
  /**
   * Implements the obfuscation function of the Paillier encryption scheme.
   * It changes the value of a ciphertext without changing the corresponding plaintext.
   * @param ciphertext to be ofuscated
   * @return obfuscated ciphertext.
   */
  public BigInteger raw_obfuscate(BigInteger ciphertext) {
    return randomPositiveNumber(modulus).modPow(modulus, modulusSquared).multiply(ciphertext).mod(modulusSquared);
  }
  
  /**
   * Implements the addition function of two ciphertexts of the Paillier encryption scheme.
   * @param ciphertext1
   * @param ciphertext2
   * @return ciphertext of the sum of the two plaintexts corresponding to ciphertext1 and 2.
   */
  public BigInteger raw_add(BigInteger ciphertext1, BigInteger ciphertext2){
    return ciphertext1.multiply(ciphertext2).mod(modulusSquared);
  }
  
  /**
   * Implements the multiplication function of the Paillier encryption scheme.
   * In the Paillier scheme you can only multiply an unencrypted value with an encrypted value.
   * @param ciphertext of factor a
   * @param plainfactor b
   * @return product a*b
   */
  public BigInteger raw_multiply(BigInteger ciphertext, BigInteger plainfactor){
    return ciphertext.modPow(plainfactor, modulusSquared);
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
