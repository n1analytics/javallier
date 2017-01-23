package com.n1analytics.paillier;


import java.math.BigInteger;
import java.util.logging.Logger;



public class MockPaillierPublicKey extends PaillierPublicKey {

    private static Logger logger = Logger.getLogger("com.n1analytics.paillier");

    public MockPaillierPublicKey(BigInteger modulus) {
        super(modulus);
        logger.warning("You've created a MockPaillierPublicKey. Are you sure? This is NOT secure/private! There won't be any actual encryption.");
    }

    /* in mocking mode we don't actually do any encryption. we stay in the plaintext space. */
    @Override
    public BigInteger raw_encrypt_without_obfuscation(BigInteger plaintext){
        return plaintext;
    }

    @Override
    public BigInteger raw_obfuscate(BigInteger ciphertext) {
        return ciphertext;
    }

    @Override
    public BigInteger raw_add(BigInteger ciphertext1, BigInteger ciphertext2){
        return ciphertext1.add(ciphertext2).mod(modulusSquared);
    }

    @Override
    public BigInteger raw_multiply(BigInteger ciphertext, BigInteger plainfactor){
        return ciphertext.multiply(plainfactor).mod(modulusSquared);
    }

    @Override
    public boolean equals(Object other) {
        return other == this || (other != null &&
                other.getClass() == MockPaillierPublicKey.class &&
                modulus.equals(((MockPaillierPublicKey) other).modulus));
    }
}
