package com.majoinen.d.encryption.utils;

import com.majoinen.d.encryption.exception.EncryptionUtilsException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * Randomly generate an encryption key.
 *
 * @author Daniel Majoinen
 * @version 1.0, 23/7/17
 */
public final class EncryptionKeyGenerator {

    private static SecureRandom random = new SecureRandom();

    private EncryptionKeyGenerator() { }

    /**
     * Generate a random key using the supplied algorithm and key length.
     *
     * @param algorithm The algorithm to use.
     * @param keyLength The length of the key to generate.
     * @return A randomly generated SecretKey using the provided algorithm.
     * @throws EncryptionUtilsException If a NoSuchAlgorithmException occurs
     * when generating the key.
     */
    public static SecretKey generateRandomKey(String algorithm, int keyLength)
      throws EncryptionUtilsException {
        KeyGenerator keyGen = getKeyGenerator(algorithm);
        keyGen.init(keyLength, random);
        return new SecretKeySpec(keyGen.generateKey().getEncoded(), algorithm);
    }

    /**
     * Get an instance of a KeyGenerator for the supplied algorithm.
     * Providing exception handling.
     *
     * @param algorithm The algorithm to use.
     * @return An instance of a KeyGenerator for the supplied algorithm.
     * @throws EncryptionUtilsException If a NoSuchAlgorithmException occurs
     * when generating the key.
     */
    private static KeyGenerator getKeyGenerator(String algorithm)
      throws EncryptionUtilsException {
        try {
            return KeyGenerator.getInstance(algorithm);
        } catch(NoSuchAlgorithmException e) {
            throw new EncryptionUtilsException("[EncryptionUtils] " +
              "Error getting EncryptionKeyGenerator instance", e);
        }
    }

    /**
     * Generate a random key pair using the supplied algorithm and key length.
     *
     * @param algorithm The algorithm to use.
     * @param keyLength The length of the keys to generate.
     * @return A randomly generated KeyPair using the provided algorithm.
     * @throws EncryptionUtilsException If a NoSuchAlgorithmException occurs
     * when generating the key, or if NoSuchProviderException occurs.
     */
    public static KeyPair generateKeyPair(String algorithm, int keyLength)
      throws EncryptionUtilsException {
        KeyPairGenerator keyGen = getKeyPairGenerator(algorithm);
        keyGen.initialize(keyLength, random);
        return keyGen.generateKeyPair();
    }

    /**
     * Get an instance of a KeyPairGenerator for the supplied algorithm.
     * Providing exception handling.
     *
     * @param algorithm The algorithm to use.
     * @return An instance of a KeyPairGenerator for the supplied algorithm.
     * @throws EncryptionUtilsException If a NoSuchAlgorithmException occurs
     * when generating the key, or if NoSuchProviderException occurs.
     */
    private static KeyPairGenerator getKeyPairGenerator(String algorithm)
      throws EncryptionUtilsException {
        try {
            return KeyPairGenerator.getInstance(algorithm);
        } catch(NoSuchAlgorithmException e) {
            throw new EncryptionUtilsException("[EncryptionUtils] " +
              "Error getting EncryptionKeyPairGenerator instance", e);
        }
    }
}
