package com.majoinen.d.encryption.pbe;

import com.majoinen.d.encryption.exception.EncryptionUtilsException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * @author Daniel Majoinen
 * @version 1.0, 25/7/17
 */
public final class PasswordHasher {

    // Set the default key length
    private static final int DEFAULT_KEY_LENGTH = 256;

    // Set the default hashing algorithm
    private static final String DEFAULT_ALGORITHM = "PBKDF2WithHmacSHA256";

    private PasswordHasher() { }

    /**
     * Hash a supplied password with a supplied salt for the supplied iterations
     * using the default key length and default algorithm.
     *
     * @param password The password to hash.
     * @param salt The salt to use when hashing.
     * @param iterations The amount of iterations to hash.
     * @return The hashed output of the password.
     * @throws EncryptionUtilsException If a NoSuchAlgorithmException or
     * InvalidKeySpecException occurs during the hashing process.
     */
    public static byte[] hash(char[] password, byte[] salt, int iterations)
      throws EncryptionUtilsException {
        return hash(password, salt, iterations, DEFAULT_KEY_LENGTH,
          DEFAULT_ALGORITHM);
    }

    /**
     * Hash a supplied password, providing a salt, iteration count, key length
     * and algorithm to use.
     *
     * @param password The password to hash.
     * @param salt The salt to use when hashing.
     * @param iterations The amount of iterations to hash the password.
     * @param keyLength The key length of the encryption key.
     * @param algorithm The algorithm to use when hashing.
     * @return The hashed output of the password.
     * @throws EncryptionUtilsException If a NoSuchAlgorithmException or
     * InvalidKeySpecException occurs during the hashing process.
     */
    public static byte[] hash(char[] password, byte[] salt, int iterations,
      int keyLength, String algorithm) throws EncryptionUtilsException {
        KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
            return skf.generateSecret(keySpec).getEncoded();
        } catch(NoSuchAlgorithmException e) {
            throw new EncryptionUtilsException("[EncryptionUtils] " +
              "No such algorithm: " + algorithm, e);
        } catch(InvalidKeySpecException e) {
            throw new EncryptionUtilsException("[EncryptionUtils] " +
              "Invalid KeySpec when hashing", e);
        }
    }
}
