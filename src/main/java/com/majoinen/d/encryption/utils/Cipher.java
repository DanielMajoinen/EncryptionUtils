package com.majoinen.d.encryption.utils;

import com.majoinen.d.encryption.exception.EncryptionUtilsException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * Encrypt or Decrypt a byte array.
 *
 * @author Daniel Majoinen
 * @version 1.0, 28/7/17
 */
public final class Cipher {

    private static final String EXCEPTION_PREFIX = "[EncryptionUtils] ";

    private Cipher() { }

    /**
     * Encrypt the supplied input with the supplied encryption key, using the
     * supplied encryption algorithm.
     *
     * @param input The input to encrypt.
     * @param initVector The initialization vector to use with the cipher.
     * @param key The encryption key to use.
     * @param algorithm The encryption algorithm to use.
     * @return The input data encrypted, or null if a BadPaddingException
     * occurs.
     * @throws EncryptionUtilsException If any exception occurs during the
     * encryption process.
     */
    public static byte[] encrypt(byte[] input, byte[] initVector,
      SecretKey key, String algorithm) throws EncryptionUtilsException {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        javax.crypto.Cipher cipher = getCipherInstance(algorithm);
        initCipher(cipher, javax.crypto.Cipher.ENCRYPT_MODE, key, iv);
        return doFinal(cipher, input);
    }

    /**
     * Encrypt the supplied input with the supplied Public Key, using the
     * supplied encryption algorithm.
     *
     * @param input The input to encrypt.
     * @param key The Public Key to use.
     * @param algorithm The encryption algorithm to use.
     * @return The input data encrypted, or null if a BadPaddingException
     * occurs.
     * @throws EncryptionUtilsException If any exception occurs during the
     * encryption process.
     */
    public static byte[] encrypt(byte[] input, PublicKey key, String algorithm)
      throws EncryptionUtilsException {
        javax.crypto.Cipher cipher = getCipherInstance(algorithm);
        initCipher(cipher, javax.crypto.Cipher.ENCRYPT_MODE, key);
        return doFinal(cipher, input);
    }

    /**
     * Decrypt the supplied input with the supplied encryption key, using the
     * supplied encryption algorithm.
     *
     * @param input The input to decrypt.
     * @param initVector The initialization vector to use with the cipher.
     * @param key The encryption key used when the input data was encrypted.
     * @param algorithm The encryption algorithm to used when the input data
     * was encrypted.
     * @return The input data decrypted, or null if a BadPaddingException
     * occurs.
     * @throws EncryptionUtilsException If any exception occurs during the
     * decryption process.
     */
    public static byte[] decrypt(byte[] input, byte[] initVector,
      SecretKey key, String algorithm) throws EncryptionUtilsException {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        javax.crypto.Cipher cipher = getCipherInstance(algorithm);
        initCipher(cipher, javax.crypto.Cipher.DECRYPT_MODE, key, iv);
        return doFinal(cipher, input);
    }

    /**
     * Decrypt the supplied input with the supplied Private Key, using the
     * supplied algorithm. Used with asymmetric encryption.
     *
     * @param input The input to decrypt.
     * @param key The Private Key to decrypt the data with.
     * @param algorithm The encryption algorithm to used when the input data
     * was encrypted.
     * @return The input data decrypted, or null if a BadPaddingException
     * occurs.
     * @throws EncryptionUtilsException If any exception occurs during the
     * decryption process.
     */
    public static byte[] decrypt(byte[] input, PrivateKey key, String algorithm)
      throws EncryptionUtilsException {
        javax.crypto.Cipher cipher = getCipherInstance(algorithm);
        initCipher(cipher, javax.crypto.Cipher.DECRYPT_MODE, key);
        return doFinal(cipher, input);
    }

    /**
     * Get a Cipher instance for the supplied algorithm.
     *
     * @param algorithm The desired ciphers algorithm.
     * @return A Cipher instance for the supplied algorithm.
     * @throws EncryptionUtilsException if a NoSuchAlgorithmException or
     * NoSuchPaddingException occurs.
     */
    private static javax.crypto.Cipher getCipherInstance(String algorithm)
      throws EncryptionUtilsException {
        try {
            return javax.crypto.Cipher.getInstance(algorithm);
        } catch(NoSuchAlgorithmException e) {
            throw new EncryptionUtilsException(EXCEPTION_PREFIX +
              "No such algorithm: " + algorithm, e);
        } catch(NoSuchPaddingException e) {
            throw new EncryptionUtilsException(EXCEPTION_PREFIX +
              "No such padding with algorithm: " + algorithm, e);
        }
    }

    /**
     * Initialize the cipher into the supplied mode, with the supplied key
     * and initialization vector.
     *
     * @param cipher The cipher to initialize.
     * @param mode The mode in which to initialize it to.
     * @param key The encryption key.
     * @param iv The initialization vector.
     * @throws EncryptionUtilsException If an InvalidKeyException or
     * InvalidAlgorithmParameterException occurs during the initialization
     * process.
     */
    private static void initCipher(javax.crypto.Cipher cipher, int mode,
      SecretKey key, IvParameterSpec iv) throws EncryptionUtilsException {
        try {
            cipher.init(mode, key, iv);
        } catch(InvalidKeyException e) {
            throw new EncryptionUtilsException(EXCEPTION_PREFIX +
              "Invalid Key while encrypting", e);
        } catch(InvalidAlgorithmParameterException e) {
            throw new EncryptionUtilsException(EXCEPTION_PREFIX +
              "Invalid algorithm parameter", e);
        }
    }

    /**
     * Initialize the cipher into the supplied mode, with the supplied key.
     * Used with asymmetric encryption.
     *
     * @param cipher The cipher to initialize.
     * @param mode The mode in which to initialize it to.
     * @param key The encryption key.
     * @throws EncryptionUtilsException If an InvalidKeyException or
     * InvalidAlgorithmParameterException occurs during the initialization
     * process.
     */
    private static void initCipher(javax.crypto.Cipher cipher, int mode,
      Key key) throws EncryptionUtilsException {
        try {
            cipher.init(mode, key);
        } catch(InvalidKeyException e) {
            throw new EncryptionUtilsException(EXCEPTION_PREFIX +
              "Invalid Key while encrypting", e);
        }
    }

    /**
     * Apply the encryption or decryption.
     *
     * @param cipher The cipher.
     * @param input The subject of encryption/decryption.
     * @return The result of the encryption/decryption, or null if a
     * BadPaddingException occurs.
     * @throws EncryptionUtilsException If an IllegalBlockSizeException occurs.
     */
    private static byte[] doFinal(javax.crypto.Cipher cipher, byte[] input)
      throws EncryptionUtilsException {
        try {
            return cipher.doFinal(input);
        } catch(IllegalBlockSizeException e) {
            throw new EncryptionUtilsException(EXCEPTION_PREFIX +
              "Illegal block size while encrypting", e);
        } catch(BadPaddingException e) {
            return new byte[0];
        }
    }

}
