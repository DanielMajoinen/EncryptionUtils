package com.majoinen.d.encryption.pbe;

import com.majoinen.d.encryption.exception.EncryptionUtilsException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Builder class for Password Based Encryption Keys.
 *
 * @author Daniel Majoinen
 * @version 1.0, 25/7/17
 */
public class PBEKeyBuilder {

    public PBEKeyBuilder() {
        // Do nothing
    }

    /**
     * Set the password for the encryption key.
     *
     * @param password The password.
     * @return A PBEKeyBuilderWithPassword instance, which is ready to be
     * built or have optional parameters defined.
     */
    public PBEKeyBuilderWithPassword setPassword(char[] password) {
        return new PBEKeyBuilderWithPassword(password);
    }

    /**
     * Nested class which provides the ability to build the key and set
     * optional parameters.
     */
    public final class PBEKeyBuilderWithPassword extends PBEKeyBuilder {

        private final char[] password;
        private byte[] salt;
        private int iterations;
        private int keyLength;
        private String keyDerivationAlgorithm = "PBKDF2WithHmacSHA256";
        private String secretKeyAlgorithm = "AES";

        private PBEKeyBuilderWithPassword(char[] password) {
            this.password = password;
        }

        /**
         * Define a salt as a Base64 encoded String and iteration count.
         *
         * @param salt The salt to use.
         * @param iterations The iteration count.
         * @return This with the salt and iteration count set.
         */
        public PBEKeyBuilderWithPassword setSalt(String salt, int iterations) {
            return setSalt(Base64.getDecoder().decode(salt), iterations);
        }

        /**
         * Define a salt as a byte array and iteration count.
         *
         * @param salt The salt to use.
         * @param iterations The iteration count.
         * @return This with the salt and iteration count set.
         */
        public PBEKeyBuilderWithPassword setSalt(byte[] salt, int iterations) {
            this.salt = salt;
            this.iterations = iterations;
            return this;
        }

        /**
         * Optionally, set the key length of the desired encryption key.
         *
         * @param keyLength The key length.
         * @return This with the key length set.
         */
        public PBEKeyBuilderWithPassword setKeyLength(int keyLength) {
            this.keyLength = keyLength;
            return this;
        }

        /**
         * Optionally, set the key derivation algorithm. This is
         * PBKDF2WithHmacSHA256 by default.
         *
         * @param algorithm The algorithm to use.
         * @return This with the key derivation algorithm set.
         */
        public PBEKeyBuilderWithPassword setKeyDerivationAlgorithm(String
          algorithm) {
            this.keyDerivationAlgorithm = algorithm;
            return this;
        }

        /**
         * Optionally, set the SecretKeySpec algorithm. This is AES by default.
         *
         * @param algorithm The algorithm to use.
         * @return This with the SecretKeySpec algorithm set.
         */
        public PBEKeyBuilderWithPassword setSecretKeyAlgorithm(String
          algorithm) {
            this.secretKeyAlgorithm = algorithm;
            return this;
        }

        /**
         * Exit point of the builder. Creates the encryption key with the
         * provided parameters.
         *
         * @return An encryption key generated with the provided parameters.
         * @throws EncryptionUtilsException if an InvalidKeySpecException or
         * NoSuchAlgorithmException occurs when creating the key.
         */
        public SecretKey buildSecretKey() throws EncryptionUtilsException {
            PBEKeySpec spec = getKeySpec();
            SecretKeyFactory skf = getSecretKeyFactory();
            return new SecretKeySpec(generateSecret(skf, spec).getEncoded(),
              secretKeyAlgorithm);
        }

        /**
         * Create a PBEKeySpec using only parameters which have been set.
         *
         * @return an appropriate PBEKeySpec.
         */
        private PBEKeySpec getKeySpec() {
            PBEKeySpec spec;
            if(salt == null)
                spec = new PBEKeySpec(password);
            else if(keyLength == 0)
                spec = new PBEKeySpec(password, salt, iterations);
            else
                spec = new PBEKeySpec(password, salt, iterations, keyLength);
            return spec;
        }

        /**
         * Generate the SecretKey using the provided SecretKeyFactory and
         * PBEKeySpec, providing exception handling.
         * @param skf The SecretKeyFactory to use.
         * @param keySpec The PBEKeySpec to use.
         * @return The generated SecretKey.
         * @throws EncryptionUtilsException If an InvalidKeySpecException
         * occurs.
         */
        private SecretKey generateSecret(SecretKeyFactory skf, PBEKeySpec
          keySpec) throws EncryptionUtilsException {
            try {
                return skf.generateSecret(keySpec);
            } catch(InvalidKeySpecException e) {
                throw new EncryptionUtilsException("[EncryptionUtils] " +
                  "Error generating SecretKeySpec", e);
            }
        }

        /**
         * Get an instance of the appropriate SecretKeyFactory for the set
         * key derivation algorithm, providing exception handling.
         *
         * @return The appropriate SecretKeyFactory.
         * @throws EncryptionUtilsException If a NoSuchAlgorithmException
         * occurs.
         */
        private SecretKeyFactory getSecretKeyFactory()
          throws EncryptionUtilsException {
            try {
                return SecretKeyFactory.getInstance(keyDerivationAlgorithm);
            } catch(NoSuchAlgorithmException e) {
                throw new EncryptionUtilsException("[EncryptionUtils] " +
                  "Error getting SecretKeyFactory instance with algorithm: " +
                  keyDerivationAlgorithm, e);
            }
        }
    }
}
