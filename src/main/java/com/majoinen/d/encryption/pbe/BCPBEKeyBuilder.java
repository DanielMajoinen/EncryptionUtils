package com.majoinen.d.encryption.pbe;

import com.majoinen.d.encryption.exception.EncryptionUtilsException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Builder class for Password Based Encryption Keys using Bouncy Castle.
 *
 * @author Daniel Majoinen
 * @version 1.0, 25/7/17
 */
public class BCPBEKeyBuilder {

    public BCPBEKeyBuilder() {
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
    public final class PBEKeyBuilderWithPassword extends BCPBEKeyBuilder {

        private final char[] password;
        private byte[] salt;
        private int iterations;
        private int keyLength = 256;

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
         * Exit point of the builder. Creates the encryption key with the
         * provided parameters, using Bouncy Castle.
         *
         * @return An encryption key generated with the provided parameters.
         * @throws EncryptionUtilsException if an InvalidKeySpecException or
         * NoSuchAlgorithmException occurs when creating the key.
         */
        public SecretKey buildSecretKey() throws EncryptionUtilsException {
            if(salt == null)
                throw new EncryptionUtilsException("Missing salt/iterations");
            PKCS5S2ParametersGenerator generator =
              new PKCS5S2ParametersGenerator(new SHA256Digest());
            generator.init(PBEParametersGenerator
              .PKCS5PasswordToUTF8Bytes(password), salt, iterations);
            byte[] derivedKey = ((KeyParameter) generator
              .generateDerivedParameters(keyLength)).getKey();
            return new SecretKeySpec(derivedKey, 0, derivedKey.length, "AES");
        }
    }
}
