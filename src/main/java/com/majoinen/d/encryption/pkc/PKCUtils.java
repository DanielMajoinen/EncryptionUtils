package com.majoinen.d.encryption.pkc;

import com.majoinen.d.encryption.exception.EncryptionUtilsException;
import com.majoinen.d.encryption.utils.Tools;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Public Key Cryptography Utilities.
 *
 * @author Daniel Majoinen
 * @version 1.0, 30/8/17
 */
public class PKCUtils {

    private static final String DELIMITER = ":";

    private static final int MODULUS_INDEX = 0;

    private static final int EXPONENT_INDEX = 1;

    private static final String ALGORITHM_RSA = "RSA";

    private PKCUtils() { }

    public static String serializeRSAPrivateKey(RSAPrivateKey key) {
        String modulus = Tools.encodeBase64(
          key.getModulus().toByteArray());
        String exponent = Tools.encodeBase64(
          key.getPrivateExponent().toByteArray());
        return modulus + DELIMITER + exponent;
    }

    public static PrivateKey deserializeRSAPrivateKey(String key)
      throws EncryptionUtilsException {
        String[] parts = key.split(DELIMITER);
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(
          new BigInteger(Tools.decodeBase64(parts[MODULUS_INDEX])),
          new BigInteger(Tools.decodeBase64(parts[EXPONENT_INDEX])));
        try {
            return KeyFactory.getInstance(ALGORITHM_RSA).generatePrivate(spec);
        } catch(NoSuchAlgorithmException e) {
            throw new EncryptionUtilsException(
              "Error getting KeyFactory instance", e);
        } catch(InvalidKeySpecException e) {
            throw new EncryptionUtilsException(
              "Unable to deserialize public key", e);
        }
    }

    public static String serializeRSAPublicKey(RSAPublicKey key) {
        String modulus = Tools.encodeBase64(
          key.getModulus().toByteArray());
        String exponent = Tools.encodeBase64(
          key.getPublicExponent().toByteArray());
        return modulus + DELIMITER + exponent;
    }

    public static PublicKey deserializeRSAPublicKey(String key)
      throws EncryptionUtilsException {
        String[] parts = key.split(DELIMITER);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
          new BigInteger(Tools.decodeBase64(parts[MODULUS_INDEX])),
          new BigInteger(Tools.decodeBase64(parts[EXPONENT_INDEX])));
        try {
            return KeyFactory.getInstance(ALGORITHM_RSA).generatePublic(spec);
        } catch(NoSuchAlgorithmException e) {
            throw new EncryptionUtilsException(
              "Error getting KeyFactory instance", e);
        } catch(InvalidKeySpecException e) {
            throw new EncryptionUtilsException(
              "Unable to deserialize public key", e);
        }
    }

    public static String sign(String algorithm, PrivateKey key, byte[] data)
      throws EncryptionUtilsException {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(key);
            signature.update(data);
            return Tools.encodeBase64(signature.sign());
        } catch(NoSuchAlgorithmException e) {
            throw new EncryptionUtilsException(
              "Error getting Signature instance", e);
        } catch(InvalidKeyException e) {
            throw new EncryptionUtilsException(
              "Error initialising signature with provided key", e);
        } catch(SignatureException e) {
            throw new EncryptionUtilsException(
              "Error signing provided data", e);
        }
    }

    public static boolean verifyBase64Signature(String algorithm, PublicKey key,
      String signatureToVerify, String data) throws EncryptionUtilsException {
        return verifySignature(algorithm, key, Tools.decodeBase64(
          signatureToVerify), data.getBytes());
    }

    public static boolean verifyBase64Signature(String algorithm, PublicKey key,
      String signatureToVerify, byte[] data) throws EncryptionUtilsException {
        return verifySignature(algorithm, key, Tools.decodeBase64(
          signatureToVerify), data);
    }

    public static boolean verifySignature(String algorithm, PublicKey key,
      byte[] signatureToVerify, byte[] data) throws EncryptionUtilsException {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(key);
            signature.update(data);
            return signature.verify(signatureToVerify);
        } catch(NoSuchAlgorithmException e) {
            throw new EncryptionUtilsException(
              "Error getting Signature instance", e);
        } catch(InvalidKeyException e) {
            throw new EncryptionUtilsException(
              "Error initialising signature with provided key", e);
        } catch(SignatureException e) {
            throw new EncryptionUtilsException(
              "Error verifying signature", e);
        }
    }

}
