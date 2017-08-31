package com.majoinen.d.encryption.utils;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Misc. tools utilised by the encryption library.
 *
 * @author Daniel Majoinen
 * @version 1.0, 15/7/17
 */
public final class Tools {

    public static final String ALPHA_NUMERIC =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private static final String DELIMITER = ":";

    private static SecureRandom random = new SecureRandom();

    private Tools() { }

    /**
     * Randomly generate a number between the two values.
     *
     * @param min The minimum possible value.
     * @param max The maximum possible value.
     * @return A value between the provided min and max.
     */
    public static int rng(int min, int max) {
        return ThreadLocalRandom.current().nextInt(min, max + 1);
    }

    /**
     * Encodes an array of bytes into a Base64 String. If there are more than
     * one arrays supplied as parameters, the encoded strings will be
     * concatenated together with a ":" as a delimiter.
     *
     * @param bytes An array of bytes to encode into Base64.
     * @return The arrays encoded as a Base64 String.
     */
    public static String encodeBase64(byte[]... bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        int lastIndex = bytes.length - 1;
        for (int i = 0; i < lastIndex; i++) {
            stringBuilder
              .append(Base64.getEncoder().encodeToString(bytes[i]))
              .append(DELIMITER);
        }
        return stringBuilder
          .append(Base64.getEncoder().encodeToString(bytes[lastIndex]))
          .toString();
    }

    /**
     * Decodes a Base64 String into an array of bytes.
     * @param input The string to decode.
     * @return The supplied String decoded into an array of bytes.
     */
    public static byte[] decodeBase64(String input) {
        return Base64.getDecoder().decode(input);
    }

    /**
     * Generate a set size byte array of random bytes.
     *
     * @param size The size of the array to generate.
     * @return An array of random bytes.
     */
    public static byte[] generateRandomBytes(int size) {
        byte[] salt = new byte[size];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Generate a random String at the desired length
     *
     * @param length Desired length of random string.
     * @param chars String of all possible characters.
     * @return The randomly generated string.
     */
    public static String generateRandomString(int length, String chars) {
        StringBuilder stringBuilder = new StringBuilder(length);
        for( int i = 0; i < length; i++ )
            stringBuilder.append(chars.charAt(random.nextInt(chars.length())));
        return stringBuilder.toString();
    }

    /**
     * Clean an array of characters, making each element 0.
     */
    public static void clean(char[]... chars) {
        for(char[] c : chars)
            Arrays.fill(c, '0');
    }

    /**
     * Clean an array of bytes, making each element 0.
     */
    public static void clean(byte[]... bytes) {
        for(byte[] b : bytes)
            Arrays.fill(b, (byte) '0');
    }
}
