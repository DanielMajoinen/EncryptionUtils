package com.majoinen.d.encryption.exception;

/**
 * Parent exception class for all EncryptionUtils exceptions.
 *
 * @author Daniel Majoinen
 * @version 1.0, 15/7/17
 */
public class EncryptionUtilsException extends Exception {
    public EncryptionUtilsException() { }

    public EncryptionUtilsException(String message) {
        super(message);
    }

    public EncryptionUtilsException(Exception e) {
        super(e);
    }

    public EncryptionUtilsException(String message, Exception e) {
        super(message, e);
    }
}
