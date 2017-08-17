EncryptionUtils
---
EncryptionUtils is an encryption library providing easy-to-use encryption and decryption. Currently it's main use is with password based encryption, utilised in PwCrypt.

Usage
---
Generate a random encryption key:

    /* Generate a random encryption key */
    SecretKey dataKey = EncryptionKeyGenerator.generateRandomKey("AES", KEY_LENGTH);

Generate randomised parameters, such as IV, Salt and iterations:

    /* Generate IV, salts & iterations */
    byte[] salt = Tools.generateRandomBytes(SALT_SIZE);
    byte[] iv = Tools.generateRandomBytes(INIT_VECTOR_SIZE);
    int iterations = Tools.rng(MIN_ITERATIONS, MAX_ITERATIONS);
    
Derive encryption key (Java 1.8):

    /* Derive encryption key */
    SecretKey dataKeyEncryptionKey = new PBEKeyBuilder()
      .setPassword(password)
      .setSalt(salt, iterations)
      .setKeyLength(KEY_LENGTH)
      .buildSecretKey();

Derive encryption key (Bouncy Castle):

    /* Derive encryption key */
    SecretKey encryptionKey = new BCPBEKeyBuilder()
      .setPassword(password)
      .setSalt(salt, iterations)
      .setKeyLength(KEY_LENGTH)
      .buildSecretKey();

Encrypt something:

    /* Use encryptionKey to encrypt data */
    byte[] encryptedData = Cipher.encrypt(data, iv, encryptionKey, "AES/CBC/PKCS5Padding");

Decrypt something:

    /* Use encryptionKey to decrypt data */
    byte[] decryptedData = Cipher.decrypt(data, iv, encryptionKey, "AES/CBC/PKCS5Padding");
