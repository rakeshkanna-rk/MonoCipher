# Message Authentication Code (MAC) Encryption with AES-GCM

This Python code implements message encryption and decryption using the AES-GCM (Galois/Counter Mode) authenticated encryption algorithm. Below is an explanation of the code's components and how they work:

1. **Importing Necessary Modules:**
   - The code imports required modules from the `Crypto` package, including `scrypt` for key derivation, `get_random_bytes` for generating random bytes, `AES` cipher from `Crypto.Cipher`, and `base64` for encoding and decoding binary data.

2. **MacEncryption Class:**
   - This class encapsulates the encryption and decryption functionality.
   - The `__init__` method initializes the object with a password. It generates a random salt and derives a master key using the provided password and salt.
   - The `derive_master_key` method uses the `scrypt` key derivation function to generate a master key.
   - The `generate_nonce` method creates a random 12-byte nonce.
   - The `mac_encrypt` method encrypts a message using AES-GCM. It generates a nonce, initializes an AES cipher in GCM mode with the master key and nonce, encrypts the message, and computes the authentication tag.
   - The `mac_decrypt` method decrypts a ciphertext. It decodes the input parameters, initializes an AES cipher in GCM mode with the master key and nonce, decrypts the ciphertext, and verifies the authentication tag.

3. **Example Usage (Commented Out):**
   - The commented-out example demonstrates how to use the `MacEncryption` class to encrypt and decrypt a message.
   - It initializes the `MacEncryption` object with a password, encrypts a message, and then decrypts the ciphertext to obtain the original message.

```python
password = "MySecretPassword"
message = "Hello, World!"

# Encryption
salt, nonce, ciphertext, tag = mac_encrypt(message)
print("Salt:", salt)
print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Tag:", tag)

# Decryption
decrypted_message = mac_decrypt(salt, nonce, ciphertext, tag)
print("Decrypted message:", decrypted_message)
```

This code provides a secure way to encrypt and decrypt messages using AES-GCM with a provided password. It's important to securely handle passwords and keys to maintain the security of the encryption scheme.
