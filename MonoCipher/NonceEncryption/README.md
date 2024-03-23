# Nonce Encryption

This Python code demonstrates encryption and decryption using the ChaCha20-Poly1305 authenticated encryption algorithm. It utilizes modules from the `Crypto` package of the `pycryptodome` library. Below is a breakdown of the code's functionality:

1. **Importing Necessary Modules:**

   - The code imports modules for key derivation, random byte generation, and the ChaCha20-Poly1305 cipher.

2. **Key Generation (`generate_key` function):**

   - The `generate_key` function derives a key using the scrypt key derivation function from a password and a salt.

3. **Encryption (`nonce_encrypt` function):**

   - The `nonce_encrypt` function takes a message and a password as input.
   - It generates a salt, derives a key, and generates a nonce.
   - The message is encrypted using the ChaCha20-Poly1305 cipher.
   - The ciphertext and authentication tag are returned as base64-encoded strings along with the salt and nonce.

4. **Decryption (`nonce_decrypt` function):**

   - The `nonce_decrypt` function takes a salt, nonce, ciphertext, tag, and password as input.
   - It decodes the base64-encoded inputs and derives a key.
   - The ciphertext is decrypted and authenticated using the ChaCha20-Poly1305 cipher.
   - The decrypted message is returned, or an error message if decryption fails.

5. **Example Usage (Commented Out):**
   - Example usage demonstrates encryption and decryption of a sample message with a password. It encrypts the message, prints the salt, nonce, ciphertext, and authentication tag, then decrypts the ciphertext and prints the decrypted message.

```python
message = "Hello, World!"
password = "MySecretPassword"

salt, nonce, ciphertext, tag = nonce_encrypt(message, password)
print("Salt:", salt)
print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Tag:", tag)

decrypted_message = nonce_decrypt(salt, nonce, ciphertext, tag, password)
print("Decrypted message:", decrypted_message)
```

This code provides a secure method for encrypting and decrypting messages using the ChaCha20-Poly1305 authenticated encryption algorithm. It's essential to handle passwords and keys securely to maintain the security of the encryption scheme.
