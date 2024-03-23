# HMAC Encryption

This Python code implements encryption and decryption using AES-CBC with HMAC authentication. It leverages modules from the `Crypto` package of the `pycryptodome` library. Below is a breakdown of the code's functionality:

1. **Importing Necessary Modules:**

   - The code imports modules for key derivation, random byte generation, AES encryption, HMAC authentication, SHA256 hashing, and base64 encoding/decoding.

2. **Key Generation (`generate_key` function):**

   - The `generate_key` function derives a key using the scrypt key derivation function from a password and a salt.

3. **IV Generation (`generate_iv` function):**

   - The `generate_iv` function generates a random 16-byte Initialization Vector (IV).

4. **Encryption (`hmac_encrypt` function):**

   - The `hmac_encrypt` function takes a message and a password as input.
   - It generates a salt, derives a key, and generates an IV.
   - The message is encrypted using AES-CBC.
   - An HMAC digest is computed using the encrypted ciphertext.
   - The salt, IV, ciphertext, and HMAC digest are returned as base64-encoded strings.

5. **Decryption (`hmac_decrypt` function):**

   - The `hmac_decrypt` function takes a salt, IV, ciphertext, HMAC digest, and password as input.
   - It decodes the base64-encoded inputs and derives a key.
   - It verifies the HMAC digest for authentication.
   - The ciphertext is decrypted using AES-CBC.
   - The decrypted message is returned, or an error message if decryption fails.

6. **Example Usage (Commented Out):**
   - Example usage demonstrates encryption and decryption of a sample message with a password. It encrypts the message, prints the salt, IV, ciphertext, and HMAC digest, then decrypts the ciphertext and prints the decrypted message.

```python
message = "Hello, World!"
password = "MySecretPassword"

salt, iv, ciphertext, hmac_digest = hmac_encrypt(message, password)
print("Salt:", salt)
print("IV:", iv)
print("Ciphertext:", ciphertext)
print("HMAC Digest:", hmac_digest)

decrypted_message = hmac_decrypt(salt, iv, ciphertext, hmac_digest, password)
print("Decrypted message:", decrypted_message)
```

This code provides a secure method for encrypting and decrypting messages while ensuring integrity using HMAC authentication. It's essential to handle passwords and keys securely to maintain the security of the encryption scheme.
