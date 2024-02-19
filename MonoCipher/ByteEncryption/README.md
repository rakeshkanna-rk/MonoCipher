# Byte Encryption

This Python code utilizes the `Crypto.Cipher` module from the `pycryptodome` library to perform AES encryption and decryption in Cipher Block Chaining (CBC) mode. Below is a breakdown of how the code works and what each part does:

1. **Importing Necessary Modules:**
   - The code imports specific modules from the `Crypto` package (`AES` cipher, random byte generator, and padding utilities) as well as the `base64` module for encoding and decoding binary data as ASCII strings.

2. **Encryption Function `byte_encrypt(message, keys)`:**
   - This function takes a `message` and an `AES key` as input.
   - It creates an AES cipher object using the provided key in CBC mode.
   - The message is then padded to match the AES block size using PKCS7 padding (implemented by the `pad` function).
   - A random Initialization Vector (IV) is generated internally by the AES cipher object.
   - The message is encrypted using the AES cipher object, and the resulting ciphertext is returned along with the base64-encoded IV.

3. **Decryption Function `byte_decrypt(iv, ciphertext, password)`:**
   - This function takes an `IV`, a `ciphertext`, and an `AES key` as input.
   - The IV and ciphertext are base64-decoded to obtain their binary representations.
   - An AES cipher object is created using the provided key and IV in CBC mode.
   - The ciphertext is decrypted using the AES cipher object.
   - The decrypted message is unpadded using PKCS7 unpadding (implemented by the `unpad` function), and then it's decoded from bytes to a UTF-8 string.
   - The decrypted message is returned.

4. **Example Usage (Commented Out):**
   - Example usage of the encryption and decryption functions is provided but commented out. It demonstrates how to encrypt a message, obtain the IV and ciphertext, and then decrypt the ciphertext back to the original message using the IV and the same key.
  
```python
message = "Hello, World!"
password = "MySecretPassword"

iv, ciphertext = byte_encrypt(message, password)
print("IV:", iv)
print("Ciphertext:", ciphertext)

decrypted_message = byte_decrypt(iv, ciphertext, password)
print("Decrypted message:", decrypted_message)
```
This code provides a basic framework for AES encryption and decryption using Python and the `pycryptodome` library. It's important to handle keys securely, as the security of the encryption relies heavily on the secrecy of the key.