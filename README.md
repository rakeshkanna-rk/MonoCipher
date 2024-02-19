![MonoCipher](MonoCipher.png)
  
# MonoCipher
**MonoCipher is python programmed package which allow users to encrypt and decrypt messages in three different levels**  
1. **Simple Cryption with Shift number**  
2. **Byte Cryption with an advance method of encryption and decryption with Initialization Vector (IV) and Cipher Text. [more on IV](https://en.wikipedia.org/wiki/Initialization_vector)**  
3. **Salt Cryption with advance method of encryption and decryption with Initialization Vector (IV), Cipher Text, Password and salt. [more on salt](https://en.wikipedia.org/wiki/Salt_(cryptography)#:~:text=In%20cryptography%2C%20a%20salt%20is,needed%20for%20a%20successful%20attack.)**  

### The core module used in the project is [pycryptodome](https://pypi.org/project/pycryptodome/)

### To Use This Module
```terminal
pip install MonoCipher
```
## Features
  
### Simple Encryption
- **This function encrypts decrypts message using shift method**  
- **This function takes an input of message and shift number | `shift_encrypt(message, shift)`**  
**For Decrypting the message the function takes as same | `shift_encrypt(message, shift)`**
  
### Byte Encryption  
- **This encryption works in an advance method of encryption and decryption with Initialization Vector (IV) and Cipher Text. [more on IV](https://en.wikipedia.org/wiki/Initialization_vector)**  
- **This function takes an input of Message and Password and returns VI and Cipher Text | `byte_encrypt(message, password)`**  
- **For Decrypting the message the function takes VI, Cipher Text, and Password | `byte_decrypt(iv, ciphertext, password)`**  
  
### Salt Encryption  
- **This encryption works in an advance method of encryption and decryption with Initialization Vector (IV), Cipher Text, Password and salt. [more on salt](https://en.wikipedia.org/wiki/Salt_(cryptography)#:~:text=In%20cryptography%2C%20a%20salt%20is,needed%20for%20a%20successful%20attack.)**  
- **This function takes an input of Message and Password and returns Salt, VI and Cipher Text | `salt_encrypt(message, password)`**  
**For Decrypting the message the function takes Salt, VI, Cipher Text, and Password | `salt_decrypt(salt, iv, ciphertext, password)`**  
- **On this process the encrypt function generates a 256-bit key | `generate_key(password, salt)`**  
  
---
  
## Usage  
  
### Simple Encryption Module:  
  
#### shift_encrypt:  
Encrypts a message using a simple Caesar cipher with a specified shift value.  
  
```python
from MonoCipher.SimpleEncryption import shift_encrypt

message = "Hello, World!"
shift = 3

encrypted_message = shift_encrypt(message, shift)
print("Encrypted message:", encrypted_message)
```
  
#### shift_decrypt:  
Decrypts a message encrypted with a Caesar cipher using the same shift value.
  
```python
from MonoCipher.SimpleEncryption import shift_decrypt

encrypted_message = "Khoor, Zruog!"
shift = 3

decrypted_message = shift_decrypt(encrypted_message, shift)
print("Decrypted message:", decrypted_message)
```
  
### Byte Encryption Module:  
  
#### byte_encrypt:  
Encrypts a message using AES encryption in CBC mode with a provided key.
  
```python
from MonoCipher.ByteEncryption import byte_encrypt

message = "Hello, World!"
password = "MySecretPassword"

iv, ciphertext = byte_encrypt(message, password)
print("IV:", iv)
print("Ciphertext:", ciphertext)
```
  
#### byte_decrypt:  
Decrypts a message encrypted with AES encryption using the same key and initialization vector (IV).
  
```python
from MonoCipher.ByteEncryption import byte_decrypt
  
iv = "some_base64_encoded_iv"
ciphertext = "some_base64_encoded_ciphertext"
password = "MySecretPassword"

decrypted_message = byte_decrypt(iv, ciphertext, password)
print("Decrypted message:", decrypted_message)
```
  
### Salt Encryption Module:  
  
#### salt_encrypt:  
Encrypts a message using AES encryption in CBC mode with a provided password and a random salt.
  
```python
from MonoCipher.SaltEncryption import salt_encrypt

message = "Hello, World!"
password = "MySecretPassword"

salt, iv, ciphertext = salt_encrypt(message, password)
print("Salt:", salt)
print("IV:", iv)
print("Ciphertext:", ciphertext)
```
  
#### salt_decrypt:  
Decrypts a message encrypted with AES encryption using the same password and salt.
  
```python
from MonoCipher.SaltEncryption import salt_decrypt

salt = "some_base64_encoded_salt"
iv = "some_base64_encoded_iv"
ciphertext = "some_base64_encoded_ciphertext"
password = "MySecretPassword"

decrypted_message = salt_decrypt(salt, iv, ciphertext, password)
print("Decrypted message:", decrypted_message)
```
  
These are the usages for each of the six functions provided by the encryption modules. You can customize the input values such as the message, shift value, password, IV, and ciphertext according to your requirements.
    
---
  
### Contributions Welcome
  
We welcome contributions from the community to enhance and improve our encryption project. Whether you're interested in adding new features, fixing bugs, improving documentation, or suggesting ideas, your contributions are highly appreciated.
  
### Contact  
**Author : Rakesh Kanna**  
**E-Mail : rakeshkanna0108@gmail.com**  
**Version : v0.1.2**  
**Repository : https://github.com/rakeshkanna-rk/MonoCipher**  
    
### Project Under [MIT LICENSE](LICENSE)  
