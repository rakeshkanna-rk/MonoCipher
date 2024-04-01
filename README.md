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
  
Certainly! Here's the updated usage section for the README.md file:

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

### HMAC Encryption Module:

#### hmac_encrypt:
Encrypts a message using HMAC authentication.

```python
from MonoCipher.HmacEncryption import hmac_encrypt

message = "Hello, World!"
password = "MySecretPassword"

salt, nonce, ciphertext, tag = hmac_encrypt(message, password)
print("Salt:", salt)
print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Tag:", tag)
```

#### hmac_decrypt:
Decrypts a message encrypted with HMAC authentication using the same parameters.

```python
from MonoCipher.HmacEncryption import hmac_decrypt

salt = "some_base64_encoded_salt"
nonce = "some_base64_encoded_nonce"
ciphertext = "some_base64_encoded_ciphertext"
tag = "some_base64_encoded_tag"
password = "MySecretPassword"

decrypted_message = hmac_decrypt(salt, nonce, ciphertext, tag, password)
print("Decrypted message:", decrypted_message)
```

### Nonce Encryption Module:

#### nonce_encrypt:
Encrypts a message using a nonce for authentication.

```python
from MonoCipher.NonceEncryption import nonce_encrypt

message = "Hello, World!"
password = "MySecretPassword"

salt, nonce, ciphertext, tag = nonce_encrypt(message, password)
print("Salt:", salt)
print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Tag:", tag)
```

#### nonce_decrypt:
Decrypts a message encrypted with a nonce for authentication using the same parameters.

```python
from MonoCipher.NonceEncryption import nonce_decrypt

salt = "some_base64_encoded_salt"
nonce = "some_base64_encoded_nonce"
ciphertext = "some_base64_encoded_ciphertext"
tag = "some_base64_encoded_tag"
password = "MySecretPassword"

decrypted_message = nonce_decrypt(salt, nonce, ciphertext, tag, password)
print("Decrypted message:", decrypted_message)
```

### MAC Encryption Module:

#### mac_encrypt:
Encrypts a message using AES-GCM with a provided password.

```python
from MonoCipher.MacEncryption import mac_encrypt

password = "MySecretPassword"
message = "Hello, World!"

salt, nonce, ciphertext, tag = mac_encrypt(message, password)
print("Salt:", salt)
print("Nonce:", nonce)
print("Ciphertext:", ciphertext)
print("Tag:", tag)
```

#### mac_decrypt:
Decrypts a message encrypted with AES-GCM using the same parameters.

```python
from MonoCipher.MacEncryption import mac_decrypt

salt = "some_base64_encoded_salt"
nonce = "some_base64_encoded_nonce"
ciphertext = "some_base64_encoded_ciphertext"
tag = "some_base64_encoded_tag"
password = "MySecretPassword"

decrypted_message = mac_decrypt(salt, nonce, ciphertext, tag, password)
print("Decrypted message:", decrypted_message)
```

  
These are the usages for each of the six functions provided by the encryption modules. You can customize the input values such as the message, shift value, password, IV, and ciphertext according to your requirements.
    
---


# MonoCipher CLI

MonoCipher CLI is a command-line tool for performing various cryptographic operations such as encryption, decryption, and hashing. It offers a user-friendly interface and supports multiple encryption algorithms.

## Features

- Encryption and decryption using symmetric and asymmetric encryption algorithms
- Hashing data with different hash functions
- Command-line interface for easy interaction
- Progress bar during updates
- Seamless integration with pip for package updates

## Installation

You can install MonoCipher CLI via pip:

```bash
pip install MonoCipher==0.1.4b0
```

## Usage

After installing MonoCipher CLI, you can use it from the command line. Here are some examples of how to use it:

- **Shift Encryption:**
```bash
MonoCipher shiftencrypt --message "Hello, World!" --shift 3
```

- **Shift Decryption:**
```bash
MonoCipher shiftdecrypt --encrypted-message "Khoor, Zruog!" --shift 3
```

- **Byte Encryption:**
```bash
MonoCipher byteencrypt --message "Hello, World!" --password "MySecretPassword"
```

- **Byte Decryption:**
```bash
MonoCipher bytedecrypt --iv "iv_value" --ciphertext "ciphertext_value" --password "MySecretPassword"
```

- **Salt Encryption:**
```bash
MonoCipher saltencrypt --message "Hello, World!" --password "MySecretPassword"
```

- **Salt Decryption:**
```bash
MonoCipher saltdecrypt --salt "salt_value" --iv "iv_value" --ciphertext "ciphertext_value" --password "MySecretPassword"
```

- **HMAC Encryption:**
```bash
MonoCipher hmacencrypt --message "Hello, World!" --password "MySecretPassword"
```

- **HMAC Decryption:**
```bash
MonoCipher hmacdecrypt --salt "salt_value" --iv "iv_value" --ciphertext "ciphertext_value" --hmac "hmac_value" --password "MySecretPassword"
```

- **MAC Encryption:**
```bash
MonoCipher macencrypt --message "Hello, World!" --password "MySecretPassword"
```

- **MAC Decryption:**
```bash
MonoCipher macdecrypt --salt "salt_value" --nonce "nonce_value" --ciphertext "ciphertext_value" --tag "tag_value" --password "MySecretPassword"
```

- **Nonce Encryption:**
```bash
MonoCipher nonceencrypt --message "Hello, World!" --password "MySecretPassword"
```

- **Nonce Decryption:**
```bash
MonoCipher noncedecrypt --salt "salt_value" --nonce "nonce_value" --ciphertext "ciphertext_value" --tag "tag_value" --password "MySecretPassword"
```

For more detailed usage information, you can run:

```bash
MonoCipher --help
```

## Update

You can update MonoCipher CLI to the latest version using the following command:

```bash
MonoCipher update
```

This command will upgrade MonoCipher CLI to the latest version. It also includes a progress bar to track the update progress.

---

### Contributions Welcome
  
We welcome contributions from the community to enhance and improve our encryption project. Whether you're interested in adding new features, fixing bugs, improving documentation, or suggesting ideas, your contributions are highly appreciated.
  
### Contact  
**Author : Rakesh Kanna**  
**E-Mail : rakeshkanna0108@gmail.com**  
**Version : v0.1.4 beta**  
**Repository : https://github.com/rakeshkanna-rk/MonoCipher**  
**PyPI : https://pypi.org/project/MonoCipher/**  
    
### Project Under [MIT LICENSE](LICENSE)  
