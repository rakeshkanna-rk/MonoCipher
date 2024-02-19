# Simple Encryption
  
The code implements a basic Caesar cipher encryption and decryption algorithm. The `shift_encrypt` function shifts each character in the message by a specified amount, while `shift_decrypt` reverses the process. This enables encryption and decryption of messages with a simple shift of characters in the alphabet.
  
1. **Encryption Function `shift_encrypt(message, shift)`**
   - This function takes a `message` and a `shift` value as input.
   - It iterates through each character in the message.
   - If the character is alphabetic (checked using `char.isalpha()`), it calculates the shifted ASCII value by adding the shift value.
   - If the character is lowercase and the shifted value exceeds the ASCII value of 'z', or if it's uppercase and exceeds the ASCII value of 'Z', it wraps around by subtracting 26.
   - If the character is outside the alphabetic range, it remains unchanged.
   - The encrypted character is appended to the `encrypted_message`.
   - Finally, the encrypted message is returned.

2. **Decryption Function `shift_decrypt(encrypted_message, shift)`:**
   - This function takes an `encrypted_message` and a `shift` value as input.
   - It iterates through each character in the encrypted message.
   - If the character is alphabetic, it calculates the shifted ASCII value by subtracting the shift value.
   - If the character is lowercase and the shifted value is less than the ASCII value of 'a', or if it's uppercase and less than the ASCII value of 'A', it wraps around by adding 26.
   - If the character is outside the alphabetic range, it remains unchanged.
   - The decrypted character is appended to the `decrypted_message`.
   - Finally, the decrypted message is returned.

3. **Example Usage (Commented Out):**
   - Example usage of the encryption and decryption functions is provided but commented out. It demonstrates how to encrypt a message with a specified shift value and then decrypt it using the same shift value.
     
   ```python
    message = "Hello, World!"
    shift = 3

    # Encryption
    encrypted_message = shift_encrypt(message, shift)
    print("Encrypted message:", encrypted_message)

    # Decryption
    decrypted_message = shift_decrypt(encrypted_message, shift)
    print("Decrypted message:", decrypted_message)
    ```
  
These functions implement a basic Caesar cipher encryption and decryption algorithm, where each character in the message is shifted by a fixed number of positions in the alphabet.