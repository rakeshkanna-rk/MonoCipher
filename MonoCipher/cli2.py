#textPlay
from textPlay.colors import *
from textPlay import options

# ENCRYPTION MODULES
from MonoCipher.ByteEncryption import byte_encrypt, byte_decrypt # ..checked
from MonoCipher.HmacEncryption import hmac_encrypt, hmac_decrypt # ..checked
from MonoCipher.MacEncryption import mac_encrypt, mac_decrypt # ..checked
from MonoCipher.NonceEncryption import nonce_encrypt, nonce_decrypt # ..checked
from MonoCipher.SaltEncryption import salt_encrypt, salt_decrypt # ..checked
from MonoCipher.SimpleEncryption import shift_encrypt, shift_decrypt # ..checked

# VERSION
VERSION = 'v0.1.4 beta'

# Varibles
breaker = '\n  ---------------——'

# Header
header = f'''{BLUE}
 __  __                    ____ _       _
|  \/  | ___  _ __   ___  / ___(_)_ __ | |__   ___ _ __ 
| |\/| |/ _ \| '_ \ / _ \| |   | | '_ \| '_ \ / _ \ '__|
| |  | | (_) | | | | (_) | |___| | |_) | | | |  __/ |   
|_|  |_|\___/|_| |_|\___/ \____|_| .__/|_| |_|\___|_|   
                                 |_|
'''
    

def checker(holder, check, err, typ: type):
    if typ == str:
        loop = True
        while loop:
            text = input(holder)
            if text == check:
               print(err)

            else:
                loop = False

        return text


    elif typ == int:
        loop = True
        while loop:
            try:
                num = int(input(holder))
                if num == check:
                   print(err)

                elif num == None:
                    print(err)

                elif num >= 500:
                    print("Enter value between 1-500")

                else:
                    loop = False
            except Exception:
                print(err)
        
        return num
    

def shift_enc():
    msg = f"{BLUE}Enter your message: {RESET}"
    msg = checker(msg, '', 'Please enter a message', str)
    sht = f"{BLUE}Enter your shift value: {RESET}"
    sht = checker(sht, 0, 'Please enter a shift value (1-500)', int)
    print(f"Encrypted Message: {shift_encrypt(msg, sht)}")
    
def shift_dec():
    msg = f"{BLUE}Enter encrypted message: {RESET}"
    msg = checker(msg, '', 'Please enter encrypted message', str)
    sht = f"{BLUE}Enter the shift value: {RESET}"
    sht = checker(sht, 0, 'Please enter the shift value (1-500)', int)
    print(f"Decrypted Message: {shift_decrypt(msg, sht)}")

def salt_enc():
    msg = f"{BLUE}Enter your message: {RESET}"
    msg = checker(msg, '', 'Please enter a message', str)
    pws = f"{BLUE}Enter your password: {RESET}"
    pws = checker(pws, '', 'Please enter a password', str)
    salt, iv, ciphertext = salt_encrypt(msg, pws)
    print(f"Salt: {salt} \nIV: {iv} \nCiphertext: {ciphertext}")
    
def salt_dec():
    salt = f"{BLUE}Enter your Salt: {RESET}"
    salt = checker(salt, '', 'Please enter the Salt', str)
    iv = f"{BLUE}Enter your IV: {RESET}"
    iv = checker(iv, '', 'Please enter the IV', str)
    ciphertext = f"{BLUE}Enter your Ciphertext: {RESET}"
    ciphertext = checker(ciphertext, '', 'Please enter the Ciphertext', str)
    pws = f"{BLUE}Enter the password: {RESET}"
    pws = checker(pws, '', 'Please enter the password', str)
    try:
        print(f"Decrypted Message: {salt_decrypt(salt, iv, ciphertext, pws)}")
    except Exception:
        print(f"{RED}Incorrect Inputs{RESET}")



def start():
    options(option=[('Shift Encryption', lambda: shift_enc()),
                    (f'Shift Decryption {breaker}', lambda: shift_dec()),
                    # TODO: Add Byte Encryption and Decryption
                    ('Salt Encryption', lambda: salt_enc()),
                    (f'Salt Decryption {breaker}', lambda: salt_dec())],
                    # TODO: Add other methods
                    index=f"{MAGENTA}>{RESET}", 
                    head=header)

start()
