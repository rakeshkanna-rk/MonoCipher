# OS
import os
import sys
import subprocess
import time
import json

#textPlay
from textPlay.colors import *
from textPlay import options
from textPlay import progress_bar_loader

# ASCII ART
import pyfiglet


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
breaker = '\n  —————————————————'
breaker2 = '\n  ================='
help_cli ='''Usage: MonoCipher <option>

Options:
 -h, --help          show this help message and exit
 -v, --version       show the version number and exit
 -m, --menu          Open main menu
 -s, --settings      Open settings window
'''

# Fetch user settings
settings = os.path.expanduser("~/.monocipher/settings.json")
with open(settings) as f:
    settings = json.load(f)

s_name = settings['metadata']['Name']
s_password = settings['metadata']['password']
s_id = settings['metadata']['solid_id']
logo = settings['settings']['logo']
save_pws = settings['settings']['save_pws']


if  s_password and s_id and s_name == '':
    print(f"{RED}Configuration not found.{RESET}")
    with open(os.devnull, "w") as devnull:
            subprocess.check_call(["MonoCipher","--settings"], stdout=devnull, stderr=subprocess.STDOUT)

if logo:
    TITLE = f"{BLUE}\n{pyfiglet.figlet_format("MonoCipher")}"
else:
    TITLE = ''

def crt_file(name):
    pass # TODO : Create file fn


def save_pass():
    pass # TODO : Save Password fn


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

def msg_():
    msg = f"{BLUE}Enter your message: {RESET}"
    msg = checker(msg, '', 'Please enter a message', str)
    return msg


def salt_():
    salt = f"{BLUE}Enter your Salt: {RESET}"
    salt = checker(salt, '', 'Please enter the Salt', str)
    return salt

def iv_():
    iv = f"{BLUE}Enter your IV: {RESET}"
    iv = checker(iv, '', 'Please enter the IV', str)
    return iv  

def ciphertext_():
    ciphertext = f"{BLUE}Enter your Ciphertext: {RESET}"
    ciphertext = checker(ciphertext, '', 'Please enter the Ciphertext', str)
    return ciphertext

def nonce_():
    nonce = f"{BLUE}Enter your Nonce: {RESET}"
    nonce = checker(nonce, '', 'Please enter the Nonce', str)
    return nonce

def tag_():
    tag = f"{BLUE}Enter your Tag: {RESET}"
    tag = checker(tag, '', 'Please enter the Tag', str)
    return tag

def password_():
    pws = f"{BLUE}Enter the password: {RESET}"
    pws = checker(pws, '', 'Please enter the password', str)
    return pws

def password_fst():
    pws = f"{BLUE}Enter your password: {RESET}"
    pws = checker(pws, '', 'Please enter a password', str)
    return pws

def shift_enc():
    msg = msg_()
    sht = f"{BLUE}Enter your shift value: {RESET}"
    sht = checker(sht, 0, 'Please enter a shift value (1-500)', int)
    print(f"Encrypted Message: {shift_encrypt(msg, sht)}")
    
def shift_dec():
    msg = msg_()
    sht = f"{BLUE}Enter the shift value: {RESET}"
    sht = checker(sht, 0, 'Please enter the shift value (1-500)', int)
    print(f"Decrypted Message: {shift_decrypt(msg, sht)}")

def byte_enc():
    msg = msg_()
    password = password_fst()
    key_length = 16
    if len(password) > key_length:
        password = password[:key_length]
    elif len(password) < key_length:
        password = password.ljust(key_length, '0')

    iv, ciphertext = byte_encrypt(msg, password)
    print(f"IV: {iv} \nCiphertext: {ciphertext}")

def byte_dec():
    iv = iv_()
    ciphertext = ciphertext_()
    password = password_()
    key_length = 16
    if len(password) > key_length:
            password = password[:key_length]  
    elif len(password) < key_length:
        password = password.ljust(key_length, '0')  
    print(f"Decrypted Message: {byte_decrypt(iv, ciphertext, password)}")

def salt_enc():
    msg = msg_()
    pws = password_fst()
    salt, iv, ciphertext = salt_encrypt(msg, pws)
    print(f"Salt: {salt} \nIV: {iv} \nCiphertext: {ciphertext}")
    
def salt_dec():
    salt = salt_()
    iv = iv_()
    ciphertext = ciphertext_()
    pws = password_()
    try:
        print(f"Decrypted Message: {salt_decrypt(salt, iv, ciphertext, pws)}")
    except Exception:
        print(f"{RED}Incorrect Inputs{RESET}")

def hmac_enc():
    msg = msg_()
    pws = password_fst()
    salt, nonce, ciphertext, tag = hmac_encrypt(msg, pws)
    print(f"Salt: {salt} \nNonce: {nonce} \nCiphertext: {ciphertext} \nTag: {tag}")

def hmac_dec():
    salt = salt_()
    nonce = nonce_()
    ciphertext = ciphertext_()
    tag = tag_()
    pws = password_()
    try:
        print(f"Decrypted Message: {hmac_decrypt(salt, nonce, ciphertext, tag, pws)}")
    except Exception:
        print(f"{RED}Incorrect Inputs{RESET}")

def nonce_enc():
    msg = msg_()
    pws = password_fst()
    salt, nonce, ciphertext, tag = nonce_encrypt(msg, pws)
    print(f"Salt: {salt} \nNonce: {nonce} \nCiphertext: {ciphertext} \nTag: {tag}")

def nonce_dec():
    salt = salt_()
    nonce = nonce_()
    ciphertext = ciphertext_()
    tag = tag_()
    pws = password_()
    try:
        print(f"Decrypted Message: {nonce_decrypt(salt, nonce, ciphertext, tag, pws)}")
    except Exception:
        print(f"{RED}Incorrect Inputs{RESET}")

def mac_enc():
    msg = msg_()
    pws = password_fst()
    salt, nonce, ciphertext, tag = mac_encrypt(msg, pws)
    print(f"Salt: {salt} \nNonce: {nonce} \nCiphertext: {ciphertext} \nTag: {tag}")

def mac_dec():
    salt = salt_()
    nonce = nonce_()
    ciphertext = ciphertext_()
    tag = tag_()
    pws = password_()
    try:
        print(f"Decrypted Message: {mac_decrypt(salt, nonce, ciphertext, tag, pws)}")
    except Exception:
        print(f"{RED}Incorrect Inputs{RESET}")

def update():
    try:
        print(f'{GREEN}Updating...{RESET}')
        # Suppress stdout and stderr to hide pip upgrade messages
        with open(os.devnull, "w") as devnull:
            # Execute pip upgrade command and suppress output
            subprocess.check_call(["pip", "install", "--upgrade", "MonoCipher"], stdout=devnull, stderr=subprocess.STDOUT)     
        progress_bar_loader() 
        print(f'\n\n\t{GREEN}Updated Successfully ✔{RESET}\n')
    except Exception as e:
        print(f'{RED}Your Update Failed due to {e}{RESET}')

def exit():
    print(f"{RED}Exiting...{RESET}")

def start():
    options(option=[('Shift Encryption', lambda: shift_enc()),
                    (f'Shift Decryption {breaker}', lambda: shift_dec()),
                    ('Byte Encryption', lambda: byte_enc()),
                    (f'Byte Decryption {breaker}', lambda: byte_dec()),
                    ('Salt Encryption', lambda: salt_enc()),
                    (f'Salt Decryption {breaker}', lambda: salt_dec()),
                    ('Hmac Encryption', lambda: hmac_enc()),
                    (f'Hmac Decryption {breaker}', lambda: hmac_dec()),
                    ('Nonce Encryption', lambda: nonce_enc()),
                    (f'Nonce Decryption {breaker}', lambda: nonce_dec()),
                    ('Mac Encryption', lambda: mac_enc()),
                    (f'Mac Decryption {breaker2}', lambda: mac_dec()),
                    (f'{CYAN}Update{RESET}', lambda: update()),
                    (f'{RED}Exit{RESET}', lambda: exit())],
                    index=f"{MAGENTA}>{RESET}", 
                    head=TITLE)

def cli():
    # TODO: Load JSON file from settings.json || os.path.expanduser('~/.monocipher/settings.json') 
    try:
        if len(sys.argv) > 3:
            print(f"{RED}Invalid Input Provided{RESET}")
            print(help_cli)


        elif sys.argv[1] == '--help' or sys.argv[1] == '-h':
            print(TITLE)
            print(help_cli)

        elif sys.argv[1] == '--menu' or sys.argv[1] == '-m':
            print(f"{GREEN} Openig Menu...{RESET}")
            time.sleep(2)
            start()

        elif sys.argv[1] == '--version' or sys.argv[1] == '-v':
            print(TITLE)
            print(f"{BLUE}MonoCipher {MAGENTA}{VERSION}{RESET}")

        elif sys.argv[1] == '--settings' or sys.argv[1] == '-s':
            print(f"{GREEN} Opening Settings...{RESET}")
            settings_path = os.path.expanduser("~/.monocipher")
            create_dir(settings_path)
            run_path = os.path.join(settings_path, "settings.py")
            json_path = os.path.join(settings_path, "settings.json")
            print(run_path)
            if os.path.exists(run_path) and os.path.exists(json_path):
                subprocess.run(["python", run_path])


            else:
                print(f"The settings folder does not exist or corrupted.")
                fld_loop = True
                while fld_loop:
                    crt_fld = input("Do you like to import the settings? (y/n): ")
                    if crt_fld == 'y':
                        import_file(os.path.expanduser("~/"))
                        print("Settings imported successfully.")
                        fld_loop = False
                    elif crt_fld == 'n':
                        print("Settings not imported.")
                        fld_loop = False
                    else:
                        print("Invalid input. Please enter 'y' or 'n'.")


        else:
            print(f"{RED}Invalid Input Provided{RESET}")
            print(help_cli)
            

    except IndexError :
        start()

def create_dir(DIR):
    os.makedirs(DIR, exist_ok=True)

def import_file(path):
    # TODO: Import settings from GDrive || gdown
    pass

cli()