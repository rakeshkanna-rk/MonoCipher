from cli_test import run_cli_tests
from test1 import test_byte_cipher, test_salt_cipher, test_shift_cipher
from test2 import test_hmac_cipher, test_mac_cipher, test_nonce_cipher

def run_all_tests():
    test_byte_cipher()
    test_salt_cipher()
    test_shift_cipher()
    test_hmac_cipher()
    test_mac_cipher()
    test_nonce_cipher()
    run_cli_tests()

if __name__ == "__main__":
    run_all_tests()