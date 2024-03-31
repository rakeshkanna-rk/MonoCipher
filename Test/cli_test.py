# cli_test.py → Test Passed ✔
# location → c:/Users/Akash kanna/OneDrive/Desktop/MonoCipher/MonoCipher/Test/cli_test.py


import sys
import os

import pytest
from click.testing import CliRunner

# Add the parent directory of MonoCipher to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can perform relative imports
try:
    from MonoCipher import mc_cli
except Exception:
    from cli import mc_cli


@pytest.fixture
def runner():
    return CliRunner()

def test_shift_encrypt(runner):
    result = runner.invoke(mc_cli, ["shiftencrypt", "--message", "hello", "--shift", "3"])
    assert result.exit_code == 0
    assert "The Encrypted Message is" in result.output

def test_byte_encrypt(runner):
    result = runner.invoke(mc_cli, ["byteencrypt", "--message", "hello", "--password", "password"])
    assert result.exit_code == 0
    assert "The Encrypted Values" in result.output

def test_salt_encrypt(runner):
    result = runner.invoke(mc_cli, ["saltencrypt", "--message", "hello", "--password", "password"])
    assert result.exit_code == 0
    assert "The Encrypted Values" in result.output

def test_hmac_encrypt(runner):
    result = runner.invoke(mc_cli, ["hmacencrypt", "--message", "hello", "--password", "password"])
    assert result.exit_code == 0
    assert "The Encrypted Values" in result.output

def test_mac_encrypt(runner):
    result = runner.invoke(mc_cli, ["macencrypt", "--message", "hello", "--password", "password"])
    assert result.exit_code == 0
    assert "The Encrypted Values" in result.output

def test_nonce_encrypt(runner):
    result = runner.invoke(mc_cli, ["nonceencrypt", "--message", "hello", "--password", "password"])
    assert result.exit_code == 0
    assert "The Encrypted Values" in result.output

def run_cli_tests():
    pytest.main()