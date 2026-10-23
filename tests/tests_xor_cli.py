#!/usr/bin/python3
import pytest
import subprocess
import sys
import os

# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MY_PGP = os.path.join(PROJECT_ROOT, 'my_pgp')


class TestXOR:
    """Test suite for XOR encryption and decryption"""
    
    def test_xor_basic_roundtrip(self):
        """Test basic XOR encryption and decryption"""
        key = "0102"
        message = "Hi"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        assert len(ciphertext) > 0
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_xor_example_from_requirements(self):
        """Test XOR with the exact example from requirements"""
        key = "576861742069732064656164206d6179206e6576657220646965"
        message = "You know nothing, Jon Snow"
        # This matches the expected output from requirements
        expected_ciphertext = "20070f2700071c6a4449060a490515164e4e12190b190011063c"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message,  # No newline - message is exactly 26 bytes like the key
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        assert ciphertext == expected_ciphertext
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_xor_long_message(self):
        """Test XOR with a message longer than the key"""
        key = "0102030405"
        message = "This is a much longer message that will wrap around the key multiple times to test proper key wrapping!"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_xor_short_message(self):
        """Test XOR with a message shorter than the key"""
        key = "0102030405060708090a0b0c0d0e0f10"
        message = "Hi!"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_xor_special_characters(self):
        """Test XOR with special characters"""
        key = "0102030405060708"
        message = "Hello, World! @#$%^&*() 123"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_xor_empty_message(self):
        """Test XOR with empty message"""
        key = "0102"
        message = ""
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message,
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
    
    def test_xor_single_byte_key(self):
        """Test XOR with a single byte key"""
        key = "ff"
        message = "Test"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_xor_multiline_message(self):
        """Test XOR with multiline message"""
        key = "010203"
        message = "Line 1\nLine 2\nLine 3"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_xor_invalid_hex_key(self):
        """Test XOR with invalid hex key"""
        key = "GHIJKL"  # Not valid hex
        message = "test"
        
        result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_xor_missing_mode_flag(self):
        """Test XOR without encryption or decryption flag"""
        key = "0102"
        
        result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-b', key],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_xor_missing_key_flag(self):
        """Test XOR without key - should passthrough data"""
        result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        # When no key is provided, it passthroughs the data
        assert result.returncode == 0
        assert result.stdout.strip() == "test"
    
    def test_xor_encryption_produces_different_output(self):
        """Verify that encryption changes the plaintext"""
        key = "0102030405"
        message = "This should be encrypted"
        
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'xor', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        # The hex ciphertext should not equal the plaintext
        assert ciphertext != message
        # And it should be hex characters only
        assert all(c in '0123456789abcdef' for c in ciphertext.lower())


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
