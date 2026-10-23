#!/usr/bin/python3
import pytest
import subprocess
import sys
import os

# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MY_PGP = os.path.join(PROJECT_ROOT, 'my_pgp')


class TestAES:
    """Test suite for AES encryption and decryption"""
    
    def test_aes_basic_roundtrip(self):
        """Test basic AES encryption and decryption"""
        key = "0102030405060708090a0b0c0d0e0f10"  # 16 bytes
        message = "Hello, World!"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        assert len(ciphertext) > 0
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_aes_example_from_requirements(self):
        """Test AES with the message from requirements"""
        key = "57696e74657220697320636f6d696e67"
        message = "All men must die"
        # This matches the expected output from requirements
        expected_ciphertext = "744ce22c385958348f0df26eceb62eef"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message,  # No newline - message is exactly 16 bytes
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        assert ciphertext == expected_ciphertext
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_aes_long_message(self):
        """Test AES with a message longer than one block (16 bytes)"""
        key = "0102030405060708090a0b0c0d0e0f10"
        message = "This is a much longer message that spans multiple AES blocks to test proper block handling!"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        # Ciphertext should be longer than one block (32 hex chars = 16 bytes)
        assert len(ciphertext) > 32
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_aes_short_message(self):
        """Test AES with a message shorter than one block"""
        key = "0102030405060708090a0b0c0d0e0f10"
        message = "Hi!"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        # Should be padded to one block (32 hex chars)
        assert len(ciphertext) == 32
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_aes_exactly_one_block(self):
        """Test AES with a message exactly 16 bytes"""
        key = "0102030405060708090a0b0c0d0e0f10"
        message = "1234567890123456"  # Exactly 16 bytes
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message,
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        # Should be one block (32 hex chars)
        assert len(ciphertext) == 32
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_aes_special_characters(self):
        """Test AES with special characters"""
        key = "0102030405060708090a0b0c0d0e0f10"
        message = "Hello! @#$%^&*() 123"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_aes_empty_message(self):
        """Test AES with empty message"""
        key = "0102030405060708090a0b0c0d0e0f10"
        message = ""
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message,
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
    
    def test_aes_multiline_message(self):
        """Test AES with multiline message"""
        key = "0102030405060708090a0b0c0d0e0f10"
        message = "Line 1\nLine 2\nLine 3"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-d', '-b', key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_aes_different_keys_produce_different_ciphertext(self):
        """Test that different keys produce different ciphertext"""
        key1 = "0102030405060708090a0b0c0d0e0f10"
        key2 = "1112131415161718191a1b1c1d1e1f20"
        message = "Same message"
        
        # Encrypt with key1
        enc1_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key1],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        # Encrypt with key2
        enc2_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key2],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc1_result.returncode == 0
        assert enc2_result.returncode == 0
        
        ciphertext1 = enc1_result.stdout.strip()
        ciphertext2 = enc2_result.stdout.strip()
        
        # Different keys should produce different ciphertext
        assert ciphertext1 != ciphertext2
    
    def test_aes_invalid_key_length(self):
        """Test AES with invalid key length (not 16 bytes)"""
        key = "0102"  # Only 1 byte, should be 16
        message = "test"
        
        result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_aes_invalid_hex_key(self):
        """Test AES with invalid hex key"""
        key = "GHIJKLMNOPQRSTUV"  # Not valid hex
        message = "test"
        
        result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_aes_missing_mode_flag(self):
        """Test AES without encryption or decryption flag"""
        key = "0102030405060708090a0b0c0d0e0f10"
        
        result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-b', key],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_aes_missing_key_flag(self):
        """Test AES without key - should passthrough data"""
        result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        # When no key is provided, it passthroughs the data
        assert result.returncode == 0
        assert result.stdout.strip() == "test"
    
    def test_aes_encryption_produces_different_output(self):
        """Verify that encryption changes the plaintext"""
        key = "0102030405060708090a0b0c0d0e0f10"
        message = "This should be encrypted"
        
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'aes', '-c', '-b', key],
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
