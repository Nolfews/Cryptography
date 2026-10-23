#!/usr/bin/python3
import pytest
import subprocess
import sys
import os

# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MY_PGP = os.path.join(PROJECT_ROOT, 'my_pgp')

class TestPGPAES:
    """Test suite for PGP-AES encryption and decryption"""
    
    @pytest.fixture
    def valid_rsa_keys(self):
        """Generate valid RSA keys for testing"""
        # Using small primes for faster tests
        result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'df', 'e5'],  # 223, 229 (primes)
            capture_output=True,
            text=True
        )
        lines = result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        return pub_key, priv_key
    
    def test_pgp_aes_basic_roundtrip(self, valid_rsa_keys):
        """Test basic PGP-AES encryption and decryption"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102030405060708090a0b0c0d0e0f10"
        message = "Hello, World!"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        assert len(enc_lines) == 2
        enc_sym_key = enc_lines[0]
        enc_message = enc_lines[1]
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-d', '-b', f'{enc_sym_key}:{priv_key}'],
            input=enc_message + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_pgp_aes_long_message(self, valid_rsa_keys):
        """Test PGP-AES with a message longer than one AES block"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102030405060708090a0b0c0d0e0f10"
        message = "This is a much longer message that spans multiple AES blocks to test proper block handling!"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        enc_sym_key = enc_lines[0]
        enc_message = enc_lines[1]
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-d', '-b', f'{enc_sym_key}:{priv_key}'],
            input=enc_message + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_pgp_aes_empty_message(self, valid_rsa_keys):
        """Test PGP-AES with empty message"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102030405060708090a0b0c0d0e0f10"
        message = ""
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message,
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        assert len(enc_lines) == 2
    
    def test_pgp_aes_invalid_key_format(self):
        """Test PGP-AES with invalid key format"""
        # Missing colon separator
        result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', 'invalidkeyformat'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_pgp_aes_invalid_sym_key_length(self, valid_rsa_keys):
        """Test PGP-AES with symmetric key that's not 16 bytes"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102"  # Only 1 byte, should be 16
        
        result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', f'{sym_key}:{pub_key}'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_pgp_aes_missing_mode_flag(self, valid_rsa_keys):
        """Test PGP-AES without encryption or decryption flag"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102030405060708090a0b0c0d0e0f10"
        
        result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-b', f'{sym_key}:{pub_key}'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84


class TestPGPXOR:
    """Test suite for PGP-XOR encryption and decryption"""
    
    @pytest.fixture
    def valid_rsa_keys(self):
        """Generate valid RSA keys for testing"""
        result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'df', 'e5'],  # 223, 229 (primes)
            capture_output=True,
            text=True
        )
        lines = result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        return pub_key, priv_key
    
    def test_pgp_xor_basic_roundtrip(self, valid_rsa_keys):
        """Test basic PGP-XOR encryption and decryption"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102"
        message = "Hi"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        assert len(enc_lines) == 2
        enc_sym_key = enc_lines[0]
        enc_message = enc_lines[1]
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-d', '-b', f'{enc_sym_key}:{priv_key}'],
            input=enc_message + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_pgp_xor_long_message(self, valid_rsa_keys):
        """Test PGP-XOR with a message longer than the key"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102030405"
        message = "This is a longer message that will wrap around the XOR key multiple times!"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        enc_sym_key = enc_lines[0]
        enc_message = enc_lines[1]
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-d', '-b', f'{enc_sym_key}:{priv_key}'],
            input=enc_message + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_pgp_xor_special_characters(self, valid_rsa_keys):
        """Test PGP-XOR with special characters"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102030405060708"
        message = "Hello, World! @#$%^&*()"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        enc_sym_key = enc_lines[0]
        enc_message = enc_lines[1]
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-d', '-b', f'{enc_sym_key}:{priv_key}'],
            input=enc_message + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_pgp_xor_empty_message(self, valid_rsa_keys):
        """Test PGP-XOR with empty message"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102"
        message = ""
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message,
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        assert len(enc_lines) == 2
    
    def test_pgp_xor_invalid_key_format(self):
        """Test PGP-XOR with invalid key format"""
        # Missing colon separator
        result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-c', '-b', 'invalidkeyformat'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_pgp_xor_missing_mode_flag(self, valid_rsa_keys):
        """Test PGP-XOR without encryption or decryption flag"""
        pub_key, priv_key = valid_rsa_keys
        sym_key = "0102"
        
        result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-b', f'{sym_key}:{pub_key}'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84


class TestPGPWithRealWorldKeys:
    """Test PGP with the keys from the requirements example"""
    
    def test_pgp_aes_with_example_keys(self):
        """Test PGP-AES with the example keys from requirements"""
        sym_key = "57696e74657220697320636f6d696e67"
        pub_key = "010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        priv_key = "81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        message = "All men must die"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        assert len(enc_lines) == 2
        enc_sym_key = enc_lines[0]
        enc_message = enc_lines[1]
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-d', '-b', f'{enc_sym_key}:{priv_key}'],
            input=enc_message + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_pgp_xor_with_example_keys(self):
        """Test PGP-XOR with the example keys from requirements"""
        sym_key = "57696e74657220697320636f6d696e67"
        pub_key = "010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        priv_key = "81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        message = "All men must die"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-c', '-b', f'{sym_key}:{pub_key}'],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        enc_lines = enc_result.stdout.strip().split('\n')
        assert len(enc_lines) == 2
        enc_sym_key = enc_lines[0]
        enc_message = enc_lines[1]
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-xor', '-d', '-b', f'{enc_sym_key}:{priv_key}'],
            input=enc_message + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message


class TestPGPEdgeCases:
    """Test edge cases and error handling"""
    
    def test_decrypt_with_wrong_key(self):
        """Test decryption with wrong RSA key"""
        # Generate two different key pairs
        result1 = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'df', 'e5'],
            capture_output=True,
            text=True
        )
        lines1 = result1.stdout.strip().split('\n')
        pub_key1 = lines1[0].split(': ')[1]
        
        result2 = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'e3', 'eb'],
            capture_output=True,
            text=True
        )
        lines2 = result2.stdout.strip().split('\n')
        priv_key2 = lines2[1].split(': ')[1]
        
        sym_key = "0102030405060708090a0b0c0d0e0f10"
        message = "Secret"
        
        # Encrypt with key1
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', f'{sym_key}:{pub_key1}'],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        enc_lines = enc_result.stdout.strip().split('\n')
        enc_sym_key = enc_lines[0]
        enc_message = enc_lines[1]
        
        # Try to decrypt with key2 (wrong key)
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-d', '-b', f'{enc_sym_key}:{priv_key2}'],
            input=enc_message + '\n',
            capture_output=True,
            text=True
        )
        
        # Should either error or produce garbage (not the original message)
        if dec_result.returncode == 0:
            assert dec_result.stdout.strip() != message
        else:
            assert dec_result.returncode == 84
    
    def test_invalid_rsa_key_format(self):
        """Test with malformed RSA key"""
        sym_key = "0102030405060708090a0b0c0d0e0f10"
        
        # Missing the modulus part
        result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', f'{sym_key}:010001'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_hex_with_invalid_characters(self):
        """Test with non-hex characters in symmetric key"""
        result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c', '-b', 'GHIJKLMNOPQRSTUV:010001-12345678'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_missing_key_parameter(self):
        """Test without providing the key parameter"""
        result = subprocess.run(
            [sys.executable, MY_PGP, 'pgp-aes', '-c'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
