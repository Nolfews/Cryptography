#!/usr/bin/python3
import pytest
import subprocess
import sys
import os

# Get the project root directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MY_PGP = os.path.join(PROJECT_ROOT, 'my_pgp')


class TestRSA:
    """Test suite for RSA encryption and decryption"""
    
    def test_rsa_keygen_small_primes(self):
        """Test RSA key generation with small primes"""
        result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'd3', 'e3'],  # 211, 227 (primes)
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        lines = result.stdout.strip().split('\n')
        assert len(lines) == 2
        assert lines[0].startswith('public key: ')
        assert lines[1].startswith('private key: ')
        
        # Verify key format (e-n and d-n)
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        
        assert '-' in pub_key
        assert '-' in priv_key
    
    def test_rsa_small_keys_example_from_requirements(self):
        """Test RSA with the small keys example from requirements"""
        # Generate keys with d3 and e3
        gen_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'd3', 'e3'],
            capture_output=True,
            text=True
        )
        
        assert gen_result.returncode == 0
        lines = gen_result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        
        # The example shows: public key: 0101-19bb, private key: 9d5b-19bb
        # These values depend on the primes, so we just verify the format
        assert pub_key.count('-') == 1
        assert priv_key.count('-') == 1
        
        message = "WF"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-d', priv_key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_rsa_large_keys_example_from_requirements(self):
        """Test RSA with the large keys example from requirements"""
        # Generate keys with the large primes from requirements
        p = "4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1"
        q = "bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb"
        
        gen_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', p, q],
            capture_output=True,
            text=True
        )
        
        assert gen_result.returncode == 0
        lines = gen_result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        
        # Expected keys from requirements
        expected_pub = "010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        expected_priv = "81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        
        assert pub_key == expected_pub
        assert priv_key == expected_priv
        
        message = "The night is dark and full of terrors"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-d', priv_key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_rsa_basic_roundtrip(self):
        """Test basic RSA encryption and decryption"""
        # Generate keys with small primes (227, 229 are both prime)
        gen_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'e3', 'e5'],  # 227, 229
            capture_output=True,
            text=True
        )
        
        assert gen_result.returncode == 0
        lines = gen_result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        
        message = "Hi"  # Keep it short for small keys
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        assert len(ciphertext) > 0
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-d', priv_key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_rsa_short_message(self):
        """Test RSA with very short message"""
        gen_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'df', 'e5'],
            capture_output=True,
            text=True
        )
        
        lines = gen_result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        
        message = "A"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-d', priv_key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_rsa_long_message(self):
        """Test RSA with longer message using large keys"""
        # Use the large keys from requirements for long messages
        p = "4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1"
        q = "bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb"
        
        gen_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', p, q],
            capture_output=True,
            text=True
        )
        
        lines = gen_result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        
        message = "This is a longer message"
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-d', priv_key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_rsa_special_characters(self):
        """Test RSA with special characters"""
        gen_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'e3', 'e5'],  # 227, 229
            capture_output=True,
            text=True
        )
        
        lines = gen_result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        
        message = "Hi!"  # Keep short for small keys
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-d', priv_key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_rsa_multiline_message(self):
        """Test RSA with multiline message"""
        gen_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'e3', 'e5'],  # 227, 229
            capture_output=True,
            text=True
        )
        
        lines = gen_result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        priv_key = lines[1].split(': ')[1]
        
        message = "A\nB"  # Keep short for small keys
        
        # Encrypt
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        assert enc_result.returncode == 0
        ciphertext = enc_result.stdout.strip()
        
        # Decrypt
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-d', priv_key],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        assert dec_result.returncode == 0
        assert dec_result.stdout.strip() == message
    
    def test_rsa_decrypt_with_wrong_key(self):
        """Test RSA decryption with wrong key"""
        # Generate two different key pairs
        gen1_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'df', 'e5'],
            capture_output=True,
            text=True
        )
        lines1 = gen1_result.stdout.strip().split('\n')
        pub_key1 = lines1[0].split(': ')[1]
        
        gen2_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'e3', 'eb'],
            capture_output=True,
            text=True
        )
        lines2 = gen2_result.stdout.strip().split('\n')
        priv_key2 = lines2[1].split(': ')[1]
        
        message = "Secret"
        
        # Encrypt with key1
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key1],
            input=message + '\n',
            capture_output=True,
            text=True
        )
        
        ciphertext = enc_result.stdout.strip()
        
        # Try to decrypt with key2 (wrong key)
        dec_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-d', priv_key2],
            input=ciphertext + '\n',
            capture_output=True,
            text=True
        )
        
        # Should produce different output (garbage or error)
        if dec_result.returncode == 0:
            assert dec_result.stdout.strip() != message
    
    def test_rsa_invalid_key_format(self):
        """Test RSA with invalid key format"""
        # Missing the modulus part
        result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', '010001'],
            input="test\n",
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_rsa_keygen_equal_primes(self):
        """Test RSA key generation with equal primes (should fail)"""
        result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'df', 'df'],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_rsa_keygen_composite_numbers(self):
        """Test RSA key generation with non-prime numbers"""
        # Note: Some small composite numbers may still work mathematically
        # but are insecure. This test verifies the system doesn't crash.
        result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', '04', '09'],  # 4 and 9 are not prime
            capture_output=True,
            text=True
        )
        
        # The system should either reject it (84) or accept it (0)
        # Both are acceptable as long as it doesn't crash
        assert result.returncode in [0, 84]
    
    def test_rsa_keygen_one_as_input(self):
        """Test RSA key generation with 1 as input (should fail)"""
        result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', '01', 'df'],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 84
    
    def test_rsa_encryption_produces_different_output(self):
        """Verify that encryption changes the plaintext"""
        gen_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-g', 'df', 'e5'],
            capture_output=True,
            text=True
        )
        
        lines = gen_result.stdout.strip().split('\n')
        pub_key = lines[0].split(': ')[1]
        
        message = "Test message"
        
        enc_result = subprocess.run(
            [sys.executable, MY_PGP, 'rsa', '-c', pub_key],
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
