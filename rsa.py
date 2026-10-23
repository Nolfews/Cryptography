import numpy as np
import sys
import math

def stream_rsa_encrypt(public_key, infile, outfile):
    """Read entire stdin as one message, encrypt as single integer, output one hex line."""
    data = infile.read()
    if isinstance(data, bytes):
        try:
            data = data.decode('utf-8')
        except Exception:
            data = data.decode('latin-1', errors='ignore')
    # Remove trailing newline only, keep other content intact
    data = data.rstrip('\n')

    # Encrypt full message in one block per assignment spec (little-endian)
    ciphertext = rsa_encrypt(data, public_key)
    outfile.write(return_display_number(ciphertext))
    outfile.write("\n")

def stream_rsa_decrypt(private_key, infile, outfile):
    """Read one hex number from stdin, decrypt to plaintext string, output once."""
    data = infile.read()
    if isinstance(data, bytes):
        try:
            data = data.decode('utf-8')
        except Exception:
            data = data.decode('latin-1', errors='ignore')
    data = data.strip()
    if not data:
        return
    plaintext = rsa_decrypt(data, private_key, verbose=False)
    outfile.write(plaintext)
    outfile.write("\n")

def rsa_encrypt_hex(hex_message, public_key):
    e, n = public_key
    message_int = int(hex_message, 16)
    encrypted_int = pow(message_int, e, n)
    return return_display_number(encrypted_int)

def rsa_decrypt_hex(hex_ciphertext, private_key):
    d, n = private_key
    ciphertext_int = decrypt_number(hex_ciphertext)
    decrypted_int = pow(ciphertext_int, d, n)
    return return_display_number(decrypted_int)

def rsa_encrypt(message, public_key, verbose=False):
    e, n = public_key
    message = message.rstrip('\n')
    message = int.from_bytes(message.encode(), byteorder='little')
    if verbose:
        print("message as int:")
        print(message)
    ciphertext = pow(message, decrypt_number(e), decrypt_number(n))
    if verbose:
        print("ciphertext:")
        display_number(ciphertext)
    return ciphertext

def rsa_decrypt(ciphertext, private_key, verbose=False):
    d, n = private_key
    ciphertext = decrypt_number(ciphertext)
    plaintext_number = pow(ciphertext, decrypt_number(d), decrypt_number(n))
    if verbose:
        print("plaintext number:")
        print(plaintext_number)
    length = (plaintext_number.bit_length() + 7) // 8 or 1
    plaintext_bytes = plaintext_number.to_bytes(length, byteorder='little')
    message = plaintext_bytes.decode('utf-8', errors='ignore')
    if verbose:
        print("plaintext message:")
        print(message)
    return message


def decrypt_number(nb):
    try:
        return int.from_bytes(bytes.fromhex(nb), byteorder='little')
    except Exception:
        print("Error: invalid hex number", file=sys.stderr)
        raise SystemExit(84)

def display_number(number):
    print(return_display_number(number))

def return_display_number(number):
    length = (number.bit_length() + 7) // 8 or 1
    bytes_le = number.to_bytes(length, byteorder='little')
    return bytes_le.hex()

def generate_keys(p, q, verbose=False):

    modulus = p * q
    array = [p - 1, q - 1]
    totient = np.lcm.reduce(array)
    preferred = [65537, 257, 17, 5, 3]
    e = None
    for candidate in preferred:
        if 1 < candidate < totient and math.gcd(candidate, int(totient)) == 1:
            e = candidate
            break

    if e is None:
        candidate = 3
        while candidate < totient:
            if math.gcd(candidate, int(totient)) == 1:
                e = candidate
                break
            candidate += 2

    if e is None:
        raise ValueError("Failed to find a suitable public exponent e")

    d = pow(e, -1, int(totient))
    public_key = (e, modulus)
    private_key = (d, modulus)

    if verbose:
        print(f"public key: {return_display_number(e)}-{return_display_number(modulus)}")
        print(f"private key: {return_display_number(d)}-{return_display_number(modulus)}")

    return public_key, private_key

def generate_keys_from_hex(p_hex, q_hex, verbose=False):
    p = decrypt_number(p_hex)
    q = decrypt_number(q_hex)

    # Validate primes and constraints expected by tests
    if p <= 1 or q <= 1:
        print("Error: p and q must be greater than 1", file=sys.stderr)
        raise SystemExit(84)
    if p == q:
        print("Error: p and q must be distinct primes", file=sys.stderr)
        raise SystemExit(84)

    try:
        generate_keys(p, q, verbose=verbose)
    except Exception as e:
        # Any failure here should map to exit 84 per spec
        print(f"Error: RSA key generation failed: {e}", file=sys.stderr)
        raise SystemExit(84)