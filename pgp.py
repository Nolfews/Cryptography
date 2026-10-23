#!/usr/bin/python3
import sys
from typing import Tuple

import rsa
from aes import key_expansion, cipher_block, inv_cipher_block, pad_block, hex_from_bytes
from xor import pad_block as xor_pad_block, bytes_from_hex as xor_bytes_from_hex, hex_from_bytes as xor_hex_from_bytes


def _bytes_from_hex_plain(s: str) -> bytes:
    """Convert hex string to bytes without any byte order reversal."""
    s = ''.join(s.strip().split())
    if s.startswith(('0x', '0X')):
        s = s[2:]
    return bytes.fromhex(s)


def _hex_from_bytes_plain(b: bytes) -> str:
    """Convert bytes to hex string without any byte order reversal."""
    return b.hex()


def _parse_rsa_pub_hex(rsa_key_hex: str) -> Tuple[int, int]:
    if '-' not in rsa_key_hex:
        raise ValueError("Invalid RSA public key format. Expected e-n (hex-hex)")
    e_hex, n_hex = rsa_key_hex.split('-', 1)
    return rsa.decrypt_number(e_hex), rsa.decrypt_number(n_hex)


def _parse_rsa_priv_hex(rsa_key_hex: str) -> Tuple[int, int]:
    if '-' not in rsa_key_hex:
        raise ValueError("Invalid RSA private key format. Expected d-n (hex-hex)")
    d_hex, n_hex = rsa_key_hex.split('-', 1)
    return rsa.decrypt_number(d_hex), rsa.decrypt_number(n_hex)


def pgp_xor_encrypt(sym_key_hex: str, rsa_pub_hex: str, infile, outfile) -> None:
    e, n = _parse_rsa_pub_hex(rsa_pub_hex)


    encrypted_sym_key = rsa.rsa_encrypt_hex(sym_key_hex, (e, n))


    sym_key = xor_bytes_from_hex(sym_key_hex)
    if len(sym_key) == 0:
        raise ValueError("Symmetric key must not be empty")


    data = infile.read()
    if isinstance(data, str):
        data = data.encode('utf-8')


    data = data.rstrip(b'\n')


    block_size = len(sym_key)
    encrypted_message = bytearray()
    for i, byte in enumerate(data):
        encrypted_message.append(byte ^ sym_key[i % block_size])


    outfile.write(encrypted_sym_key + '\n')
    outfile.write(xor_hex_from_bytes(bytes(encrypted_message)) + '\n')


def pgp_xor_decrypt(enc_sym_key_hex: str, rsa_priv_hex: str, infile, outfile) -> None:
    d, n = _parse_rsa_priv_hex(rsa_priv_hex)



    decrypted_sym_key_le_hex = rsa.rsa_decrypt_hex(enc_sym_key_hex, (d, n))

    decrypted_int = rsa.decrypt_number(decrypted_sym_key_le_hex)
    length = (decrypted_int.bit_length() + 7) // 8 or 1
    decrypted_sym_key_hex = decrypted_int.to_bytes(length, byteorder='big').hex()

    sym_key = xor_bytes_from_hex(decrypted_sym_key_hex)

    if len(sym_key) == 0:
        raise ValueError("Decrypted symmetric key must not be empty")


    data = infile.read()
    if isinstance(data, bytes):
        data = data.decode('utf-8')


    data = data.strip()
    encrypted_message = bytes.fromhex(data)


    block_size = len(sym_key)
    decrypted_message = bytearray()
    for i, byte in enumerate(encrypted_message):
        decrypted_message.append(byte ^ sym_key[i % block_size])


    outfile.write(bytes(decrypted_message).rstrip(b'\x00').decode('utf-8', errors='ignore') + '\n')


def pgp_aes_encrypt(sym_key_hex: str, rsa_pub_hex: str, infile, outfile, one_block: bool = False) -> None:
    e, n = _parse_rsa_pub_hex(rsa_pub_hex)


    encrypted_sym_key = rsa.rsa_encrypt_hex(sym_key_hex, (e, n))


    sym_key = _bytes_from_hex_plain(sym_key_hex)
    if len(sym_key) != 16:
        raise ValueError("AES symmetric key must be 16 bytes (32 hex chars)")

    round_keys = key_expansion(sym_key)


    data = infile.read()
    if isinstance(data, str):
        data = data.encode('utf-8')


    data = data.rstrip(b'\n')


    encrypted_message = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        if len(block) < 16:
            block = pad_block(block)
        encrypted_block = cipher_block(block, round_keys)
        encrypted_message.extend(encrypted_block)


    outfile.write(encrypted_sym_key + '\n')
    outfile.write(hex_from_bytes(bytes(encrypted_message)) + '\n')


def pgp_aes_decrypt(enc_sym_key_hex: str, rsa_priv_hex: str, infile, outfile, one_block: bool = False) -> None:
    d, n = _parse_rsa_priv_hex(rsa_priv_hex)



    decrypted_sym_key_le_hex = rsa.rsa_decrypt_hex(enc_sym_key_hex, (d, n))

    decrypted_int = rsa.decrypt_number(decrypted_sym_key_le_hex)
    length = (decrypted_int.bit_length() + 7) // 8 or 1
    decrypted_sym_key_hex = decrypted_int.to_bytes(length, byteorder='big').hex()

    sym_key = _bytes_from_hex_plain(decrypted_sym_key_hex)

    if len(sym_key) != 16:
        raise ValueError("Decrypted AES symmetric key must be 16 bytes")

    round_keys = key_expansion(sym_key)


    data = infile.read()
    if isinstance(data, bytes):
        data = data.decode('utf-8')


    data = ''.join(data.strip().split())


    decrypted_message = bytearray()
    for i in range(0, len(data), 32):
        block_hex = data[i:i+32]
        if len(block_hex) < 32:
            block_hex = block_hex.ljust(32, '0')
        block = bytes.fromhex(block_hex)
        decrypted_block = inv_cipher_block(block, round_keys)
        decrypted_message.extend(decrypted_block)


    outfile.write(bytes(decrypted_message).rstrip(b'\x00').decode('utf-8', errors='ignore') + '\n')
