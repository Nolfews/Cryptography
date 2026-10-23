#!/usr/bin/python3
import pytest
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aes import (
	S_BOX,
	INV_S_BOX,
	RCON,
	sub_word,
	rot_word,
	rcon_word,
	xor_words,
	key_expansion,
	add_round_key,
	sub_bytes,
	inv_sub_bytes,
	shift_rows,
	inv_shift_rows,
	xtime,
	mul,
	mix_single_column,
	mix_columns,
	inv_mix_single_column,
	inv_mix_columns,
	cipher_block,
	inv_cipher_block,
	pad_block,
	bytes_from_hex,
	hex_from_bytes,
)


def test_sbox_inverse():
	for i, v in enumerate(S_BOX):
		assert INV_S_BOX[v] == i


def test_sub_rot_rcon_xor():
	w = [0x00, 0x01, 0x02, 0x03]
	assert rot_word(w) == [0x01, 0x02, 0x03, 0x00]
	sw = sub_word(w)
	assert all(0 <= b < 256 for b in sw)
	assert rcon_word(1) == [RCON[1], 0, 0, 0]
	assert xor_words([1,2,3,4],[4,3,2,1]) == [5,1,1,5]


def test_key_expansion_round_keys_length():
	key = bytes(range(16))
	rks = key_expansion(key)
	assert isinstance(rks, list)
	assert len(rks) == 11
	for rk in rks:
		assert isinstance(rk, bytes) and len(rk) == 16


def test_add_sub_shift_bytes_roundtrip():
	state = list(range(16))
	original = state[:]
	sub_bytes(state)
	assert state != original
	inv_sub_bytes(state)
	assert state == original

	shift_rows(state)
	assert state != original
	inv_shift_rows(state)
	assert state == original


def test_xtime_and_mul():
	assert xtime(0x57) == ((0x57 << 1) & 0xff) ^ (0x1b if 0x57 & 0x80 else 0x00)
	assert mul(0x57, 0x13) == 0xfe


def test_mix_columns_and_inverse():
	col = [0xdb, 0x13, 0x53, 0x45]
	mixed = mix_single_column(col)
	assert mixed == [0x8e, 0x4d, 0xa1, 0xbc]

	inv = inv_mix_single_column(mixed)
	assert inv == col

	state = [
		0xdb,0x13,0x53,0x45,
		0x00,0x11,0x22,0x33,
		0x44,0x55,0x66,0x77,
		0x88,0x99,0xaa,0xbb,
	]
	before = state[:]
	mix_columns(state)
	assert state != before
	inv_mix_columns(state)
	assert state == before


def test_cipher_and_inv_cipher_block_identity():
	key = bytes(range(16))
	rks = key_expansion(key)
	block = bytes(range(16))
	ciphered = cipher_block(block, rks)
	assert isinstance(ciphered, bytes) and len(ciphered) == 16
	deciphered = inv_cipher_block(ciphered, rks)
	assert deciphered == block

def test_add_round_key_applies_xor():
	state = list(range(16))
	rk = bytes([0xff]*16)
	original = state[:]
	add_round_key(state, rk)
	assert state != original
	add_round_key(state, rk)
	assert state == original


def test_known_vector_against_reference():
	key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
	pt = bytes.fromhex('00112233445566778899aabbccddeeff')
	rks = key_expansion(key)
	ct = cipher_block(pt, rks)
	assert ct.hex() == '69c4e0d86a7b0430d8cdb78070b4c55a'
	assert inv_cipher_block(ct, rks) == pt


if __name__ == '__main__':
	pytest.main([__file__])
