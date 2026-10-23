#!/usr/bin/python3
import io
import pytest
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from xor import (
	pad_block,
	bytes_from_hex,
	hex_from_bytes,
	xor_block,
)

def test_pad_and_hex_helpers():
	assert pad_block(b"ab", 4) == b"ab" + b"\x00"*2
	assert hex_from_bytes(b"\x01\x0a") == "010a"
	assert bytes_from_hex("010a") == b"\x01\x0a"


def test_xor_block_roundtrip():
	key = bytes.fromhex('576861742069732064656164206d6179206e6576657220646965')
	data = b"You know nothing, Jon Snow"
	out = bytearray()
	for i in range(0, len(data), len(key)):
		blk = data[i:i+len(key)]
		if len(blk) < len(key):
			blk = pad_block(blk, len(key))
		out += xor_block(blk, key)

	dec = bytearray()
	for i in range(0, len(out), len(key)):
		blk = out[i:i+len(key)]
		dec += xor_block(blk, key)

	assert dec.rstrip(b"\x00") == data
