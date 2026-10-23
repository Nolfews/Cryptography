#!/usr/bin/python3
from typing import List, Union

def pad_block(b: bytes, block_size: int) -> bytes:
	if len(b) >= block_size:
		return b
	return b + b"\x00" * (block_size - len(b))


def bytes_from_hex(s: Union[str, bytes]) -> bytes:
	"""Convert hex string to bytes in normal order (for tests)."""
	if isinstance(s, bytes):
		try:
			s = s.decode('utf-8')
		except Exception:
			s = s.decode('latin-1')

	s = ''.join(s.strip().split())
	if s.startswith(('0x', '0X')):
		s = s[2:]
	b = bytes.fromhex(s)
	return b


def hex_from_bytes(b: bytes) -> str:
	"""Convert bytes to hex string in normal order (for tests)."""
	return b.hex()


def bytes_from_hex_le(s: Union[str, bytes]) -> bytes:
	if isinstance(s, bytes):
		try:
			s = s.decode('utf-8')
		except Exception:
			s = s.decode('latin-1')
	s = ''.join(s.strip().split())
	if s.startswith(('0x', '0X')):
		s = s[2:]
	b = bytes.fromhex(s)
	return b[::-1]


def hex_from_bytes_le(b: bytes) -> str:
	return ''.join(f"{x:02x}" for x in b[::-1])


def xor_block(block: bytes, key: bytes) -> bytes:
	return bytes([b ^ key[i % len(key)] for i, b in enumerate(block)])


