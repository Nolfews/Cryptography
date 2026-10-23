# my_pgp — simple PGP-like command line tool (xor / aes / rsa)

This repository contains simple implementations of several cryptographic primitives (XOR, AES-128, RSA) and a small command line program called `my_pgp` to encrypt/decrypt messages read from standard input.

Purpose
-------
The project is intended for learning: it demonstrates basic building blocks of symmetric and asymmetric encryption and a tiny CLI wrapper that combines them in PGP-like modes.

Quick usage
-----------
Run the program with:

```
./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]
```

For detailed help, run:

```
./my_pgp -h
```

Arguments
---------
CRYPTO_SYSTEM
- `xor` : XOR-based symmetric cipher
- `aes` : AES-128 symmetric cipher
- `rsa` : RSA asymmetric cipher
- `pgp-xor` : RSA + XOR combined mode
- `pgp-aes` : RSA + AES-128 combined mode

MODE
- `-c` : encrypt (MESSAGE provided is plaintext)
- `-d` : decrypt (MESSAGE provided is ciphertext)
- `-g P Q` : RSA only — generate a public/private key pair from primes P and Q (no MESSAGE is read)

OPTIONS
- `-b` : single-block mode (for `xor`, `aes`, `pgp-*`). In this mode the MESSAGE and the symmetric key must have the same size.

key
: the key used to encrypt/decrypt. Not compatible with `-g`. For symmetric modes the key is passed as hex.

Example
-------
Encrypt and decrypt a small message with AES single-block mode:

```
$ echo "All men must die" > message
$ ./my_pgp aes -c -b 57696e74657220697320636f6d696e67 < message > ciphered
$ cat -e ciphered
744ce22c385958348f0df26eceb62eef$
$ ./my_pgp aes -d -b 57696e74657220697320636f6d696e67 < ciphered | cat -e
All men must die$
```

Tests
-----
Unit tests are located in the `tests/` directory. A convenience script `tests.sh` is provided to run the test suite. To run the tests locally:

```
chmod +x tests.sh
./tests.sh
```

The script runs `pytest` against the tests. If `pytest` is not installed, install it via your package manager or `pip install pytest`.
