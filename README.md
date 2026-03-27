# Padding Oracle Attack Tool

A command-line tool that demonstrates the **CBC Padding Oracle Attack** against DES-CBC or AES-CBC encrypted ciphertext.

## What is a Padding Oracle Attack?

A padding oracle is a system that decrypts ciphertext and reveals — through its response — whether the decrypted bytes have valid PKCS#7 padding. An attacker can exploit this to recover the full plaintext **without knowing the key**, by sending crafted ciphertexts and observing the oracle's yes/no responses.

This tool simulates both sides of the attack:
- **Oracle** — the vulnerable decryption function (embedded, no separate process)
- **Attacker** — iterates byte-by-byte, brute-forcing the intermediate decryption values

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```
usage: padding_oracle [-h] (--ciphertext HEX | --plaintext TEXT | --plaintext-hex HEX)
                      [--cipher {des,aes}] [--iv HEX] --key FILE|HEX [--verbose] [--raw]
```

| Flag | Description |
|------|-------------|
| `--ciphertext`, `-c` | Hex-encoded ciphertext to attack |
| `--plaintext`, `-p` | UTF-8 plaintext to encrypt then attack (full demo) |
| `--plaintext-hex` | Hex-encoded plaintext bytes to encrypt then attack |
| `--cipher` | Block cipher: `des` (default) or `aes` |
| `--iv`, `-i` | Hex-encoded IV. Required with `--ciphertext`; random if omitted in plaintext modes |
| `--key`, `-k` | Cipher key — path to a raw key file **or** a hex string of the correct length |
| `--verbose`, `-v` | Print per-byte progress and live oracle call count |
| `--raw` | Write raw decrypted bytes to stdout |

### Key sizes

| Cipher | Block size | Key size |
|--------|-----------|----------|
| DES | 8 bytes | 8 bytes (16 hex chars) |
| AES | 16 bytes | 16 / 24 / 32 bytes |

### Examples

```bash
# Attack a known DES ciphertext
python padding_oracle.py \
  --ciphertext c0ffeedead1234ab \
  --iv 0000000000000000 \
  --key key.txt

# Encrypt plaintext with DES then attack it (full demo)
python padding_oracle.py --plaintext 'hello world' --key key.txt --verbose

# Same but with AES
python padding_oracle.py --plaintext 'hello world' --key aes_key.txt --cipher aes --verbose

# Binary plaintext via hex
python padding_oracle.py --plaintext-hex 48656c6c6f --key key.txt

# Key as hex string instead of file (DES: 8 bytes = 16 hex chars)
python padding_oracle.py \
  --ciphertext c0ffeedead1234ab \
  --iv 0000000000000000 \
  --key 706f61697366756e
```

## How it works

For each ciphertext block **C2**, the attacker crafts a 2-block payload `XJ || C2` and queries the oracle with a zero IV. In CBC mode, the oracle decrypts:

```
P2 = decrypt(C2) XOR XJ
```

The attacker brute-forces `XJ` byte-by-byte (right to left) until the oracle reports valid padding. When byte `i` is found:

```
plaintext[i] = padding_value XOR C_prev[i] XOR XJ[i]
```

Complexity: at most `256 × block_size × num_blocks` oracle queries.

## Files

| File | Purpose |
|------|---------|
| `padding_oracle.py` | Main CLI tool (oracle + attack) |
| `requirements.txt` | Python dependencies |
