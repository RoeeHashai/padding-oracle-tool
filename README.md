# Padding Oracle Attack Tool

A command-line tool that demonstrates the **CBC Padding Oracle Attack** against DES-encrypted ciphertext.

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
usage: padding_oracle [-h] --ciphertext HEX --iv HEX --key FILE|HEX [--verbose] [--raw]
```

| Flag | Description |
|------|-------------|
| `--ciphertext`, `-c` | Hex-encoded ciphertext (must be a multiple of 8 bytes) |
| `--iv`, `-i` | Hex-encoded IV (exactly 8 bytes) |
| `--key`, `-k` | DES key — path to a raw key file **or** a 16-char hex string |
| `--verbose`, `-v` | Print per-byte progress |
| `--raw` | Write raw decrypted bytes to stdout |

### Examples

```bash
# Key from file, silent output
python padding_oracle.py \
  --ciphertext c0ffeedead1234ab8877665544332211 \
  --iv 0000000000000000 \
  --key key.txt

# Key as hex (706f61697366756e == "poaisfun")
python padding_oracle.py \
  --ciphertext c0ffeedead1234ab8877665544332211 \
  --iv 0000000000000000 \
  --key 706f61697366756e \
  --verbose
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
| `oracle.py` | Standalone oracle script (original class exercise) |
| `requirements.txt` | Python dependencies |
