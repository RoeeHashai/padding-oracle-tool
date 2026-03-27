#!/usr/bin/env python3
"""
Padding Oracle Attack Tool

Demonstrates a padding oracle attack against DES-CBC or AES-CBC encrypted ciphertext.
The oracle is an in-process function — no subprocess overhead.
"""

import argparse
import os
import sys
import time
from Cryptodome.Cipher import AES, DES
from Cryptodome.Util.Padding import pad, unpad

# Supported ciphers: name -> (module, block_size, valid_key_sizes)
CIPHERS = {
    "des": (DES, DES.block_size, [8]),
    "aes": (AES, AES.block_size, [16, 24, 32]),
}


# ---------------------------------------------------------------------------
# Oracle (simulates the vulnerable server)
# ---------------------------------------------------------------------------

def oracle(cipher_module, key: bytes, ciphertext: bytes, iv: bytes, call_counter: list) -> bool:
    """
    Returns True if ciphertext decrypts to PKCS7-validly-padded plaintext.
    call_counter is a one-element list used to track total oracle invocations.
    """
    call_counter[0] += 1
    block_size = cipher_module.block_size
    c = cipher_module.new(key, cipher_module.MODE_CBC, iv)
    decrypted = c.decrypt(ciphertext)
    try:
        unpad(decrypted, block_size)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Attack
# ---------------------------------------------------------------------------

def _xor3(a: int, b: int, c: int) -> int:
    return a ^ b ^ c


def padding_oracle_attack(
    cipher_module,
    key: bytes,
    ciphertext: bytes,
    iv: bytes,
    verbose: bool = False,
) -> tuple[bytes, int]:
    """
    Recovers plaintext from CBC ciphertext using a padding oracle.
    Returns (plaintext_bytes, total_oracle_calls).
    """
    block_size = cipher_module.block_size
    zero_iv = bytes(block_size)
    num_blocks = len(ciphertext) // block_size
    plaintext_blocks: list[bytes] = []
    call_counter = [0]
    recovered_so_far = ""

    for block_i in range(num_blocks):
        block_start = block_i * block_size
        C2 = ciphertext[block_start : block_start + block_size]
        C_prev = iv if block_i == 0 else ciphertext[block_start - block_size : block_start]

        XJ = bytearray(block_size)
        XJ_C2 = XJ + bytearray(C2)
        plaintext_block = bytearray(block_size)

        for byte_idx in reversed(range(block_size)):
            padding_val = block_size - byte_idx

            if verbose:
                print(
                    f"\r[*] Block {block_i + 1}/{num_blocks}  "
                    f"byte {block_size - byte_idx}/{block_size}  "
                    f"calls so far: {call_counter[0]}",
                    end="",
                    flush=True,
                )

            # Step 1 — brute-force XJ[byte_idx]
            for candidate in range(256):
                XJ_C2[byte_idx] = candidate
                if oracle(cipher_module, key, bytes(XJ_C2), zero_iv, call_counter):
                    break
            else:
                raise RuntimeError(f"No valid byte found at block {block_i}, position {byte_idx}")

            # Step 2 — recover plaintext byte
            plaintext_block[byte_idx] = _xor3(padding_val, C_prev[byte_idx], XJ_C2[byte_idx])

            # Step 3 — prepare XJ for next iteration
            next_pad = padding_val + 1
            for j in range(block_size - byte_idx):
                pos = (block_size - 1) - j
                XJ_C2[pos] = _xor3(next_pad, C_prev[pos], plaintext_block[pos])

        if verbose:
            print()

        plaintext_blocks.append(bytes(plaintext_block))

        # Live block reveal
        block_text = bytes(plaintext_block).decode("utf-8", errors="replace")
        recovered_so_far += block_text
        print(f"[+] Recovering : {recovered_so_far!r}", end="\r", flush=True)

    print()  # finish the recovering line
    return b"".join(plaintext_blocks), call_counter[0]


# ---------------------------------------------------------------------------
# Encryption (for the demo / plaintext-input mode)
# ---------------------------------------------------------------------------

def encrypt(cipher_module, key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    block_size = cipher_module.block_size
    c = cipher_module.new(key, cipher_module.MODE_CBC, iv)
    return c.encrypt(pad(plaintext, block_size))


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def load_key(key_arg: str, valid_sizes: list[int]) -> bytes:
    """
    Accepts a path to a raw key file, or a hex string of the right length.
    valid_sizes: accepted key lengths in bytes.
    """
    # Try as hex string
    for size in valid_sizes:
        if len(key_arg) == size * 2:
            try:
                return bytes.fromhex(key_arg)
            except ValueError:
                break

    # Fall back to file
    try:
        with open(key_arg, "rb") as f:
            key = f.read().strip()
    except FileNotFoundError:
        raise ValueError(f"Key file not found: {key_arg}")

    if len(key) not in valid_sizes:
        raise ValueError(
            f"Key must be one of {valid_sizes} bytes, got {len(key)} (file: {key_arg})"
        )
    return key


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="padding_oracle",
        description="Padding Oracle Attack — recovers CBC plaintext without the key.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Attack a known DES ciphertext
  %(prog)s --ciphertext c0ffeedead1234ab --iv 0000000000000000 --key key.txt

  # Encrypt plaintext first, then attack it (full demo)
  %(prog)s --plaintext 'hello world' --key key.txt

  # Same but with AES
  %(prog)s --plaintext 'hello world' --key aeskey.txt --cipher aes --verbose

  # Binary plaintext via hex
  %(prog)s --plaintext-hex 48656c6c6f --key key.txt
""",
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--ciphertext", "-c",
        metavar="HEX",
        help="hex-encoded ciphertext to attack",
    )
    input_group.add_argument(
        "--plaintext", "-p",
        metavar="TEXT",
        help="UTF-8 plaintext to encrypt then attack (full demo)",
    )
    input_group.add_argument(
        "--plaintext-hex",
        metavar="HEX",
        help="hex-encoded plaintext bytes to encrypt then attack",
    )

    parser.add_argument(
        "--cipher",
        choices=CIPHERS.keys(),
        default="des",
        help="block cipher to use (default: des)",
    )
    parser.add_argument(
        "--iv", "-i",
        metavar="HEX",
        default=None,
        help="hex-encoded IV. Required with --ciphertext; random if omitted in plaintext modes",
    )
    parser.add_argument(
        "--key", "-k",
        required=True,
        metavar="FILE|HEX",
        help="cipher key — path to a raw key file OR a hex string of the correct length",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="print per-byte progress and oracle call count",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="write raw decrypted bytes to stdout instead of UTF-8 text",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    cipher_module, block_size, valid_key_sizes = CIPHERS[args.cipher]

    # Load key
    try:
        key = load_key(args.key, valid_key_sizes)
    except ValueError as exc:
        parser.error(str(exc))

    # Resolve IV
    if args.iv is not None:
        try:
            iv = bytes.fromhex(args.iv)
        except ValueError:
            parser.error(f"--iv is not valid hex: {args.iv!r}")
        if len(iv) != block_size:
            parser.error(f"IV must be {block_size} bytes ({block_size * 2} hex chars) for {args.cipher.upper()}, got {len(iv)}")
    else:
        iv = None

    # --- Plaintext modes: encrypt first ---
    plaintext_input: bytes | None = None
    if args.plaintext is not None:
        plaintext_input = args.plaintext.encode("utf-8")
    elif args.plaintext_hex is not None:
        try:
            plaintext_input = bytes.fromhex(args.plaintext_hex)
        except ValueError:
            parser.error(f"--plaintext-hex is not valid hex: {args.plaintext_hex!r}")

    if plaintext_input is not None:
        if iv is None:
            iv = os.urandom(block_size)
        ciphertext = encrypt(cipher_module, key, plaintext_input, iv)
        label = repr(args.plaintext) if args.plaintext else f"0x{args.plaintext_hex}"
        print(f"[+] Cipher     : {args.cipher.upper()}-CBC")
        print(f"[+] Plaintext  : {label}")
        print(f"[+] IV         : {iv.hex()}")
        print(f"[+] Ciphertext : {ciphertext.hex()}")
        print()

    # --- Ciphertext mode ---
    else:
        if iv is None:
            parser.error("--iv is required when using --ciphertext")
        try:
            ciphertext = bytes.fromhex(args.ciphertext)
        except ValueError:
            parser.error(f"--ciphertext is not valid hex: {args.ciphertext!r}")
        if len(ciphertext) == 0 or len(ciphertext) % block_size != 0:
            parser.error(
                f"Ciphertext length ({len(ciphertext)} bytes) must be a "
                f"non-zero multiple of {block_size} ({args.cipher.upper()} block size)"
            )

    if args.verbose:
        print(f"[*] Blocks     : {len(ciphertext) // block_size}")
        print(f"[*] Max calls  : {len(ciphertext) // block_size * block_size * 256}")

    # Run the attack
    t_start = time.perf_counter()
    try:
        plaintext_raw, call_count = padding_oracle_attack(
            cipher_module, key, ciphertext, iv, verbose=args.verbose
        )
    except RuntimeError as exc:
        print(f"[!] Attack failed: {exc}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.perf_counter() - t_start

    print(f"[*] Oracle calls: {call_count}  |  time: {elapsed:.2f}s")

    # Output
    if args.raw:
        sys.stdout.buffer.write(plaintext_raw)
    else:
        try:
            plaintext = unpad(plaintext_raw, block_size)
        except ValueError:
            plaintext = plaintext_raw
        print(f"[+] Recovered  : {plaintext.decode('utf-8', errors='replace')!r}")


if __name__ == "__main__":
    main()
