#!/usr/bin/env python3
"""
SecureVault - File Encryptor/Decryptor
Encryption: AES-256-GCM (authenticated, military-grade)
Key Derivation: Argon2id (strongest password-to-key function available)
Supports: any file type — images, video, Word, Excel, PDF, etc.
"""

import os
import sys
import struct
import secrets
import argparse
import getpass
from pathlib import Path

# --- Dependency check -----------------------------------------------------------
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("[ERROR] Install dependencies: pip install cryptography argon2-cffi")

try:
    from argon2.low_level import hash_secret_raw, Type
except ImportError:
    sys.exit("[ERROR] Install dependencies: pip install argon2-cffi")

# -------------------------------------------------------------------------------

MAGIC = b"SVLT\x01\x00\x00\x00"   # SecureVault v1 magic header
VERSION = 1

# Argon2id parameters (OWASP 2023 recommendation — high security)
ARGON2_TIME_COST   = 3       # iterations
ARGON2_MEMORY_COST = 65536   # 64 MB RAM
ARGON2_PARALLELISM = 4       # parallel threads
ARGON2_HASH_LEN    = 32      # 256-bit key output

SALT_LEN  = 32   # 256-bit salt
NONCE_LEN = 12   # 96-bit nonce (AES-GCM standard)
CHUNK_SIZE = 64 * 1024   # 64 KB per chunk (enables large file support)

# ANSI color codes
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# -------------------------------------------------------------------------------
# Core cryptographic primitives
# -------------------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def _chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """Derive per-chunk nonce: base XOR chunk_index (big-endian, 12 bytes)."""
    idx_bytes = index.to_bytes(NONCE_LEN, "big")
    return bytes(a ^ b for a, b in zip(base_nonce, idx_bytes))


# -------------------------------------------------------------------------------
# Encrypted file format
# -------------------------------------------------------------------------------
#
#   [ 8 bytes ] Magic header + version  (SVLT\x01\x00\x00\x00)
#   [ 1 byte  ] Original filename length (max 255 chars)
#   [ N bytes ] Original filename (UTF-8)
#   [ 32 bytes] Salt (Argon2id)
#   [ 12 bytes] Base nonce (AES-256-GCM)
#   [ 8 bytes ] Number of chunks (big-endian uint64)
#   For each chunk:
#     [ 4 bytes ] Ciphertext length including 16-byte GCM tag (big-endian uint32)
#     [ M bytes ] Ciphertext + tag
#
# -------------------------------------------------------------------------------

def encrypt_file(src_path: Path, dst_path: Path, password: str) -> None:
    """Encrypt a file to dst_path using AES-256-GCM + Argon2id."""
    salt       = secrets.token_bytes(SALT_LEN)
    base_nonce = secrets.token_bytes(NONCE_LEN)

    print(f"  {CYAN}Deriving key with Argon2id...{RESET}", end="", flush=True)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    print(f" {GREEN}done{RESET}")

    filename_bytes = src_path.name.encode("utf-8")[:255]

    # Read source in chunks, encrypt each chunk
    chunks = []
    file_size = src_path.stat().st_size
    processed = 0
    chunk_index = 0

    with open(src_path, "rb") as f:
        while True:
            plaintext = f.read(CHUNK_SIZE)
            if not plaintext:
                break
            nonce      = _chunk_nonce(base_nonce, chunk_index)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            chunks.append(ciphertext)
            processed += len(plaintext)
            chunk_index += 1
            _print_progress(processed, file_size)

    print()

    # Write encrypted file
    with open(dst_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("B", len(filename_bytes)))
        f.write(filename_bytes)
        f.write(salt)
        f.write(base_nonce)
        f.write(struct.pack(">Q", len(chunks)))
        for chunk in chunks:
            f.write(struct.pack(">I", len(chunk)))
            f.write(chunk)


def decrypt_file(src_path: Path, dst_path: Path | None, password: str) -> Path:
    """Decrypt an encrypted file. Returns the output path."""
    with open(src_path, "rb") as f:
        # Read and validate header
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Not a SecureVault encrypted file (invalid magic header).")

        fname_len      = struct.unpack("B", f.read(1))[0]
        original_fname = f.read(fname_len).decode("utf-8")
        salt           = f.read(SALT_LEN)
        base_nonce     = f.read(NONCE_LEN)
        num_chunks     = struct.unpack(">Q", f.read(8))[0]

        print(f"  {CYAN}Deriving key with Argon2id...{RESET}", end="", flush=True)
        key    = derive_key(password, salt)
        aesgcm = AESGCM(key)
        print(f" {GREEN}done{RESET}")

        # Determine output path
        if dst_path is None:
            dst_path = src_path.parent / original_fname

        total_ct_size = 0
        chunk_data = []
        for i in range(num_chunks):
            ct_len = struct.unpack(">I", f.read(4))[0]
            ct     = f.read(ct_len)
            chunk_data.append((i, ct))
            total_ct_size += ct_len

    # Decrypt chunks and write output
    with open(dst_path, "wb") as out:
        processed = 0
        for i, ct in chunk_data:
            nonce     = _chunk_nonce(base_nonce, i)
            try:
                plaintext = aesgcm.decrypt(nonce, ct, None)
            except Exception:
                dst_path.unlink(missing_ok=True)
                raise ValueError(
                    "Decryption failed — wrong password or corrupted file."
                )
            out.write(plaintext)
            processed += len(ct)
            _print_progress(processed, total_ct_size)

    print()
    return dst_path


# -------------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------------

def _print_progress(done: int, total: int) -> None:
    if total == 0:
        return
    pct   = min(100, int(done * 100 / total))
    bar   = "█" * (pct // 5) + "░" * (20 - pct // 5)
    size  = _human_size(done)
    print(f"\r  [{bar}] {pct:3d}%  {size}", end="", flush=True)


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _get_password(confirm: bool = False) -> str:
    password = getpass.getpass("  Enter password/key: ")
    if not password:
        sys.exit(f"{RED}[ERROR] Password cannot be empty.{RESET}")
    if confirm:
        confirm_pw = getpass.getpass("  Confirm password:    ")
        if password != confirm_pw:
            sys.exit(f"{RED}[ERROR] Passwords do not match.{RESET}")
    return password


def _banner() -> None:
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════╗
║         SecureVault — File Encryptor v1.0        ║
║  Encryption : AES-256-GCM  (military-grade)      ║
║  Key Deriv. : Argon2id     (OWASP recommended)   ║
╚══════════════════════════════════════════════════╝{RESET}""")


# -------------------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------------------

def cmd_encrypt(args: argparse.Namespace) -> None:
    sources = [Path(p) for p in args.files]
    for src in sources:
        if not src.exists():
            print(f"{RED}[SKIP] File not found: {src}{RESET}")
            continue
        dst = Path(args.output) if args.output and len(sources) == 1 else src.with_suffix(src.suffix + ".enc")
        print(f"\n{BOLD}Encrypting:{RESET} {src}  →  {dst}")
        password = args.password or _get_password(confirm=True)
        try:
            encrypt_file(src, dst, password)
            print(f"  {GREEN}[OK]{RESET} Saved: {dst}  ({_human_size(dst.stat().st_size)})")
        except Exception as e:
            print(f"  {RED}[ERROR] {e}{RESET}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    sources = [Path(p) for p in args.files]
    for src in sources:
        if not src.exists():
            print(f"{RED}[SKIP] File not found: {src}{RESET}")
            continue
        dst = Path(args.output) if args.output and len(sources) == 1 else None
        print(f"\n{BOLD}Decrypting:{RESET} {src}")
        password = args.password or _get_password(confirm=False)
        try:
            out = decrypt_file(src, dst, password)
            print(f"  {GREEN}[OK]{RESET} Restored: {out}  ({_human_size(out.stat().st_size)})")
        except Exception as e:
            print(f"  {RED}[ERROR] {e}{RESET}")


def cmd_info(args: argparse.Namespace) -> None:
    for fp in args.files:
        p = Path(fp)
        if not p.exists():
            print(f"{RED}[SKIP] {p} not found{RESET}")
            continue
        try:
            with open(p, "rb") as f:
                magic = f.read(len(MAGIC))
                if magic != MAGIC:
                    print(f"{YELLOW}[!]{RESET} {p}: not a SecureVault file")
                    continue
                fname_len      = struct.unpack("B", f.read(1))[0]
                original_fname = f.read(fname_len).decode("utf-8")
                f.read(SALT_LEN + NONCE_LEN)
                num_chunks = struct.unpack(">Q", f.read(8))[0]
            print(f"{GREEN}[INFO]{RESET} {p}")
            print(f"       Original filename : {original_fname}")
            print(f"       Chunks            : {num_chunks}")
            print(f"       Encrypted size    : {_human_size(p.stat().st_size)}")
        except Exception as e:
            print(f"{RED}[ERROR] {p}: {e}{RESET}")


def main() -> None:
    _banner()

    parser = argparse.ArgumentParser(
        prog="file_encryptor",
        description="SecureVault — AES-256-GCM file encryptor/decryptor",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # encrypt
    p_enc = sub.add_parser("encrypt", aliases=["enc", "e"], help="Encrypt one or more files")
    p_enc.add_argument("files", nargs="+", help="File(s) to encrypt")
    p_enc.add_argument("-o", "--output", help="Output path (single file only)")
    p_enc.add_argument("-p", "--password", help="Password/key (avoid: will appear in shell history)")
    p_enc.set_defaults(func=cmd_encrypt)

    # decrypt
    p_dec = sub.add_parser("decrypt", aliases=["dec", "d"], help="Decrypt one or more .enc files")
    p_dec.add_argument("files", nargs="+", help="File(s) to decrypt (*.enc)")
    p_dec.add_argument("-o", "--output", help="Output path (single file only)")
    p_dec.add_argument("-p", "--password", help="Password/key")
    p_dec.set_defaults(func=cmd_decrypt)

    # info
    p_inf = sub.add_parser("info", help="Show metadata of an encrypted file (no key required)")
    p_inf.add_argument("files", nargs="+")
    p_inf.set_defaults(func=cmd_info)

    args = parser.parse_args()
    args.func(args)
    print()


if __name__ == "__main__":
    main()
