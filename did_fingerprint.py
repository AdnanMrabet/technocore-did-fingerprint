#!/usr/bin/env python3
"""Inspect canonical Ed25519 did:key fingerprints and local allowlists."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path
from typing import Any


MAX_ALLOWLIST_BYTES = 256 * 1024
MAX_ALLOWLIST_ENTRIES = 4096
ED25519_MULTICODEC = b"\xed\x01"
BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {character: index for index, character in enumerate(BASE58BTC_ALPHABET)}


class FingerprintError(ValueError):
    """A DID or allowlist is malformed or unsafe to process."""


def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def base58btc_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise FingerprintError("base58btc value must be a non-empty string")
    number = 0
    for character in value:
        try:
            digit = BASE58BTC_INDEX[character]
        except KeyError as error:
            raise FingerprintError(f"invalid base58btc character: {character!r}") from error
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


def public_key_from_did(did: str) -> bytes:
    prefix = "did:key:"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise FingerprintError("DID must start with did:key:z6Mk")
    multibase = did[len(prefix) :]
    if len(multibase) != 48 or not multibase.startswith("z6Mk"):
        raise FingerprintError("DID must use the canonical 48-character Ed25519 multibase form")
    decoded = base58btc_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(ED25519_MULTICODEC):
        raise FingerprintError("DID does not contain an Ed25519 public key")
    canonical = "z" + base58btc_encode(decoded)
    if not hmac.compare_digest(canonical, multibase):
        raise FingerprintError("DID multibase encoding is not canonical")
    return decoded[2:]


def did_from_public_key(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise FingerprintError("Ed25519 public key must contain exactly 32 bytes")
    return "did:key:z" + base58btc_encode(ED25519_MULTICODEC + public_key)


def ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def fingerprint_info(did: str) -> dict[str, Any]:
    public_key = public_key_from_did(did)
    algorithm = b"ssh-ed25519"
    ssh_blob = ssh_string(algorithm) + ssh_string(public_key)
    ssh_public = base64.b64encode(ssh_blob).decode("ascii")
    raw_digest = hashlib.sha256(public_key).digest()
    ssh_digest = hashlib.sha256(ssh_blob).digest()
    return {
        "did": did,
        "display": f"{did[:16]}...{did[-8:]}",
        "method": "key",
        "multibase": did.removeprefix("did:key:"),
        "multicodec": "ed25519-pub",
        "multicodec_prefix_hex": ED25519_MULTICODEC.hex(),
        "public_key_hex": public_key.hex(),
        "public_key_sha256_hex": raw_digest.hex(),
        "public_key_sha256_base64url": base64.urlsafe_b64encode(raw_digest)
        .decode("ascii")
        .rstrip("="),
        "openssh_public_key": f"ssh-ed25519 {ssh_public} technocore-did",
        "openssh_fingerprint": "SHA256:"
        + base64.b64encode(ssh_digest).decode("ascii").rstrip("="),
    }


def load_allowlist(path: Path) -> list[tuple[int, str]]:
    resolved = path.expanduser().resolve()
    try:
        raw = resolved.read_bytes()
    except OSError as error:
        raise FingerprintError(f"cannot read allowlist: {error}") from error
    if len(raw) > MAX_ALLOWLIST_BYTES:
        raise FingerprintError("allowlist exceeds the safety limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FingerprintError("allowlist is not valid UTF-8") from error
    entries: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if any(character.isspace() for character in line):
            raise FingerprintError(f"allowlist line {line_number} contains whitespace")
        try:
            public_key_from_did(line)
        except FingerprintError as error:
            raise FingerprintError(f"invalid DID on allowlist line {line_number}: {error}") from error
        entries.append((line_number, line))
        if len(entries) > MAX_ALLOWLIST_ENTRIES:
            raise FingerprintError("allowlist contains too many entries")
    return entries


def check_allowlist(did: str, entries: list[tuple[int, str]]) -> dict[str, Any]:
    public_key_from_did(did)
    matching_lines = [
        line_number
        for line_number, entry in entries
        if hmac.compare_digest(did.encode("ascii"), entry.encode("ascii"))
    ]
    return {
        "did": did,
        "allowed": bool(matching_lines),
        "matching_lines": matching_lines,
        "entries_checked": len(entries),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="decode and fingerprint a DID")
    inspect.add_argument("did")
    allowlist = commands.add_parser("allowlist", help="check a DID against a local allowlist")
    allowlist.add_argument("did")
    allowlist.add_argument("allowlist_file", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            result = fingerprint_info(args.did)
            exit_code = 0
        else:
            result = check_allowlist(args.did, load_allowlist(args.allowlist_file))
            exit_code = 0 if result["allowed"] else 1
    except FingerprintError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
