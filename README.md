# Technocore DID Fingerprint

An offline CLI for decoding canonical Ed25519 `did:key` identifiers into stable,
reviewable fingerprints. It helps agent operators compare identities, build local
allowlists, and inspect public keys without contacting a resolver or exposing any
private key.

This is an independent community tool, not an official FLOP Labs project and not
evidence of guaranteed `$FLOP` eligibility.

## Features

- Validates canonical `did:key:z6Mk...` Ed25519 identifiers.
- Decodes the multibase and Ed25519 multicodec bytes.
- Shows the raw 32-byte public key in hexadecimal.
- Produces SHA-256 fingerprints for the raw key and OpenSSH key blob.
- Produces an interoperable `ssh-ed25519` public-key line.
- Checks a DID against a strict local allowlist using constant-time comparison.
- Runs entirely offline with no third-party dependencies.

## Inspect a DID

Python 3.12 is recommended.

```bash
python did_fingerprint.py inspect did:key:z6Mk...
```

The JSON output contains:

- the canonical DID and shortened display form;
- multicodec name and bytes;
- raw Ed25519 public key;
- raw-key SHA-256 fingerprint;
- OpenSSH public key and standard `SHA256:` fingerprint.

## Check an allowlist

Create a UTF-8 text file containing one complete DID per line. Blank lines and
lines beginning with `#` are ignored.

```text
# production agents
did:key:z6Mk...
did:key:z6Mk...
```

Then run:

```bash
python did_fingerprint.py allowlist did:key:z6Mk... trusted-dids.txt
```

The command exits with status `0` when allowed, `1` when not allowed, and `2` for
malformed input. Every non-comment allowlist entry is validated; a bad entry
causes the whole check to fail closed.

## Security notes

- A DID is a public key identifier, not a human identity or blockchain wallet.
- A matching allowlist entry means only that the exact public key was listed.
- The tool never performs network requests and never reads `identity.pem`.
- Keep private PEM files and passphrases separate from public DID allowlists.
- Use complete DIDs for authorization. Short display forms are for humans only.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers canonical round trips, known key bytes, OpenSSH encoding,
fingerprint stability, malformed multibase data, allow/deny decisions, duplicate
entries, and fail-closed invalid allowlists.

## License

MIT
