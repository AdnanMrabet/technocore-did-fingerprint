from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

import did_fingerprint as fingerprint


PUBLIC_KEY = bytes(range(32))
DID = fingerprint.did_from_public_key(PUBLIC_KEY)
OTHER_DID = fingerprint.did_from_public_key(bytes(reversed(range(32))))


class DidFingerprintTests(unittest.TestCase):
    def test_canonical_round_trip(self):
        self.assertEqual(fingerprint.public_key_from_did(DID), PUBLIC_KEY)
        self.assertTrue(DID.startswith("did:key:z6Mk"))
        self.assertEqual(len(DID.removeprefix("did:key:")), 48)

    def test_known_raw_key_fingerprint(self):
        info = fingerprint.fingerprint_info(DID)
        self.assertEqual(info["public_key_hex"], PUBLIC_KEY.hex())
        self.assertEqual(info["public_key_sha256_hex"], hashlib.sha256(PUBLIC_KEY).hexdigest())

    def test_openssh_encoding_contains_the_same_key(self):
        info = fingerprint.fingerprint_info(DID)
        _, encoded, comment = info["openssh_public_key"].split()
        blob = base64.b64decode(encoded)
        self.assertTrue(blob.endswith(PUBLIC_KEY))
        self.assertEqual(comment, "technocore-did")
        self.assertTrue(info["openssh_fingerprint"].startswith("SHA256:"))

    def test_invalid_multibase_character_is_rejected(self):
        malformed = DID[:-1] + "0"
        with self.assertRaises(fingerprint.FingerprintError):
            fingerprint.public_key_from_did(malformed)

    def test_wrong_multicodec_is_rejected(self):
        wrong = "did:key:z" + fingerprint.base58btc_encode(b"\x01\x02" + PUBLIC_KEY)
        with self.assertRaisesRegex(fingerprint.FingerprintError, "Ed25519"):
            fingerprint.public_key_from_did(wrong)

    def test_allowlist_allows_exact_match_and_reports_duplicates(self):
        result = fingerprint.check_allowlist(DID, [(2, DID), (4, DID), (5, OTHER_DID)])
        self.assertTrue(result["allowed"])
        self.assertEqual(result["matching_lines"], [2, 4])

    def test_allowlist_denies_missing_did(self):
        result = fingerprint.check_allowlist(DID, [(1, OTHER_DID)])
        self.assertFalse(result["allowed"])
        self.assertEqual(result["matching_lines"], [])

    def test_allowlist_parser_ignores_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "allowlist.txt")
            path.write_text(f"# agents\n\n{DID}\n", encoding="utf-8")
            self.assertEqual(fingerprint.load_allowlist(path), [(3, DID)])

    def test_invalid_allowlist_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "allowlist.txt")
            path.write_text(f"{DID}\nnot-a-did\n", encoding="utf-8")
            with self.assertRaisesRegex(fingerprint.FingerprintError, "line 2"):
                fingerprint.load_allowlist(path)


if __name__ == "__main__":
    unittest.main()
