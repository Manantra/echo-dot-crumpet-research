"""Firmware-free offline tests for the HTTP Range OTA inspector."""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import remote_ota_probe

from test_ota_inventory import fixture

TEST_URL = "https://d1s31zyz7dcc2d.cloudfront.net/synthetic-example.bin"


class RemoteProbeTests(unittest.TestCase):
    def test_synthetic_zip_via_mocked_ranges(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ota.zip"
            fixture(path)
            raw = path.read_bytes()
            def fake_range(url, begin, end):
                self.assertEqual(url, TEST_URL)
                return raw[begin:end + 1]
            with patch.object(remote_ota_probe, "fetch_range", side_effect=fake_range):
                with contextlib.redirect_stdout(io.StringIO()) as printed:
                    findings = remote_ota_probe.probe(TEST_URL)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0][0], "brhgptpl_0")
            self.assertIn("VERIFIED brhgptpl_0", printed.getvalue())

    def test_rejects_non_amazon_host(self):
        with self.assertRaisesRegex(ValueError, "Only official Amazon CDN"):
            remote_ota_probe.probe("https://example.com/fake.bin")

    def test_corrupted_payload_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ota.zip"
            fixture(path, damage=True)
            raw = path.read_bytes()
            with patch.object(remote_ota_probe, "fetch_range",
                              side_effect=lambda url, a, b: raw[a:b + 1]):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                        remote_ota_probe.probe(TEST_URL)


if __name__ == "__main__":
    unittest.main()
