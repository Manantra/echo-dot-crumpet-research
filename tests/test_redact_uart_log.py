"""Synthetic-only tests; every identifier below is fabricated."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from redact_uart_log import MASK, main, redact_bytes, redact_line


class RuleTests(unittest.TestCase):
    def test_mac_colon_and_dash(self):
        for mac in ("aa:bb:cc:11:22:33", "AA-BB-CC-11-22-33"):
            line, hits = redact_line(f"bt addr {mac} ok")
            self.assertNotIn(mac, line)
            self.assertIn(MASK, line)
            self.assertTrue(hits)

    def test_serial_and_dsn_keyed(self):
        line, _ = redact_line("androidboot.serialno=G090AB12CD34EF56 dsn: G090AB12CD34EF56")
        self.assertNotIn("G090AB12", line)
        self.assertIn("serialno=" + MASK, line)

    def test_dsn_like_bare_token(self):
        line, hits = redact_line("device G090AB12CD34EF56 booted")
        self.assertEqual(line, f"device {MASK} booted")
        self.assertEqual(hits, ["dsn_like_token"])

    def test_ssid_with_spaces_and_quotes(self):
        self.assertEqual(redact_line("ssid=My Home WiFi")[0], "ssid=" + MASK)
        self.assertEqual(redact_line('SSID: "Cafe Net" ch 6')[0], "SSID: " + MASK + " ch 6")

    def test_key_token_password_masked_keep_label(self):
        line, _ = redact_line("auth_token=abcdef0123 password: hunter2 root_key=deadbeef")
        for secret in ("abcdef0123", "hunter2", "deadbeef"):
            self.assertNotIn(secret, line)
        self.assertIn("password: " + MASK, line)

    def test_email_and_guid(self):
        line, hits = redact_line("acct me@example.com guid 123e4567-e89b-12d3-a456-426614174000")
        self.assertEqual(line, f"acct {MASK} guid {MASK}")
        self.assertEqual(sorted(hits), ["email_account", "guid"])

    def test_mediatek_hardware_ids_and_lastpc(self):
        cases = {
            "[TZ_INIT] MEID : 0x11, 0x22, 0x33, 0x44": "[TZ_INIT] MEID : " + MASK,
            "[TZ_INIT] hwuid[2] : 0x01234567": "[TZ_INIT] hwuid[2] : " + MASK,
            "[TZ_INIT] HRID[0] : 0x89ABCDEF": "[TZ_INIT] HRID[0] : " + MASK,
            "lastpc[0][3] = 12345678": "lastpc[0][3] = " + MASK,
            "[3074] LASTPC[1][7] = abcdef01": "[3074] LASTPC[1][7] = " + MASK,
        }
        for raw, want in cases.items():
            line, hits = redact_line(raw)
            self.assertEqual(line, want)
            self.assertEqual(hits, ["hw_identifier"])

    def test_boot_banners_and_build_strings_survive(self):
        for keep in ("[PLFM] Build Time: 20231103_072325",
                     "Fire OS 6.5.7.1 HW code: 0x8167",
                     "DRAM size 0x10000000 at 0x40000000",
                     "NAND ID: C2 DC 90 A2 57 03 MX30LF4G28AD",
                     "[TZ_INIT] atf_log_port : 0x11005000",
                     "NAND INFO:mtk_nand_flash_get 429: nand id: 98 DC 90 26 76 16"):
            self.assertEqual(redact_line(keep), (keep, []))

    def test_idempotent(self):
        once, _ = redact_line("mac=aa:bb:cc:11:22:33 serial: ABC123")
        self.assertEqual(redact_line(once), (once, []))


class FileTests(unittest.TestCase):
    RAW = (b"line one\r\nserial: SN12345 here\r\n\xff\xfe garbage\n"
           b"sha " + b"a" * 64 + b"\nlast no newline mac aa:bb:cc:11:22:33")

    def test_line_structure_and_endings_preserved(self):
        out, rep = redact_bytes(self.RAW)
        self.assertEqual(out.count(b"\n"), self.RAW.count(b"\n"))
        self.assertEqual(len(out.splitlines()), len(self.RAW.splitlines()))
        self.assertIn(b"\r\n", out)
        self.assertIn(b"\xff\xfe garbage", out)         # non-text bytes round-trip
        self.assertNotIn(b"SN12345", out)
        self.assertNotIn(b"aa:bb:cc", out)

    def test_long_hex_reviewed_not_masked(self):
        out, rep = redact_bytes(self.RAW)
        self.assertIn(b"a" * 64, out)
        self.assertEqual(rep["review_long_hex_lines"], [4])

    def test_cli_never_touches_or_overwrites(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d, "boot.log"); src.write_bytes(self.RAW)
            self.assertEqual(main([str(src)]), 0)
            self.assertEqual(src.read_bytes(), self.RAW)             # original intact
            dst = Path(d, "boot.redacted.log")
            self.assertTrue(dst.exists())
            first = dst.read_bytes()
            with self.assertRaises(SystemExit):                      # refuses overwrite
                main([str(src)])
            self.assertEqual(dst.read_bytes(), first)
            with self.assertRaises(SystemExit):                      # refuses output==input
                main([str(src), "-o", str(src)])
            self.assertEqual(src.read_bytes(), self.RAW)

    def test_report_has_no_secret_values(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d, "x.log"); src.write_bytes(b"serial: TOPSECRET99\n")
            rep = Path(d, "r.txt")
            main([str(src), "--report", str(rep)])
            self.assertNotIn("TOPSECRET99", rep.read_text())


if __name__ == "__main__":
    unittest.main()
