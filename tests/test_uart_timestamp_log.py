"""Synthetic-only tests; a fake serial port stands in for hardware."""
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import uart_timestamp_log as logger


class FakePort:
    chunks = []
    opened = []

    def __init__(self, port, baud, timeout=None):
        FakePort.opened.append((port, baud))

    def read(self, size):
        return FakePort.chunks.pop(0) if FakePort.chunks else b""

    def close(self):
        pass


class HelperTests(unittest.TestCase):
    def test_printable_masks_non_text(self):
        self.assertEqual(logger.printable(b"ok\x00\xff\tgo\r"), "ok..\tgo.")

    def test_stamp_format(self):
        self.assertRegex(logger.stamp(0.0), r"^\d\d:\d\d:\d\d\.\d{3}$")


class LoggerTests(unittest.TestCase):
    def run_logger(self, chunks):
        FakePort.chunks, FakePort.opened = list(chunks), []
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(sys.modules, {"serial": types.SimpleNamespace(Serial=FakePort)}):
            logger.main(["--out-dir", d, "--seconds", "0.3", "--name", "t", "--baud", "115200"])
            raw = next(Path(d).glob("*.raw")).read_bytes()
            lines = next(Path(d).glob("*.txt")).read_text().splitlines()
        return raw, lines

    def test_raw_bytes_saved_exactly_and_lines_stamped(self):
        data = [b"first li", b"ne\r\nsecond\n", b"\x00\xffbin\n"]
        raw, lines = self.run_logger(data)
        self.assertEqual(raw, b"".join(data))
        self.assertEqual(FakePort.opened, [("COM3", 115200)])
        self.assertTrue(lines[0].startswith("# start "))
        body = [ln.split(" | ", 1)[1] for ln in lines[1:]]
        self.assertEqual(body, ["first line", "second", "..bin"])

    def test_refuses_missing_output_directory(self):
        with self.assertRaises(SystemExit):
            logger.main(["--out-dir", "no-such-directory-here"])


if __name__ == "__main__":
    unittest.main()
