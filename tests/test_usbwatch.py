"""Synthetic-only tests; the fake sysfs tree and descriptor bytes are fabricated."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import usbwatch
from usbwatch import read, snapshot

SEP = "+"

DESCRIPTORS = bytes.fromhex("12010002020000400d0e00200001010203010902")


def make_device(root):
    dev = Path(root, "9-9")
    dev.mkdir()
    for name, value in {"idVendor": "dead", "idProduct": "beef", "speed": "12",
                        "product": "Fake Device", "bNumConfigurations": "1"}.items():
        (dev / name).write_text(value + "\n")
    (dev / "descriptors").write_bytes(DESCRIPTORS)
    iface = Path(root, "9-9" + SEP + "1.0")
    iface.mkdir()
    for name, value in {"bInterfaceNumber": "00", "bInterfaceClass": "02"}.items():
        (iface / name).write_text(value + "\n")
    return dev


@mock.patch.object(usbwatch, "IFACE_SEP", SEP)
class SnapshotTests(unittest.TestCase):
    def test_read_strips_and_tolerates_missing(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "a").write_text("value\n")
            self.assertEqual(read(str(Path(d, "a"))), "value")
            self.assertIsNone(read(str(Path(d, "missing"))))

    def test_snapshot_collects_attributes_descriptors_and_interfaces(self):
        with tempfile.TemporaryDirectory() as d:
            snap = snapshot(str(make_device(d)))
        self.assertEqual((snap["idVendor"], snap["idProduct"], snap["speed"]), ("dead", "beef", "12"))
        self.assertEqual(snap["product"], "Fake Device")
        self.assertIsNone(snap["serial"])
        self.assertEqual(bytes.fromhex(snap["descriptors_hex"]), DESCRIPTORS)
        iface = snap["interfaces"]["9-9" + SEP + "1.0"]
        self.assertEqual(iface["bInterfaceClass"], "02")
        self.assertIsNone(iface["driver"])

    def test_snapshot_without_descriptors_file(self):
        with tempfile.TemporaryDirectory() as d:
            dev = make_device(d)
            (dev / "descriptors").unlink()
            self.assertIsNone(snapshot(str(dev))["descriptors_hex"])


if __name__ == "__main__":
    unittest.main()
