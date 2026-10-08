#!/usr/bin/env python3
"""Size/geometry sanity check for pre-existing Crumpet MX30LF4G28AD NAND dumps.

Based on historical Crumpet UART chip identification and the manufacturer's
MX30LF4G28AD SLC NAND 4096+256 bytes/page, 64 pages/block, 2048 blocks.
Stats local file length only; never opens the device, flashes NAND, or writes.
Data-only and interleaved data+OOB dumps are NOT interchangeable.
"""
import argparse
from pathlib import Path

CHIP_MODEL = "MX30LF4G28AD"
BLOCK_COUNT = 2048
PAGES_PER_BLOCK = 64
DATA_BYTES = 4096
OOB_BYTES = 256
RAW_PAGE_BYTES = DATA_BYTES + OOB_BYTES
TOTAL_PAGES = BLOCK_COUNT * PAGES_PER_BLOCK
DATA_ONLY_SIZE = TOTAL_PAGES * DATA_BYTES
DATA_PLUS_OOB_SIZE = TOTAL_PAGES * RAW_PAGE_BYTES
# Observed in old Crumpet UART (not an exhaustive bad-block inventory).
HISTORIC_BBT_PAGES = (131008, 130944)


def describe_size(size):
    if size < 0:
        raise ValueError("Negative image length")
    pages_data, rem_data = divmod(size, DATA_BYTES)
    pages_raw, rem_raw = divmod(size, RAW_PAGE_BYTES)
    return {
        "bytes": size,
        "classification": (
            "exact_data_plus_oob" if size == DATA_PLUS_OOB_SIZE else
            "exact_data_only" if size == DATA_ONLY_SIZE else
            "other_or_partial"),
        "data_only_full_size": DATA_ONLY_SIZE,
        "data_and_oob_full_size": DATA_PLUS_OOB_SIZE,
        "could_be_data_page_aligned": rem_data == 0,
        "could_be_interleaved_raw_page_aligned": rem_raw == 0,
        "data_page_count": pages_data if rem_data == 0 else None,
        "raw_page_count": pages_raw if rem_raw == 0 else None,
        "has_oob_proven": False,
        "ecc_validated": False,
        "bbt_validated": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("existing_local_dump", type=Path,
                   help="Already acquired local file; only stat() is performed")
    args = p.parse_args()
    length = args.existing_local_dump.stat().st_size
    report = describe_size(length)
    print("Chip geometry candidate:", CHIP_MODEL)
    print("Pages:", TOTAL_PAGES, "block count:", BLOCK_COUNT,
          "pages/block:", PAGES_PER_BLOCK)
    print("Main bytes/page:", DATA_BYTES, "OOB bytes/page:", OOB_BYTES)
    print("Full data-only byte count:", DATA_ONLY_SIZE)
    print("Full main+OOB byte count:", DATA_PLUS_OOB_SIZE)
    print("Observed historical bad-block-table copy page numbers:",
          ", ".join(str(x) for x in HISTORIC_BBT_PAGES))
    print("Existing file length:", report["bytes"])
    print("File-size classification:", report["classification"])
    print("ECC/OOB/bad-block validation: NOT PERFORMED")
    print("A matching length does not prove a complete, correct, "
          "descrambled, original or restorable image.")
    print("Never use this program as authorization to write NAND.")


if __name__ == "__main__":
    main()
