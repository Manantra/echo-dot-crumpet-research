#!/usr/bin/env python3
"""Read-only inspection of DA loader metadata for a specified MTK hardware code.

Point at a *local copy* of the upstream mtkclient/mtkclient/Loader directory.
Parses metadata only. Never executes, uploads, patches, exports or modifies
Download Agent binaries, and never connects to USB or a phone/Echo device.
"""
import argparse
import hashlib
import struct
from pathlib import Path

DA_ENTRY_SIZE = 0xDC
DA_HEADER = 0x6C
MAX_RECORDS = 1000
MAX_REGIONS = 8


def parse_loader(path, target=0x8167):
    raw = path.read_bytes()
    if len(raw) < DA_HEADER + DA_ENTRY_SIZE:
        raise ValueError(f"{path.name}: no loader metadata header")
    count = struct.unpack_from("<I", raw, 0x68)[0]
    if not 0 <= count <= MAX_RECORDS:
        raise ValueError(f"{path.name}: invalid loader entry count {count}")
    # Mirrors the DA metadata version detection in upstream daconfig.py.
    old = raw[DA_HEADER + 0xD8:DA_HEADER + 0xDA] == b"\xDA\xDA"
    step = 0xD8 if old else DA_ENTRY_SIZE
    matches = []
    for number in range(count):
        address = DA_HEADER + number * step
        if address + 20 > len(raw):
            raise ValueError(f"{path.name}: truncated DA table")
        magic, hardware, subtype, version = struct.unpack_from("<HHHH", raw, address)
        if magic != 0xDADA:
            raise ValueError(f"{path.name}: invalid DA entry magic")
        if hardware != target:
            continue
        if old:
            software_version = 0
            region_count = struct.unpack_from("<H", raw, address + 16)[0]
            first_region = address + 18
        else:
            software_version = struct.unpack_from("<H", raw, address + 8)[0]
            region_count = struct.unpack_from("<H", raw, address + 18)[0]
            first_region = address + 20
        if not 1 <= region_count <= MAX_REGIONS:
            raise ValueError("Invalid DA region count")
        regions = []
        for index in range(region_count):
            region_offset = first_region + index * 20
            if region_offset + 20 > len(raw):
                raise ValueError("Truncated DA region descriptor")
            offset, size, load_at, start_offset, signature_size = struct.unpack_from(
                "<IIIII", raw, region_offset
            )
            if size and (offset > len(raw) or size > len(raw) - offset):
                raise ValueError("DA section exceeds loader file length")
            regions.append(dict(region=index, file_offset=offset, bytes=size,
                                address=load_at, start_offset=start_offset,
                                signature_bytes=signature_size))
        matches.append(dict(filename=path.name, index=number, hw_code=hardware,
                            sub_code=subtype, hw_version=version,
                            sw_version=software_version, regions=regions,
                            file_sha256=hashlib.sha256(raw).hexdigest()))
    return matches


def scan_directory(directory, target=0x8167):
    if not directory.is_dir():
        raise ValueError("Provide an existing local MTKClient Loader directory")
    files = sorted((p for p in directory.iterdir()
                    if p.is_file() and
                    ("MTK_AllInOne_DA" in p.name or "MTK_DA" in p.name)), reverse=True)
    matches = []
    for path in files:
        matches.extend(parse_loader(path, target))
    if not matches:
        return matches, [], []
    # The currently inspected upstream daconfig.py drops later records when
    # their *hw_version* and *sw_version* match a retained entry; its
    # hw_sub_code == hw_sub_code check is tautological (not a subtype match).
    retained, suppressed = [], []
    for entry in matches:
        if any(e["hw_version"] == entry["hw_version"] and
               e["sw_version"] == entry["sw_version"] for e in retained):
            suppressed.append(entry)
        else:
            retained.append(entry)
    return matches, retained, suppressed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("loader_directory", type=Path)
    parser.add_argument("--hw", type=lambda value: int(value, 0), default=0x8167)
    args = parser.parse_args()
    found, selected, suppressed = scan_directory(args.loader_directory, args.hw)
    print(f"READ-ONLY DA metadata audit for HW {args.hw:#06x}")
    for entry in found:
        print(f"  {entry['filename']} record #{entry['index']} "
              f"sub={entry['sub_code']:#06x} hwver={entry['hw_version']:#06x} "
              f"swver={entry['sw_version']:#06x} SHA256={entry['file_sha256']}")
        for region in entry["regions"]:
            print(f"    stage/region={region['region']} "
                  f"filelen={region['bytes']:#x} address={region['address']:#x} "
                  f"signature={region['signature_bytes']:#x}")
    print("Metadata records matching hwcode:", len(found))
    print("Expected retained by first matching version:", len(selected))
    for entry in suppressed:
        print(f"  Alternative hidden by duplicate/version filter: {entry['filename']}")
    print("Version-filter result is derived from source code, NOT from running MTKClient.")
    print("Finding a different loader does not prove its safety or Crumpet compatibility.")
    print("No DA binary exported, patched or uploaded; no device contacted.")


if __name__ == "__main__":
    main()
