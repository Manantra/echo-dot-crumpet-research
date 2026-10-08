#!/usr/bin/env python3
"""Read-only audit of Amazon Crumpet MTK raw-NAND boot headers and embedded GPT.

Operates on previously obtained local image bytes, or on manifest-verified
official Amazon OTA brhgptpl_0..3 via HTTPS byte ranges (in RAM only).
DOES NOT WRITE firmware, change any GUID, flash NAND or access devices.

The GPT inside this specific Preloader *image container* has unusual backup
and partition-0 fields. It must NOT be treated as a standard disk image for
GPT repair or flashing utilities.
"""
import argparse
import hashlib
import struct
import zlib
from pathlib import Path

from compare_official_preloader_payloads import extract_partition

NAND_HEADER = 0x0
NAND_HEADER_COPY = 0x100
BRLYT = 0x1000
GPT = 0x3000
ENTRIES = 0x4000
GFH = 0x8000
BOOT_NAME = b"BOOTLOADER!\0"
NAND_VERSION = b"V006"
NAND_ID = b"NFIINFO\0"


def inspect_image(data):
    gfh_offset = data.find(b"MMM\x01")
    # Both historical container packings are empirically verified: the
    # archived 2019 Crumpet excerpt uses 0xC00-spaced landmarks, while
    # the 2021–2025 official OTAs use 0x1000-spaced landmarks.
    if gfh_offset not in (0x6000, 0x8000) or len(data) < gfh_offset + 0x38:
        raise ValueError("Unrecognized 2019 or 2021+ Crumpet GFH location")
    layout_unit = gfh_offset // 8
    brlyt_offset, gpt_offset, entries_offset = (
        layout_unit, 3 * layout_unit, 4 * layout_unit)

    for off in (NAND_HEADER, NAND_HEADER_COPY):
        if (data[off:off + 12] != BOOT_NAME or
                data[off + 12:off + 16] != NAND_VERSION or
                data[off + 16:off + 24] != NAND_ID):
            raise ValueError(f"MTK NAND V006 header missing at {off:#x}")
    if data[:128] != data[NAND_HEADER_COPY:NAND_HEADER_COPY + 128]:
        raise ValueError("Duplicated MTK NAND header differs")
    ioif, pagesize, addrcycles = struct.unpack_from("<HHH", data, 24)
    if data[brlyt_offset:brlyt_offset + 8] != b"BRLYT\0\0\0":
        raise ValueError("BRLYT layout marker missing at 0x1000")
    ver, head, total, magic, kind, head2, total2, unused = struct.unpack_from(
        "<8I", data, brlyt_offset + 8)
    if ver != 1 or magic != 0x42424242 or kind != 0x10002:
        raise ValueError("Not a recognized MTK NAND BRLYT layout")
    if head != head2 or total != total2:
        raise ValueError("Redundant BRLYT fields disagree")
    if data[gpt_offset:gpt_offset + 8] != b"EFI PART":
        raise ValueError("Embedded GPT signature missing")
    revision, headersize, headercrc = struct.unpack_from("<III", data, gpt_offset + 8)
    if not 92 <= headersize <= 512:
        raise ValueError("Unreasonable GPT header size")
    header = bytearray(data[gpt_offset:gpt_offset + headersize])
    header[16:20] = b"\x00" * 4
    if zlib.crc32(header) != headercrc:
        raise ValueError("Embedded GPT header CRC32 failed")
    current_lba, backup_lba, first_usable, last_usable = struct.unpack_from(
        "<QQQQ", data, gpt_offset + 0x18)
    entry_lba, nentries, entrysize, entrycrc = struct.unpack_from(
        "<QIII", data, gpt_offset + 0x48
    )
    if nentries < 1 or entrysize != 128 or nentries * entrysize > gfh_offset - entries_offset:
        raise ValueError("Unsupported embedded GPT entry table bounds")
    block = data[entries_offset:entries_offset + nentries * entrysize]
    if zlib.crc32(block) != entrycrc:
        raise ValueError("Embedded GPT entry table CRC32 failed")
    partitions = []
    for index in range(nentries):
        start = index * entrysize
        record = block[start:start + entrysize]
        if record[:16] == bytes(16):
            continue
        low, high, flags = struct.unpack_from("<QQQ", record, 32)
        try:
            name = record[56:128].decode("utf-16le").partition("\0")[0]
        except UnicodeError as exc:
            raise ValueError(f"Invalid UTF16 GPT label #{index}") from exc
        if not name or high < low:
            raise ValueError("Invalid GPT entry range or name")
        partitions.append({
            "index": index, "name": name, "first_lba": low,
            "last_lba": high, "attributes": flags,
            # public OTA unique GUID bytes never emitted
        })
    if data[gfh_offset:gfh_offset + 4] != b"MMM\x01":
        raise ValueError("No GFH image at offset 0x8000")
    # The layout values shift by the exact GPT first-LBA offset for the
    # corresponding brhgptpl partition. Verify rather than guess which
    # redundant boot copy this image describes.
    matching_copies = [
        partition["name"] for partition in partitions
        if partition["name"] in ("brhgptpl_0", "brhgptpl_1",
                                  "brhgptpl_2", "brhgptpl_3")
        and head == partition["first_lba"] + 8
        and total == partition["first_lba"] + 0x108
    ]
    return {
        "nand_ioif": ioif, "nand_pagesize": pagesize,
        "nand_address_cycles": addrcycles,
        "brlyt_first": head, "brlyt_second": total,
        "brlyt_matches_gpt_copy": matching_copies[0] if len(matching_copies) == 1 else None,
        "gpt_revision": revision,
        "gfh_offset": gfh_offset,
        "brlyt_offset": brlyt_offset,
        "gpt_offset": gpt_offset,
        "entries_offset": entries_offset,
        "gpt_current_lba": current_lba,
        "gpt_backup_lba": backup_lba,
        "gpt_first_usable": first_usable, "gpt_last_usable": last_usable,
        "gpt_entries_lba": entry_lba, "gpt_nentries": nentries,
        "gpt_entrysize": entrysize, "gpt_entries_used": len(partitions),
        "partitions": partitions,
        "gfh_sha256": hashlib.sha256(data[gfh_offset:]).hexdigest(),
    }


def classify_differences(a, b):
    """Classify every differing byte; leave no unrecognized delta implicit."""
    left, right = inspect_image(a), inspect_image(b)
    if len(a) != len(b):
        raise ValueError("Partition image sizes differ")
    if left["gfh_offset"] != right["gfh_offset"]:
        raise ValueError("Historical image container layouts differ; not byte-comparable")
    brlyt_offset, gpt_offset, entries_offset = (
        left["brlyt_offset"], left["gpt_offset"], left["entries_offset"])
    categories = {key: 0 for key in (
        "brlyt_copy_fields", "gpt_header_crc", "gpt_disk_guid",
        "gpt_partition_array_crc", "gpt_unique_partition_guids", "other")}
    for offset, (x, y) in enumerate(zip(a, b)):
        if x == y:
            continue
        if offset in range(brlyt_offset + 0x0C, brlyt_offset + 0x14) or offset in range(
                brlyt_offset + 0x1C, brlyt_offset + 0x24):
            category = "brlyt_copy_fields"
        elif offset in range(gpt_offset + 0x10, gpt_offset + 0x14):
            category = "gpt_header_crc"
        elif offset in range(gpt_offset + 0x38, gpt_offset + 0x48):
            category = "gpt_disk_guid"
        elif offset in range(gpt_offset + 0x58, gpt_offset + 0x5C):
            category = "gpt_partition_array_crc"
        elif entries_offset <= offset < entries_offset + left["gpt_nentries"] * 128 and (
                (offset - entries_offset) % 128) in range(16, 32):
            category = "gpt_unique_partition_guids"
        else:
            category = "other"
        categories[category] += 1
    return categories


def main():
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--image", type=Path,
                        help="Already available local preloader partition file")
    source.add_argument("--official-ota", metavar="HTTPS_URL",
                        help="Only official Amazon Crumpet OTA; in-memory Range reads")
    p.add_argument("--copy", type=int, choices=range(4), default=0)
    p.add_argument("--compare-ota", metavar="HTTPS_URL",
                   help="Optional second official OTA, same boot copy")
    args = p.parse_args()
    if args.compare_ota and not args.official_ota:
        p.error("--compare-ota requires --official-ota")
    raw = (extract_partition(args.official_ota, f"brhgptpl_{args.copy}")
           if args.official_ota else args.image.read_bytes())
    info = inspect_image(raw)
    print("MTK V006 NAND header: ioif={:#x}, page_size={} bytes, addr_cycles={}".format(
        info["nand_ioif"], info["nand_pagesize"], info["nand_address_cycles"]))
    print("NAND boot BRLYT: first={:#x} second={:#x}".format(
        info["brlyt_first"], info["brlyt_second"]))
    print("BRLYT values match GPT boot partition:",
          info["brlyt_matches_gpt_copy"] or "NO VERIFIED MATCH")
    print("Embedded GPT header and partition-array CRC32: BOTH VALID")
    print("GFH/GPT/container offsets:",
          hex(info["gfh_offset"]), hex(info["gpt_offset"]),
          hex(info["entries_offset"]))
    print("GPT revision", hex(info["gpt_revision"]),
          "entries", info["gpt_nentries"], "used", info["gpt_entries_used"])
    print("GPT current/backup/usable:",
          *(hex(info[key]) for key in (
              "gpt_current_lba", "gpt_backup_lba",
              "gpt_first_usable", "gpt_last_usable")))
    print("GPT partition layout (LBA counts; not a flash command):")
    for part in info["partitions"]:
        print("  #{} {:15} {:>8x} .. {:>8x} ({:>6x} units)".format(
            part["index"], part["name"], part["first_lba"],
            part["last_lba"], part["last_lba"] - part["first_lba"] + 1))
    print("GFH-anchored SHA256:", info["gfh_sha256"])
    if args.compare_ota:
        other = extract_partition(args.compare_ota, f"brhgptpl_{args.copy}")
        counts = classify_differences(raw, other)
        print("Difference classification:", counts)
        if counts["other"]:
            print("WARNING: changes exist outside recognized GPT GUID/CRC/copy fields")
        else:
            print("All changed bytes classified as known GPT/BRLYT metadata")
    print("WARNING: embedded layout is not a generic repairable PC GPT disk; "
          "backup_lba and boot partitions overlap reserved ranges.")
    print("No GUIDs or proprietary data printed; no image saved; no device accessed.")


if __name__ == "__main__":
    main()
