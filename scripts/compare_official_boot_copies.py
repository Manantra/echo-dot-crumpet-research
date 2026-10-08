#!/usr/bin/env python3
"""Compare four manifest-verified raw-NAND Crumpet boot copies in one official OTA.

Downloads only the compressed preloader OTA operations using HTTP Range,
checks per-operation/partition SHA-256 against the OTA manifest, never saves
firmware and never communicates with or modifies a physical device.
"""
import argparse
import hashlib

from compare_official_preloader_payloads import extract_partition, summarize_pair


def compare_copies(images):
    if len(images) != 4:
        raise ValueError("Four consecutive Crumpet preloader partitions required")
    baseline = images[0]
    result = []
    for copy, data in enumerate(images):
        stats = summarize_pair(baseline, data)
        positions = [i for i, (a, b) in enumerate(zip(baseline, data)) if a != b]
        result.append((copy, stats, positions))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ota_url", help="Official Amazon Crumpet OTA HTTPS URL")
    args = parser.parse_args()
    images = [extract_partition(args.ota_url, f"brhgptpl_{i}")
              for i in range(4)]
    result = compare_copies(images)
    print("Crumpet's 4 manifest-verified boot copies — offline data comparison")
    for number, stats, positions in result:
        print(f"  Copy {number}: whole SHA256={stats['full_sha256_b']}")
        print(f"    GFH-start={stats['gfh_offset']:#x} "
              f"GFH+ SHA256={stats['gfh_suffix_sha256_b']}")
        print(f"    differing bytes vs copy 0: {len(positions)}")
        print("    differing offsets:",
              ",".join(f"0x{i:x}" for i in positions) if positions else "-")
    if all(item[1]["suffix_changed_bytes"] == 0 for item in result):
        print("IDENTICAL GFH-ANCHORED IMAGE IN ALL FOUR COPIES")
    else:
        print("WARNING: GFH-anchored image differs across copies")
    print("Different prefix fields do not, by themselves, identify their meaning.")
    print("No binaries saved; OTA publisher signature not independently validated.")


if __name__ == "__main__":
    main()
