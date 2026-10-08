#!/usr/bin/env python3
"""Offline cryptographic DA1↔DA2 pairing audit for MTKClient Loader files.

Reads only the metadata and hash bytes of local DA containers. Never
decrypts, patches, uploads, saves or executes proprietary DA code.
A matching embedded digest does not demonstrate that the target hardware
will accept or execute either Download Agent.
"""
import argparse
from hashlib import md5, sha1, sha256
from pathlib import Path

from audit_mtkclient_da_metadata import scan_directory

ALGORITHMS = (("MD5", md5), ("SHA1", sha1), ("SHA256", sha256))


def read_pair(directory, entry):
    file = directory / entry["filename"]
    binary = file.read_bytes()
    regions = entry["regions"]
    if len(regions) < 3:
        raise ValueError("DA container has fewer than three regions")
    out = []
    for name, region in (("DA1", regions[1]), ("DA2", regions[2])):
        start = region["file_offset"]
        size = region["bytes"]
        sig = region["signature_bytes"]
        if size <= 0 or sig >= size or start + size > len(binary):
            raise ValueError(f"Invalid {name} region extent or signature size")
        out.append(binary[start:start + size - sig])
    return tuple(out)


def digest_references(da1, da2):
    """Find full-length digests of an intact DA2 body within the DA1 body."""
    matches = {}
    for name, digestor in ALGORITHMS:
        h = digestor(da2).digest()
        offset = da1.find(h)
        if offset != -1:
            matches[name] = (offset, h.hex())
    return matches


def audit(directory, hardware=0x8167):
    entries, _, _ = scan_directory(directory, hardware)
    pairs = [(entry["filename"], read_pair(directory, entry)) for entry in entries]
    result = []
    for da1_name, (da1, da2) in pairs:
        rows = []
        for da2_name, (_, other_da2) in pairs:
            rows.append({
                "da2_filename": da2_name,
                "same_container": da1_name == da2_name,
                "digest_refs": digest_references(da1, other_da2),
            })
        result.append({"da1_filename": da1_name, "candidates": rows})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("loader_directory", type=Path,
                   help="Existing local MTKClient mt kclient/Loader directory")
    p.add_argument("--hw", type=lambda s: int(s, 0), default=0x8167)
    args = p.parse_args()
    result = audit(args.loader_directory, args.hw)
    print("READ-ONLY DA1 / DA2 embedded-digest cross-comparison")
    print("No proprietary code or full DA contents displayed.")
    for src in result:
        print("DA1:", src["da1_filename"])
        for candidate in src["candidates"]:
            print("  target DA2:", candidate["da2_filename"],
                  "(same bundle)" if candidate["same_container"] else "(different bundle)")
            for algorithm, (offset, digest) in candidate["digest_refs"].items():
                print(f"    MATCH {algorithm} at DA1 file-region +{offset:#x}: {digest}")
            if not candidate["digest_refs"]:
                print("    No complete MD5/SHA-1/SHA-256 digest found in this DA1.")
    print("Caution: a literal digest match is not proof that a verification check ran.")
    print("No firmware written or device contacted.")


if __name__ == "__main__":
    main()
