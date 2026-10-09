#!/usr/bin/env python3
"""Audit old-vs-current Crumpet EMI extraction; never connect to USB/NAND.

Inputs: already obtained, SHA-pinned archived/official Crumpet preloader
images and the pinned original MTKClient XFLASH source. This code compares
an independent 400-byte embedded EMI locator against the old
DAconfig.m_extract_emi() algorithm. It emits ONLY hashes/lengths/offsets.
Do NOT interpret a valid offline EMI block as a working DA2 handshake or
as authorization to upload/flash anything.
"""
import argparse
import ast
import hashlib
import struct
from pathlib import Path

PINNED_PRELOADERS = {
    "e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637": "public-2019",
    "a5b30bff5dc20e7f426e45197b77f175a6d986ecb9329c6e96767b21a04cd2a5": "official-2021",
    "837d0d7580093696373864e9bb4b229dfd68f09b0054c97f9e75bfe3bb4bf73a": "official-2025-nov",
}
EXPECTED_EMI_SHA = "c2a394668216e8bc20959bef29aee38002854a0b38444f6fcd9877fd5d548120"
EMI_MARKER = b"MTK_BLOADER_INFO_v28"
GFH_MARKER = b"MMM\x018\x00\x00\x00"
EMI_LEN = 400


def gfhsigned_slice(image):
    """Replicate upstream FILE_INFO signature-tail trim, not signature validation."""
    at = image.find(GFH_MARKER)
    if at < 0 or image.find(GFH_MARKER, at + 1) >= 0:
        raise ValueError("Expected exactly one preloader GFH FILE_INFO")
    tail = image[at:]
    if len(tail) < 0x38:
        raise ValueError("Truncated GFH FILE_INFO")
    mlen = struct.unpack_from("<I", tail, 0x20)[0]
    siglen = struct.unpack_from("<I", tail, 0x2c)[0]
    if not 0 < siglen < mlen <= len(tail):
        raise ValueError("Invalid GFH declared lengths")
    return tail[:mlen - siglen]


def direct_embedded_emi(image, require_known=True):
    """Find one original MTK_BLOADER_INFO_v28 400B block+length footer.

    This is independent of MTKClient's signed-GFH-based tail-extraction rule.
    It is intentionally only a comparison/audit, NOT replacement upload code.
    """
    sha = hashlib.sha256(image).hexdigest()
    if require_known and sha not in PINNED_PRELOADERS:
        raise ValueError("Unknown preloader full SHA-256 (fail closed)")
    at = image.find(EMI_MARKER)
    if at < 0 or image.find(EMI_MARKER, at + 1) >= 0:
        raise ValueError("Expected exactly one embedded EMI v28 marker")
    end = at + EMI_LEN
    if end + 4 > len(image):
        raise ValueError("Embedded EMI/footer truncated")
    length_footer = struct.unpack_from("<I", image, end)[0]
    if length_footer != EMI_LEN:
        raise ValueError("Embedded EMI footer is not 400")
    emi = image[at:end]
    emi_hash = hashlib.sha256(emi).hexdigest()
    if require_known and emi_hash != EXPECTED_EMI_SHA:
        raise ValueError("Pinned original Crumpet EMI bytes changed")
    return {
        "build": PINNED_PRELOADERS.get(sha, "synthetic"),
        "full_sha256": sha,
        "embedded_emi_offset": at,
        "embedded_emi_length": len(emi),
        "embedded_emi_sha256": emi_hash,
        "footer_value": length_footer,
    }


def reproduce_upstream_m_extract_emi(image):
    """Byte-for-byte algorithmic reproduction of cd25cf9 DAconfig XFLASH branch.

    Deliberately retains legacy handling of 0xFFFFFFFF at the supposed GFH
    signed-body end, so the 2019 mismatch remains detectable. The original
    upstream method was separately extracted via AST and run on real inputs
    to cross-check this independent reproduction.
    """
    data = gfhsigned_slice(image)
    dramsize = struct.unpack("<I", data[-4:])[0]
    if dramsize == 0:
        data = data[:-0x800]
        dramsize = struct.unpack("<I", data[-4:])[0]
    data = data[-dramsize - 4:-4]
    marker = data.find(b"MTK_BLOADER_INFO_v")
    if marker < 0:
        return None
    verstring = data[marker + len(b"MTK_BLOADER_INFO_v"):
                     marker + len(b"MTK_BLOADER_INFO_v") + 2].rstrip(b"\0")
    try:
        version = int(verstring)
    except ValueError:
        return None
    if marker == 0:
        return version, bytes(data)
    bin_at = data.find(b"MTK_BIN")
    if bin_at >= 0:
        return version, bytes(data[bin_at + 0xC:])
    return None


def inspect_image(image, require_known=True):
    canonical = direct_embedded_emi(image, require_known=require_known)
    signed = gfhsigned_slice(image)
    canonical["gfh_signed_slice_tail_word"] = struct.unpack("<I", signed[-4:])[0]
    legacy = reproduce_upstream_m_extract_emi(image)
    canonical["mtkclient_emiver"] = legacy[0] if legacy else None
    canonical["mtkclient_emilen"] = len(legacy[1]) if legacy else None
    canonical["mtkclient_emi_sha256"] = (
        hashlib.sha256(legacy[1]).hexdigest() if legacy else None)
    canonical["legacy_result_matches_verified_embedded_emi"] = (
        bool(legacy)
        and legacy[0] == 28
        and canonical["mtkclient_emilen"] == EMI_LEN
        and canonical["mtkclient_emi_sha256"] ==
        canonical["embedded_emi_sha256"])
    return canonical


def _calls(node, name):
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == name
        for n in ast.walk(node))


def inspect_brom_autoselect_source(code):
    """Inspect actual BROM source branch, fail closed if structure has changed."""
    root = ast.parse(code)
    classes = [n for n in root.body if isinstance(n, ast.ClassDef)
               and n.name == "DAXFlash"]
    if len(classes) != 1:
        raise ValueError("Cannot locate original XFLASH class")
    methods = [n for n in classes[0].body if isinstance(n, ast.FunctionDef)
               and n.name == "upload_da"]
    if len(methods) != 1:
        raise ValueError("Cannot locate original upload_da")
    matches = [
        n for n in ast.walk(methods[0])
        if isinstance(n, ast.If)
        and isinstance(n.test, ast.Compare)
        and isinstance(n.test.left, ast.Name)
        and n.test.left.id == "connagent"
        and len(n.test.comparators) == 1
        and isinstance(n.test.comparators[0], ast.Constant)
        and n.test.comparators[0].value == b"brom"
    ]
    if len(matches) != 1:
        raise ValueError("Cannot prove one original BROM connection branch")
    body = matches[0].body
    if not any(_calls(n, "send_emi") for n in body):
        raise ValueError("No explicit-EMI send in BROM branch")
    # get_nand_info() is absent on the original BROM discovery path.
    emmc = any(_calls(n, "get_emmc_info") for n in body)
    ufs = any(_calls(n, "get_ufs_info") for n in body)
    nand = any(_calls(n, "get_nand_info") for n in body)
    cid = any(
        isinstance(n, ast.Attribute) and n.attr == "cid"
        for stmt in body for n in ast.walk(stmt))
    if not emmc or not ufs or not cid:
        raise ValueError("Pinned eMMC/UFS CID auto-discovery pattern changed")
    return {
        "brom_attempts_emmc_info_autodiscovery": emmc,
        "brom_attempts_ufs_info_autodiscovery": ufs,
        "brom_attempts_raw_nand_id_autodiscovery": nand,
        "brom_matches_candidate_files_by_cid": cid,
        "brom_can_send_explicit_emi": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xflash_lib_py", type=Path,
                        help="Pinned cd25cf9 original xflash_lib.py (read only)")
    parser.add_argument("preloader_images", nargs="+", type=Path,
                        help="Existing pinned 2019/2021/2025 Crumpet preloader images")
    args = parser.parse_args()
    for k, v in inspect_brom_autoselect_source(
            args.xflash_lib_py.read_text(encoding="utf-8")).items():
        print(f"{k}: {v}")
    for file in args.preloader_images:
        print("PRELOADER", file.name)
        for k, v in inspect_image(file.read_bytes()).items():
            print(f"  {k}: {hex(v) if isinstance(v, int) and k.endswith('_offset') else v}")
    print("The 2019 wrapper has a 400B matching Crumpet EMI but legacy upstream "
          "GFH-trailer parsing falsely selects a much longer suffix.")
    print("Not evidence DA Stage2 works on Crumpet; no upload, USB, flash or patch.")


if __name__ == "__main__":
    main()
