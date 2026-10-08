#!/usr/bin/env python3
"""Read-only Crumpet amonet source-path and stock GPT compatibility checker.

Inspect a LOCAL upstream amonet-koboreru tree and optionally a local,
already acquired original Crumpet preloader image or official Amazon OTA.
No ARM code execution, compilation, USB, device communication or file writes.
This is a source diagnostic, not a root or unlock utility.
"""
import argparse
from pathlib import Path
import re

from audit_nand_boot_gpt import inspect_image
from compare_official_preloader_payloads import extract_partition


def get_function(source, name):
    """Retrieve a C function body with brace balancing (for pinned source)."""
    hits = list(re.finditer(
        r"\b(?:int|void|uint8_t)\s+" + re.escape(name) +
        r"\s*\([^;{}]*\)\s*\{", source))
    if len(hits) != 1:
        raise ValueError(f"Expected exactly one function definition: {name}")
    start = hits[0].end()
    depth = 1
    for pos in range(start, len(source)):
        c = source[pos]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos]
    raise ValueError(f"Unbalanced C braces for {name}")


def get_macro(header, name):
    matches = re.findall(
        r"(?m)^\s*#define\s+" + re.escape(name) + r"\s+([^\n]+)$", header)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {name} macro")
    return matches[0].strip()


def source_audit(root):
    """Audit the **specific observed upstream source layout**, fail closed."""
    root = Path(root)
    paths = {
        "config": root / "include/devices/crumpet.h",
        "crumpet": root / "devices/crumpet.c",
        "preloader": root / "include/preloader.h",
        "main": root / "main.c",
        "usbdl": root / "usbdl.c",
        "build": root / "build.sh",
    }
    source = {k: v.read_text(encoding="utf-8") for k, v in paths.items()}
    macro = get_macro(source["config"], "LK_PART_NAME")
    m = re.fullmatch(r'"([^"]+)"', macro)
    if not m:
        raise ValueError("LK_PART_NAME must be a single literal for this audit")

    # Preprocessor fallback in the actual source is only active if neither
    # device nor its platform header defines the feature. Search all headers
    # that may participate in this device's compilation, not other devices.
    platform = get_macro(source["config"], "PLATFORM")
    relevant_headers = [paths["config"]]
    relevant_headers += list((root / "platform" / platform).rglob("*.h"))
    relevant_headers += list((root / "platform/include").rglob("*.h"))
    relevant_headers += [paths["preloader"]]
    usb_defined = any(re.search(
        r"(?m)^\s*#define\s+USB_CABLE_IN_ADDR\b",
        p.read_text(encoding="utf-8")) for p in relevant_headers)
    fallback = bool(re.search(
        r"static\s+inline\s+int\s+usb_cable_in\s*\(\s*void\s*\)\s*"
        r"\{\s*return\s+1\s*;\s*\}", source["preloader"]))
    usb_key = get_function(source["crumpet"], "usbdl_detect_key")
    key_always_true = bool(re.fullmatch(
        r"\s*(?://[^\n]*\n\s*)*return\s+1\s*;\s*", usb_key))
    handshake = get_function(source["usbdl"], "do_usb_handshake")
    handshake_forever = (
        bool(re.search(r"\bwhile\s*\(\s*1\s*\)\s*\{", handshake)) and
        not re.search(r"\b(?:break|return|goto)\b", handshake))
    enter = get_function(source["usbdl"], "enter_usbdl")
    expected_condition = bool(re.search(
        r"if\s*\(\s*force\s*\|\|\s*\(\s*usb_cable_in\s*\(\s*\)\s*"
        r"&&\s*usbdl_detect_key\s*\(\s*\)\s*\)\s*\)", enter))
    enter_uses_loop = bool(re.search(r"\bdo_usb_handshake\s*\(\s*\)", enter))
    main = get_function(source["main"], "main")
    # The upstream main.c comments explicitly mention enter_usbdl()
    # *before* the actual call. Remove comments to avoid a false path match.
    main = re.sub(r"/\\*.*?\\*/", "", main, flags=re.DOTALL)
    main = re.sub(r"//[^\\n]*", "", main)
    main_order = []
    for symbol in ("apply_patches", "setup_usb_descriptors",
                   "boot_device_init", "enter_usbdl", "bldr_load_part"):
        search = re.search(r"\b" + symbol + r"\s*\(", main)
        if not search:
            raise ValueError("Crumpet main lacks expected call: " + symbol)
        main_order.append((symbol, search.start()))
    ordered = all(a[1] < b[1] for a, b in zip(main_order, main_order[1:]))
    normal_usb = bool(re.search(r"\benter_usbdl\s*\(\s*0\s*\)\s*;", main))
    loader = bool(re.search(r"\bbldr_load_part\s*\(\s*LK_PART_NAME\s*,", main))
    donor = root / "tees" / "tee_crumpet.img"
    return {
        "lk_partition": m.group(1),
        "platform": platform,
        "usb_cable_macro_defined": usb_defined,
        "usb_fallback_always_true": fallback,
        "usb_key_always_true": key_always_true,
        "handshake_loop_no_source_exit": handshake_forever,
        "usb_gate_matches_source": expected_condition,
        "enter_calls_handshake": enter_uses_loop,
        "main_calls_in_expected_order": ordered,
        "normal_enter_before_lk_load": normal_usb and loader and ordered,
        "requires_missing_donor": (
            "tee_" + "$DEVICE" in source["build"] and
            not donor.is_file()),
    }


def correlate(root, image):
    observed = source_audit(root)
    parts = inspect_image(image)["partitions"]
    partition_names = [p["name"] for p in parts]
    observed["gpt_entry_count"] = len(partition_names)
    observed["lk_partition_in_gpt"] = (
        observed["lk_partition"] in partition_names)
    observed["gpt_contains_lk_a_and_b"] = (
        "lk_a" in partition_names and "lk_b" in partition_names)
    return observed


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("amonet_dir", type=Path,
                     help="LOCAL checkout of upstream amonet-koboreru")
    image = cli.add_mutually_exclusive_group()
    image.add_argument("--image", type=Path,
                       help="Already-existing local original Crumpet boot image")
    image.add_argument("--official-ota", metavar="URL",
                       help="Official Amazon Crumpet OTA URL, bounded in-RAM download")
    args = cli.parse_args()
    result = source_audit(args.amonet_dir)
    if args.image or args.official_ota:
        data = (args.image.read_bytes() if args.image else
                extract_partition(args.official_ota))
        result = correlate(args.amonet_dir, data)
    for name, value in result.items():
        print(f"{name}: {value}")
    forced = (
        not result["usb_cable_macro_defined"] and
        result["usb_fallback_always_true"] and
        result["usb_key_always_true"] and
        result["handshake_loop_no_source_exit"] and
        result["usb_gate_matches_source"] and
        result["enter_calls_handshake"] and
        result["normal_enter_before_lk_load"])
    print("CRUMPET DEFAULT SOURCE PATH ENTERS NONRETURNING USBDL:",
          forced)
    if "lk_partition_in_gpt" in result:
        print("DECLARED LK_PART_NAME PRESENT IN VERIFIED GPT:",
              result["lk_partition_in_gpt"])
    print("These observations do not prove the exploit reaches main() on real hardware.")
    print("A missing GPT name does not rule out non-GPT partition aliases.")
    print("No images written or patched; device and USB access are not used.")


if __name__ == "__main__":
    main()
