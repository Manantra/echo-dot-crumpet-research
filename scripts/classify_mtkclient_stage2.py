#!/usr/bin/env python3
"""Read-only classification of a previously captured MTKClient console log.

Reports protocol milestones without dumping the original log, device IDs,
private keys, preloader binaries or memory contents. Never opens a serial/USB
device, initiates BROM, uploads DA, writes NAND, or modifies any files.
"""
import argparse
import re
from pathlib import Path

PATTERNS = (
    ("hardware_8167", r"(?:HW code:\s*0x8167|CPU:.*MT8167)"),
    ("preloader_detected", r"(?:Detected regular mode|USB.*0e8d:2000)"),
    ("brom_explicit", r"(?:Device is in BROM mode|USB.*0e8d:0003)"),
    ("kamakiri_success_reported", r"Kamakiri.*(?:success|pass|done)"),
    ("xflash_stage1", r"Uploading xflash stage 1"),
    ("stage1_jump", r"Successfully uploaded stage 1, jumping"),
    ("stage1_sync", r"Successfully received DA sync"),
    ("connection_agent_brom", r"(?:Connection agent.*brom|connagent.*brom)"),
    ("emi_command_accepted", r"DRAM setup passed\."),
    ("emi_data_succeeded", r"Sending emi data succeeded\."),
    ("missing_emi_warning", r"No preloader given\. Operation may fail"),
    ("auto_emi_emmc_only", r"No emmc info, can't parse existing preloaders"),
    ("stage2_attempt", r"Uploading stage 2\.\.\."),
    ("stage2_payload_accepted", r"Upload data was accepted\. Jumping to stage 2"),
    ("stage2_status_exception", r"Stage was't executed\. Maybe dram issue"),
    ("stage2_boot_success", r"(?:Boot to succeeded|Successfully uploaded stage 2)"),
    ("stage2_generic_failure", r"Failed to upload da"),
    ("daemon_nand_info", r"NAND (?:Pagesize|Blocksize|Sparesize|Total size|ID):"),
    ("signature_rejected", r"(?:DA_IMAGE_SIG_VERIFY_FAIL|0x2001.*[Ss]ig|signature verification fail)"),
)
EXPECTED_STAGE = (
    "xflash_stage1", "stage1_jump", "stage1_sync", "emi_command_accepted",
    "stage2_attempt", "stage2_payload_accepted", "stage2_boot_success"
)


def classify(raw):
    """Return non-sensitive bool flags plus a conservative outcome statement."""
    flags = {name: bool(re.search(pattern, raw, re.I))
             for name, pattern in PATTERNS}
    if flags["stage2_boot_success"]:
        status = "Stage-2 handshake/success log observed; not evidence of unlock/root."
    elif flags["stage2_status_exception"]:
        status = ("No Stage-2 status response was obtained (exception/timeout). "
                  "The cause is unknown; this is NOT a confirmed DRAM, NAND "
                  "or security rejection.")
    elif flags["stage2_payload_accepted"]:
        status = ("Stage-2 data transfer was acknowledged, but no success "
                  "or explicit timeout marker was captured; execution unverified.")
    elif flags["stage1_sync"]:
        status = "DA Stage-1 synchronization observed; Stage-2 execution unverified."
    elif flags["signature_rejected"]:
        status = "A signature rejection was logged; no successful DA execution shown."
    else:
        status = "Insufficient MTKClient milestones to identify the DA failure phase."

    unknowns = []
    if not flags["hardware_8167"]:
        unknowns.append("Confirm HW code 0x8167 from a non-sensitive transcript.")
    if not flags["stage1_sync"]:
        unknowns.append("Need Stage-1 synchronization outcome.")
    if not flags["emi_command_accepted"]:
        unknowns.append("Need EMI-command response status and how EMI was selected.")
    if not flags["stage2_boot_success"]:
        unknowns.append("Need Stage-2 returned status or transport-level exception.")
    if flags["stage2_payload_accepted"] and flags["stage2_status_exception"]:
        unknowns.append("Determine USB state at post-BOOT_TO status read (disconnect, timeout, or transfer error).")
    return flags, status, unknowns


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Previously collected, local MTKClient log text")
    args = parser.parse_args()
    raw = args.log.read_text(encoding="utf-8", errors="replace")
    flags, status, unknowns = classify(raw)
    print("Offline MTKClient log phase audit — NO device access")
    for name, value in flags.items():
        print(f"  {name}: {'OBSERVED' if value else 'not found'}")
    print("Interpretation:", status)
    print("Needed before cause attribution:")
    for item in unknowns:
        print("  -", item)
    print("A log cannot demonstrate NAND access or root unless confirmed by separate evidence.")
    print("Remove serial numbers, identifiers, cryptographic values and private paths before sharing logs.")


if __name__ == "__main__":
    main()
