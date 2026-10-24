#!/usr/bin/env python3
"""Read-only redaction of an already captured UART/boot log.

Reads an existing log file and writes a NEW redacted copy with private
identifiers (serial/DSN, MAC/Bluetooth addresses, Wi-Fi SSIDs, account
strings, keys/tokens, GUIDs, MEID/hwuid/HRID/lastpc values) replaced by XXXX. Line structure is preserved
(same number of lines, same line endings; lines are masked, never deleted).
Never opens a serial/USB device, never modifies or deletes the original, and
refuses to overwrite an existing file. The report lists rule names, counts and
line numbers only, never the masked values.

Heuristic: always review the redacted copy by eye before publishing it.
Long hex runs (possible keys/hashes) are reported for review but NOT masked,
because public firmware hashes are legitimate evidence.
"""
import argparse
import hashlib
import re
import sys
from pathlib import Path

MASK = "XXXX"
_VALUE = r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
_SEP = r"\s*[:=]\s*"

# (name, compiled regex, group index of the secret span, or None for the whole match)
RULES = (
    # Wi-Fi names may contain spaces: quoted string, else rest of the line.
    ("wifi_ssid",
     re.compile(r"""(?i)\b((?:[\w.]*[_.])?b?e?ssid\w*""" + _SEP + r""")("[^"\r\n]*"|'[^'\r\n]*'|[^\r\n]*)"""),
     2),
    ("keyed_identifier",
     re.compile(r"""(?i)\b((?:[\w.]*[_.])?(?:\w*serial\w*|dsn|sn|mac(?:addr\w*)?|bdaddr|btaddr|imei|"""
                r"""account\w*|customer\w*|psk|token|secret|passw\w*|passphrase|apikey|api_key|\w*key)"""
                + _SEP + r""")(""" + _VALUE + r""")"""),
     2),
    # MediaTek preloader/LK hardware IDs and PC traces: values may span a whole line.
    ("hw_identifier",
     re.compile(r"(?i)\b((?:meid|hwuid|hrid|lastpc)(?:\[\d+\])*" + _SEP + r")([^\r\n]*)"),
     2),
    ("email_account",
     re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), None),
    ("mac_or_bt_address",
     re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])"), None),
    ("guid",
     re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"), None),
    # Amazon-style 16-character DSN/serial (e.g. G0xx...). Heuristic.
    ("dsn_like_token",
     re.compile(r"\bG0[0-9A-Z]{14}\b"), None),
)
REVIEW_LONG_HEX = re.compile(r"\b[0-9A-Fa-f]{32,}\b")


def redact_line(line):
    """Return (redacted_line, [rule names applied, one entry per mask])."""
    hits = []
    for name, rx, grp in RULES:
        def sub(m, name=name, grp=grp):
            if m.group(grp or 0) == MASK:
                return m.group(0)
            hits.append(name)
            if grp is None:
                return MASK
            return m.group(0)[:m.start(grp) - m.start(0)] + MASK
        line = rx.sub(sub, line)
    return line, hits


def redact_bytes(data):
    """Redact a whole log. Returns (redacted_bytes, report dict)."""
    # latin-1 maps every byte to one char, so non-text garbage round-trips exactly.
    lines = data.decode("latin-1").splitlines(keepends=True)
    out, counts, masked_lines, review = [], {}, {}, []
    for no, raw in enumerate(lines, 1):
        body = raw.rstrip("\r\n")
        ending = raw[len(body):]
        new, hits = redact_line(body)
        for h in hits:
            counts[h] = counts.get(h, 0) + 1
            masked_lines.setdefault(h, []).append(no)
        if REVIEW_LONG_HEX.search(new):
            review.append(no)
        out.append(new + ending)
    result = "".join(out).encode("latin-1")
    assert len(out) == len(lines), "line count must be preserved"
    return result, {"lines": len(lines), "counts": counts,
                    "masked_lines": masked_lines, "review_long_hex_lines": review}


def format_report(report, src_sha, dst_sha):
    rows = ["Redaction report (values are never listed)",
            f"original sha256 : {src_sha}",
            f"redacted sha256 : {dst_sha}",
            f"lines           : {report['lines']} (unchanged)"]
    if not report["counts"]:
        rows.append("masked          : nothing matched (still review by eye)")
    for name, n in sorted(report["counts"].items()):
        shown = report["masked_lines"][name]
        tail = ",..." if len(shown) > 20 else ""
        rows.append(f"masked {name}: {n} on lines "
                    + ",".join(map(str, sorted(set(shown))[:20])) + tail)
    if report["review_long_hex_lines"]:
        rows.append("REVIEW (not masked) long hex runs on lines: "
                    + ",".join(map(str, report["review_long_hex_lines"][:20])))
    rows.append("Heuristic only: inspect the redacted file before sharing it.")
    return "\n".join(rows)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("raw_log", type=Path, help="Existing captured log (left untouched)")
    p.add_argument("-o", "--output", type=Path,
                   help="New file to create (default: <name>.redacted<ext>); never overwritten")
    p.add_argument("--report", type=Path, help="Optional new file for the report")
    args = p.parse_args(argv)

    src = args.raw_log
    dst = args.output or src.with_name(src.stem + ".redacted" + src.suffix)
    if not src.is_file():
        p.error(f"not a regular file: {src}")
    if dst.resolve() == src.resolve():
        p.error("output must differ from the original log")
    data = src.read_bytes()
    redacted, report = redact_bytes(data)
    try:
        with open(dst, "xb") as fh:      # exclusive create: refuses to overwrite
            fh.write(redacted)
    except FileExistsError:
        p.error(f"refusing to overwrite existing file: {dst}")
    text = format_report(report, hashlib.sha256(data).hexdigest(),
                         hashlib.sha256(redacted).hexdigest())
    print(text)
    if args.report:
        try:
            with open(args.report, "x", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except FileExistsError:
            p.error(f"refusing to overwrite existing file: {args.report}")
    print(f"Wrote {dst}; original left untouched: {src}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
