# Crumpet raw NAND: verified logical GPT partition layout (2019–2025)

**Updated 2026-10-08.** This page summarizes our [CRC-verified NAND/GPT research](crumpet-nand-gpt-2019-2025.md), which compares the [public 2019 Crumpet NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) and manifest-hash-verified official 2021–2025 Amazon Crumpet OTA boot images.

The embedded **GPT header and 32 × 128-byte partition entry array both have valid CRC32s** in the examined images. Eighteen entries are populated. Their names and logical LBA extents are **identical** between the 2019 excerpt and the November 2025 OTA.

| Name | First LBA | Last LBA |
|---|---:|---:|
| `brhgptpl_0` | `0x0000` | `0x003F` |
| `reserve0` | `0x0040` | `0x00FF` |
| `lk_a` | `0x0100` | `0x027F` |
| `lk_b` | `0x0280` | `0x03FF` |
| `brhgptpl_1` | `0x0400` | `0x043F` |
| `reserve1` | `0x0440` | `0x05FF` |
| `idme_nand` | `0x0600` | `0x07FF` |
| `brhgptpl_2` | `0x0800` | `0x083F` |
| `reserve2` | `0x0840` | `0x09FF` |
| `misc` | `0x0A00` | `0x0BFF` |
| `brhgptpl_3` | `0x0C00` | `0x0C3F` |
| `reserve3` | `0x0C40` | `0x0DFF` |
| `tee1` | `0x0E00` | `0x12FF` |
| `boot_a` | `0x1300` | `0x223F` |
| `tee2` | `0x2240` | `0x273F` |
| `boot_b` | `0x2740` | `0x367F` |
| `persist` | `0x3680` | `0x3E7F` |
| `userdata` | `0x3E80` | `0x1FDFF` |

The [2019 UART log](https://github.com/jvandewiel/no-alexa/blob/main/logicanalyzer/uart_logs/uart_normal_oldsw.txt) independently reports a **4,096-byte logical partition block size** and matching `[GPT_PL]` entries.

**Crucial corrections to older notes:**
- The 2019 NAND excerpt has GPT/GFH landmarks at `0x2400/0x6000`, not the later OTA's `0x3000/0x8000`; these are host file-layout differences. Do **not** directly equate those image offsets with on-chip physical NAND addresses.
- May vs Nov 2025 raw boot image hash differences are entirely **GPT GUID regeneration (16 disk GUID + 285 changed unique-partition-GUID bytes) and two CRC32s (4+4 bytes)**. No other bytes changed.
- The four `brhgptpl_*` boot-copy `BRLYT` fields correlate exactly with each corresponding GPT `first_lba`: first field `+0x8`, second `+0x108`, duplicated.
- The table's **`backup_lba=1` and `brhgptpl_0` starting at LBA 0** make it inappropriate to treat this embedded layout as an ordinary repairable desktop GPT disk.

See [`scripts/audit_nand_boot_gpt.py`](../scripts/audit_nand_boot_gpt.py) for the read-only parser; it validates header and partition CRCs on both historic encodings.

**Still unproven:** physical raw NAND page+OOB layout, BCH/ECC/scrambling, bad-block tables, reliable restore/writeback, bootloader unlock or persistent root. `idme_nand`, `persist` and other partitions may carry device-specific content; never transplant or flash them based on this reference.
