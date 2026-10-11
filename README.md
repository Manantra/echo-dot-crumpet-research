# Echo Dot 3 Refresh (Crumpet) — Research

Public, community-oriented **read-only reverse-engineering research** for the Amazon Echo Dot 3rd Gen Refresh (codename `crumpet`, model `C78MP8`).

> **Status: no independently confirmed persistent root, unlock or functional TWRP procedure for Crumpet.** This is not an unlock kit. **Do not flash Donut images to Crumpet.**

## What is known

- **New (2026-10-11): confirmed DA1 mutable state and independent C78MP8 status.** In pinned V5 and AllInOne DA1 binaries, the second **56/32-byte** parameter source is a **runtime-written table**, not a fixed firmware literal: V5 has **16 static address occurrences and six verified field-write instructions**; AllInOne has **10 occurrences and four verified field writes**. Values are not observable without a real device trace, so their involvement in Crumpet DA2 failure remains a hypothesis. The [new DA1 field-level investigation](docs/crumpet-da1-mutable-state-and-october-2026-unlock-status.md) also cross-checks [an independent October 3 Crumpet analysis](https://community.home-assistant.io/t/echo-dot-3rd-gen-2018-as-a-fully-local-assist-satellite-keeping-amazons-mic-array-and-wake-word-engine/1025971/36) and the [current echo-dot-assist supported device list](https://github.com/Gamer92000/echo-dot-assist): **donut D9N29T supported; crumpet C78MP8 explicitly unsupported**. No verified persistent root/unlock.


- Crumpet uses **raw NAND**; the older Echo Dot 3 **Donut** uses a different boot/storage layout.
- Public [Crumpet UART logs](https://github.com/jvandewiel/no-alexa/tree/main/logicanalyzer/uart_logs) cover 2019 and 2021 preloaders.
- A [2019 raw-NAND excerpt](https://github.com/jvandewiel/no-alexa/blob/main/dumped_files/brhgptpl_0.bin) is available. Whole-file SHA-256: `e51970de327ec58ba32ee506b7b1358ff7877e43672be833f5d6a7c2b2a68637`.
- **New (2026-10-08):** We verified and extracted **four March 2021 Crumpet preloader images** from Amazon's Fire OS 6.5.4.8 OTA, with their SHA-256 checksums validated against the official update manifest. [Full analysis](docs/ota-2021-analysis.md).
- **[2026-10-11 DA1 mutable state blocks and independently verified Crumpet unlock status](docs/crumpet-da1-mutable-state-and-october-2026-unlock-status.md)**
- **New precise Stage-2 ACK boundary (2026-10-10):** Both stock MT8167 DA1 binaries contain the *correct SHA-1 of their own DA2* and execute a 20-byte checksum comparison; on mismatch their original code prepares **`0xC0070004`**. Crucially, upstream MTKClient prints **`Upload data was accepted. Jumping to stage 2...` only after `send_data()` reads first protocol status `0`**; it then separately waits for DA2's framed `SYNC`. Thus that log line is *DA1 transfer acceptance, not DA2 execution*. This rules out an **already reported DA1 mismatch status** as the immediate cause of an accepted-then-timeout log, though modified/runtime-patched DAs may differ. [New paired binary+host AST proof](docs/da1-sha1-status-vs-da2-sync-ack.md).
- **New definitive DA1→DA2 ABI evidence (2026-10-10):** Both original MT8167 DA1 binaries **explicitly construct** the `0xFE4A4D42` magic header, a one-bit runtime flag and two copied parameter sections (24+56 bytes V5, 24+32 bytes alternative) at `0x239018` / `0x222A70`. Each puts the resulting **88/64-byte buffer address in R0** before a dynamically targeted `BLX`. Both paired DA2 sizes and magic requirements exactly match. **An intrinsic magic/struct-size mismatch in unmodified matched pairs is contradicted by these instruction traces**; only live memory, incorrect stage transition or modified/mixed agents could make this gate fail. [Pinned Thumb disassembly and offline cross-DA audit](docs/mt8167-da1-runtime-parameter-block-handoff.md). No on-device DA2 execution demonstrated.
- **New BROM EMI-root-cause lead (2026-10-09):** MTKClient's missing-EMI BROM **auto-discovery searches eMMC/UFS, not raw NAND**. Its real `DAconfig.m_extract_emi()` parses the public **2019 Crumpet Preloader as a spurious 37,152-byte EMI**, although the same file includes the genuine **400-byte `MTK_BLOADER_INFO_v28`** record. **The 2019, official 2021 and official Nov-2025 embedded 400B EMI records are byte-identical**, SHA-256 `c2a394668216e8bc20959bef29aee38002854a0b38444f6fcd9877fd5d548120`. This is a verified host extraction bug and a BROM automatic-selection gap, **not proven Crumpet DA2 execution**. [Source, original data and reproduced method](docs/crumpet-emi-2019-layout-and-brom-nand-gap.md).
- **New DA2 bootstrap *failure gate* (2026-10-09):** Both pinned 0x8167 DA1/DA2 pairs share a fully decoded ARM→Thumb parameter contract: DA2 stores incoming **R0** at `0x40000020`, copies **88B (V5)** or **64B (alternate)** of DA1 runtime parameters, and `bootstrap2` validates `0xFE4A4D42` before starting platform/commands. **On a bad argument magic, an actual Thumb `b .` loop prevents SYNC**. After successful initialization both build the **proper 12-byte XFLASH `0xFEEEEEEF` header + four-byte `SYNC` payload**, so a bare-SYNC protocol mismatch is not supported by the original code. [Exact DA2 startup map, error gates and checker](docs/mt8167-da2-bootstrap-r0-magic-sync.md). This is a possible failure mechanism, **not** Crumpet runtime confirmation.
- **New hard DA2 evidence (2026-10-09):** The default `MTK_DA_V5.bin` executable Stage-2 image contains an **exact lookup-table record** for the historical Crumpet **Macronix MX30LF4G28AD** NAND: a valid RAM name pointer, ID `C2 DC 90 A2 57 03`, ID-length 6, **4096-byte data pages and 256-byte OOB**. The alternate MT8167 DA lacks that exact record. A separate upstream AST audit proves `boot_to(timeout=0.5)` only sleeps, `send_data` can loop forever after write failure, and **USB reconnection is deferred until Stage-2 already succeeds**. An empty 12-byte status read produces the misleading generic DRAM line. [Exact bytes, protocol analysis and open questions](docs/mtkclient-stage2-nand-profile-transport.md). **This is not DA2 success or root.**
- **Latest verified root/unlock feasibility (2026-10-09):** The 2019 public Crumpet image has **three additional independently confirmed invalid Amonet function pointers** under its stored-image RAM mapping: `part_get` lands midway through a Thumb-2 instruction, and two TEE-function pointers land **inside actual null-terminated error/training strings**. Same security-related GFH records are byte-identical across 2019/2021/2025, **but that does not establish safe signed downgrade**. The historical NAND chip is identified as Macronix MX30LF4G28AD (4096+256-byte pages); read-only geometry checks are now available. [Concrete root options and missing validation steps](docs/crumpet-root-unlock-feasibility-2026-10-09.md).
- **Further verified Crumpet Amonet blocker (2026-10-09):** `PART_GET_ADDR=0x20F250` points **inside a 32-bit Thumb-2 instruction** (second halfword) in independently manifest-hash-verified official **2022 and Nov-2025** preloader images. In 2021 it lands at an instruction boundary but **not at an established function entry**. [Exact byte/instruction evidence](docs/crumpet-amonet-part-get-thumb2-misalignment.md). This makes the hardcoded function-pointer assumptions substantially less credible without a live RAM map.
- **New 2026 Crumpet TWRP device tree reviewed:** a Crumpet target and prebuilt ARM kernel exist, but shared recovery fstab and init use **eMMC-specific paths**. Five by-name labels are absent from the verified *early NAND GPT*, no built `recovery.img` or successful Crumpet TWRP boot log was established. [Read-only compatibility audit](docs/crumpet-twrp-emmc-vs-nand-audit.md).
- **New, source-proven Crumpet amonet port blockers (2026-10-09):** `enter_usbdl(0)` unconditionally enters a nonreturning USB handshake on Crumpet *before* LK loading (key and cable detection both compile to `true`). Additionally, `LK_PART_NAME "expdb"` is **absent from the CRC-validated Crumpet GPT** in 2019 and November 2025; the source distribution has no `tee_crumpet.img` donor. Even a theoretically executing payload **is not a complete persistent-root boot implementation**. [Source and GPT evidence](docs/amonet-crumpet-unreachable-lk-and-expdb.md).
- **New ARM bootstrap evidence (2026-10-09):** Four genuine 2019/2021/2022/2025 Crumpet preloaders share exactly the same ARM BSS-zeroing and indirect ARM→Thumb handoff instructions. Their embedded SRAM bounds, control-slot pointers, and Thumb continuation destinations differ. A new opcode-validated [bootstrap audit](docs/crumpet-arm-bootstrap-memory-map.md) substantially strengthens the stored-file/VMA mapping, **without proving actual runtime relocation** or any root method.
- **New Crumpet amonet patch-site validation warning:** All five upstream hardcoded RAM-patch addresses were mapped into **2019, 2021, 2022, 2024 and 2025** preloader files. At least one supposed function (`0x217F2C`) maps **inside a USB ASCII diagnostic in the 2019 image**, and other sites change meaning across versions. The upstream patcher writes directly to the given RAM address, without version-based remapping; live RAM relocation remains unverified. [Full byte-by-byte audit](docs/amonet-hardcoded-patch-address-audit.md). **Do not try these constants on a device.**
- **New (2026-10-08): Complete Crumpet NAND/GPT header decode.** We independently verified both CRC32s and **all 18 unchanged logical partition ranges from the public 2019 NAND excerpt through Nov 2025**. All 309 altered bytes in a May→Nov 2025 Preloader partition are **GPT disk/partition GUID bytes plus CRC32 fields**, not new Preloader code. The four redundant boot-copy BRLYT fields map exactly to their corresponding GPT first LBAs. **Not a root/recovery procedure.** [Detailed findings](docs/crumpet-nand-gpt-2019-2025.md).
- **Latest catalogued Crumpet OTA checked:** We verified November **2025** (Fire OS 6.5.7.1, NS6571/6208) and three earlier 2025 OTA images. `lk` remains **byte-identical to Jan 2024**; the full Preloader region from the MediaTek GFH header at `0x8000` is **identical across four 2025 updates** despite differing raw-NAND partition hashes. The **four Nov 2025 boot copies** also have identical GFH images, varying by only 4 position-related prefix bytes each. [Verified comparison](docs/latest-2025-ota-boot-payload-comparison.md).
- **New DA1→DA2 integrity and DA1 sync diagnostic finding:** Both bundled MT8167 DA1 variants embed the **SHA-1 of their own DA2 body** (signature excluded), not the other's. The upstream MTKClient DA1 setup function ignores `False` results from `sync()`, `setup_env()` and `setup_hw_init()`, yet may still log successful DA sync; independently reproduced with synthetic hardware-free mocks. [Detailed evidence](docs/da1-da2-pairing-handoff-checks.md).
- **Revision-match cross-check:** A reported Crumpet preloader has HW `0x8167`, subcode `0x8A00`, HW revision `0xCB00`, SW revision `1`; bundled DA metadata is `0xCA00/SW0`. MTKClient accepts older DAs. An independent same-revision MT8167 eMMC device reaches DA2 using a **same-named**, not hash-verified, V5 loader over **Preloader mode**. This contrasts with Crumpet's BROM/EMI timeout. [Version-matching audit](docs/mt8167-hw-revision-da-selection.md).
- **New Stage-2 handoff finding:** MTKClient's `Stage was't executed` message can be triggered by a missing/truncated **XFLASH USB status response**, not just device failure; the Crumpet's 2019/2021 UART logs show **256 MiB RAM at `0x40000000`**, with both DA2 code/BSS layouts fitting physically. [Status and memory analysis](docs/da2-handoff-status-memory.md).
- **DA2 binary + EMI research:** Both bundled MT8167 DA2 variants have ARM entry `0x40000024` and raw-NAND/BMT diagnostics, but distinct executable bodies. Independently verified official Crumpet 2021/2022/2024/2025 preloaders contain an **identical 400-byte EMI block (`MTK_BLOADER_INFO_v28`)**. No DA2 on Crumpet has been shown to boot. [Detailed binary analysis](docs/da2-binary-emi-compatibility.md).
- **MT8167 Download Agent research:** Source-code auditing identifies Stage-2 timeout as a missing response, **not proof** of DRAM or NAND failure. The bundled MTKClient has **two distinct 0x8167 DA binaries** (both targeting Stage-2 address `0x40000000`), but its version/duplicate selection normally retains only one. [Evidence and limits](docs/mtkclient-da-stage2-analysis.md).
- **Unlock research update:** Independently verified official `lk` binaries from **2021–2025** contain vendor `flash:unlock`, `flash:otucert`, `flash:otucode` strings. For the 2024/2025-identical `lk`, Thumb disassembly confirms the generic Fastboot dispatcher, the actual `unlock` validation call and one-time certificate/code handlers. No publicly validated accepted certificate or persistent Crumpet unlock exists. [Verified LK timeline](docs/lk-image-timeline.md) · [ARM unlock call graph](docs/lk-fastboot-unlock-disassembly.md).
- **Verified newer header-handling call chain:** the loader reads the 512-byte header, parses address/length, optionally transforms the TEE destination, checks protected memory ranges, then performs its larger read. The ATF/TEE verification wrapper follows the load. [Details](docs/tee-header-address-processing.md).
- **Key SRAM protection finding:** newer preloader builds guard BSS `[0x00102180, 0x00109DAC)`, which **contains the published payload's block-device target `0x001086EC`**. A hypothetical copy matching the payload's effective zero destination and size `0x00108804` intersects this protected region, so the new guard would reject it *if passed the actual copy address and size*. [Verified boundaries and conditional analysis](docs/sram-guard-exploit-intersection.md).
- **ARM analysis:** The 2022 preloader range checks and the 2023/2024-era rewritten text/BSS guards have been disassembled, with confirmed literal cross-references and calls. [Code analysis](docs/arm-range-check-analysis.md). This does not establish exploitable behaviour.
- **2023 build now obtained:** the exact Crumpet build string `20231103_072325` appears in preloader images verified from official 2025 OTAs. The image's full hash differs from a community device dump, so bitwise equivalence is **not** claimed. [Verified version timeline](docs/verified-preloader-timeline.md).
- [`amonet-koboreru`](https://github.com/R0rt1z2/amonet-koboreru) has Crumpet-specific code; its maintainer says the NAND port has **not been tested on real hardware** and is on hold.
- A [TWRP device tree](https://github.com/R0rt1z2/twrp_device_amazon_echo-mt8167) exists, but a working Crumpet recovery is **not demonstrated**.

## Where to start

- [Research status and evidence levels](STATUS.md)
- **[DA1 SHA-1 acceptance ACK vs distinct DA2 SYNC: what Crumpet's Stage-2 failure log proves](docs/da1-sha1-status-vs-da2-sync-ack.md)**
- **[Crumpet DA1 builds and passes actual 88/64-byte DA2 runtime magic structures](docs/mt8167-da1-runtime-parameter-block-handoff.md)**
- **[Crumpet 2019 EMI parsing defect and raw-NAND BROM automatic-EMI gap](docs/crumpet-emi-2019-layout-and-brom-nand-gap.md)**
- **[DA1→DA2 bootstrap: verified R0 argument pointer, mandatory `0xFE4A4D42` gate and framed XFLASH `SYNC`](docs/mt8167-da2-bootstrap-r0-magic-sync.md)**
- **[DA2 breakthrough: exact MX30LF4G28AD NAND table match and USB Stage-2 status/reconnect audit](docs/mtkclient-stage2-nand-profile-transport.md)**
- **[Current Crumpet root/unlock feasibility: exact blockers, BROM/Kamakiri entry, downgrade limits, NAND backup requirements](docs/crumpet-root-unlock-feasibility-2026-10-09.md)**
- **[2019 Crumpet Amonet TEE function pointers resolve to ASCII literals](scripts/audit_2019_amonet_string_pointer_collisions.py)**
- **[2019/2021/2025 Preloader GFH signing/security metadata comparator](scripts/audit_crumpet_preloader_gfh_security.py)**
- **[Read-only Macronix NAND 4096+256 dump-size sanity checker](scripts/check_crumpet_raw_nand_dump_size.py)**
- **[Amonet Crumpet `part_get` function pointer enters middle of Thumb-2 instruction on 2022/2025 firmware](docs/crumpet-amonet-part-get-thumb2-misalignment.md)**
- **[Crumpet TWRP storage audit: shared eMMC paths vs Raw NAND partition names](docs/crumpet-twrp-emmc-vs-nand-audit.md)**
- **[Amonet Crumpet source-level boot dead end, missing GPT `expdb` and absent donor image](docs/amonet-crumpet-unreachable-lk-and-expdb.md)**
- **[Crumpet ARM bootstrap: directly decoded BSS clear and Thumb handoff across 2019–2025](docs/crumpet-arm-bootstrap-memory-map.md)**
- **[Published Crumpet amonet hardcoded patch-site audit against 5 verified preloaders](docs/amonet-hardcoded-patch-address-audit.md)**
- **[Fully decoded Crumpet raw-NAND GPT container, valid CRCs, 2019–2025 stable layout, four boot-copy offsets](docs/crumpet-nand-gpt-2019-2025.md)**
- **[Latest 2025 Crumpet LK/Preloader proof: full hash changes occur only in NAND prefix](docs/latest-2025-ota-boot-payload-comparison.md)**
- **[DA1↔DA2 cryptographic pairing, BROM vs Preloader setup, and unchecked DA1 results](docs/da1-da2-pairing-handoff-checks.md)**
- **[MTKClient MT8167 DA Stage-2 timeout: source-code analysis](docs/mtkclient-da-stage2-analysis.md)**
- **[MT8167 DA2 executable comparison and verified 2021–2025 Crumpet EMI block](docs/da2-binary-emi-compatibility.md)**
- **[XFLASH status protocol, USB exception handling and Crumpet's measured 256 MiB DRAM](docs/da2-handoff-status-memory.md)**
- **[HW 0xCB00/SW1 Crumpet versus DA revisions, plus independent MT8167 Stage-2 counterexample](docs/mt8167-hw-revision-da-selection.md)**
- **[Verified LK firmware chronology: 2021–2025](docs/lk-image-timeline.md)**
- **[Decoded vendor LK Fastboot unlock/certificate call graph](docs/lk-fastboot-unlock-disassembly.md)**
- **[Current Crumpet root/unlock feasibility assessment (2026-10-08): verified LK certificate code, BROM limitations and NAND recovery](docs/root-unlock-feasibility-2026-10-08.md)**
- [Boot chain and exploit preconditions](docs/boot-chain.md)
- [Preliminary preloader binary analysis](docs/preloader-analysis.md)
- [Verified 2021 OTA partition inventory, SHA-256 hashes and 2019 comparison](docs/ota-2021-analysis.md)
- [Verified 2021–2025 preloader version timeline and byte differences](docs/verified-preloader-timeline.md)
- [ATF/TEE loading and signature verification: decoded ARM call chains](docs/tee-load-signature-order.md)
- **[TEE header fields and conditional address calculation: guard-before-read trace](docs/tee-header-address-processing.md)**
- **[SRAM/BSS guard versus the published exploit: decoded protection limits](docs/sram-guard-exploit-intersection.md)**
- **[ARM-disassembled old-vs-new memory-range guards, with cross-references and call sites](docs/arm-range-check-analysis.md)**
- [Open technical questions](research/open-questions.md)
- [Sources and attribution](references/sources.md)
- [How to contribute](CONTRIBUTING.md)

## Read-only Python tools

```bash
python3 scripts/preloader_forensics.py --fetch-2019
python3 scripts/preloader_compare.py older.bin newer.bin
python3 scripts/audit_sram_guard.py /path/to/local-2023-era-preloader.bin
python3 scripts/inspect_guard_chain.py /path/to/local-2023-era-preloader.bin
python3 scripts/trace_preloader_calls.py /path/to/local-2023-era-preloader.bin --begin 0x20df40 --length 0xe0 --target 0x20f3ac --target 0x216100
python3 scripts/ota_inventory.py /path/to/original-crumpet-ota.bin --verify-bootloaders
python3 scripts/remote_ota_probe.py 'https://d1s31zyz7dcc2d.cloudfront.net/2025/5/15/e3e28ff9-b9bf-4946-9793-900df1c389ac/update-kindle-crumpet-NS6566_user_6813_0011779349892.bin' --include-lk
# Optional: install Capstone to disassemble a locally obtained preloader
# python3 -m pip install capstone
python3 scripts/disassemble_preloader.py /path/to/local-preloader.bin --address 0x20e3d8 --length 0x2a
# For the exact sha256-pinned official Crumpet LK from Jan 2024 / May 2025:
python3 scripts/inspect_lk_unlock.py /path/to/local-lk.bin
# Purely offline: analyze an EXISTING redacted MTKClient log (no device access)
python3 scripts/classify_mtkclient_stage2.py /path/to/saved-mtkclient.log
# Read-only decoder for a previously captured 12-byte XFLASH status frame + payload
python3 scripts/decode_xflash_status.py --hex 'efeeee fe 01000000 04000000 53594e43'
# Purely offline: inspect your local MTKClient DA loader folder
python3 scripts/audit_mtkclient_da_metadata.py /path/to/mtkclient/mtkclient/Loader --device-hwver 0xcb00 --device-swver 1 --device-subcode 0x8a00
python3 scripts/audit_da_pair_integrity.py /path/to/mtkclient/mtkclient/Loader
python3 scripts/audit_xflash_mode_flow.py /path/to/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py
# Official Amazon OTA Range reads, comparing only hashes/offsets (no saved binaries)
python3 scripts/compare_official_preloader_payloads.py OLDER_AMAZON_OTA_URL NEWER_AMAZON_OTA_URL
python3 scripts/compare_official_boot_copies.py AMAZON_CRUMPET_OTA_URL
# Validate embedded GPT CRCs and boot-copy headers (only reads official OTA)
python3 scripts/audit_nand_boot_gpt.py --official-ota AMAZON_CRUMPET_OTA_URL --copy 0
# Or analyze the publicly archived 2019 excerpt with its earlier byte offsets
python3 scripts/audit_nand_boot_gpt.py --image /path/to/2019/brhgptpl_0.bin
# Read-only mapping of the public amonet Crumpet absolute addresses to historical images
python3 scripts/audit_amonet_patch_sites.py /path/to/amonet/amonet/devices/crumpet.c /path/to/amonet/amonet/patch.c /path/to/preloader.bin
# Read-only A32 bootstrap/BSS/Thumb-address validation against local preloader image
python3 scripts/audit_preloader_bootstrap.py /path/to/preloader.bin
# Validate Amonet source boot path and actual Crumpet NAND GPT names, read-only
python3 scripts/audit_amonet_crumpet_boot_flow.py /path/to/amonet-koboreru/amonet --official-ota AMAZON_CRUMPET_OTA_URL
# Offline validation of Crumpet Amonet part_get Thumb entry (requires Capstone)
python3 scripts/audit_crumpet_amonet_part_get_entry.py /path/to/amonet/amonet/include/devices/crumpet.h /path/to/verified/preloader-2025.bin
# Cross-check public TWRP source fstab with early NAND GPT (read-only)
python3 scripts/audit_crumpet_twrp_storage.py /path/to/twrp_device_amazon_echo-mt8167 --official-ota AMAZON_CRUMPET_OTA_URL
# Offline pinned-image security headers and two 2019 TEE pointer collisions
python3 scripts/audit_crumpet_preloader_gfh_security.py /path/to/2019.bin /path/to/2021.bin /path/to/2025.bin
python3 scripts/audit_2019_amonet_string_pointer_collisions.py /path/to/amonet/include/devices/crumpet.h /path/to/public-2019.bin
# Existing device-authorized NAND dump file: file size only, NO ECC/restore claim
python3 scripts/check_crumpet_raw_nand_dump_size.py /path/to/local-dump.bin
# Inspect SHA-pinned MT8167 DA2 NAND lookup table and diagnostic USB source (NO device)
python3 scripts/audit_da2_crumpet_nand_profile.py /path/to/mtkclient/mtkclient/Loader
python3 scripts/audit_xflash_stage2_transport.py /path/to/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py /path/to/mtkclient/mtkclient/Library/Connection/usblib.py
# ARM+Thumb proof of DA1→DA2 runtime R0/magic, deliberate hang and framed SYNC
python3 scripts/audit_da2_bootstrap_contract.py /path/to/mtkclient/mtkclient/Loader
# Purely offline old/current Crumpet EMI records vs MTKClient GFH parser and BROM auto-discovery
python3 scripts/audit_crumpet_emi_fallback.py /path/to/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py /path/to/2019.bin /path/to/2021.bin /path/to/2025.bin
# Validate original DA1 parameter assembly, stack-derived indirect BLX, and DA2 ABI
python3 scripts/audit_da1_runtime_handoff.py /path/to/mtkclient/mtkclient/Loader
# Verify original DA1 embedded SHA-1 compare and host's *two* independent status reads
python3 scripts/audit_da1_stage2_sha1_ack.py /path/to/mtkclient/mtkclient/Loader /path/to/mtkclient/mtkclient/Library/DA/xflash/xflash_lib.py
python3 scripts/audit_da_stage2.py /path/to/mtkclient/mtkclient/Loader
python3 scripts/audit_preloader_emi.py /path/to/local-crumpet-preloader.bin
python3 -m unittest discover -s tests -v
```

All tools only inspect input bytes and print findings; they do **not** communicate with devices or flash firmware. The forensics tool's optional fetch retrieves a public reference file over HTTPS. Missing strings or simplistic file-offset calculations cannot establish exploitability.

## Scope and safety

This repo hosts original research notes and non-destructive scripts only. **No Amazon firmware dumps, private identifiers, secrets, or unverified flash instructions.** Please label observations vs community reports vs hypotheses; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Original research documentation and scripts in this repository are provided under MIT. Third-party works remain with their original authors.

## Latest DA1 state-provenance update (2026-10-11)

[Default-value initializer and subsequent state-store audit](docs/da1-state-defaults-and-overrides-2026-10-11.md): both exact stock MT8167 DA1 binaries contain default-state initializer routines for the 56/32-byte source later copied into DA2, plus separate stores targeting some of those fields. The [offline checker](scripts/audit_da1_state_initializers.py) requires original SHA-256-pinned agents; ten additional synthetic regressions bring the offline suite to **232/232 passing** (checked on hermes). This is not a live DA2 boot/root result; source initialization order and actual hardware values are still unknown.

### Root research direction (2026-10-11)

**Strategy changed:** [Evidence-gated, eight-route Crumpet root/unlock assessment](docs/crumpet-root-strategy-decision-2026-10-11.md) pauses incremental DA1/DA2 disassembly without fresh physical evidence. Priorities are discriminating *existing* same-device USB/DA2 traces, an independent raw NAND backup/restore validation standard on expendable hardware, and new exact-C78MP8 exploit/unlock evidence. An increased offline regression-test count **does not** imply progress toward root. No verified root/unlock is available.
