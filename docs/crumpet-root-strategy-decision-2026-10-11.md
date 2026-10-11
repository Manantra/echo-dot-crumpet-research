# Crumpet root/unlock strategy reset — evidence gates instead of disassembly loops

**Date:** 2026-10-11. **Device:** Amazon Echo Dot 3rd Gen Refresh C78MP8 / AEOCP / `crumpet`, MediaTek MT8167/MT8516, **raw NAND**. **Purpose:** decide which research could materially advance a *reproducible, recoverable* unlock, and which branches should stop consuming effort. **This is an evidence-based decision memo, not a new exploit or a claim that all routes are impossible.** No device access, NAND write, DA upload, eFuse operation or risky experiment.

## Decision in one sentence

**Suspend further unprompted DA1/DA2 static micro-analysis.** Continue DA2 *only* when new, discriminating, existing Crumpet hardware evidence is available; work independently on a safe raw-NAND read/restore evidence standard for a sacrificial device; watch for an authenticated, independently reproducible Crumpet-specific new entry. Do not equate increased test count with root progress.

## 1. What we really know

Evidence classes are deliberately different:

- **Direct offline verification:** repository checkers cross-validated the supplied original Amazon OTA components, several preloader/LK versions, DA1/DA2 binaries and their handoff logic. V5 DA2 contains a record for historical `MX30LF4G28AD` NAND, while no root code was executed on a real Crumpet. The two matching stock DA1s construct compatible argument blocks, and original DA1 has mutable source state. See [handoff](mt8167-da1-runtime-parameter-block-handoff.md), [state provenance](da1-state-defaults-and-overrides-2026-10-11.md), [Stage-2 transport](mtkclient-stage2-nand-profile-transport.md), [vendor LK](lk-fastboot-unlock-disassembly.md), [Amonet blockers](crumpet-root-unlock-feasibility-2026-10-09.md).
- **Third-party observations, not reproduced here:** [September–October 2026 Crumpet reports](https://github.com/R0rt1z2/amonet-koboreru/issues/2) describe BROM/Kamakiri success and preloader dumping on some units, but DA Stage 2 not completing. An October 7 report from *a different owner* documents **Preloader** USB `0e8d:2000`, Fastboot `0bb4:0c01`, inability to see BROM `0e8d:0003`, and a returned **`DA_IMAGE_SIG_VERIFY_FAIL (0x2001)`** during an attempted DA upload. This is evidence of a rejected upload through that reported preloader path, **not** proof that BROM/Kamakiri is universally unavailable or that DA2 failed for the same cause on other units. Do not reproduce unsafe attempts on primary hardware.
- **Independent status corroboration:** [echo-dot-assist README](https://github.com/Gamer92000/echo-dot-assist) marks `donut D9N29T` supported, but **`crumpet C78MP8` unsupported**. Its author's [October 3, 2026 Crumpet assessment](https://community.home-assistant.io/t/echo-dot-3rd-gen-2018-as-a-fully-local-assist-satellite-keeping-amazons-mic-array-and-wake-word-engine/1025971/36) says currently known exploits are patched. This is a firsthand developer assessment, not a proof that *all possible* vulnerabilities are excluded.
- **Historical physical NAND capability, not validated restore:** [no-alexa](https://github.com/jvandewiel/no-alexa) documents physical NAND readback on an earlier unit, while [mtk-nand-utils](https://github.com/gilderchuck/mtk-nand-utils) implements MT8167/MT8516 PRBS/scrambler and BCH decode for 4096+256-byte pages. A read/decoded dump is not automatically a verified image or writable recovery.

**Unreached milestones:** no independently documented on-device DA2 `SYNC` on C78MP8, no complete same-device raw NAND+OOB capture *and validated restore*, no accepted Amazon fastboot unlock credential, no booted custom LK/kernel/TEE, no persistent root.

## 2. Decision matrix (ordinal, not probabilities)

| Route | Existing foothold | Main missing proof | Practical effort / brick risk | Decision / trigger |
|---|---|---|---|---|
| **A. Existing BROM/Kamakiri → DA2** | Some independent C78MP8 BROM/Preloader-read reports; two pinned DA pairs audited | Exact same-session selected DA hashes, EMI source, first ACK, later XFLASH status, USB disconnect events and Stage-2 execution | Low risk for *offline review* of historical logs; live arbitrary DA uploads are not automatically safe | **Conditional priority 1**: resume **only** when a diagnostic trace can distinguish competing hypotheses or a separate credible C78MP8 DA2 `SYNC` is reported |
| **B. Physical raw-NAND imaging/recovery** | Crumpet chip geometry from UART; read/decode resources exist | Same-chip two consistent main+OOB dumps, OOB/ECC/PRBS/BBT/boot-copy validation, independently working **write-back + boot** on expendable hardware | High skill/cost; potentially destructive | **Priority 2 for an equipped, consenting researcher with a spare unit**: work on repeatable decode and recovery standard, **not** a guessed flash |
| **C. Amazon LK one-time unlock** | Actual signed LK command parser and certificate/code checks confirmed | Valid legitimate production-issued credential/authorization, or independently established specific verification flaw | Low-risk documentary investigation; speculative unlock/flash is risky | **Park** pending new issuer documentation or verified code-level bypass with production-device proof |
| **D. Fire OS / kernel privilege escalation** | Known Android/Linux foundation and OTA image access; no specific entry proven | Actual reachable unprivileged input/execution entry; affected exact build and kernel; escalation; persistence across verified boot | Medium-to-high research effort; noisy non-transferable CVE speculation | **Event-driven only**: a C78MP8-tested exploit or precise matching reachable attack surface, not generic MTK CVE lists |
| **E. Old Amonet Crumpet TEE/Preloader port** | Untested source port; community donor-era discussion | Authentic exploit entry and valid targets; proper USB/LK path; correct NAND partition alias; safe recovery | Very high brick risk and multiple **independent current source blockers** | **Stop on device; no more porting-by-assumption.** Reopen only on original author’s real Crumpet demonstration or new validated live-memory evidence |
| **F. Old signed Preloader downgrade** | Old official firmware and similar GFH record layout | BootROM authorization and rollback accept; device-specific restore plan | Extremely high; can destroy boot chain | **Stop** until recovery is independently proven and signed older code acceptance is verified without flash assumptions |
| **G. TWRP/custom recovery** | Crumpet-labelled tree | Real boot entry, NAND-aware fstab, tested image, verified security bypass | High risk; *downstream* of already unsolved boot access | **Stop** as an independent entry strategy |
| **H. JTAG / voltage/clock fault / NAND glitch** | Analogy to other Amazon/MTK devices, not Crumpet proof | C78MP8 debug interface accessibility or controlled-fault proof and ability to recover | Highest expense/hardware risk | **Long-horizon spare-unit lab only; not recommended as next action** |

Do not confuse *best path for technical information* with *best route to root*: raw NAND chip-off might produce useful evidence while doing nothing to bypass secure boot; a DA2 read primitive might work without permitting an unsigned kernel.

## 3. Stopping the research loop: concrete go/no-go rules

### Gate A — Has the DA2 project learned anything new about a *real* C78MP8?

**GO only on at least one**:
- Previously captured, owner-authorized, redactable same-session USB+host transcript with stage mode (BROM vs Preloader), exact selected original/patch DA identity, EMI identification, the first DA1 ACK, XFLASH status read exception and USB enumeration chronology.
- Independent authentic report of a DA2 `SYNC` response or **read-only** NAND ID/data command on a named C78MP8 hardware/firmware revision.
- Reproducible, original-source host defect that unambiguously explains a *recorded* device behavior, rather than a speculative alternative.

**STOP** if only new literal xrefs, arbitrary additional DA1 functions, test-count growth, or more DA2 timeout anecdotes without discriminating logs appear. Earlier apparent success strings are only stage-specific ACKs, not proof of successful DA2 startup.

### Gate B — Is NAND recovery demonstrably independent?

**GO** on a spare/donor unit with documented chip ID, main+OOB raw captures checked twice for consistency, independent ECC/PRBS/BBT validation, all boot copies and device-private areas accounted for, and verified **restore + cold boot** after an intentionally controlled spare-unit experiment, with electrical/ESD precautions.

**STOP** if there is only a nominal file size, a decoded data-only image, a donor flash from another unit, or a tool claiming it can *write* without a successful restore trial. Do not touch primary hardware.

### Gate C — Can a new path actually escape the verified boot chain?

**GO** only if it has concrete exact-device proof of one of: a valid authorized unlock, code execution at the required privilege level, a checked exploitable flaw in an actual Crumpet build, or a booted custom image. The next step must identify precisely what secure-boot barrier it crosses.

**STOP** if the evidence consists solely of a Fastboot command *string*, a generic root exploit on another MT8167 product, or a `donut/biscuit` port copied to `crumpet`.

## 4. Revised research order and resources

1. **Once-only evidence inventory:** check whether public owner reports actually include raw USB event timestamps/packet data and DA/EMI hashes. If not, **park DA1/DA2 now**; do not start another static register-tracing chain.
2. **Standalone recoverability work** using already published **read-only** NAND samples, decoder checks, and explicit device-unique/OOB/BBT constraints. The deliverable is a *proof bar*; a safe restoration requires a sacrificial device, not just a script.
3. **External proof watch** for truly new C78MP8 hardware demonstrations, valid Amazon authorized unlock issuer evidence, specific production Fire-OS vulnerability, or supported custom boot. Different model codes and unsupported repo badges are not proof.
4. **Redirect on real user goal:** if the desired output is a local Home Assistant assistant rather than the puzzle of *rooting this exact chip*, an already supported `donut`/other supported device is a distinct, far more practical route. **It does not root or repurpose the existing C78MP8.**

## 5. Research scorecard to avoid metric gaming

Measure: **(a)** externally reproducible *on-C78MP8* capability, **(b)** resolved branch decision, **(c)** actually validated restore, and **(d)** independently executed custom code / root. Do **not** use number of tests, source xrefs, commits, functions, SHA matches, or discovered generic gadgets as proxies for unlock progress. The previously reported **232/232 offline tests** remain useful for *correctness* of the offline assertions, but are **not** root-success evidence.

**Outcome of this strategic review: NO validated practical unlock as of 2026-10-11.** No quantified probability is supportable. This memo is a stopping/triage decision; it did not run new tests or change device firmware. See [STATUS.md](../STATUS.md), [open questions](../research/open-questions.md) and [upstream issue #2](https://github.com/R0rt1z2/amonet-koboreru/issues/2).
