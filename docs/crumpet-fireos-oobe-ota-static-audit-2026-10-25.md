# Crumpet Fire OS 2022/2023: real-binary OOBE/OTA static audit (2026-10-25)

**Target:** Amazon Echo Dot 3 Refresh, `C78MP8` / `crumpet` (MT8167/MT8516, raw NAND).  
**Question:** Does the stock setup/OTA surface expose an obvious initial custom-firmware upload, installation or arbitrary-code execution route, independent of Amonet and DA2?  
**Result:** **No such route demonstrated in this focused offline audit.** The actual `DopplerOOBE` Thrift service exports 18 unchanged method names in both builds, none named for uploading or installing firmware. Their implementation, authorization and runtime reachability have **not** been comprehensively proven; a method-name inventory cannot exclude bugs or undiscovered code paths.

**Method:** independent examination on authorized Linux research machine `hermes` of two official Amazon update archives, their reconstructed `system` SquashFS partition images, Android init scripts, dynamic ELF symbols and read-only printable strings. No extracted Amazon executable was run. No USB or network traffic to an Echo, no live device boot, no flash, no NAND write, no developer messages or external GitHub posts. Private/non-public user identifiers were not accessed. Vendor package signatures were **not** independently verified.

## 1. Source identity and integrity

URLs come from the [FTVDB Crumpet firmware index](https://github.com/FTVDB/FTVDB/blob/main/database/firmware/com.amazon.crumpet.android.os.json). The complete archives were downloaded from the listed Amazon CloudFront endpoints and independently SHA-256 hashed. The values matched [OpenDot's archived two-release file inventory](https://github.com/chadakenn/opendot/blob/main/docs/firmware-comparison.md).

| Item | November 2022 | June 2023 |
|---|---|---|
| Version | Fire OS 6.5.5.5 `NS6555/4307` | Fire OS 6.5.5.9 `NS6559/4660` |
| Source | [Official archive](https://d1s31zyz7dcc2d.cloudfront.net/0485845e3f9082ae176fbd54f0183bbe/update-kindle-crumpet-NS6555_user_4307_0008087720836.bin) | [Official archive](https://d1s31zyz7dcc2d.cloudfront.net/92c5511f6db8ee28c00430c3afe87c2e/update-kindle-crumpet-NS6559_user_4660_0009094444164.bin) |
| Full-file SHA-256 | `e1d5138f1fa283c336139c7601099a6b87a3d1ff79220fa78ccb5568daf2e83e` | `1a84d094b8b5fe51514e1c1ed773645204720a47c460a17f391100ad8e8d6e6d` |
| Reconstructed `system` SHA-256 | `53bec617d2b9b2d3b2ca5ae10eeb30e09ad57390530519fa156f24fafd8cc020` | `f8335b744c31f04c77daa24fc0978041c952a0fe9536e749ed94b6019a1caa3f` |
| System image length | 136,626,176 bytes | 136,626,176 bytes |

The `system` images were reconstructed with [OpenDot's read-only-input partition extractor](https://github.com/chadakenn/opendot/blob/main/tools/extract_partition.py), which verifies operation/final-image hashes against the **given archive's CrAU payload manifest**. Agreement with hashes and manifest **does not authenticate Amazon's original package-signing chain**. Neither archive is confirmed to be the firmware on any particular user-owned C78MP8.

## 2. Actual OOBE launch configuration and privileges

The recovered `system/etc/init/init.oobe.puffin.rc` is **byte-identical** in both releases, SHA-256 `b25dd0b20ce010d550ea37500dbf9b73fc78a25fa95ebfa818e0c8eab3b8b968`.

- Android init defines three disabled, one-shot service variants invoking `/system/bin/oobed -r 1`, `-r 2` and `-r 3`. These run as **user `oobe`**, not `root`, with various named supplementary groups.
- Startup actions are conditional on `com.amazon.puffin.OOBED_START` values `on_boot`, `on_button_press`, `on_network_disconnect`; `oobe_setup` has its own `OOBE_SETUP=1` property trigger. This is **configured conditional startup**, not proof that all modes run on every device.
- `system/etc/init/init.ace.otad.rc` defines `ace_otad` as **user `ace_otad`**, class `core`. `init.mt8516.rc` separately defines `otad` under **user `ace_otad`**, class `main`.
- `system/etc/init/on_demand_update_engine.rc` defines `update_engine` as **user `root`**, class `late_start`, explicitly **`disabled`** (on-demand). Its config is byte-identical in both releases.

These are runtime *intent/configuration* observations. There is no evidence here of an OOBE caller gaining `root` merely because a different on-demand update service runs as root. Process isolation, Binder permissions, SELinux enforcement and live network exposure require separate proof.

## 3. Independently enumerated Thrift interface (18 methods)

Both `oobed` executables dynamically depend on `libdoppleroobe.so` and `libcivetweb.so`. Offline `strings` from `oobed` contain the route markers `/OOBE`, `/proxy.js`, `8080`, and Thrift handler diagnostic strings. These establish **compiled-in references**, not a live open port on a particular network/interface or an authentication result.

**Important primary-source improvement over previous second-hand notes:** The generated `libdoppleroobe.so` exports **18 distinct `OOBE::DopplerOOBEProcessor::process_*` dynamic symbols** in **both** builds. The whole library is byte-identical, SHA-256 `7bb75f692c0e8e3b45a50809050bf062a9401c78dd63be758297da804131ee4d`. The exact list is:

| Provisioning / network | Status / configuration |
|---|---|
| `connectToAP`, `connectToAPEx`, `connectToAPv2`, `connectToAPv2Ex`, `disconnectFromAP`, `evaluateCaptivePortal`, `forgetAP`, `getScanList`, `getKnownList` | `getOTADetails`, `getDeviceDetails`, `getRegistrationState`, `getAlexaConnectionState`, `getLinkCode`, `generateCSR`, `setLocaleAndEndpoints`, `setupComplete`, `ping` |

**Interpretation:** The compiled RPC processor **does not advertise** a `flash`, `uploadFirmware`, `applyPayload`, `installImage` or remote-shell method. `getOTADetails` is an exposed named RPC, but its full handler behavior, credentials, and server dispatch were **not** control-flow-proven by this symbol-level check. Nor does the absence of a named upload RPC prove the overall service is free of exploitable vulnerabilities. Additional dynamically registered routes, indirect callbacks or memory-safety issues were not exhaustively examined.

One `oobed` printable string refers to `decryptDataUsingShellCommand`. It is **not** part of the enumerated generated Thrift `process_*` interface. A diagnostic string alone does **not** establish remotely controllable shell execution or injection; no such claim is made.

## 4. OTA separation and two-version binary differences

| Extracted file | Comparison | SHA-256 or observation |
|---|---|---|
| `system/bin/update_engine` | **Identical** | `03dd12c11643da8500d46e07083d72f93c3695cfb728daa7c2b0a8e569738412` |
| `system/lib/libdoppleroobe.so` | **Identical** | `7bb75f692c0e8e3b45a50809050bf062a9401c78dd63be758297da804131ee4d` |
| `system/lib/libcivetweb.so` | **Identical** | `48cfe2ad0803ac98921014898d996d02e8d522969650fbc54a22d488629b9d0b` |
| `system/etc/security/otacerts.zip` | **Identical** | `741dcd1bf1a2135d43539f64ce2667448879ac4f91a97cdd53bb64c4a0d6a8d7` |
| `system/etc/update_engine/update-payload-key.pub.pem` | **Identical** | `a8daa18a171775e19f0595ec6393d4e3dd9b7e6eb57151240e3accb92a1716c0` |
| `system/bin/oobed` | Different | 2022 `1187080a5d6de8c07dd95f891e8b809bb524512373dcde0086b50916096b33e4`; 2023 `52758de944deaa30be0d2c56b07ecb26b260b4a3c4bb93873db67928a81deb4c` |
| `system/bin/ace_otad` | Different | 2022 `d06285474d9780ab68e379539f794c36a199cc3ba23efd725bb1fd155b6d3c32`; 2023 `419c0c180011544af804f71848ef551839e1be3fc6849be1bebebebb5908df7b` |
| `system/bin/otad` | Different | 2022 `14af51a2ac71e39be370c10f92b46d5059bd880ef39c04729c9cb564a7e0168f`; 2023 `fc3a8fc0734e77ac5f69add2ffe35b6bf3dfcd0b06dfc516c2774a716e6d557e` |

The `otad` binary has dynamic Android Binder references and logs about connecting to `IUpdateEngine`. That supports a **local Binder-mediated orchestration relationship**, not a demonstrated unauthenticated network-facing privileged installer. The newer `otad` has printable `Signature matches` diagnostics; their presence or absence cannot independently establish verification policy. Identical trust-key bytes are consistent with continued trusted update policy but are **not an end-to-end cryptographic security proof**.

## 5. Reproduction (host-only, no executable firmware launch)

Use legally obtained *unmodified* copies of the two official Crumpet OTA archives and a local checkout of [OpenDot's extractor](https://github.com/chadakenn/opendot/blob/main/tools/extract_partition.py). Example commands assume the archives have been saved locally as `2022.bin` and `2023.bin`:

```bash
sha256sum 2022.bin 2023.bin

python3 opendot/tools/extract_partition.py 2022.bin system system-2022.img
python3 opendot/tools/extract_partition.py 2023.bin system system-2023.img
sha256sum system-2022.img system-2023.img

for y in 2022 2023; do
  unsquashfs -no-xattrs -no-progress -d "extract-$y" "system-$y.img" \
    system/bin/oobed system/bin/otad system/bin/ace_otad system/bin/update_engine \
    system/lib/libdoppleroobe.so system/lib/libcivetweb.so \
    system/etc/init system/etc/security/otacerts.zip system/etc/update_engine
  nm -D -C "extract-$y/system/lib/libdoppleroobe.so" \
    | grep -o -E 'DopplerOOBEProcessor::process_[A-Za-z0-9_]+' \
    | sort -u
done
```

This performs read-only examination of firmware input, writing **only local** extracted files. Do not redistribute full Amazon archives, extracted executable blobs or device-private content. Missing optional dependencies, filesystem variations and unverified signing/installed build should be recorded instead of assumed away.

## 6. Decision for root/unlock research

**Scoped branch `WI-01` (first-install via OOBE/OTA): PARK for now.** A real C78MP8 two-version binary investigation corroborates the setup service and update orchestration, while providing **no published direct firmware-upload RPC, no independently validated unauthenticated code-execution entry, and no signed update bypass**. The original **13 Amonet/DA2/Fastboot/NAND blocker gates remain unchanged**.

**Resume only if** primary evidence supplies a relevant, reachable exact-firmware privileged operation or independently validated vulnerability/authorization flaw; link the version and observed privilege boundary. A different service hash, a keyword, a generic CVE or an unverified cached version number is insufficient. No additional blind network probing or unsafe hardware experiments are justified. This is **not** a proof that every Crumpet software vulnerability is impossible.

Source of earlier reported hypotheses: [OpenDot OTA/provisioning architecture](https://github.com/chadakenn/opendot/blob/main/docs/ota-architecture.md). This document independently validates a narrower subset: actual file hashes, Android init service configuration, dynamic dependency and exported Thrift processor method names.
