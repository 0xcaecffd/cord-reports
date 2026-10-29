---
title: Technical analysis: the NSIS and Electron fake Steam installer (c8628650)
date: 2026-10-29
summary: Full CORD Research static analysis of the representative 61 MB installer: the NSIS stub, the 7-zip and asar layers, and the bytenode V8 payload.
tlp: CLEAR
tags: technical analysis, CORD Research
hidden: true
---

<div class="callout" markdown="1">

Technical companion to [the main report](../2026-10-steam-lure/index.html). This is the CORD Research
pipeline's full static analysis of one representative sample, published as produced:
questions, narrative, layers, behaviours, IOCs, detection anchors, reachability, unknowns,
functions and evidence. Nothing was executed. Evidence hashes are SHA-256 prefixes of the
exact bytes each claim rests on.

</div>

| | |
|---|---|
| sha256 | `c86286508d09cd68ff0a38b7db9b6f76fd353a9a009402c9c512a568e439b46b` |
| schema | `cord-research.report/1.5.0` |
| created | 2026-10-29T01:12Z |
| blind run | no |
| depth | full |
| verdict | L2: malicious payload stealer (confidence 0.75; evidence E25, E26, E27, E28) |
| family | not attributed |
| model | claude-opus-4-6 · medium |
| gate | gated no; truncated_of None; capture_defect None |

## Questions

| id | question | status | evidence | unknowns |
|---|---|---|---|---|
| Q1 | What the file is: format, toolchain, packing, layers and how each is decoded | answered | E1, E17, E18, E19, E20, E21 |  |
| Q2 | What it does: capabilities and the functions behind them | answered | E5, E6, E10, E11, E20, E22, E25, E26, E27, E28 | U3 |
| Q3 | Configuration and IOCs, each marked observed or inferred | answered | E15, E16, E17, E27, E28 |  |
| Q4 | Classification, with confidence | answered | E20, E21, E22, E23 |  |
| Q5 | Unknowns and limits | answered | E20 |  |

## Narrative

## Summary

A 64 MB NSIS 3 Unicode installer (PE32 x86, MSVC, ASLR and NX enabled) wraps a trojanized Electron application that impersonates Steam. The NSIS overlay at offset 0x1a600 (63 MB, entropy 8.0) holds a deflate-compressed 7z archive containing a renamed Chromium-based executable, supporting DLLs, and an Electron asar package. The asar's entry point loads compiled V8 bytecode through bytenode, hiding the payload's logic from static JavaScript analysis. That bytecode (L2, 93 KB) is a credential stealer: it opens targeted URLs in a BrowserWindow with nodeIntegration enabled and contextIsolation disabled, injects CSS and JavaScript, and exfiltrates collected data to two HTTPS endpoints (I3, I4).

## Behaviour

The NSIS stub (L0) enters at 0x40338f, initializing OLE and the command line (B1, B2). A dynamic API resolver loads functions from a module/function name table (B3, E3). The bytecode interpreter at 0x401434 processes NSIS instructions through a state-driven dispatch table (B5 through B9). The self-reader validates the NSIS header magic and maps archive data (B10, E29). A string variable resolver expands bytecoded strings with installer paths, environment variables, registry values and shell folders (B12, E31). Registry helpers create keys and query values (B6, E32, E33). The installer page dialog manages threaded extraction with progress display (B13, E13). Once extraction finishes, CreateProcessW launches the dropped payload with CREATE_NO_WINDOW (0x4000000), hiding the Electron process (B11, E30). The NSIS stub has no custom malicious code; all 27 decompiled functions are standard NSIS 3 runtime internals (B15, E20).

The Electron asar (L1, 202 KB) contains a 44-byte main.js that loads main.jsc through bytenode (B16, E21, E24). The package.json claims authorship by Valve Corporation with product name "steam-login-app" (B19, E17, E23). The V8 bytecode (L2, 93 KB, magic 0xdf05dec0) contains 176 recoverable strings (E26). These reveal a BrowserWindow configuration with nodeIntegration enabled and contextIsolation disabled, a TARGET_URLS array, CSS injection using a dark theme (#212328), obfuscated _0x-prefixed variable names (27 occurrences), a custom-encoded string table (indices A0077 through A0170), and references to browser storage and service worker paths (B17, B18, E22). Two HTTPS URLs in the bytecode constant pool serve as exfiltration endpoints (B20, E27, E28), one for data upload (I3, I4). The bytecode also references file system and path operations consistent with local data collection before exfiltration (B21, E26).

The V8 bytecode cannot be fully disassembled without the matching V8 engine version (Chrome 122 User-Agent string present); string extraction and IOC scanning provide partial visibility into the payload's logic (U5, resolved by E25 through E28). The NSIS installer script bytecode was not decoded (U2), and no family-specific patterns matched (U4).

## Reach

The L0 call graph has 105 internal functions with 87 reached from the single entry root, 27 decompiled in the main-path sweep. All 24 high-value reached functions are accounted for. L1 was extracted from the NSIS archive and its asar structure parsed (E24). L2 was extracted from the asar and triaged: FLOSS recovered 176 strings and 3 IOC candidates (2 URLs kept as I3 and I4, 1 version-like IPv4 declined).

## Verdict and anchors

L2 is the malicious payload, capability class stealer, confidence 0.75. L0 is a malicious dropper. No family is attributed: the cluster label names no known family, and the V8 bytecode prevents code-level comparison to published stealer frameworks. Strongest anchors: A1 (NSIS interpreter dispatch structure, structural constant); A3 (rich header, structural constant); A5 (NSIS-over-7z-over-asar nesting with bytenode, structural constant); A6 (asar package.json metadata with forged Valve fields, config tier); A7 (V8 bytecode with TARGET_URLS and obfuscated variables, behavioural template).

## Layers

| id | parent | format | size | sha256 | verdict | hop |
|---|---|---|---|---|---|---|
| L0 |  | PE32 | 63935908 | `c86286508d09cd68ff0a38b7db9b6f76fd353a9a009402c9c512a568e439b46b` | malicious dropper (confidence 0.4; evidence E1, E10, E11) |  |
| L1 | L0 | electron_asar | 201982 | `6942177c4eae47027e058bdadec8d82afb4826ea4e459ac0e5bc938038f417cc` | malicious payload stealer (confidence 0.7; evidence E20, E21, E22, E23, E24) | nsis_extract_then_7z_extract, emulated no; evidence E20 |
| L2 | L1 | v8_bytecode | 93416 | `3bf8b47b12d4630495baf611033c80ac6d31c27117b8a0409048d52b8e6260f7` | malicious payload stealer (confidence 0.75; evidence E25, E26, E27, E28) | asar_extract, emulated no; evidence E24 |

### Derived artifacts

| id | of | path | transform | evidence |
|---|---|---|---|---|
| D1 | L1 | `out/L1/sample.bin` | nsis_extract_then_7z_extract | E24 |
| D2 | L2 | `out/L2/sample.bin` | asar_extract | E25 |

## Behaviours

| id | layer | behaviour | ATT&CK | MBC | reach | evidence |
|---|---|---|---|---|---|---|
| B1 | L0 | privilege escalation via token adjustment | T1134.002 |  | reached | E1 |
| B2 | L0 | environment variable manipulation | T1574.007 |  | reached | E2 |
| B3 | L0 | dynamic API resolution via name table | T1106 | E1059 | reached | E3 |
| B4 | L0 | system shutdown capability | T1529 |  | reached | E4 |
| B5 | L0 | file system operations via NSIS interpreter | T1083 | E1083 | reached | E5 |
| B6 | L0 | registry read and write | T1112 | E1082 | reached | E6 |
| B7 | L0 | library loading and unloading | T1129 |  | reached | E7 |
| B8 | L0 | COM object instantiation | T1559.001 |  | reached | E8 |
| B9 | L0 | INI file read and write | T1005 |  | reached | E9 |
| B10 | L0 | NSIS archive parsing from overlay | T1140 |  | reached | E10 |
| B11 | L0 | process creation and shell execution | T1204.002 |  | reached | E11 |
| B12 | L0 | installer UI and path resolution |  |  | reached | E12 |
| B13 | L0 | clipboard write and thread creation | T1115 |  | reached | E13 |
| B14 | L0 | uninstaller registration |  |  | reached | E14 |
| B15 | L0 | NSIS installer drops Electron app disguised as Steam | T1036.005 |  | reached | E20 |
| B16 | L1 | Electron app uses compiled V8 bytecode (bytenode) for code hiding | T1027 |  | unknown | E21, E22 |
| B17 | L1 | Fake Steam login with BrowserWindow, CSS/JS injection, and TARGET_URLS targeting | T1056.004 |  | unknown | E22 |
| B18 | L1 | Browser storage and service worker data access | T1539 |  | unknown | E22 |
| B19 | L0 | Impersonates Valve Corporation in version info and package.json | T1036.005 |  | reached | E17, E23 |
| B20 | L2 | HTTPS exfiltration endpoints embedded in V8 bytecode near end of file | T1041 |  | unknown | E27, E28 |
| B21 | L2 | V8 bytecode references file system and path operations for data collection | T1005 |  | unknown | E26 |

## IOCs

| id | type | role | value | port | layer | method | bestiary | evidence |
|---|---|---|---|---|---|---|---|---|
| I1 | url | other | `hxxp://nsis[.]sf[.]net/NSIS_Error (stock NSIS string, benign)` |  | L0 | plaintext | urls | E15 |
| I2 | registry_key | other | `Software\Microsoft\Windows\CurrentVersion (stock NSIS string, benign)` |  | L0 | plaintext | registry_keys | E16 |
| I3 | url | c2 | `hxxps://fakefake[.]shop/3253523` |  | L2 | plaintext | urls | E27 |
| I4 | url | c2 | `hxxps://pulse-keys[.]store/6887` |  | L2 | plaintext | urls | E28 |

## Anchors

### A1 · nominated · realtime · build · L0

NSIS overlay with high entropy and large size at fixed offset

- on disk: yes; singleton: yes
- locator: base overlay; delta 0
- pattern: structure, RAW, bytes in E10
- durability (structural_constant): overlay offset and NSIS header are fixed by the build
- expected false matches: other NSIS installers with large overlays; needs version info or icon to narrow
- evidence: E10

### A2 · nominated · realtime · build · L0

PE version info resource fields identifying this build

- on disk: yes; singleton: yes
- locator: base resource; delta 0
- pattern: metadata, RAW, bytes in E17
- durability (config): version info is set by the NSIS script and may change between builds
- expected false matches: legitimate software using the same company or product name
- evidence: E17

### A3 · nominated · realtime · build · L0

PE timestamp 2018-12-15 and rich header pinning the NSIS stub version

- on disk: yes; singleton: yes
- locator: base metadata; delta 0
- pattern: metadata, RAW, bytes in E18
- durability (structural_constant): NSIS stub compile time is fixed for the NSIS version used
- expected false matches: any NSIS v3.x installer compiled with the same stub version
- evidence: E18

### A4 · nominated · realtime · campaign · L0

lure icon resource identifying the campaign theme

- on disk: yes; singleton: yes
- locator: base resource; delta 0
- pattern: bytes, RAW, bytes in E19
- durability (config): icon is part of the lure and identifies the campaign theme
- expected false matches: other samples reusing the same stolen icon
- evidence: E19

### A5 · nominated · realtime · build · L0

NSIS overlay containing 7z with Electron app.asar using bytenode-compiled V8 bytecode

- on disk: yes; singleton: yes
- locator: base overlay; delta 0
- pattern: structure, RAW, bytes in E20
- durability (structural_constant): The NSIS-over-7z-over-asar nesting with bytenode is the delivery shape, not tied to a single build
- expected false matches: Legitimate Electron apps also use NSIS installers, but bytenode-compiled main.jsc is uncommon in benign software
- evidence: E20

### A6 · nominated · realtime · campaign · L1

package.json with name steam-login-app and author Valve Corporation in Electron asar

- on disk: yes; singleton: yes
- locator: base metadata; delta 0
- pattern: metadata, RAW, bytes in E23
- durability (config): Attacker controls package.json fields and can change them per campaign
- expected false matches: No legitimate Valve software names itself steam-login-app
- evidence: E23

### A7 · nominated · realtime · build · L1

main.jsc V8 bytecode loaded via bytenode with TARGET_URLS and BrowserWindow credential harvesting

- on disk: yes; singleton: yes
- locator: base overlay; delta 0
- pattern: bytes, RAW, bytes in E22
- durability (behavioural_template): V8 bytecode magic and embedded string constants change with V8 engine version and obfuscator
- expected false matches: Other Electron malware using bytenode, but TARGET_URLS + Steam impersonation narrows the match
- evidence: E21, E22

## Reachability

| layer | graph | roots | internal | reached | unreached | status | evidence |
|---|---|---|---|---|---|---|---|
| L0 | ghidra_callgraph | entry 1 | 104 | 81 | 23 | possibly_reached |  |
| L0 | native_callgraph | entry 1 | 105 | 87 | 18 | possibly_reached |  |

### Limits

- **L0**: roots_searched entry; roots_not_searched tls_callbacks; computed_sites_in_reached_code call_reg 7; call_mem_base_disp 1; unresolved_in_reached_code 27; library_filters ; data_ref_edges 7; passes run: dispatch_reach (+0 edges) (reach +0)
  - not claimed: FLOSS failed: file size 64MB exceeds 16MB limit, so no decoded strings recovered from emulation. NSIS archive overlay (63.8MB) not extracted: payload contents are unknown. 23 internal functions unreached but possibly_reached due to 27 unresolved computed call sites in reached code.

## Unknowns

- **U1** Q2
  - attempted: fn_profile on 5 UI functions (0x404722, 0x404c9e, 0x4043f0, 0x405296, 0x401000): standard NSIS dialog handlers with no sensitive APIs
  - why it failed: cap (stop: depth_cap)
- **U2** Q2
  - attempted: identified NSIS archive overlay at offset 108032 (63.8MB, entropy 8.0), confirmed NullsoftInst header magic in FUN_00402edd, FLOSS refused: file size exceeds 16MB limit
  - why it failed: L1-decode completed and produced a valid asar archive (201982 bytes, controls C2 structure and C5 reproduce both passed). The V8 bytecode in main.jsc remains undecoded because no V8 bytecode disassembler matching the Chromium 122 engine version is available. (stop: payload_not_in_file)
- **U3** Q4
  - attempted: read L0 code: all functions are stock NSIS framework, cluster label pe/unk.steamlure-28f2b618 names no known family
  - why it failed: family-specific payload is inside the compressed NSIS archive (U2) (stop: payload_not_in_file)
- **U4** Q3
  - attempted: triaged IOC candidates from pe code sections: 1 URL, 1 registry key kept, 723 host candidates at overlay offsets cannot be resolved without extraction
  - why it failed: overlay not extracted (stop: payload_not_in_file)
- **U5** Q2
  - attempted: Extracted 176 ASCII strings from main.jsc V8 bytecode (93416 bytes). Found obfuscated variable names, Electron API calls, TARGET_URLS reference, CSS/JS injection strings, browser storage access, and a 74KB embedded blob., V8 bytecode (magic 0xdf05dec0) cannot be decompiled statically without a matching V8 version.
  - why it failed: main.jsc is compiled V8 bytecode; full decompilation requires V8 bytecode disassembly with the matching engine version from Steam.exe (Electron/Chromium 122). String extraction gave partial visibility. (stop: fixed_point); evidence E25, E26, E27, E28

## Functions (17)

| layer | addr | name | name source | reach | size | role | evidence |
|---|---|---|---|---|---|---|---|
| L0 | `0x40338f` | entry | export | reached |  | NSIS initialization: parses command line, adjusts privileges, sets up temp directory and environment, calls archive parser and UI |  |
| L0 | `0x401434` | FUN_00401434 | decompiler | reached |  | NSIS bytecode interpreter: dispatches script opcodes for file, registry, library, COM, INI and UI operations via state table |  |
| L0 | `0x402edd` | FUN_00402edd | decompiler | reached |  | NSIS self-reader: opens own file, validates NSIS header magic, reads archive data into memory |  |
| L0 | `0x4058a3` | FUN_004058a3 | decompiler | reached |  | CreateProcessW wrapper with CREATE_NO_WINDOW (0x4000000) flag for launching dropped payloads silently |  |
| L0 | `0x4058e6` | FUN_004058e6 | decompiler | reached |  | ShellExecuteExW wrapper for launching files via the shell |  |
| L0 | `0x406694` | FUN_00406694 | decompiler | reached |  | Dynamic API resolver: GetModuleHandleA then GetProcAddress from a module/function name table at a fixed address |  |
| L0 | `0x4039aa` | FUN_004039aa | decompiler | reached |  | installer UI creation: registers window class, creates dialog, shows installer window, calls path resolver |  |
| L0 | `0x4062dc` | FUN_004062dc | decompiler | reached |  | NSIS string variable resolver: expands bytecoded strings with installer paths, environment variables, registry values, and shell folder paths |  |
| L0 | `0x405461` | FUN_00405461 | decompiler | reached |  | NSIS installer page dialog: handles WM_INITDIALOG with list view setup, creates a thread to run installer sections, manages progress |  |
| L0 | `0x405f06` | FUN_00405f06 | decompiler | reached |  | writes uninstaller registration entry to file |  |
| L0 | `0x402d44` | FUN_00402d44 | decompiler | reached |  | recursive registry key deletion via RegDeleteKeyW and RegEnumKeyW |  |
| L0 | `0x402e79` | FUN_00402e79 | decompiler | reached |  | Progress dialog manager: shows or destroys the extraction progress window based on tick count |  |
| L0 | `0x402df3` | FUN_00402df3 | decompiler | reached |  | Progress dialog procedure: displays extraction percentage via timer (WM_TIMER) |  |
| L0 | `0x403116` | FUN_00403116 | decompiler | reached |  | NSIS archive data extractor: reads blocks from the archive and writes to a file handle or buffer |  |
| L0 | `0x406155` | FUN_00406155 | decompiler | reached |  | Registry key creation wrapper: calls RegCreateKeyExW through the NSIS registry root resolver |  |
| L0 | `0x406188` | FUN_00406188 | decompiler | reached |  | Registry value reader: opens a key, queries a value with RegQueryValueExW, returns the data |  |
| L0 | `0x4065fd` | FUN_004065fd | decompiler | reached |  | File existence check: FindFirstFileW with immediate FindClose, returns find data pointer or null |  |

## Evidence (34)

| id | layer | locus | method | polarity | bytes_sha256 | claim | tool |
|---|---|---|---|---|---|---|---|
| E1 | L0 | function 0x40338f | static_read | present | `290a784cb132f2b7…` | B1 |  |
| E2 | L0 | function 0x40338f | static_read | present | `290a784cb132f2b7…` | B2 |  |
| E3 | L0 | function 0x406694 | static_read | present | `c993c210b9856638…` | B3 |  |
| E4 | L0 | function 0x40338f | static_read | present | `290a784cb132f2b7…` | B4 |  |
| E5 | L0 | function 0x401434 | static_read | present | `9029d4c345044b55…` | B5 |  |
| E6 | L0 | function 0x401434 | static_read | present | `9029d4c345044b55…` | B6 |  |
| E7 | L0 | function 0x401434 | static_read | present | `9029d4c345044b55…` | B7 |  |
| E8 | L0 | function 0x401434 | static_read | present | `9029d4c345044b55…` | B8 |  |
| E9 | L0 | function 0x401434 | static_read | present | `9029d4c345044b55…` | B9 |  |
| E10 | L0 | function 0x402edd | static_read | present | `4c8d16a8435463d7…` | B10 |  |
| E11 | L0 | function 0x4058a3 | static_read | present | `8e984a718f427b83…` | B11 |  |
| E12 | L0 | function 0x4039aa | static_read | present | `14e3be81523eb9a8…` | B12 |  |
| E13 | L0 | function 0x405461 | static_read | present | `765d43b2620b5f15…` | B13 |  |
| E14 | L0 | function 0x405f06 | static_read | present | `82aa398c2e99aa89…` | B14 |  |
| E15 | L0 | file_range 0x83ac +29 | static_read | present | `d10bc9b4151c88ea…` | I1 |  |
| E16 | L0 | file_range 0x7028 +41 | static_read | present | `2cdf006dcabcea99…` | I2 |  |
| E17 | L0 | artifact out/L0/version_info.json | static_read | present | `d0d1567d4fc3b4b8…` | A2 |  |
| E18 | L0 | header pe_timestamp | static_read | present |  | A3 |  |
| E19 | L0 | resource ICON/1 | static_read | present | `c9ea553f8efcd2ff…` | A4 |  |
| E20 | L0 | section overlay | static_read | present |  | B13 |  |
| E21 | L1 | artifact out/L1_extract/resources/app.asar | static_read | present | `6942177c4eae4702…` | B14 |  |
| E22 | L1 | artifact out/L1_extract/jsc_strings.txt | static_read | present | `ffe89248dac0158b…` | B14 |  |
| E23 | L1 | artifact out/L1_extract/resources/app.asar | static_read | present | `6942177c4eae4702…` | B15 |  |
| E24 | L1 | artifact out/L1/sample.bin | decoded | present | `6942177c4eae4702…` | B16 (control: C2, passed) |  |
| E25 | L2 | artifact out/L2/sample.bin | static_read | present | `3bf8b47b12d46304…` | V8 bytecode extracted from L1 asar archive (main.jsc) (control: C1,C2, passed) |  |
| E26 | L2 | artifact out/L1_extract/jsc_strings.txt | static_read | present | `ffe89248dac0158b…` | V8 bytecode string analysis: 176 strings, 10 API/C2/exfil, 6 file/path, 3 HTTP/network, 2 browser, 2 sysinfo, 1 storage, 1 inject, 1 serviceworker |  |
| E27 | L2 | file_range 0x168bc +29 | static_read | present | `960a75d2b25f21ac…` | HTTPS URL embedded in V8 bytecode at offset 92284, 29 bytes |  |
| E28 | L2 | file_range 0x168e8 +29 | static_read | present | `9d37072b498f1d91…` | HTTPS URL with upload keyword embedded in V8 bytecode at offset 92328, 29 bytes |  |
| E29 | L0 | function 0x402edd | static_read | present | `4c8d16a8435463d7…` | B10 |  |
| E30 | L0 | function 0x4058a3 | static_read | present | `8e984a718f427b83…` | B11 |  |
| E31 | L0 | function 0x4062dc | static_read | present | `286dfe5594736882…` | B12 |  |
| E32 | L0 | function 0x406155 | static_read | present | `895bbabd8f6f9591…` | B6 |  |
| E33 | L0 | function 0x406188 | static_read | present | `8743dbd8a2c088a6…` | B6 |  |
| E34 | L0 | function 0x406694 | static_read | present | `c993c210b9856638…` | B3 |  |

