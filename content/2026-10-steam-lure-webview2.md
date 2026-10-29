---
title: Technical analysis: the WebView2 fake Steam app (f27af032)
date: 2026-10-29
summary: Full CORD Research static analysis of the representative WebView2 fake Steam program: entry, WinMain, the JSON bridge, the WinInet client and the machine fingerprint.
tlp: CLEAR
tags: technical analysis, CORD Research
hidden: true
---

<div class="callout" markdown="1">

Technical companion to [the main report](../2026-10-steam-lure/index.html). This is the CORD Research
pipeline's first automated static analysis of one representative sample, published as produced:
questions, narrative, layers, behaviours, IOCs, detection anchors, reachability, unknowns,
functions and evidence. Nothing was executed. Evidence hashes are SHA-256 prefixes of the
exact bytes each claim rests on.

</div>

<div class="callout bad" markdown="1">

**Corrected by a later full re-analysis.** A deeper static pass overturned four claims on
this page. The program runs WebView2 with **Node integration off**, not on. Its file bridge
(`window.steamm`) reads and writes **only inside the program's own folder**, not across the
machine. The "system fingerprint" function at `0x1400094c0` is **unreferenced junk** that
changes size each build to vary the hash, not a real routine. And the program steals nothing
from disk: it is a **credential-relay shell** that relays the typed Steam login. The
corrected account is in [the main report's malware
section](../2026-10-steam-lure/index.html#the-malware-fake-steam-apps-and-game-cheats). The
anchors and evidence below are left as the pipeline produced them.

</div>

| | |
|---|---|
| sha256 | `f27af032b01fc6982ff936086eaeeaa6a517a9b3fad74939ee4e50729c9e3b2c` |
| schema | `cord-research.report/1.5.0` |
| created | 2026-10-28T22:36Z |
| blind run | no |
| depth | full |
| verdict | L0: malicious dropper stealer (confidence 0.85; evidence E1, E2, E3, E5, E7, E13) |
| family | not attributed |
| model | claude-opus-4-6 · medium |
| gate | gated no; truncated_of None; capture_defect None |

## Questions

| id | question | status | evidence | unknowns |
|---|---|---|---|---|
| Q1 | What the file is: format, toolchain, packing, layers and how each is decoded | answered | E13, E17, E2 |  |
| Q2 | What it does: capabilities and the functions behind them | partial | E1, E3, E5, E6, E7, E8, E9, E19, E20 | U1, U3, U4, U5 |
| Q3 | Configuration and IOCs, each marked observed or inferred | partial | E14, E21 | U2 |
| Q4 | Classification, with confidence | answered | E1, E2, E3, E5, E7, E13, E19, E20 |  |
| Q5 | Unknowns and limits | answered | E13, E21 | U1, U2, U3, U4, U5, U6, U7 |

## Narrative

## Summary

This is a 1 MB x64 PE (mingw-linked, no version info, timestamp 2026-09-22) that acts as a WebView2-based credential-phishing lure and dropper. It carries a 164 KB embedded PE in RCDATA resource 300 and drops it to disk at startup. The application creates a frameless browser-control window styled as a login page, bridges JavaScript and native code through a JSON IPC protocol (B10, E19, E20), and collects a system fingerprint using obfuscated XOR/shift arithmetic over PID, tick count and locale (B6, E7). An HTTP client built on WinInet sends requests to two L0 URLs (I1, I2) with 15/30 s timeouts (B3, E3, E4, E14). The lure gives its operator stolen credentials and a machine fingerprint; the dropped PE's purpose is not recovered (U1).

## Behaviour

The PE entry (E17) calls a CRT startup that enforces single-instance execution through a LOCK cmpxchg on a global; a second copy spins on Sleep(1000) until the first exits (B8, E9). WinMain (E1) reads its own module path, builds a drop path and writes the RCDATA 300 payload to disk (B1, E2), then loads the WebView2 runtime and creates a centered, DPI-scaled window with DWM extended frame and dark background 0x1f1b1bff (B2, E5). A 1500 ms timer navigates the WebView2 control to a URL (I1) referenced by the setup function at 0x1400056b0.

A JSON IPC protocol bridges WebView2 and native code: a builder at 0x140002900 constructs responses and a parser at 0x1400075c0 dispatches commands (B10, E19, E20). Through this channel the lure page requests file reads (B9, E15), file writes (B9, E16) and URL launches (B5, E6). The UI thread handler (B4, E8) dispatches these in response to JSON messages from the WebView2 frontend.

The HTTP client at 0x140004000 parses URLs with InternetCrackUrlW, opens connections with InternetConnectW, and reads responses with InternetReadFile (B3, E3, E4, E14). Two L0 URLs were recovered (I1, I2); 9 of 11 other URL candidates and all 5 registry-path candidates reside in the embedded PE at file offsets 0xd70c0-0xff420, belonging to L1 not L0 (E21, U2, U6). The system fingerprint function at 0x1400094c0 computes a value from PID, tick count and locale through XOR constants 0xfd6c0c64, 0x9c0fc46e, 0x2f77d26c and a shift loop (B6, E7), producing a host identifier sent alongside requests.

What was not recovered: the embedded PE payload's behaviour (U1), the targets of 12 FLOSS decoded strings not mapped to functions (U5), the WebView2 lure content served at runtime (U3), the credential capture mechanism handled by WebView2 JavaScript (U4), the full data set exfiltrated over HTTP (U2), and the purpose of 5 embedded-PE registry paths (U6).

## Reach

The call graph has 2508 internal functions. Three roots (entry plus 2 TLS callbacks) reach 330 natively; a dispatch-reach pass resolved 270 of 1358 computed call sites, adding 362 functions (692 total). 76 unresolved computed call sites remain in reached code (U7); 1816 functions are unreached.

## Verdict and anchors

Malicious: a WebView2-based credential-phishing lure that drops an embedded PE at startup, collects a system fingerprint and communicates over HTTP. No family attributed; the cluster label pe/unk.steamlure-28f2b618 agrees with the observed lure behaviour but no family-specific markers were recovered (E13).

Strongest anchors: A1 (entry stub, 30 bytes at file offset 0x400, E17) is a realtime candidate because its rel32 operand varies per binary, making the sequence build-specific; present in 8/8 cluster members. A2 (RCDATA resource 300 containing an embedded PE, E2) is realtime-viable and stable across the cluster. A3 (WinInet HTTP request function with InternetCrackUrl/HttpOpenRequest/HttpSendRequest/InternetReadFile call sequence, E3) is a batch anchor. A4 (system fingerprint function with XOR constants 0xfd6c0c64/0x9c0fc46e/0x2f77d26c, E7) is realtime-viable and distinctive.

## Layers

| id | parent | format | size | sha256 | verdict | hop |
|---|---|---|---|---|---|---|
| L0 |  | PE32+ | 1052672 | `f27af032b01fc6982ff936086eaeeaa6a517a9b3fad74939ee4e50729c9e3b2c` | malicious dropper stealer (confidence 0.85; evidence E1, E2, E3, E5, E7, E13) |  |

## Behaviours

| id | layer | behaviour | ATT&CK | MBC | reach | evidence |
|---|---|---|---|---|---|---|
| B1 | L0 | drops embedded PE from resource | T1027.009 |  | reached | E1, E2 |
| B2 | L0 | creates WebView2 browser control for lure UI | T1204.001 |  | reached | E1, E5 |
| B3 | L0 | HTTP networking via WinInet | T1071.001 | C0002.003 | reached | E3, E4, E14 |
| B4 | L0 | creates child process | T1106 |  | reached | E8 |
| B5 | L0 | opens URLs via ShellExecute | T1204.001 |  | reached | E6 |
| B6 | L0 | collects system fingerprint | T1082 | E1082 | reached | E7 |
| B7 | L0 | timer-delayed window reveal |  |  | reached | E11, E12 |
| B8 | L0 | single-instance execution lock |  |  | reached | E9 |
| B9 | L0 | reads and writes files by path parameter | T1005 |  | reached | E15, E16 |
| B10 | L0 | JSON-based IPC between WebView2 and native code | T1559 |  | reached | E19, E20 |

## IOCs

| id | type | role | value | port | layer | method | bestiary | evidence |
|---|---|---|---|---|---|---|---|---|
| I1 | url |  | `hxxps://8909451279.f1shh[.]at/clie (truncated copy)` |  | L0 | plaintext |  | E14 |
| I2 | url |  | `hxxps://8909451279.f1shh[.]at/client` |  | L0 | plaintext |  | E14 |

## Anchors

### A1 · nominated · realtime · build · L0

entry stub 30-byte sequence at file offset 0x400, including the E8 rel32 call to the main function

- on disk: yes; singleton: yes
- locator: base entrypoint; delta 0; window 30
- pattern: bytes, RAW, bytes in E17
- durability (structural_constant): entry stub bytes are compiler-generated and stable across builds with the same toolchain and entry layout
- expected false matches: other mingw x64 executables with the same CRT entry stub; low given the rel32 operand varies per binary
- evidence: E17

### A2 · nominated · realtime · build · L0

RCDATA resource 300 containing embedded PE (164704 bytes)

- on disk: yes; singleton: yes
- locator: base resource; delta 0; window 64
- pattern: structure, RAW, bytes in E2
- durability (behavioural_template): resource ID and type are build constants; the embedded PE content varies per campaign but the container structure is stable
- expected false matches: any PE with RCDATA ID 300; narrow with PE header checks on the resource content
- evidence: E2

### A3 · nominated · batch · build · L0

WinInet HTTP request function at 0x140004000 with InternetCrackUrl+HttpOpenRequest+HttpSendRequest+InternetReadFile call sequence

- on disk: yes; singleton: yes
- locator: base function; delta 0; window 1315
- pattern: api_set, RAW, bytes in E3
- durability (behavioural_template): the specific API call sequence and function layout are tied to the build; the function is a custom HTTP client, not a library wrapper
- expected false matches: other WinInet-based HTTP clients with the same API sequence; moderate
- evidence: E3

### A4 · nominated · realtime · build · L0

system fingerprint function at 0x1400094c0 with obfuscated XOR/shift computation over PID, tick count and locale

- on disk: yes; singleton: yes
- locator: base function; delta 0; window 256
- pattern: bytes, RAW, bytes in E7
- durability (behavioural_template): the XOR constants (0xfd6c0c64, 0x9c0fc46e, 0x2f77d26c) and shift loop are build-specific and unlikely in goodware
- expected false matches: none expected; the constant combination is distinctive
- evidence: E7

## Reachability

| layer | graph | roots | internal | reached | unreached | status | evidence |
|---|---|---|---|---|---|---|---|
| L0 | native_callgraph.dispatch.json | entry 1; tls_callback 2 | 2508 | 692 | 1816 | possibly_reached |  |

### Limits

- **L0**: roots_searched entry, tls_callbacks; roots_not_searched ; library_filters capa_library, function_id; unresolved_in_reached_code 76; passes run: dispatch_reach (reach +362)
  - not claimed: L1 payload not extracted or analysed. WebView2 lure HTML/JS content not recovered from static analysis. Credential capture mechanism not confirmed. 12 FLOSS decoded strings not mapped to callers. 5 registry IOC candidates not triaged. URL roles not confirmed for 11 URL IOC candidates.

## Unknowns

- **U1** Q2
  - attempted: identified RCDATA 300 as PE, confirmed extraction in WinMain decompilation
  - why it failed: payload_not_in_file (stop: payload_not_in_file)
- **U2** Q3
  - attempted: decompiled HTTP function 0x140004000, confirmed API sequence; identified 11 URL IOC candidates from static strings, deepen: verified 9 of 11 URLs are in embedded PE at file offsets 0xd70c0-0xff420, not L0; only c0009 and c0010 are L0 URLs; c0009 referenced by webview2_setup 0x1400056b0
  - why it failed: L0 has only 2 URLs; remaining URL-to-function mapping deferred to L1 analysis
- **U3** Q2
  - attempted: confirmed WebView2 initialization and COM setup at 0x1400056b0; no static HTML found in L0 resources besides the embedded PE
  - why it failed: lure content fetched at runtime or in dropped PE, not in L0
- **U4** Q2
  - attempted: read navigation event handler 0x140008f60 and URL handler 0x140003c10; neither shows explicit credential extraction in L0, deepen: identified JSON IPC protocol (0x140002900 builder, 0x1400075c0 parser); ui_thread_handler 0x140005a90 dispatches to file_reader/file_writer/url_launcher/WndProc via JSON messages from WebView2 frontend
  - why it failed: credential capture handled by WebView2 JavaScript sending postMessage to native code; the native handlers (file_reader, file_writer, url_launcher) execute commands but extraction logic is in the lure page served to WebView2
- **U5** Q2
  - attempted: FLOSS found 12 decoded strings; attempted to group by routine but output masked
  - why it failed: decoded strings not mapped to callers due to masked output
- **U6** Q3
  - attempted: identified 5 registry path candidates c0012-c0016 in IOC index, deepen: verified all 5 registry candidates at file offsets 0xf50e8-0xf5c98 are within embedded PE range 0xd70c0-0xff420, belong to L1 not L0
  - why it failed: registry candidates are L1 (embedded PE) data, not L0 strings; deferred to L1 analysis
- **U7** Q5
  - attempted: dispatch_reach pass resolved 270 of 1358 computed call sites, gaining 362 functions (330 to 692 reached)
  - why it failed: 76 unresolved computed call sites in reached code; no state/index tables found

## Functions (19)

| layer | addr | name | name source | reach | size | role | evidence |
|---|---|---|---|---|---|---|---|
| L0 | `0x140001000` | entry | metadata | reached |  | PE entry point, calls crt_startup |  |
| L0 | `0x140001020` | crt_startup | analyst | reached |  | CRT startup, creates mutex for single-instance lock, calls WinMain |  |
| L0 | `0x140001400` | WinMain | analyst | reached |  | Drops embedded PE from RCDATA 300, registers window class, creates WebView2 environment |  |
| L0 | `0x140002480` | WndProc | analyst | reached |  | Window procedure dispatching WM messages, calls WebView2 setup and JSON response builder |  |
| L0 | `0x140002900` | json_response_builder | analyst | referenced_not_called |  | Builds JSON objects with id/ok/result fields as IPC responses to WebView2 frontend |  |
| L0 | `0x1400030e0` | edge_handler | analyst | reached |  | Handles WebView2 edge runtime environment callbacks |  |
| L0 | `0x1400033d0` | file_reader | analyst | reached |  | Reads files by path parameter, builds JSON response with contents |  |
| L0 | `0x1400038b0` | file_writer | analyst | reached |  | Writes files by path parameter, builds JSON response with status |  |
| L0 | `0x140003c10` | url_launcher | analyst | reached |  | Opens URLs via ShellExecuteW, builds JSON response with result |  |
| L0 | `0x140004000` | http_request | analyst | reached |  | Sends HTTP requests via WinInet (InternetOpenA, InternetOpenUrlA, InternetReadFile), reads response |  |
| L0 | `0x140004580` | internet_init | analyst | reached |  | Initialises WinInet session handle with InternetOpenA |  |
| L0 | `0x140004620` | http_request_builder | analyst | reached |  | Constructs HTTP request parameters from global state and string operations, helper for http_request |  |
| L0 | `0x140004960` | timer_reveal | analyst | reached |  | Timer callback that shows the main window after delay |  |
| L0 | `0x1400056b0` | webview2_setup | analyst | reached |  | Creates WebView2 controller and configures COM environment, references L0 URLs |  |
| L0 | `0x140005a90` | ui_thread_handler | analyst | reached |  | Handles WebView2 postMessage events: parses incoming JSON, dispatches to native handlers, creates child processes |  |
| L0 | `0x1400075c0` | json_parser | analyst | referenced_not_called |  | Recursive-descent JSON parser for incoming WebView2 messages; handles strings, arrays, objects, numbers |  |
| L0 | `0x140008f60` | nav_event_handler | analyst | reached |  | WebView2 navigation completed event handler, configures browser settings |  |
| L0 | `0x140009480` | timer_setup | analyst | reached |  | Sets up Windows timer for delayed window reveal |  |
| L0 | `0x1400094c0` | system_fingerprint | analyst | reached |  | Collects system identity data using XOR constants 0xfd6c0c64 and 0x9c0fc46e |  |

## Evidence (22)

| id | layer | locus | method | polarity | bytes_sha256 | claim | tool |
|---|---|---|---|---|---|---|---|
| E1 | L0 | function 0x140001400 +3663 | static_read | present | `274c7d8bdf32a305…` | WinMain: extracts RCDATA 300, drops embedded PE to disk, creates WebView2 window, enters message loop |  |
| E2 | L0 | resource RCDATA/300/1033 | static_read | present | `a9a09232c2580532…` | embedded PE resource, 164704 bytes, entropy 6.2, dropped to disk by WinMain |  |
| E3 | L0 | function 0x140004000 +1315 | static_read | present | `5032dc13fb4c90e3…` | HTTP request function: InternetCrackUrl, InternetConnect, HttpOpenRequest, HttpAddRequestHeaders, HttpSendRequest, HttpQueryInfo, InternetReadFile |  |
| E4 | L0 | function 0x140004580 +147 | static_read | present | `4f9929b06ee17d20…` | InternetOpenW with 15s/30s timeouts for network initialization |  |
| E5 | L0 | function 0x1400056b0 +830 | static_read | present | `a707a3eedee73bb7…` | WebView2 COM initialization: sets background color, configures navigation and docking via COM vtable calls |  |
| E6 | L0 | function 0x140003c10 +893 | static_read | present | `3b8f2af6be25b944…` | ShellExecuteW handler: opens URLs from WebView2 navigation events |  |
| E7 | L0 | function 0x1400094c0 +2313 | static_read | present | `f669c1232d5ccf43…` | system fingerprinting: GetLocalTime, GetLocaleInfoA, GetSystemInfo, GetCurrentProcessId, GetTickCount, then obfuscated XOR/shift computation |  |
| E8 | L0 | function 0x140005a90 +6076 | static_read | present | `ad9e58c92bbf7f22…` | CreateThread, ShowWindow, PostMessage, cursor management - UI and threading handler |  |
| E9 | L0 | function 0x140001020 +892 | static_read | present | `0930912e1dad559b…` | CRT startup with LOCK-based single-instance mutex, spins on Sleep(1000) if another instance holds the lock |  |
| E10 | L0 | function 0x140002480 +878 | static_read | present | `d1eba2999d631ff9…` | window procedure: handles WM_DESTROY (PostQuitMessage), WM_CLOSE and paint/size messages, dispatches to WebView2 vtable |  |
| E11 | L0 | function 0x140009480 +58 | static_read | present | `60841f87500d5dd5…` | SetTimer(9999, 1500ms) callback setup for delayed window reveal |  |
| E12 | L0 | function 0x140004960 +79 | static_read | present | `0382389affa6fc2f…` | timer callback: KillTimer, ShowWindow, SetForegroundWindow - reveals the lure after delay |  |
| E13 | L0 | header pe_header | static_read | present |  | x64 PE, mingw-linked, no version info, 2 TLS callbacks, ASLR+NX, timestamp 2026-09-22 |  |
| E14 | L0 | import wininet.dll | static_read | present |  | 10 WinInet imports for HTTP networking |  |
| E15 | L0 | function 0x1400033d0 +975 | static_read | present | `8df08bce4463a45a…` | file reader: extracts path parameter, opens with CreateFileW, reads with ReadFile |  |
| E16 | L0 | function 0x1400038b0 +730 | static_read | present | `b89a6c38ecf8ff15…` | file writer: extracts path parameter, creates with CreateFileW, writes with WriteFile |  |
| E17 | L0 | file_range 0x400 +30 | static_read | present | `3e704c7957b5b219…` | entry stub at file offset 0x400 (RVA 0x1000), 30 bytes, calls main at offset +17 |  |
| E18 | L0 | function 0x140008f60 +1153 | static_read | present | `ba991d8af56c0bd7…` | COM navigation event handler: retrieves URL string from WebView2 interface, processes it for action dispatch |  |
| E19 | L0 | function 0x140002900 +720 | static_read | present | `161452e872d6e8af…` | JSON response builder with id/ok/result fields for WebView2-native IPC |  |
| E20 | L0 | function 0x1400075c0 +1644 | static_read | present | `72f1040b434a6062…` | JSON parser for incoming WebView2 messages, recursive descent |  |
| E21 | L0 | artifact out/L0/ioc_candidates/index.json | static_read | present | `d91ff94ddb191dfe…` | 9 of 11 URL IOCs and all 5 registry candidates at file offsets within embedded PE range 0xd70c0-0xff420 belong to L1 not L0 |  |
| E22 | L0 | function 0x140004620 +671 | static_read | present | `67a0649b48521e06…` | HTTP request builder helper using string operations and global state |  |

