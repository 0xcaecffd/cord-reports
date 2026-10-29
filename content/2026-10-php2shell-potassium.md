---
title: PHP2Shell and potassium: four RCE paths, the DDoS bot pushed through them, and the operator behind it
date: 2026-10-27
updated: 2026-10-29 (restructured; four-path analysis and detection matrix)
summary: Three PHP session CVEs yield four demonstrated remote-code-execution paths. This is the full analysis: the attack chains, the detection matrix built against real crashing traffic, the encrypted Mirai-derived bot pushed through within hours, and the operator, down to decoy DNS, an Ethereum C2 fallback and a money trail to named exchanges.
tlp: CLEAR
tags: php, rce, mirai, ddos, blockchain
---

<div class="callout bad" markdown="1">

**Patch now.** PHP 8.3.36 / 8.4.27 / 8.5.12 and later fix CVE-2026-109618 and
CVE-2026-109619, and the same releases close the denial-of-service variant. A fourth
issue, CVE-2026-115560, is a separate bug class, needs an application framework to reach
code execution, and is unpatched; its trigger is withheld from this public copy. Indicators
below are defanged; the full lists are in [iocs.csv](iocs.csv) and the YARA rules in
[rules/](rules/potassium-all.yar).

</div>

## Four RCE paths from one flaw

Three CVEs in PHP's session upload-progress feature produce four distinct
remote-code-execution paths. All four were demonstrated end to end in our lab on stock
`php:8.3.35-apache` (mod_php prefork, default configuration). Three are memory-corruption
chains fixed in PHP 8.3.36 / 8.4.27 / 8.5.12. The fourth, CVE-2026-115560, is a different
bug class: it reaches code execution only with an application framework present, and it is
unpatched as of late October 2026.

All four begin at the same stumble. A crafted request makes PHP run out of memory in the
middle of parsing, and PHP's internal "give up and unwind" jump (`zend_bailout`) skips the
cleanup that a normal request runs. What that skipped cleanup leaves behind decides which
path opens.

<figure class="diagram">
<svg viewBox="0 0 760 500" xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="d-t d-d" class="chaindiag" font-family="var(--font-sans)">
<title id="d-t">PHP2Shell: four RCE paths from one out-of-memory bailout</title>
<desc id="d-d">A crafted upload makes PHP run out of memory mid-parse; the bailout skips session cleanup. Three patched paths reclaim a dangling reference to run a command on stock PHP; a fourth, unpatched path injects an object that needs a framework gadget. The attacker then installs the potassium DDoS bot.</desc>
<style>
.chaindiag text{fill:var(--fg);font-size:13px}
.chaindiag .sub{fill:var(--muted);font-size:11px}
.chaindiag .cve{font-size:12px;font-weight:600}
.chaindiag .box{fill:var(--surface);stroke:var(--line)}
.chaindiag .edge{stroke:var(--muted);stroke-width:1.5;fill:none;marker-end:url(#arh)}
.chaindiag .bar{height:4px}
.chaindiag .lbl{fill:var(--muted);font-size:11px;font-style:italic}
</style>
<defs><marker id="arh" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="var(--muted)"/></marker></defs>

<!-- spine -->
<rect class="box" x="180" y="12" width="400" height="38" rx="6"/>
<text x="380" y="30" text-anchor="middle">Unauthenticated HTTP request</text>
<text x="380" y="44" text-anchor="middle" class="sub">looks like ordinary form data, no login needed</text>
<path class="edge" d="M380,50 L380,68"/>

<rect class="box" x="180" y="70" width="400" height="38" rx="6"/>
<rect x="180" y="70" width="400" height="4" rx="2" fill="var(--accent)"/>
<text x="380" y="88" text-anchor="middle">Request 1: a crafted upload exhausts memory mid-parse</text>
<text x="380" y="102" text-anchor="middle" class="sub">a few hundred KB is enough on a default 128 MB limit</text>
<path class="edge" d="M380,108 L380,126"/>

<rect class="box" x="150" y="128" width="460" height="44" rx="6"/>
<rect x="150" y="128" width="460" height="4" rx="2" fill="var(--warn)"/>
<text x="380" y="148" text-anchor="middle">PHP's error bailout unwinds the request and skips cleanup</text>
<text x="380" y="163" text-anchor="middle" class="sub">the shared stumble: a reference or object is left in a bad state</text>

<text x="380" y="196" text-anchor="middle" class="lbl">a second request reclaims what the skipped cleanup left behind</text>

<!-- four paths -->
<g>
<rect class="box" x="10" y="208" width="175" height="58" rx="6"/>
<rect x="10" y="208" width="175" height="4" rx="2" fill="var(--bad)"/>
<text x="97" y="228" text-anchor="middle" class="cve">CVE-2026-109618</text>
<text x="97" y="245" text-anchor="middle" class="sub">Big-field</text>
<text x="97" y="259" text-anchor="middle" class="sub">out of memory</text>

<rect class="box" x="197" y="208" width="175" height="58" rx="6"/>
<rect x="197" y="208" width="175" height="4" rx="2" fill="var(--bad)"/>
<text x="284" y="228" text-anchor="middle" class="cve">CVE-2026-109619</text>
<text x="284" y="245" text-anchor="middle" class="sub">Filename</text>
<text x="284" y="259" text-anchor="middle" class="sub">out of memory</text>

<rect class="box" x="384" y="208" width="175" height="58" rx="6"/>
<rect x="384" y="208" width="175" height="4" rx="2" fill="var(--bad)"/>
<text x="471" y="228" text-anchor="middle" class="cve">CVE-2026-109618</text>
<text x="471" y="245" text-anchor="middle" class="sub">Unserialize</text>
<text x="471" y="259" text-anchor="middle" class="sub">dual primitive</text>

<rect class="box" x="571" y="208" width="179" height="58" rx="6"/>
<rect x="571" y="208" width="179" height="4" rx="2" fill="var(--warn)"/>
<text x="660" y="228" text-anchor="middle" class="cve">CVE-2026-115560</text>
<text x="660" y="245" text-anchor="middle" class="sub">Serializer mismatch</text>
<text x="660" y="259" text-anchor="middle" class="sub">no fix yet</text>
</g>

<path class="edge" d="M97,266 L97,300"/>
<path class="edge" d="M284,266 L284,300"/>
<path class="edge" d="M471,266 L471,300"/>
<path class="edge" d="M660,266 L660,300"/>

<!-- outcomes -->
<rect class="box" x="10" y="302" width="549" height="50" rx="6"/>
<text x="284" y="322" text-anchor="middle">system() runs as the web-server user</text>
<text x="284" y="338" text-anchor="middle" class="sub">remote code execution on stock PHP &#183; fixed in 8.3.36 / 8.4.27 / 8.5.12</text>

<rect class="box" x="571" y="302" width="179" height="50" rx="6"/>
<text x="660" y="320" text-anchor="middle" class="sub">object injection</text>
<text x="660" y="335" text-anchor="middle" class="sub">RCE only with a</text>
<text x="660" y="348" text-anchor="middle" class="sub">framework gadget</text>

<path class="edge" d="M284,352 L284,384"/>

<!-- aftermath -->
<rect class="box" x="140" y="386" width="288" height="40" rx="6"/>
<text x="284" y="405" text-anchor="middle">the attacker installs a loader</text>
<text x="284" y="419" text-anchor="middle" class="sub">fetched over the fresh shell, run as ./nfs php</text>
<path class="edge" d="M284,426 L284,444"/>

<rect class="box" x="120" y="446" width="328" height="44" rx="6"/>
<rect x="120" y="446" width="328" height="4" rx="2" fill="var(--bad)"/>
<text x="284" y="466" text-anchor="middle">potassium</text>
<text x="284" y="481" text-anchor="middle" class="sub">an encrypted, Mirai-derived Linux DDoS bot</text>
</svg>
<figcaption>The four paths share one starting point: an out-of-memory bailout that skips cleanup. Three leave a dangling reference that a second request reclaims to run a command on stock PHP; the fourth injects an object that only reaches code execution with a framework gadget, and has no fix yet.</figcaption>
</figure>

### The paths at a glance


| | 109618 Big-field | 109619 Filename | 109618 Unserialize | 115560 Serializer mismatch |
|---|---|---|---|---|
| **Bug class** | Use-after-free | Use-after-free | Use-after-free (dual) | Serializer mismatch |
| **What is left dangling** | A freed session reference | Same, different trigger | A write primitive *and* a session reference | Nothing freed; attacker input is deserialized |
| **Out-of-memory trigger** | An oversized field value | An overlong upload filename (plus a file part) | Same as big-field | None |
| **Primitive** | Code execution | Code execution | Arbitrary write + code execution | Object instantiation to code execution |
| **Stock PHP RCE?** | Yes | Yes | Yes | No — needs a framework gadget |
| **Fixed?** | Yes, 8.3.36+ | Yes, 8.3.36+ | Yes, 8.3.36+ | **No** |
| **Also affects** | mod_php prefork | mod_php prefork | mod_php prefork | Any SAPI (mod_php, FPM) |


All three memory-corruption paths were confirmed on default configuration: 14 segfaults in
15 rounds on the vulnerable build, and 0 crashes in 261 rounds on the patched build with
byte-for-byte identical traffic. The session file on disk is never corrupted; the damage
lives entirely in the running worker's memory.

### How each path works

These descriptions stay at the level of PHP's own advisories. The step-by-step
exploit-development detail (heap grooming, the reclaim carrier, the gadget chain) is not
published.

**CVE-2026-109618, big-field out of memory.** A multipart POST with a file part and an
oversized field value exhausts `memory_limit` mid-parse. The bailout skips session cleanup
and leaves a dangling reference. A follow-up request reclaims that freed slot and redirects
a destructor so the engine runs a command as the web-server user. Two preliminary requests
leak the addresses the reclaim needs.

**CVE-2026-109619, filename out of memory.** The same corruption and the same end, reached
by a different trigger: an overlong upload filename exhausts memory from a single header
field. A preceding file part is required, so the progress array is populated and the stale
reference survives into the next request. Zero-byte file content is enough.

**CVE-2026-109618, unserialize dual primitive.** The one out-of-memory bailout can leave
*two* independent globals in a bad state at once: the session reference above, and the
session unserializer's own bookkeeping, which yields an arbitrary write. Our proof of
concept chains both from a single follow-up request, showing the two primitives are
reachable and composable, not just one or the other.

**CVE-2026-115560, serializer mismatch (unpatched).** A separate bug. The upload-progress
callback writes session data with the server-configured serializer before application code
runs; if the application later switches serializers, attacker-controlled input can be
deserialized into a live object. On stock PHP this reaches no code execution, because the
standard library ships no usable destructor gadget. With a framework that has one (the
PHPGGC catalog lists dozens), it does. This affects fully patched builds. **The trigger and
the gadget path are withheld here until a fix ships.**

## Detection

The original detection suite was built against the wrong assumption, that the attack would
look like a large, loud payload. Against the real crashing traffic only one of the first
fifteen signatures fired. We rebuilt and engine-validated the suite directly against the
functional attack. The rules below detect the *attempt*; a request that fails to corrupt
memory is a failed attempt at the same attack, not benign traffic, so alerting on the shape
is the right call.

### Request-side (Suricata)


| SID | What it matches | Big-field | Filename | Unserialize | 115560 |
|---|---|---|---|---|---|
| 92610008 | Upload-progress telemetry (field present) | yes | yes | yes | yes |
| 92610020 / 21 | Overlong upload filename (>= 1 KB) | no | yes | varies | no |
| 92610022 | `PHPSESSID` sent as a multipart form field | yes | yes | yes | possible |
| 92610038 | `system\x00` in the multipart body | fire | fire | no | no |
| 92610040 | Upload-progress request with no file part | fire | fire | fire | no |
| 92610041 | Session-pinned upload carrying progress | OOM | OOM | OOM | yes |


### Response-side (Suricata)


| SID | What it matches | Use |
|---|---|---|
| 92610053 | Oversized `PHPSESSID` (> 64 chars) in `Set-Cookie` | the info-leak stages |
| 92610054 | Non-hex `PHPSESSID` in `Set-Cookie` | the info-leak stages |


### Host-side signals


| Signal | Crash exit | Silent use-after-free | Serializer mismatch |
|---|---|---|---|
| `AH00051` / `AH00052` worker reap | yes (16/16) | no (0/30) | no |
| `zend_mm_heap corrupted` | sometimes | no | no |
| `Allowed memory size exhausted` | yes (request 1) | yes (request 1) | no |
| `Failed to write session data (files)` | no (dead worker) | yes (30/30) | no |
| HTTP status of the second request | connection closed | **200** | **200** |


**The reliable detector is the ordered triple**: request 1 logs `Allowed memory size
exhausted`, then request 2 returns HTTP 200 while logging `Failed to write session data`,
with no worker reap and no allocator-corruption line. Each signal alone is ambiguous; the
ordered triple is not. It catches both the crash and the silent use-after-free exits of the
memory-corruption paths. It does not catch the serializer mismatch.

### What is not covered

- **The published big-field proof of concept** uses a urlencoded body with an oversized
  field *name*, not multipart. The multipart-keyed rules miss it; a dedicated rule is
  drafted but not yet baselined.
- **The serializer-mismatch injection.** A generic rule can alert on PHP serialized-object
  markers (`O:`, `a:`) appearing in an upload-progress field value. We hold the precise,
  higher-fidelity signature with the trigger until CVE-2026-115560 is patched.
- **The silent use-after-free** has no wire-side signal at all. The worker survives and
  returns 200; the only tell is the host-side `Failed to write session data` line.

### Mitigations


| Mitigation | 109618 / 109619 (and the DoS variant) | 115560 |
|---|---|---|
| Patch to 8.3.36 / 8.4.27 / 8.5.12+ | **Fixes** | Does not fix |
| `session.upload_progress.enabled = 0` | **Fixes** (removes the trigger) | **Fixes** |
| Switch to PHP-FPM | Mitigates (502 on crash, no persistent state) | Does not mitigate |
| Do not switch `session.serialize_handler` at runtime | No effect | **Fixes** |
| Raising `memory_limit` | No help: moves where the failure lands, does not stop it | n/a |
| `session.use_strict_mode = 1` | No help: one harmless request earns a server-issued session ID that strict mode accepts | n/a |


---

## The malware: potassium, the second stage

Within hours of the patch, attackers were already using this exact flaw to plant a second-stage bot, the malware that lands once the exploit has opened the door. We obtained the sample, and it turned out to be far more than a run-of-the-mill Mirai knock-off (Mirai being the widely copied botnet code that most Linux DDoS malware descends from).

**What it is.** A Linux DDoS bot: software that turns a compromised server into a foot soldier for knocking other sites offline. It does not spread on its own; it is placed onto servers through the PHP2Shell exploit above. It is the newest build of a family that Nokia Deepfield documented in May 2026 under the name **potassium**, and the same binary the research firm ELLIO identified on 2026-10-22 as the PHP2Shell second stage, seen in the wild the day before.

**The sample, by the numbers.**

| Field | Value |
|---|---|
| SHA-256 | `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` |
| MD5 | `b61a098fc62a2c2696e196dca78da71a` |
| File | ELF64 x86-64, statically linked, stripped, 179,632 bytes |
| Detection at discovery | 4 of ~65 engines, heuristic only, effectively invisible |
| Delivered via | loader fetched from `hxxp://92[.]118[.]112[.]100/nfs`, run as `./nfs php`; loader source `45[.]198[.]224[.]169` |

**Why it stands out.** Ordinary Mirai copies leave their settings and tell-tale text in plain sight. This one encrypts everything: a 476-slot string table locked under ChaCha20, with even the cipher's own constant masked. Its link back to the operators uses modern cryptography (X25519 key exchange, ChaCha20-Poly1305). It can open a remote shell for them, hide its own process from the system, and update itself. Most tellingly, it lies about where its control server is (more on that in Act III). And the scanning engine classic Mirai uses to spread on its own has been stripped out, the sign that this build is placed deliberately by a loader rather than spreading like a worm.

### The wider family and our confidence

This sample is one build off a production line. We scored every related file in our own collection and ran four detection rules back across a year of global malware submissions. Here is what came back, ranked by how sure we are:

- **Same operator, high confidence.** Two x86-64 "sibling" builds, `6f272c85365a…` (2026-10-04) and `b58cf55ad3e6…` (2026-09-23), carry the same encrypted blockchain settings and overlapping control-server lists once decrypted. This sample and `6f272c85365a…` share two of the very same control-server hosts outright. The blockchain seals it: both build lines registered their names through the same service and point at the same operator-specific resolver, tying them together on a public ledger.
- **Same operator, likely.** Six ARM builds from September and October 2026, one of which (`5420b2745e8d…`) was seen reaching the exact same control server as our sample.
- **Same toolkit, operator unproven.** Three un-stripped "developer" builds that accidentally shipped with their source-file names intact, revealing the project's internal module layout, plus two older ARM builds.
- **Fresh finds (2026-10-22).** Our retrohunt surfaced 23 more in-the-wild builds not previously in our corpus: six x86-64 and seventeen ARM/SuperH/x86, including versions bundled inside Android app packages. Our four detection rules flagged all of them with zero false alarms against clean software.

In short: this is an actively maintained, multi-platform family, from Linux servers to Android devices, not a one-off.


---

## The operator

The crew is careful, but careful people are consistent, and consistency makes a pattern. The pattern led us a long way.

### Their infrastructure

They rotate their control-server domains like clockwork: a new `.st` domain every few weeks (with one two-month lull over the summer), bought through two small resellers, each dressed up with a legitimate-looking web page, with the real control servers tucked away on short subdomains. Their hosting spans Estonia, France, Switzerland, Russia, Armenia and DigitalOcean. New infrastructure typically goes live about a week before a new malware build ships, a rhythm regular enough to track.

### The sleight of hand: decoy DNS

When the bot looks up its control domain, it never connects to the address it gets back. It **scrambles** that address first: older builds swap the two halves; this build keeps the first number and rotates the rest, then connects to the result. The addresses anyone can see point at university, military and ordinary consumer networks: innocent bystanders. **Blocking the published address does nothing, and would hurt the wrong people.** We worked the scramble backwards and recovered the real servers, including the live one at `134[.]199[.]154[.]64` (DigitalOcean), plus eight more behind the group's other hosts, two of them this sample's own second domain.

### A C2 fallback on the blockchain

Buried in the configuration is something new: a backup plan. If the domains are ever taken down, the bot can look up its control-server address on the **Ethereum blockchain** instead, a public ledger that no registrar or hosting provider can switch off. It is wired to read a text record (labelled `ip`) from three blockchain names: `2sexy4u[.]eth` and `sushiconsumer[.]eth` (this sample) and `catswithhatslolksjhakf[.]eth` (the siblings), through a fixed registry (`0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`) and resolver (`0xf29100983e058b709f3d539b0c765937b804ac15`). This build does not use it yet; the feature is built and tested but not switched on. The values parked there appear to be scrambled with the same decoy trick: unwinding three of the October values with this build's scramble lands them in the same DigitalOcean range as the live server. Read it as a glimpse of where the family is heading: a fallback that no domain takedown can touch.

### Following the money

Because the blockchain is public, we could read who owns those names and who paid for them. This is the strongest thread in the whole investigation:

- **Two wallets, one playbook.** The sample's two blockchain names sit in one wallet (`0x32ab9ef9…da7b`); the siblings' name sits in a second (`0xd5e34876…f995`). Both registered through the same service and point at the same operator-specific resolver, an on-chain tie between the two build lines, on top of the control-server hosts they already share in their code.
- **That second wallet is a smart contract**, an account-abstraction setup that keeps the controlling key off the public ledger. It has been active since 2025 (see the wallet appendix), so it is a wallet held in reserve rather than spun up for this campaign.
- **Both wallets were funded through throwaway relay wallets**: pass the money through once, then discard the wallet. A pattern meant to break the trail. They used no mixer like Tornado Cash; the one anonymity step is a single no-KYC swap (ChangeNOW) on one branch, so the trail is bent, not cut.
- **And both branches of that trail now reach exchanges that know their customers.** The relay that seeded the smart-contract wallet was itself funded, on 2025-06-10, by a **Coinbase** hot wallet (`0xb5d85cbf…`). Coinbase is a KYC exchange: it verifies who its account holders are. That withdrawal is tied to a real, identifiable account the exchange can name under legal process. This is the single most promising lead toward the people behind the group.
- **The other wallet's trail, which we had stopped one step short of, is now fully followed (26 October).** It runs through a busy, shared cash-movement service on the blockchain. Money comes into that service from a **KuCoin** exchange wallet (`0x45300136…`) and leaves it to a **Binance** deposit address (`0x16f59CEf…`), with one deliberate detour through **ChangeNOW** (`0x3f3Ee0a9…`), a swap service that asks for no identity. Because that service moves money for many unrelated people, KuCoin and Binance here are leads to confirm, not proof on their own. The upshot: every branch of the money ends either at an exchange that keeps customer records (Coinbase, KuCoin, Binance) or at the no-identity swap the operator used to break the chain. From here on, naming anyone means going to those exchanges with legal process, **Coinbase first**. Attribution stays with the operator group; no individual is named.

### What their tradecraft tells us

They are competent and deliberate: encrypted builds, rotating infrastructure, decoy addressing, disposable funding wallets, a blockchain fallback waiting in the wings, and wallet keys kept off the public record. But the discipline is uneven. They let developer builds slip out with their internal file names intact, and the money trail still touches a named exchange. Two soft signals, which we hold loosely, point toward a European operator: their blockchain activity clusters in a 06:00–14:00 UTC window (European working hours), and Deepfield observed Dutch-language content in an earlier campaign.


---

## Detecting and blocking the malware

- **YARA.** Four rules cover the family across architectures with no hits on clean software
  (16,686 ELF samples, 4,699 Linux system binaries and 1,542 Windows files tested):
  [`elf_mirai_ext_x64_build_family`](rules/elf_mirai_ext_x64_build_family.yar),
  [`elf_mirai_ext_x64_chacha_lineage`](rules/elf_mirai_ext_x64_chacha_lineage.yar),
  [`elf_mirai_ext_multiarch_literals`](rules/elf_mirai_ext_multiarch_literals.yar) and a
  survey rule for triage. All four in one file:
  [potassium-all.yar](rules/potassium-all.yar).
- **Block the real control servers** in the appendix, never the published DNS answers,
  which are decoys pointing at bystanders.
- **On Linux hosts**, look for a loopback listener on TCP port 1234, a hidden directory at
  `/var/tmp/.cache/sysd`, files at `/tmp/.manta` or `/tmp/.xwiki`, and a process whose
  `/proc` entry is masked by another.
- **Proactively**, watch the three ENS names for record changes (a read-only query), watch
  for new `.st` domains from the same two resellers, and pivot on the relay wallets.

## Appendix — full indicators

Collected 2026-10-22 from the decrypted store of the sample, the decoded stores of the two x86-64 siblings, VirusTotal relationships and passive DNS, and read-only Ethereum mainnet lookups. Published DNS answers of the C2 hosts are decoys (the address-rewriting trick described in Act III) and are listed apart; do not block them.

#### A1. The sample

| hash | value |
|---|---|
| md5 | `b61a098fc62a2c2696e196dca78da71a` |
| sha1 | `c472dab4ff7c16782a8037f988d4daa6d4bdb343` |
| sha256 | `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` |
| size | 179632 bytes |

#### A2. Hostnames in the sample's string store

| slot | value | role |
|---|---|---|
| 0x0 | `thunder[.]godofthunder[.]st` | C2 host |
| 0x1 | `thunder[.]godofthunder[.]st` | C2 host |
| 0x2 | `thunder[.]godofthunder[.]st` | C2 host |
| 0x3 | `thunder[.]godofthunder[.]st` | C2 host |
| 0x4 | `thunder[.]godofthunder[.]st` | C2 host |
| 0x5 | `thunder[.]godofthunder[.]st` | C2 host |
| 0x6 | `thunder[.]godofthunder[.]st` | C2 host |
| 0x7 | `thunder[.]godofthunder[.]st` | C2 host |
| 0x8 | `2sexy4u[.]eth` | ENS name |
| 0x9 | `sushiconsumer[.]eth` | ENS name |
| 0xa | `ethereum.publicnode.com` | public Ethereum JSON-RPC endpoint |
| 0xb | `ethereum-rpc.publicnode.com` | public Ethereum JSON-RPC endpoint |
| 0xc | `eth.drpc.org` | public Ethereum JSON-RPC endpoint |
| 0xd | `1rpc.io` | public Ethereum JSON-RPC endpoint |
| 0xe | `eth-mainnet.blockreq.com` | public Ethereum JSON-RPC endpoint |
| 0xf | `ethereum-public.nodies.app` | public Ethereum JSON-RPC endpoint |
| 0x10 | `rpc.mevblocker.io` | public Ethereum JSON-RPC endpoint |
| 0x113 | `hackattackkaboom[.]botlesscucks[.]st` | C2 host |
| 0x114 | `hik[.]gettingheadfromduckysmom[.]st` | C2 host |

#### A3. ENS resolution recipe (store slots 11-20)

| slot | value |
|---|---|
| 11 | `ethereum-rpc.publicnode.com` |
| 12 | `eth.drpc.org` |
| 13 | `1rpc.io` |
| 14 | `eth-mainnet.blockreq.com` |
| 15 | `ethereum-public.nodies.app` |
| 16 | `rpc.mevblocker.io` |
| 18 | `/eth` |
| 19 | `/v1/rpc/public` |
| 20 | `00000000000C2E074eC69A0dFb2997BA6C7d2e1e` |

#### A4. Ethereum mainnet state of the ENS names (read-only lookups, 2026-10-22)

ENS registry `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`; selectors `resolver(bytes32)` = `0x0178b8bf`, `text(bytes32,string)` = `0x59d1d43c`; text key `ip`.

| name | carried by | namehash | resolver (equals store) | owner (registry) | expiry | text `ip` | `addr` record |
|---|---|---|---|---|---|---|---|
| `2sexy4u[.]eth` | sample | `0x21372c2e8f485fe1666dc12be5709f2e63214a4b79f076daa287a959e4c2d514` | `0xf29100983e058b709f3d539b0c765937b804ac15` (yes) | `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` | 2030-10-13 | `143[.]220[.]202[.]110` | `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` |
| `catswithhatslolksjhakf[.]eth` | x86-64 siblings | `0x022d83e68fb35299866ff21bbff6c7aaf73092c07a5c14448363005f12832024` | `0xf29100983e058b709f3d539b0c765937b804ac15` (yes) | `0xd5e348763fef825c36ad60a4294567187cc9f995` | 2027-09-10 | `49[.]6[.]172[.]233` | `0xd5e348763fef825c36ad60a4294567187cc9f995` |
| `sushiconsumer[.]eth` | sample | `0x46e5a3d52c2bd76e560a74cf4c104f7e219daa40586021854bd404d65d5ad6de` | `0xf29100983e058b709f3d539b0c765937b804ac15` (yes) | `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` | 2029-10-13 | `(absent)` | `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` |

Record history (Blockscout log API, read once on 2026-10-22; the values of the superseded records were not retained and a re-read was rate-limited): the first name has `NewResolver` events on 2022-05-24 and 2026-10-13 and eleven `TextChanged` events with keys `ip`, `ip1`, `ip2`, `ip4`, `readme`, of which four `ip` changes within hours on 2026-10-14 over three distinct values; the second name has one `NewResolver` on 2026-09-10 and one `ip` set on 2026-09-11; the third has one `NewResolver` on 2026-10-13 and no text record.

Public RPC endpoints in the store (the bot would use these; they are legitimate providers and not blockable indicators): `ethereum.publicnode.com`, `ethereum-rpc.publicnode.com`, `eth.drpc.org`, `1rpc.io`, `eth-mainnet.blockreq.com`, `ethereum-public.nodies.app`, `rpc.mevblocker.io`.

#### A5. Ports, process names, paths, resolvers

- C2 ports (random pick from 14): `50217, 50341, 50488, 50613, 50792, 50904, 51127, 51289, 51456, 51603, 51871, 52134, 52398, 52645`
- loopback single-instance lock: TCP `1234` (retry counter 0x1a); stock Mirai uses 48101
- process names adopted after daemonising (prctl and argv[0]): `telnetd`, `udhcpc`, `upnpd`, `watchdog`, `syslogd`, `klogd`, `uhttpd`, `uchttpd`
- potassium markers in the store: `Segmentation fault (core dumped)`, `big brother is watching`, `dvrInside`, `dvrLocker`, `im in the matrix`
- shell paths: `/apex/com.android.runtime/bin/sh`, `/data/local/tmp/sh`, `/sbin/sh`, `/system/bin/sh`, `/usr/bin/sh`, `/vendor/bin/sh`
- watchdog devices: `/dev/misc/watchdog`, `/dev/watchdog`
- on-disk install path seen in VirusTotal in-the-wild names of core builds: `/var/tmp/.cache/sysd`
- additional drop paths seen in retrohunt matches (2026-10-22): `/tmp/.manta`, `/tmp/.xwiki`
- embedded DNS resolvers (18, used for the bot's own lookups; legitimate public resolvers): `8[.]8[.]8[.]8`, `8[.]8[.]4[.]4`, `1[.]1[.]1[.]1`, `1[.]0[.]0[.]1`, `208[.]67[.]222[.]222`, `208[.]67[.]220[.]220`, `9[.]9[.]9[.]9`, `149[.]112[.]112[.]112`, `94[.]140[.]14[.]14`, `94[.]140[.]15[.]15`, `114[.]114[.]114[.]114`, `114[.]114[.]115[.]115`, `223[.]5[.]5[.]5`, `223[.]6[.]6[.]6`, `119[.]29[.]29[.]29`, `180[.]76[.]76[.]76`, `64[.]6[.]64[.]6`, `64[.]6[.]65[.]6`

#### A6. Domains

| domain | kind | registered | registrar | VT malicious | notes |
|---|---|---|---|---|---|
| `abuse[.]st` | apex | 2026-05-29 | StanCo and Istanco | 0 | 0 communicating files, 20 URLs |
| `botlesscucks[.]st` | apex | 2026-05-14 | StanCo and Istanco | 19 | 0 communicating files, 20 URLs |
| `gettingheadfromduckysmom[.]st` | apex | 2026-09-29 | Sirdio | 0 | 0 communicating files, 8 URLs |
| `godofthunder[.]st` | apex | 2026-10-12 | Sirdio | 2 | 0 communicating files, 4 URLs |
| `iloveboats[.]st` | apex | 2026-08-03 | None | 19 | 40 communicating files, 20 URLs |
| `potassium[.]st` | apex | 2026-06-06 | Sirdio | 11 | 0 communicating files, 14 URLs |
| `dvrs[.]botlesscucks[.]st` | C2 host (siblings) | 2026-05-14 | StanCo and Istanco | 14 | 16 communicating files, 2 URLs |
| `dvrs2[.]botlesscucks[.]st` | C2 host (siblings) | 2026-05-14 | StanCo and Istanco | 0 | 0 communicating files, 0 URLs |
| `dvrs4[.]botlesscucks[.]st` | C2 host (siblings) | 2026-05-14 | StanCo and Istanco | 0 | 0 communicating files, 0 URLs |
| `hackattackkaboom[.]botlesscucks[.]st` | C2 host (sample) | 2026-05-14 | StanCo and Istanco | 13 | 0 communicating files, 4 URLs |
| `hik[.]gettingheadfromduckysmom[.]st` | C2 host (sample) | 2026-09-29 | Sirdio | 9 | 1 communicating files, 2 URLs |
| `ijustgetsonervy[.]potassium[.]st` | host seen in relatives' sandbox DNS | 2026-06-06 | Sirdio | 11 | 5 communicating files, 2 URLs |
| `thunder[.]godofthunder[.]st` | C2 host (sample) | 2026-10-12 | Sirdio | 3 | 2 communicating files, 2 URLs |
| `urlhaus[.]abuse[.]st` | host seen in relatives' sandbox DNS | 2026-05-29 | StanCo and Istanco | 0 | 1 communicating files, 0 URLs |

Siblings' C2 hosts by store slot: 6f272c85365a: `dvrs[.]botlesscucks[.]st`, `dvrs2[.]botlesscucks[.]st`, `dvrs4[.]botlesscucks[.]st`, `hackattackkaboom[.]botlesscucks[.]st`, `hik[.]gettingheadfromduckysmom[.]st`; b58cf55ad3e6: `dvrs[.]botlesscucks[.]st`, `dvrs2[.]botlesscucks[.]st`, `dvrs4[.]botlesscucks[.]st`

#### A7. Real C2 and hosting addresses

| address | AS | country | role | evidence |
|---|---|---|---|---|
| `193[.]233[.]252[.]153` | 215540 Global Connectivity Solutions Llp | RU | real C2 behind `urlhaus[.]abuse[.]st` (related) | decoy answer `252[.]153[.]193[.]233` on 2026-07-28, transform halfswap; contacted by 2 relatives |
| `157[.]22[.]240[.]126` | 215540 Global Connectivity Solutions Llp | RU | real C2 behind `ijustgetsonervy[.]potassium[.]st` (related) | decoy answer `240[.]126[.]157[.]22` on 2026-08-09, transform halfswap; contacted by 3 relatives |
| `157[.]22[.]240[.]126` | 215540 Global Connectivity Solutions Llp | RU | real C2 behind `dvrs[.]botlesscucks[.]st` (related) | decoy answer `240[.]126[.]157[.]22` on 2026-09-12, transform halfswap; contacted by 3 relatives |
| `130[.]49[.]190[.]185` | 215540 Global Connectivity Solutions Llp | RU | real C2 behind `dvrs[.]botlesscucks[.]st` (related) | decoy answer `190[.]185[.]130[.]49` on 2026-09-22, transform halfswap; contacted by 2 relatives |
| `212[.]192[.]14[.]31` | 207713 Global Internet Solutions LLC | RU | real C2 behind `dvrs[.]botlesscucks[.]st` (related) | decoy answer `14[.]31[.]212[.]192` on 2026-09-25, transform halfswap; contacted by 2 relatives |
| `5[.]181[.]2[.]75` | None None | None | real C2 behind `dvrs[.]botlesscucks[.]st` (related) | decoy answer `2[.]75[.]5[.]181` on 2026-10-02, transform halfswap; contacted by 2 relatives |
| `132[.]243[.]187[.]133` | 219359 Edge Core FZE | AM | real C2 behind `dvrs[.]botlesscucks[.]st` (related) | decoy answer `187[.]133[.]132[.]243` on 2026-10-04, transform halfswap; contacted by 2 relatives |
| `45[.]198[.]224[.]123` | None None | None | real C2 behind `hik[.]gettingheadfromduckysmom[.]st` (sample) | decoy answer `224[.]123[.]45[.]198` on 2026-10-17, transform halfswap; contacted by 1 relatives |
| `45[.]198[.]224[.]124` | None None | None | real C2 behind `hik[.]gettingheadfromduckysmom[.]st` (sample) | decoy answer `224[.]124[.]45[.]198` on 2026-10-19, transform halfswap; contacted by 1 relatives |
| `134[.]199[.]154[.]64` | DigitalOcean (per ELLIO) | US | real C2 behind `thunder[.]godofthunder[.]st` (sample) | decoy answer `134[.]154[.]64[.]199` on 2026-10-21, transform rotate3; contacted by 1 relatives |
| `217[.]60[.]103[.]135` | 209373 Swissnet LLC | CH | contacted by 2+ core builds (sandbox) | 40 communicating files on VirusTotal, 17 malicious votes |
| `1[.]122[.]168[.]192` | 1221 Telstra Limited | AU | contacted by 2+ core builds (sandbox) | 27 communicating files on VirusTotal, 0 malicious votes |
| `14[.]31[.]212[.]192` | 4134 Chinanet | CN | passive-DNS answer (may be a decoy; see A8) | 7 communicating files on VirusTotal, 0 malicious votes |
| `190[.]185[.]130[.]49` | 27983 Red Intercable Digital S.A. | AR | passive-DNS answer (may be a decoy; see A8) | 7 communicating files on VirusTotal, 0 malicious votes |
| `2[.]75[.]5[.]181` | 29355 Kcell JSC | KZ | passive-DNS answer (may be a decoy; see A8) | 5 communicating files on VirusTotal, 0 malicious votes |
| `164[.]68[.]127[.]227` | 51167 Contabo GmbH | FR | passive-DNS answer (may be a decoy; see A8) | 3 communicating files on VirusTotal, 0 malicious votes |
| `187[.]112[.]132[.]243` | 18881 TELEFONICA BRASIL S.A | BR | passive-DNS answer (may be a decoy; see A8) | 3 communicating files on VirusTotal, 1 malicious votes |
| `187[.]133[.]132[.]243` | 8151 UNINET | MX | passive-DNS answer (may be a decoy; see A8) | 3 communicating files on VirusTotal, 0 malicious votes |
| `134[.]154[.]64[.]199` | 2152 CENIC | US | passive-DNS answer (may be a decoy; see A8) | 2 communicating files on VirusTotal, 0 malicious votes |
| `2[.]72[.]5[.]181` | 29355 Kcell JSC | KZ | passive-DNS answer (may be a decoy; see A8) | 2 communicating files on VirusTotal, 0 malicious votes |
| `109[.]10[.]145[.]249` | 15557 Societe Francaise Du Radiotelephone - SFR SA | FR | passive-DNS answer (may be a decoy; see A8) | 1 communicating files on VirusTotal, 0 malicious votes |
| `116[.]130[.]147[.]45` | 4837 CHINA UNICOM China169 Backbone | CN | passive-DNS answer (may be a decoy; see A8) | 1 communicating files on VirusTotal, 0 malicious votes |
| `117[.]55[.]202[.]115` | 61254 ESTOXY OU | EE | passive-DNS answer (may be a decoy; see A8) | 1 communicating files on VirusTotal, 2 malicious votes |
| `203[.]219[.]204[.]76` | 7545 TPG Telecom Limited | AU | passive-DNS answer (may be a decoy; see A8) | 1 communicating files on VirusTotal, 0 malicious votes |
| `30[.]194[.]157[.]173` | 749 United States Department of Defense (DoD) | US | passive-DNS answer (may be a decoy; see A8) | 1 communicating files on VirusTotal, 0 malicious votes |
| `113[.]104[.]89[.]23` | 4134 Chinanet | CN | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `116[.]7[.]147[.]45` | 4134 Chinanet | CN | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `131[.]59[.]78[.]159` | 56 United States Department of Defense (DoD) | US | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `139[.]103[.]78[.]153` | 611 NB-PEI Educational Computer Network | CA | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `192[.]88[.]155[.]2` | 63407 Terracon Consultants, Inc. | US | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `2[.]8[.]5[.]181` | 3215 Orange | FR | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `207[.]101[.]93[.]152` | 2828 Verizon Business | US | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `218[.]95[.]130[.]49` | 4134 Chinanet | CN | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `31[.]186[.]45[.]142` | 44473 S.T. S.r.l. | IT | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `41[.]108[.]89[.]32` | 36947 Telecom Algeria | DZ | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `41[.]109[.]89[.]32` | 36947 Telecom Algeria | DZ | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `41[.]111[.]89[.]32` | 36947 Telecom Algeria | DZ | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `41[.]114[.]89[.]32` | 12091 MTN SA | ZA | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `41[.]117[.]89[.]32` | 12091 MTN SA | ZA | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `41[.]128[.]89[.]32` | 24863 Link Egypt (Link.NET) | EG | passive-DNS answer (may be a decoy; see A8) | 0 communicating files on VirusTotal, 0 malicious votes |
| `49[.]6[.]172[.]233` | not announced | | ENS `ip` record value of `catswithhatslolksjhakf[.]eth` | current on-chain value; no sample seen contacting it |

Published by ELLIO (2026-10-22) for the same sample: C2 address `134[.]199[.]154[.]64` (DigitalOcean, reached through the rotation from the decoy `134[.]154[.]64[.]199`), update host `117[.]55[.]202[.]115`, staging host `92[.]118[.]112[.]100` (AS215540) serving `hxxp://92[.]118[.]112[.]100/nfs`, loader source `45[.]198[.]224[.]169`. Of these, the C2 address appears among the contacted addresses of our relatives and the update host is the EE address above.

#### A8. Decoy DNS answers (do not block)

| host | date | published answer | half-swap candidate | rotation candidate |
|---|---|---|---|---|
| `abuse[.]st` | 2026-05-30 | `164[.]68[.]127[.]227` | `127[.]227[.]164[.]68` | `164[.]227[.]68[.]127` |
| `botlesscucks[.]st` | 2026-05-14 | `164[.]68[.]127[.]227` | `127[.]227[.]164[.]68` | `164[.]227[.]68[.]127` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-16 | `41[.]128[.]89[.]32` | `89[.]32[.]41[.]128` | `41[.]32[.]128[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-08 | `41[.]111[.]89[.]32` | `89[.]32[.]41[.]111` | `41[.]32[.]111[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-08 | `41[.]63[.]89[.]32` | `89[.]32[.]41[.]63` | `41[.]32[.]63[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-08 | `41[.]114[.]89[.]32` | `89[.]32[.]41[.]114` | `41[.]32[.]114[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-08 | `41[.]59[.]89[.]32` | `89[.]32[.]41[.]59` | `41[.]32[.]59[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-08 | `41[.]108[.]89[.]32` | `89[.]32[.]41[.]108` | `41[.]32[.]108[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-08 | `41[.]117[.]89[.]32` | `89[.]32[.]41[.]117` | `41[.]32[.]117[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-08 | `41[.]146[.]89[.]32` | `89[.]32[.]41[.]146` | `41[.]32[.]146[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-07 | `41[.]109[.]89[.]32` | `89[.]32[.]41[.]109` | `41[.]32[.]109[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-06 | `41[.]49[.]89[.]32` | `89[.]32[.]41[.]49` | `41[.]32[.]49[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-06 | `192[.]88[.]155[.]2` | `155[.]2[.]192[.]88` | `192[.]2[.]88[.]155` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `62[.]30[.]62[.]133` | `62[.]133[.]62[.]30` | `62[.]133[.]30[.]62` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `109[.]10[.]145[.]249` | `145[.]249[.]109[.]10` | `109[.]249[.]10[.]145` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `84[.]98[.]89[.]185` | `89[.]185[.]84[.]98` | `84[.]185[.]98[.]89` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `67[.]244[.]138[.]124` | `138[.]124[.]67[.]244` | `67[.]124[.]244[.]138` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `116[.]130[.]147[.]45` | `147[.]45[.]116[.]130` | `116[.]45[.]130[.]147` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `67[.]16[.]138[.]124` | `138[.]124[.]67[.]16` | `67[.]124[.]16[.]138` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `67[.]60[.]138[.]124` | `138[.]124[.]67[.]60` | `67[.]124[.]60[.]138` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `187[.]112[.]132[.]243` | `132[.]243[.]187[.]112` | `187[.]243[.]112[.]132` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-04 | `187[.]133[.]132[.]243` | `132[.]243[.]187[.]133` | `187[.]243[.]133[.]132` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-02 | `2[.]75[.]5[.]181` | `5[.]181[.]2[.]75` | `2[.]181[.]75[.]5` |
| `dvrs[.]botlesscucks[.]st` | 2026-10-01 | `2[.]72[.]5[.]181` | `5[.]181[.]2[.]72` | `2[.]181[.]72[.]5` |
| `dvrs[.]botlesscucks[.]st` | 2026-09-25 | `14[.]31[.]212[.]192` | `212[.]192[.]14[.]31` | `14[.]192[.]31[.]212` |
| `dvrs[.]botlesscucks[.]st` | 2026-09-23 | `233[.]131[.]45[.]95` | `45[.]95[.]233[.]131` | `233[.]95[.]131[.]45` |
| `dvrs[.]botlesscucks[.]st` | 2026-09-22 | `190[.]185[.]130[.]49` | `130[.]49[.]190[.]185` | `190[.]49[.]185[.]130` |
| `dvrs[.]botlesscucks[.]st` | 2026-09-20 | `116[.]7[.]147[.]45` | `147[.]45[.]116[.]7` | `116[.]45[.]7[.]147` |
| `dvrs[.]botlesscucks[.]st` | 2026-09-12 | `240[.]126[.]157[.]22` | `157[.]22[.]240[.]126` | `240[.]22[.]126[.]157` |
| `dvrs[.]botlesscucks[.]st` | 2026-09-09 | `30[.]194[.]157[.]173` | `157[.]173[.]30[.]194` | `30[.]173[.]194[.]157` |
| `dvrs2[.]botlesscucks[.]st` | 2026-10-07 | `41[.]59[.]89[.]32` | `89[.]32[.]41[.]59` | `41[.]32[.]59[.]89` |
| `dvrs2[.]botlesscucks[.]st` | 2026-10-07 | `41[.]63[.]89[.]32` | `89[.]32[.]41[.]63` | `41[.]32[.]63[.]89` |
| `dvrs2[.]botlesscucks[.]st` | 2026-10-06 | `41[.]49[.]89[.]32` | `89[.]32[.]41[.]49` | `41[.]32[.]49[.]89` |
| `gettingheadfromduckysmom[.]st` | 2026-09-29 | `164[.]68[.]127[.]227` | `127[.]227[.]164[.]68` | `164[.]227[.]68[.]127` |
| `godofthunder[.]st` | 2026-10-12 | `164[.]68[.]127[.]227` | `127[.]227[.]164[.]68` | `164[.]227[.]68[.]127` |
| `hackattackkaboom[.]botlesscucks[.]st` | 2026-06-05 | `117[.]55[.]202[.]115` | `202[.]115[.]117[.]55` | `117[.]115[.]55[.]202` |
| `hackattackkaboom[.]botlesscucks[.]st` | 2026-05-20 | `45[.]153[.]34[.]26` | `34[.]26[.]45[.]153` | `45[.]26[.]153[.]34` |
| `hik[.]gettingheadfromduckysmom[.]st` | 2026-10-19 | `224[.]124[.]45[.]198` | `45[.]198[.]224[.]124` | `224[.]198[.]124[.]45` |
| `hik[.]gettingheadfromduckysmom[.]st` | 2026-10-17 | `224[.]123[.]45[.]198` | `45[.]198[.]224[.]123` | `224[.]198[.]123[.]45` |
| `hik[.]gettingheadfromduckysmom[.]st` | 2026-10-16 | `203[.]219[.]204[.]76` | `204[.]76[.]203[.]219` | `203[.]76[.]219[.]204` |
| `hik[.]gettingheadfromduckysmom[.]st` | 2026-10-02 | `45[.]198[.]224[.]124` | `224[.]124[.]45[.]198` | `45[.]124[.]198[.]224` |
| `hik[.]gettingheadfromduckysmom[.]st` | 2026-10-02 | `45[.]198[.]224[.]123` | `224[.]123[.]45[.]198` | `45[.]123[.]198[.]224` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-19 | `19[.]146[.]31[.]56` | `31[.]56[.]19[.]146` | `19[.]56[.]146[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-17 | `19[.]149[.]31[.]56` | `31[.]56[.]19[.]149` | `19[.]56[.]149[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-17 | `19[.]142[.]31[.]56` | `31[.]56[.]19[.]142` | `19[.]56[.]142[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-17 | `19[.]141[.]31[.]56` | `31[.]56[.]19[.]141` | `19[.]56[.]141[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-16 | `19[.]144[.]31[.]56` | `31[.]56[.]19[.]144` | `19[.]56[.]144[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-16 | `19[.]147[.]31[.]56` | `31[.]56[.]19[.]147` | `19[.]56[.]147[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-16 | `19[.]143[.]31[.]56` | `31[.]56[.]19[.]143` | `19[.]56[.]143[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-10 | `19[.]111[.]31[.]56` | `31[.]56[.]19[.]111` | `19[.]56[.]111[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-07 | `113[.]104[.]89[.]23` | `89[.]23[.]113[.]104` | `113[.]23[.]104[.]89` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-07 | `19[.]70[.]31[.]56` | `31[.]56[.]19[.]70` | `19[.]56[.]70[.]31` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-07 | `41[.]19[.]89[.]32` | `89[.]32[.]41[.]19` | `41[.]32[.]19[.]89` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-07 | `41[.]43[.]89[.]32` | `89[.]32[.]41[.]43` | `41[.]32[.]43[.]89` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-07 | `232[.]146[.]45[.]95` | `45[.]95[.]232[.]146` | `232[.]95[.]146[.]45` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-06 | `82[.]70[.]89[.]185` | `89[.]185[.]82[.]70` | `82[.]185[.]70[.]89` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-06 | `69[.]144[.]87[.]251` | `87[.]251[.]69[.]144` | `69[.]251[.]144[.]87` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-06 | `69[.]145[.]87[.]251` | `87[.]251[.]69[.]145` | `69[.]251[.]145[.]87` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-06 | `69[.]166[.]87[.]251` | `87[.]251[.]69[.]166` | `69[.]251[.]166[.]87` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-05 | `31[.]186[.]45[.]142` | `45[.]142[.]31[.]186` | `31[.]142[.]186[.]45` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-04 | `68[.]31[.]45[.]155` | `45[.]155[.]68[.]31` | `68[.]155[.]31[.]45` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-04 | `2[.]8[.]5[.]181` | `5[.]181[.]2[.]8` | `2[.]181[.]8[.]5` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-10-03 | `69[.]165[.]87[.]251` | `87[.]251[.]69[.]165` | `69[.]251[.]165[.]87` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-09-24 | `82[.]39[.]89[.]185` | `89[.]185[.]82[.]39` | `82[.]185[.]39[.]89` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-09-23 | `82[.]37[.]89[.]185` | `89[.]185[.]82[.]37` | `82[.]185[.]37[.]89` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-09-22 | `82[.]38[.]89[.]185` | `89[.]185[.]82[.]38` | `82[.]185[.]38[.]89` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-30 | `103[.]25[.]217[.]60` | `217[.]60[.]103[.]25` | `103[.]60[.]25[.]217` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-18 | `218[.]95[.]130[.]49` | `130[.]49[.]218[.]95` | `218[.]49[.]95[.]130` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-12 | `131[.]59[.]78[.]159` | `78[.]159[.]131[.]59` | `131[.]159[.]59[.]78` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-12 | `207[.]101[.]93[.]152` | `93[.]152[.]207[.]101` | `207[.]152[.]101[.]93` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `139[.]103[.]78[.]153` | `78[.]153[.]139[.]103` | `139[.]153[.]103[.]78` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `62[.]8[.]138[.]124` | `138[.]124[.]62[.]8` | `62[.]124[.]8[.]138` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `2[.]220[.]5[.]181` | `5[.]181[.]2[.]220` | `2[.]181[.]220[.]5` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `2[.]223[.]5[.]181` | `5[.]181[.]2[.]223` | `2[.]181[.]223[.]5` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `240[.]194[.]157[.]22` | `157[.]22[.]240[.]194` | `240[.]22[.]194[.]157` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `241[.]124[.]157[.]22` | `157[.]22[.]241[.]124` | `241[.]22[.]124[.]157` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `240[.]126[.]157[.]22` | `157[.]22[.]240[.]126` | `240[.]22[.]126[.]157` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `241[.]125[.]157[.]22` | `157[.]22[.]241[.]125` | `241[.]22[.]125[.]157` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-08-09 | `246[.]5[.]77[.]83` | `77[.]83[.]246[.]5` | `246[.]83[.]5[.]77` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-07-31 | `53[.]203[.]178[.]16` | `178[.]16[.]53[.]203` | `53[.]16[.]203[.]178` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-07-26 | `70[.]147[.]154[.]90` | `154[.]90[.]70[.]147` | `70[.]90[.]147[.]154` |
| `ijustgetsonervy[.]potassium[.]st` | 2026-07-26 | `224[.]24[.]45[.]198` | `45[.]198[.]224[.]24` | `224[.]198[.]24[.]45` |
| `iloveboats[.]st` | 2026-08-08 | `94[.]154[.]43[.]60` | `43[.]60[.]94[.]154` | `94[.]60[.]154[.]43` |
| `iloveboats[.]st` | 2026-08-04 | `94[.]154[.]43[.]158` | `43[.]158[.]94[.]154` | `94[.]158[.]154[.]43` |
| `potassium[.]st` | 2026-06-06 | `164[.]68[.]127[.]227` | `127[.]227[.]164[.]68` | `164[.]227[.]68[.]127` |
| `thunder[.]godofthunder[.]st` | 2026-10-21 | `134[.]154[.]64[.]199` | `64[.]199[.]134[.]154` | `134[.]199[.]154[.]64` |
| `urlhaus[.]abuse[.]st` | 2026-07-28 | `252[.]153[.]193[.]233` | `193[.]233[.]252[.]153` | `252[.]233[.]153[.]193` |

#### A9. URLs

| url | source |
|---|---|
| `hxxp://170[.]64[.]137[.]28/x86_64` | ITW URL of 5494394cdfb5 |
| `hxxp://184[.]174[.]96[.]216/s7cn4[.]x86` | ITW URL of 4cae4c533e96 |
| `hxxp://184[.]174[.]96[.]216/s7cn4[.]x86/` | ITW URL of 4cae4c533e96 |
| `hxxp://45[.]135[.]193[.]63/flutter[.]m68k` | ITW URL of 95ca6596a568 |
| `hxxp://45[.]135[.]193[.]63/m68k` | ITW URL of 95ca6596a568 |
| `hxxp://45[.]74[.]3[.]24/bot[.]x86_64` | ITW URL of b7482848fb53 |
| `hxxp://89[.]185[.]82[.]24/arm5` | ITW URL of 07b98716aa3f |
| `hxxp://89[.]185[.]82[.]24/arm6` | ITW URL of 9db8b250054f |
| `hxxp://89[.]185[.]82[.]24/arm7` | ITW URL of 8329ed49c67a; ITW URL of 9ae981175d5e |
| `hxxp://89[.]185[.]82[.]24/arm77` | ITW URL of 5420b2745e8d |
| `hxxp://89[.]185[.]82[.]24/sh4` | ITW URL of 2a937c301fb2 |
| `hxxp://92[.]118[.]112[.]100/nfs` | ITW URL of 0c5486f06620 |
| `hxxp://abuse[.]st/` | URL under abuse.st |
| `hxxp://abusing[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://boom[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://dedi9999[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://dedinumberinfinite[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://dvrdownloader[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://dvrs[.]botlesscucks[.]st/` | URL under botlesscucks.st; URL under dvrs[.]botlesscucks[.]st |
| `hxxp://fsocietyhackattack[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st |
| `hxxp://godofthunder[.]st/` | URL under godofthunder.st |
| `hxxp://hackattackkaboom[.]botlesscucks[.]st/` | URL under hackattackkaboom[.]botlesscucks[.]st |
| `hxxp://hackattackkaboom[.]botlesscucks[.]st/arm7` | URL under hackattackkaboom[.]botlesscucks[.]st |
| `hxxp://hackattackkaboom[.]botlesscucks[.]st/x86_64` | URL under hackattackkaboom[.]botlesscucks[.]st |
| `hxxp://hik[.]gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st; URL under hik[.]gettingheadfromduckysmom[.]st |
| `hxxp://ijustgetsonervy[.]potassium[.]st/` | URL under ijustgetsonervy[.]potassium[.]st; URL under potassium.st |
| `hxxp://ijustgetsonervy1[.]potassium[.]st/` | URL under potassium.st |
| `hxxp://iloveboats[.]st/` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/bash[.]sh` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/bash[.]sh/` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]arm6/` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]arm7` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]m68k` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]mips` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]mips/` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]mipsel` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]mipsel/` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]ppc/` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]ppc440` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]ppc440/` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]sh4` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]x32` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]x64-test` | URL under iloveboats.st |
| `hxxp://iloveboats[.]st:8081/titan[.]x64-test/` | URL under iloveboats.st |
| `hxxp://mail[.]potassium[.]st/` | URL under potassium.st |
| `hxxp://musika[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://potassium[.]st/` | URL under potassium.st |
| `hxxp://smart[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://stoplooking1[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://stoplooking2[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://thunder[.]godofthunder[.]st/` | URL under godofthunder.st; URL under thunder[.]godofthunder[.]st |
| `hxxp://tvt[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://vitacocoyougoloco[.]potassium[.]st/` | URL under potassium.st |
| `hxxp://vitacocoyoungoloco[.]potassium[.]st/` | URL under potassium.st |
| `hxxp://www[.]abusing[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://www[.]boom[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://www[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://www[.]gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st |
| `hxxp://www[.]godofthunder[.]st/` | URL under godofthunder.st |
| `hxxp://www[.]hik[.]gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st |
| `hxxp://www[.]iloveboats[.]st/` | URL under iloveboats.st |
| `hxxp://www[.]musika[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://www[.]potassium[.]st/` | URL under potassium.st |
| `hxxp://www[.]smart[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://www[.]tvt[.]abuse[.]st/` | URL under abuse.st |
| `hxxp://www[.]vitacocoyougoloco[.]potassium[.]st/` | URL under potassium.st |
| `hxxp://www[.]youareall[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://youareall[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://94[.]183[.]174[.]77/flutter[.]m68k` | ITW URL of 95ca6596a568 |
| `hxxps://abusing[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://boom[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://dvrs[.]botlesscucks[.]st/` | URL under dvrs[.]botlesscucks[.]st |
| `hxxps://fsocietyhackattack[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st |
| `hxxps://hackattackkaboom[.]botlesscucks[.]st/` | URL under botlesscucks.st; URL under hackattackkaboom[.]botlesscucks[.]st |
| `hxxps://hik[.]gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st; URL under hik[.]gettingheadfromduckysmom[.]st |
| `hxxps://ijustgetsonervy[.]potassium[.]st/` | URL under ijustgetsonervy[.]potassium[.]st; URL under potassium.st |
| `hxxps://ijustgetsonervy1[.]potassium[.]st/` | URL under potassium.st |
| `hxxps://iloveboats[.]st/` | URL under iloveboats.st |
| `hxxps://musika[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://potassium[.]st/` | URL under potassium.st |
| `hxxps://smart[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://stoplooking[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://stoplooking2[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://thunder[.]godofthunder[.]st/` | URL under godofthunder.st; URL under thunder[.]godofthunder[.]st |
| `hxxps://tvt[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://vitacocoyougoloco[.]potassium[.]st/` | URL under potassium.st |
| `hxxps://www[.]abusing[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://www[.]boom[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://www[.]dvrs[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://www[.]gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st |
| `hxxps://www[.]hik[.]gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st |
| `hxxps://www[.]iloveboats[.]st/` | URL under iloveboats.st |
| `hxxps://www[.]potassium[.]st/` | URL under potassium.st |
| `hxxps://www[.]smart[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://www[.]stoplooking[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://www[.]tvt[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://www[.]vitacocoyougoloco[.]potassium[.]st/` | URL under potassium.st |
| `hxxps://www[.]youareall[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://youareall[.]botlesscucks[.]st/` | URL under botlesscucks.st |

#### A10. Execution parents and files tied to the infrastructure

Execution parents (droppers and scripts that ran a relative):

| parent sha256 | ran |
|---|---|
| `f27a60ab9231adebcd917f1ca6e0510785d4d42c2fa2b09e7fd589562dff9251` | 19404421a1be, f27a60ab9231 |
| `04d3aefbcb6d2097f66a3ec053a2b17cb1af298a215f6299f691aae88992acd9` | 04d3aefbcb6d |
| `2a3aab2a262a9fccf8c35ebe2fdfe08f533395a4cf78b2cb202e5ca2129c5c4e` | 2a3aab2a262a |
| `4f72fc11689772b49972d34a31dba448aacd1fd0a65eeac4681585bc9d04a5d0` | 4f72fc116897 |
| `5c3b7bc52f43afdd7f0e2232f1695e867b71d58a91842654d376c2474521fdf6` | 5c3b7bc52f43 |
| `a5b910d1d1f43d45a0bc2aa08bcd059cacc3aa3940002ed08828a9a0caedf4cf` | 676c914f3002 |
| `6b7c0fa7c4cf72f39fb8753d2599353ccfd8449ddbb21b07acc05da4fd254c06` | 6b7c0fa7c4cf |
| `8d3039c111ecccfb08e37344787e93998c08c59cfb8ee11b3f76e93371186f08` | 8d3039c111ec |
| `91c3d9de90635f38e9ac25c69846edb2a950f52b891379e6cdd285961255fb98` | 90b06f07eb75 |
| `972b7ffa46c52aaec7de4a209f37835515c089db8fe84996b7fdae4f31b1cf4f` | 972b7ffa46c5 |
| `99dee7e7d52a95393b69093792c1c2a974dc2360467a64a22bd14e110d152735` | 99dee7e7d52a |
| `1e88235e2a193668e2f8b1ab0bfd4e91b8707ecf450748cd73709e7dd777dc26` | 9e0d7b64f1d7 |
| `ead9b20d35f4bfbe23f6471a3d526a072a8292b04e20d5f03afdf63cfff13b00` | 9e0d7b64f1d7 |
| `9e966b85bc00a124a69addc5dd676cf54fe0dd4649b1a98a2bd9c447b852ca55` | 9e966b85bc00 |
| `a9353bc636c4ab17b0cbe68e289d908db6927ca5df6f28082dcde4f8694c18f2` | a9353bc636c4 |
| `76d52746897f0a6a99b991fe9b5fc4a5ae6afdc12d57f1f0d3b3c18cd967c343` | b48bfc0b588e |
| `b48bfc0b588e0ea9d4638d64ffdfb9b2b28537c64d5a53134d0edb9bdf7ab182` | b48bfc0b588e |
| `b4ae86de813acefbdeac8794336a72da081e68b8004a68be0ec3aa258d86d76a` | b4ae86de813a |
| `87740a04af37f2d637caf98a73ab30c18273f1a8b3a48e4c0f935a4b365445c8` | b7482848fb53 |
| `b7482848fb53521948ca29e5d7b4bf78454f6ac768355b52c62aef149f3fff3f` | b7482848fb53 |
| `32a9892b9968c6acf561d371891ec53a54c22d0d30172ed2fd38fdfea4147a81` | bc6854418c71 |
| `d3d562dd6dd1ab9eb00c129df63bd410af9559de00a2221f4b82f29c98072131` | d3d562dd6dd1 |
| `e178d34417d1c130c933ed8cfaa1bcc991529cb1d76d8529ad09349cd4564cc9` | e178d34417d1 |
| `e58ff94b9a26238f683278c3a3d48fba18dd26ff85c706d5972192bd7168d0a7` | e58ff94b9a26 |
| `e7aeac7b5834cc74cc104dfb928a328c8182c0dd24d02ba43d2b831e9f63ec72` | e7aeac7b5834 |
| `ef549f315d3af072ff7db4c7f65cdf1e7a9b30bb3a0143a6f9ef7b2d2dc2ffec` | ef549f315d3a |
| `f7724e6386bd8c3ef54bcd8b093ab7b40af8879ee3ec8b5fbd9a36e966790873` | f7724e6386bd |
| `fcbe8dd8a0180128d705bbe6b6c2a5809997d5c317bffe30674b7753e5a6d370` | fcbe8dd8a018 |

Files not in the corpus that communicate with the group's domains or real hosting (79):

| sha256 | type | first submission | VT label | via |
|---|---|---|---|---|
| `193e1d0c060de1f249a4b5cfbf82ec6be47223ae4ac3c668851eb33b8e0758d7` | Android | 2022-10-09 | None | `1[.]122[.]168[.]192` |
| `293473bbf4fa7abb674c12d0b0ff59a47df87d38c0c89658ff343aab189cc89d` | Android | 2022-11-11 | None | `1[.]122[.]168[.]192` |
| `60c078cdcbb2c0d66ba9998d8ec2ebd820b4d9938ae03da7451db00d25935b02` | Android | 2023-12-05 | None | `1[.]122[.]168[.]192` |
| `7b15e02eb1012a75718bdbb7e4eb296337f7ddab152a72caf81f4440abf101b5` | ELF | 2026-06-06 | trojan.mirai/usblf626 | `ijustgetsonervy[.]potassium[.]st` |
| `4f4cf083f86f7f6e3172993b99b970e70aa36627e328c486a875b9e12b5a9502` | ELF | 2026-06-09 | trojan.mirai/usblf926 | `193[.]233[.]252[.]153`, `ijustgetsonervy[.]potassium[.]st` |
| `7b9c4745eae8f7b4630c1e0287bbbc2e946956d0a9855fb2d1cf46c5fe9b7d47` | ELF | 2026-06-14 | trojan.mirai/possible | `164[.]68[.]127[.]227` |
| `10c7853e6dc953e6b805cef03a7324caf6c87e68117a7c3175feb463c5c9c0e0` | ELF | 2026-06-18 | trojan.mirai/miraiagen | `193[.]233[.]252[.]153` |
| `05e0414efe5881316753e5a5ac212c1718f6f18a134cf2779adc10eef7ec525e` | ELF | 2026-08-04 | trojan.mirai/condi | `iloveboats[.]st` |
| `0ce362bf06c68be344858677d7426c328682a614fead927e0a22cbb9909dfb71` | ELF | 2026-08-04 | trojan.mirai/miraiagen | `iloveboats[.]st` |
| `133d712ef14ede70885452f0e83ead522457954871c5ecce74019df4a81fa62a` | ELF | 2026-08-04 | trojan.mirai/miraiagen | `iloveboats[.]st` |
| `311a51ead623e45f2e5310236cc0db150ad92dbafbdffc09593283b2172529a0` | ELF | 2026-08-04 | trojan.mirai/miraiagen | `iloveboats[.]st` |
| `357866d4d773a24217e8a4053fb1a7e9f75ed1be571a2acbec1d4069f7b2a452` | ELF | 2026-08-04 | trojan.mirai/tl0101h526zt | `iloveboats[.]st` |
| `45a8be88406c96cc70a24dee4a70549d374101037b1f612186d205eced87b1ad` | ELF | 2026-08-04 | trojan.mirai/miraiagen | `iloveboats[.]st` |
| `480319a161dcbd7aba883f7950b690819552f4d19b50c500a6310f93424edfe7` | ELF | 2026-08-04 | trojan.mirai/usblh626 | `iloveboats[.]st` |
| `4dd104330e996a429f67c9d0a6c9dbeb72ecbc18efc6cec3b437ddb67c20b7a2` | ELF | 2026-08-04 | trojan.mirai/tl0101h526zw | `iloveboats[.]st` |
| `54cf8090eb6444b31110065b81e518a95db0dce6c9e84c50733d12fe1efaf316` | ELF | 2026-08-04 | trojan.mirai/tl0101h526zy | `iloveboats[.]st` |
| `552fd7f65d88d0bcbab4a158789ee908a9ac57f3f0405544c4ebac3217a51cf4` | ELF | 2026-08-04 | trojan.mirai/egairtigado | `iloveboats[.]st` |
| `5c7dd5ca5b8b851094c92ca2bd2616c77888e56d6444f422d63c03c0692ace55` | ELF | 2026-08-04 | trojan.mirai/egairtigado | `iloveboats[.]st` |
| `1d73e05dc57be92556585d06299e706a7dbf66203d5770f8dfdd433481b87ac9` | ELF | 2026-08-05 | trojan.mirai/usblh726 | `iloveboats[.]st` |
| `4135a4f52eb88adb74fe31baaa9b13c89b17a743ccf8dc2dae2f7ee5e2c634e5` | ELF | 2026-08-05 | trojan.mirai/condi | `iloveboats[.]st` |
| `58344ba1d657d0620d762730bcfca0fc5d7df510777c7984db227e3013f6f356` | ELF | 2026-08-05 | trojan.mirai/egairtigado | `iloveboats[.]st` |
| `061c95f6e18dc10f64c5bc442084e7333fc56462bb0da197dd15f9ef2efbd0c7` | ELF | 2026-08-06 | trojan.mirai/condi | `iloveboats[.]st` |
| `07310b71a33cb76729daed760d08efb079b4591db5b62c647e4deeacb2556e2b` | ELF | 2026-08-06 | trojan.mirai/condi | `iloveboats[.]st` |
| `11f0b6ae9d0de0c3d397b692adf8da6d86c3af4d3110eda87258a255cb76d8a7` | ELF | 2026-08-06 | trojan.mirai/usblhn26 | `iloveboats[.]st` |
| `15e7ed72b583b5963afd09be21fa1c43c1634de711e97af81d30deb6ce7097eb` | ELF | 2026-08-06 | trojan.mirai/condi | `iloveboats[.]st` |
| `2628eaa0b416dc297d79ab137259099ea511306534f633ff4b850de7bcdd8df7` | ELF | 2026-08-06 | trojan.mirai/gafgyt | `iloveboats[.]st` |
| `2739948d9d667643e0e85204590bad2d533ca3e6ba7efe5c9d7f23ffb1325a8b` | ELF | 2026-08-06 | trojan.mirai/tl0101h826zt | `iloveboats[.]st` |
| `31b13816f0b94bd65ebd7d8e898c78eb919da4bd3500ae2bbebcc1ccbc79a508` | ELF | 2026-08-06 | trojan.mirai | `iloveboats[.]st` |
| `3b66f8c544c1882dc1c63e08e6b92e38df9fe4e4d4b13fdd3e9dbc186b7f923a` | ELF | 2026-08-06 | trojan.mirai/usblha26 | `iloveboats[.]st` |
| `4fbc4150ddc9d3e33312377246498d1ca598562edfae0a53b2a0ed2ad84b1033` | ELF | 2026-08-06 | trojan.mirai/condi | `iloveboats[.]st` |
| `566e7e389cfed8aeaeb57badfeb406a7b1738fb09a4564a04b907d92f49b386f` | Shell script | 2026-08-06 | trojan.shell/gen2 | `iloveboats[.]st` |
| `5708704e888e29816dee0a43bcd10e839d91c304e9f6581a457a8f07155d7404` | ELF | 2026-08-06 | trojan.mirai/botnet | `iloveboats[.]st` |
| `57a6606aa4794894d72be744994a892172e655fe6926a20b4737edb36caf3a58` | ELF | 2026-08-06 | trojan.mirai/condi | `iloveboats[.]st` |
| `07aeab518d9cdd0e0eeee5653d8e62187fe02a78775118a32fd73e58b759d607` | ELF | 2026-08-07 | trojan.mirai/botnet | `iloveboats[.]st` |
| `097f826ec0d3f171d67d8ddfc65fa2892aef6a4cbdad57dd7f737c17dcb7627f` | ELF | 2026-08-07 | trojan.mirai | `iloveboats[.]st` |
| `09a37df33ad341dd957aa8838e1ffcce7a8be7859dddcdf95be7221377fdcc57` | ELF | 2026-08-07 | trojan.mirai/siggen | `iloveboats[.]st` |
| `11b3f4067a423158786021eee5ba5baf69a97d9cde5974c401733a64113a897d` | ELF | 2026-08-07 | trojan.mirai/tl0101h826zt | `iloveboats[.]st` |
| `12a2558cceab1c295b0497cdff6e4d919da147e910bcf6f7addcebc308c13d03` | ELF | 2026-08-07 | trojan.mirai/botnet | `iloveboats[.]st` |
| `4497610ad3cdd72cf058b3a92bf76d1b5fc94b65e218794bd53ebce338744c58` | ELF | 2026-08-07 | trojan.mirai/ravartar | `iloveboats[.]st` |
| `51e25237d9b05007d1687a8a1687507579300fef256adfbf1aeecb18d8f8ec4a` | ELF | 2026-08-07 | trojan.mirai/condi | `iloveboats[.]st` |
| `593e250c04a957ec6a260557e8e956cf9b2765614371f0e4d2af55f515e290a4` | ELF | 2026-08-07 | trojan.mirai/usblh726 | `iloveboats[.]st` |
| `5c177c68e47e508593a608f755a2ce23e832fefa3ff4f504ad906592f03e9529` | ELF | 2026-08-07 | trojan.mirai/usblh726 | `iloveboats[.]st` |
| `5bda8b6db17de1ff60ae1e7718f5c2bf5f3447658ac85311cc56a86279ceb3ff` | ELF | 2026-08-08 | trojan.mirai/gafgyt | `iloveboats[.]st` |
| `2bff7468dd9c34e76609953e14435e8932074efeef3e5d623f601c4e45ca9723` | ELF | 2026-08-10 | trojan.mirai/botnet | `iloveboats[.]st` |
| `01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a` | ELF | 2026-08-12 | trojan.mirai/abmrisk | `1[.]122[.]168[.]192` |
| `35bf80f0af528d458d53a7f7179e0ae284d6fb2be613bab904b8fe115e730b0d` | ELF | 2026-08-12 | trojan.mirai/gafgyt | `1[.]122[.]168[.]192` |
| `7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9` | ELF | 2026-08-12 | trojan.mirai/tl0101he26zu | `1[.]122[.]168[.]192` |
| `3a56f24ab23598a62933859f8839bf74796547c29d5e78727e56fbc497327330` | ELF | 2026-08-13 | trojan.mirai/usblhe26 | `1[.]122[.]168[.]192` |
| `44a6090b72ff9094a862f13a14ff333fcf19b41eb58af9c0bd54f23834c175fa` | ELF | 2026-08-13 | trojan.mirai/tl0101he26zw | `1[.]122[.]168[.]192` |
| `6a1cefffb07c9a6d58f42f1ed686e4ff7de0f70196d6fef76f424f219e36a315` | ELF | 2026-08-13 | trojan.mirai/usblhd26 | `1[.]122[.]168[.]192` |
| `5e64d60235104c62a531c5996927dad7defa9c7e2f7e16422608e6ed26b9837e` | ZIP | 2026-08-17 | trojan. | `1[.]122[.]168[.]192` |
| `76659732f7dbfe456bce1237ac158bb811181164cb6ca24a1aa2e9dea1bd9ba1` | Win32 EXE | 2026-08-17 | trojan.cayunamer | `1[.]122[.]168[.]192` |
| `767cd32bc1acd108fd673467e8f0baaf420c4ad1fdc3d2d74756821dc2ed1f9f` | Win32 EXE | 2026-09-02 | trojan.dacic/babyk | `1[.]122[.]168[.]192` |
| `3dd111519325ecf18ed9202649c4f8740a2c195382cd4337fc701056d2234f3b` | ZIP | 2026-09-08 | trojan. | `1[.]122[.]168[.]192` |
| `3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc` | ELF | 2026-09-09 | trojan.mirai/ddos | `1[.]122[.]168[.]192`, `157[.]22[.]240[.]126`, `30[.]194[.]157[.]173`, `dvrs[.]botlesscucks[.]st` |
| `07b8e9dd4a45f9c2afe81fa0b02445c44461cc508d6de71ef18fd4a008af95bd` | ELF | 2026-09-23 | trojan.mirai/tl0101io26zz | `1[.]122[.]168[.]192`, `130[.]49[.]190[.]185`, `157[.]22[.]240[.]126`, `190[.]185[.]130[.]49`, `dvrs[.]botlesscucks[.]st` |
| `2b32143e21c0b2ceed37f1100d3a3d42379c48c6d4163f31e25aa524bea34a14` | ELF | 2026-09-23 | trojan.mirai/gafgyt | `1[.]122[.]168[.]192`, `190[.]185[.]130[.]49`, `dvrs[.]botlesscucks[.]st` |
| `0a0c931f6a7b4d4d66389dab1c83cb4f7355f627399a040e79ce34ae2ab02957` | Shell script | 2026-09-23 | downloader.bash/miraib | `217[.]60[.]103[.]135` |
| `59a57a435776d6ef223fd4f8fd51086f82ad2a53ac5b23451bdc55a4a48727ab` | ELF | 2026-09-23 | trojan.mirai/abbackdoor | `217[.]60[.]103[.]135` |
| `03a11dd222b251f0dfd2f1c5140d8d94ec101284e7bc602e25b049d5133d52b4` | ELF | 2026-09-24 | trojan.mirai/nzfl | `217[.]60[.]103[.]135` |
| `0fb58f267cde56907dd8c626e384589c845a431d2eeaa1d316b7d4aeff71539d` | ELF | 2026-09-24 | trojan.mirai | `217[.]60[.]103[.]135` |
| `1921fbac7491fd43f197b13d471e7faab8fd41273115ce36ba3731b74934d01b` | ELF | 2026-09-24 | trojan.mirai/usblip26 | `217[.]60[.]103[.]135` |
| `1a5d8121b5999225a58bb2271b70dee017684ffe1f63b1dc9c4c8b198c861220` | ELF | 2026-09-24 | trojan.mirai/gafgyt | `217[.]60[.]103[.]135` |
| `1df80ce06971c31a0d332fd7ebe7d6c74a7e7bb3485298004c1c4e9482763532` | ELF | 2026-09-24 | trojan.mirai/usbliu26 | `217[.]60[.]103[.]135` |
| `43642929001bd532ebb961c15953d0e703055f9e4b2685686eb0da19bf6ab370` | ELF | 2026-09-24 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `480d93ed11cea67d663bb04e3e5be57dbfcb323a4165e02838b28afb7446e71a` | ELF | 2026-09-24 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `6b138dd673640dc611a8b5883301e5b77e6564d43a8462264f50260f674a8ef4` | ELF | 2026-09-25 | trojan.mirai/abtrojan | `1[.]122[.]168[.]192`, `130[.]49[.]190[.]185`, `14[.]31[.]212[.]192`, `190[.]185[.]130[.]49`, `212[.]192[.]14[.]31`, `dvrs[.]botlesscucks[.]st` |
| `402b27b1676f6129d85a4c6d27f12b57a60af4ad8b35b1ef217438947806c22e` | Shell script | 2026-09-25 | downloader.bash/miraib | `217[.]60[.]103[.]135` |
| `5177a4a05f79a3164a9629c9bb7804050a64d6ddb2c1b1ed0716d8622247b4ed` | ELF | 2026-09-25 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `051a17b7019d9d9c0c8a236959d92aa83608d2e7e294c7211d9a4c09cb455a2d` | ELF | 2026-09-26 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `051fee03359d2a9d503adad576f89d8b97fd96a46e552023758269d14f591ec0` | ELF | 2026-09-26 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `522428fc37e143139abe0a6e17de326bdcd61a584db15ad3bd74ecce56c74675` | ELF | 2026-09-26 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `5290182e01b17bbc00c95df73749b91a716537c402aac65b4ca908cea8d45ce6` | ELF | 2026-09-26 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `5e788a7f8e9e4cbcc150a353848918a380a314eaad86ba78b74704ae090406c3` | ELF | 2026-09-26 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `5ecff0a7ad9d48b97487032014fd620ccf49a53f7a48a0fa6e0bdd1ef7787dd6` | Shell script | 2026-09-26 | trojan.sbadur/shell | `217[.]60[.]103[.]135` |
| `45db5310a177214d3a38ce54e6a3abd9da05ba456f925886cdab810b396dc528` | Android | 2026-10-01 | trojan.adbloader/ag1602320 | `217[.]60[.]103[.]135` |
| `4898d1f8e5e60450001a65c693b7e350869695193a3a50a3e71cc42654895b70` | Android | 2026-10-02 | trojan.adbloader/ag1539407 | `217[.]60[.]103[.]135` |
| `322eb146bac70314bc69438db23ec2fdbbd43a091e34baef566f1d4c3a19d50b` | ELF | 2026-10-06 | trojan.mirai/ddos | `217[.]60[.]103[.]135` |
| `39060de52929785f443861a57ba4da1ec96b67197c422922370a255c1c922561` | Shell script | 2026-10-07 | trojan.shell/abdownloader | `217[.]60[.]103[.]135` |

In-the-wild file names of the core builds: `arm7`, `arm5`, `sh4`, `x86_64.elf`, `nfs`, numeric names, and `/var/tmp/.cache/sysd`.

#### A11. Operator wallets (Ethereum, read-only lookups 2026-10-22)

| address | role | type |
|---|---|---|
| `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` | owns the sample's ENS names `2sexy4u[.]eth` and `sushiconsumer[.]eth` | externally-owned account (10 txs) |
| `0xd5e348763fef825c36ad60a4294567187cc9f995` | owns the siblings' ENS name `catswithhatslolksjhakf[.]eth` | smart contract (ERC-4337), active since 2025 |
| `0x868a97277edc8a8c5d9e6cdaddb28d8103031635` | throwaway relay that funded wallet `0x32ab9ef9…` on 2026-10-13 | externally-owned account (drained) |
| `0x6577669d78ac611870f74a50d94b6c17a9c293d0` | throwaway relay that funded wallet `0xd5e34876…` | externally-owned account |
| `0xb5d85cbf7cb3ee0d56b3bb207d5fc4b82f43f511` | Coinbase hot wallet; seeded the relay above on 2025-06-10 (KYC attribution lead) | exchange |
| `0x8715fff43f70f103428f96fd4c4432c5ee75044c` | funded relay `0x868a97…`; reused wallet, part of a shared OTC / cash-movement cluster (traced 2026-10-26) | externally-owned account (72 txs) |
| `0xd6468298Bb652b3C05bbce14eC2025Fc5f6a9276` | funder that fed the reused wallet `0x8715fff4…`; busy USDT to many parties (shared cash cluster) | externally-owned account |
| `0x51dBd97Fa14F4D78F8Afc2E92A692a9E087Efb5C` | upstream wallet (6.65 ETH) in the shared cluster; funded in by KuCoin | externally-owned account |
| `0x45300136662dD4e58fc0DF61E6290DFfD992B785` | KuCoin hot wallet; funded `0x51dBd97…` on 2026-10-25 (lead to confirm) | exchange |
| `0x16f59CEfA5A2828Fe9812D94444573fe87C5c8c9` | Binance deposit address; the reused wallet cashes out here 2026-10-12 (lead to confirm) | exchange deposit |
| `0x3f3Ee0a9cAC2d01DB44001eca3E8382fbe40207B` | ChangeNOW no-KYC swap deposit; funds `0xd6468298…` (deliberate break in the trail) | swap service |
| `0x59e16fccd424cc24e280be16e11bcd56fb0ce547` | third-party ENS registration contract used by both operator wallets | contract |
| `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` | ENS registry (public) | contract |
| `0xf29100983e058b709f3d539b0c765937b804ac15` | resolver all three operator names use (operator-specific) | contract |

#### A12. Related sample hashes

High-confidence siblings (same operator):

- `6f272c85365a1783eedbf7bc80112db52d13bca5415703df127b869b23bc179f` (x86-64, 2026-10-04)
- `b58cf55ad3e632086b1fa91989a38ea5266530eb0f52ee54eb81ad4edc49cc48` (x86-64, 2026-09-23)

Likely same operator (ARM):

- `5420b2745e8d8c347563d73c3945b50b12f7c21b38fbfefd0202779fe1fa98c1`
- `07b98716aa3f8991a377340cf55b335e8f7fc62425c3762fa11d53b91d427521`
- `8329ed49c67ab2a0f02b6c43ffda4aa2f3ff6a7599a2a9769aabb121cbcbfa87`
- `bc6854418c71d63e9209be6260fdc76517603fb9c1bdbcabb9858043207a418d`
- `9ae981175d5e8cf979faf9c4e3e13b3b8270c52a707b3ffc3e6f53b37ea091d2`
- `a2b38e3080c9a3c53dff1216cb8d8e8b773e10d95523f2ce518c2a41b2b124e3`

Builds surfaced by the 2026-10-22 retrohunt (not previously in our corpus):

- x86-64: `6b138dd673640dc611a8b5883301e5b77e6564d43a8462264f50260f674a8ef4`, `2d3af69a38b0bee1a059a0d4ce907f8bb2128f25a753fff0f84f48ddcb9592c6`, `c1351f990db3f775e6774194a457081a9f8cea3e57d6d182767fd86551a82c39`, `7f436c109405ec81a44f52d33f2ba3276c797238729dad09f299a84147fbc8d5`, `b85897f6378ff42ec4934f574c8ca447d2c37fe58d0ab7f877fdf48e0522ec6f`, `3a032308c72fe33ddd89f03d9f64e2c56cad5fb0dc6ed8e3d3c6eb684108b629`
- ARM / SuperH / x86: `3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc`, `c475cf4e7877b792544783d3edeb028882df09ee5363ab7f90ce11e14c41cb26`, `e36e40cfdd57ce91c7d349f42b0e7768aa233337166c15e7f215d081df9c0ba9`, `b200ab6d281055e113fe82fbd7d4fef86183221a4a68c6154ab8ca6fc08c34fb`, `44a6090b72ff9094a862f13a14ff333fcf19b41eb58af9c0bd54f23834c175fa`, `7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9`, `10c7853e6dc953e6b805cef03a7324caf6c87e68117a7c3175feb463c5c9c0e0`, `01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a`, `6a1cefffb07c9a6d58f42f1ed686e4ff7de0f70196d6fef76f424f219e36a315`, `3f50a7629d8d324e7a614cf89881822b89bb37d26fe0852e7ebf5173b5340d29`, `2b32143e21c0b2ceed37f1100d3a3d42379c48c6d4163f31e25aa524bea34a14`, `b78ae1663194190fb8c92cf1f436ad892c08d51fdbe8cccdaa12e539988e731a`, `5997a6f80b25f550c5e7617bceac4477c580057846f8061e7165d1fbfa89f30a`, `73308b7c5982e99b90075f4d48583c00bb984f1765bc6bd5a01ff3b1bbdd5f51`, `f54f5cec97c24c3eb24f095be8c464b87f4dfc37c0d2f9507b020b24dcf28dd9`, `c65bca6729f694f1b0c806c30c76c54a70e3d32c8981bbe0f62428028b78db6d`, `e2529d4afa39ae4db2eb05d5176317c906289abf09660c75bdeec43e54c55aa3`
