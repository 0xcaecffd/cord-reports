---
title: From a PHP flaw to a global botnet: PHP2Shell and the potassium Mirai lineage
date: 2026-10-27
summary: Executive debrief. A critical PHP session flaw exploited within hours of its patch, the encrypted Mirai-derived DDoS bot pushed through it, and the operator behind it, down to decoy DNS, a blockchain C2 fallback and a money trail that reaches named exchanges.
tlp: CLEAR
tags: php, mirai, ddos, linux, blockchain
---

<div class="cards">
<div class="card"><div class="k">Detection at discovery</div><div class="v">4 / ~65</div></div>
<div class="card"><div class="k">Related builds found</div><div class="v">36+</div></div>
<div class="card"><div class="k">Real C2 servers recovered</div><div class="v">9</div></div>
<div class="card"><div class="k">YARA false positives on clean software</div><div class="v">0</div></div>
</div>

This is one connected story in three acts. First, a pair of critical PHP flaws that
early reporting called hard to exploit, which our lab showed to be exploitable on
default installations. Second, the malware attackers pushed through that hole within
hours of disclosure, which we caught in the wild. Third, the crew behind it: their
tools, their infrastructure, and a money trail on the blockchain that runs back to
named exchanges.

The full indicator list is in the [appendix](#appendix-indicators) and in
[iocs.csv](iocs.csv). We name no individuals. Attribution is to a group, defined by its
code, its infrastructure and its wallets.

<div class="callout bad" markdown="1">

**Patch now.** PHP 8.3.36 and later fix CVE-2026-109618 and CVE-2026-109619. If you run
PHP with sessions enabled and cannot patch today, see
[Detect the exploitation](#detect-the-exploitation).

</div>

## Act I: the exploit (PHP2Shell)

### What the flaw is

CVE-2026-109618 and CVE-2026-109619 are use-after-free bugs in PHP's session
upload-progress handling. When a request runs out of memory while PHP is still parsing
it, PHP abandons the request without the normal clean-up and leaves stale pointers in
its memory allocator. A follow-up request to the same worker then reads that corrupted
memory before any application code runs. Both were patched in PHP 8.3.36 while already
being exploited in the wild.

### Why "hard to exploit" was wrong

Early public reporting said exploitation needed an unusually low memory limit
(`memory_limit=8M`). Our lab reproduction showed that is not true. A stock installation
with the default 128 MB limit can be driven out of memory by a request of a few hundred
kilobytes, well inside the default upload size, because of how PHP builds its internal
upload metadata. The attack traffic looks like ordinary form data, not a large or
unusual payload.

Results from default Docker images:

| Build | Result |
|---|---|
| PHP 8.3.35 (vulnerable) | Worker crashes in 14 of 15 test rounds, with the crash inside PHP's allocator |
| PHP 8.3.36 (patched) | 0 crashes in 261 runs of identical traffic |

Follow-on lab work turned the crash into working remote code execution as the web
server user on unpatched builds, with unauthenticated HTTP access only. We are not
publishing the exploitation details.

During the same work we identified a further, separate PHP session issue. It is in
coordinated disclosure and is not described here.

### What this means for defenders

- Treat any PHP 8.x below 8.3.36 that uses sessions as remotely exploitable, whatever
  its memory settings.
- Detection that looks for an oversized upload misses this attack. Look for the
  behaviour instead (see [What to do](#what-to-do-about-it)).

## Act II: the payload we caught in the wild

Within hours of the patch, attackers were using this flaw to plant a second-stage bot.
We obtained the sample. It turned out to be far more than a run-of-the-mill Mirai copy
(Mirai being the widely copied botnet code that most Linux DDoS malware descends from).

**What it is.** A Linux DDoS bot: software that turns a compromised server into a
foot soldier for knocking other sites offline. It does not spread on its own. It is
placed onto servers through the PHP2Shell exploit. It is the newest build of a family
that Nokia Deepfield documented in May 2026 under the name **potassium**, and the same
binary the research firm ELLIO identified on 2026-10-22 as the PHP2Shell second stage,
seen in the wild the day before.

| Field | Value |
|---|---|
| SHA-256 | `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` |
| MD5 | `b61a098fc62a2c2696e196dca78da71a` |
| File | ELF64 x86-64, statically linked, stripped, 179,632 bytes |
| Detection at discovery | 4 of about 65 engines, heuristic only |
| Delivered via | Loader fetched from `hxxp://92.118.112[.]100/nfs`, run as `./nfs php`; loader source `45.198.224[.]169` |

**Why it stands out.** Ordinary Mirai copies leave their settings and tell-tale text in
plain sight. This one encrypts everything: a 476-slot string table locked under
ChaCha20, with even the cipher's own constant masked. Its link back to the operators
uses modern cryptography (X25519 key exchange, ChaCha20-Poly1305). It can open a remote
shell, hide its own process and update itself. It lies about where its control server
is (see Act III). And the scanner classic Mirai uses to spread on its own has been
removed: this build is placed deliberately by a loader rather than spreading like a
worm.

### The wider family and our confidence

This sample is one build off a production line. We scored every related file in the
CORD corpus and ran four detection rules back across a year of global malware
submissions. Ranked by how sure we are:

- **Same operator, high confidence.** Two x86-64 sibling builds, `6f272c85365a…`
  (2026-10-04) and `b58cf55ad3e6…` (2026-09-23), carry the same encrypted blockchain
  settings and overlapping control-server lists once decrypted. This sample and
  `6f272c85365a…` share two control-server hosts outright. Both build lines registered
  their blockchain names through the same service and point at the same
  operator-specific resolver.
- **Same operator, likely.** Six ARM builds from September and October 2026. One of
  them (`5420b2745e8d…`) was seen reaching the same control server as our sample.
- **Same toolkit, operator unproven.** Three un-stripped "developer" builds that
  shipped with their source-file names intact, plus two older ARM builds.
- **Fresh finds (2026-10-22).** Our retrohunt surfaced 23 more in-the-wild builds:
  six x86-64 and seventeen ARM, SuperH and x86, including versions bundled inside
  Android app packages. Our four rules flagged all of them with no false alarms on
  clean software.

This is an actively maintained, multi-platform family, from Linux servers to Android
devices.

## Act III: the operator

The crew is careful, but careful people are consistent, and consistency makes a pattern.

### Their infrastructure

They rotate their control-server domains on a schedule: a new `.st` domain every few
weeks (with one two-month gap over the summer), bought through two small resellers,
each dressed up with a legitimate-looking web page, with the real control servers on
short subdomains. Their hosting spans Estonia, France, Switzerland, Russia, Armenia and
DigitalOcean. New infrastructure typically goes live about a week before a new build
ships.

### The sleight of hand: decoy DNS

When the bot looks up its control domain, it never connects to the address it gets
back. It scrambles that address first. Older builds swap the two halves. This build
keeps the first number and rotates the rest. The addresses anyone can see in DNS point
at university, military and ordinary consumer networks: innocent bystanders.
**Blocking the published address does nothing, and would hurt the wrong people.** We
reversed the scramble and recovered the real servers, including the live one at
`134.199.154[.]64` (DigitalOcean), plus eight more behind the group's other hosts.

### A C2 fallback on the blockchain

The configuration holds a backup plan. If the domains are ever taken down, the bot can
look up its control-server address on the **Ethereum blockchain** instead, a public
ledger that no registrar or hosting provider can switch off. It reads a text record
labelled `ip` from three ENS names: `2sexy4u[.]eth` and `sushiconsumer[.]eth` (this
sample) and `catswithhatslolksjhakf[.]eth` (the siblings), through the public ENS
registry and one operator-specific resolver
(`0xf29100983e058b709f3d539b0c765937b804ac15`). This build does not use it yet: the
feature is built but not switched on. The values parked there appear to be scrambled
with the same decoy trick. Unwinding three of the October values with this build's
scramble lands them in the same DigitalOcean range as the live server.

### Following the money

Because the blockchain is public, we could read who owns those names and who paid for
them. This is the strongest thread in the investigation.

- **Two wallets, one playbook.** The sample's two names sit in one wallet
  (`0x32ab9ef9…da7b`). The siblings' name sits in a second (`0xd5e34876…f995`). Both
  registered through the same service and point at the same resolver: an on-chain tie
  between the two build lines, on top of the control-server hosts they share in code.
- **The second wallet is a smart contract**, an account-abstraction setup that keeps
  the controlling key off the public ledger. It has been active since 2025, so it was
  held in reserve rather than created for this campaign.
- **Both wallets were funded through throwaway relay wallets**, used once and
  discarded to break the trail. No mixer was used. The one anonymity step is a single
  no-KYC swap (ChangeNOW) on one branch, so the trail is bent, not cut.
- **Both branches reach exchanges that know their customers.** The relay that seeded
  the smart-contract wallet was funded on 2025-06-10 by a **Coinbase** hot wallet
  (`0xb5d85cbf…`). Coinbase verifies its account holders, so that withdrawal ties to an
  account the exchange can identify under legal process.
- **The other branch** runs through a busy shared cash-movement service. Money enters
  it from a **KuCoin** wallet (`0x45300136…`) and leaves to a **Binance** deposit
  address (`0x16f59CEf…`), with one detour through **ChangeNOW** (`0x3f3Ee0a9…`).
  Because the service moves money for many unrelated people, KuCoin and Binance here are
  leads to confirm, not proof.

Every branch ends either at an exchange that keeps customer records or at the no-KYC
swap. Naming anyone from here means legal process at those exchanges. Attribution stays
with the operator group.

### What their tradecraft tells us

They are competent and deliberate: encrypted builds, rotating infrastructure, decoy
addressing, disposable funding wallets, a blockchain fallback waiting in the wings, and
wallet keys kept off the public record. The discipline is uneven, though. Developer
builds slipped out with their internal file names, and the money trail touches a named
exchange. Two soft signals, held loosely, point toward a European operator: their
blockchain activity clusters between 06:00 and 14:00 UTC, and Deepfield observed
Dutch-language content in an earlier campaign.

## What to do about it

### Detect the exploitation

- Upgrade to PHP 8.3.36 or later.
- Alert on bursts of `multipart/form-data` POSTs carrying `PHP_SESSION_UPLOAD_PROGRESS`
  to pages that do not accept uploads.
- Alert on PHP workers that run out of memory and crash (SIGSEGV) in bursts.
- Alert on any web-server worker that starts a shell and then downloads a file.

### Detect the malware

Four YARA rules cover the family across architectures with no hits on clean software
(16,686 ELF samples, 4,699 Linux system binaries and 1,542 Windows files tested):

| Rule | Scope |
|---|---|
| [`elf_mirai_ext_x64_build_family`](rules/elf_mirai_ext_x64_build_family.yar) | x86-64 builds from this code generator (tight) |
| [`elf_mirai_ext_x64_chacha_lineage`](rules/elf_mirai_ext_x64_chacha_lineage.yar) | x86-64 builds with the lineage's ChaCha20 routine |
| [`elf_mirai_ext_multiarch_literals`](rules/elf_mirai_ext_multiarch_literals.yar) | Any architecture, by literal-pool constants |
| [`elf_masked_chacha_constant_survey`](rules/elf_masked_chacha_constant_survey.yar) | Wide survey rule for triage |

All four in one file: [potassium-all.yar](rules/potassium-all.yar).

### Block and hunt the infrastructure

- Block the **real, recovered** control servers in the appendix, never the published
  DNS answers, which belong to bystanders.
- On Linux hosts, look for a loopback listener on TCP port 1234, a hidden directory at
  `/var/tmp/.cache/sysd`, files at `/tmp/.manta` or `/tmp/.xwiki`, and a process whose
  `/proc` entry is masked by another.
- Watch the three ENS names for record changes (a read-only query), watch for new `.st`
  domains from the same two resellers, and pivot on the relay wallets.

## Appendix: indicators

Collected 2026-10-22 from the decrypted string store of the sample, the decoded stores of
the two x86-64 siblings, VirusTotal relationships and passive DNS, and read-only Ethereum
lookups, with the money trail extended on 2026-10-26. Hosts, IPs and URLs are defanged.
Published DNS answers of the C2 hosts are decoys that point at bystanders and are left
out on purpose.

### A1. The sample

| hash | value |
|---|---|
| md5 | `b61a098fc62a2c2696e196dca78da71a` |
| sha1 | `c472dab4ff7c16782a8037f988d4daa6d4bdb343` |
| sha256 | `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` |
| size | 179632 bytes |


### A2. Hostnames in the sample's string store

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


### A4. Ethereum mainnet state of the ENS names (read-only lookups, 2026-10-22)

ENS registry `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`; selectors `resolver(bytes32)` = `0x0178b8bf`, `text(bytes32,string)` = `0x59d1d43c`; text key `ip`.

| name | carried by | namehash | resolver (equals store) | owner (registry) | expiry | text `ip` | `addr` record |
|---|---|---|---|---|---|---|---|
| `2sexy4u[.]eth` | sample | `0x21372c2e8f485fe1666dc12be5709f2e63214a4b79f076daa287a959e4c2d514` | `0xf29100983e058b709f3d539b0c765937b804ac15` (yes) | `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` | 2030-10-13 | `143[.]220[.]202[.]110` | `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` |
| `catswithhatslolksjhakf[.]eth` | x86-64 siblings | `0x022d83e68fb35299866ff21bbff6c7aaf73092c07a5c14448363005f12832024` | `0xf29100983e058b709f3d539b0c765937b804ac15` (yes) | `0xd5e348763fef825c36ad60a4294567187cc9f995` | 2027-09-10 | `49[.]6[.]172[.]233` | `0xd5e348763fef825c36ad60a4294567187cc9f995` |
| `sushiconsumer[.]eth` | sample | `0x46e5a3d52c2bd76e560a74cf4c104f7e219daa40586021854bd404d65d5ad6de` | `0xf29100983e058b709f3d539b0c765937b804ac15` (yes) | `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` | 2029-10-13 | `(absent)` | `0x32ab9ef9123a495ee7e68c3c18de94c401e8da7b` |

Record history (Blockscout log API, read once on 2026-10-22; the values of the superseded records were not retained and a re-read was rate-limited): the first name has `NewResolver` events on 2022-05-24 and 2026-10-13 and eleven `TextChanged` events with keys `ip`, `ip1`, `ip2`, `ip4`, `readme`, of which four `ip` changes within hours on 2026-10-14 over three distinct values; the second name has one `NewResolver` on 2026-09-10 and one `ip` set on 2026-09-11; the third has one `NewResolver` on 2026-10-13 and no text record.

Public RPC endpoints in the store (the bot would use these; they are legitimate providers and not blockable indicators): `ethereum.publicnode.com`, `ethereum-rpc.publicnode.com`, `eth.drpc.org`, `1rpc.io`, `eth-mainnet.blockreq.com`, `ethereum-public.nodies.app`, `rpc.mevblocker.io`.


### A5. Ports, process names, paths, resolvers

- C2 ports (random pick from 14): `50217, 50341, 50488, 50613, 50792, 50904, 51127, 51289, 51456, 51603, 51871, 52134, 52398, 52645`
- loopback single-instance lock: TCP `1234` (retry counter 0x1a); stock Mirai uses 48101
- process names adopted after daemonising (prctl and argv[0]): `telnetd`, `udhcpc`, `upnpd`, `watchdog`, `syslogd`, `klogd`, `uhttpd`, `uchttpd`
- potassium markers in the store: `Segmentation fault (core dumped)`, `big brother is watching`, `dvrInside`, `dvrLocker`, `im in the matrix`
- shell paths: `/apex/com.android.runtime/bin/sh`, `/data/local/tmp/sh`, `/sbin/sh`, `/system/bin/sh`, `/usr/bin/sh`, `/vendor/bin/sh`
- watchdog devices: `/dev/misc/watchdog`, `/dev/watchdog`
- on-disk install path seen in VirusTotal in-the-wild names of core builds: `/var/tmp/.cache/sysd`
- additional drop paths seen in retrohunt matches (2026-10-22): `/tmp/.manta`, `/tmp/.xwiki`
- embedded DNS resolvers (18, used for the bot's own lookups; legitimate public resolvers): `8[.]8[.]8[.]8`, `8[.]8[.]4[.]4`, `1[.]1[.]1[.]1`, `1[.]0[.]0[.]1`, `208[.]67[.]222[.]222`, `208[.]67[.]220[.]220`, `9[.]9[.]9[.]9`, `149[.]112[.]112[.]112`, `94[.]140[.]14[.]14`, `94[.]140[.]15[.]15`, `114[.]114[.]114[.]114`, `114[.]114[.]115[.]115`, `223[.]5[.]5[.]5`, `223[.]6[.]6[.]6`, `119[.]29[.]29[.]29`, `180[.]76[.]76[.]76`, `64[.]6[.]64[.]6`, `64[.]6[.]65[.]6`


### A6. Domains

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


### A7. Real C2 and hosting addresses

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
| `49[.]6[.]172[.]233` | not announced | | ENS `ip` record value of `catswithhatslolksjhakf[.]eth` | current on-chain value; no sample seen contacting it |

Published by ELLIO (2026-10-22) for the same sample: C2 address `134[.]199[.]154[.]64` (DigitalOcean, reached through the rotation from the decoy `134[.]154[.]64[.]199`), update host `117[.]55[.]202[.]115`, staging host `92[.]118[.]112[.]100` (AS215540) serving `hxxp://92[.]118[.]112[.]100/nfs`, loader source `45[.]198[.]224[.]169`. Of these, the C2 address appears among the contacted addresses of our relatives and the update host is the EE address above.


### A9. URLs

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
| `hxxp://dvrs[.]botlesscucks[.]st/` | URL under botlesscucks.st; URL under dvrs.botlesscucks.st |
| `hxxp://fsocietyhackattack[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxp://gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st |
| `hxxp://godofthunder[.]st/` | URL under godofthunder.st |
| `hxxp://hackattackkaboom[.]botlesscucks[.]st/` | URL under hackattackkaboom.botlesscucks.st |
| `hxxp://hackattackkaboom[.]botlesscucks[.]st/arm7` | URL under hackattackkaboom.botlesscucks.st |
| `hxxp://hackattackkaboom[.]botlesscucks[.]st/x86_64` | URL under hackattackkaboom.botlesscucks.st |
| `hxxp://hik[.]gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st; URL under hik.gettingheadfromduckysmom.st |
| `hxxp://ijustgetsonervy[.]potassium[.]st/` | URL under ijustgetsonervy.potassium.st; URL under potassium.st |
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
| `hxxp://thunder[.]godofthunder[.]st/` | URL under godofthunder.st; URL under thunder.godofthunder.st |
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
| `hxxps://dvrs[.]botlesscucks[.]st/` | URL under dvrs.botlesscucks.st |
| `hxxps://fsocietyhackattack[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st |
| `hxxps://hackattackkaboom[.]botlesscucks[.]st/` | URL under botlesscucks.st; URL under hackattackkaboom.botlesscucks.st |
| `hxxps://hik[.]gettingheadfromduckysmom[.]st/` | URL under gettingheadfromduckysmom.st; URL under hik.gettingheadfromduckysmom.st |
| `hxxps://ijustgetsonervy[.]potassium[.]st/` | URL under ijustgetsonervy.potassium.st; URL under potassium.st |
| `hxxps://ijustgetsonervy1[.]potassium[.]st/` | URL under potassium.st |
| `hxxps://iloveboats[.]st/` | URL under iloveboats.st |
| `hxxps://musika[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://potassium[.]st/` | URL under potassium.st |
| `hxxps://smart[.]abuse[.]st/` | URL under abuse.st |
| `hxxps://stoplooking[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://stoplooking2[.]botlesscucks[.]st/` | URL under botlesscucks.st |
| `hxxps://thunder[.]godofthunder[.]st/` | URL under godofthunder.st; URL under thunder.godofthunder.st |
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


### A10. Execution parents and files tied to the infrastructure

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

The 79 further files that communicate with the group's domains or hosting are listed in [iocs.csv](iocs.csv).

### A11. Operator wallets (Ethereum, read-only lookups 2026-10-22)

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


### A12. Related sample hashes

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

Builds surfaced by the 2026-10-22 retrohunt (not previously in the CORD corpus):

- x86-64: `6b138dd673640dc611a8b5883301e5b77e6564d43a8462264f50260f674a8ef4`, `2d3af69a38b0bee1a059a0d4ce907f8bb2128f25a753fff0f84f48ddcb9592c6`, `c1351f990db3f775e6774194a457081a9f8cea3e57d6d182767fd86551a82c39`, `7f436c109405ec81a44f52d33f2ba3276c797238729dad09f299a84147fbc8d5`, `b85897f6378ff42ec4934f574c8ca447d2c37fe58d0ab7f877fdf48e0522ec6f`, `3a032308c72fe33ddd89f03d9f64e2c56cad5fb0dc6ed8e3d3c6eb684108b629`
- ARM / SuperH / x86: `3461b097ea026c9161113f0f590e75c47908cebd3d6a30de3b821c10a85ea9fc`, `c475cf4e7877b792544783d3edeb028882df09ee5363ab7f90ce11e14c41cb26`, `e36e40cfdd57ce91c7d349f42b0e7768aa233337166c15e7f215d081df9c0ba9`, `b200ab6d281055e113fe82fbd7d4fef86183221a4a68c6154ab8ca6fc08c34fb`, `44a6090b72ff9094a862f13a14ff333fcf19b41eb58af9c0bd54f23834c175fa`, `7fc40677a79d0cbc675d8c0042d6cfbc87ca1a9982f5046008feb7bd4fe799b9`, `10c7853e6dc953e6b805cef03a7324caf6c87e68117a7c3175feb463c5c9c0e0`, `01c70849ed30aa1cc4e08cb7529b62c2e3a9044ad0ab000ad84a343444a8dd5a`, `6a1cefffb07c9a6d58f42f1ed686e4ff7de0f70196d6fef76f424f219e36a315`, `3f50a7629d8d324e7a614cf89881822b89bb37d26fe0852e7ebf5173b5340d29`, `2b32143e21c0b2ceed37f1100d3a3d42379c48c6d4163f31e25aa524bea34a14`, `b78ae1663194190fb8c92cf1f436ad892c08d51fdbe8cccdaa12e539988e731a`, `5997a6f80b25f550c5e7617bceac4477c580057846f8061e7165d1fbfa89f30a`, `73308b7c5982e99b90075f4d48583c00bb984f1765bc6bd5a01ff3b1bbdd5f51`, `f54f5cec97c24c3eb24f095be8c464b87f4dfc37c0d2f9507b020b24dcf28dd9`, `c65bca6729f694f1b0c806c30c76c54a70e3d32c8981bbe0f62428028b78db6d`, `e2529d4afa39ae4db2eb05d5176317c906289abf09660c75bdeec43e54c55aa3`

