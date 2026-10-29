"""Public full version of the potassium executive debrief.

Keeps the internal DEBRIEF-EXEC.md text whole, with three changes: the title and date
move into front matter and the act headings become h2; hostnames, IPs and URLs in code
spans are defanged (hashes, wallets, paths and ports are left as they are); and the
mechanism of the still-unpatched serializer-mismatch chain (CVE-2026-115560) is replaced
by a note, because publishing it would describe a working exploit for an open bug.

usage: python tools/debrief_full.py <DEBRIEF-EXEC.md> <out content md> <out iocs.csv>
"""
import re
import subprocess
import sys

src, out_md, out_csv = sys.argv[1:4]
text = open(src, encoding="utf-8").read()

HOST = re.compile(r"^(?:[a-z0-9-]+\.)+(?:st|eth|com|org|io|app|net|ru|at|shop)(?::\d+)?$", re.I)
IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PUBLIC_RPC = {"ethereum.publicnode.com", "ethereum-rpc.publicnode.com", "eth.drpc.org", "1rpc.io",
              "eth-mainnet.blockreq.com", "ethereum-public.nodies.app", "rpc.mevblocker.io"}


def defang(v: str) -> str:
    if v.startswith(("http://", "https://")):
        return v.replace("http", "hxxp", 1).replace(".", "[.]")
    if (HOST.match(v) and v not in PUBLIC_RPC) or IP.match(v):
        return v.replace(".", "[.]")
    return v


body = text.split("\n", 1)[1]                      # drop the H1
body = re.sub(r"^\*\*Threat briefing[^\n]*\n", "", body.lstrip(), flags=re.M)
body = re.sub(r"(?m)^(#{1,5}) ", r"#\1 ", body)      # every heading one level down
body = re.sub(r"\n---\n\n---\n", "\n", body)

unpatched = re.compile(r"\*\*Serializer-mismatch chain \(1\), CVE-2026-115560.*?(?=\nAll four chains)", re.S)
if not unpatched.search(body):
    sys.exit("unpatched-chain paragraph not found; refusing to publish without removing it")
body = unpatched.sub(
    "**Fourth chain (1), CVE-2026-115560, unpatched as of October 2026.** A separate "
    "issue that also needs an application framework to reach code execution; stock PHP "
    "alone is not affected. Its details are withheld from this public copy until a fix "
    "ships.\n", body)
for leak in ("pipe character", "parse boundary", "3.5 KB", "parsers disagree", "Serializer-mismatch",
             "serializer mismatch", "Session-serializer"):
    if leak in body:
        sys.exit(f"unpatched-chain detail still present ({leak!r}); refusing to write")

# Lab notes from PHP2SHELL-DEBRIEF.md (same folder): the detection rebuild figures and the
# controlled-reclaim technique behind the patched unserialize chain. Both concern only the
# patched CVEs. The notes predate the working chains, so their "no exploit yet" is dropped.
notes_src = src.replace("DEBRIEF-EXEC.md", "PHP2SHELL-DEBRIEF.md")
notes = open(notes_src, encoding="utf-8").read()
reclaim = notes.split("## Toward actual code execution", 1)[1].split("\n", 1)[1].strip()
reclaim = reclaim.replace(" (we do not have one yet)", "")
lab = ("### Lab notes: from crash to controlled reclaim (patched CVEs)\n\n"
       "These notes, written on 2026-10-22 before the chains above were finished, show the "
       "step that turned the crash into a usable primitive for CVE-2026-109618.\n\n"
       + reclaim + "\n\n"
       "**Detection rebuild.** Against the working attack, only one of our fifteen original "
       "detection rules fired. We rebuilt and engine-validated the suite against the crashing "
       "traffic: 28 Suricata rules and 8 Sigma rules that correlate the two-request sequence, "
       "with no false positives in testing.\n\n")
if "## Act II" not in body:
    sys.exit("Act II heading not found")
body = body.replace("## Act II", lab + "## Act II", 1)

body = re.sub(r"`([^`]+)`", lambda m: "`%s`" % defang(m.group(1)), body)

front = """---
title: From a PHP flaw to a global botnet: PHP2Shell and the potassium Mirai lineage
date: 2026-10-27
updated: 2026-10-29 (full technical edition)
summary: Executive debrief, full technical edition. Two critical PHP session flaws turned into remote code execution on default installs, the encrypted Mirai-derived DDoS bot pushed through them within hours, and the operator behind it, down to decoy DNS, an Ethereum C2 fallback and a money trail to named exchanges.
tlp: CLEAR
tags: php, mirai, ddos, linux, blockchain
---

<div class="cards">
<div class="card"><div class="k">RCE chains demonstrated</div><div class="v">4</div></div>
<div class="card"><div class="k">Detection at discovery</div><div class="v">4 / ~65</div></div>
<div class="card"><div class="k">Related builds found</div><div class="v">36+</div></div>
<div class="card"><div class="k">Real C2 servers recovered</div><div class="v">9</div></div>
<div class="card"><div class="k">YARA false positives on clean software</div><div class="v">0</div></div>
</div>

<div class="callout bad" markdown="1">

**Patch now.** PHP 8.3.36 and later fix CVE-2026-109618 and CVE-2026-109619. A further
issue, CVE-2026-115560, is unpatched; its mechanism is withheld here. Indicators below are
defanged; machine-readable lists are in [iocs.csv](iocs.csv), and the YARA rules are in
[rules/](rules/potassium-all.yar).

</div>

"""
open(out_md, "w", encoding="utf-8").write(front + body)
print("wrote", out_md, len(body), "chars")
subprocess.run([sys.executable, "tools/debrief_appendix.py", src, "NUL" if sys.platform == "win32" else "/dev/null", out_csv], check=True)
