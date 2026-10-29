"""Public appendix for the potassium executive debrief.

Reads the internal DEBRIEF-EXEC.md appendix and writes a defanged Markdown appendix and a
machine-readable iocs.csv. Changes from the internal copy: hostnames, IPs and URLs are
defanged; A3 (resolution recipe) and A8 (bystander decoy answers) are dropped; A7 keeps
only the real C2 and contacted-hosting rows, not the passive-DNS answers that may be
bystanders; A10's 79-file table goes to the CSV only.

usage: python tools/debrief_appendix.py <DEBRIEF-EXEC.md> <out appendix.md> <out iocs.csv>
"""
import csv
import re
import sys

src, out_md, out_csv = sys.argv[1:4]
text = open(src, encoding="utf-8").read()
appendix = text[text.index("### A1."):]

HOST = re.compile(r"^(?:[a-z0-9-]+\.)+(?:st|eth|com|org|io|app|net|ru|at|shop)$", re.I)
IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PUBLIC_RPC = {"ethereum.publicnode.com", "ethereum-rpc.publicnode.com", "eth.drpc.org", "1rpc.io",
              "eth-mainnet.blockreq.com", "ethereum-public.nodies.app", "rpc.mevblocker.io"}


def defang(v: str) -> str:
    if v.startswith(("http://", "https://")):
        return v.replace("http", "hxxp", 1).replace(".", "[.]")
    if (HOST.match(v) and v not in PUBLIC_RPC) or IP.match(v):
        return v.replace(".", "[.]")
    return v


def defang_code(line: str) -> str:
    return re.sub(r"`([^`]+)`", lambda m: "`%s`" % defang(m.group(1)), line)


sections = re.split(r"(?m)^(?=### A\d+\.)", appendix)
md, rows = [], []
for sec in sections:
    if not sec.strip():
        continue
    head = sec.splitlines()[0]
    num = int(re.match(r"### A(\d+)\.", head).group(1))
    if num in (3, 8):
        continue
    lines = sec.splitlines()
    if num == 7:
        lines = [l for l in lines if not l.startswith("| `") or
                 ("real C2" in l or "contacted by 2+" in l or "ENS `ip`" in l)]
    if num == 10:
        cut = next(i for i, l in enumerate(lines) if l.startswith("Files not in the corpus"))
        for l in lines[cut:]:
            m = re.match(r"\| `([0-9a-f]{64})` \| ([^|]+) \| ([^|]+) \| ([^|]+) \| (.+) \|$", l)
            if m:
                rows.append(["sha256", m.group(1), "file tied to the group's infrastructure",
                             m.group(2).strip(), "via " + re.sub(r"`", "", m.group(5)).strip()])
        lines = lines[:cut] + ["The 79 further files that communicate with the group's domains or "
                               "hosting are listed in [iocs.csv](iocs.csv)."]
    lines = [l.replace("our corpus", "the CORD corpus") for l in lines]
    md.append("\n".join(defang_code(l) for l in lines))

    # CSV rows from code spans in table rows
    for l in lines:
        if not l.startswith("| `"):
            continue
        cells = [c.strip() for c in l.strip("|").split("|")]
        val = cells[0].strip("`")
        kind = ("sha256" if re.fullmatch(r"[0-9a-f]{64}", val) else
                "wallet" if val.lower().startswith("0x") else
                "url" if val.startswith("http") else
                "ip" if IP.match(val) else
                "domain" if HOST.match(val) else None)
        if kind and val not in PUBLIC_RPC:
            rows.append([kind, val, cells[-2] if len(cells) > 2 else "", "", " | ".join(cells[1:])])
    for h in re.findall(r"`([0-9a-f]{64})`", sec if num == 12 else ""):
        rows.append(["sha256", h, "related build", "", head.split(". ", 1)[1]])

open(out_md, "w", encoding="utf-8").write("\n\n".join(md) + "\n")
seen = set()
with open(out_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["type", "value", "role", "file_type", "notes"])
    for r in rows:
        if (r[0], r[1]) in seen:
            continue
        seen.add((r[0], r[1]))
        w.writerow(r)
print(f"appendix sections {len(md)}, csv rows {len(seen)}")
