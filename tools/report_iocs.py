"""Write iocs.csv and iocs.json for a report from the tables under its "## Indicators" heading.

Values are re-fanged (hxxp -> http, [.] -> .) so the lists import cleanly into tooling; the
page itself keeps them defanged. The section heading above each table becomes the category.

usage: python tools/report_iocs.py content/<slug>.md reports/<slug>/
"""
import csv
import json
import re
import sys
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
text = src.read_text(encoding="utf-8")
section = text.split("\n## Indicators", 1)[1].split("\n## ", 1)[0]


def refang(v: str) -> str:
    return v.replace("hxxp", "http").replace("[.]", ".")


def kind(v: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", v):
        return "sha256"
    if v.startswith("http"):
        return "url"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
        return "ip"
    if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", v, re.I):
        return "domain"
    return "other"


rows, category = [], ""
for line in section.splitlines():
    if line.startswith("### "):
        category = line[4:].strip()
        continue
    if not line.startswith("| ") or line.startswith("| Indicator") or line.startswith("| SHA-256 |") \
            or line.startswith("| Type |") or set(line) <= set("|- "):
        continue
    cells = [c.strip() for c in line.strip("|").split("|")]
    if category == "Other":
        label, val = cells[0], refang(cells[1].replace("`", ""))
        rows.append({"type": label.lower(), "value": val, "role": label, "category": category})
        continue
    m = re.match(r"`([^`]+)`", cells[0])
    if not m:
        continue
    val = refang(m.group(1))
    rows.append({"type": kind(val), "value": val, "role": " / ".join(cells[1:]), "category": category})

out.mkdir(parents=True, exist_ok=True)
with open(out / "iocs.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["type", "value", "role", "category"])
    w.writeheader()
    w.writerows(rows)
(out / "iocs.json").write_text(json.dumps({"report": src.stem, "indicators": rows}, indent=1),
                               encoding="utf-8")
print(len(rows), "indicators")
