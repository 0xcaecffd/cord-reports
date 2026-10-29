"""Turn a CORD Research report.md into a public technical companion page.

Fills each `see out/<layer>/ioc_candidates/<id>.txt` reference with the defanged value
given on the command line, drops the internal "Produced with" section (skill hashes,
corpus snapshot), and adds front matter with `hidden: true` so the page stays off the
index and is linked from its parent report.

usage: python tools/research_page.py <report.md> <out.md> <title> <summary> <parent slug> \
           L0/c0009=<value> L2/c0001=<value> ...
"""
import re
import sys

src, out, title, summary, parent = sys.argv[1:6]
values = dict(a.split("=", 1) for a in sys.argv[6:])
text = open(src, encoding="utf-8").read()


def fill(m):
    key = f"{m.group(1)}/{m.group(2)}"
    if key not in values:
        sys.exit(f"no value given for {key}")
    return f"`{values[key]}`"


text = re.sub(r"see `out/(L\d+)/ioc_candidates/(c\d+)\.txt`", fill, text)
text = re.sub(r"\n## Produced with\n.*", "\n", text, flags=re.S)
text = text.split("\n", 1)[1]                          # drop "# CORD Research report …"
if re.search(r"see `out/", text):
    sys.exit("an IOC file reference is still unfilled")
if re.search(r"/srv/|scratch|wrex|10\.73\.", text):
    sys.exit("an internal path is present")

front = f"""---
title: {title}
date: 2026-10-29
summary: {summary}
tlp: CLEAR
tags: technical analysis, CORD Research
hidden: true
---

<div class="callout" markdown="1">

Technical companion to [the main report](../{parent}/index.html). This is the CORD Research
pipeline's full static analysis of one representative sample, published as produced:
questions, narrative, layers, behaviours, IOCs, detection anchors, reachability, unknowns,
functions and evidence. Nothing was executed. Evidence hashes are SHA-256 prefixes of the
exact bytes each claim rests on.

</div>
"""
open(out, "w", encoding="utf-8").write(front + text)
print("wrote", out)
