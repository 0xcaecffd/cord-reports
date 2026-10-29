"""Publish CORD Research per-sample reports (report.html) into the site.

Each report is copied as produced by the research renderer (cover + full report:
behaviours, IOCs, decoded strings, process map, how the code connects, code, evidence).
Three changes only: a bar at the top links back to the case report and carries any
correction or addition from later analysis; attacker hosts the renderer left plain in
decoded strings are defanged; nothing else in CORD's analysis is rewritten.

usage: python tools/publish_cord_reports.py
"""
import re
from pathlib import Path

SAMPLES = Path(r"C:\Users\Executor\cord\reports\samples")
SITE = Path(__file__).resolve().parent.parent

CORR_WV2 = (
    "<strong>Corrected by a later full static re-analysis.</strong> This is CORD's first automated "
    "pass, published as produced. Four points below were overturned: the program is a "
    "<strong>credential-relay shell</strong>, not a stealer, and reads nothing from disk; the "
    "RCDATA 300 resource is Microsoft's signed <code>WebView2Loader.dll</code>, not a second stage; "
    "the <code>window.steamm</code> file bridge is confined to the program's own folder; and the "
    "\"system fingerprint\" at <code>0x1400094c0</code> is unreferenced junk that changes size each "
    "build. WebView2 is also launched with SmartScreen, Safe Browsing and certificate checks off."
)
CORR_ELECTRON = (
    "<strong>Corrected by a later full static re-analysis.</strong> This is CORD's first automated "
    "pass, published as produced. The Electron app is a <strong>credential-relay shell</strong>, not "
    "a stealer: it reads no browser storage, cookies or files. Its window runs with "
    "<strong>Node integration off</strong>, not on. The September builds' JavaScript was decoded in "
    "full (string decoder reimplemented, never run); the payload tries three hosts, "
    "<code>njrlmwtgpk[.]shop</code>, <code>fakefake[.]shop</code> and <code>pulse-keys[.]store</code>."
)
ADD_HIJACK = (
    "<strong>Extended by a later full static re-analysis.</strong> CORD's pass below could not decode "
    "the download URL or read the ten RCDATA resources. The re-analysis did: the XOR-encoded URL is "
    "<code>hxxps://koooolda[.]shop/43413</code>, and resource 103 is the relay kit's client script, "
    "which POSTs <code>DyNaM1c</code>-prefixed actions (<code>visit</code>, <code>doLogin</code>, "
    "<code>submitCode</code>, <code>checkConfirmations</code>) XOR-encrypted with the affiliate "
    "cookie's secret. The program serves a local Steam sign-in UI over WebView2 to that kit."
)

JOBS = [
    ("steamlure-28f2b618/f27af032b01f/r20261028-1/report.html",
     "reports/2026-10-steam-lure/samples/f27af032.html", "2026-10-steam-lure", CORR_WV2, "bad"),
    ("steamlure-28f2b618/c86286508d09/r20261028-1/report.html",
     "reports/2026-10-steam-lure/samples/c8628650.html", "2026-10-steam-lure", CORR_ELECTRON, "bad"),
    ("steamlure-28f2b618/3d2b12f8523f/r20261028-1/report.html",
     "reports/2026-10-steam-lure/samples/3d2b12f8.html", "2026-10-steam-lure", ADD_HIJACK, "ok"),
    ("mirai/0c5486f06620/r20261022-1/report.html",
     "reports/2026-10-php2shell-potassium/samples/0c5486f0.html", "2026-10-php2shell-potassium", None, None),
]

# attacker hosts the renderer showed plain inside decoded strings (potassium)
DEFANG = ["thunder.godofthunder.st", "hackattackkaboom.botlesscucks.st",
          "hik.gettingheadfromduckysmom.st", "2sexy4u.eth", "sushiconsumer.eth"]


def bar(case: str, note: "str | None", kind: "str | None") -> str:
    edge = {"bad": "var(--bad)", "ok": "var(--ok)"}.get(kind, "var(--accent)")
    out = ('<div style="max-width:76rem;margin:0 auto;padding:.7rem 1.25rem;font:14px/1.5 var(--font-sans);">'
           f'<a href="../index.html" style="color:var(--accent);text-decoration:none">&larr; Back to the case report</a>'
           '<span style="color:var(--muted)"> &middot; CORD Reports</span>')
    if note:
        out += (f'<div style="margin-top:.6rem;padding:.75rem 1rem;border:1px solid var(--line);'
                f'border-left:4px solid {edge};border-radius:6px;background:var(--surface);color:var(--fg)">'
                f'{note}</div>')
    return out + "</div>"


for src, dst, case, note, kind in JOBS:
    html = (SAMPLES / src).read_text(encoding="utf-8")
    for host in DEFANG:
        html = html.replace(host, host.replace(".", "[.]"))
    html, n = re.subn(r"(<body[^>]*>)", lambda m: m.group(1) + bar(case, note, kind), html, count=1)
    if n != 1:
        raise SystemExit(f"no <body> in {src}")
    for bad in (r"/srv/scratch", r"/opt/cord", "wrex", r"10\.73\."):
        if re.search(bad, html):
            raise SystemExit(f"internal reference {bad!r} in {src}")
    out = SITE / dst
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"published {dst} ({len(html) // 1024} KB)")
