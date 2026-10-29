"""Build the CORD Reports site: content/<slug>.md -> reports/<slug>/index.html, plus index.html.

Each content file starts with a front-matter block between `---` lines:

    ---
    title: Steam gift-card QR phish and stealer kit
    date: 2026-10-29
    summary: One sentence for the index card.
    tlp: CLEAR
    tags: phishing, infostealer, steam
    ---

Images and downloads for a report live in reports/<slug>/ beside the page and are linked
relatively (img/x.png, iocs.csv). The pages are static and self-contained apart from
assets/; GitHub Pages serves the repository root as is (.nojekyll).

usage: python build.py
"""
from __future__ import annotations

import datetime
import html
import re
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent
CONTENT = ROOT / "content"
REPORTS = ROOT / "reports"
SITE = "CORD Reports"


def front_matter(text: str) -> "tuple[dict, str]":
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        raise SystemExit("missing front matter")
    meta = {}
    for line in m.group(1).splitlines():
        k, _, v = line.partition(":")
        meta[k.strip()] = v.strip()
    return meta, text[m.end():]


def logo() -> str:
    svg = (ROOT / "assets" / "logo.svg").read_text(encoding="utf-8")
    return re.sub(r"<\?xml[^>]*>\s*", "", svg).strip()


def page(title: str, body: str, depth: int, description: str = "") -> str:
    up = "../" * depth
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description)}">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="{up}assets/mark.svg" type="image/svg+xml">
<link rel="stylesheet" href="{up}assets/tokens.css">
<link rel="stylesheet" href="{up}assets/site.css">
<script>/* set the saved theme before first paint so there is no flash */
try{{var t=localStorage.getItem("cord-theme");if(t)document.documentElement.setAttribute("data-theme",t);}}catch(e){{}}</script>
</head>
<body>
<div class="progress" aria-hidden="true"></div>
<header class="top"><div class="in">
<a class="brand" href="{up}index.html" aria-label="{SITE} home">{logo()}</a>
<span class="site">Reports</span>
<nav><a href="{up}index.html">All reports</a><a href="{up}about.html">About</a>
<button class="theme-toggle" type="button" aria-label="Toggle light and dark theme" title="Toggle theme">
<svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z"/></svg>
<svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
</button></nav>
</div></header>
{body}
<footer>CORD &middot; Cluster, Optimize, Research, Detection. Defensive threat research on
malware and scams already in circulation. Indicators are defanged; never visit them from a
normal browser.</footer>
<script src="{up}assets/app.js" defer></script>
</body>
</html>
"""


def render_md(text: str) -> "tuple[str, str]":
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "attr_list", "md_in_html",
                                       "sane_lists", "def_list"],
                           extension_configs={"toc": {"toc_depth": "2-3", "permalink": "#"}})
    body = md.convert(text)
    # wrap wide tables so they scroll on a phone instead of widening the page
    body = body.replace("<table>", '<div class="tw"><table>').replace("</table>", "</table></div>")
    return body, md.toc


def build_report(src: Path) -> dict:
    meta, text = front_matter(src.read_text(encoding="utf-8"))
    slug = src.stem
    body, toc = render_md(text)
    tags = "".join(f'<span class="pill">{html.escape(t.strip())}</span>'
                   for t in meta.get("tags", "").split(",") if t.strip())
    tlp = meta.get("tlp", "CLEAR")
    hero = f"""<main class="wrap report">
<section class="hero">
<div class="meta"><span class="pill tlp">TLP:{html.escape(tlp)}</span>{tags}</div>
<h1>{html.escape(meta["title"])}</h1>
<p class="sub">{html.escape(meta.get("summary", ""))}</p>
<p class="sub small">Published {html.escape(meta["date"])}{(" &middot; updated " + html.escape(meta["updated"])) if meta.get("updated") else ""}</p>
</section>
<div class="cols">
<aside class="toc"><div class="toc-in"><div class="toc-h">Contents</div>{toc}</div></aside>
<details class="toc-m"><summary>Contents</summary>{toc}</details>
<article class="prose">{body}</article>
</div>
</main>"""
    out = REPORTS / slug / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page(meta["title"] + " | " + SITE, hero, 2, meta.get("summary", "")),
                   encoding="utf-8")
    print("built", out.relative_to(ROOT))
    return dict(meta, slug=slug)


def build_index(items: "list[dict]") -> None:
    cards = []
    for m in sorted(items, key=lambda m: m["date"], reverse=True):
        tags = "".join(f'<span class="pill">{html.escape(t.strip())}</span>'
                       for t in m.get("tags", "").split(",") if t.strip())
        cards.append(f"""<a class="rcard" href="reports/{m['slug']}/index.html">
<div class="meta"><span class="date">{html.escape(m['date'])}</span><span class="pill tlp">TLP:{html.escape(m.get('tlp', 'CLEAR'))}</span>{tags}</div>
<h2>{html.escape(m['title'])}</h2>
<p>{html.escape(m.get('summary', ''))}</p>
</a>""")
    body = f"""<main class="wrap">
<section class="hero">
<h1>Threat reports</h1>
<p class="sub">Investigations from the CORD toolchain: what a campaign does, the infrastructure behind it,
indicators to block, detection rules, and how to recover if you were hit.</p>
</section>
<div class="rlist">{''.join(cards)}</div>
</main>"""
    (ROOT / "index.html").write_text(page(SITE, body, 0, "CORD threat reports"), encoding="utf-8")
    print("built index.html")


def build_about() -> None:
    src = ROOT / "content" / "_about.md"
    if not src.exists():
        return
    body, _ = render_md(src.read_text(encoding="utf-8"))
    (ROOT / "about.html").write_text(
        page("About | " + SITE, f'<main class="wrap"><article class="prose solo">{body}</article></main>', 0,
             "About CORD Reports"), encoding="utf-8")
    print("built about.html")


if __name__ == "__main__":
    items = [build_report(p) for p in sorted(CONTENT.glob("*.md")) if not p.name.startswith("_")]
    # `hidden: true` pages (technical companions) are built and linked from their parent
    # report but kept off the index
    build_index([m for m in items if m.get("hidden", "").lower() != "true"])
    build_about()
    print("done", datetime.datetime.now().isoformat(timespec="seconds"))
