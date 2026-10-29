# CORD Reports

Public threat reports from the CORD toolchain, served with GitHub Pages.

## Layout

- `content/<slug>.md`: one report, with front matter (title, date, summary, tlp, tags).
  `content/_about.md` is the about page.
- `reports/<slug>/`: the built page plus its images (`img/`), indicator lists and YARA
  rules (`rules/`).
- `assets/`: CORD brand tokens, logo, favicon and the site stylesheet.
- `build.py`: builds every report page, `index.html` and `about.html`.
- `tools/`: helpers that prepare report material.

## Build

```
python -m pip install markdown
python build.py
```

Commit the built HTML. GitHub Pages serves the repository root as is (`.nojekyll`).

## Before publishing a report

- Indicators defanged in prose and tables; full values only in the CSV or JSON lists.
- Screenshots re-encoded, metadata stripped, live QR codes and links pixelated.
- No samples, no internal paths or hostnames, no victim-identifying details.
- No exploitation details for unpatched vulnerabilities.
- YARA rules only, each measured against goodware.
