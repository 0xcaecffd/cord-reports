# About CORD Reports

CORD is a defensive detection-engineering toolchain: **C**luster, **O**ptimize,
**R**esearch, **D**etection. It collects malware already in circulation, groups it into
families, analyses representatives in an isolated lab, and writes detection rules that
are measured against real samples and clean software before they ship.

These pages publish what that work finds when it is useful to defenders and to people
who were hit: how a campaign works, the infrastructure behind it, indicators to block,
detection rules, and recovery steps.

## How to read a report

- **Indicators are defanged.** `example[.]com` and `hxxps://` stop accidental clicks.
  Re-fang them only inside your security tooling. Each report also has a CSV or JSON
  list for import.
- **Confidence is stated.** Claims are marked high, medium or low, with the reason.
  Attribution stops at the group level. We do not name individuals.
- **Screenshots are sanitised.** Images are re-encoded with metadata removed. Anything
  that would still work as a lure, such as a QR code to a live phishing page, is
  pixelated.
- **Nothing was run on a victim's behalf.** Malware is analysed statically in an
  isolated lab. Live phishing sites are fetched read-only over Tor. We never submit
  forms or sign in.

## Rules

YARA rules are published under each report. They are tested against the samples they
target and against clean software before they appear here. Use them for hunting and
triage, and test them in your own environment before you block on them.

## Contact

Corrections and additional indicators are welcome through issues on this site's
GitHub repository.
