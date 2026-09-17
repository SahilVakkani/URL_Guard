# URL Reputation Guard

A Chrome extension (Manifest V3) that checks every site you visit against
**four** threat intelligence sources  VirusTotal, Google Safe Browsing,
URLhaus (abuse.ch), and AlienVault OTX and warns you before you interact
with a phishing or malware-hosting page.

Built as a hands-on threat-intel enrichment project by a SOC/threat
intelligence analyst the same multi-source correlation approach used to
triage alerts in a real SOC, applied to everyday browsing.

## What it does

- **On every page load**, looks up the URL against all configured sources in
  parallel and combines them into one verdict.
- **Toolbar badge**: 🟢 clean · 🟠 suspicious (count = # sources flagging it)
  · 🔴 malicious (count) · ⚪ unscanned/error/not configured.
- **Click the icon** for a full breakdown: which sources were checked, what
  each one said, vendor counts, threat-pulse counts, and links to the full
  report on each service.
- **In-page warning banner** appears automatically on malicious/suspicious
  pages, naming which sources flagged it dismissible, non-intrusive on
  clean sites (no banner at all).
- **On-demand VirusTotal scanning** for URLs none of the sources have seen
  before.
- **Smart caching + de-duplication**: results are cached for 1 hour per URL,
  concurrent checks for the same URL are merged into a single request, and a
  background alarm sweeps expired cache entries every 6 hours — so it stays
  fast and stays well within free-tier API limits.

## Why multiple sources?

Any single reputation source has blind spots. VirusTotal aggregates 70+
antivirus engines but can lag on brand-new phishing domains. Google Safe
Browsing is fast and authoritative for browser-level blocklisting. URLhaus is
narrow but excellent specifically for active malware-distribution URLs. OTX
surfaces community/researcher threat-intel pulses that commercial engines
haven't caught up to yet. Combining them is the same "don't trust one feed"
principle used in real SOC alert enrichment — this project treats a
browser tab the way a SOC analyst treats an incoming IOC.

## Setup

You need **at least one** API key configured; more sources give better
coverage, but VirusTotal alone is enough to get started.

1. **Load the extension**
   - Clone or download this repo.
   - Go to `chrome://extensions`, enable **Developer mode**, click
     **Load unpacked**, and select the repo folder.
2. **Get API keys** (all have free tiers):
   | Source | Where to get a key | Free tier |
   |---|---|---|
   | VirusTotal | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | 4 req/min, 500/day |
   | Google Safe Browsing | [Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) | 10,000 req/day |
   | AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com/) → Settings → API Integration | Free, generous |
   | URLhaus (abuse.ch) | [auth.abuse.ch](https://auth.abuse.ch/) (optional Auth-Key) | Free |
3. Click the extension icon → **⚙ Settings**, paste in whichever keys you
   have, and Save. Reload any open tabs to apply.

## Architecture

```
manifest.json     — Manifest V3 config, tightly scoped host permissions
background.js     — service worker: parallel multi-source lookups, VT rate-
                     limiting queue, caching, de-duplication, cache cleanup
content.js/.css   — in-page warning banner (escapes all dynamic text)
popup.html/.js/.css — toolbar popup: overall verdict + per-source breakdown
options.html/.js  — API key management (chrome.storage.local only)
icons/            — extension icons
```
## License

MIT — see [LICENSE](./LICENSE).
