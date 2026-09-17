# URL Reputation Guard

A Chrome extension (Manifest V3) that checks every site you visit against
**four** threat intelligence sources — VirusTotal, Google Safe Browsing,
URLhaus (abuse.ch), and AlienVault OTX — and warns you before you interact
with a phishing or malware-hosting page.

Built as a hands-on threat-intel enrichment project by a SOC/threat
intelligence analyst — the same multi-source correlation approach used to
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
  pages, naming which sources flagged it — dismissible, non-intrusive on
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

No build step, no bundler, no backend — it's plain HTML/CSS/JS calling each
vendor's API directly from the browser.

## Privacy

Be aware of what this extension inherently does, since that's the honest
tradeoff of a reputation-checking tool:

- **Every URL you visit is sent** to whichever sources you've configured
  (VirusTotal / Google / abuse.ch / AlienVault) so they can look it up. This
  is unavoidable — that's how URL reputation checking works.
- **API keys** are stored only in `chrome.storage.local` on your machine —
  never synced across devices, never sent anywhere except directly to the
  service they belong to.
- **No telemetry, no analytics, no third-party server.** This project has no
  backend of its own; nothing is logged or collected beyond what each
  third-party API already does on their end for its own service.
- If you don't want a particular service seeing your browsing, simply don't
  add a key for it — each source is fully optional and independent.

See [SECURITY.md](./SECURITY.md) for the technical security design (host
permission scoping, XSS-safe rendering, fetch timeouts).

## Limitations

- This is a **warning layer, not a blocker** — it flags risk but doesn't
  prevent navigation. See "Ideas for extending this" below for how to turn
  it into an active blocker.
- Rate limits are real, especially VirusTotal's free tier (4/min). The
  1-hour cache and request de-duplication keep normal browsing well within
  limits, but rapid navigation across many brand-new domains can still hit
  a ceiling — the badge shows a rate-limit error when that happens rather
  than failing silently.
- Reputation lookups reflect what's already been reported to these
  services — a URL that's malicious but brand new may show as "clean" or
  "unscanned" everywhere until someone else reports it first.

## Ideas for extending this

Good next steps if you want to keep building on this (and good talking
points if you're using this as a portfolio project):

- **Active blocking**: use `declarativeNetRequest` to redirect away from
  confirmed-malicious URLs before the page loads, instead of just warning
  after the fact.
- **Context-menu link check**: right-click any link to check its reputation
  before clicking it, without navigating there first.
- **Typosquatting/homograph detection**: flag domains that are a short edit
  distance from popular domains, or that mix Unicode look-alike characters —
  catches phishing domains no reputation feed has indexed yet.
- **IP/ASN reputation**: resolve the domain and check the hosting IP against
  AbuseIPDB — useful for freshly-registered domains on known-bad
  infrastructure.
- **Domain age / WHOIS heuristic**: very young domains are disproportionately
  used in phishing campaigns; surfacing registration age adds a heuristic
  signal independent of the reputation feeds.
- **Personal threat log**: keep a local, exportable (CSV/JSON) history of
  every site that was ever flagged — a "personal SOC ticket queue" for your
  own browsing.
- **Generate an incident-style report**: a button that turns a flagged
  site's data into a short markdown write-up (indicators, sources, verdict) —
  mirrors real SOC reporting and demonstrates that skill directly.
- **Map findings to MITRE ATT&CK** (e.g., T1566 Phishing, T1583.001 Domains)
  in the popup for anyone using this alongside detection-engineering work.
- **Unit tests** for the aggregation logic (`aggregate()` in `background.js`)
  — it's pure and easy to test in isolation.

## License

MIT — see [LICENSE](./LICENSE).
