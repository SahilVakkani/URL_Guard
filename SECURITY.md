# Security Policy

## Reporting a vulnerability

If you find a security issue in this extension (e.g. a way a malicious page
could read or exfiltrate stored API keys, bypass the reputation check, or
inject content via an unescaped API response), please open a GitHub issue
describing the problem, or reach out to the maintainer directly for anything
sensitive enough to withhold from a public issue until it's fixed.

## Design notes relevant to security review

- **API keys** are stored in `chrome.storage.local` only — never synced,
  never sent to any server other than the API they belong to.
- **No backend server.** All API calls happen directly from the browser's
  service worker to VirusTotal / Google Safe Browsing / URLhaus / AlienVault
  OTX. There is nothing in between that could log or intercept keys or URLs.
- **Host permissions** are scoped to exactly the four API domains the
  extension calls — not `<all_urls>` for fetch access. The content script
  still needs to run on all `http(s)://` pages (`matches`) to show the
  warning banner, which is a separate, narrower permission grant than host
  access for network requests.
- **No `eval`, no remote code execution.** All logic ships in the extension
  package; nothing is fetched and executed at runtime.
- **XSS hygiene.** Every string that originates from a third-party API
  (threat names, tags, error messages) is HTML-escaped before being inserted
  into the popup or the in-page banner.
- **Fetch timeouts** (`AbortController`, 10s) prevent a slow or hung
  third-party API from stalling the extension indefinitely.
