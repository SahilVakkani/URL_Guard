# Contributing

Contributions are welcome — this started as a personal SOC/threat-intel
portfolio project, and pull requests that improve accuracy, add sources, or
fix bugs are appreciated.

## Development setup

No build step — it's plain HTML/CSS/JS, loaded directly as an unpacked
extension.

1. Fork and clone the repo.
2. Go to `chrome://extensions`, enable Developer mode, click **Load unpacked**,
   select the repo folder.
3. Add your own API keys via the extension's Settings page (see README).
4. Make your changes, then click the reload icon on the extension card in
   `chrome://extensions` to pick them up.

## Before opening a PR

Run the two checks CI will run:

```
npm run validate
npm run lint:syntax
```

## Ideas for contributions

See the "Ideas for extending this" section in the README — typosquatting
detection, a context-menu link checker, IP/domain reputation via AbuseIPDB,
and a local flagged-sites export are all good starting points.

## Reporting security issues

If you find a security issue (e.g. a way an untrusted page could exfiltrate
a stored API key, or an XSS vector in the popup/banner), please open a
GitHub issue or contact the maintainer directly rather than filing a public
exploit — see SECURITY.md.
