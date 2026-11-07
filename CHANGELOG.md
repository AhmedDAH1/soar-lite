# Changelog

All notable changes to SOAR-Lite. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-08

A security release. Alerts are written by whoever sends them, often an
attacker, so SOAR-Lite now checks who sent an alert and never lets alert text
run as code.

### Breaking changes
- Webhooks require a signature. Set `WEBHOOK_SECRET` on the server and sign
  every request (README, "Sending alerts"); unsigned requests get `401`, and
  webhooks are off until a secret is set.
- `DEBUG` is off by default, so the API docs at `/docs` must be enabled
  explicitly.
- Docker Compose publishes the dashboard on `127.0.0.1` only and no longer
  publishes the PostgreSQL port.

### Security
- **Forged alerts.** `/api/webhooks/siem`, `/edr` and `/email` accepted
  requests from anyone, and `/generic` checked a signature only when the
  sender chose to send one, against a hard-coded secret. Every webhook now
  needs an HMAC-SHA256 signature over a timestamp and the body; edited,
  expired (over five minutes) or replayed requests are refused.
- **Stored XSS.** Alert titles, descriptions, IOC values and timeline entries
  were inserted into the dashboard as HTML, so an alert titled
  `<img src=x onerror=...>` ran script in the analyst's browser. Every value is
  now escaped, and a Content-Security-Policy (`script-src 'self'`) blocks
  inline scripts and event handlers as a second layer.
- **The public demo was writable.** Visitors could create alerts (including
  the XSS above), change incidents and spend the enrichment API quotas.
  `DEMO_MODE` (or the old `SEED_DEMO=1`) now refuses every change.
- **PDF reports.** ReportLab interprets markup in text: an alert title
  containing a tag made report generation fail, and one containing a link
  put a clickable link in the report. Alert text is now escaped.
- Chart.js and Tailwind are bundled instead of loaded from CDNs, so the
  dashboard runs no third-party code (and works where those CDNs are
  blocked).
- Removed the wildcard CORS policy that let any website read the API in
  debug mode.
- Error responses no longer include internal exception messages.

### Added
- `tests/test_security.py`: 29 tests that fail if any of these controls is
  removed. 88 tests in total.
- `python tests/webhook_tester.py` signs its requests.
- The dashboard shows a banner and hides controls that change data in the
  read-only demo.

### Changed
- Lint is enforced in CI (it ran with `|| true`, so it could never fail), and
  the codebase was cleaned up to pass it.

### Fixed
- **Internal attackers left no indicator.** Private IP addresses were dropped
  during IOC extraction, so an incident about an internal host scanning the
  network had no IOC for it. They are now kept as IOCs and still never sent
  to external enrichment services.
- The same indicator found in an alert's title, description and raw data was
  stored three times; it is now stored once.
- Attachment names such as `invoice.pdf.exe` were extracted as domains.
- The incident page's header card was never closed, so the tabs were nested
  inside it.

## [1.1.0] - 2026-05-31

### Added
- Live deployment on Render with demo data seeded through the ingestion
  pipeline.

[2.0.0]: https://github.com/AhmedDAH1/soar-lite/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/AhmedDAH1/soar-lite/releases/tag/v1.1.0
