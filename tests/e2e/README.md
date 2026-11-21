# Browser journeys

These scripts test real user journeys in a browser against a local, throw-away privnet. They are the evidence behind the scorecard in `PRODUCT_IMPROVEMENT_BACKLOG.md`.
Run them at the start of an improvement session to detect regressions, and again at the end to measure progress.

| Script | What it does |
|---|---|
| `journeys.mjs` | J1–J14: first-time setup, adding devices, share links, auth errors and lockout, validation, destructive actions, DNS, HTTPS, IDOR checks, logout/login, mobile, keyboard tab order, 404s, timings. Also runs axe-core (WCAG 2.2 AA plus best practice) on 10 pages. |
| `journeys-features.mjs` | J15–J18: rename, account page, live status on the join page, friendly 404, and axe in dark mode. Run it after `journeys.mjs` on the same database. |

## Running

```bash
# once, in a scratch directory outside the repo
mkdir -p /tmp/privnet-e2e && cd /tmp/privnet-e2e && npm i playwright@1.49.1 axe-core@4.10.2

# from the repo root: start an empty local instance
tests/e2e/run-local.sh /tmp/privnet-e2e/work

# from the scratch directory (axe-core resolves from the current directory)
cd /tmp/privnet-e2e
node /path/to/privnet/tests/e2e/journeys.mjs work
node /path/to/privnet/tests/e2e/journeys-features.mjs work
```

Each run writes `journeys.json` (metrics plus axe results) and a few screenshots into the work directory.

Notes:
- The scripts use the system Chrome (`channel: 'chrome'`).
- Test contexts set `bypassCSP: true` so axe can be injected. The app's CSP itself is not changed.
- Certificate issuance always fails locally (no reachable CA). J8 checks the error path.
