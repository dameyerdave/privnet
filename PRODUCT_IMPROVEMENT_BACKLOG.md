# privnet — Product Improvement Backlog

The persistent source of truth for product quality, discovered problems, implemented improvements and future work.
**Read this file completely before starting a new improvement session.** Append to it; never replace it.

---

## A. Product Overview

**Purpose.** privnet is a self-hosted, Tailscale-like service built on WireGuard. Users create small private networks (4–16 devices).
privnet allocates the addresses, generates keys, runs the hub and gives every device a step-by-step setup guide plus a QR code.
Optional extras:
- a nip.io-style DNS service with per-user namespaces;
- trusted Let's Encrypt certificates per device (downloadable, or served by an HTTPS proxy on the hub).

**Personas**
| Persona | Goal | Typical device mix |
|---|---|---|
| Home-lab owner (primary) | Reach NAS, Raspberry Pi, laptop and phone securely from anywhere | Linux servers, macOS/Windows laptops, phones |
| Family admin | Set up devices of non-technical relatives | Phones/tablets, sends share links |
| Developer / power user | Private names and trusted HTTPS for services, scripted renewals | Linux, CLI, ACME clients |
| Invited device owner (no account) | Connect their own device from a share link | Phone or laptop |

**Primary use cases / critical workflows**
1. Sign up → create network → add device → connect it (QR code or config) → see it online. *(critical, first-time)*
2. Add more devices to an existing network; check which devices are online. *(frequent)*
3. Share an onboarding link with someone else; they connect without an account. *(frequent for family admins)*
4. Give a device an HTTPS name (hub proxy or downloadable certificate). *(secondary)*
5. DNS namespaces and custom names; get wildcard certificates via the acme-dns API. *(secondary, power users)*
6. Remove devices, delete networks/namespaces. *(occasional, destructive)*
7. Log in / log out. *(frequent)*

**Technology stack**
- **Backend:** Go 1.26, single binary, `net/http` with `html/template`, no JS framework.
- **Storage:** SQLite (modernc, no CGO) with AES-GCM encryption of secrets at rest.
- **Networking:** kernel WireGuard via wgctrl plus iproute2 and iptables; DNS via miekg/dns; ACME via `golang.org/x/crypto/acme`.
- **Frontend:** server-rendered pages, about 300 lines of vanilla JS (`web/static/app.js`), a single CSS file with light/dark tokens, and a strict CSP (no inline scripts or styles).
- **Deployment:** Kubernetes (xuno cluster), kustomize, Docker Hub image, Cloudflare tunnel for HTTPS, Octavia load balancers for WireGuard UDP and DNS.

**Main components**
| Component | Location |
|---|---|
| Entry point and config | `cmd/privnet/main.go` |
| Address planning | `internal/ipam` |
| Persistence | `internal/store` |
| WireGuard, routing, firewall | `internal/wg` |
| Per-platform guides | `internal/cookbook` |
| Authoritative DNS | `internal/dns` |
| ACME issuer and HTTPS proxy | `internal/certs` |
| HTTP handlers and templates | `internal/web`, `web/templates`, `web/static` |

**Supported platforms**
- Web UI: modern desktop and mobile browsers.
- Device guides: Linux, macOS, Windows, iOS, Android.

**Known testing limitations**
- Local runs use `WG_MODE=fake`: no real tunnels, and handshake status is simulated.
- Let's Encrypt can't validate local DNS, so local certificate issuance always fails (exercises the error path only).
- Production must not be modified during improvement sessions.
- Real WireGuard and ACME end-to-end runs were done earlier against production with explicit authorization.

---

## B. Product Quality Scorecard

Scores are 1–10 and only given with evidence. "S1" means session 1 (2026-11-21).
Baseline evidence: `journeys.mjs` (15 scripted browser journeys), axe-core 4.10 on 10 pages, timing samples, and manual review of screenshots at 1280 px, 390 px and in dark mode.

| Category | Baseline (S1) | Current | Evidence |
|---|---|---|---|
| First-time usability | 8 | 8 | J1: signup → network → device → guide in 5 clicks, 4 inputs, 0.9 s. The guide opens automatically for new devices. |
| Workflow efficiency | 7 | 7 | J2: add a device in 4 clicks. Devices and networks can't be renamed, and values can't be copied with one click. |
| Navigation | 8 | 8 | Active nav, breadcrumbs, skip link. Unknown URLs show a bare Go "404 page not found" with no way back (J13). |
| UI consistency | 8 | 8 | One CSS token system; consistent cards, accordions, pills and danger zones. |
| Visual quality | 8 | 8 | Screenshots at 1280/390 px in light and dark mode. |
| Performance | 9 | 9 | Local server medians of 1–2 ms on all pages; network page HTML 9.5 KB, DCL 15 ms; static assets cached and hashed. |
| Accessibility | 6 | 6 | axe: `color-contrast` (serious) on 10/10 pages, `link-in-text-block` on 6, `heading-order` on the guide; 14 targets under 24 px on the phone device page. |
| Reliability | 7 | 7 | 500 error on signup with a password over 72 bytes; bare 404 page; duplicate device names accepted. |
| Security | 6 | 6 | No login brute-force protection (26 wrong attempts, all 401, J4); no HSTS in production. IDOR checks pass (8/8 return 404, J9); CSRF and CSP are in place. |
| Mobile usability | 8 | 8 | J11: QR code at 277 px on a phone; devices shown as cards; no horizontal overflow on any page. |
| Overall product quality | 7 | 7 | Weighted judgement of the rows above. |

---

## C. Prioritized Improvement Backlog

Score = Impact × Frequency × Confidence / Effort. Statuses follow §3.2 of the process prompt.

| ID | Title | Cat. | P | I | F | C | E | Score | Status | Session |
|---|---|---|---|---|---|---|---|---|---|---|
| SEC-001 | No brute-force protection on login, signup and token endpoints | Security | P1 | 5 | 3 | 5 | 2 | 37.5 | Discovered | S1 |
| BUG-001 | Signup with a password over 72 bytes returns HTTP 500 | Reliability | P1 | 3 | 2 | 5 | 1 | 30 | Discovered | S1 |
| A11Y-001 | Text and links fail WCAG AA contrast (accent on soft backgrounds, eyebrow, footer) | Accessibility | P1 | 4 | 5 | 5 | 1 | 100 | Discovered | S1 |
| A11Y-002 | Links inside text are only distinguishable by color | Accessibility | P2 | 3 | 5 | 5 | 1 | 75 | Discovered | S1 |
| UX-001 | Unknown URLs show a bare "404 page not found" without layout or way back | UX | P2 | 3 | 2 | 5 | 1 | 30 | Discovered | S1 |
| UX-002 | Duplicate device names are accepted, so two "my laptop" rows look identical | UX | P2 | 3 | 3 | 5 | 1 | 45 | Discovered | S1 |
| UX-003 | Devices and networks can't be renamed (typos are permanent) | UX | P2 | 3 | 3 | 5 | 2 | 22.5 | Discovered | S1 |
| UX-004 | No account page: users can't change their password or delete their account | UX/Security | P2 | 4 | 2 | 5 | 2 | 20 | Discovered | S1 |
| UX-005 | An invited user (share link) gets no feedback when their device connects | UX | P2 | 4 | 3 | 4 | 2 | 24 | Discovered | S1 |
| SEC-002 | No `Strict-Transport-Security` header in production | Security | P2 | 3 | 5 | 5 | 1 | 75 | Discovered | S1 |
| A11Y-003 | Copy buttons and similar controls are smaller than 24 × 24 px (WCAG 2.5.8) | Accessibility | P2 | 2 | 4 | 4 | 1 | 32 | Discovered | S1 |
| A11Y-004 | Heading levels skip in the setup guide (h2 → h4) | Accessibility | P3 | 2 | 4 | 5 | 1 | 40 | Discovered | S1 |
| UX-006 | Focus is lost after creating a network (URL fragment suppresses autofocus) | UX | P3 | 2 | 4 | 4 | 1 | 32 | Discovered | S1 |
| UX-007 | Important values (DNS name, address, endpoint) need manual text selection to copy | UX | P3 | 2 | 4 | 4 | 1 | 32 | Discovered | S1 |
| UX-008 | A full network can't be resized; the only option is to delete and recreate | UX | P3 | 3 | 1 | 4 | 4 | 3 | Discovered | S1 |
| UX-009 | No password reset ("forgot password") | UX | P3 | 4 | 1 | 5 | 4 | 5 | Discovered | S1 |
| PERF-001 | Server-side and page performance | Performance | – | – | – | – | – | – | No issue found (1–2 ms medians) | S1 |

### Issue details

**SEC-001 No brute-force protection.**
- *User problem:* an attacker can guess passwords without limit; accounts protect private keys and network access.
- *Evidence:* J4 posted 26 wrong passwords for one account and every response was 401, with no delay or lockout. `handleLogin` in `internal/web/handlers.go` has no limiter.
- *Solution:* an in-memory limiter keyed per client IP and per account. Use `CF-Connecting-IP` when present, since traffic only arrives through the Cloudflare tunnel. Locked requests get HTTP 429 with a clear "try again in N minutes" message. Signup gets a per-IP limit; the token-authenticated endpoints (acme-dns update, certificate fetch, join) get a per-IP limit on failures.
- *Acceptance:* the 11th failed login for one account within 15 minutes is refused with 429 and a readable message, even with the correct password. A success resets the counter. Unit tests cover this.
- *Files:* `internal/web/ratelimit.go` (new), `handlers.go`, `dns.go`, `certs.go`.
- *Validation:* unit tests plus rerunning J4.

**BUG-001 500 on long passwords.**
- *Evidence:* a signup POST with a 100-character password returns 500, because bcrypt returns `ErrPasswordTooLong`.
- *Solution:* validate 10–72 bytes with a clear message and `maxlength` on the inputs. Login treats over-long passwords as wrong instead of erroring.
- *Acceptance:* a 100-character password gets a 400 with a message. Test added.

**A11Y-001 Contrast.**
- *Evidence:* axe `color-contrast` (serious) on every page. Failing elements: the active nav link (`--accent` on `--accent-soft`), the `.eyebrow`, footer and inline links (#2f6df6 on #f6f7f9, about 4.3:1), and selected chips.
- *Solution:* darken the light-mode accent to meet ≥4.5:1 on all surfaces, and check dark mode too.
- *Acceptance:* axe reports zero `color-contrast` violations on all audited pages in light and dark mode.

**A11Y-002 Link distinction.**
- *Evidence:* axe `link-in-text-block` on signup, login, device, join and dnszone.
- *Solution:* underline links in running text (paragraphs, breadcrumbs, helper text); navigation and buttons stay as they are.
- *Acceptance:* zero `link-in-text-block` violations.

**UX-001 Bare 404.**
- *Evidence:* J13 `/nope` returns the plain text "404 page not found".
- *Solution:* a catch-all route renders the styled status page with links to Networks or Home.
- *Acceptance:* unknown paths return 404 with the layout, a heading and a link home.

**UX-002 Duplicate device names.**
- *Evidence:* J5 accepted "my laptop" twice. The list shows two identical names; only the hidden hostname differs (`my-laptop-2`).
- *Solution:* reject a case-insensitive duplicate name within a network: "There's already a device named …".
- *Acceptance:* the duplicate gets a 400 with the message, and the form keeps its input.

**UX-003 Rename.**
- *Solution:* a "Rename" action on the device and network pages (inline form). The device hostname, DNS name and IP stay unchanged so configs keep working, and the page says so.
- *Acceptance:* renaming updates the page title and lists, and empty, too-long or duplicate names are rejected.

**UX-004 Account page.**
- *Solution:* an `/account` page linked from the nav email address. It offers a password change (current password required, other sessions logged out) and account deletion (password plus typed confirmation; deletes networks, devices and namespaces, then re-syncs the hub).
- *Acceptance:* both flows work end to end, wrong passwords are rejected, and other sessions are invalidated after a password change.

**UX-005 Join feedback.**
- *Solution:* a token-authenticated `GET /join/{token}/status` endpoint. The join page polls it and shows the same "connected" banner as the device page.
- *Acceptance:* the anonymous join page flips to "connected" without a reload. Expired or revoked tokens return 404.

**SEC-002 HSTS.**
- *Solution:* send `Strict-Transport-Security: max-age=31536000` when `BASE_URL` is https.

**A11Y-003 Small targets.**
- *Evidence:* J11 found 14 interactive elements under 24 px on the phone device page, mostly copy buttons (about 22 px) and `summary` toggles.
- *Solution:* give copy buttons and toggles a minimum 24 px hit area. Inline text links are exempt under WCAG.

**A11Y-004 Heading order.**
- *Solution:* setup-guide step titles become h3. Adjust the CSS.

**UX-006 Focus after create.**
- *Solution:* if nothing has focus after load, focus the first `[autofocus]` element.

**UX-007 Copy values.**
- *Solution:* a small copy button next to key values on the device page.

---

## D. Active Implementation Queue

Session 1, in order. Security and reliability come first, then cheap high-score accessibility fixes, then workflow features.

| # | Issue | P | Expected user benefit | Effort | Status | Depends on |
|---|---|---|---|---|---|---|
| 1 | SEC-001 | P1 | Accounts can't be brute-forced | 2 | In Progress | – |
| 2 | BUG-001 | P1 | Long passphrases work instead of a 500 | 1 | Ready | – |
| 3 | A11Y-001 | P1 | Readable text and links for low-vision users | 1 | Ready | – |
| 4 | A11Y-002 | P2 | Links recognizable without color | 1 | Ready | A11Y-001 |
| 5 | SEC-002 | P2 | HTTPS enforced by browsers | 1 | Ready | – |
| 6 | UX-001 | P2 | Lost users find their way back | 1 | Ready | – |
| 7 | UX-002 | P2 | No more indistinguishable devices | 1 | Ready | – |
| 8 | UX-006, A11Y-004, A11Y-003 | P3/P2 | Focus, structure and touch-target polish | 1 | Ready | – |
| 9 | UX-005 | P2 | Invited users see they're connected | 2 | Ready | – |
| 10 | UX-003 | P2 | Fix typos in device and network names | 2 | Ready | UX-002 |
| 11 | UX-004 | P2 | Change password, delete account | 2 | Ready | SEC-001 |
| 12 | UX-007 | P3 | One-click copy of key values | 1 | Ready | – |

## E. Completed Improvements

## F. Deferred and Blocked Improvements

## G. Session History

## H. Next Eight-Hour Session Plan
