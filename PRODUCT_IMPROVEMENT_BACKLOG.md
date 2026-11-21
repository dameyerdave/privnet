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
| First-time usability | 8 | 9 | Baseline: J1: signup → network → device → guide in 5 clicks, 4 inputs, 0.9 s. The guide opens automatically for new devices. **S1 result:** J1 unchanged at 5 clicks / 4 inputs (0.9 s), but focus now lands in the device-name field after creating a network, and new devices offer "+ Add another device". The join page shows live connection status (J17). |
| Workflow efficiency | 7 | 8 | Baseline: J2: add a device in 4 clicks. Devices and networks can't be renamed, and values can't be copied with one click. **S1 result:** Rename in 1 click + typing + Enter (J15); one-click copy of address, DNS name and endpoint; chained device creation; account self-service. |
| Navigation | 8 | 9 | Baseline: Active nav, breadcrumbs, skip link. Unknown URLs show a bare Go "404 page not found" with no way back (J13). **S1 result:** Friendly 404 inside the layout with "Your networks" and "Go back" (J18). Account reachable from the nav (J16). |
| UI consistency | 8 | 8 | Baseline: One CSS token system; consistent cards, accordions, pills and danger zones. **S1 result:** Typed confirmation banners (success and error), consistent rename popovers and danger zones. |
| Visual quality | 8 | 8 | Baseline: Screenshots at 1280/390 px in light and dark mode. **S1 result:** Screenshots of the account page, rename popover, 404 page and phone device page reviewed. |
| Performance | 9 | 9 | Baseline: Local server medians of 1–2 ms on all pages; network page HTML 9.5 KB, DCL 15 ms; static assets cached and hashed. **S1 result:** Unchanged: medians 1–2 ms; network page HTML 10.1 KB, DCL 6–16 ms (J14). |
| Accessibility | 6 | 9 | Baseline: axe: `color-contrast` (serious) on 10/10 pages, `link-in-text-block` on 6, `heading-order` on the guide; 14 targets under 24 px on the phone device page. **S1 result:** axe: 0 violations on 10 pages in light mode and 9 pages in dark mode, including the new account and 404 pages. Remaining targets under 24 px are inline text links and radios inside larger labels (WCAG 2.5.8 exempt). |
| Reliability | 7 | 8 | Baseline: 500 error on signup with a password over 72 bytes; bare 404 page; duplicate device names accepted. **S1 result:** 500 error on long passwords fixed (test); duplicate device names rejected (test); live views report a lost session instead of silently freezing. |
| Security | 6 | 8 | Baseline: No login brute-force protection (26 wrong attempts, all 401, J4); no HSTS in production. IDOR checks pass (8/8 return 404, J9); CSRF and CSP are in place. **S1 result:** Login lockout (26th attempt returns 429, J4) and per-IP limits on sign-up and all token endpoints (tests); HSTS on https; password change signs out other sessions; govulncheck reports no vulnerabilities. IDOR still 8/8 return 404 (J9). |
| Mobile usability | 8 | 8 | Baseline: J11: QR code at 277 px on a phone; devices shown as cards; no horizontal overflow on any page. **S1 result:** Unchanged layout; copy buttons fully visible on touch screens; toggles keep their markers. |
| Overall product quality | 7 | 8 | Baseline: Weighted judgement of the rows above. **S1 result:** All P1 issues and every P2 issue from session 1 verified. |

---

## C. Prioritized Improvement Backlog

Score = Impact × Frequency × Confidence / Effort. Statuses follow §3.2 of the process prompt.

| ID | Title | Cat. | P | I | F | C | E | Score | Status | Session |
|---|---|---|---|---|---|---|---|---|---|---|
| SEC-001 | No brute-force protection on login, signup and token endpoints | Security | P1 | 5 | 3 | 5 | 2 | 37.5 | Verified | S1 |
| BUG-001 | Signup with a password over 72 bytes returns HTTP 500 | Reliability | P1 | 3 | 2 | 5 | 1 | 30 | Verified | S1 |
| A11Y-001 | Text and links fail WCAG AA contrast (accent on soft backgrounds, eyebrow, footer) | Accessibility | P1 | 4 | 5 | 5 | 1 | 100 | Verified | S1 |
| A11Y-002 | Links inside text are only distinguishable by color | Accessibility | P2 | 3 | 5 | 5 | 1 | 75 | Verified | S1 |
| UX-001 | Unknown URLs show a bare "404 page not found" without layout or way back | UX | P2 | 3 | 2 | 5 | 1 | 30 | Verified | S1 |
| UX-002 | Duplicate device names are accepted, so two "my laptop" rows look identical | UX | P2 | 3 | 3 | 5 | 1 | 45 | Verified | S1 |
| UX-003 | Devices and networks can't be renamed (typos are permanent) | UX | P2 | 3 | 3 | 5 | 2 | 22.5 | Verified | S1 |
| UX-004 | No account page: users can't change their password or delete their account | UX/Security | P2 | 4 | 2 | 5 | 2 | 20 | Verified | S1 |
| UX-005 | An invited user (share link) gets no feedback when their device connects | UX | P2 | 4 | 3 | 4 | 2 | 24 | Verified | S1 |
| SEC-002 | No `Strict-Transport-Security` header in production | Security | P2 | 3 | 5 | 5 | 1 | 75 | Verified | S1 |
| A11Y-003 | Copy buttons and similar controls are smaller than 24 × 24 px (WCAG 2.5.8) | Accessibility | P2 | 2 | 4 | 4 | 1 | 32 | Verified | S1 |
| A11Y-004 | Heading levels skip in the setup guide (h2 → h4) | Accessibility | P3 | 2 | 4 | 5 | 1 | 40 | Verified | S1 |
| UX-006 | Focus is lost after creating a network (URL fragment suppresses autofocus) | UX | P3 | 2 | 4 | 4 | 1 | 32 | Verified | S1 |
| UX-007 | Important values (DNS name, address, endpoint) need manual text selection to copy | UX | P3 | 2 | 4 | 4 | 1 | 32 | Verified | S1 |
| UX-008 | A full network can't be resized; the only option is to delete and recreate | UX | P3 | 3 | 1 | 4 | 4 | 3 | Deferred | S1 |
| UX-009 | No password reset ("forgot password") | UX | P3 | 4 | 1 | 5 | 4 | 5 | Deferred | S1 |
| UX-010 | After adding a device there's no direct way to add the next one | UX | P2 | 3 | 3 | 5 | 1 | 45 | Verified | S1 |
| REL-001 | Live status freezes silently when the session expires | Reliability | P2 | 2 | 2 | 5 | 1 | 20 | Verified | S1 |
| UX-011 | Power users have no keyboard shortcuts (e.g. "n" for a new device, "/" for the nav) | UX | P3 | 2 | 2 | 3 | 2 | 6 | Discovered | S1 |
| UX-012 | Connected devices still lead with a large QR code; experienced users come for status, HTTPS and sharing | UX | P3 | 2 | 3 | 3 | 2 | 9 | Discovered | S1 |
| SEC-003 | Sign-up reveals whether an email is registered ("An account with this email already exists") | Security | P3 | 2 | 2 | 5 | 3 | 6.7 | Discovered | S1 |
| A11Y-005 | On phones, "Share onboarding" comes before the setup guide (source order of the two-column layout) | Accessibility/UX | P3 | 2 | 3 | 4 | 2 | 12 | Discovered | S1 |
| ARCH-001 | Rate limits are in memory: they reset on restart and won't work with more than one replica | Architecture | P3 | 2 | 1 | 5 | 3 | 3.3 | Deferred | S1 |
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
| 1 | SEC-001 | P1 | Accounts can't be brute-forced | 2 | Verified | – |
| 2 | BUG-001 | P1 | Long passphrases work instead of a 500 | 1 | Verified | – |
| 3 | A11Y-001 | P1 | Readable text and links for low-vision users | 1 | Verified | – |
| 4 | A11Y-002 | P2 | Links recognizable without color | 1 | Verified | A11Y-001 |
| 5 | SEC-002 | P2 | HTTPS enforced by browsers | 1 | Verified | – |
| 6 | UX-001 | P2 | Lost users find their way back | 1 | Verified | – |
| 7 | UX-002 | P2 | No more indistinguishable devices | 1 | Verified | – |
| 8 | UX-006, A11Y-004, A11Y-003 | P3/P2 | Focus, structure and touch-target polish | 1 | Verified | – |
| 9 | UX-005 | P2 | Invited users see they're connected | 2 | Verified | – |
| 10 | UX-003 | P2 | Fix typos in device and network names | 2 | Verified | UX-002 |
| 11 | UX-004 | P2 | Change password, delete account | 2 | Verified | SEC-001 |
| 12 | UX-007 | P3 | One-click copy of key values | 1 | Verified | – |
| 13 | UX-010, REL-001 | P2 | Chained device creation; lost-session notice | 1 | Verified | – |

The session 1 queue is complete. The next queue is in section H.

## E. Completed Improvements

All of these were completed on 2026-11-21 (session 1).
Shared validation for every item:
- `go vet ./...` and `go test -count=1 ./...` pass.
- The final run of `tests/e2e/journeys.mjs` and `journeys-features.mjs` on a fresh database had no JS errors.
- axe reports zero violations in light and dark mode.

The commits are local only (`9a08170`, `109effc` and the session-close commit). They are **not pushed or deployed**, per the session rules.

| ID | Problem | Solution | Files | Tests / validation | Measured result |
|---|---|---|---|---|---|
| SEC-001 | Unlimited password guessing | Sliding-window limiter: 10 failed logins per account and 30 per IP per 15 min; 10 sign-ups per IP per hour; 30 invalid tokens per IP per 15 min (share links, join status, cert fetch, acme-dns). Locked requests get 429 with `Retry-After` and a readable message. Password checks on the account page count too. | `internal/web/ratelimit.go`, `handlers.go`, `dns.go`, `certs.go`, `account.go` | `TestLimiterWindow`, `TestClientIP`, `TestLoginLockout`, `TestShareTokenGuessingIsLimited`; J4 | 26 wrong attempts: before all 401, after 429 |
| BUG-001 | 500 error for passwords over 72 bytes | `passwordProblem` (10–72 bytes) with a clear message, `maxlength=72`, and over-long logins treated as wrong | `handlers.go`, `signup.html` | `TestPasswordProblem`, `TestPasswordLimits` | 100-char password: before 500, after 400 with message |
| SEC-002 | No HSTS | `Strict-Transport-Security: max-age=31536000` when `BASE_URL` is https | `server.go` | `TestFriendly404AndHSTS` | Header present on https, absent on http |
| A11Y-001 | Contrast failures on every page | Light accent `#2f6df6` → `#2459d8` (≥5.2:1 on all surfaces); success green `#138a4b` → `#0e7340` (5.2:1); dark accent `#6b98ff`, dark button `#3366e6`; banner animation no longer fades opacity | `app.css` | axe (light and dark) | Pages with `color-contrast` violations: 10/10 → 0 |
| A11Y-002 | Links distinguishable only by color | Underline links in paragraphs, lists, breadcrumbs, helper text, alerts and the footer | `app.css` | axe | `link-in-text-block`: 6 pages → 0 |
| A11Y-003 | Targets under 24 px | Copy buttons at least 28 × 44 px, toggles padded, flash close 28 px | `app.css` | J11 | 14 → 7 (all 7 are WCAG-exempt inline links or radios inside larger labels) |
| A11Y-004 | Heading levels skipped | Step titles h4 → h3 in guides, ACME recipes and the DNS explainer | `cookbooks.html`, `acme.html`, `dns.html`, `app.css` | axe | `heading-order` → 0 |
| UX-001 | Bare Go 404 | Catch-all route renders the status page inside the layout, with "Your networks" or the home page plus "Go back" | `server.go`, `status.html`, `app.js` | `TestFriendly404AndHSTS`; J13, J18 | "404 page not found" → styled page with navigation |
| UX-002 | Duplicate device names | Case-insensitive uniqueness per network, with a message and the input kept | `handlers.go` | `TestDuplicateDeviceName`; J5 | Duplicate now rejected |
| UX-003 | Names can't be changed | "Rename" popover on the network and device pages (focus and select, Escape or click outside closes); display name only, so hostname, IP and configs stay. Success and error banners. | `store.go`, `handlers.go`, `server.go`, `render.go`, `network.html`, `device.html`, `app.js`, `app.css` | `TestRename` (including IDOR); J15 and a keyboard-only check | 1 click + type + Enter |
| UX-004 | No account self-service | `/account` linked from the nav email: change password (current password required; other sessions revoked) and delete account (typed email plus password; cascading delete; hub re-synced so keys are revoked immediately) | `account.go`, `account.html`, `store.go`, `layout.html`, `render.go` | `TestAccountPasswordAndDelete`; J16 | – |
| UX-005 | Invitees get no success signal | Token-authenticated `GET /join/{token}/status` (only that device's online state; rate-limited); the join page reuses the live pill and "connected" banner | `handlers.go`, `server.go`, `device.html` | `TestJoinStatus`; J17 | Join page now polls and shows "connected" |
| UX-006 | Focus lost after creating a network | Restore `[autofocus]` after load when the URL has a fragment; links to `#add`/`#create` focus the first field | `app.js`, `network.html`, `networks.html` | J1 (`focus=name`); "Add another device" check | focus BODY → device-name field |
| UX-007 | Copying values needs manual selection | Inline "Copy" next to address, DNS name and hub endpoint (shown on hover or focus on desktop, always on touch) | `device.html`, `app.css` | Manual and screenshot check | 1 click instead of select + copy |
| UX-010 | Adding several devices needs repeated navigation | The "device is ready" banner offers "+ Add another device" while slots are free, landing in the focused name field | `device.html`, `handlers.go`, `app.js` | `TestAddAnotherDeviceOffer`; browser check | Saves 1 navigation and 1 click per extra device |
| REL-001 | Live views freeze silently after logout or expiry | A 401 from a status poll stops polling and shows "You have been signed out… Log in again" (keeps `next`) | `app.js` | Browser check (cookie cleared → notice after 5 s) | – |
| (process) | No repeatable UX evidence | Journey scripts and a local runner moved into the repo | `tests/e2e/*` | Ran from the repo location against a fresh instance | – |

## F. Deferred and Blocked Improvements

| ID | Reason | Dependencies | Effort | Recommended next action |
|---|---|---|---|---|
| UX-008 | Resizing a network needs a migration path: a new subnet, re-addressing devices and re-distributing configs. That breaks connected devices unless done carefully. | IPAM changes; a per-device "config changed" notice | 4 | Design "grow network" that allocates a larger block and shows every device a "download new config" prompt |
| UX-009 | Password reset needs outbound email (SMTP or provider) and token flows; no mail infrastructure exists | Mail service, secret management | 4 | Decide on a mail provider first. Meanwhile the account page gives signed-in users self-service. |
| ARCH-001 | Fine for the current single-replica deployment | Shared store (SQLite table or Redis) | 3 | Only needed if privnet ever runs more than one replica |
| Deploy | Session rules forbid pushing or deploying without explicit authorization | Owner approval | 1 | Owner reviews the local commits, then `git push` and `deploy/deploy.sh` |

## G. Session History

### Session 1, 2026-11-21

- **Duration:** about 35 minutes of wall-clock execution (20:33–21:08 CET), not eight hours.
- **Scope:** the improvement process was started here. It follows several earlier, unstructured UX passes in the same conversation (accordions, a first UX pass, the HTTPS feature).
- **Areas inspected:**
  - all templates, `app.js` and `app.css`;
  - the web handlers: auth, sessions, CSRF, security headers, token endpoints;
  - the store schema;
  - production response headers;
  - dependencies (govulncheck).
- **Journeys tested:** J1–J18 (see `tests/e2e/README.md`), covering first-time, regular and power-user flows, phone (390 px), desktop (1280 px), dark mode, keyboard-only and anonymous invitee. Measured clicks, inputs, page loads and times.
- **Issues discovered:** 23, including 7 new low-priority ones recorded at the end of the session.
- **Implemented and verified:** SEC-001, SEC-002, BUG-001, A11Y-001 to A11Y-004, UX-001 to UX-007, UX-010, REL-001.
- **Deferred:** UX-008, UX-009, ARCH-001.
- **Blockers:** none technical. Deployment waits for owner approval.
- **Regressions found and fixed during validation:**
  - a hidden username field became visible;
  - disclosure markers disappeared;
  - the banner animation lowered contrast while axe measured;
  - invalid `listitem` roles on links;
  - an empty table header.
- **Recommended next priorities:** see H.

## H. Next Eight-Hour Session Plan

Start by reading this file. Then run `tests/e2e/run-local.sh` and both journey scripts to confirm there are no regressions from session 1.

1. **Deploy check (with owner approval):** verify HSTS, the lockout and the new pages in production. Recheck the scorecard against production headers.
2. **UX-012:** for connected devices, lead with status and actions (HTTPS, share, rename) and move the QR code and config into a collapsible "Connect another time" panel. Validate J11 and J2.
3. **A11Y-005:** fix the reading order on phones so the setup guide comes before share onboarding (reorder the markup with CSS grid areas).
4. **UX-008:** design and implement "grow network" (bigger block, devices prompted to re-download configs). Needs careful IPAM tests.
5. **UX-011:** add keyboard shortcuts for power users, documented in a "?" overlay. Make sure they don't fire inside inputs, and check them with axe.
6. **SEC-003:** soften email enumeration at sign-up (generic message plus rate limit), weighed against clarity for legitimate users.
7. **Audit areas not yet covered:**
   - the DNS zone page and ACME recipe tabs on phones;
   - the HTTPS proxy flow end to end (needs production or a staging CA);
   - screen-reader passes (VoiceOver) of the device and join pages;
   - very long names and Unicode in device and network names;
   - many networks (pagination is not needed below 16 devices per network).
8. **Process:** turn `tests/e2e` into a CI job (Chrome, axe) so contrast and journey regressions fail the build.
