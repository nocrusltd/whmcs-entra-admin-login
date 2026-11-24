# Security review and penetration test report

| | |
|---|---|
| **Date of testing** | 24 November 2026 |
| **Target of record** | The `entra_admin_login` addon source in this repository, and the project owner's production WHMCS deployment of it (hostnames and identifiers redacted; recorded in the owner's engagement notes) |
| **Authorization** | The owner of the application commissioned this review and confirmed written permission to test the production deployment |
| **Test type** | White-box source review (full read of all addon code) plus grey-box external penetration testing over HTTPS, in two rounds (see §2.2) |
| **Overall result** | **No exploitable vulnerabilities found in the addon.** All findings are deployment hardening items and low-severity observations |
| **Findings** | 2 Medium, 2 Low, 4 Informational (one of the Informational items is already fixed in code; see the table) |

> **Redaction note.** This report is published in an open-source repository. Hostnames, URLs, tenant and client identifiers, certificate details, and other deployment specifics are deliberately omitted. Where a finding only applies to the owner's server configuration rather than to the addon, the affected component is described generically.

---

## 1. Executive summary

The addon implements a single-tenant OpenID Connect sign-in flow (authorisation code + PKCE, public client) that logs a WHMCS administrator in with a Microsoft Entra ID identity. Flows of this kind carry a concentrated set of risks: ID-token forgery, cross-tenant token confusion, state/CSRF abuse, session fixation, and account-link hijacking.

The review found **no way to exploit any of these**. The token validation is strict and fails closed on every check; the sign-in state is bound to the server-side session, is single-use, and expires; the linking flow re-verifies the administrator's session at callback time; and existing account links can never be silently replaced. Live testing confirmed that each of these controls behaves as written against the production deployment — including, in a second round, waiting out the full 600-second flow expiry against the clock and firing eleven genuine failed admin logins to test for lockout behaviour.

The findings that did come out of the engagement concern the surrounding server configuration (transport security headers, cookie attributes, and the admin folder's default name) rather than the addon. None of them enables a working attack on their own; they reduce the value of other controls and are worth fixing, in the order given in §6. The most substantive of them is the absence of any observed rate limiting on the admin login handler. A WAF sits in front of the deployment and blocked every injection signature attempted, but a signature filter is not a rate limiter.

## 2. Scope and methodology

### In scope

- Every source file of the addon (the `modules/addons/entra_admin_login/` tree and `tests/run.php`), read in full.
- The deployed addon's sign-in endpoint and its behaviour over unauthenticated HTTP(S).
- The WHMCS admin login surface as it relates to the addon (error handling, CSRF enforcement, unauthenticated redirects, response headers, TLS).
- Attempts to forge, replay, or cross-session the OIDC callback; to start or complete an account link without credentials; to inject markup through any parameter; and to access internal files directly.

### Out of scope

- WHMCS core beyond the checks above (not the owner's code).
- Client-area functionality.
- Brute-force or denial-of-service testing *beyond* the eleven-attempt lockout probe described in §2.2 (no sustained brute force, no rate-limit bypass attempts, no load testing — these remain excluded by design even after the scope was widened).
- Source-level review of WHMCS internals used by the addon (`WHMCS\Auth` methods); their presence and failure modes were checked instead.

### Method

1. **Full source review.** All addon code read line by line, with specific attention to: JWT algorithm pinning, issuer/tenant/audience binding, nonce and state comparison, PKCE construction, key-set handling, session lifecycle, CSRF coverage of every state-changing action, output escaping, log hygiene, file-write atomicity, and failure behaviour (fail-open vs fail-closed).
2. **Live external testing** over HTTPS with a command-line HTTP client, replaying crafted requests against the deployed endpoint: flow initiation, forged callbacks, valid-state callback with a bogus code, state replay, link-flow attempts over GET and POST with and without a CSRF token, reflected-parameter injection attempts, direct file access, directory listing, unauthenticated access to the admin area, error-response disclosure, and TLS/transport inspection.

### 2.2 Round two (same day) — expanded scope and blocking actions

After the first pass, the owner authorised broadening the attack surface and performing the blocking tests that round one had deliberately withheld. Round two added:

- **Blocking tests.** A burst of eleven consecutive genuine failed admin logins — each with a freshly valid CSRF token, against a randomly generated nonexistent username, so no real account was touched — accepting that the testing IP itself might end up temporarily blocked. Also a real 620-second wait to exercise the sign-in flow's expiry against the clock, rather than by source review alone.
- **Parameter manipulation.** HTTP parameter pollution and PHP type juggling against the callback's `is_string` guards (`state[]=`, `code[]=`, duplicated parameters), CRLF/newline injection into the redirect path, and 8 KB oversized parameters.
- **Session manipulation.** Pre-setting a client-chosen session cookie value and confirming the sign-in flow binds its state under it (session-fixation surface), and whether the server keeps or rotates a client-supplied ID.
- **Header-level attacks.** Host-header injection against the sign-in endpoint (routed to the server IP with a foreign `Host`), and CORS reflection via a foreign `Origin`.
- **Enclave characterisation.** Identifying and probing the WAF in front of the deployment: its trigger conditions, whether blocks are per-request or IP-wide, and four standard bypass attempts (mixed case, nested tag, `svg onload`, quote-breakout).
- **Timing oracle.** Response-time comparison on the admin login handler between a likely-existing and a nonexistent username.
- **Reflection audit.** The WHMCS admin `redirect` parameter, echoed into the login form, checked for quote breakout.

## 3. Findings summary

| ID | Title | Severity | Component | Status |
|---|---|---|---|---|
| SEC-001 | No HTTP Strict Transport Security (HSTS) | Medium | Deployment | Open |
| SEC-002 | Missing security headers on the WHMCS admin area | Low | Deployment | Partially fixed — the addon's endpoint now sends its own headers (merged PR); the admin area still needs server-level headers |
| SEC-003 | Session cookie has no SameSite attribute | Low | Deployment | Open |
| SEC-004 | Admin area uses the WHMCS default folder name | Informational | Deployment | Open |
| SEC-005 | No rate limiting observed on admin login | Medium | Deployment | Open |
| SEC-006 | Admin username not passed through the log sanitiser | Informational | Addon | **Fixed** — sanitised in a merged PR on the day of testing |
| SEC-007 | PHP session IDs accepted from clients | Low | Deployment | Open |
| SEC-008 | `redirect` parameter reflected into the login form | Informational | WHMCS core | Open (escaped; post-login handling unverified) |

## 4. Detailed findings

### SEC-001 — No HTTP Strict Transport Security (HSTS)

**Severity:** Medium · **Component:** Deployment · **Status:** Open

**Description.** No `Strict-Transport-Security` header is returned on any response, and it is absent from the HTTPS host's response set as a whole. Plain-HTTP requests are redirected to HTTPS with a `301`, which is correct, but the redirect only helps a client that reaches the genuine server. A network-position attacker can strip or intercept the *first* plaintext request (or a manually typed `http://` URL) before the redirect is ever seen. The admin area is the highest-value target on the deployment and is the page users type from memory.

**Evidence.** Header inspection of the admin login page and the sign-in endpoint responses over HTTPS showed transport-security headers absent. Plain HTTP returned a `301` redirect to HTTPS.

**Impact.** On the first plaintext visit, an active man-in-the-middle could capture or alter an admin authentication interaction. No exploit was attempted (this would require a network position and interception testing was out of scope).

**Remediation.** Serve `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses, at the web-server level. Begin with a shorter `max-age` if roll-out risk is a concern, then raise it.

---

### SEC-002 — Missing security headers on the WHMCS admin area

**Severity:** Low · **Component:** Deployment · **Status:** Partially fixed

**Description.** The WHMCS admin area responses carry no `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Permissions-Policy`. The login page can therefore be framed by any origin, and content-type sniffing is not disabled.

> **Update (round two).** The addon's own endpoint now sends `X-Content-Type-Options`, `X-Frame-Options: DENY` and a restrictive CSP, and this was verified live on the deployment. The WHMCS admin area at large (rendered by WHMCS core, whose headers the addon cannot control) remains without them, so the finding stays open at the server level.

**Impact.** Clickjacking against a framed admin login is of limited practical value (the attacker cannot read the submitted credentials, and the OIDC callback is protected by server-side state), but it can be used for touch-redirection or forced-interaction tricks. Without `nosniff`, a mis-set `Content-Type` on any future endpoint becomes easier to abuse. These are cheap, standard hardening headers.

**Remediation.** Add at the web-server level, for the admin area at minimum: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, a restrictive `Permissions-Policy`, and a CSP that allows only what the admin template needs. Include the addon's sign-in endpoint (its error page is static markup and needs nothing beyond `frame-ancestors`/`default-src`).

---

### SEC-003 — Session cookie has no SameSite attribute

**Severity:** Low · **Component:** Deployment · **Status:** Open

**Description.** The PHP session cookie is issued with `Secure` and `HttpOnly` (good) but no `SameSite` attribute, so behaviour depends on each browser's default. Modern browsers treat a missing attribute as `Lax`, which is adequate for this design: the OIDC callback is a top-level GET navigation (sent under `Lax`), and every state-changing POST carries a CSRF token. But `Lax` is a compatibility default, not a stated policy, and older browsers fall back to sending the cookie unrestrictedly.

**Impact.** No demonstrated issue: CSRF-relevant actions are token-protected (verified live, see SEC-006's adjacent tests in §5) and the sign-in flow's state is server-bound. This is defence-in-depth.

**Remediate** by setting `session.cookie_samesite = Lax` in the PHP configuration (WHMCS's admin area does not need third-party embedding). Do not use `Strict` here: the OIDC callback arrives as a cross-site top-level GET navigation, and `Strict` would drop the session cookie on it and break sign-in.

---

### SEC-004 — Admin area uses the WHMCS default folder name

**Severity:** Informational · **Component:** Deployment · **Status:** Open

**Description.** The admin area is served under WHMCS's default admin folder name, reachable at a predictable path. Mass scanners and opportunistic attackers enumerate these paths first. WHMCS supports a custom admin path, and the addon already handles it correctly (see `entra_admin_login_admin_folder()`, which reads `$GLOBALS['customadminpath']`, and the relative link generated by `LoginPageButton`).

**Impact.** None on its own — a renamed folder is obscurity, not a security boundary, and the admin area remains protected by authentication regardless of its name. It reduces log noise and casual targeting.

**Remediation.** Optional. Rename the admin folder and set the custom admin path per WHMCS documentation; the addon requires no changes to support this.

---

### SEC-005 — No rate limiting observed on admin login

**Severity:** Medium · **Component:** Deployment · **Status:** Open

**Description.** Round one withheld this test by design (§2). In round two, eleven consecutive genuine failed logins were submitted to the admin login handler — each with a freshly valid CSRF token (verified present, 40 characters, and confirmed to reach the credential check by the `invalid` flag in the response redirect), using a randomly generated nonexistent username so no real account was affected. All eleven attempts were processed: the same failure redirect each time, no HTTP 429 or delay, no CAPTCHA challenge, no temporary IP ban, and no lockout message. The admin area remained fully reachable immediately afterwards.

**Impact.** The admin credential endpoint — the highest-value surface on the deployment — appears to accept unlimited online guessing attempts, subject only to a WAF that filters by payload *signature* rather than rate. Password strength is therefore the sole control against brute force. Since usernames are not enumerable (generic error, no timing oracle — see §5), guesses would need to cover both username and password space, which raises the cost of a real attack considerably; the rating is Medium rather than High for that reason.

**Remediation.** Enable admin login failure throttling in *System Settings → Security Policy* (WHMCS ships it; it does not appear to be active here), and alert on admin login failures. A server-level rate limit on the admin login handler as a second layer would also cover token-less guessing (which is rejected by CSRF checks but not counted as a failure by WHMCS).

---

### SEC-006 — Admin username not passed through the log sanitiser

**Severity:** Informational · **Component:** Addon (`login.php`) · **Status:** Fixed

**Description.** Token-derived text was sanitised before it reached the WHMCS activity log (`LogText::clean`), but two log calls interpolated `$admin->username` straight from the database: the "disabled admin" rejection and the successful sign-in message.

**Impact.** Negligible as written: admin usernames are created by other admins, so an attacker who could set a malicious username already had admin access. It was an invariant violation, not an exploitable path.

**Resolution.** Both call sites now wrap the username in `LogText::clean()`, merged to `main` and **verified live-deployed** during this engagement (the deployed endpoint matches the fixed source). No further action.

---

### SEC-007 — PHP session IDs accepted from clients

**Severity:** Low · **Component:** Deployment · **Status:** Open

**Description.** Round two probed session handling: a session cookie value chosen by the tester was supplied to the server, a sign-in flow was started under it, and the flow's state was stored and then accepted on callback under that same client-chosen ID. A subsequent request confirmed the server *keeps* a client-supplied ID rather than rotating it. This is PHP's default behaviour with `session.use_strict_mode` off: the session layer will instantiate a session for any ID a client presents.

**Impact.** This is the classic session-fixation surface. It is **mitigated on the addon's path**: `AdminSession::start()` calls `session_regenerate_id(true)` at the privilege change, so an ID fixed before sign-in is discarded when the admin session is created. The residual risk is in anything else that trusts a pre-authenticated session ID, including WHMCS core paths outside this review's scope, and any future code that forgets to regenerate.

**Remediation.** Set `session.use_strict_mode = 1` in the PHP configuration: the server then rejects unknown client-supplied session IDs and issues fresh ones, closing the fixation surface platform-wide. Test the sign-in round-trip afterwards (some applications subtly depend on lax IDs).

---

### SEC-008 — `redirect` parameter reflected into the login form

**Severity:** Informational · **Component:** WHMCS core · **Status:** Open (unverified)

**Description.** The WHMCS admin login page echoes its `redirect` query parameter into a hidden form field on the rendered page, and it accepts absolute URLs in that parameter (`https://…` and protocol-relative `//…` were both accepted at render time). Output escaping **is** applied — a single quote in the value was rendered as `&#039;`, and no quote breakout was possible, so there is no reflected XSS here (and the WAF independently blocked every markup payload attempted). What could not be verified without credentials is whether the value is validated *after* a successful login, when the handler acts on it.

**Impact.** None demonstrated. If the post-login handler does not validate the target, a phished link of the form `login.php?redirect=//attacker/…` would bounce a freshly authenticated admin to an attacker site — a credential-harvesting tail for a social-engineering attack. Modern WHMCS validates this parameter on use, but that could not be confirmed on this deployment.

**Remediation.** The owner should log in once via a link with a benign absolute `redirect` value and observe where the browser lands; if it leaves the WHMCS origin, report it to WHMCS support (it is core behaviour, not addon code).

## 5. Controls verified (source review and live testing)

All of the following behaved correctly under live adversarial requests. Each row names the control, where it lives, and how it was exercised.

| Control | Where | Verified by |
|---|---|---|
| State is bound to the server session and compared in constant time | `login.php`, `hash_equals` on stored vs. supplied state | Forged callback with an arbitrary state → rejected without touching the stored flow |
| State is single-use | `login.php`, flow unset after a match | Live flow: first callback consumed it; replay of the same callback → "invalid or was already used" |
| Flow expires | `login.php`, 600 s TTL | Source review (waiting out the TTL was not repeated live) |
| A valid state does not bypass token validation | `IdTokenValidator` | Callback with a valid state and a bogus code → live token-endpoint redemption failed → "could not be verified" |
| JWT algorithm pinned | `IdTokenValidator`, `alg` must be `RS256` | Source review; no `none`/`HS256` confusion path exists |
| Issuer, tenant and audience bound to configuration | `iss`, `tid`, `aud` claims | Source review |
| Freshness enforced | `exp`/`nbf`/`iat` with bounded clock skew | Source review |
| Nonce single-use and constant-time | `hash_equals` on the flow nonce | Source review |
| Key set fetched per tenant, not from the common endpoint | `OidcClient::signingKeys` | Source review — prevents cross-tenant key confusion |
| Signing keys constrained to RSA ≥ 2048 | `Jwks` | Source review |
| PKCE S256 with the verifier server-side | `OidcClient` | Source review + live authorize redirect carries only the challenge |
| Linking requires POST + CSRF token + admin session | `login.php` `action=link` | GET → refused; POST without token → WHMCS CSRF rejection |
| Link callback re-verifies the current admin | `entra_current_admin_id() === $flow['admin_id']` | Source review |
| Existing links are never silently replaced | `Links::link` transaction | Source review |
| Identity matched on immutable (tenant, object ID), not email | `Links` | Source review |
| Session ID regenerated at privilege change | `AdminSession::start`, `session_regenerate_id(true)` | Source review — kills pre-sign-in fixation |
| No open redirect | All redirects derive from the configured System URL | Source review; no user-controlled URL reaches `Location` |
| No markup injection via request parameters | `LogText::clean`, fixed-string messages, `htmlspecialchars` on all output | Injection attempts in `state`, `error`, `error_description` → no reflection |
| Direct file access harmless | `entra_admin_login.php` guard; lib files define classes only | Fetched directly → guard message / empty output; no listing on the folder |
| Admin area not bypassable | WHMCS core | Unauthenticated request to the addon page → redirect to login |
| Deactivation fails closed | `Settings::isActive` via the version row | Source review |
| Template write is atomic | temp file + rename, permissions preserved | Source review |
| Flow expires after 600 s | `login.php` TTL check | **Live**: flow started, state captured, callback replayed after a real 620 s wait → "took too long" rejection |
| No type-juggling/HPP bypass | `is_string` guards on `state`/`code` | **Live**: `state[]`, `code[]`, duplicated params all rejected as invalid state |
| No CRLF injection into responses | `header()` inputs not user-derived | **Live**: CRLF sequence in `state` → rejected, no header reflected |
| Oversized parameters handled | server / PHP limits | **Live**: 8 KB URL → server `414` error page, no crash |
| `error` params sanitized with a valid state | `login.php` error branch | **Live**: valid state + `error` + hostile `error_description` → flow consumed, sanitised fixed-string message shown |
| No username enumeration via response time | WHMCS login handler | **Live**: likely-existing vs nonexistent username, overlapping response times (no oracle at this sample size) |
| No host-header injection into the app | addon uses the stored System URL | **Live**: foreign `Host` → server default-vhost 404, app never saw the request |
| No CORS reflection | responses to foreign `Origin` | **Live**: no `Access-Control-Allow-Origin` on any endpoint probed |
| WAF present and not bypassed | server-level | **Live**: signature blocks on all four XSS bypass attempts (mixed case, nested tag, `svg onload`, quote-breakout); blocking is per-request, not a lasting IP ban |
| Session regeneration at privilege change | `AdminSession::start` | Source review + **live** confirmation that the pre-auth session layer itself is lax (see SEC-007) |

## 6. Remediation priority

1. **SEC-001 (HSTS)** — one header, removes the first-visit downgrade class. Do this first.
2. **SEC-005 (admin login rate limiting)** — enable WHMCS's shipped admin login failure throttling and alert on failures; this is the only finding that leaves a credential endpoint unthrottled.
3. **SEC-002 (security headers on the admin area)** — same effort class as SEC-001; the addon's own endpoint is already covered.
4. **SEC-007 (`session.use_strict_mode = 1`)** — one PHP setting; test the full sign-in round-trip afterwards.
5. **SEC-003 (SameSite=Lax)** — one PHP setting alongside SEC-007.
6. **SEC-008** — one manual verification by the owner (log in via a crafted `redirect` link, observe the landing point).
7. **SEC-006** — done, merged and verified deployed during the engagement.
8. **SEC-004** — optional, purely to reduce scanner noise.

## 7. Limitations

- Time-boxed to a single day; a longer engagement would repeat the lockout tests against a staging instance rather than production.
- WHMCS core was treated as a trusted dependency, not reviewed in source; SEC-008's post-login behaviour could not be exercised without credentials.
- Failed-login testing was limited to eleven attempts against a nonexistent account. Sustained brute force — enough to exhaust any configured thresholds — was still excluded by design, so a throttle configured above that count could not be ruled out (though WHMCS's shipped default is well below it).
- The round-two session probe demonstrated the fixation *surface* but not a completed fixation attack: finishing one would require a real sign-in and a cooperating victim.
- Browser-level testing (UI redressing, DOM-based issues in the admin area's JavaScript) was not performed; the addon itself ships no client-side script beyond a static link.
- A merged PR landed mid-engagement (log sanitisation + endpoint headers); findings were re-checked against the updated code and the updated deployment as noted.
