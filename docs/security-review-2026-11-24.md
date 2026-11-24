# Security review and penetration test report

| | |
|---|---|
| **Date of testing** | 24 November 2026 |
| **Target of record** | The `entra_admin_login` addon source in this repository, and the project owner's production WHMCS deployment of it (hostnames and identifiers redacted; recorded in the owner's engagement notes) |
| **Authorization** | The owner of the application commissioned this review and confirmed written permission to test the production deployment |
| **Test type** | White-box source review (full read of all addon code) plus grey-box external penetration testing over HTTPS |
| **Overall result** | **No exploitable vulnerabilities found in the addon.** All findings are deployment hardening items and low-severity observations |
| **Findings** | 1 Medium, 2 Low, 3 Informational (deployment); 1 Informational (code nit) |

> **Redaction note.** This report is published in an open-source repository. Hostnames, URLs, tenant and client identifiers, certificate details, and other deployment specifics are deliberately omitted. Where a finding only applies to the owner's server configuration rather than to the addon, the affected component is described generically.

---

## 1. Executive summary

The addon implements a single-tenant OpenID Connect sign-in flow (authorisation code + PKCE, public client) that logs a WHMCS administrator in with a Microsoft Entra ID identity. Flows of this kind carry a concentrated set of risks: ID-token forgery, cross-tenant token confusion, state/CSRF abuse, session fixation, and account-link hijacking.

The review found **no way to exploit any of these**. The token validation is strict and fails closed on every check; the sign-in state is bound to the server-side session, is single-use, and expires; the linking flow re-verifies the administrator's session at callback time; and existing account links can never be silently replaced. Live testing confirmed that each of these controls behaves as written against the production deployment.

The findings that did come out of the engagement concern the surrounding server configuration (transport security headers, cookie attributes, and the admin folder's default name) rather than the addon. None of them enables a working attack on their own; they reduce the value of other controls and are worth fixing, in the order given in §6.

## 2. Scope and methodology

### In scope

- Every source file of the addon (the `modules/addons/entra_admin_login/` tree and `tests/run.php`), read in full.
- The deployed addon's sign-in endpoint and its behaviour over unauthenticated HTTP(S).
- The WHMCS admin login surface as it relates to the addon (error handling, CSRF enforcement, unauthenticated redirects, response headers, TLS).
- Attempts to forge, replay, or cross-session the OIDC callback; to start or complete an account link without credentials; to inject markup through any parameter; and to access internal files directly.

### Out of scope

- WHMCS core beyond the checks above (not the owner's code).
- Client-area functionality.
- Brute-force or denial-of-service testing (attempted logins were limited to two single bogus credentials against a randomly generated nonexistent username; no rate-limit bypass was pursued).
- Source-level review of WHMCS internals used by the addon (`WHMCS\Auth` methods); their presence and failure modes were checked instead.

### Method

1. **Full source review.** All addon code read line by line, with specific attention to: JWT algorithm pinning, issuer/tenant/audience binding, nonce and state comparison, PKCE construction, key-set handling, session lifecycle, CSRF coverage of every state-changing action, output escaping, log hygiene, file-write atomicity, and failure behaviour (fail-open vs fail-closed).
2. **Live external testing** over HTTPS with a command-line HTTP client, replaying crafted requests against the deployed endpoint: flow initiation, forged callbacks, valid-state callback with a bogus code, state replay, link-flow attempts over GET and POST with and without a CSRF token, reflected-parameter injection attempts, direct file access, directory listing, unauthenticated access to the admin area, error-response disclosure, and TLS/transport inspection.

## 3. Findings summary

| ID | Title | Severity | Component | Fixed by |
|---|---|---|---|---|
| SEC-001 | No HTTP Strict Transport Security (HSTS) | Medium | Deployment | Server configuration |
| SEC-002 | Missing security headers on the admin area | Low | Deployment | Server configuration |
| SEC-003 | Session cookie has no SameSite attribute | Low | Deployment | PHP configuration |
| SEC-004 | Admin area uses the WHMCS default folder name | Informational | Deployment | WHMCS configuration |
| SEC-005 | Admin login throttling could not be verified | Informational | Deployment | WHMCS configuration |
| SEC-006 | Admin username not passed through the log sanitiser | Informational | Addon | Code change |

## 4. Detailed findings

### SEC-001 — No HTTP Strict Transport Security (HSTS)

**Severity:** Medium · **Component:** Deployment · **Status:** Open

**Description.** No `Strict-Transport-Security` header is returned on any response, and it is absent from the HTTPS host's response set as a whole. Plain-HTTP requests are redirected to HTTPS with a `301`, which is correct, but the redirect only helps a client that reaches the genuine server. A network-position attacker can strip or intercept the *first* plaintext request (or a manually typed `http://` URL) before the redirect is ever seen. The admin area is the highest-value target on the deployment and is the page users type from memory.

**Evidence.** Header inspection of the admin login page and the sign-in endpoint responses over HTTPS showed transport-security headers absent. Plain HTTP returned a `301` redirect to HTTPS.

**Impact.** On the first plaintext visit, an active man-in-the-middle could capture or alter an admin authentication interaction. No exploit was attempted (this would require a network position and interception testing was out of scope).

**Remediation.** Serve `Strict-Transport-Security: max-age=31536000; includeSubDomains` on all HTTPS responses, at the web-server level. Begin with a shorter `max-age` if roll-out risk is a concern, then raise it.

---

### SEC-002 — Missing security headers on the admin area

**Severity:** Low · **Component:** Deployment · **Status:** Open

**Description.** The admin area responses carry no `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Permissions-Policy`. The login page can therefore be framed by any origin, and content-type sniffing is not disabled.

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

### SEC-005 — Admin login throttling could not be verified

**Severity:** Informational · **Component:** Deployment · **Status:** To verify

**Description.** Two authentication attempts with a single bogus, randomly generated username produced a generic failure redirect (`invalid` flag) and no observable throttling or lockout. The test was deliberately stopped there: sustained brute-force testing against the owner's own production admin endpoint risks banning the testing IP and approaches denial of service, so it was excluded from scope.

**Impact.** Unknown. WHMCS ships configurable admin login-failure protection; whether it is enabled and tuned on this deployment was not established.

**Remediation.** The owner should confirm in *System Settings → Security Policy* that admin login failure throttling is enabled with sane thresholds, and that admin login failures are logged and alerted on. This is a verification item, not a confirmed weakness.

---

### SEC-006 — Admin username not passed through the log sanitiser

**Severity:** Informational · **Component:** Addon (`login.php`) · **Status:** Open

**Description.** Token-derived text is sanitised before it reaches the WHMCS activity log (`LogText::clean`), and the code's own comment states the invariant "only sanitised token text goes into log lines". Two log calls instead interpolate `$admin->username` straight from the database: the "disabled admin" rejection and the successful sign-in message (`logActivity('Entra ID Admin Login: admin ' . $admin->username ...)`).

**Impact.** Negligible as written: admin usernames are created by other admins, so an attacker who could set a malicious username already has admin access. It is an invariant violation, not an exploitable path, and both messages are fixed strings otherwise.

**Remediation.** Wrap the username in `LogText::clean()` at both call sites for consistency with the stated invariant.

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

## 6. Remediation priority

1. **SEC-001 (HSTS)** — one header, removes the first-visit downgrade class. Do this first.
2. **SEC-002 (security headers)** — same effort class as SEC-001.
3. **SEC-005** — confirm admin login throttling is on and alerted (verification, no code).
4. **SEC-003 (SameSite=Lax)** — one PHP setting; test the full sign-in round-trip afterwards.
5. **SEC-006** — two-line code change in the addon, whenever convenient.
6. **SEC-004** — optional, purely to reduce scanner noise.

## 7. Limitations

- Time-boxed to a single day; a longer engagement would repeat the state-expiry and lockout tests against a staging instance rather than production.
- WHMCS core was treated as a trusted dependency, not reviewed in source.
- Brute-force, and any testing that could lock or ban accounts or addresses, was out of scope by design (§2).
- Browser-level testing (UI redressing, DOM-based issues in the admin area's JavaScript) was not performed; the addon itself ships no client-side script beyond a static link.
