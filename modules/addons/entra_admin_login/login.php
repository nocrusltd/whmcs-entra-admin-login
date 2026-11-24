<?php
// SPDX-License-Identifier: MIT
//
// Sign-in endpoint and OIDC redirect URI.
//
//   GET  login.php                 start a sign-in
//   POST login.php?action=link     start linking the signed-in admin's Microsoft account (CSRF protected)
//   GET  login.php?code=...&state= Entra's redirect back after either of the above

use Nocrus\EntraAdminLogin\AdminSession;
use Nocrus\EntraAdminLogin\IdTokenValidator;
use Nocrus\EntraAdminLogin\Links;
use Nocrus\EntraAdminLogin\LogText;
use Nocrus\EntraAdminLogin\OidcClient;
use Nocrus\EntraAdminLogin\Roles;
use Nocrus\EntraAdminLogin\Settings;

require dirname(__DIR__, 3) . '/init.php';
if (!function_exists('entra_admin_login_config')) {
    require_once __DIR__ . '/entra_admin_login.php';
}

const ENTRA_FLOW_KEY = 'entra_admin_login_flow';
const ENTRA_FLOW_TTL = 600;

header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
// The only page this file renders is the plain error page (one inline style
// block, one link). Everything else is a redirect.
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");

/**
 * Shows a plain error page and stops. $logDetail goes to the WHMCS activity log
 * only; it never contains tokens or codes.
 *
 * @param string      $message
 * @param string|null $logDetail
 */
function entra_fail($message, $logDetail = null)
{
    logActivity('Entra ID Admin Login failed: ' . ($logDetail !== null ? $logDetail : $message));
    $back = htmlspecialchars(entra_admin_login_admin_url() . 'login.php', ENT_QUOTES, 'UTF-8');
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign-in failed</title>'
        . '<meta name="viewport" content="width=device-width, initial-scale=1">'
        . '<style>body{font-family:system-ui,sans-serif;background:#f4f5f7;color:#1f2328;margin:0;'
        . 'display:flex;min-height:100vh;align-items:center;justify-content:center}'
        . 'main{background:#fff;max-width:28rem;margin:1rem;padding:2rem;border-radius:8px;'
        . 'box-shadow:0 1px 3px rgba(0,0,0,.12)}a{color:#0969da}</style></head><body><main>'
        . '<h1 style="font-size:1.25rem;margin-top:0">Sign-in failed</h1><p>'
        . htmlspecialchars($message, ENT_QUOTES, 'UTF-8')
        . '</p><p><a href="' . $back . '">Back to the admin login page</a></p></main></body></html>';
    exit;
}

/** @param string $url */
function entra_redirect($url)
{
    header('Location: ' . $url, true, 302);
    exit;
}

/** @return int The signed-in admin's ID, or 0. */
function entra_current_admin_id()
{
    if (!class_exists('\WHMCS\Authentication\CurrentUser')) {
        return 0;
    }
    $user = new \WHMCS\Authentication\CurrentUser();
    return $user->isAuthenticatedAdmin() ? (int) $user->admin()->id : 0;
}

$settings = Settings::load();
if (!$settings->isActive()) {
    entra_fail('Microsoft sign-in is not enabled.', 'addon is not active');
}
if (!$settings->isConfigured()) {
    entra_fail('Microsoft sign-in is not configured.', 'tenant ID or client ID missing or not a GUID');
}

$tenantId = $settings->tenantId();
$client = new OidcClient($tenantId, $settings->clientId(), entra_admin_login_url());

// ---- Start a sign-in or a link ---------------------------------------------

if (!isset($_GET['code']) && !isset($_GET['error'])) {
    $mode = 'login';
    $adminId = 0;
    $prompt = $settings->alwaysPromptForAccount() ? 'select_account' : '';

    if (($_GET['action'] ?? '') === 'link') {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            entra_fail('Use the "Link my Microsoft account" button on the addon page.', 'link started without POST');
        }
        check_token('WHMCS.admin.default');
        $adminId = entra_current_admin_id();
        if ($adminId === 0) {
            entra_fail('Sign in to WHMCS before linking a Microsoft account.', 'link started without an admin session');
        }
        $mode = 'link';
        // Make the admin enter their Microsoft credentials now, so a link cannot
        // ride on someone else's signed-in Microsoft session in this browser.
        $prompt = 'login';
    } elseif (entra_current_admin_id() !== 0) {
        entra_redirect(entra_admin_login_admin_url());
    }

    $flow = [
        'state' => OidcClient::randomToken(),
        'nonce' => OidcClient::randomToken(),
        'verifier' => OidcClient::randomToken(48),
        'mode' => $mode,
        'admin_id' => $adminId,
        'started' => time(),
    ];
    $_SESSION[ENTRA_FLOW_KEY] = $flow;

    entra_redirect($client->authorizationUrl($flow['state'], $flow['nonce'], $flow['verifier'], $prompt));
}

// ---- Callback from Entra ---------------------------------------------------

// A request whose state does not match is rejected without touching the stored
// flow, so a forged callback (say, an <img> on another site) cannot cancel a
// sign-in that is in progress. A matching state consumes the flow: one use only.
$flow = $_SESSION[ENTRA_FLOW_KEY] ?? null;
if (!is_array($flow) || !is_string($flow['state'] ?? null)
    || !is_string($_GET['state'] ?? null) || !hash_equals($flow['state'], $_GET['state'])) {
    entra_fail('This sign-in link is invalid or was already used. Please start again.', 'state missing or mismatched');
}
unset($_SESSION[ENTRA_FLOW_KEY]);
if (time() - (int) $flow['started'] > ENTRA_FLOW_TTL) {
    entra_fail('The sign-in took too long. Please start again.', 'flow older than ' . ENTRA_FLOW_TTL . ' seconds');
}
if (isset($_GET['error'])) {
    $error = preg_replace('/[^a-z_]/', '', strtolower((string) $_GET['error']));
    // Entra descriptions start with an AADSTS code; keep just that, it is enough to look up.
    preg_match('/AADSTS\d+/', (string) ($_GET['error_description'] ?? ''), $code);
    entra_fail(
        'Microsoft did not complete the sign-in (' . $error . ').',
        'Entra returned ' . $error . ($code ? ' ' . $code[0] : '')
    );
}
if (!is_string($_GET['code'] ?? null) || $_GET['code'] === '') {
    entra_fail('Microsoft did not return a sign-in code.', 'callback without code');
}

try {
    $idToken = $client->redeemCode($_GET['code'], $flow['verifier']);
    $validator = new IdTokenValidator($tenantId, $settings->clientId());
    $claims = $validator->validate($idToken, $client->signingKeys(), $flow['nonce']);
} catch (\Exception $e) {
    entra_fail('Your Microsoft sign-in could not be verified.', LogText::clean($e->getMessage()));
}

$objectId = strtolower($claims['oid']);
$username = is_string($claims['preferred_username'] ?? null) ? $claims['preferred_username'] : '';
$displayName = is_string($claims['name'] ?? null) ? $claims['name'] : '';
// Only sanitised text goes into log lines.
$who = ($username !== '' ? LogText::clean($username) : 'unknown user') . ' (oid ' . LogText::clean($objectId) . ')';

if (!Roles::satisfied($claims, $settings->requiredRoles())) {
    entra_fail('Your Microsoft account does not have a role that allows WHMCS admin sign-in.', 'missing required app role: ' . $who);
}

if ($flow['mode'] === 'link') {
    $adminId = (int) $flow['admin_id'];
    if ($adminId === 0 || entra_current_admin_id() !== $adminId) {
        entra_fail('Your WHMCS session changed during linking. Please start again.', 'admin session changed during link');
    }
    try {
        Links::link($adminId, $tenantId, $objectId, $username, $displayName);
    } catch (\RuntimeException $e) {
        // Links::link's own messages are fixed strings; anything else (a database error) is not shown.
        $known = strpos($e->getMessage(), 'already linked') !== false;
        entra_fail(
            $known ? $e->getMessage() : 'The account could not be linked.',
            ($known ? $e->getMessage() : 'link failed: ' . get_class($e)) . ' ' . $who . ' -> admin ID ' . $adminId
        );
    }
    logActivity('Entra ID Admin Login: ' . $who . ' linked to admin ID ' . $adminId);
    entra_redirect(entra_admin_login_admin_url() . 'addonmodules.php?module=' . Settings::MODULE . '&linked=1');
}

$link = Links::findByAccount($tenantId, $objectId);
if (!$link) {
    entra_fail('No WHMCS admin is linked to this Microsoft account.', 'no link for ' . $who);
}

$admin = \WHMCS\Database\Capsule::table('tbladmins')->where('id', (int) $link->admin_id)->first();
if (!$admin) {
    entra_fail('The WHMCS admin linked to this Microsoft account no longer exists.', 'linked admin ID ' . (int) $link->admin_id . ' missing for ' . $who);
}
if (!empty($admin->disabled)) {
    entra_fail('This WHMCS admin account is disabled.', 'disabled admin ' . LogText::clean($admin->username) . ' for ' . $who);
}

try {
    AdminSession::start((int) $admin->id);
} catch (\Exception $e) {
    entra_fail('WHMCS could not start your session. Sign in with your password instead.', LogText::clean($e->getMessage()));
}

Links::recordLogin($link->id, $username, $displayName);
logActivity('Entra ID Admin Login: admin ' . LogText::clean($admin->username) . ' signed in as ' . $who);

entra_redirect(entra_admin_login_admin_url());
