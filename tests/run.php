<?php
// SPDX-License-Identifier: MIT
//
// Dependency-free test runner: php tests/run.php
// Exits non-zero if any test fails.

declare(strict_types=1);

error_reporting(E_ALL);
set_error_handler(function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

require __DIR__ . '/../modules/addons/entra_admin_login/lib/bootstrap.php';

use Nocrus\EntraAdminLogin\Base64Url;
use Nocrus\EntraAdminLogin\Guid;
use Nocrus\EntraAdminLogin\IdTokenValidator;
use Nocrus\EntraAdminLogin\Jwks;
use Nocrus\EntraAdminLogin\LoginPageButton;
use Nocrus\EntraAdminLogin\LogText;
use Nocrus\EntraAdminLogin\OidcClient;
use Nocrus\EntraAdminLogin\Roles;
use Nocrus\EntraAdminLogin\Settings;

const TENANT = '2257e97a-0000-4000-8000-000000000001';
const CLIENT = '3d32e296-0000-4000-8000-000000000002';
const OID = 'c59c4328-0000-4000-8000-000000000003';
const NOW = 1800000000;
const NONCE = 'nonce-abc';

$tests = [];
function test(string $name, callable $fn): void
{
    $GLOBALS['tests'][$name] = $fn;
}

function check(bool $condition, string $message = 'assertion failed'): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function same($expected, $actual, string $message = ''): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(($message !== '' ? $message . ': ' : '')
            . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

/** Asserts $fn throws a RuntimeException whose message contains $needle. */
function throws(string $needle, callable $fn): void
{
    try {
        $fn();
    } catch (RuntimeException $e) {
        check(strpos($e->getMessage(), $needle) !== false, 'expected "' . $needle . '" in "' . $e->getMessage() . '"');
        return;
    }
    throw new RuntimeException('expected an exception containing "' . $needle . '"');
}

// ---- Key material -----------------------------------------------------------

function newKey(int $bits = 2048)
{
    $key = openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    check($key !== false, 'could not generate an RSA key');
    return $key;
}

$signingKey = newKey();
$otherKey = newKey();

function jwkFor($key, string $kid): array
{
    $rsa = openssl_pkey_get_details($key)['rsa'];
    return ['kty' => 'RSA', 'use' => 'sig', 'kid' => $kid, 'n' => Base64Url::encode($rsa['n']), 'e' => Base64Url::encode($rsa['e'])];
}

function x5cFor($key): string
{
    $csr = openssl_csr_new(['commonName' => 'test'], $key, ['digest_alg' => 'sha256']);
    $cert = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
    openssl_x509_export($cert, $pem);
    return preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem);
}

function claims(array $overrides = []): array
{
    $claims = [
        'ver' => '2.0',
        'iss' => 'https://login.microsoftonline.com/' . TENANT . '/v2.0',
        'tid' => TENANT,
        'aud' => CLIENT,
        'iat' => NOW - 10,
        'nbf' => NOW - 10,
        'exp' => NOW + 3600,
        'nonce' => NONCE,
        'oid' => OID,
        'preferred_username' => 'admin@example.test',
        'name' => 'Test Admin',
    ];
    foreach ($overrides as $name => $value) {
        if ($value === null) {
            unset($claims[$name]);
        } else {
            $claims[$name] = $value;
        }
    }
    return $claims;
}

function jwt(array $claims, $key, array $header = ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'k1']): string
{
    $input = Base64Url::encode(json_encode($header)) . '.' . Base64Url::encode(json_encode($claims));
    openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256);
    return $input . '.' . Base64Url::encode($signature);
}

function validate(string $token, array $jwks, string $nonce = NONCE): array
{
    return (new IdTokenValidator(TENANT, CLIENT))->validate($token, $jwks, $nonce, NOW);
}

$jwks = ['keys' => [jwkFor($otherKey, 'k0'), jwkFor($signingKey, 'k1')]];

// ---- Base64Url / Guid / PKCE ---------------------------------------------

test('base64url round-trips binary data', function () {
    $bytes = random_bytes(257);
    same($bytes, Base64Url::decode(Base64Url::encode($bytes)));
});

test('base64url rejects standard-alphabet and padded input', function () {
    throws('base64url', function () { Base64Url::decode('ab+/'); });
    throws('base64url', function () { Base64Url::decode('abc='); });
    throws('base64url', function () { Base64Url::decode('a'); });
    throws('base64url', function () { Base64Url::decode("abcd\n"); });
});

test('guid validation', function () {
    check(Guid::isValid(TENANT));
    check(Guid::isValid(strtoupper(TENANT)));
    check(!Guid::isValid('not-a-guid'));
    check(!Guid::isValid(TENANT . "\n"));
    check(!Guid::isValid(null));
});

test('pkce challenge matches the RFC 7636 appendix B vector', function () {
    same('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', OidcClient::pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
});

test('random tokens are url-safe and distinct', function () {
    $a = OidcClient::randomToken();
    $b = OidcClient::randomToken();
    check($a !== $b);
    check(preg_match('/^[A-Za-z0-9_-]{43}$/', $a) === 1, 'unexpected token shape ' . $a);
});

// ---- OidcClient ----------------------------------------------------------------

test('authorization URL carries PKCE, state, nonce and the exact redirect URI', function () {
    $client = new OidcClient(strtoupper(TENANT), CLIENT, 'https://billing.example.test/modules/addons/entra_admin_login/login.php');
    $url = $client->authorizationUrl('st', 'no', 'verifier', 'login');
    same(0, strpos($url, 'https://login.microsoftonline.com/' . TENANT . '/oauth2/v2.0/authorize?'));
    parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
    same(CLIENT, $q['client_id']);
    same('code', $q['response_type']);
    same('query', $q['response_mode']);
    same('https://billing.example.test/modules/addons/entra_admin_login/login.php', $q['redirect_uri']);
    same('openid profile email', $q['scope']);
    same('st', $q['state']);
    same('no', $q['nonce']);
    same(OidcClient::pkceChallenge('verifier'), $q['code_challenge']);
    same('S256', $q['code_challenge_method']);
    same('login', $q['prompt']);
});

test('authorization URL omits prompt when none is asked for', function () {
    $url = (new OidcClient(TENANT, CLIENT, 'https://x.test/cb'))->authorizationUrl('a', 'b', 'c');
    check(strpos($url, 'prompt=') === false);
});

test('code redemption posts the verifier and no secret, and returns the ID token', function () {
    $seen = null;
    $client = new OidcClient(TENANT, CLIENT, 'https://x.test/cb', function ($method, $url, $form) use (&$seen) {
        $seen = [$method, $url, $form];
        return [200, json_encode(['id_token' => 'the.id.token', 'access_token' => 'ignored'])];
    });
    same('the.id.token', $client->redeemCode('the-code', 'the-verifier'));
    same('POST', $seen[0]);
    same('https://login.microsoftonline.com/' . TENANT . '/oauth2/v2.0/token', $seen[1]);
    same('authorization_code', $seen[2]['grant_type']);
    same('the-code', $seen[2]['code']);
    same('the-verifier', $seen[2]['code_verifier']);
    same('https://x.test/cb', $seen[2]['redirect_uri']);
    check(!array_key_exists('client_secret', $seen[2]), 'public client must not send a secret');
});

test('code redemption surfaces the first line of an Entra error', function () {
    $client = new OidcClient(TENANT, CLIENT, 'https://x.test/cb', function () {
        return [400, json_encode(['error' => 'invalid_grant', 'error_description' => "AADSTS54005: code already redeemed.\r\nTrace ID: x"])];
    });
    throws('invalid_grant (AADSTS54005: code already redeemed.)', function () use ($client) { $client->redeemCode('c', 'v'); });
});

test('code redemption with an empty or blank error description adds no empty brackets', function () {
    foreach (['', "\r\n"] as $description) {
        $client = new OidcClient(TENANT, CLIENT, 'https://x.test/cb', function () use ($description) {
            return [400, json_encode(['error' => 'invalid_grant', 'error_description' => $description])];
        });
        try {
            $client->redeemCode('c', 'v');
            throw new LogicException('expected an exception');
        } catch (RuntimeException $e) {
            same('Token endpoint refused the code: invalid_grant', $e->getMessage());
        }
    }
});

test('code redemption rejects a response without an ID token or non-JSON', function () {
    $noToken = new OidcClient(TENANT, CLIENT, 'https://x.test/cb', function () { return [200, '{"access_token":"a"}']; });
    throws('no ID token', function () use ($noToken) { $noToken->redeemCode('c', 'v'); });
    $html = new OidcClient(TENANT, CLIENT, 'https://x.test/cb', function () { return [200, '<html>']; });
    throws('not JSON', function () use ($html) { $html->redeemCode('c', 'v'); });
});

test('signing keys come from the tenant keys endpoint and errors are reported', function () use ($jwks) {
    $url = null;
    $client = new OidcClient(TENANT, CLIENT, 'https://x.test/cb', function ($m, $u) use (&$url, $jwks) {
        $url = $u;
        return [200, json_encode($jwks)];
    });
    same($jwks, $client->signingKeys());
    same('https://login.microsoftonline.com/' . TENANT . '/discovery/v2.0/keys', $url);
    $down = new OidcClient(TENANT, CLIENT, 'https://x.test/cb', function () { return [503, '{}']; });
    throws('HTTP 503', function () use ($down) { $down->signingKeys(); });
});

// ---- Jwks ---------------------------------------------------------------------

test('modulus/exponent PEM is identical to the one OpenSSL exports', function () use ($signingKey) {
    $details = openssl_pkey_get_details($signingKey);
    same($details['key'], Jwks::rsaPublicKeyPem($details['rsa']['n'], $details['rsa']['e']));
});

test('jwks ignores keys of the wrong type or use', function () use ($signingKey) {
    $jwk = jwkFor($signingKey, 'k1');
    throws('No RSA signing key', function () use ($jwk) { Jwks::publicKey(['keys' => [array_merge($jwk, ['use' => 'enc'])]], 'k1'); });
    throws('No RSA signing key', function () use ($jwk) { Jwks::publicKey(['keys' => [array_merge($jwk, ['kty' => 'EC'])]], 'k1'); });
    throws('no keys', function () { Jwks::publicKey([], 'k1'); });
});

test('jwks refuses RSA keys under 2048 bits', function () {
    $weak = newKey(1024);
    throws('at least 2048 bits', function () use ($weak) { Jwks::publicKey(['keys' => [jwkFor($weak, 'k1')]], 'k1'); });
});

// ---- IdTokenValidator --------------------------------------------------------

test('a correct token validates and returns its claims', function () use ($signingKey, $jwks) {
    $claims = validate(jwt(claims(), $signingKey), $jwks);
    same(OID, $claims['oid']);
    same('admin@example.test', $claims['preferred_username']);
});

test('a key published only as an x5c certificate validates', function () use ($signingKey) {
    $set = ['keys' => [['kty' => 'RSA', 'use' => 'sig', 'kid' => 'k1', 'x5c' => [x5cFor($signingKey)]]]];
    same(OID, validate(jwt(claims(), $signingKey), $set)['oid']);
});

test('upper-case tenant and audience GUIDs still match', function () use ($signingKey, $jwks) {
    $token = jwt(claims(['tid' => strtoupper(TENANT), 'aud' => strtoupper(CLIENT)]), $signingKey);
    same(OID, validate($token, $jwks)['oid']);
});

test('a token signed by another key is rejected', function () use ($otherKey, $jwks) {
    throws('signature does not verify', function () use ($otherKey, $jwks) { validate(jwt(claims(), $otherKey), $jwks); });
});

test('a tampered payload is rejected', function () use ($signingKey, $jwks) {
    $parts = explode('.', jwt(claims(), $signingKey));
    $parts[1] = Base64Url::encode(json_encode(claims(['oid' => 'aaaaaaaa-0000-4000-8000-000000000009'])));
    throws('signature does not verify', function () use ($parts, $jwks) { validate(implode('.', $parts), $jwks); });
});

test('alg none and HS256 are refused before any key is used', function () use ($signingKey, $jwks) {
    foreach (['none', 'HS256', 'RS512', 'PS256'] as $alg) {
        $token = jwt(claims(), $signingKey, ['alg' => $alg, 'kid' => 'k1']);
        throws('not RS256', function () use ($token, $jwks) { validate($token, $jwks); });
    }
});

test('a missing or unknown kid is rejected', function () use ($signingKey, $jwks) {
    throws('no key ID', function () use ($signingKey, $jwks) { validate(jwt(claims(), $signingKey, ['alg' => 'RS256']), $jwks); });
    throws('No RSA signing key', function () use ($signingKey, $jwks) { validate(jwt(claims(), $signingKey, ['alg' => 'RS256', 'kid' => 'nope']), $jwks); });
});

test('issuer, tenant and audience must all match', function () use ($signingKey, $jwks) {
    $cases = [
        'issuer' => ['iss' => 'https://login.microsoftonline.com/' . CLIENT . '/v2.0'],
        'issuer ' => ['iss' => 'https://sts.windows.net/' . TENANT . '/'],
        'tenant' => ['tid' => CLIENT],
        'audience' => ['aud' => TENANT],
        'audience ' => ['aud' => [CLIENT]],
    ];
    foreach ($cases as $needle => $override) {
        $token = jwt(claims($override), $signingKey);
        throws(trim($needle), function () use ($token, $jwks) { validate($token, $jwks); });
    }
});

test('only v2.0 tokens are accepted', function () use ($signingKey, $jwks) {
    throws('v2.0', function () use ($signingKey, $jwks) { validate(jwt(claims(['ver' => '1.0']), $signingKey), $jwks); });
    throws('v2.0', function () use ($signingKey, $jwks) { validate(jwt(claims(['ver' => null]), $signingKey), $jwks); });
});

test('expiry honours the leeway and no further', function () use ($signingKey, $jwks) {
    same(OID, validate(jwt(claims(['exp' => NOW - IdTokenValidator::LEEWAY]), $signingKey), $jwks)['oid']);
    throws('expired', function () use ($signingKey, $jwks) { validate(jwt(claims(['exp' => NOW - IdTokenValidator::LEEWAY - 1]), $signingKey), $jwks); });
    throws('expired', function () use ($signingKey, $jwks) { validate(jwt(claims(['exp' => null]), $signingKey), $jwks); });
    throws('expired', function () use ($signingKey, $jwks) { validate(jwt(claims(['exp' => (string) (NOW + 60)]), $signingKey), $jwks); });
});

test('not-before and issued-at in the future are rejected', function () use ($signingKey, $jwks) {
    throws('not valid yet', function () use ($signingKey, $jwks) { validate(jwt(claims(['nbf' => NOW + IdTokenValidator::LEEWAY + 1]), $signingKey), $jwks); });
    throws('issue time', function () use ($signingKey, $jwks) { validate(jwt(claims(['iat' => NOW + IdTokenValidator::LEEWAY + 1]), $signingKey), $jwks); });
    throws('issue time', function () use ($signingKey, $jwks) { validate(jwt(claims(['iat' => null]), $signingKey), $jwks); });
});

test('the nonce must match and cannot be empty', function () use ($signingKey, $jwks) {
    throws('nonce', function () use ($signingKey, $jwks) { validate(jwt(claims(), $signingKey), $jwks, 'other-nonce'); });
    throws('nonce', function () use ($signingKey, $jwks) { validate(jwt(claims(['nonce' => null]), $signingKey), $jwks); });
    throws('nonce', function () use ($signingKey, $jwks) { validate(jwt(claims(['nonce' => '']), $signingKey), $jwks, ''); });
});

test('the object ID must be present and a GUID', function () use ($signingKey, $jwks) {
    throws('object ID', function () use ($signingKey, $jwks) { validate(jwt(claims(['oid' => null]), $signingKey), $jwks); });
    throws('object ID', function () use ($signingKey, $jwks) { validate(jwt(claims(['oid' => 'admin@example.test']), $signingKey), $jwks); });
});

test('malformed tokens are rejected', function () use ($jwks) {
    throws('three-part', function () use ($jwks) { validate('a.b', $jwks); });
    throws('base64url', function () use ($jwks) { validate('a+b.c.d', $jwks); });
    throws('JSON object', function () use ($jwks) { validate(Base64Url::encode('"x"') . '.' . Base64Url::encode('{}') . '.' . Base64Url::encode('s'), $jwks); });
});

// ---- Roles / Settings --------------------------------------------------------

test('role check', function () {
    check(Roles::satisfied([], []));
    check(Roles::satisfied(['roles' => ['WHMCS.Admin']], ['WHMCS.Admin', 'Other']));
    check(!Roles::satisfied(['roles' => ['Reader']], ['WHMCS.Admin']));
    check(!Roles::satisfied([], ['WHMCS.Admin']));
    check(!Roles::satisfied(['roles' => 'WHMCS.Admin'], ['WHMCS.Admin']));
});

test('settings parse and reject malformed GUIDs', function () {
    $s = new Settings(['version' => '1.0.0', 'tenantId' => ' ' . strtoupper(TENANT) . ' ', 'clientId' => CLIENT,
        'requiredRoles' => ' WHMCS.Admin, ,Billing ', 'selectAccount' => 'on']);
    check($s->isActive());
    check($s->isConfigured());
    same(TENANT, $s->tenantId());
    same(['WHMCS.Admin', 'Billing'], $s->requiredRoles());
    check($s->alwaysPromptForAccount());

    $bad = new Settings(['tenantId' => 'common', 'clientId' => CLIENT]);
    check(!$bad->isActive());
    check(!$bad->isConfigured(), '"common" must not be accepted as a tenant');
    same([], $bad->requiredRoles());
    check(!$bad->alwaysPromptForAccount());
});

test('log text keeps identifiers and drops markup and control characters', function () {
    same('admin@example.test (oid ' . OID . ')', LogText::clean('admin@example.test (oid ' . OID . ')'));
    same('Token endpoint refused the code: invalid_grant (AADSTS54005: code already redeemed.)',
        LogText::clean('Token endpoint refused the code: invalid_grant (AADSTS54005: code already redeemed.)'));
    same('scriptalert(1)/script@x.test', LogText::clean('<script>alert(1)</script>@x.test'));
    same('ab', LogText::clean("a\"'&<>\n\r\x00b"));
    same('', LogText::clean(null));
    same(200, strlen(LogText::clean(str_repeat('a', 500))));
});

// ---- LoginPageButton ------------------------------------------------------------

// A minimal stand-in with the same shape as the WHMCS admin login template.
function loginTemplate(string $nl = "\n"): string
{
    return implode($nl, [
        '<div class="login-body">',
        '    {if $errorMsg}<div class="alert">{$errorMsg}</div>{/if}',
        '    {if $step eq "login"}',
        '        <form method="post" action="dologin.php">',
        '            <input type="text" name="username" />',
        '            <input type="submit" class="btn btn-primary btn-block" />',
        '        </form>',
        '    {elseif $step eq "reset"}',
        '        <form method="post" action="pwreset.php"></form>',
        '    {/if}',
        '</div>',
        '',
    ]);
}

test('login button goes inside the login step, directly above the password form', function () {
    $out = LoginPageButton::apply(loginTemplate());
    check(LoginPageButton::isApplied($out));
    $step = strpos($out, '{if $step eq "login"}');
    $start = strpos($out, LoginPageButton::START);
    $button = strpos($out, 'href="../modules/addons/entra_admin_login/login.php"');
    $end = strpos($out, LoginPageButton::END);
    $form = strpos($out, '<form method="post" action="dologin.php">');
    check($step < $start && $start < $button && $button < $end && $end < $form, 'block is not between the login step and the form');
    check(strpos($out, '        ' . LoginPageButton::START . "\n") !== false, 'block does not match the form indentation');
    same(1, substr_count($out, 'Sign in with Microsoft'));
    same(1, substr_count($out, '<form method="post" action="pwreset.php">'), 'other steps must be untouched');
});

test('applying twice changes nothing and removing restores the original exactly', function () {
    $original = loginTemplate();
    $once = LoginPageButton::apply($original);
    same($once, LoginPageButton::apply($once));
    same($original, LoginPageButton::remove($once));
    same($original, LoginPageButton::remove($original));
});

test('windows line endings are kept', function () {
    $original = loginTemplate("\r\n");
    $out = LoginPageButton::apply($original);
    check(strpos(str_replace("\r\n", '', $out), "\n") === false, 'a bare LF was introduced');
    same($original, LoginPageButton::remove($out));
});

test('the template is refused when the login form is missing or ambiguous', function () {
    throws('expected login form', function () { LoginPageButton::apply(str_replace('action="dologin.php"', 'action="other.php"', loginTemplate())); });
    throws('expected login form', function () { LoginPageButton::apply(str_replace('{if $step eq "login"}', '{if $step == "login"}', loginTemplate())); });
    throws('expected login form', function () { LoginPageButton::apply(loginTemplate() . loginTemplate()); });
});

// ---- Run ----------------------------------------------------------------------

$failed = 0;
foreach ($tests as $name => $fn) {
    try {
        $fn();
        echo "ok   - $name\n";
    } catch (Throwable $e) {
        $failed++;
        echo "FAIL - $name\n       " . get_class($e) . ': ' . $e->getMessage() . "\n";
    }
}
printf("\n%d tests, %d failed\n", count($tests), $failed);
exit($failed === 0 ? 0 : 1);
