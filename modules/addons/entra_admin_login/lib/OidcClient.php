<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

/**
 * Authorisation code flow with PKCE against one Entra ID tenant.
 *
 * The app is registered as a public client, so there is no client secret to
 * store, rotate or let expire. PKCE binds the authorisation code to the
 * verifier kept in this server's session, so an intercepted code is useless.
 */
final class OidcClient
{
    const AUTHORITY = 'https://login.microsoftonline.com/';
    const SCOPE = 'openid profile email';

    /** @var string */
    private $tenantId;

    /** @var string */
    private $clientId;

    /** @var string */
    private $redirectUri;

    /** @var callable(string, string, array|null): array{0:int,1:string} */
    private $http;

    /**
     * @param string        $tenantId
     * @param string        $clientId
     * @param string        $redirectUri Must match the app registration exactly.
     * @param callable|null $http        fn(method, url, ?form) => [status, body]. Tests inject a fake.
     */
    public function __construct($tenantId, $clientId, $redirectUri, $http = null)
    {
        $this->tenantId = strtolower($tenantId);
        $this->clientId = strtolower($clientId);
        $this->redirectUri = $redirectUri;
        $this->http = $http ?: [self::class, 'curlRequest'];
    }

    /**
     * @param string $state
     * @param string $nonce
     * @param string $codeVerifier
     * @param string $prompt Optional OIDC prompt value, e.g. "login" or "select_account".
     * @return string
     */
    public function authorizationUrl($state, $nonce, $codeVerifier, $prompt = '')
    {
        $query = [
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'response_mode' => 'query',
            'redirect_uri' => $this->redirectUri,
            'scope' => self::SCOPE,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::pkceChallenge($codeVerifier),
            'code_challenge_method' => 'S256',
        ];
        if ($prompt !== '') {
            $query['prompt'] = $prompt;
        }

        return $this->endpoint('oauth2/v2.0/authorize') . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Redeems an authorisation code and returns the raw ID token.
     *
     * @param string $code
     * @param string $codeVerifier
     * @return string
     */
    public function redeemCode($code, $codeVerifier)
    {
        list($status, $body) = call_user_func($this->http, 'POST', $this->endpoint('oauth2/v2.0/token'), [
            'client_id' => $this->clientId,
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'code_verifier' => $codeVerifier,
            'scope' => self::SCOPE,
        ]);
        $json = self::decode($body);

        if ($status !== 200 || isset($json['error'])) {
            $error = is_string($json['error'] ?? null) ? $json['error'] : 'HTTP ' . $status;
            // Entra error descriptions start with an AADSTS code on the first line; the rest is trace noise.
            $description = is_string($json['error_description'] ?? null) ? strtok($json['error_description'], "\r\n") : '';
            throw new \RuntimeException('Token endpoint refused the code: ' . $error . ($description !== '' ? ' (' . $description . ')' : ''));
        }
        if (!is_string($json['id_token'] ?? null)) {
            throw new \RuntimeException('Token endpoint returned no ID token.');
        }

        return $json['id_token'];
    }

    /** @return array The tenant's JSON Web Key Set. */
    public function signingKeys()
    {
        list($status, $body) = call_user_func($this->http, 'GET', $this->endpoint('discovery/v2.0/keys'), null);
        $json = self::decode($body);
        if ($status !== 200 || !is_array($json['keys'] ?? null)) {
            throw new \RuntimeException('Could not fetch the tenant signing keys (HTTP ' . $status . ').');
        }
        return $json;
    }

    /**
     * @param int $bytes
     * @return string URL-safe random string.
     */
    public static function randomToken($bytes = 32)
    {
        return Base64Url::encode(random_bytes($bytes));
    }

    /**
     * RFC 7636 S256 code challenge.
     *
     * @param string $verifier
     * @return string
     */
    public static function pkceChallenge($verifier)
    {
        return Base64Url::encode(hash('sha256', $verifier, true));
    }

    /**
     * @param string     $method
     * @param string     $url
     * @param array|null $form
     * @return array{0:int,1:string}
     */
    public static function curlRequest($method, $url, $form)
    {
        $ch = curl_init($url);
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ];
        if ($method === 'POST') {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = http_build_query((array) $form, '', '&');
        }
        curl_setopt_array($ch, $options);

        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        if (PHP_VERSION_ID < 80000) {
            // A no-op since PHP 8.0 and deprecated in 8.5.
            curl_close($ch);
        }

        if ($body === false) {
            throw new \RuntimeException('Request to Microsoft failed: ' . $error);
        }
        return [$status, (string) $body];
    }

    /**
     * @param string $path
     * @return string
     */
    private function endpoint($path)
    {
        return self::AUTHORITY . rawurlencode($this->tenantId) . '/' . $path;
    }

    /**
     * @param string $body
     * @return array
     */
    private static function decode($body)
    {
        $json = json_decode((string) $body, true, 32);
        if (!is_array($json)) {
            throw new \RuntimeException('Microsoft returned a response that is not JSON.');
        }
        return $json;
    }
}
