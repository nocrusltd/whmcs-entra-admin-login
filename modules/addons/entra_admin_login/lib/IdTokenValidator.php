<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

/**
 * Verifies a Microsoft Entra ID v2.0 ID token for a single tenant and client.
 *
 * Every check fails closed: a missing claim is treated the same as a wrong one.
 */
final class IdTokenValidator
{
    /** Allowed clock skew between this server and Entra, in seconds. */
    const LEEWAY = 120;

    /** @var string */
    private $tenantId;

    /** @var string */
    private $clientId;

    /**
     * @param string $tenantId Directory (tenant) GUID, lower case.
     * @param string $clientId Application (client) GUID.
     */
    public function __construct($tenantId, $clientId)
    {
        $this->tenantId = strtolower($tenantId);
        $this->clientId = strtolower($clientId);
    }

    /**
     * @param string   $jwt           Compact-serialised ID token.
     * @param array    $jwks          Decoded JSON Web Key Set from the tenant's keys endpoint.
     * @param string   $expectedNonce Nonce sent in the authorisation request.
     * @param int|null $now           Unix time; defaults to time(). Only tests pass this.
     *
     * @return array The verified claims.
     *
     * @throws \RuntimeException When any check fails.
     */
    public function validate($jwt, array $jwks, $expectedNonce, $now = null)
    {
        $now = $now === null ? time() : (int) $now;

        if (!is_string($jwt)) {
            throw new \RuntimeException('ID token is not a string.');
        }
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \RuntimeException('ID token is not a three-part JWT.');
        }

        $header = self::decodeJson($parts[0]);
        $claims = self::decodeJson($parts[1]);
        $signature = Base64Url::decode($parts[2]);

        // Pin the algorithm. Never let the token choose it.
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new \RuntimeException('ID token algorithm is not RS256.');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new \RuntimeException('ID token header has no key ID.');
        }

        $key = Jwks::publicKey($jwks, $kid);
        $verified = openssl_verify($parts[0] . '.' . $parts[1], $signature, $key, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            throw new \RuntimeException('ID token signature does not verify.');
        }

        // Signature is good; now check the token was issued for us, by our tenant, recently.
        if (($claims['ver'] ?? null) !== '2.0') {
            throw new \RuntimeException('ID token is not a v2.0 token.');
        }
        $expectedIssuer = 'https://login.microsoftonline.com/' . $this->tenantId . '/v2.0';
        if (($claims['iss'] ?? null) !== $expectedIssuer) {
            throw new \RuntimeException('ID token issuer is not the configured tenant.');
        }
        if (!is_string($claims['tid'] ?? null) || strtolower($claims['tid']) !== $this->tenantId) {
            throw new \RuntimeException('ID token tenant is not the configured tenant.');
        }
        if (!is_string($claims['aud'] ?? null) || strtolower($claims['aud']) !== $this->clientId) {
            throw new \RuntimeException('ID token audience is not this application.');
        }
        if (!is_int($claims['exp'] ?? null) || $claims['exp'] + self::LEEWAY < $now) {
            throw new \RuntimeException('ID token has expired.');
        }
        if (array_key_exists('nbf', $claims)
            && (!is_int($claims['nbf']) || $claims['nbf'] - self::LEEWAY > $now)) {
            throw new \RuntimeException('ID token is not valid yet.');
        }
        if (!is_int($claims['iat'] ?? null) || $claims['iat'] - self::LEEWAY > $now) {
            throw new \RuntimeException('ID token issue time is in the future.');
        }
        if (!is_string($expectedNonce) || $expectedNonce === ''
            || !is_string($claims['nonce'] ?? null)
            || !hash_equals($expectedNonce, $claims['nonce'])) {
            throw new \RuntimeException('ID token nonce does not match this sign-in.');
        }
        if (!is_string($claims['oid'] ?? null) || !Guid::isValid($claims['oid'])) {
            throw new \RuntimeException('ID token has no valid object ID (oid).');
        }

        return $claims;
    }

    /**
     * @param string $segment
     * @return array
     */
    private static function decodeJson($segment)
    {
        $decoded = json_decode(Base64Url::decode($segment), true, 32);
        if (!is_array($decoded)) {
            throw new \RuntimeException('ID token segment is not a JSON object.');
        }
        return $decoded;
    }
}
