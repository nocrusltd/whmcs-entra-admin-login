<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

/** Turns an RSA entry of a JSON Web Key Set into an OpenSSL public key. */
final class Jwks
{
    /**
     * @param array  $jwks Decoded key set ({"keys": [...]}).
     * @param string $kid  Key ID from the token header.
     * @return resource|\OpenSSLAsymmetricKey
     * @throws \RuntimeException When no usable RSA signing key has that ID.
     */
    public static function publicKey(array $jwks, $kid)
    {
        $keys = $jwks['keys'] ?? null;
        if (!is_array($keys)) {
            throw new \RuntimeException('Key set has no keys.');
        }

        foreach ($keys as $jwk) {
            if (!is_array($jwk) || ($jwk['kid'] ?? null) !== $kid) {
                continue;
            }
            if (($jwk['kty'] ?? null) !== 'RSA') {
                continue;
            }
            if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
                continue;
            }

            // Prefer the modulus and exponent: they are the key itself. x5c is a
            // fallback for key sets that only publish a certificate.
            if (is_string($jwk['n'] ?? null) && is_string($jwk['e'] ?? null)) {
                $pem = self::rsaPublicKeyPem(Base64Url::decode($jwk['n']), Base64Url::decode($jwk['e']));
            } elseif (is_string($jwk['x5c'][0] ?? null)) {
                $pem = "-----BEGIN CERTIFICATE-----\n"
                    . chunk_split($jwk['x5c'][0], 64, "\n")
                    . "-----END CERTIFICATE-----\n";
            } else {
                continue;
            }

            $key = openssl_pkey_get_public($pem);
            if ($key === false) {
                throw new \RuntimeException('Signing key ' . $kid . ' could not be loaded.');
            }
            $details = openssl_pkey_get_details($key);
            if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ($details['bits'] ?? 0) < 2048) {
                throw new \RuntimeException('Signing key ' . $kid . ' is not an RSA key of at least 2048 bits.');
            }
            return $key;
        }

        throw new \RuntimeException('No RSA signing key with ID ' . $kid . ' in the key set.');
    }

    /**
     * Builds a SubjectPublicKeyInfo PEM from a raw RSA modulus and exponent.
     *
     * @param string $modulus  Big-endian bytes.
     * @param string $exponent Big-endian bytes.
     * @return string
     */
    public static function rsaPublicKeyPem($modulus, $exponent)
    {
        if ($modulus === '' || $exponent === '') {
            throw new \RuntimeException('RSA key has an empty modulus or exponent.');
        }
        $rsaPublicKey = self::der(0x30, self::derInteger($modulus) . self::derInteger($exponent));
        // AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters.
        $algorithm = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $spki = self::der(0x30, $algorithm . self::der(0x03, "\x00" . $rsaPublicKey));

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * @param string $bytes Unsigned big-endian integer.
     * @return string
     */
    private static function derInteger($bytes)
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
            // Keep the integer positive.
            $bytes = "\x00" . $bytes;
        }
        return self::der(0x02, $bytes);
    }

    /**
     * @param int    $tag
     * @param string $content
     * @return string
     */
    private static function der($tag, $content)
    {
        $length = strlen($content);
        if ($length < 0x80) {
            $encodedLength = chr($length);
        } else {
            $lengthBytes = ltrim(pack('N', $length), "\x00");
            $encodedLength = chr(0x80 | strlen($lengthBytes)) . $lengthBytes;
        }
        return chr($tag) . $encodedLength . $content;
    }
}
