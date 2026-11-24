<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

/** Strict base64url (RFC 4648 section 5) without padding. */
final class Base64Url
{
    /**
     * @param string $data
     * @return string
     */
    public static function encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param string $data
     * @return string
     * @throws \RuntimeException On characters outside the base64url alphabet.
     */
    public static function decode($data)
    {
        if (!is_string($data) || !preg_match('/^[A-Za-z0-9_-]*$/D', $data) || strlen($data) % 4 === 1) {
            throw new \RuntimeException('Value is not valid base64url.');
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \RuntimeException('Value is not valid base64url.');
        }
        return $decoded;
    }
}
