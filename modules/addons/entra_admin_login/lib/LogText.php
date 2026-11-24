<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

/** Makes token-derived text safe to put in an activity log line. */
final class LogText
{
    /**
     * Keeps letters, digits, spaces and the punctuation found in UPNs, GUIDs
     * and Entra error codes. No <, >, &, quotes or control characters survive,
     * so nothing from a token or an Entra response can carry markup into the
     * WHMCS activity log however WHMCS renders it.
     *
     * @param mixed $value
     * @return string
     */
    public static function clean($value)
    {
        if (!is_string($value)) {
            return '';
        }
        return substr(preg_replace('/[^A-Za-z0-9@._+\-:(),\/ ]/', '', $value), 0, 200);
    }
}
