<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

final class Roles
{
    /**
     * @param array    $claims   Verified ID token claims.
     * @param string[] $required App role values; empty means no requirement.
     * @return bool True when no roles are required or the token carries at least one of them.
     */
    public static function satisfied(array $claims, array $required)
    {
        if ($required === []) {
            return true;
        }
        $held = $claims['roles'] ?? [];
        if (!is_array($held)) {
            return false;
        }
        $held = array_filter($held, 'is_string');
        return array_intersect($required, $held) !== [];
    }
}
