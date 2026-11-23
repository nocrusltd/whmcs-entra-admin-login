<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

final class Guid
{
    /**
     * @param mixed $value
     * @return bool True for a canonical 8-4-4-4-12 hex GUID, any case.
     */
    public static function isValid($value)
    {
        return is_string($value)
            && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iD', $value) === 1;
    }
}
