<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

/** The addon's configuration, as stored by WHMCS in tbladdonmodules. */
final class Settings
{
    const MODULE = 'entra_admin_login';

    /** @var array<string, string> */
    private $values;

    /** @param array<string, string> $values setting => value */
    public function __construct(array $values)
    {
        $this->values = $values;
    }

    /** Reads the live settings from the WHMCS database. */
    public static function load()
    {
        $rows = \WHMCS\Database\Capsule::table('tbladdonmodules')
            ->where('module', self::MODULE)
            ->pluck('value', 'setting');

        return new self(is_array($rows) ? $rows : $rows->all());
    }

    /** WHMCS writes a "version" row on activation and deletes all rows on deactivation. */
    public function isActive()
    {
        return isset($this->values['version']);
    }

    /** @return string Lower-case tenant GUID, or '' when unset or malformed. */
    public function tenantId()
    {
        return $this->guid('tenantId');
    }

    /** @return string Lower-case client GUID, or '' when unset or malformed. */
    public function clientId()
    {
        return $this->guid('clientId');
    }

    /** @return bool */
    public function isConfigured()
    {
        return $this->tenantId() !== '' && $this->clientId() !== '';
    }

    /**
     * App role values a user must hold at least one of. Empty means no role check.
     *
     * @return string[]
     */
    public function requiredRoles()
    {
        $raw = (string) ($this->values['requiredRoles'] ?? '');
        return array_values(array_filter(array_map('trim', explode(',', $raw)), 'strlen'));
    }

    /** @return bool */
    public function alwaysPromptForAccount()
    {
        return ($this->values['selectAccount'] ?? '') === 'on';
    }

    /**
     * @param string $name
     * @return string
     */
    private function guid($name)
    {
        $value = strtolower(trim((string) ($this->values[$name] ?? '')));
        return Guid::isValid($value) ? $value : '';
    }
}
