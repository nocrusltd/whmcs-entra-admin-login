<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

use WHMCS\Database\Capsule;

/**
 * Which Entra account may sign in as which WHMCS admin.
 *
 * Accounts are matched on the immutable (tenant ID, object ID) pair. Email
 * addresses and UPNs can be renamed or reassigned, so they are stored for
 * display only and never used to decide who someone is.
 */
final class Links
{
    const TABLE = 'mod_entra_admin_login_links';

    public static function createTable()
    {
        if (Capsule::schema()->hasTable(self::TABLE)) {
            return;
        }
        Capsule::schema()->create(self::TABLE, function ($table) {
            $table->increments('id');
            $table->integer('admin_id')->unsigned()->unique();
            $table->string('tenant_id', 36);
            $table->string('object_id', 36);
            $table->string('username', 255)->default('');
            $table->string('display_name', 255)->default('');
            $table->dateTime('linked_at')->nullable();
            $table->dateTime('last_login_at')->nullable();
            $table->unique(['tenant_id', 'object_id']);
        });
    }

    /**
     * @param string $tenantId
     * @param string $objectId
     * @return object|null
     */
    public static function findByAccount($tenantId, $objectId)
    {
        return Capsule::table(self::TABLE)
            ->where('tenant_id', strtolower($tenantId))
            ->where('object_id', strtolower($objectId))
            ->first();
    }

    /**
     * Links an Entra account to an admin, replacing any earlier link for that admin.
     *
     * @throws \RuntimeException When the account is already linked to a different admin.
     */
    public static function link($adminId, $tenantId, $objectId, $username, $displayName)
    {
        $tenantId = strtolower($tenantId);
        $objectId = strtolower($objectId);

        Capsule::connection()->transaction(function () use ($adminId, $tenantId, $objectId, $username, $displayName) {
            $existing = self::findByAccount($tenantId, $objectId);
            if ($existing && (int) $existing->admin_id !== (int) $adminId) {
                throw new \RuntimeException('That Microsoft account is already linked to another WHMCS admin.');
            }
            Capsule::table(self::TABLE)->where('admin_id', (int) $adminId)->delete();
            Capsule::table(self::TABLE)->insert([
                'admin_id' => (int) $adminId,
                'tenant_id' => $tenantId,
                'object_id' => $objectId,
                'username' => self::clip($username),
                'display_name' => self::clip($displayName),
                'linked_at' => date('Y-m-d H:i:s'),
            ]);
        });
    }

    /** @param int $adminId */
    public static function unlink($adminId)
    {
        return Capsule::table(self::TABLE)->where('admin_id', (int) $adminId)->delete();
    }

    public static function recordLogin($linkId, $username, $displayName)
    {
        Capsule::table(self::TABLE)->where('id', (int) $linkId)->update([
            'last_login_at' => date('Y-m-d H:i:s'),
            'username' => self::clip($username),
            'display_name' => self::clip($displayName),
        ]);
    }

    /** @return \Illuminate\Support\Collection Every admin with their link, if any. */
    public static function adminsWithLinks()
    {
        return Capsule::table('tbladmins as a')
            ->leftJoin(self::TABLE . ' as l', 'l.admin_id', '=', 'a.id')
            ->select(
                'a.id',
                'a.username as admin_username',
                'a.firstname',
                'a.lastname',
                'a.disabled',
                'l.username as entra_username',
                'l.display_name as entra_name',
                'l.linked_at',
                'l.last_login_at'
            )
            ->orderBy('a.username')
            ->get();
    }

    /**
     * @param mixed $value
     * @return string
     */
    private static function clip($value)
    {
        $value = is_string($value) ? $value : '';
        return function_exists('mb_substr') ? mb_substr($value, 0, 255) : substr($value, 0, 255);
    }
}
