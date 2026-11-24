<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

/**
 * Starts a WHMCS admin session for an admin whose identity has already been proven.
 *
 * WHMCS documents no API for this. It uses the same internal WHMCS\Auth calls
 * that WHMCS's own login runs after a password check. They are checked for
 * existence first so that a WHMCS upgrade that renames them fails closed with a
 * clear error instead of half-logging someone in. Password login is unaffected.
 */
final class AdminSession
{
    const REQUIRED_METHODS = ['getInfobyID', 'setSessionVars', 'processLogin'];

    /**
     * @param int $adminId
     * @throws \RuntimeException
     */
    public static function start($adminId)
    {
        if (!class_exists('\WHMCS\Auth')) {
            throw new \RuntimeException('This WHMCS version has no WHMCS\Auth class.');
        }
        $auth = new \WHMCS\Auth();
        foreach (self::REQUIRED_METHODS as $method) {
            if (!method_exists($auth, $method)) {
                throw new \RuntimeException('This WHMCS version has no WHMCS\Auth::' . $method . '().');
            }
        }
        if (!$auth->getInfobyID((int) $adminId)) {
            throw new \RuntimeException('WHMCS could not load admin ID ' . (int) $adminId . '.');
        }

        // New session ID at the privilege change, so a session ID planted before
        // sign-in cannot be used afterwards.
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }

        try {
            $auth->setSessionVars();
            $auth->processLogin();
        } catch (\Throwable $e) {
            // Never leave a half-built admin session behind.
            $_SESSION = [];
            throw new \RuntimeException('WHMCS refused to start the admin session: ' . $e->getMessage(), 0, $e);
        }
    }
}
