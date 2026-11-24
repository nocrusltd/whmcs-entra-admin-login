<?php
// SPDX-License-Identifier: MIT

namespace Nocrus\EntraAdminLogin;

/**
 * Adds a "Sign in with Microsoft" button above the password form on the WHMCS
 * admin login page, and removes it again.
 *
 * The admin login template has no hook output, so the only way to put a button
 * there is to edit admin/templates/login.tpl. The edit is one clearly marked
 * block, applied and removed only by this class. WHMCS updates overwrite the
 * template, which simply drops the block; the addon page shows that and offers
 * to re-apply it. The password form itself is never changed.
 */
final class LoginPageButton
{
    const START = '{* entra_admin_login:start - added by the Entra ID Admin Login addon; manage it from Addons > Entra ID Admin Login *}';
    const END = '{* entra_admin_login:end *}';

    /** The login step's opening, immediately followed by the password form. */
    const ANCHOR = '/(\{if \$step eq "login"\}[ \t]*\r?\n)([ \t]*)(<form method="post" action="dologin\.php">)/';

    /**
     * @param string $template
     * @return bool
     */
    public static function isApplied($template)
    {
        return strpos($template, self::START) !== false;
    }

    /**
     * @param string $template Contents of admin/templates/login.tpl.
     * @return string The template with the button block added. Unchanged if already there.
     * @throws \RuntimeException When the login form is not found exactly once where expected.
     */
    public static function apply($template)
    {
        if (self::isApplied($template)) {
            return $template;
        }
        if (preg_match_all(self::ANCHOR, $template) !== 1) {
            throw new \RuntimeException('The admin login template does not have the expected login form, so the button was not added.');
        }
        $newline = strpos($template, "\r\n") !== false ? "\r\n" : "\n";

        return preg_replace_callback(self::ANCHOR, function ($m) use ($newline) {
            return $m[1] . self::block($m[2], $newline) . $m[2] . $m[3];
        }, $template, 1);
    }

    /**
     * @param string $template
     * @return string The template without the button block.
     */
    public static function remove($template)
    {
        $pattern = '/[ \t]*' . preg_quote(self::START, '/') . '.*?' . preg_quote(self::END, '/') . '[ \t]*\r?\n/s';
        return preg_replace($pattern, '', $template);
    }

    /**
     * @param string $indent
     * @param string $newline
     * @return string
     */
    private static function block($indent, $newline)
    {
        // The admin login page is <admin folder>/login.php, one level below the
        // WHMCS root, so this relative link works whatever the folder is called.
        $lines = [
            self::START,
            '<a href="../modules/addons/entra_admin_login/login.php" class="btn btn-primary btn-block">Sign in with Microsoft</a>',
            '<p class="text-center text-muted" style="margin:15px 0">or sign in with your WHMCS password</p>',
            self::END,
        ];
        $out = '';
        foreach ($lines as $line) {
            $out .= $indent . $line . $newline;
        }
        return $out;
    }
}
