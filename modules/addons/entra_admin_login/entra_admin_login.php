<?php
// SPDX-License-Identifier: MIT
//
// Entra ID Admin Login: sign in to the WHMCS admin area with a Microsoft Entra ID account.

use Nocrus\EntraAdminLogin\Links;
use Nocrus\EntraAdminLogin\LoginPageButton;
use Nocrus\EntraAdminLogin\Settings;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/lib/bootstrap.php';

if (!defined('ENTRA_ADMIN_LOGIN_VERSION')) {
    define('ENTRA_ADMIN_LOGIN_VERSION', '1.0.0');
}

function entra_admin_login_config()
{
    return [
        'name' => 'Entra ID Admin Login',
        'description' => 'Sign in to the admin area with a Microsoft Entra ID account (OpenID Connect, single tenant).',
        'version' => ENTRA_ADMIN_LOGIN_VERSION,
        'author' => 'Nocrus Limited',
        'language' => 'english',
        'fields' => [
            'tenantId' => [
                'FriendlyName' => 'Directory (tenant) ID',
                'Type' => 'text',
                'Size' => '40',
                'Description' => 'GUID of the Entra ID tenant. Only accounts from this tenant can sign in.',
            ],
            'clientId' => [
                'FriendlyName' => 'Application (client) ID',
                'Type' => 'text',
                'Size' => '40',
                'Description' => 'GUID of the app registration.',
            ],
            'requiredRoles' => [
                'FriendlyName' => 'Required app roles',
                'Type' => 'text',
                'Size' => '60',
                'Description' => 'Optional, comma separated. The user must hold at least one of these app role values.',
            ],
            'selectAccount' => [
                'FriendlyName' => 'Always show account picker',
                'Type' => 'yesno',
                'Description' => 'Ask which Microsoft account to use on every sign-in.',
            ],
        ],
    ];
}

function entra_admin_login_activate()
{
    try {
        Links::createTable();
    } catch (\Exception $e) {
        return ['status' => 'error', 'description' => 'Could not create the link table: ' . $e->getMessage()];
    }

    try {
        entra_admin_login_set_button(true);
        $button = ' The "Sign in with Microsoft" button was added to the admin login page.';
    } catch (\Exception $e) {
        $button = ' The login page button was not added: ' . $e->getMessage();
    }

    return [
        'status' => 'success',
        'description' => 'Activated. Enter the tenant and client IDs, then link admin accounts from Addons > Entra ID Admin Login.' . $button,
    ];
}

function entra_admin_login_deactivate()
{
    // The link table is kept, so deactivating and reactivating does not make
    // every admin link again. Drop mod_entra_admin_login_links by hand to remove it.
    try {
        entra_admin_login_set_button(false);
        $button = ' The login page button was removed.';
    } catch (\Exception $e) {
        $button = ' The login page button could not be removed: ' . $e->getMessage();
    }
    return ['status' => 'success', 'description' => 'Deactivated. Account links were kept.' . $button];
}

/**
 * The addon page: shows the redirect URI, lets the signed-in admin link their
 * own Microsoft account, and lets admins remove links.
 *
 * @param array $vars
 */
function entra_admin_login_output($vars)
{
    $settings = Settings::load();
    $e = function ($value) {
        return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    };

    $notice = '';
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['entra_action'] ?? '') === 'unlink') {
        check_token('WHMCS.admin.default');
        // Admins can only remove their own link. To cut someone else off, disable
        // their WHMCS admin account or remove them from the Entra app assignment.
        $adminId = (int) ($_SESSION['adminid'] ?? 0);
        if ($adminId > 0 && Links::unlink($adminId)) {
            logActivity('Entra ID Admin Login: Microsoft account unlinked from admin ID ' . $adminId);
            $notice = '<div class="alert alert-success">Microsoft account unlinked.</div>';
        }
    }
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && in_array($_POST['entra_action'] ?? '', ['button_on', 'button_off'], true)) {
        check_token('WHMCS.admin.default');
        $on = $_POST['entra_action'] === 'button_on';
        try {
            entra_admin_login_set_button($on);
            logActivity('Entra ID Admin Login: login page button ' . ($on ? 'added' : 'removed'));
            $notice = '<div class="alert alert-success">Login page button ' . ($on ? 'added' : 'removed') . '.</div>';
        } catch (\Exception $ex) {
            $notice = '<div class="alert alert-danger">' . $e($ex->getMessage()) . '</div>';
        }
    }
    if (isset($_GET['linked'])) {
        $notice = '<div class="alert alert-success">Your Microsoft account is linked. You can now use the sign-in URL below.</div>';
    }

    $loginUrl = entra_admin_login_url();
    echo $notice;

    // The sign-in flow lives in the PHP session, whose cookie belongs to the host
    // the admin is using. Linking and sign-in only work on the System URL's host.
    $systemHost = strtolower((string) parse_url($loginUrl, PHP_URL_HOST));
    $currentHost = strtolower((string) preg_replace('/:\d+$/', '', (string) ($_SERVER['HTTP_HOST'] ?? '')));
    if ($systemHost !== '' && $currentHost !== '' && $systemHost !== $currentHost) {
        echo '<div class="alert alert-warning">You are using <strong>' . $e($currentHost) . '</strong> but the WHMCS System URL is on <strong>'
            . $e($systemHost) . '</strong>. Linking and Microsoft sign-in only work on <strong>' . $e($systemHost)
            . '</strong>; open the admin area there first.</div>';
    }

    if (!$settings->isConfigured()) {
        echo '<div class="alert alert-warning">Enter a valid tenant ID and client ID under '
            . 'System Settings &gt; Addon Modules &gt; Entra ID Admin Login before linking accounts.</div>';
    }

    echo '<div class="panel panel-default"><div class="panel-heading"><strong>Sign-in URL</strong></div><div class="panel-body">'
        . '<p>Register this exact URL as a <strong>Mobile and desktop applications</strong> redirect URI on the app registration. '
        . 'It is also the address admins use to sign in with Microsoft.</p>'
        . '<p><code>' . $e($loginUrl) . '</code></p>'
        . '</div></div>';

    // Login page button status.
    try {
        $buttonOn = LoginPageButton::isApplied((string) file_get_contents(entra_admin_login_login_template()));
        $buttonState = $buttonOn
            ? '<span class="label label-success">On the login page</span>'
            : '<span class="label label-warning">Not on the login page</span> A WHMCS update replaces the login template and removes the button; add it again here.';
    } catch (\Exception $ex) {
        $buttonOn = null;
        $buttonState = '<span class="label label-danger">Login template not readable</span>';
    }
    echo '<div class="panel panel-default"><div class="panel-heading"><strong>Admin login page button</strong></div><div class="panel-body">'
        . '<p>Shows "Sign in with Microsoft" above the username and password form, which stays available as the fallback.</p>'
        . '<p>' . $buttonState . '</p>';
    if ($buttonOn !== null) {
        echo '<form method="post" action="' . $e($vars['modulelink']) . '">'
            . generate_token('form')
            . '<input type="hidden" name="entra_action" value="' . ($buttonOn ? 'button_off' : 'button_on') . '">'
            . '<button type="submit" class="btn btn-sm ' . ($buttonOn ? 'btn-default">Remove button' : 'btn-primary">Add button') . '</button>'
            . '</form>';
    }
    echo '</div></div>';

    if ($settings->isConfigured()) {
        // POST with the WHMCS CSRF token, so another site cannot start a link for a signed-in admin.
        echo '<form method="post" action="' . $e($loginUrl . '?action=link') . '">'
            . generate_token('form')
            . '<button type="submit" class="btn btn-primary">Link my Microsoft account</button>'
            . '</form><br>';
    }

    echo '<table class="table table-striped"><thead><tr>'
        . '<th>WHMCS admin</th><th>Microsoft account</th><th>Linked</th><th>Last Microsoft sign-in</th><th></th>'
        . '</tr></thead><tbody>';

    $currentAdmin = (int) ($_SESSION['adminid'] ?? 0);
    foreach (Links::adminsWithLinks() as $row) {
        $name = trim($row->firstname . ' ' . $row->lastname);
        echo '<tr><td>' . $e($row->admin_username)
            . ($name !== '' ? ' <span class="text-muted">(' . $e($name) . ')</span>' : '')
            . ($row->disabled ? ' <span class="label label-default">disabled</span>' : '')
            . ((int) $row->id === $currentAdmin ? ' <span class="label label-info">you</span>' : '')
            . '</td>';

        if ($row->linked_at === null) {
            echo '<td colspan="4" class="text-muted">Not linked</td></tr>';
            continue;
        }

        echo '<td>' . $e($row->entra_name) . '<br><small>' . $e($row->entra_username) . '</small></td>'
            . '<td>' . $e($row->linked_at) . '</td>'
            . '<td>' . $e($row->last_login_at ?: 'Never') . '</td>'
            . '<td>';
        if ((int) $row->id === $currentAdmin) {
            echo '<form method="post" action="' . $e($vars['modulelink']) . '">'
                . generate_token('form')
                . '<input type="hidden" name="entra_action" value="unlink">'
                . '<button type="submit" class="btn btn-xs btn-danger">Unlink</button>'
                . '</form>';
        }
        echo '</td></tr>';
    }

    echo '</tbody></table>';
}

/** @return string Absolute URL of login.php, which is also the OIDC redirect URI. */
function entra_admin_login_url()
{
    $systemUrl = rtrim((string) \WHMCS\Config\Setting::getValue('SystemURL'), '/');
    return $systemUrl . '/modules/addons/' . Settings::MODULE . '/login.php';
}

/** @return string Absolute URL of the admin area. */
function entra_admin_login_admin_url()
{
    $systemUrl = rtrim((string) \WHMCS\Config\Setting::getValue('SystemURL'), '/');
    return $systemUrl . '/' . trim(entra_admin_login_admin_folder(), '/') . '/';
}

/** @return string Path of the admin login template. */
function entra_admin_login_login_template()
{
    $root = defined('ROOTDIR') ? ROOTDIR : dirname(__DIR__, 3);
    return rtrim($root, '/') . '/' . trim(entra_admin_login_admin_folder(), '/') . '/templates/login.tpl';
}

/** @return string Name of the admin folder. */
function entra_admin_login_admin_folder()
{
    return isset($GLOBALS['customadminpath']) && is_string($GLOBALS['customadminpath']) && $GLOBALS['customadminpath'] !== ''
        ? $GLOBALS['customadminpath']
        : 'admin';
}

/**
 * Adds or removes the login page button. Writes a temporary file next to the
 * template and renames it over the original, so the template is never half-written.
 *
 * @param bool $on
 * @throws \RuntimeException
 */
function entra_admin_login_set_button($on)
{
    $path = entra_admin_login_login_template();
    $current = is_readable($path) ? file_get_contents($path) : false;
    if ($current === false) {
        throw new \RuntimeException('Cannot read ' . $path . '.');
    }
    $updated = $on ? LoginPageButton::apply($current) : LoginPageButton::remove($current);
    if ($updated === $current) {
        return;
    }

    $temp = $path . '.entra-' . bin2hex(random_bytes(6)) . '.tmp';
    if (file_put_contents($temp, $updated) !== strlen($updated)) {
        @unlink($temp);
        throw new \RuntimeException('Cannot write next to ' . $path . '.');
    }
    $mode = @fileperms($path);
    if ($mode !== false) {
        @chmod($temp, $mode & 0777);
    }
    if (!@rename($temp, $path)) {
        @unlink($temp);
        throw new \RuntimeException('Cannot replace ' . $path . '.');
    }
}
