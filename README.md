# WHMCS Entra ID Admin Login

A WHMCS addon module that lets administrators sign in to the WHMCS admin area with their Microsoft Entra ID account, using OpenID Connect.

WHMCS has no built-in way to do this. Its own "OpenID Connect" feature runs the other way: WHMCS acts as the identity provider for other apps.

- Authorisation code flow with PKCE, plus `state` and `nonce`. The app is a public client, so there is no client secret to store, rotate or let expire.
- The ID token's RS256 signature is checked against the tenant's published keys, along with its issuer, tenant, audience, version, expiry and nonce.
- Locked to one tenant. Multi-tenant and personal Microsoft accounts are rejected.
- Admins are matched on their immutable Entra object ID. Email addresses and UPNs are never used to decide who someone is.
- Optional app-role requirement.
- Every sign-in, link and failure is written to the WHMCS activity log.
- No dependencies: install it by copying one folder.

Requires WHMCS 8 or 9 and PHP 7.4 or later with the `curl` and `openssl` extensions.

## How it signs admins in

WHMCS documents no API for starting an admin session from a module. After Entra has proven who someone is, this addon calls the same internal `WHMCS\Auth` methods (`getInfobyID`, `setSessionVars`, `processLogin`) that WHMCS's own login calls after a password check. They are checked for existence before use, so if a WHMCS upgrade renames them, Microsoft sign-in fails closed with a clear message. **Password login is never changed or disabled** and remains your way in if Entra or this addon is unavailable.

Signing in with Microsoft does **not** go through WHMCS two-factor authentication. Enforce MFA in Entra ID instead (Conditional Access or security defaults).

## Install

1. Copy `modules/addons/entra_admin_login` into your WHMCS installation, so it lives at `<whmcs>/modules/addons/entra_admin_login`.
2. In WHMCS, go to **System Settings > Addon Modules**, activate **Entra ID Admin Login**, and give your admin role access to it.
3. Open **Addons > Entra ID Admin Login** to see the exact sign-in URL for your installation. It is `<WHMCS System URL>/modules/addons/entra_admin_login/login.php`.

## Register the app in Entra ID

With the Azure CLI, signed in to the right tenant (`az account show` to check):

```bash
REDIRECT_URI='https://billing.example.com/modules/addons/entra_admin_login/login.php'

# Single-tenant app with a public-client (mobile and desktop) redirect URI.
APP_ID=$(az ad app create \
  --display-name 'WHMCS admin login' \
  --sign-in-audience AzureADMyOrg \
  --public-client-redirect-uris "$REDIRECT_URI" \
  --query appId -o tsv)

# Service principal, and require assignment so only assigned users and groups can sign in.
SP_ID=$(az ad sp create --id "$APP_ID" --query id -o tsv)
az ad sp update --id "$SP_ID" --set appRoleAssignmentRequired=true

az account show --query tenantId -o tsv   # Directory (tenant) ID
echo "$APP_ID"                             # Application (client) ID
```

Then:

- **Assign users or groups** to the enterprise application (Entra admin center > Enterprise applications > the app > Users and groups). Only assigned users can sign in.
- **Grant admin consent** for the `openid`, `profile` and `email` delegated permissions if your tenant does not allow user consent.

The redirect URI must be registered as a **public client** (Mobile and desktop applications) redirect, not a Web redirect, because the addon redeems the code without a client secret. It must match the sign-in URL exactly, including scheme and path.

## Configure

Under **System Settings > Addon Modules > Entra ID Admin Login > Configure**:

| Setting | Meaning |
| --- | --- |
| Directory (tenant) ID | Tenant GUID. Names such as `common` or `organizations` are rejected. |
| Application (client) ID | The app registration's client ID. |
| Required app roles | Optional, comma separated. When set, the user's token must carry at least one of these app role values. Define the roles on the app registration and assign them. |
| Always show account picker | Ask which Microsoft account to use on every sign-in. |

## Link admins

An admin must link their Microsoft account before they can sign in with it:

1. Sign in to WHMCS with your password.
2. Open **Addons > Entra ID Admin Login** and click **Link my Microsoft account**.
3. Enter your Microsoft credentials when asked. Linking always asks for them, even if you are already signed in to Microsoft in that browser.

Each Microsoft account can be linked to one WHMCS admin, and each admin to one Microsoft account. The addon page lists every link and lets admins remove them. Disabled WHMCS admins cannot sign in, linked or not.

There is deliberately no automatic linking by email address: an attacker who could set an email address on either side would otherwise get an admin session.

## Sign in

Open the sign-in URL (bookmark it). There is no documented hook for adding a button to the WHMCS admin login page. To add one, edit your admin login template and re-apply the change after WHMCS upgrades:

```html
<a href="../modules/addons/entra_admin_login/login.php" class="btn btn-default btn-block">Sign in with Microsoft</a>
```

## Removing the addon

Deactivating the addon stops Microsoft sign-in immediately. Account links are kept in the `mod_entra_admin_login_links` table so that reactivating does not make every admin link again. Drop that table to remove them.

## Development

The tests need only the PHP CLI with the `openssl` extension:

```bash
php tests/run.php
# or, without a local PHP:
docker run --rm -v "$PWD":/app -w /app php:8.3-cli php tests/run.php
```

CI runs them on PHP 7.4 to 8.4. The tests cover the token validator, key handling and OIDC client. The parts that talk to WHMCS (`login.php`, the addon page and `AdminSession`) can only be tested against a real WHMCS installation.

## Security

Please report vulnerabilities privately via GitHub's "Report a vulnerability" on this repository rather than in a public issue.

## Licence

[MIT](LICENSE). Not affiliated with or endorsed by WHMCS or Microsoft.
