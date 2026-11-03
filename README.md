# bludit-secure

OIDC SSO, TOTP and passkey second-factor authentication for **Bludit 3.22.0**.

Current version: **0.1.6 — experimental**. Test on a copy of your site before deployment.

## Features

- Keeps the existing Bludit login page, theme and password form.
- Adds a full-width, slate-grey **Sign in with XYZ** button with a configurable provider name.
- Automatically opens the browser passkey prompt after password verification when a passkey is enabled. Cancellation does not trigger a prompt loop; an explicit retry remains available.
- Integrates **Security** into the native admin dashboard, including its sidebar, shield icon and Bootstrap controls. Sign out through the existing **Log out** sidebar entry.
- Shows SSO link status, provider, SSO username and SSO email in the administrator's native **Users** list and the user's **Security** page.
- Lets each user register TOTP, multiple named passkeys and an OIDC identity, then choose their own second-factor policy: disabled, TOTP, passkey, or either method.
- Optionally requires the local second factor after SSO as well.
- Provides ten single-use recovery codes, shown once and replaceable at any time.
- Uses English for all plugin interface text. No specific password manager is required.

Local passkeys belong to the **Bludit domain**. Your identity provider's passkeys belong to the **provider domain**. These are separate registrations. Local passkeys act as a second factor after a password or SSO; passwordless local login is not implemented.

## Requirements

- Bludit **3.22.0** and PHP **8.2+**.
- PHP extensions: sodium, curl, mbstring and openssl, plus the usual Bludit requirements.
- A valid HTTPS public URL configured in Bludit's advanced settings. HTTPS termination at a reverse proxy alone does not update this setting.
- Write access for PHP to `bl-content/databases/plugins/bludit-secure/`.
- Network access from PHP to the OIDC provider's discovery, token and signing-key endpoints.
- A trusted reverse proxy configuration that supplies the actual client address as `REMOTE_ADDR` for rate limiting. Do not trust arbitrary client-supplied forwarding headers.

## Installation

Download the installable release ZIP and extract its `bludit-secure/` directory into `bl-plugins/`. Release packages include the required Composer dependencies. If installing from a source archive or checkout, install the dependencies before activating the plugin.

1. Back up your site and `bl-content`; retain server access for recovery.
2. Extract the packaged ZIP so the entry point is `bl-plugins/bludit-secure/plugin.php`.
3. Verify that `bl-plugins/bludit-secure/vendor/autoload.php` exists.
4. Configure Bludit's public URL with its exact HTTPS address, then activate **Bludit Secure**.
5. Sign in again and open **Security** in the admin sidebar.

Existing native Bludit sessions and remember-me cookies cannot bypass the plugin. Activation requires a fresh plugin-authenticated session.

Packaged ZIPs include dependencies. Git checkouts do **not** include `vendor/`; install the locked dependencies before activation:

```sh
composer install --no-dev --prefer-dist --optimize-autoloader
```

Activating without dependencies or with an HTTP site URL will block access to the admin area until the problem is corrected.

### Docker updates

For `bludit/docker`, copy the extracted plugin into `/usr/share/nginx/html/bl-plugins/bludit-secure/`. Example on the Docker host, with the ZIP already in `/tmp`:

```sh
docker cp bludit:/usr/share/nginx/html/bl-plugins/bludit-secure \
  "/tmp/bludit-secure-backup-$(date +%Y%m%d-%H%M%S)"

unzip -o /tmp/bludit-secure-0.1.6.zip -d /tmp/bludit-secure-0.1.6

docker cp /tmp/bludit-secure-0.1.6/bludit-secure/. \
  bludit:/usr/share/nginx/html/bl-plugins/bludit-secure/

docker restart bludit
```

This updates plugin files. Account settings and enrolled factors remain in `bl-content`. Persist both plugin files and `bl-content` with appropriate mounts so container recreation does not discard them.

## OIDC configuration

Create a confidential OIDC client in your provider, such as Pocket ID. Register the exact redirect URI displayed in the plugin settings, for example:

```text
https://blog.example/admin/login?bs=oidc
```

The URI respects Bludit's configured admin path and installation subdirectory. Enter the exact issuer URL, client ID and client secret. Choose the provider name displayed in **Sign in with XYZ**. Leaving the client secret field blank preserves its current value.

Each user first signs in to their existing Bludit account, opens **Security**, then selects **Link account to …**. After provider authentication, the identity is associated with that account using **issuer + subject**. Identities are never linked automatically by email. A provider identity cannot be linked to two accounts.

The plugin requests `openid profile email`. The provider's username (`preferred_username`) and email are display information, stored in the encrypted plugin database. They do not change the Bludit username, email or role and are never used to associate accounts. Emails not marked verified by the provider are labeled accordingly. Administrators can see these details on **Users**; each user can see their own on **Security**.

Existing SSO links remain valid. Sign in with SSO once after upgrading to populate the username and email; the provider may ask you to approve the additional scopes. Profile details refresh after a successful SSO sign-in, including the local second factor when required. Missing optional claims are shown as **Not provided**. Unlinking SSO removes its stored profile details.

Authorization Code flow uses PKCE S256. The jumbojett library checks state, nonce, token signature and claims. Bludit account roles remain authoritative; the plugin does not create accounts or assign roles from provider claims.

The plugin requires advertised PKCE S256 support, a matching nonce, integer `iat` and `exp` claims, and a matching authorized party (`azp`) for multiple audiences. State is checked before contacting the token endpoint. Discovery, token and signing-key endpoints must use direct HTTPS URLs: HTTP and endpoint redirects are rejected. Responses are limited to 1 MiB. Authorization starts have a separate persistent attempt budget. Changing the global SSO configuration requires an administrator sign-in within the last five minutes.

Logging out ends the Bludit session only. Provider-wide logout and OIDC back-channel logout are not implemented.

## Per-user security settings

In **Security**:

- **TOTP:** select **Set up TOTP**, copy the `otpauth://` setup URI into your authenticator app and confirm a code. TOTP uses SHA-1, six digits and a 30-second period. Previously accepted codes cannot be reused.
- **Passkeys:** select **Add passkey**, enter a name and choose your password manager or authenticator in the browser. Multiple passkeys are supported, with user verification required. The browser selects the authenticator; the plugin does not force a particular manager.
- **Second factor:** choose the required method and whether it also applies after SSO. **TOTP or passkey** requires both methods to be registered.
- **Recovery:** generate codes and store them separately. Generating new codes invalidates all previous codes.

Registering your first factor automatically enables its corresponding verification mode. Before removing a required factor, select a compatible mode or explicitly disable second-factor authentication. Deleting a factor never silently disables protection.

Changes require a completed sign-in within the last five minutes. After that, use **Log out** in the sidebar and sign in again with your existing factors. Changes invalidate other plugin sessions for that account. There is no site-wide mandatory MFA policy in this version.

Native password, password salt or role changes invalidate plugin sessions and pending sign-ins on their next request. A changed role takes effect after a fresh sign-in.

## Storage and recovery

TOTP secrets, passkey public keys, linked identities, recovery-code hashes and rate-limit records are stored in an authenticated, sodium-encrypted file. The encryption key is stored separately in the same private plugin data directory. Files have a PHP exit preamble and permissions of 0600. Encryption does not protect against an attacker who can read both the server files and the key.

Back up `secure.key.php`, `secure.data.php` and the Bludit user database together. Losing the key makes stored factors unrecoverable. Do not reuse an old account name for another person without removing its security registrations. The OIDC client secret is stored in the regular plugin configuration; protect that file and its backups too.

The encryption key and encrypted database are created together. If either file subsequently disappears while the other remains, authentication fails closed; restore the matching pair from backup. A legacy installation containing a key but no database also requires manual recovery. The plugin cannot distinguish deletion of both files from a fresh installation.

Incomplete sign-ins expire after five minutes; WebAuthn challenges expire after two minutes. Persistent verification budgets allow ten attempts per account and IP over five minutes, with separate budgets for management and enrollment. The plugin checks authentication before Bludit dispatches admin AJAX requests.

If all factors are lost, use a recovery code. Without one, a server administrator can temporarily move `bl-plugins/bludit-secure/` **outside `bl-plugins`** to restore native login. Restrict admin access during this maintenance operation, then restore the plugin and repair registrations. Uninstalling the plugin through Bludit deletes its data; it is not a temporary disable operation.

The plugin protects **web sessions under `/admin`**. It does not change authentication for the Bludit API, other plugins or external services.

JavaScript URLs include a content hash so updated passkey behavior is not hidden by stale asset caches.

## Changes in 0.1.6

- Adds SSO link status, provider, username and email to the native administrator Users table.
- Displays the linked SSO profile on Security and refreshes it after completed SSO sign-in.
- Requests profile and email scopes while keeping account matching strictly on issuer and subject.
- Preserves existing registrations and indicates when an older link needs an SSO sign-in to load profile details.

## Changes in 0.1.5

- Retains the native login page and integrates Security into the dashboard.
- Automatically requests a passkey after password verification.
- Versions JavaScript URLs by content hash.
- Uses English interface text and native dropdown styling.
- Adds a sidebar shield icon and removes duplicate sign-out buttons.
- Styles the SSO button as a full-width secondary action with spacing below Login.
