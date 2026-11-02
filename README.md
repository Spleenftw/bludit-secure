# bludit-secure

OIDC SSO, TOTP and passkey second-factor authentication for **Bludit 3.22.0**.

Current version: **0.1.5 — experimental**. Test on a copy of your site before deployment.

## Features

- Keeps the existing Bludit login page, theme and password form.
- Adds a full-width, slate-grey **Sign in with XYZ** button with a configurable provider name.
- Automatically opens the browser passkey prompt after password verification when a passkey is enabled. Cancellation does not trigger a prompt loop; an explicit retry remains available.
- Integrates **Security** into the native admin dashboard, including its sidebar, shield icon and Bootstrap controls. Sign out through the existing **Log out** sidebar entry.
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

unzip -o /tmp/bludit-secure-0.1.5.zip -d /tmp/bludit-secure-0.1.5

docker cp /tmp/bludit-secure-0.1.5/bludit-secure/. \
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

Authorization Code flow uses PKCE S256. The jumbojett library checks state, nonce, token signature and claims. Bludit account roles remain authoritative; the plugin does not create accounts or assign roles from provider claims.

Logging out ends the Bludit session only. Provider-wide logout and OIDC back-channel logout are not implemented.

## Per-user security settings

In **Security**:

- **TOTP:** select **Set up TOTP**, copy the `otpauth://` setup URI into your authenticator app and confirm a code. TOTP uses SHA-1, six digits and a 30-second period. Previously accepted codes cannot be reused.
- **Passkeys:** select **Add passkey**, enter a name and choose your password manager or authenticator in the browser. Multiple passkeys are supported, with user verification required. The browser selects the authenticator; the plugin does not force a particular manager.
- **Second factor:** choose the required method and whether it also applies after SSO. **TOTP or passkey** requires both methods to be registered.
- **Recovery:** generate codes and store them separately. Generating new codes invalidates all previous codes.

Registering your first factor automatically enables its corresponding verification mode. Before removing a required factor, select a compatible mode or explicitly disable second-factor authentication. Deleting a factor never silently disables protection.

Changes require a completed sign-in within the last five minutes. After that, use **Log out** in the sidebar and sign in again with your existing factors. Changes invalidate other plugin sessions for that account. There is no site-wide mandatory MFA policy in this version.

## Storage and recovery

TOTP secrets, passkey public keys, linked identities, recovery-code hashes and rate-limit records are stored in an authenticated, sodium-encrypted file. The encryption key is stored separately in the same private plugin data directory. Files have a PHP exit preamble and permissions of 0600. Encryption does not protect against an attacker who can read both the server files and the key.

Back up `secure.key.php`, `secure.data.php` and the Bludit user database together. Losing the key makes stored factors unrecoverable. Do not reuse an old account name for another person without removing its security registrations. The OIDC client secret is stored in the regular plugin configuration; protect that file and its backups too.

Incomplete sign-ins expire after five minutes; WebAuthn challenges expire after two minutes. Persistent verification budgets allow ten attempts per account and IP over five minutes, with separate budgets for management and enrollment. The plugin checks authentication before Bludit dispatches admin AJAX requests.

If all factors are lost, use a recovery code. Without one, a server administrator can temporarily move `bl-plugins/bludit-secure/` **outside `bl-plugins`** to restore native login. Restrict admin access during this maintenance operation, then restore the plugin and repair registrations. Uninstalling the plugin through Bludit deletes its data; it is not a temporary disable operation.

The plugin protects **web sessions under `/admin`**. It does not change authentication for the Bludit API, other plugins or external services.

JavaScript URLs include a content hash so updated passkey behavior is not hidden by stale asset caches.

## Validation

```sh
php tests/core.php
composer validate --no-check-publish
composer audit --no-dev
# With Node.js installed:
node tests/auto-passkey.cjs
```

HTTP tests in `tests/http_totp.py` and `tests/http_webauthn.py` require a **disposable** Bludit 3.22.0 instance with the plugin activated and test credentials `admin / TestPassword123`. The fixture uses a configured public URL of `https://127.0.0.1:18765/` and a PHP test server at `http://127.0.0.1:18765/`. HTTP transport and simulated HTTPS origins are fixture-only and do not replace real browser testing.

Set `TEST_PHP` (PHP executable), `TEST_PHP_INI` (php.ini) and `TEST_BLUDIT` (fixture root). `TEST_BASE` is optional. Run `http_totp.py` on a fresh fixture, then `http_webauthn.py`. **The WebAuthn test deletes plugin security records in that fixture. Never point it at a real site.**

Local checks cover PHP 8.4 syntax, RFC 6238 vectors, encrypted storage and tampering, transactions, persistent limits, native login CSRF, pending-session dashboard/AJAX protection, TOTP and recovery-code replay rejection, signed WebAuthn registration and assertions, invalid origins/signatures, consumed challenges, native admin integration and automatic prompting without cancellation loops.

The password-to-passkey browser flow over HTTPS was also reported working by the user. A complete live Pocket ID flow, backup restoration and compatibility with other authentication plugins still require validation. The latest local dependency audit reported no known advisories; rerun it before release.

## Changes in 0.1.5

- Retains the native login page and integrates Security into the dashboard.
- Automatically requests a passkey after password verification.
- Versions JavaScript URLs by content hash.
- Uses English interface text and native dropdown styling.
- Adds a sidebar shield icon and removes duplicate sign-out buttons.
- Styles the SSO button as a full-width secondary action with spacing below Login.
