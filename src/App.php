<?php
namespace BluditSecure;

final class UserError extends \RuntimeException {}

final class App
{
    private Store $store;
    private $plugin;
    private string $base;
    private string $origin;
    public function __construct($plugin) {
        $this->plugin = $plugin;
        $this->store = new Store($plugin->phpPathDB());
        $this->base = DOMAIN_ADMIN.'login';
        $parts = parse_url(DOMAIN_ADMIN);
        if (($parts['scheme'] ?? '') !== 'https') { throw new UserError('HTTPS is required'); }
        $this->origin = 'https://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '');
    }
    private function scriptUrl(): string {
        $version = substr(hash_file('sha256', dirname(__DIR__).'/assets/secure.js'), 0, 16);
        return $this->plugin->htmlPath().'assets/secure.js?v='.$version;
    }
    private function cfg(string $key): string { return trim($this->plugin->getValue($key, false)); }
    private function ssoEnabled(): bool { return $this->cfg('issuer') !== '' && $this->cfg('clientId') !== '' && $this->cfg('clientSecret') !== ''; }
    private function e(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
    public function accountUrl(): string { return DOMAIN_ADMIN.'plugin/'.strtolower(get_class($this->plugin)); }
    private function go(string $action = ''): never {
        $url = $action === 'account' ? $this->accountUrl() : $this->base.($action ? '?bs='.$action : '');
        header('Location: '.$url, true, 303); exit;
    }
    private function form(string $action, string $body): string {
        return '<form method="post" action="'.$this->e($this->base.'?bs='.$action).'"><input type="hidden" name="secureCsrf" value="'.$this->e($_SESSION['bs']['csrf']).'">'.$body.'</form>';
    }
    private function json(mixed $data, int $status = 200): never {
        http_response_code($status); header('Content-Type: application/json'); header('Cache-Control: no-store'); echo json_encode($data, JSON_THROW_ON_ERROR); exit;
    }
    private function csrf(): void {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !hash_equals($_SESSION['bs']['csrf'], (string)($_POST['secureCsrf'] ?? ''))) { throw new UserError('Invalid CSRF'); }
    }
    private function user(string $name): array {
        global $users;
        $u = $users->getUserDB($name);
        if (!$u || ($u['password'] ?? '!') === '!') { throw new UserError('Account unavailable'); }
        return $u;
    }
    /** Bind authentication to the native credentials and role, without storing them in the session. */
    private function userStamp(array $user): string {
        return hash('sha256', json_encode([$user['password'], $user['salt'] ?? '', $user['role']], JSON_THROW_ON_ERROR));
    }
    private function allowed(array $a, string $factor): bool {
        return $a['mode'] === 'either' || $a['mode'] === $factor;
    }
    private function requiresMfa(array $a, string $via): bool { return $a['mode'] !== 'off' && ($via !== 'sso' || $a['ssoMfa']); }
    private function pending(string $name, string $via, ?int $revision = null, ?string $userStamp = null): void {
        $user = $this->user($name);
        $a = $this->store->get($name);
        if (($revision !== null && $a['revision'] !== $revision) || ($userStamp !== null && $this->userStamp($user) !== $userStamp)) { throw new UserError('Account changed. Please sign in again.'); }
        session_regenerate_id(true);
        // Do not carry enrollment secrets, recovery codes or linking flows across sign-ins.
        $_SESSION['bs'] = ['csrf'=>bin2hex(random_bytes(32))];
        $_SESSION['bs']['pending'] = ['name'=>$name, 'via'=>$via, 'expires'=>time()+300, 'revision'=>$a['revision'], 'userStamp'=>$this->userStamp($user)];
        if (!$this->requiresMfa($a, $via)) { $this->finish($name); }
        $this->go('mfa');
    }
    private function finish(string $name): never {
        $this->completePending($name);
        header('Location: '.DOMAIN_ADMIN, true, 303); exit;
    }
    private function completePending(string $name): void {
        global $login, $security;
        $p = $this->pendingUser();
        if ($p['name'] !== $name) { throw new UserError('Invalid sign-in account.'); }
        // Recheck under the storage lock: a concurrent factor change must revoke this login.
        $this->store->transaction(function (&$d) use ($name, $p, $login, $security) {
            $u = $this->user($name); $a = Store::account($d, $name);
            if ($a['revision'] !== $p['revision'] || $this->userStamp($u) !== $p['userStamp']) { throw new UserError('Account changed. Please sign in again.'); }
            $login->setLogin($name, $u['role']);
            $security->generateTokenCSRF();
            $_SESSION['bs']['auth'] = ['name'=>$name, 'at'=>time(), 'revision'=>$p['revision'], 'userStamp'=>$p['userStamp']];
        });
        unset($_SESSION['bs']['pending'], $_SESSION['bs']['challenge']);
        $_SESSION['bs']['csrf'] = bin2hex(random_bytes(32));
    }
    private function authenticated(): ?string {
        global $login;
        $auth = $_SESSION['bs']['auth'] ?? null;
        if (!$auth || !$login->isLogged() || $login->username() !== $auth['name']) { return null; }
        $a = $this->store->get($auth['name']);
        return $auth['revision'] === $a['revision'] && ($auth['userStamp'] ?? '') === $this->userStamp($this->user($auth['name'])) ? $auth['name'] : null;
    }
    private function recent(): string {
        $name = $this->authenticated();
        if (!$name || $_SESSION['bs']['auth']['at'] < time()-300) { throw new UserError('Sign in again before changing your account security.'); }
        return $name;
    }
    public function authorizeConfiguration(): void {
        $name = $this->recent();
        if ($this->user($name)['role'] !== 'admin') { throw new UserError('Administrator access is required.'); }
    }
    private function pendingUser(): array {
        $p = $_SESSION['bs']['pending'] ?? null;
        if (!$p || $p['expires'] < time()) { unset($_SESSION['bs']['pending']); throw new UserError('Sign-in attempt expired. Please start again.'); }
        $user = $this->user($p['name']);
        if ($this->store->get($p['name'])['revision'] !== $p['revision'] || ($p['userStamp'] ?? '') !== $this->userStamp($user)) { unset($_SESSION['bs']['pending']); throw new UserError('Account or authentication methods have changed. Please sign in again.'); }
        return $p;
    }
    private function budget(string $name, string $scope = 'auth'): void {
        global $security;
        if ($security->isBlocked() || !$this->store->attempt($scope.':'.$name, $scope.':'.($_SERVER['REMOTE_ADDR'] ?? 'unknown'))) { throw new UserError('Too many attempts. Try again in five minutes.'); }
    }
    public function run(): void {
        global $login, $security;
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
        $_SESSION['bs'] ??= [];
        $_SESSION['bs']['csrf'] ??= bin2hex(random_bytes(32));
        $action = (string)($_GET['bs'] ?? '');
        $name = $this->authenticated();
        // Native sessions, remember cookies and direct AJAX cannot bypass this marker.
        if (!$name) {
            if (isset($_SESSION['bs']['auth'])) { $_SESSION['bs'] = ['csrf'=>bin2hex(random_bytes(32))]; }
            foreach (['username','role','fingerPrint','sessionTime'] as $k) { \Session::set($k, null); }
        }
        if (!$name && ($GLOBALS['layout']['slug'] ?? '') === 'ajax') { $this->json(['error'=>'Complete authentication is required.'], 401); }
        if ($action === '' && $name) { return; }
        try {
            if ($action === 'oidc') { $this->oidc(); }
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                if ($action === '' && !$name) {
                    if (!$security->validateTokenCSRF((string)($_POST['tokenCSRF'] ?? ''))) { throw new UserError('Invalid CSRF'); }
                    $this->password();
                }
                $this->csrf();
                if ($action === 'password') { $this->password(); }
                if ($action === 'logout') { unset($_SESSION['bs']); $login->logout(); $this->go(); }
                if ($action === 'sso' || $action === 'link') { $this->startOidc($action === 'link'); }
                if ($action === 'mfa') { $this->verifyCode(); }
                if (str_starts_with($action, 'key-')) { $this->webauthn($action); }
                if ($action === 'manage') { $this->manage(); }
            }
            if (!$name && isset($_SESSION['bs']['pending'])) { $this->pendingUser(); }
            if ($name) { $this->go('account'); }
            // Bludit renders its existing login theme and view.
            return;
        } catch (\Throwable $e) {
            // Provider exceptions can contain tokens or response bodies.
            error_log('bludit-secure: '.get_class($e));
            $msg = $e instanceof UserError ? $e->getMessage() : 'Verification failed. Try again or check the server logs.';
            // Never expose protocol payloads, tokens or secrets to the browser.
            if (str_starts_with($action, 'key-')) { $this->json(['error'=>'Verification failed. Sign in again or retry.'], 400); }
            $_SESSION['bs']['notice'] = mb_substr($msg, 0, 200);
            $this->go($this->authenticated() ? 'account' : (isset($_SESSION['bs']['pending']) ? 'mfa' : ''));
        }
    }
    private function password(): void {
        global $users;
        $name = trim((string)($_POST['username'] ?? '')); $pw = (string)($_POST['password'] ?? '');
        $this->budget($name);
        $u = $users->getUserDB($name);
        if (!$u || $u['password'] === '!' || !hash_equals($u['password'], $users->generatePasswordHash($pw, $u['salt']))) { throw new UserError('Incorrect username or password.'); }
        $this->pending($name, 'password', null, $this->userStamp($u));
    }
    /** Enhance the native login form in place; keep the theme, branding and layout. */
    public function renderLogin(string $html): string {
        $pending = isset($_SESSION['bs']['pending']);
        $extra = '';
        if (isset($_SESSION['bs']['notice'])) {
            $extra .= '<div class="alert alert-info" role="alert">'.$this->e($_SESSION['bs']['notice']).'</div>';
            unset($_SESSION['bs']['notice']);
        }
        if ($pending) {
            $extra .= $this->bootstrapMarkup($this->mfaContent());
            $extra .= '<p id="status" role="status" class="text-danger mt-3"></p><script src="'.$this->e($this->scriptUrl()).'" defer></script>';
        }
        $sso = !$pending && $this->ssoEnabled() ? $this->bootstrapMarkup($this->form('sso', '<button type="submit" class="btn btn-secondary btn-block mt-3 py-3"><span>Sign in with '.$this->e($this->cfg('ssoLabel')).'</span></button>')) : '';
        $pattern = '~<form\b[^>]*>(?:(?!</form>).)*?name=["\']password["\'](?:(?!</form>).)*?</form>~is';
        $result = preg_replace_callback($pattern, function ($match) use ($pending, $extra, $sso) {
            if ($pending) { return $extra; }
            // Non-visual token for plugin endpoints; native password submission still validates tokenCSRF.
            $form = preg_replace('~</form>~i', '<input type="hidden" name="secureCsrf" value="'.$this->e($_SESSION['bs']['csrf']).'"></form>', $match[0], 1);
            return $extra.$form.$sso;
        }, $html, 1, $count);
        // Other admin themes can still expose the second factor through their login hooks.
        return $count ? $result : $html.$extra.$sso;
    }
    private function mfaContent(): string {
        $p = $this->pendingUser(); $a = $this->store->get($p['name']);
        $body = '<p>Verify your identity using a second factor.</p>';
        if ($a['totp'] && $this->allowed($a, 'totp')) { $body .= $this->form('mfa', '<label>TOTP code<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required></label><button>Verify code</button>'); }
        if ($a['keys'] && $this->allowed($a, 'passkey')) { $body .= '<p>Complete the passkey prompt in your browser.</p>'.$this->keyButton(false, true); }
        if ($a['recovery']) { $body .= $this->form('mfa', '<label>Recovery code<input name="recovery" autocomplete="off" required></label><button>Use recovery code</button>'); }
        $body .= $this->form('logout', '<button>Cancel sign-in</button>');
        return '<h2 class="h5 mb-3">Two-step verification</h2>'.$body;
    }
    private function verifyCode(): never {
        $p = $this->pendingUser(); $this->budget($p['name']);
        $ok = $this->store->update($p['name'], function (&$a) use ($p) {
            if ($a['revision'] !== $p['revision']) { throw new UserError('Account changed. Please sign in again.'); }
            $recovery = trim((string)($_POST['recovery'] ?? ''));
            if ($recovery !== '') {
                foreach ($a['recovery'] as $i=>$hash) { if (hash_equals($hash, hash('sha256', $recovery))) { unset($a['recovery'][$i]); $a['recovery'] = array_values($a['recovery']); return true; } }
                return false;
            }
            if (!$a['totp'] || !$this->allowed($a, 'totp')) { return false; }
            $step = Totp::verify($a['totp'], trim((string)($_POST['code'] ?? '')), $a['lastStep']);
            if ($step === null) { return false; } $a['lastStep'] = $step; return true;
        });
        if (!$ok) { throw new UserError('This code is invalid, expired or has already been used.'); }
        $this->finish($p['name']);
    }
    public function accountView(): string {
        $name = $this->authenticated();
        if ($name === null) { throw new UserError('Sign-in is required.'); }
        $html = \Bootstrap::pageTitle(['title'=>'Security', 'icon'=>'lock']);
        if (isset($_SESSION['bs']['notice'])) {
            $html .= '<div class="alert alert-info" role="alert">'.$this->e($_SESSION['bs']['notice']).'</div>';
            unset($_SESSION['bs']['notice']);
        }
        $html .= $this->accountContent($name);
        return $this->bootstrapMarkup($html).'<p id="status" role="status" class="text-danger mt-3"></p><script src="'.$this->e($this->scriptUrl()).'" defer></script>';
    }
    private function bootstrapMarkup(string $html): string {
        // Use the active admin theme and its Bootstrap components; no standalone CSS.
        $html = str_replace('<h2>', '<h2 class="h5 mt-4 mb-3 pb-2 border-bottom">', $html);
        $html = str_replace('<label>', '<label class="d-block mb-3">', $html);
        $html = str_replace('<form ', '<form class="mb-3" ', $html);
        $html = preg_replace('/<input(?![^>]*class=)(?![^>]*type="(?:hidden|checkbox)")/', '<input class="form-control"', $html);
        $html = str_replace('<select ', '<select class="custom-select" ', $html);
        $html = preg_replace('/<button(?![^>]*class=)/', '<button class="btn btn-outline-primary btn-sm my-1"', $html);
        $html = str_replace('<code class="secret">', '<code class="d-block border rounded p-3 mb-3 text-break">', $html);
        $html = str_replace('<pre>', '<pre class="border rounded p-3">', $html);
        return $html;
    }
    private function accountContent(string $name): string {
        $a = $this->store->get($name);
        $body = '<p>Account: <strong>'.$this->e($name).'</strong>. <a href="'.$this->e(DOMAIN_ADMIN).'">Back to dashboard</a></p>';
        if ($_SESSION['bs']['auth']['at'] < time()-300) {
            return $body.'<div class="alert alert-info">Use Log out in the sidebar, then sign in again to change your authentication methods.</div>';
        }
        $body .= '<h2>Two-factor authentication</h2><p>Choose the second factor required after your password. With either method enabled, you can use a TOTP code or a passkey.</p>';
        $select = '<label>Second factor<select name="mode">';
        foreach (['off'=>'Disabled','totp'=>'TOTP','passkey'=>'Passkey','either'=>'TOTP or passkey'] as $v=>$label) { $select .= '<option value="'.$v.'" '.($a['mode']===$v?'selected':'').'>'.$label.'</option>'; }
        $select .= '</select></label><label><input type="checkbox" name="ssoMfa" value="1" '.($a['ssoMfa']?'checked':'').'> Also require this second factor after SSO</label><button name="op" value="preferences">Save preferences</button>';
        $body .= $this->form('manage', $select);
        $body .= '<h2>TOTP</h2><p>'.($a['totp'] ? 'TOTP is enabled.' : 'No TOTP configured.').'</p>';
        if (!$a['totp']) {
            $body .= $this->form('manage', '<button name="op" value="totp-start">Set up TOTP</button>');
            $en = $_SESSION['bs']['enroll'] ?? null;
            if ($en && $en['expires'] >= time() && $en['name'] === $name) {
                $uri = 'otpauth://totp/'.rawurlencode('Bludit:'.$name).'?secret='.$en['secret'].'&issuer=Bludit&algorithm=SHA1&digits=6&period=30';
                $body .= '<p>Add this setup key to your authenticator app:</p><code class="secret">'.$this->e($uri).'</code>';
                $body .= $this->form('manage', '<label>Confirmation code<input name="code" inputmode="numeric" pattern="[0-9]{6}" required></label><button name="op" value="totp-confirm">Confirm TOTP</button>');
            }
        } else { $body .= $this->form('manage', '<button name="op" value="totp-delete">Remove TOTP</button>'); }
        $body .= '<h2>Passkeys</h2><p>Register a passkey for this site using your password manager or authenticator.</p>'.$this->keyButton(true);
        foreach ($a['keys'] as $id=>$k) { $body .= $this->form('manage', '<input type="hidden" name="key" value="'.$this->e($id).'"><span>'.$this->e($k['label']).'</span> <button name="op" value="key-delete">Remove passkey</button>'); }
        $body .= '<h2>SSO</h2>';
        if ($a['sso']) { $body .= '<p>SSO identity linked.</p>'.$this->form('manage', '<button name="op" value="unlink">Unlink SSO</button>'); }
        elseif ($this->ssoEnabled()) { $body .= $this->form('link', '<button>Link account to '.$this->e($this->cfg('ssoLabel')).'</button>'); }
        else { $body .= '<p>An administrator must configure SSO first.</p>'; }
        $body .= '<h2>Recovery</h2><p>'.count($a['recovery']).' recovery code(s) remaining. Generating new codes invalidates the previous ones. Store them outside your account.</p>'.$this->form('manage', '<button name="op" value="recovery">Generate ten recovery codes</button>');
        if (isset($_SESSION['bs']['codes'])) {
            $body .= '<p>These codes are shown only once:</p><pre>'.$this->e(implode("\n", $_SESSION['bs']['codes'])).'</pre>'; unset($_SESSION['bs']['codes']);
        }
        return $body;
    }
    private function manage(): never {
        $name = $this->recent(); $this->budget($name, 'manage'); $op = (string)($_POST['op'] ?? '');
        $expectedRevision = $_SESSION['bs']['auth']['revision'];
        if ($op === 'totp-start') {
            $_SESSION['bs']['enroll'] = ['name'=>$name, 'secret'=>Totp::secret(), 'expires'=>time()+300]; $this->go('account');
        }
        $codes = [];
        if ($op === 'recovery') { for ($i=0; $i<10; ++$i) { $codes[] = bin2hex(random_bytes(10)); } }
        $revision = $this->store->update($name, function (&$a) use ($op, $name, $codes, $expectedRevision) {
            if ($a['revision'] !== $expectedRevision) { throw new UserError('Account changed. Please sign in again.'); }
            switch ($op) {
                case 'totp-confirm':
                    $en = $_SESSION['bs']['enroll'] ?? null;
                    if (!$en || $en['name'] !== $name || $en['expires'] < time() || $a['totp']) { throw new UserError('Setup expired or TOTP is already enabled.'); }
                    $step = Totp::verify($en['secret'], trim($_POST['code'] ?? ''), -1);
                    if ($step === null) { throw new UserError('Incorrect confirmation code.'); }
                    $a['totp'] = $en['secret']; $a['lastStep'] = $step;
                    if ($a['mode'] === 'off') { $a['mode'] = 'totp'; }
                    unset($_SESSION['bs']['enroll']); break;
                case 'totp-delete': $a['totp'] = null; $a['lastStep'] = -1; break;
                case 'key-delete': unset($a['keys'][(string)($_POST['key'] ?? '')]); break;
                case 'unlink': $a['sso'] = null; break;
                case 'recovery': $a['recovery'] = array_map(fn($c)=>hash('sha256',$c), $codes); break;
                case 'preferences':
                    $mode = $_POST['mode'] ?? '';
                    if (!in_array($mode, ['off','totp','passkey','either'], true)) { throw new UserError('Invalid selection.'); }
                    if (($mode === 'totp' && !$a['totp']) || ($mode === 'passkey' && !$a['keys']) || ($mode === 'either' && (!$a['totp'] || !$a['keys']))) { throw new UserError('Register the selected authentication methods first.'); }
                    $a['mode'] = $mode; $a['ssoMfa'] = isset($_POST['ssoMfa']); break;
                default: throw new UserError('Unknown action.');
            }
            // Deleting a required factor must not silently disable MFA.
            if (($a['mode'] === 'totp' && !$a['totp']) || ($a['mode'] === 'passkey' && !$a['keys']) || ($a['mode'] === 'either' && (!$a['totp'] || !$a['keys']))) { throw new UserError('Change the verification mode before removing this authentication method.'); }
            return ++$a['revision'];
        });
        $_SESSION['bs']['auth']['revision'] = $revision;
        if ($codes) { $_SESSION['bs']['codes'] = $codes; }
        $_SESSION['bs']['notice'] = 'Changes saved.'; $this->go('account');
    }
    private function oidcClient(): OidcClient {
        if (!$this->ssoEnabled() || parse_url($this->cfg('issuer'), PHP_URL_SCHEME) !== 'https') { throw new UserError('SSO is not configured.'); }
        $oidc = new OidcClient($this->cfg('issuer'), $this->cfg('clientId'), $this->cfg('clientSecret'));
        $oidc->setRedirectURL($this->base.'?bs=oidc');
        $oidc->setCodeChallengeMethod('S256');
        $oidc->setAllowImplicitFlow(false);
        $oidc->setTimeout(15);
        return $oidc;
    }
    private function startOidc(bool $link): never {
        $name = $link ? $this->recent() : null;
        $this->budget(hash('sha256', session_id()), 'oidc');
        $_SESSION['bs']['oidc'] = ['link'=>$name, 'expires'=>time()+300, 'config'=>$this->oidcConfigStamp(), 'revision'=>$name !== null ? $_SESSION['bs']['auth']['revision'] : null];
        unset($_SESSION['bs']['pending']);
        $this->oidcClient()->authenticateRequest([]);
        throw new UserError('Unable to redirect to SSO.');
    }
    private function oidc(): never {
        $flow = $_SESSION['bs']['oidc'] ?? null;
        unset($_SESSION['bs']['oidc']);
        if (!$flow || $flow['expires'] < time() || ($flow['config'] ?? '') !== $this->oidcConfigStamp() || !isset($_GET['code'], $_GET['state'])) { throw new UserError('SSO sign-in expired or was cancelled.'); }
        // The library verifies state, nonce, JWT signature, issuer, audience and expiry.
        $oidc = $this->oidcClient();
        $oidc->authenticateRequest(['code'=>$_GET['code'], 'state'=>$_GET['state']]);
        unset($_SESSION['bs']['oidc']);
        $sub = $oidc->getVerifiedClaims('sub');
        $iss = $oidc->getVerifiedClaims('iss');
        if (!is_string($sub) || $sub === '' || !is_string($iss) || $iss !== $this->cfg('issuer')) { throw new UserError('Invalid SSO identity.'); }
        $identity = ['issuer'=>$iss, 'subject'=>$sub];
        if ($flow['link'] !== null) {
            $name = $this->recent();
            if ($name !== $flow['link']) { throw new UserError('Invalid account-linking session.'); }
            $rev = $this->store->transaction(function (&$d) use ($name, $identity, $flow) {
                foreach ($d['accounts'] as $other=>$a) { if ($other !== $name && $a['sso'] === $identity) { throw new UserError('This identity is already linked to another account.'); } }
                $a = Store::account($d, $name);
                if ($a['revision'] !== $flow['revision']) { throw new UserError('Account changed. Please start linking again.'); }
                $a['sso'] = $identity; ++$a['revision']; $d['accounts'][$name] = $a; return $a['revision'];
            });
            $_SESSION['bs']['auth']['revision'] = $rev;
            $_SESSION['bs']['notice'] = 'SSO identity linked.'; $this->go('account');
        }
        $match = $this->store->transaction(function (&$d) use ($identity) {
            foreach ($d['accounts'] as $name=>$a) { if ($a['sso'] === $identity) { return ['name'=>$name, 'revision'=>$a['revision']]; } } return null;
        });
        if ($match === null) { throw new UserError('This SSO identity is not linked to a Bludit account. Sign in with your password to link it.'); }
        $this->budget($match['name']); $this->pending($match['name'], 'sso', $match['revision']);
        exit;
    }
    private function keyButton(bool $create, bool $automatic = false): string {
        return '<div class="webauthn"'.($automatic ? ' data-auto-passkey="true"' : '').' data-base="'.$this->e($this->base).'" data-csrf="'.$this->e($_SESSION['bs']['csrf']).'">'.($create?'<label>Passkey name<input class="key-label" maxlength="80" value="My passkey"></label>':'').'<button type="button" data-key="'.($create?'create':'get').'">'.($create?'Add passkey':'Try passkey again').'</button></div>';
    }
    private function oidcConfigStamp(): string {
        return hash('sha256', json_encode([$this->cfg('issuer'), $this->cfg('clientId'), $this->cfg('clientSecret')], JSON_THROW_ON_ERROR));
    }
    private static function b64(string $raw): string { return rtrim(strtr(base64_encode($raw), '+/', '-_'), '='); }
    private static function unb64(string $raw): string {
        if (strlen($raw) > 100000 || !preg_match('/^[A-Za-z0-9_-]*$/D', $raw)) { throw new UserError('Invalid binary data'); }
        $result = base64_decode(strtr($raw, '-_', '+/'), true);
        if ($result === false || self::b64($result) !== $raw) { throw new UserError('Invalid binary data'); } return $result;
    }
    private function checkOrigin(string $client): void {
        $data = json_decode($client, true, 16, JSON_THROW_ON_ERROR);
        if (!is_array($data) || ($data['origin'] ?? null) !== $this->origin || (array_key_exists('crossOrigin', $data) && $data['crossOrigin'] !== false)) { throw new UserError('Invalid WebAuthn origin'); }
    }
    private function webauthn(string $action): never {
        $create = in_array($action, ['key-create-options','key-create-finish'], true);
        if (!in_array($action, ['key-create-options','key-create-finish','key-get-options','key-get-finish'], true)) { throw new UserError('Unknown action'); }
        $name = $create ? $this->recent() : $this->pendingUser()['name'];
        $this->budget($name, $create ? 'enroll' : 'auth'); $a = $this->store->get($name);
        if ($create && $a['revision'] !== $_SESSION['bs']['auth']['revision']) { throw new UserError('Account changed. Please sign in again.'); }
        if (!$create && (!$this->allowed($a, 'passkey') || !$a['keys'])) { throw new UserError('Passkey unavailable'); }
        $wa = new \lbuchs\WebAuthn\WebAuthn('Bludit', parse_url($this->origin, PHP_URL_HOST), ['none'], true);
        if (str_ends_with($action, '-options')) {
            $ids = array_map(fn($id)=>self::unb64($id), array_keys($a['keys']));
            if ($create) {
                if (count($ids) >= 20) { throw new UserError('Maximum 20 passkeys'); }
                $args = $wa->getCreateArgs(hash('sha256', 'bludit:'.$name, true), $name, $name, 60, true, true, null, $ids);
            } else { $args = $wa->getGetArgs($ids, 60, true, true, true, true, true, true); }
            $_SESSION['bs']['challenge'] = ['value'=>self::b64($wa->getChallenge()->getBinaryString()), 'name'=>$name, 'create'=>$create, 'expires'=>time()+120, 'revision'=>$a['revision']];
            $this->json($args);
        }
        $ch = $_SESSION['bs']['challenge'] ?? null; unset($_SESSION['bs']['challenge']);
        if (!$ch || $ch['name'] !== $name || $ch['create'] !== $create || $ch['expires'] < time() || $ch['revision'] !== $a['revision']) { throw new UserError('Challenge expired'); }
        $client = self::unb64((string)($_POST['clientDataJSON'] ?? '')); $this->checkOrigin($client);
        $challenge = self::unb64($ch['value']);
        if ($create) {
            $result = $wa->processCreate($client, self::unb64((string)($_POST['attestationObject'] ?? '')), $challenge, true, true, false);
            $id = self::b64($result->credentialId);
            $revision = $this->store->transaction(function (&$d) use ($name, $id, $result, $ch) {
                foreach ($d['accounts'] as $a) { if (isset($a['keys'][$id])) { throw new UserError('Credential already registered'); } }
                $a = Store::account($d, $name);
                if ($a['revision'] !== $ch['revision']) { throw new UserError('Account changed'); }
                $a['keys'][$id] = ['publicKey'=>$result->credentialPublicKey, 'counter'=>$result->signatureCounter ?? 0, 'label'=>mb_substr(trim((string)($_POST['label'] ?? 'Passkey')), 0, 80) ?: 'Passkey'];
                if ($a['mode'] === 'off') { $a['mode'] = 'passkey'; }
                ++$a['revision']; $d['accounts'][$name] = $a; return $a['revision'];
            });
            $_SESSION['bs']['auth']['revision'] = $revision;
            $this->json(['redirect'=>$this->accountUrl()]);
        }
        $id = (string)($_POST['id'] ?? '');
        if (isset($_POST['userHandle']) && !hash_equals(hash('sha256', 'bludit:'.$name, true), self::unb64((string)$_POST['userHandle']))) { throw new UserError('Invalid passkey user handle'); }
        $this->store->update($name, function (&$a) use ($id, $ch, $wa, $client, $challenge) {
            if ($a['revision'] !== $ch['revision'] || !isset($a['keys'][$id])) { throw new UserError('Unknown credential'); }
            $key = $a['keys'][$id];
            $wa->processGet($client, self::unb64((string)($_POST['authenticatorData'] ?? '')), self::unb64((string)($_POST['signature'] ?? '')), $key['publicKey'], $challenge, $key['counter'], true, true);
            $a['keys'][$id]['counter'] = $wa->getSignatureCounter() ?? $key['counter'];
        });
        // Finish through an ordinary navigation so the browser receives regenerated session cookies.
        $this->finishJson($name);
    }
    private function finishJson(string $name): never {
        $this->completePending($name);
        $this->json(['redirect'=>DOMAIN_ADMIN]);
    }
}
