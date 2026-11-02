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
    private function cfg(string $key): string { return trim($this->plugin->getValue($key, false)); }
    private function ssoEnabled(): bool { return $this->cfg('issuer') !== '' && $this->cfg('clientId') !== '' && $this->cfg('clientSecret') !== ''; }
    private function e(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
    private function go(string $action = ''): never { header('Location: '.$this->base.($action ? '?bs='.$action : ''), true, 303); exit; }
    private function form(string $action, string $body): string {
        return '<form method="post" action="'.$this->e($this->base.'?bs='.$action).'"><input type="hidden" name="secureCsrf" value="'.$this->e($_SESSION['bs']['csrf']).'">'.$body.'</form>';
    }
    private function page(string $title, string $body): never {
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store'); header('Referrer-Policy: no-referrer'); header('X-Frame-Options: DENY');
        header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        $asset = $this->plugin->htmlPath().'assets/';
        echo '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>'.$this->e($title).'</title><link rel="stylesheet" href="'.$asset.'secure.css"></head><body><main><h1>'.$this->e($title).'</h1>';
        if (isset($_SESSION['bs']['notice'])) { echo '<p role="alert">'.$this->e($_SESSION['bs']['notice']).'</p>'; unset($_SESSION['bs']['notice']); }
        echo $body.'<p id="status" role="status"></p></main><script src="'.$asset.'secure.js" defer></script></body></html>'; exit;
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
    private function allowed(array $a, string $factor): bool {
        return $a['mode'] === 'either' || $a['mode'] === $factor;
    }
    private function requiresMfa(array $a, string $via): bool { return $a['mode'] !== 'off' && ($via !== 'sso' || $a['ssoMfa']); }
    private function pending(string $name, string $via): void {
        $this->user($name);
        session_regenerate_id(true);
        unset($_SESSION['bs']['auth'], $_SESSION['bs']['challenge']);
        $a = $this->store->get($name);
        $_SESSION['bs']['pending'] = ['name'=>$name, 'via'=>$via, 'expires'=>time()+300, 'revision'=>$a['revision']];
        if (!$this->requiresMfa($a, $via)) { $this->finish($name); }
        $this->go('mfa');
    }
    private function finish(string $name): never {
        global $login, $security;
        $u = $this->user($name); $a = $this->store->get($name);
        $login->setLogin($name, $u['role']);
        $security->generateTokenCSRF();
        $_SESSION['bs']['auth'] = ['name'=>$name, 'at'=>time(), 'revision'=>$a['revision']];
        unset($_SESSION['bs']['pending'], $_SESSION['bs']['challenge']);
        $this->go('account');
    }
    private function authenticated(): ?string {
        global $login;
        $auth = $_SESSION['bs']['auth'] ?? null;
        if (!$auth || !$login->isLogged() || $login->username() !== $auth['name']) { return null; }
        $a = $this->store->get($auth['name']);
        return $auth['revision'] === $a['revision'] ? $auth['name'] : null;
    }
    private function recent(): string {
        $name = $this->authenticated();
        if (!$name || $_SESSION['bs']['auth']['at'] < time()-300) { throw new UserError('Reconnectez-vous avant de modifier la sécurité de votre compte.'); }
        return $name;
    }
    private function pendingUser(): array {
        $p = $_SESSION['bs']['pending'] ?? null;
        if (!$p || $p['expires'] < time()) { unset($_SESSION['bs']['pending']); throw new UserError('Connexion expirée. Recommencez.'); }
        $this->user($p['name']);
        if ($this->store->get($p['name'])['revision'] !== $p['revision']) { unset($_SESSION['bs']['pending']); throw new UserError('Les facteurs ont changé. Recommencez la connexion.'); }
        return $p;
    }
    private function budget(string $name, string $scope = 'auth'): void {
        global $security;
        if ($security->isBlocked() || !$this->store->attempt($scope.':'.$name, $scope.':'.($_SERVER['REMOTE_ADDR'] ?? 'unknown'))) { throw new UserError('Trop de tentatives. Réessayez dans cinq minutes.'); }
    }
    public function run(): void {
        global $login;
        $_SESSION['bs'] ??= [];
        $_SESSION['bs']['csrf'] ??= bin2hex(random_bytes(32));
        $action = (string)($_GET['bs'] ?? '');
        $name = $this->authenticated();
        // Native sessions, remember cookies and direct AJAX cannot bypass this marker.
        if (!$name) {
            foreach (['username','role','fingerPrint','sessionTime'] as $k) { \Session::set($k, null); }
        }
        if ($action === '' && $name) { return; }
        try {
            if ($action === 'oidc') { $this->oidc(); }
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $this->csrf();
                if ($action === 'password') { $this->password(); }
                if ($action === 'logout') { unset($_SESSION['bs']); $login->logout(); $this->go(); }
                if ($action === 'sso' || $action === 'link') { $this->startOidc($action === 'link'); }
                if ($action === 'mfa') { $this->verifyCode(); }
                if (str_starts_with($action, 'key-')) { $this->webauthn($action); }
                if ($action === 'manage') { $this->manage(); }
            }
            if ($action === 'mfa' || (!$name && isset($_SESSION['bs']['pending']))) { $this->mfaPage(); }
            if ($name) { $this->accountPage($name); }
            $this->loginPage();
        } catch (\Throwable $e) {
            error_log('bludit-secure: '.get_class($e).' '.$e->getMessage());
            $msg = $e instanceof UserError ? $e->getMessage() : 'Vérification impossible. Recommencez ou consultez les journaux.';
            // Never expose protocol payloads, tokens or secrets to the browser.
            if (str_starts_with($action, 'key-')) { $this->json(['error'=>'Vérification impossible. Reconnectez-vous ou réessayez.'], 400); }
            $_SESSION['bs']['notice'] = mb_substr($msg, 0, 200);
            $this->go($this->authenticated() ? 'account' : (isset($_SESSION['bs']['pending']) ? 'mfa' : ''));
        }
    }
    private function password(): void {
        global $users;
        $name = trim((string)($_POST['username'] ?? '')); $pw = (string)($_POST['password'] ?? '');
        $this->budget($name);
        $u = $users->getUserDB($name);
        if (!$u || $u['password'] === '!' || !hash_equals($u['password'], $users->generatePasswordHash($pw, $u['salt']))) { throw new UserError('Identifiants incorrects.'); }
        $this->pending($name, 'password');
    }
    private function loginPage(): never {
        $body = $this->form('password', '<label>Identifiant<input name="username" autocomplete="username" required></label><label>Mot de passe<input type="password" name="password" autocomplete="current-password" required></label><button>Se connecter</button>');
        if ($this->ssoEnabled()) { $body .= $this->form('sso', '<button>Se connecter avec '.$this->e($this->cfg('ssoLabel')).'</button>'); }
        $this->page('Connexion à Bludit', $body);
    }
    private function mfaPage(): never {
        $p = $this->pendingUser(); $a = $this->store->get($p['name']);
        $body = '<p>Validez le second facteur de votre compte.</p>';
        if ($a['totp'] && $this->allowed($a, 'totp')) { $body .= $this->form('mfa', '<label>Code TOTP<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required></label><button>Vérifier le code</button>'); }
        if ($a['keys'] && $this->allowed($a, 'passkey')) { $body .= $this->keyButton(false); }
        if ($a['recovery']) { $body .= $this->form('mfa', '<label>Code de récupération<input name="recovery" autocomplete="off" required></label><button>Utiliser le code de récupération</button>'); }
        $body .= $this->form('logout', '<button>Annuler la connexion</button>');
        $this->page('Vérification en deux étapes', $body);
    }
    private function verifyCode(): never {
        $p = $this->pendingUser(); $this->budget($p['name']);
        $ok = $this->store->update($p['name'], function (&$a) {
            $recovery = trim((string)($_POST['recovery'] ?? ''));
            if ($recovery !== '') {
                foreach ($a['recovery'] as $i=>$hash) { if (hash_equals($hash, hash('sha256', $recovery))) { unset($a['recovery'][$i]); $a['recovery'] = array_values($a['recovery']); return true; } }
                return false;
            }
            if (!$a['totp'] || !$this->allowed($a, 'totp')) { return false; }
            $step = Totp::verify($a['totp'], trim((string)($_POST['code'] ?? '')), $a['lastStep']);
            if ($step === null) { return false; } $a['lastStep'] = $step; return true;
        });
        if (!$ok) { throw new UserError('Code invalide, expiré ou déjà utilisé.'); }
        $this->finish($p['name']);
    }
    private function accountPage(string $name): never {
        $a = $this->store->get($name);
        $body = '<p>Compte : <strong>'.$this->e($name).'</strong>. <a href="'.$this->e(DOMAIN_ADMIN).'">Retour à l’administration</a></p>';
        if ($_SESSION['bs']['auth']['at'] < time()-300) {
            $this->page('Sécurité de mon compte', $body.'<p>Une nouvelle connexion est nécessaire pour modifier vos facteurs.</p>'.$this->form('logout', '<button>Se déconnecter pour vérifier mon identité</button>'));
        }
        $body .= '<h2>Authentification à deux facteurs</h2><p>Choisissez le facteur demandé après votre mot de passe. « Au choix » permet de présenter un TOTP ou une passkey.</p>';
        $select = '<label>Second facteur<select name="mode">';
        foreach (['off'=>'Désactivé','totp'=>'TOTP','passkey'=>'Passkey','either'=>'TOTP ou passkey au choix'] as $v=>$label) { $select .= '<option value="'.$v.'" '.($a['mode']===$v?'selected':'').'>'.$label.'</option>'; }
        $select .= '</select></label><label><input type="checkbox" name="ssoMfa" value="1" '.($a['ssoMfa']?'checked':'').'> Demander aussi ce second facteur après le SSO</label><button name="op" value="preferences">Enregistrer mes choix</button>';
        $body .= $this->form('manage', $select);
        $body .= '<h2>TOTP</h2><p>'.($a['totp'] ? 'TOTP activé.' : 'Aucun TOTP enregistré.').'</p>';
        if (!$a['totp']) {
            $body .= $this->form('manage', '<button name="op" value="totp-start">Préparer un TOTP</button>');
            $en = $_SESSION['bs']['enroll'] ?? null;
            if ($en && $en['expires'] >= time() && $en['name'] === $name) {
                $uri = 'otpauth://totp/'.rawurlencode('Bludit:'.$name).'?secret='.$en['secret'].'&issuer=Bludit&algorithm=SHA1&digits=6&period=30';
                $body .= '<p>Dans Bitwarden, collez cette URI dans le champ « Clé d’authentification (TOTP) » :</p><code class="secret">'.$this->e($uri).'</code>';
                $body .= $this->form('manage', '<label>Code de confirmation<input name="code" inputmode="numeric" pattern="[0-9]{6}" required></label><button name="op" value="totp-confirm">Confirmer le TOTP</button>');
            }
        } else { $body .= $this->form('manage', '<button name="op" value="totp-delete">Supprimer mon TOTP</button>'); }
        $body .= '<h2>Passkeys</h2><p>Enregistrez une passkey pour ce site dans Bitwarden ou votre authentificateur.</p>'.$this->keyButton(true);
        foreach ($a['keys'] as $id=>$k) { $body .= $this->form('manage', '<input type="hidden" name="key" value="'.$this->e($id).'"><span>'.$this->e($k['label']).'</span> <button name="op" value="key-delete">Supprimer cette passkey</button>'); }
        $body .= '<h2>SSO</h2>';
        if ($a['sso']) { $body .= '<p>Identité SSO liée.</p>'.$this->form('manage', '<button name="op" value="unlink">Délier mon SSO</button>'); }
        elseif ($this->ssoEnabled()) { $body .= $this->form('link', '<button>Lier mon compte à '.$this->e($this->cfg('ssoLabel')).'</button>'); }
        else { $body .= '<p>Le SSO doit être configuré par un administrateur.</p>'; }
        $body .= '<h2>Récupération</h2><p>'.count($a['recovery']).' code(s) restant(s). En générer de nouveaux invalide les précédents. Conservez-les hors de votre compte.</p>'.$this->form('manage', '<button name="op" value="recovery">Générer dix codes de récupération</button>');
        if (isset($_SESSION['bs']['codes'])) {
            $body .= '<p>Ces codes ne seront affichés qu’une fois :</p><pre>'.$this->e(implode("\n", $_SESSION['bs']['codes'])).'</pre>'; unset($_SESSION['bs']['codes']);
        }
        $body .= $this->form('logout', '<button>Se déconnecter</button>');
        $this->page('Sécurité de mon compte', $body);
    }
    private function manage(): never {
        $name = $this->recent(); $this->budget($name, 'manage'); $op = (string)($_POST['op'] ?? '');
        if ($op === 'totp-start') {
            $_SESSION['bs']['enroll'] = ['name'=>$name, 'secret'=>Totp::secret(), 'expires'=>time()+300]; $this->go('account');
        }
        $codes = [];
        if ($op === 'recovery') { for ($i=0; $i<10; ++$i) { $codes[] = bin2hex(random_bytes(10)); } }
        $revision = $this->store->update($name, function (&$a) use ($op, $name, $codes) {
            switch ($op) {
                case 'totp-confirm':
                    $en = $_SESSION['bs']['enroll'] ?? null;
                    if (!$en || $en['name'] !== $name || $en['expires'] < time() || $a['totp']) { throw new UserError('Enregistrement expiré ou TOTP déjà actif.'); }
                    $step = Totp::verify($en['secret'], trim($_POST['code'] ?? ''), -1);
                    if ($step === null) { throw new UserError('Code de confirmation incorrect.'); }
                    $a['totp'] = $en['secret']; $a['lastStep'] = $step;
                    if ($a['mode'] === 'off') { $a['mode'] = 'totp'; }
                    unset($_SESSION['bs']['enroll']); break;
                case 'totp-delete': $a['totp'] = null; $a['lastStep'] = -1; break;
                case 'key-delete': unset($a['keys'][(string)($_POST['key'] ?? '')]); break;
                case 'unlink': $a['sso'] = null; break;
                case 'recovery': $a['recovery'] = array_map(fn($c)=>hash('sha256',$c), $codes); break;
                case 'preferences':
                    $mode = $_POST['mode'] ?? '';
                    if (!in_array($mode, ['off','totp','passkey','either'], true)) { throw new UserError('Choix invalide.'); }
                    if (($mode === 'totp' && !$a['totp']) || ($mode === 'passkey' && !$a['keys']) || ($mode === 'either' && (!$a['totp'] || !$a['keys']))) { throw new UserError('Enregistrez d’abord les facteurs choisis.'); }
                    $a['mode'] = $mode; $a['ssoMfa'] = isset($_POST['ssoMfa']); break;
                default: throw new UserError('Action inconnue.');
            }
            // Deleting a required factor must not silently disable MFA.
            if (($a['mode'] === 'totp' && !$a['totp']) || ($a['mode'] === 'passkey' && !$a['keys']) || ($a['mode'] === 'either' && (!$a['totp'] || !$a['keys']))) { throw new UserError('Changez le mode de vérification avant de supprimer ce facteur.'); }
            return ++$a['revision'];
        });
        $_SESSION['bs']['auth']['revision'] = $revision;
        if ($codes) { $_SESSION['bs']['codes'] = $codes; }
        $_SESSION['bs']['notice'] = 'Modification enregistrée.'; $this->go('account');
    }
    private function oidcClient(): \Jumbojett\OpenIDConnectClient {
        if (!$this->ssoEnabled() || parse_url($this->cfg('issuer'), PHP_URL_SCHEME) !== 'https') { throw new UserError('SSO non configuré.'); }
        $oidc = new \Jumbojett\OpenIDConnectClient($this->cfg('issuer'), $this->cfg('clientId'), $this->cfg('clientSecret'));
        $oidc->setRedirectURL($this->base.'?bs=oidc');
        $oidc->setCodeChallengeMethod('S256');
        $oidc->setAllowImplicitFlow(false);
        $oidc->setTimeout(15);
        return $oidc;
    }
    private function startOidc(bool $link): never {
        $name = $link ? $this->recent() : null;
        $_SESSION['bs']['oidc'] = ['link'=>$name, 'expires'=>time()+300];
        unset($_SESSION['bs']['pending']);
        $this->oidcClient()->authenticate();
        throw new UserError('Redirection SSO impossible.');
    }
    private function oidc(): never {
        $flow = $_SESSION['bs']['oidc'] ?? null;
        if (!$flow || $flow['expires'] < time() || !isset($_GET['code'], $_GET['state'])) { throw new UserError('Connexion SSO expirée ou annulée.'); }
        // The library verifies state, nonce, JWT signature, issuer, audience and expiry.
        $oidc = $this->oidcClient();
        $oidc->authenticate();
        unset($_SESSION['bs']['oidc']);
        $sub = $oidc->getVerifiedClaims('sub');
        $iss = $oidc->getVerifiedClaims('iss');
        if (!is_string($sub) || $sub === '' || !is_string($iss) || $iss !== $this->cfg('issuer')) { throw new UserError('Identité SSO invalide.'); }
        $identity = ['issuer'=>$iss, 'subject'=>$sub];
        if ($flow['link'] !== null) {
            $name = $this->recent();
            if ($name !== $flow['link']) { throw new UserError('Session de liaison invalide.'); }
            $rev = $this->store->transaction(function (&$d) use ($name, $identity) {
                foreach ($d['accounts'] as $other=>$a) { if ($other !== $name && $a['sso'] === $identity) { throw new UserError('Identité déjà liée à un autre compte.'); } }
                $a = Store::account($d, $name); $a['sso'] = $identity; ++$a['revision']; $d['accounts'][$name] = $a; return $a['revision'];
            });
            $_SESSION['bs']['auth']['revision'] = $rev;
            $_SESSION['bs']['notice'] = 'Identité SSO liée.'; $this->go('account');
        }
        $name = $this->store->transaction(function (&$d) use ($identity) {
            foreach ($d['accounts'] as $name=>$a) { if ($a['sso'] === $identity) { return $name; } } return null;
        });
        if ($name === null) { throw new UserError('Ce SSO n’est lié à aucun compte Bludit. Connectez-vous avec votre mot de passe pour le lier.'); }
        $this->budget($name); $this->pending($name, 'sso');
        exit;
    }
    private function keyButton(bool $create): string {
        return '<div class="webauthn" data-base="'.$this->e($this->base).'" data-csrf="'.$this->e($_SESSION['bs']['csrf']).'">'.($create?'<label>Nom de la passkey<input class="key-label" maxlength="80" value="Ma passkey"></label>':'').'<button type="button" data-key="'.($create?'create':'get').'">'.($create?'Ajouter une passkey':'Vérifier ma passkey').'</button></div>';
    }
    private static function b64(string $raw): string { return rtrim(strtr(base64_encode($raw), '+/', '-_'), '='); }
    private static function unb64(string $raw): string {
        if (!preg_match('/^[A-Za-z0-9_-]*$/D', $raw) || strlen($raw) > 100000) { throw new UserError('Invalid binary data'); }
        $result = base64_decode(strtr($raw, '-_', '+/'), true);
        if ($result === false) { throw new UserError('Invalid binary data'); } return $result;
    }
    private function checkOrigin(string $client): void {
        $data = json_decode($client, true, 16, JSON_THROW_ON_ERROR);
        if (($data['origin'] ?? null) !== $this->origin || !empty($data['crossOrigin'])) { throw new UserError('Invalid WebAuthn origin'); }
    }
    private function webauthn(string $action): never {
        $create = in_array($action, ['key-create-options','key-create-finish'], true);
        if (!in_array($action, ['key-create-options','key-create-finish','key-get-options','key-get-finish'], true)) { throw new UserError('Action inconnue'); }
        $name = $create ? $this->recent() : $this->pendingUser()['name'];
        $this->budget($name, $create ? 'enroll' : 'auth'); $a = $this->store->get($name);
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
            $this->json(['redirect'=>$this->base.'?bs=account']);
        }
        $id = (string)($_POST['id'] ?? '');
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
        global $login, $security;
        $u = $this->user($name); $a = $this->store->get($name);
        $login->setLogin($name, $u['role']); $security->generateTokenCSRF();
        $_SESSION['bs']['auth'] = ['name'=>$name, 'at'=>time(), 'revision'=>$a['revision']];
        unset($_SESSION['bs']['pending'], $_SESSION['bs']['challenge']);
        $this->json(['redirect'=>$this->base.'?bs=account']);
    }
}
