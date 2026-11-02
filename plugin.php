<?php defined('BLUDIT') or die('Bludit CMS.');

class pluginBluditSecure extends Plugin
{
    public function init() {
        $this->dbFields = ['ssoLabel'=>'Pocket ID', 'issuer'=>'', 'clientId'=>'', 'clientSecret'=>''];
    }
    public function form() {
        $html = '<p>Chaque utilisateur gère ses facteurs dans <a href="'.HTML_PATH_ADMIN_ROOT.'login?bs=account">Sécurité de mon compte</a>.</p>';
        foreach (['ssoLabel'=>'Nom du SSO (Se connecter avec …)', 'issuer'=>'URL HTTPS de Pocket ID / issuer OIDC', 'clientId'=>'Client ID', 'clientSecret'=>'Client secret'] as $key=>$label) {
            $html .= '<div><label>'.htmlspecialchars($label).'</label><input name="'.$key.'" type="'.($key==='clientSecret'?'password':'text').'" value="'.($key==='clientSecret'?'':htmlspecialchars($this->getValue($key, false), ENT_QUOTES, 'UTF-8')).'" autocomplete="off"></div>';
        }
        return $html.'<p>Secret vide : conserver le secret existant. URI de retour OIDC : <code>'.htmlspecialchars(DOMAIN_ADMIN.'login?bs=oidc').'</code>. Aucun compte n’est associé automatiquement par e-mail : chaque utilisateur lie son identité depuis son espace personnel.</p>';
    }
    public function post() {
        if (empty($_POST['clientSecret'])) { unset($_POST['clientSecret']); }
        $issuer = trim($_POST['issuer'] ?? '');
        if ($issuer !== '' && (parse_url($issuer, PHP_URL_SCHEME) !== 'https' || parse_url($issuer, PHP_URL_USER) || parse_url($issuer, PHP_URL_QUERY) || parse_url($issuer, PHP_URL_FRAGMENT))) { return false; }
        return parent::post();
    }
    /** Runs while plugins are built, BEFORE Bludit's AJAX dispatch and native login. */
    public function prepare() {
        global $url;
        if ($url->whereAmI() !== 'admin') { return; }
        try {
            require_once __DIR__.'/vendor/autoload.php';
            require_once __DIR__.'/src/Store.php';
            require_once __DIR__.'/src/Totp.php';
            require_once __DIR__.'/src/App.php';
            (new \BluditSecure\App($this))->run();
        } catch (\Throwable $e) {
            error_log('bludit-secure: '.get_class($e).' '.$e->getMessage());
            http_response_code(503);
            header('Cache-Control: no-store');
            exit('Bludit Secure indisponible. Consulter les journaux du serveur.');
        }
    }
    public function adminSidebar() {
        return '<a class="nav-link" href="'.HTML_PATH_ADMIN_ROOT.'login?bs=account">Sécurité de mon compte</a>';
    }
}
