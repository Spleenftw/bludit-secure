<?php defined('BLUDIT') or die('Bludit CMS.');

class pluginBluditSecure extends Plugin
{
    private ?int $loginBufferLevel = null;

    public function init() {
        $this->dbFields = ['ssoLabel'=>'Pocket ID', 'issuer'=>'', 'clientId'=>'', 'clientSecret'=>''];
    }
    public function form() {
        $html = '<p>Each user can manage their authentication methods in <a href="'.HTML_PATH_ADMIN_ROOT.'plugin/pluginbluditsecure">Security</a>.</p>';
        foreach (['ssoLabel'=>'SSO name (Sign in with …)', 'issuer'=>'OIDC issuer URL (HTTPS)', 'clientId'=>'Client ID', 'clientSecret'=>'Client secret'] as $key=>$label) {
            $html .= '<div><label>'.htmlspecialchars($label).'</label><input name="'.$key.'" type="'.($key==='clientSecret'?'password':'text').'" value="'.($key==='clientSecret'?'':htmlspecialchars($this->getValue($key, false), ENT_QUOTES, 'UTF-8')).'" autocomplete="off"></div>';
        }
        return $html.'<p>Leave the secret blank to keep the existing value. OIDC redirect URI: <code>'.htmlspecialchars(DOMAIN_ADMIN.'login?bs=oidc').'</code>. Accounts are never linked automatically by email. Each user must link their SSO identity from Security.</p>';
    }
    public function post() {
        try { (new \BluditSecure\App($this))->authorizeConfiguration(); }
        catch (\BluditSecure\UserError $e) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=UTF-8');
            exit('Sign in again as an administrator before changing SSO configuration.');
        }
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
            require_once __DIR__.'/src/OidcClient.php';
            (new \BluditSecure\App($this))->run();
        } catch (\Throwable $e) {
            error_log('bludit-secure: '.get_class($e));
            http_response_code(503);
            header('Cache-Control: no-store');
            exit('Bludit Secure is unavailable. Check the server logs.');
        }
    }
    public function beforeAdminLoad() {
        global $login, $layout;
        if (!$login->isLogged()) {
            // Password POSTs are checked in prepare(); never execute native remember-me login.
            $layout['controller'] = 'bludit-secure-login';
            $layout['plugin'] = false;
        }
    }
    public function loginBodyBegin() {
        $this->loginBufferLevel = ob_get_level();
        ob_start();
    }
    public function loginBodyEnd() {
        if ($this->loginBufferLevel === null || ob_get_level() !== $this->loginBufferLevel + 1) {
            return '';
        }
        $html = ob_get_clean();
        $this->loginBufferLevel = null;
        return (new \BluditSecure\App($this))->renderLogin($html);
    }
    public function adminController() {
        global $layout;
        $layout['title'] = 'Security';
        header('Cache-Control: no-store');
        header('Referrer-Policy: no-referrer');
    }
    public function adminView() {
        return (new \BluditSecure\App($this))->accountView();
    }
    public function adminSidebar() {
        return '<a class="nav-link" href="'.HTML_PATH_ADMIN_ROOT.'plugin/pluginbluditsecure"><span class="fa fa-shield" aria-hidden="true"></span>Security</a>';
    }
    public function adminBodyEnd() {
        return (new \BluditSecure\App($this))->usersViewEnhancement();
    }
}
