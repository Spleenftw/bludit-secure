<?php
namespace BluditSecure;

/** Keep protocol validation explicit rather than relying on optional library checks. */
class OidcClient extends \Jumbojett\OpenIDConnectClient
{
    private ?string $contentType = null;

    public function authenticateRequest(array $parameters): bool {
        $previous = $_REQUEST;
        $_REQUEST = $parameters;
        try { return $this->authenticate(); }
        finally { $_REQUEST = $previous; }
    }
    public function authenticate(): bool {
        if (isset($_REQUEST['code'])) {
            $state = $this->getState();
            if (!is_string($_REQUEST['code']) || $_REQUEST['code'] === '' || !is_string($_REQUEST['state'] ?? null) || !is_string($state) || $state === '' || !hash_equals($state, $_REQUEST['state'])) {
                throw new UserError('Invalid SSO state.');
            }
            if (!is_string($this->getCodeVerifier()) || $this->getCodeVerifier() === '') { throw new UserError('Missing SSO PKCE verifier.'); }
        }
        return parent::authenticate();
    }
    protected function getProviderConfigValue(string $param, $default = null) {
        $value = parent::getProviderConfigValue($param, $default);
        if ($param === 'code_challenge_methods_supported' && (!is_array($value) || !in_array('S256', $value, true))) {
            throw new UserError('The SSO provider must advertise PKCE S256 support.');
        }
        return $value;
    }
    protected function verifyJWTClaims($claims, ?string $accessToken = null): bool {
        $nonce = $this->getNonce();
        $now = time();
        if (!is_object($claims) || !is_string($claims->iss ?? null) || !is_string($claims->sub ?? null) || $claims->sub === '' ||
            !is_int($claims->exp ?? null) || !is_int($claims->iat ?? null) || $claims->exp < $now - 60 || $claims->iat > $now + 60 || $claims->exp <= $claims->iat ||
            !is_string($nonce) || $nonce === '' || !is_string($claims->nonce ?? null) || !hash_equals($nonce, $claims->nonce)) { return false; }
        $audiences = is_string($claims->aud ?? null) ? [$claims->aud] : ($claims->aud ?? null);
        if (!is_array($audiences) || !array_is_list($audiences) || !$audiences || !in_array($this->getClientID(), $audiences, true)) { return false; }
        foreach ($audiences as $audience) { if (!is_string($audience) || $audience === '') { return false; } }
        if ((count($audiences) > 1 || isset($claims->azp)) && ($claims->azp ?? null) !== $this->getClientID()) { return false; }
        return parent::verifyJWTClaims($claims, $accessToken);
    }
    private function httpsUrl(string $url): void {
        $parts = parse_url($url);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment']) || preg_match('/[\x00-\x20\x7f]/', $url)) {
            throw new UserError('SSO endpoints must use HTTPS without user information or fragments.');
        }
    }
    public function redirect(string $url) {
        $this->httpsUrl($url);
        parent::redirect($url);
    }
    protected function fetchURL(string $url, ?string $post_body = null, array $headers = []) {
        $this->httpsUrl($url);
        $ch = curl_init($url);
        $body = '';
        try {
            $options = [CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS=>CURLPROTO_HTTPS,
                CURLOPT_FOLLOWLOCATION=>false, CURLOPT_SSL_VERIFYHOST=>2, CURLOPT_SSL_VERIFYPEER=>true,
                CURLOPT_TIMEOUT=>$this->getTimeout(), CURLOPT_CONNECTTIMEOUT=>10,
                CURLOPT_USERAGENT=>$this->getUserAgent(), CURLOPT_WRITEFUNCTION=>static function ($handle, string $chunk) use (&$body): int {
                    if (strlen($body) + strlen($chunk) > 1048576) { return 0; }
                    $body .= $chunk; return strlen($chunk);
                }];
            if ($post_body !== null) {
                $options[CURLOPT_POST] = true; $options[CURLOPT_POSTFIELDS] = $post_body;
                $headers[] = 'Content-Type: application/x-www-form-urlencoded';
            }
            $options[CURLOPT_HTTPHEADER] = $headers;
            curl_setopt_array($ch, $options);
            $ok = curl_exec($ch);
            $this->responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $this->contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: null;
            // Never forward a client secret across endpoint redirects.
            if ($ok === false || $this->responseCode < 200 || $this->responseCode >= 300) { throw new UserError('SSO endpoint request failed.'); }
            return $body;
        } finally { curl_close($ch); }
    }
    public function getResponseContentType(): ?string { return $this->contentType; }
}
