<?php
namespace BluditSecure;

/** One locked transaction for reads/updates; PHP-protected encrypted file, outside uploads. */
final class Store
{
    private string $dir;
    public function __construct(string $dir) {
        $this->dir = $dir;
        if (!is_dir($dir) && !mkdir($dir, 0700, true)) { throw new \RuntimeException('Storage unavailable'); }
    }
    public function transaction(callable $fn): mixed {
        $lock = fopen($this->dir.'/secure.lock.php', 'c+');
        if (!$lock || !flock($lock, LOCK_EX)) { throw new \RuntimeException('Storage locked'); }
        try {
            chmod($this->dir.'/secure.lock.php', 0600);
            $kp = $this->dir.'/secure.key.php';
            $prefix = "<?php exit; ?>\n";
            if (!file_exists($kp)) {
                if (file_exists($this->dir.'/secure.data.php')) { throw new \RuntimeException('Missing encryption key'); }
                $this->write($kp, $prefix.base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)));
            }
            $key = base64_decode(substr(file_get_contents($kp), strlen($prefix)), true);
            if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) { throw new \RuntimeException('Invalid encryption key'); }
            $path = $this->dir.'/secure.data.php';
            $data = ['accounts'=>[], 'limits'=>[]];
            if (file_exists($path)) {
                $raw = base64_decode(substr(file_get_contents($path), strlen($prefix)), true);
                if ($raw === false || strlen($raw) < 40) { throw new \RuntimeException('Invalid storage'); }
                $plain = sodium_crypto_secretbox_open(substr($raw, 24), substr($raw, 0, 24), $key);
                if ($plain === false) { throw new \RuntimeException('Storage authentication failed'); }
                $data = json_decode($plain, true, 64, JSON_THROW_ON_ERROR);
            }
            $before = $data;
            $result = $fn($data);
            if ($data !== $before) {
                $nonce = random_bytes(24);
                $this->write($path, $prefix.base64_encode($nonce.sodium_crypto_secretbox(json_encode($data, JSON_THROW_ON_ERROR), $nonce, $key)));
            }
            sodium_memzero($key);
            return $result;
        } finally { flock($lock, LOCK_UN); fclose($lock); }
    }
    private function write(string $path, string $data): void {
        $tmp = tempnam($this->dir, '.secure-');
        if ($tmp === false) { throw new \RuntimeException('Storage unavailable'); }
        try {
            chmod($tmp, 0600);
            if (file_put_contents($tmp, $data) !== strlen($data) || !rename($tmp, $path)) { throw new \RuntimeException('Storage write failed'); }
        } finally { if (file_exists($tmp)) { unlink($tmp); } }
    }
    public static function account(array $data, string $name): array {
        return $data['accounts'][$name] ?? ['totp'=>null, 'lastStep'=>-1, 'keys'=>[], 'recovery'=>[], 'mode'=>'off', 'sso'=>null, 'ssoMfa'=>true, 'revision'=>0];
    }
    public function get(string $name): array { return $this->transaction(fn(&$d) => self::account($d, $name)); }
    public function update(string $name, callable $fn): mixed {
        return $this->transaction(function (&$d) use ($name, $fn) {
            $a = self::account($d, $name); $result = $fn($a); $d['accounts'][$name] = $a; return $result;
        });
    }
    /** Persistent per-account + per-IP budget, independent of sessions. */
    public function attempt(string $name, string $ip): bool {
        return $this->transaction(function (&$d) use ($name, $ip) {
            $now = time();
            foreach ($d['limits'] as $k=>$v) { if ($v['until'] <= $now) { unset($d['limits'][$k]); } }
            $ids = [hash('sha256', 'account:'.$name), hash('sha256', 'ip:'.$ip)];
            foreach ($ids as $id) { if (($d['limits'][$id]['count'] ?? 0) >= 10) { return false; } }
            foreach ($ids as $id) {
                $d['limits'][$id] ??= ['count'=>0, 'until'=>$now+300];
                ++$d['limits'][$id]['count'];
            }
            return true;
        });
    }
}
