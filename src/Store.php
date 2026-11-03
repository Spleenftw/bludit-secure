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
        if (!$lock) { throw new \RuntimeException('Storage locked'); }
        if (!flock($lock, LOCK_EX)) { fclose($lock); throw new \RuntimeException('Storage locked'); }
        $key = null;
        try {
            chmod($this->dir.'/secure.lock.php', 0600);
            $kp = $this->dir.'/secure.key.php';
            $path = $this->dir.'/secure.data.php';
            $prefix = "<?php exit; ?>\n";
            if (!file_exists($kp)) {
                if (file_exists($path)) { throw new \RuntimeException('Missing encryption key'); }
                $initialKey = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
                try {
                    $this->write($kp, $prefix.base64_encode($initialKey));
                    $nonce = random_bytes(24);
                    $this->write($path, $prefix.base64_encode($nonce.sodium_crypto_secretbox('{"accounts":[],"limits":[]}', $nonce, $initialKey)));
                } finally { sodium_memzero($initialKey); }
            }
            if (!file_exists($path)) { throw new \RuntimeException('Missing security data'); }
            $keyFile = file_get_contents($kp);
            if ($keyFile === false || !str_starts_with($keyFile, $prefix)) { throw new \RuntimeException('Invalid encryption key header'); }
            $key = base64_decode(substr($keyFile, strlen($prefix)), true);
            if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) { throw new \RuntimeException('Invalid encryption key'); }
            $data = ['accounts'=>[], 'limits'=>[]];
            if (file_exists($path)) {
                $dataFile = file_get_contents($path);
                if ($dataFile === false || !str_starts_with($dataFile, $prefix)) { throw new \RuntimeException('Invalid storage header'); }
                $raw = base64_decode(substr($dataFile, strlen($prefix)), true);
                if ($raw === false || strlen($raw) < 40) { throw new \RuntimeException('Invalid storage'); }
                $plain = sodium_crypto_secretbox_open(substr($raw, 24), substr($raw, 0, 24), $key);
                if ($plain === false) { throw new \RuntimeException('Storage authentication failed'); }
                $data = json_decode($plain, true, 64, JSON_THROW_ON_ERROR);
                if (!is_array($data) || !isset($data['accounts'], $data['limits']) || !is_array($data['accounts']) || !is_array($data['limits'])) { throw new \RuntimeException('Invalid storage structure'); }
            }
            $before = $data;
            $result = $fn($data);
            if ($data !== $before) {
                $nonce = random_bytes(24);
                $this->write($path, $prefix.base64_encode($nonce.sodium_crypto_secretbox(json_encode($data, JSON_THROW_ON_ERROR), $nonce, $key)));
            }
            return $result;
        } finally {
            if (is_string($key)) { sodium_memzero($key); }
            flock($lock, LOCK_UN); fclose($lock);
        }
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
        return $data['accounts'][$name] ?? ['totp'=>null, 'lastStep'=>-1, 'keys'=>[], 'recovery'=>[], 'mode'=>'off', 'sso'=>null, 'ssoProfile'=>null, 'ssoMfa'=>true, 'revision'=>0];
    }
    public function get(string $name): array { return $this->transaction(fn(&$d) => self::account($d, $name)); }
    public function update(string $name, callable $fn): mixed {
        return $this->transaction(function (&$d) use ($name, $fn) {
            $a = self::account($d, $name); $result = $fn($a); $d['accounts'][$name] = $a; return $result;
        });
    }
    /** Reserve before checking credentials so concurrent failures cannot exceed the budget. */
    public function beginAttempt(string $name, string $ip, int $limit = 10): ?array {
        if ($limit < 1) { throw new \InvalidArgumentException('Invalid attempt limit'); }
        return $this->transaction(function (&$d) use ($name, $ip, $limit) {
            $now = time();
            foreach ($d['limits'] as $k=>$v) { if ($v['until'] <= $now) { unset($d['limits'][$k]); } }
            $ids = [hash('sha256', 'account:'.$name), hash('sha256', 'ip:'.$ip)];
            foreach ($ids as $id) { if (($d['limits'][$id]['count'] ?? 0) >= $limit) { return null; } }
            $reservation = [];
            foreach ($ids as $id) {
                $d['limits'][$id] ??= ['count'=>0, 'until'=>$now+300];
                $d['limits'][$id]['window'] ??= bin2hex(random_bytes(8));
                ++$d['limits'][$id]['count'];
                $reservation[$id] = $d['limits'][$id]['window'];
            }
            return $reservation;
        });
    }
    /** Refund only this successful attempt, preserving other accounts' or requests' failures. */
    public function releaseAttempt(array $reservation): void {
        $this->transaction(function (&$d) use ($reservation) {
            foreach ($reservation as $id=>$window) {
                if (($d['limits'][$id]['window'] ?? null) !== $window) { continue; }
                if (--$d['limits'][$id]['count'] <= 0) { unset($d['limits'][$id]); }
            }
        });
    }
    /** Throttle non-verification work without refunding successful requests. */
    public function attempt(string $name, string $ip, int $limit = 10): bool {
        return $this->beginAttempt($name, $ip, $limit) !== null;
    }
}
