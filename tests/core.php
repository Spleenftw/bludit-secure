<?php
require __DIR__.'/../src/Store.php';
require __DIR__.'/../src/Totp.php';
use BluditSecure\Store;
use BluditSecure\Totp;
function check($condition, $label) { if (!$condition) { throw new RuntimeException($label); } echo "OK $label\n"; }
// RFC 6238 SHA-1 vectors truncated to 6 digits.
$secret = Totp::encode('12345678901234567890');
foreach ([59=>'287082',1111111109=>'081804',1111111111=>'050471',1234567890=>'005924',2000000000=>'279037',20000000000=>'353130'] as $time=>$expected) { check(Totp::code($secret, intdiv($time,30)) === $expected, 'RFC vector '.$time); }
check(Totp::verify($secret, '287082', -1, 59) === 1, 'valid TOTP');
check(Totp::verify($secret, '287082', 1, 59) === null, 'reject replay');
check(Totp::verify($secret, '287082', -1, 180) === null, 'reject expired TOTP');
check(Totp::verify($secret, '287082x', -1, 59) === null, 'reject malformed TOTP');
$dir = sys_get_temp_dir().'/bludit-secure-test-'.bin2hex(random_bytes(8));
$s = new Store($dir);
try {
    $s->update('admin', function (&$a) use ($secret) { $a['totp'] = $secret; ++$a['revision']; });
    check($s->get('admin')['totp'] === $secret, 'encrypted round trip');
    check(!str_contains(file_get_contents($dir.'/secure.data.php'), $secret), 'no plaintext secret');
    check((fileperms($dir.'/secure.key.php') & 0777) === 0600, 'private encryption key');
    try { $s->update('admin', function (&$a) { $a['totp'] = 'bad'; throw new RuntimeException('rollback'); }); } catch (RuntimeException $e) {}
    check($s->get('admin')['totp'] === $secret, 'failed transaction rolls back');
    for ($i=0;$i<10;$i++) { check($s->attempt('admin', '127.0.0.1'), 'attempt '.$i); }
    check(!$s->attempt('admin', '127.0.0.2'), 'per-account limit across IPs');
    check(!$s->attempt('other', '127.0.0.1'), 'per-IP limit across accounts');
    $path = $dir.'/secure.data.php'; $raw = file_get_contents($path); $raw[40] = $raw[40] === 'A' ? 'B' : 'A'; file_put_contents($path, $raw);
    $failed = false; try { $s->get('admin'); } catch (Throwable $e) { $failed = true; }
    check($failed, 'tampered ciphertext fails closed');
} finally { foreach (glob($dir.'/*') as $file) { unlink($file); } rmdir($dir); }
