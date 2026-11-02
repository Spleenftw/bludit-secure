<?php
namespace BluditSecure;
final class Totp
{
    public static function secret(): string { return self::encode(random_bytes(20)); }
    public static function encode(string $raw): string {
        $bits = ''; foreach (unpack('C*', $raw) as $v) { $bits .= str_pad(decbin($v), 8, '0', STR_PAD_LEFT); }
        $out = ''; foreach (str_split($bits, 5) as $v) { $out .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[bindec(str_pad($v, 5, '0'))]; } return $out;
    }
    public static function code(string $secret, int $step): string {
        $bits = ''; foreach (str_split($secret) as $c) {
            $v = strpos('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $c);
            if ($v === false) { throw new \InvalidArgumentException('Invalid base32'); }
            $bits .= str_pad(decbin($v), 5, '0', STR_PAD_LEFT);
        }
        $raw = ''; foreach (str_split($bits, 8) as $b) { if (strlen($b) === 8) { $raw .= chr(bindec($b)); } }
        $hash = hash_hmac('sha1', pack('N2', intdiv($step, 4294967296), $step % 4294967296), $raw, true);
        $offset = ord($hash[19]) & 15;
        $n = unpack('N', substr($hash, $offset, 4))[1] & 0x7fffffff;
        return str_pad((string)($n % 1000000), 6, '0', STR_PAD_LEFT);
    }
    public static function verify(string $secret, string $code, int $lastStep, ?int $now = null): ?int {
        if (!preg_match('/^[0-9]{6}$/D', $code)) { return null; }
        $step = intdiv($now ?? time(), 30);
        for ($n = $step-1; $n <= $step+1; ++$n) {
            if ($n > $lastStep && hash_equals(self::code($secret, $n), $code)) { return $n; }
        }
        return null;
    }
}
