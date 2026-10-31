<?php
// lang.php - The web UI's languages: English (the source text) and Finnish.
//
// Strings are written in English in the pages and looked up by that text in lang/<code>.php; a missing
// translation falls back to the English. The choice: ?lang=xx (saved in a cookie for a year), then the
// cookie, then the browser's Accept-Language, then English. Messages that come from the API stay as the
// API wrote them.

const LANGS = ['en' => 'English', 'fi' => 'Suomi'];

function lang(): string {
    static $lang = null;
    if ($lang !== null) {
        return $lang;
    }
    $asked = $_GET['lang'] ?? null;
    if (is_string($asked) && isset(LANGS[$asked])) {
        $lang = $asked;
        if (!headers_sent()) {
            setcookie('lang', $lang, ['expires' => time() + 365 * 86400, 'path' => '/', 'samesite' => 'Lax',
                                      'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                                      'httponly' => true]);
        }
        return $lang;
    }
    $saved = $_COOKIE['lang'] ?? null;
    if (is_string($saved) && isset(LANGS[$saved])) {
        return $lang = $saved;
    }
    // Accept-Language: "fi-FI,fi;q=0.9,en;q=0.8": the first listed language this UI has wins
    foreach (explode(',', (string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')) as $part) {
        $code = strtolower(substr(trim(explode(';', $part)[0]), 0, 2));
        if (isset(LANGS[$code])) {
            return $lang = $code;
        }
    }
    return $lang = 'en';
}

function lang_table(): array {
    static $tables = [];
    $l = lang();
    if (!isset($tables[$l])) {
        $file = __DIR__ . '/lang/' . $l . '.php';
        $tables[$l] = ($l !== 'en' && is_file($file)) ? (require $file) : [];
    }
    return $tables[$l];
}

// The text in the chosen language. With arguments, %s/%d in it are filled like sprintf (escape them
// yourself when they come from users or the API). The result is trusted page text: some strings carry
// markup such as <strong>, so it is not escaped here.
function t(string $en, ...$args): string {
    $s = lang_table()[$en] ?? $en;
    return $args ? vsprintf($s, $args) : $s;
}

// A date (and time) from the API, in the local way of writing it
function t_date(?string $iso, bool $time = false): string {
    if (!$iso || ($ts = strtotime($iso)) === false) {
        return '–';
    }
    $fmt = lang() === 'fi' ? ($time ? 'j.n.Y H:i' : 'j.n.Y') : ($time ? 'Y-m-d H:i' : 'Y-m-d');
    return date($fmt, $ts);
}

// Bytes in binary units (the quota is set in GiB), with a decimal comma in Finnish
function t_bytes(int|float $bytes): string {
    $units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    $n = $i === 0 ? (string)(int)$bytes : number_format($bytes, $bytes >= 100 ? 0 : ($bytes >= 10 ? 1 : 2),
                                                      lang() === 'fi' ? ',' : '.', '');
    $n = preg_replace('/[.,]$/', '', preg_replace('/([.,]\d*?)0+$/', '$1', $n));   // "10 GiB", "9.5 GiB"
    return $n . "\u{00a0}" . $units[$i];
}

// Links to the other languages, keeping the page (and its query, without an old lang=)
function lang_switch(): string {
    $query = $_GET;
    $out = [];
    foreach (LANGS as $code => $name) {
        if ($code === lang()) {
            continue;
        }
        $query['lang'] = $code;
        $href = strtok($_SERVER['REQUEST_URI'] ?? '', '?') . '?' . http_build_query($query);
        $out[] = '<a href="' . htmlspecialchars($href, ENT_QUOTES) . '" hreflang="' . $code . '" lang="' . $code
               . '" class="lang-switch" style="color:inherit">' . htmlspecialchars($name) . '</a>';
    }
    return implode(' ', $out);
}

// The strings the page scripts show (assets/passkey.js, assets/derive.js), for the chosen language
function js_strings_tag(): string {
    $keys = [
        'This browser does not support passkeys. Use another way to sign in.',
        'Follow the prompt of your browser or phone…',
        'Cancelled, timed out, or no passkey for this account here. Try again, or use another way.',
        'The passkey did not work (%s). Try again, or use another way.',
        'Preparing your password securely…',
        'The password must be at least %s characters.',
        'The two passwords do not match.',
        'This browser cannot prepare your password securely. Use a current browser.',
        'Copied',
        'Sign in →',
        'Create account →',
        'Are you absolutely sure? All your data will be deleted when the waiting period ends.',
    ];
    $map = [];
    foreach ($keys as $k) {
        $map[$k] = t($k);
    }
    return '<script type="application/json" id="i18n">'
         . json_encode($map, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE) . '</script>';
}
