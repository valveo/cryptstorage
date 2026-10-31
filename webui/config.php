<?php
// config.php - Central configuration for Web UI

require_once __DIR__ . '/lang.php';

// API base URL (internal Docker network)
define('API_BASE_URL', getenv('API_BASE_URL') ?: 'http://api:8000');

// Session settings
define('SESSION_NAME', 'cryptstorage_session');
define('SESSION_LIFETIME', 3600); // 1 hour

// App name shown in UI
define('APP_NAME', 'CryptStorage');

// Source code of this server (AGPL-3.0 section 13). Point it at your own copy if you run a changed version.
define('SOURCE_URL', getenv('SOURCE_URL') ?: 'https://github.com/valveo/cryptstorage');

// DEMO SERVER ONLY: accounts are deleted this many hours after registration (0 = a normal server)
define('DEMO_LIFETIME_HOURS', (float)(getenv('ACCOUNT_LIFETIME_HOURS') ?: 0));

function demo_notice(): string {
    if (DEMO_LIFETIME_HOURS <= 0) {
        return '';
    }
    return '<div class="alert alert-error">'
        . t('Demo server: every account and its files are deleted %s hours after registration. Do not store anything you need.',
            htmlspecialchars((string)DEMO_LIFETIME_HOURS)) . '</div>';
}

// Client download page on this server (ansible client_downloads_src), e.g. "/download/"; empty = no link
define('DOWNLOAD_URL', getenv('DOWNLOAD_URL') ?: '');

function download_link(): string {
    if (DOWNLOAD_URL === '') {
        return '';
    }
    return '<p class="hint" style="margin:0 0 1rem"><a href="' . htmlspecialchars(DOWNLOAD_URL, ENT_QUOTES)
        . '" style="color:inherit">' . t('Download the app') . '</a> ' . t('(Windows, Linux): it encrypts your files and opens your storage.') . '</p>';
}

// The build this web UI runs: BUILD_VERSION, written by the deploy (scripts/version.sh), e.g.
// "dev+9151441 (2026-10-29)". Shown in the footer, so it is plain which code a server runs.
function build_version(): string {
    static $v = null;
    if ($v === null) {
        $v = substr(trim((string)@file_get_contents(__DIR__ . '/BUILD_VERSION')), 0, 80) ?: 'dev';
    }
    return $v;
}

function source_link(): string {
    return '<footer style="position:fixed;left:0;right:0;bottom:8px;z-index:10;text-align:center;font-size:.8rem;opacity:.75">'
        . lang_switch() . ' &middot; '
        . '<a href="' . htmlspecialchars(SOURCE_URL, ENT_QUOTES) . '" rel="noopener" style="color:inherit">' . t('Source code') . '</a>'
        . ' &middot; AGPL-3.0 &middot; ' . t('version') . ' ' . htmlspecialchars(build_version()) . '</footer>';
}
