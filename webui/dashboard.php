<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/api.php';

session_start_secure();
require_login();

$api     = new ApiClient(get_token());
$user    = $api->me();
$usage   = $api->storage_usage();
// The server requires two-factor and this account has none yet: only its setup is open
$setup_required = ($usage['detail'] ?? '') === 'SECOND_FACTOR_SETUP_REQUIRED';

$error   = '';
$success = '';
$totp_setup = null;
$backup_codes = null;
$passkey_options = null;

// Sensitive actions need no password here: the web UI never asks for it, because the server also
// serves this page's scripts. The API accepts a sign-in from the last 10 minutes instead.
$reauth = false;
function action_error(array $res, string $fallback): string {
    global $reauth;
    $detail = $res['detail'] ?? null;
    if ($detail === 'REAUTH_REQUIRED') {
        $reauth = true;
        return t('To confirm this, sign in again: it is more than 10 minutes since you signed in.');
    }
    if ($detail === 'TOTP_REQUIRED') {
        return t('Enter a code from your authenticator app to confirm.');
    }
    return is_string($detail) ? $detail : ($res['error'] ?? t($fallback));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $action = $_POST['action'] ?? '';
    $code = trim($_POST['code'] ?? '');

    if ($action === 'totp_setup') {
        $res = $api->totp_setup();
        if (isset($res['secret'])) {
            $totp_setup = $res;
        } else {
            $error = action_error($res, 'Could not start two-factor setup.');
        }

    } elseif ($action === 'totp_enable') {
        $res = $api->totp_enable($code, trim($_POST['email_code'] ?? ''));
        if (isset($res['backup_codes'])) {
            $success = t('Two-factor authentication is on.');
            $backup_codes = $res['backup_codes'];
            $user = $api->me();
            $usage = $api->storage_usage();
            $setup_required = false;
        } else {
            $error = action_error($res, 'Could not turn on two-factor.');
        }

    } elseif ($action === 'totp_disable') {
        $res = $api->totp_disable($code);
        if (isset($res['message'])) {
            $success = t('Two-factor authentication is off.');
            $user = $api->me();
        } else {
            $error = action_error($res, 'Could not turn off two-factor.');
        }

    } elseif ($action === 'passkey_begin') {
        $res = $api->passkey_register_begin($code);
        if (isset($res['options'], $res['session'])) {
            $name = trim($_POST['name'] ?? '');
            $_SESSION['pk_reg'] = ['session' => $res['session'], 'name' => $name !== '' ? mb_substr($name, 0, 64) : t('Passkey')];
            $passkey_options = $res['options'];
        } else {
            $error = action_error($res, 'Could not start adding a passkey.');
        }

    } elseif ($action === 'passkey_finish') {
        $reg = $_SESSION['pk_reg'] ?? null;
        unset($_SESSION['pk_reg']);
        $credential = posted_credential();
        $res = ($reg && $credential) ? $api->passkey_register_finish($reg['session'], $reg['name'], $credential)
                                     : ['detail' => t('Adding the passkey expired. Start again.')];
        if (isset($res['id'])) {
            $success = t('Passkey added. Next time, sign in with it alone.');
        } else {
            $error = action_error($res, 'Could not add the passkey.');
        }

    } elseif ($action === 'passkey_delete') {
        $res = $api->passkey_delete($_POST['passkey_id'] ?? '', $code);
        if (isset($res['message'])) {
            $success = t('Passkey removed.');
        } else {
            $error = action_error($res, 'Could not remove the passkey.');
        }

    } elseif ($action === 'stick_lock') {
        $res = $api->stick_lock($_POST['stick_id'] ?? '');
        if (isset($res['message'])) {
            $success = t('Stick locked: its key cannot be opened, even with your password. If you find the stick, connect with it in the app to unlock it.');
        } else {
            $error = action_error($res, 'Could not lock the stick.');
        }

    } elseif ($action === 'stick_delete') {
        $res = $api->stick_delete($_POST['stick_id'] ?? '', $code);
        if (isset($res['message'])) {
            $success = $res['message'];
        } else {
            $error = action_error($res, 'Could not remove the stick.');
        }

    } elseif ($action === 'cancel_change') {
        $res = $api->cancel_pending($_POST['change_id'] ?? '');
        if (isset($res['message'])) {
            $success = t('Cancelled. If you did not ask for that change, change your password in the app now.');
        } else {
            $error = action_error($res, 'Could not cancel.');
        }

    } elseif ($action === 'delete_account') {
        $res = $api->delete_account($code);
        if (isset($res['message']) && !empty($res['pending'])) {
            $success = $res['message'];
        } elseif (isset($res['message'])) {
            clear_session();
            header('Location: index.php?deleted=1');
            exit;
        } else {
            $error = action_error($res, 'Deletion failed.');
        }
    }
}

$passkey_list = ($user['totp_enabled'] ?? false) ? $api->passkeys() : [];
$passkey_list = array_is_list($passkey_list) ? $passkey_list : [];
$stick_list = $api->sticks();
$stick_list = array_is_list($stick_list) ? $stick_list : [];
$changes = $api->pending_changes();
$changes = array_is_list($changes) ? $changes : [];
$change_names = ['ssh_key' => t('New USB stick key'), 'delete' => t('Deletion of the account and all data'),
                 'stick' => t('Removal of a locked USB stick')];
// This user's escrow state. The operator controls this page too: the client's own check is the real one.
$escrow = $api->escrow();
$escrow = isset($escrow['recovery_policy']) ? $escrow : null;
$fingerprint = fn(?string $fp): string => $fp ? implode(' ', str_split(substr($fp, 0, 32), 4)) : '–';

// Storage: binary units, as the quota is set (GiB)
$quota_bytes = (int)($usage['quota_bytes'] ?? $user['quota_bytes'] ?? 0);
$used_bytes  = (int)($usage['used_bytes'] ?? 0);
$has_usage   = isset($usage['used_bytes']);
// (the API sends bytes only: the old page read a 'percent' field it never had, so its bar stayed empty)
$used_pct    = $quota_bytes > 0 ? 100 * $used_bytes / $quota_bytes : 0;
$fill_class  = $used_pct >= 90 ? 'full' : ($used_pct >= 75 ? 'high' : '');
$username    = get_username();

// Escrow is shown on the overview only when it matters: on for this user, or its record broken
$escrow_on    = $escrow && ($escrow['has_escrow'] ?? false);
$escrow_alarm = $escrow && !($escrow['settings_log_ok'] ?? true);

// Getting started: shown until two-factor, a passkey and a stick are all in place
$steps = [
    ['done' => (bool)($user['totp_enabled'] ?? false), 'tab' => 'signin',
     'text' => t('Turn on two-factor authentication'), 'hint' => t('Required: a code from your phone keeps a stolen password from being enough.')],
    ['done' => (bool)$passkey_list, 'tab' => 'signin',
     'text' => t('Add a passkey'), 'hint' => t('Recommended: sign in with a fingerprint, face or security key, without typing your password here.')],
    ['done' => (bool)$stick_list, 'tab' => 'sticks',
     'text' => t('Install the app and connect with your USB stick'), 'hint' => t('The app encrypts your files on your own computer and keeps the key on the stick.')],
];
$steps_left = count(array_filter($steps, fn($st) => !$st['done']));

// The section to open: where the posted action lives, then the link's #hash (in the script), else the overview
$action_tabs = ['totp_setup' => 'signin', 'totp_enable' => 'signin', 'totp_disable' => 'signin',
                'passkey_begin' => 'signin', 'passkey_finish' => 'signin', 'passkey_delete' => 'signin',
                'stick_lock' => 'sticks', 'stick_delete' => 'sticks', 'delete_account' => 'account'];
$tab = $setup_required ? 'signin' : ($action_tabs[$_POST['action'] ?? ''] ?? '');
$tabs = ['overview' => t('Overview'), 'signin' => t('Sign-in'), 'sticks' => t('USB sticks'), 'account' => t('Account')];
?>
<!DOCTYPE html>
<html lang="<?= lang() ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= t('Dashboard') ?> — <?= APP_NAME ?></title>
<link rel="stylesheet" href="assets/fonts/fonts.css">
<style>
  html { font-size: 112.5%; }
  :root {
    --bg:      #0a0a0f;
    --surface: #111118;
    --border:  #1e1e2e;
    --accent:  #00e5a0;
    --text:    #e8e8f0;
    --muted:   #a3a3bb;
    --error:   #ff4d6d;
    --ok:      #00e5a0;
    --mono:    'Space Mono', monospace;
    --sans:    'DM Sans', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
  }

  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(var(--border) 1px, transparent 1px),
      linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 40px 40px;
    opacity: 0.3;
    pointer-events: none;
  }

  header {
    position: relative;
    z-index: 1;
    border-bottom: 1px solid var(--border);
    padding: 1rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(10,10,15,0.85);
    backdrop-filter: blur(8px);
  }

  .logo {
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: var(--accent);
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .logo-icon {
    width: 24px;
    height: 24px;
    border: 2px solid var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 1.5rem;
  }

  .username-badge {
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--muted);
    letter-spacing: 0.08em;
  }

  .username-badge span { color: var(--text); }

  .btn-logout {
    font-family: var(--mono);
    font-size: 0.8rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    text-decoration: none;
    border: 1px solid var(--border);
    padding: 0.4rem 0.75rem;
    transition: color 0.2s, border-color 0.2s;
  }

  .btn-logout:hover { color: var(--error); border-color: var(--error); }

  main {
    position: relative;
    z-index: 1;
    max-width: 820px;
    margin: 0 auto;
    padding: 2rem 2rem 4rem;
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .tab-panel { display: flex; flex-direction: column; gap: 1.25rem; }
  .tab-panel[hidden] { display: none; }

  .tabs { display: flex; flex-wrap: wrap; gap: .25rem; border-bottom: 1px solid var(--border); }
  .tabs a {
    font-family: var(--mono); font-size: .85rem; letter-spacing: .06em; text-transform: uppercase;
    color: var(--muted); text-decoration: none; padding: .7rem 1rem; border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }
  .tabs a:hover { color: var(--text); }
  .tabs a[aria-current="page"] { color: var(--accent); border-bottom-color: var(--accent); }
  /* Without scripts every section shows, so the section links are only jump links */
  main:not(.js-tabs) .tabs { display: none; }

  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 1.5rem;
    animation: fadeUp 0.3s ease both;
  }

  .onboarding { border-color: var(--accent); }
  .steps-count { float: right; text-transform: none; letter-spacing: 0; }
  .steps { list-style: none; margin: .75rem 0 1rem; display: flex; flex-direction: column; gap: .85rem; }
  .steps li { display: flex; gap: .8rem; align-items: flex-start; }
  .step-mark {
    flex: 0 0 1.4rem; height: 1.4rem; border: 2px solid var(--muted); border-radius: 50%;
    display: flex; align-items: center; justify-content: center; font-size: .8rem; color: var(--bg);
  }
  .steps li.done .step-mark { background: var(--accent); border-color: var(--accent); }
  .steps li.done .step-text { color: var(--muted); text-decoration: line-through; }
  .step-text { color: var(--text); font-weight: 500; }
  a.step-text { color: var(--accent); }
  .step-hint { display: block; color: var(--muted); font-size: .85rem; margin-top: .15rem; }

  .setup-steps { margin: .25rem 0 1.25rem 1.2rem; display: flex; flex-direction: column; gap: .75rem; }
  .setup-steps li { padding-left: .25rem; }
  .totp-qr { margin: .75rem 0; line-height: 0; }
  .totp-qr:empty { display: none; }
  .totp-qr svg { width: 220px; height: 220px; background: #fff; border: 8px solid #fff; }
  .code-input { font-family: var(--mono); font-size: 1.15rem !important; letter-spacing: .2em; max-width: 14rem; }

  .status-line { display: flex; align-items: center; gap: .5rem; margin-bottom: .5rem; font-weight: 500; }
  .item-row { margin-bottom: .75rem; padding-bottom: .75rem; border-bottom: 1px solid var(--border); }
  .item-name { flex: 1 1 12rem; }
  .lang-switch { color: inherit; }

  @media (max-width: 640px) {
    header { padding: .75rem 1rem; flex-wrap: wrap; gap: .5rem; }
    .header-right { gap: .75rem; flex-wrap: wrap; }
    .username-badge { display: none; }
    main { padding: 1rem 1rem 4rem; }
    .panel { padding: 1.1rem; }
    .tabs a { padding: .6rem .7rem; font-size: .8rem; }
  }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(16px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .panel-title {
    font-family: var(--mono);
    font-size: 0.8rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 1.25rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid var(--border);
  }

  /* Storage status panel */
  .status-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1.25rem;
  }

  .status-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .status-dot.on  { background: var(--ok);    box-shadow: 0 0 8px var(--ok); }
  .status-dot.off { background: var(--muted); }

  .status-label {
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 700;
  }

  .status-label.on  { color: var(--ok); }
  .status-label.off { color: var(--muted); }

  .quota-bar-wrap {
    margin-bottom: 1.25rem;
  }

  .quota-label {
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--muted);
    margin-bottom: 0.4rem;
    letter-spacing: 0.08em;
  }

  .quota-numbers { display: flex; align-items: baseline; gap: .5rem; margin: .5rem 0 .6rem; }
  .quota-used { font-size: 1.5rem; font-weight: 500; }
  .quota-of { color: var(--muted); }
  .quota-bar { height: 12px; background: var(--border); width: 100%; border-radius: 6px; overflow: hidden; }
  .quota-fill { height: 100%; background: var(--accent); width: 0%; border-radius: 6px; transition: width 0.6s ease; }
  .quota-fill.high { background: #f59e0b; }
  .quota-fill.full { background: var(--error); }
  .quota-free { margin-top: .5rem; font-size: .85rem; color: var(--muted); }
  .quota-free.high { color: #f59e0b; }
  .quota-free.full { color: var(--error); }

  .ssh-cmd-box {
    background: var(--bg);
    border: 1px solid var(--border);
    padding: 0.75rem 1rem;
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--accent);
    word-break: break-all;
    margin-bottom: 1rem;
    cursor: pointer;
    transition: border-color 0.2s;
    position: relative;
  }

  .ssh-cmd-box:hover { border-color: var(--accent); }

  .copy-hint {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 0.3rem;
  }

  /* Forms */
  .field { margin-bottom: 1rem; }

  label {
    display: block;
    font-family: var(--mono);
    font-size: 0.8rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.4rem;
  }

  input, textarea {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: var(--sans);
    font-size: 0.88rem;
    padding: 0.6rem 0.8rem;
    outline: none;
    transition: border-color 0.2s;
    resize: vertical;
  }

  input:focus, textarea:focus { border-color: var(--accent); }

  textarea {
    font-family: var(--mono);
    font-size: 0.8rem;
    min-height: 68px;
  }

  .btn {
    background: var(--accent);
    color: #000;
    border: none;
    padding: 0.65rem 1.25rem;
    font-family: var(--mono);
    font-size: 0.8rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    cursor: pointer;
    transition: opacity 0.2s;
  }

  .btn:hover { opacity: 0.85; }

  .btn-danger {
    background: none;
    color: var(--error);
    border: 1px solid var(--error);
  }

  .btn-danger:hover { background: rgba(255,77,109,0.08); opacity: 1; }

  .btn-muted {
    background: none;
    color: var(--muted);
    border: 1px solid var(--border);
  }

  .btn-muted:hover { color: var(--text); border-color: var(--text); opacity: 1; }

  .btn-row { display: flex; gap: 0.75rem; flex-wrap: wrap; }

  .alert {
    padding: 0.7rem 1rem;
    font-size: 0.82rem;
    margin-bottom: 1rem;
    border-left: 3px solid;
  }

  .alert-error   { border-color: var(--error);  background: rgba(255,77,109,0.07); color: var(--error); }
  .alert-success { border-color: var(--ok);     background: rgba(0,229,160,0.07);  color: var(--ok); }

  .meta-row {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
  }

  .meta-row:last-child { border-bottom: none; }
  .meta-key   { color: var(--muted); font-family: var(--mono); font-size: 0.8rem; }
  .meta-value { color: var(--text); }

  /* Delete section */
  .danger-zone {
    border-color: rgba(255,77,109,0.25);
  }

  .danger-zone .panel-title { color: var(--error); }

  .warn-text {
    font-size: 0.82rem;
    color: var(--muted);
    margin-bottom: 1rem;
    line-height: 1.6;
  }

  @media (max-width: 640px) {
    main { grid-template-columns: 1fr; }
    .panel:nth-child(1) { grid-column: 1; }
  }
  .recovery { margin: 1rem 0; padding: 1rem; border: 1px solid var(--warn, #ffb020); background: rgba(255,176,32,0.07); }
  .recovery strong { display: block; margin-bottom: .5rem; }
  .recovery code { display: block; font-size: 1.1rem; letter-spacing: .08em; padding: .6rem; margin: .5rem 0;
                   background: rgba(0,0,0,0.35); user-select: all; word-break: break-all; }
  .recovery p { margin: .4rem 0 0; font-size: .85rem; opacity: .85; }
  .totp-secret { display: flex; flex-wrap: wrap; align-items: center; gap: .75rem; margin: .75rem 0 .5rem; }
  .totp-secret code { flex: 1 1 auto; font-family: var(--mono); font-size: 1.35rem; letter-spacing: .12em;
                      word-spacing: .3em; line-height: 1.6; padding: .6rem .8rem; background: rgba(0,0,0,0.35);
                      border: 1px solid var(--border); color: var(--text); user-select: all; word-break: break-word; }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">⬡</div>
    <?= APP_NAME ?>
  </div>
  <div class="header-right">
    <div class="username-badge"><?= t('signed in as') ?> <span><?= htmlspecialchars($username) ?></span></div>
    <?= lang_switch() ?>
    <a href="logout.php" class="btn-logout"><?= t('Sign out') ?></a>
  </div>
</header>

<main data-tab="<?= htmlspecialchars($tab, ENT_QUOTES) ?>">

  <?php if (demo_notice()): ?><?= demo_notice() ?><?php endif; ?>
  <?php if ($error):   ?><div class="alert alert-error"><?= htmlspecialchars($error) ?>
    <?php if ($reauth): ?> <a href="logout.php" style="color:inherit"><?= t('Sign in again') ?></a><?php endif; ?></div><?php endif; ?>
  <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
  <?php if ($setup_required): ?>
  <div class="alert alert-error"><?= t('This server requires two-factor authentication. Set it up below; until then your storage cannot be opened from this account.') ?></div>
  <?php endif; ?>
  <?php if ($escrow_alarm): ?>
  <div class="alert alert-error"><?= t("The record of this server's escrow settings has been tampered with. Ask your administrator what changed.") ?></div>
  <?php endif; ?>
  <?php if ($changes): ?>
  <!-- Waiting changes: the owner can always see and stop them, whichever section is open -->
  <div class="panel danger-zone">
    <div class="panel-title"><?= t('Waiting changes') ?></div>
    <p class="warn-text" style="margin-bottom:1rem"><?= t('These take effect at the time shown. If you did not ask for one, cancel it and change your password.') ?></p>
    <?php foreach ($changes as $ch): ?>
    <form method="POST" class="btn-row" style="margin-bottom:.5rem">
      <?= csrf_field() ?>
      <input type="hidden" name="action" value="cancel_change">
      <input type="hidden" name="change_id" value="<?= htmlspecialchars($ch['id'] ?? '', ENT_QUOTES) ?>">
      <span class="meta-value"><?= htmlspecialchars($change_names[$ch['kind'] ?? ''] ?? ($ch['kind'] ?? '')) ?>,
        <?= isset($ch['due_at']) ? htmlspecialchars(t_date($ch['due_at'], true)) . ' UTC' : '' ?></span>
      <button type="submit" class="btn"><?= t('Cancel') ?></button>
    </form>
    <?php endforeach; ?>
  </div>
  <?php endif; ?>

  <nav class="tabs" aria-label="<?= t('Sections') ?>">
    <?php foreach ($tabs as $key => $label): ?>
    <a href="#<?= $key ?>" data-tab-link="<?= $key ?>"><?= $label ?></a>
    <?php endforeach; ?>
  </nav>

  <!-- ===== Overview ===== -->
  <section class="tab-panel" data-tab-panel="overview">
    <?php if ($steps_left > 0): ?>
    <!-- Getting started: hidden for good once every step is done -->
    <div class="panel onboarding">
      <div class="panel-title"><?= t('Getting started') ?> <span class="steps-count"><?= t('%d of %d done', count($steps) - $steps_left, count($steps)) ?></span></div>
      <ol class="steps">
        <?php foreach ($steps as $st): ?>
        <li class="<?= $st['done'] ? 'done' : '' ?>">
          <span class="step-mark" aria-hidden="true"><?= $st['done'] ? '✓' : '' ?></span>
          <span>
            <?php if ($st['done']): ?><span class="step-text"><?= $st['text'] ?></span>
            <?php else: ?><a href="#<?= $st['tab'] ?>" class="step-text"><?= $st['text'] ?></a><?php endif; ?>
            <span class="step-hint"><?= $st['hint'] ?></span>
          </span>
        </li>
        <?php endforeach; ?>
      </ol>
      <?php if (!$steps[2]['done']): ?><?= download_link() ?><?php endif; ?>
    </div>
    <?php endif; ?>

    <div class="panel">
      <div class="panel-title"><?= t('Storage') ?></div>
      <?php if ($has_usage && $quota_bytes > 0): ?>
      <div class="quota-numbers">
        <span class="quota-used"><?= t('%s used', t_bytes($used_bytes)) ?></span>
        <span class="quota-of"><?= t('of %s', t_bytes($quota_bytes)) ?></span>
      </div>
      <div class="quota-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="<?= round($used_pct) ?>">
        <div class="quota-fill <?= $fill_class ?>" style="width:<?= min(100, max(0, $used_pct)) ?>%"></div>
      </div>
      <div class="quota-free <?= $fill_class ?>">
        <?= t('%s free (%s%% used)', t_bytes(max(0, $quota_bytes - $used_bytes)), htmlspecialchars((string)round($used_pct))) ?>
        <?php if ($used_pct >= 90): ?> · <?= t('Storage almost full: remove files or ask for more space.') ?><?php endif; ?>
      </div>
      <?php else: ?>
      <p class="warn-text"><?= t('Storage use is shown once two-factor authentication is on.') ?></p>
      <?php endif; ?>
      <p class="warn-text" style="margin-top:1rem"><?= t('Your files are encrypted on your own computer. Open them with the CryptStorage app; this page never shows what is stored.') ?></p>
      <?php if ($steps[2]['done']): ?><div style="margin-top:.75rem"><?= download_link() ?></div><?php endif; ?>
    </div>

    <?php if ($escrow_on): ?>
    <!-- Escrow: shown here only when someone else holds a copy of the key -->
    <div class="panel danger-zone">
      <div class="panel-title"><?= t('Escrow is on') ?></div>
      <p class="warn-text" style="margin-bottom:1rem"><?= t('Your organisation holds a sealed copy of your storage key, so its administrators can read your files.') ?></p>
      <div class="meta-row">
        <span class="meta-key"><?= t('Organisation key') ?></span>
        <span class="meta-value"><code><?= htmlspecialchars($fingerprint($escrow['escrow_key_fingerprint'] ?? null)) ?></code></span>
      </div>
      <div class="meta-row">
        <span class="meta-key"><?= t('Your copy sealed to') ?></span>
        <span class="meta-value"><code><?= htmlspecialchars($fingerprint($escrow['sealed_key_fingerprint'] ?? null)) ?></code>
          <?= isset($escrow['sealed_at']) ? htmlspecialchars(t_date($escrow['sealed_at'])) : '' ?></span>
      </div>
      <p class="warn-text" style="margin-top:1rem"><?= t('The app on your computer checks these against what it remembers on your stick and warns you if they change.') ?>
        <a href="#account" style="color:inherit"><?= t('Details') ?></a></p>
    </div>
    <?php endif; ?>
  </section>

  <!-- ===== Sign-in: two-factor and passkeys ===== -->
  <section class="tab-panel" data-tab-panel="signin">
    <div class="panel">
      <div class="panel-title"><?= t('Two-factor authentication') ?></div>
      <?php if ($backup_codes): ?>
      <div class="recovery">
        <strong><?= t('Save your backup codes now') ?></strong>
        <code><?= htmlspecialchars(implode("\n", $backup_codes)) ?></code>
        <p><?= t('Each code works once if you lose your phone. They are shown only once.') ?></p>
      </div>
      <?php elseif ($user['totp_enabled'] ?? false): ?>
      <p class="status-line"><span class="status-dot on"></span><?= t('On') ?></p>
      <p class="warn-text" style="margin-bottom:1rem"><?= t('Turning it off needs a code (not possible when the server requires it).') ?></p>
      <form method="POST">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="totp_disable">
        <div class="field"><label><?= t('Code or backup code') ?></label>
          <input type="text" name="code" autocomplete="one-time-code" required></div>
        <button type="submit" class="btn btn-muted"><?= t('Turn off') ?></button>
      </form>
      <?php elseif ($totp_setup): ?>
      <ol class="setup-steps">
        <li><?= t('Open your authenticator app (for example Google Authenticator, Microsoft Authenticator or Aegis) and add an account.') ?></li>
        <li><?= t('Scan this QR code with the app:') ?>
          <div class="totp-qr" id="totp-qr" data-uri="<?= htmlspecialchars($totp_setup['otpauth_uri'] ?? '', ENT_QUOTES) ?>"
               role="img" aria-label="<?= t('QR code for the authenticator app') ?>"></div>
          <span class="step-hint"><?= t('Cannot scan? Choose to enter a key by hand in the app and type or copy this key:') ?></span>
          <div class="totp-secret">
            <code id="totp-secret" aria-label="<?= t('Key for the authenticator app') ?>"><?= htmlspecialchars(trim(chunk_split($totp_setup['secret'], 4, ' '))) ?></code>
            <button type="button" class="btn btn-muted" data-copy="<?= htmlspecialchars($totp_setup['secret'], ENT_QUOTES) ?>"><?= t('Copy') ?></button>
          </div>
          <span class="step-hint"><?= t('The spaces are only for reading; the app accepts the key with or without them.') ?></span></li>
        <li><?= t('Type the 6-digit code the app shows, and the 8-digit code we sent to your e-mail.') ?></li>
      </ol>
      <form method="POST">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="totp_enable">
        <div class="field"><label><?= t('6-digit code from the app') ?></label>
          <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" required class="code-input"></div>
        <div class="field"><label><?= t('8-digit code from the e-mail') ?></label>
          <input type="text" name="email_code" inputmode="numeric" autocomplete="off" required class="code-input"></div>
        <button type="submit" class="btn"><?= t('Confirm and turn on') ?></button>
      </form>
      <?php else: ?>
      <p class="status-line"><span class="status-dot off"></span><?= t('Off') ?></p>
      <p class="warn-text" style="margin-bottom:1rem"><?= t('Adds a code from your phone to signing in, so a stolen password alone is not enough.') ?></p>
      <form method="POST">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="totp_setup">
        <button type="submit" class="btn"><?= t('Set up') ?></button>
      </form>
      <?php endif; ?>
    </div>

    <!-- Passkeys: the recommended second factor; the authenticator app stays as the fallback -->
    <div class="panel">
      <div class="panel-title"><?= t('Passkeys') ?></div>
      <?php if (!($user['totp_enabled'] ?? false)): ?>
      <p class="warn-text"><?= t('Set up two-factor authentication first. A passkey then lets you sign in with Face ID, a fingerprint or your phone instead of typing a code; the authenticator app stays as the fallback.') ?></p>
      <?php elseif ($passkey_options): ?>
      <p class="warn-text" style="margin-bottom:1rem"><?= t('Now confirm on this device, or choose your phone and scan the QR code.') ?></p>
      <button type="button" class="btn" data-passkey-start><?= t('Create passkey') ?></button>
      <div class="warn-text" data-passkey-status style="margin-top:.5rem"></div>
      <?= passkey_options_tag($passkey_options, 'create') ?>
      <form method="POST" data-passkey-form>
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="passkey_finish">
        <input type="hidden" name="credential" value="">
      </form>
      <?php else: ?>
      <p class="warn-text" style="margin-bottom:1rem"><?= t('Sign in with Face ID, a fingerprint or your phone instead of typing a code, and sign in to this page with the passkey alone, without your password. Recommended; keep the authenticator app as the fallback.') ?></p>
      <?php foreach ($passkey_list as $pk): ?>
      <form method="POST" class="btn-row item-row">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="passkey_delete">
        <input type="hidden" name="passkey_id" value="<?= htmlspecialchars($pk['id'] ?? '', ENT_QUOTES) ?>">
        <span class="meta-value item-name"><?= htmlspecialchars($pk['name'] ?? '') ?>
          <span class="meta-key"><?= isset($pk['last_used_at']) ? t('used %s', htmlspecialchars(t_date($pk['last_used_at']))) : t('not used yet') ?></span></span>
        <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="<?= t('Code (if asked)') ?>" style="max-width:150px">
        <button type="submit" class="btn btn-muted"><?= t('Remove') ?></button>
      </form>
      <?php endforeach; ?>
      <form method="POST" style="margin-top:1rem">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="passkey_begin">
        <div class="field"><label><?= t('Name') ?></label>
          <input type="text" name="name" maxlength="64" placeholder="<?= t('e.g. iPhone') ?>" autocomplete="off"></div>
        <div class="field"><label><?= t('Code from the app') ?> <span style="text-transform:none"><?= t('(not needed within 5 minutes of signing in)') ?></span></label>
          <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code"></div>
        <button type="submit" class="btn"><?= t('Add a passkey') ?></button>
      </form>
      <?php endif; ?>
    </div>
  </section>

  <!-- ===== USB sticks: the server holds half of each stick's key, so a lost stick can be switched off ===== -->
  <section class="tab-panel" data-tab-panel="sticks">
    <div class="panel">
      <div class="panel-title"><?= t('USB sticks') ?></div>
      <?php if (!$stick_list): ?>
      <p class="warn-text"><?= t('No stick is protected by the server yet. The app does it the next time you connect.') ?></p>
      <div style="margin-top:1rem"><?= download_link() ?></div>
      <?php else: ?>
      <p class="warn-text" style="margin-bottom:1rem"><?= t('The key on each stick also needs a secret this server keeps. If you lose a stick, lock it here: its key cannot be opened at once, even with your password. If you find it, connect with it in the app to unlock it. Removing a stick for good waits like deleting the account, and you get an e-mail with a cancel link.') ?></p>
      <?php foreach ($stick_list as $sk): $sid = htmlspecialchars($sk['id'] ?? '', ENT_QUOTES); ?>
      <div class="btn-row item-row">
        <span class="meta-value item-name"><?= htmlspecialchars($sk['name'] ?? '') ?>
          <span class="meta-key"><?= isset($sk['last_used_at']) ? t('used %s', htmlspecialchars(t_date($sk['last_used_at']))) : t('not used yet') ?></span>
          <?php if (!empty($sk['removal_due'])): ?>
          <span class="meta-key stick-state"><?= t('locked, removed on %s UTC', htmlspecialchars(t_date($sk['removal_due'], true))) ?></span>
          <?php elseif (!empty($sk['locked_at'])): ?>
          <span class="meta-key stick-state"><?= t('locked: unlock it by connecting with it in the app') ?></span>
          <?php endif; ?></span>
        <?php if (empty($sk['locked_at'])): ?>
        <form method="POST" style="display:inline">
          <?= csrf_field() ?>
          <input type="hidden" name="action" value="stick_lock">
          <input type="hidden" name="stick_id" value="<?= $sid ?>">
          <button type="submit" class="btn btn-danger"><?= t('Lost? Lock it') ?></button>
        </form>
        <?php endif; ?>
        <?php if (empty($sk['removal_due'])): ?>
        <form method="POST" style="display:inline">
          <?= csrf_field() ?>
          <input type="hidden" name="action" value="stick_delete">
          <input type="hidden" name="stick_id" value="<?= $sid ?>">
          <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="<?= t('Code (if asked)') ?>" style="max-width:150px">
          <button type="submit" class="btn btn-muted"><?= t('Remove for good') ?></button>
        </form>
        <?php endif; ?>
      </div>
      <?php endforeach; ?>
      <?php endif; ?>
    </div>
  </section>

  <!-- ===== Account: details, escrow state, deletion ===== -->
  <section class="tab-panel" data-tab-panel="account">
    <div class="panel">
      <div class="panel-title"><?= t('Account') ?></div>
      <div class="meta-row">
        <span class="meta-key"><?= t('Username') ?></span>
        <span class="meta-value"><?= htmlspecialchars($user['username'] ?? '') ?></span>
      </div>
      <div class="meta-row">
        <span class="meta-key"><?= t('Email') ?></span>
        <span class="meta-value"><?= htmlspecialchars($user['email'] ?? '') ?></span>
      </div>
      <div class="meta-row">
        <span class="meta-key"><?= t('Member since') ?></span>
        <span class="meta-value"><?= htmlspecialchars(t_date($user['created_at'] ?? null)) ?></span>
      </div>
      <div class="meta-row">
        <span class="meta-key"><?= t('Last login') ?></span>
        <span class="meta-value"><?= htmlspecialchars(t_date($user['last_login'] ?? null, true)) ?></span>
      </div>
    </div>

    <!-- Recovery and escrow. The operator controls this page too: the client's own check is the real one. -->
    <div class="panel<?= ($escrow_on || $escrow_alarm) ? ' danger-zone' : '' ?>">
      <div class="panel-title"><?= t('Recovery and escrow') ?></div>
      <?php if (!$escrow): ?>
      <p class="warn-text"><?= t('The escrow state could not be read.') ?></p>
      <?php else: ?>
      <p class="warn-text" style="margin-bottom:1rem"><?= $escrow_on
          ? t('<strong>Escrow is ON for you.</strong> Your organisation holds a sealed copy of your storage key, so its administrators can read your files.')
          : t('<strong>Escrow is OFF for you.</strong> No copy of your storage key is held by anyone else. Nothing is sealed for you without your consent in the app.') ?></p>
      <div class="meta-row">
        <span class="meta-key"><?= t('Server policy') ?></span>
        <span class="meta-value"><?= htmlspecialchars($escrow['recovery_policy']) ?></span>
      </div>
      <div class="meta-row">
        <span class="meta-key"><?= t('Organisation key') ?></span>
        <span class="meta-value"><code><?= htmlspecialchars($fingerprint($escrow['escrow_key_fingerprint'] ?? null)) ?></code></span>
      </div>
      <?php if ($escrow_on): ?>
      <div class="meta-row">
        <span class="meta-key"><?= t('Your copy sealed to') ?></span>
        <span class="meta-value"><code><?= htmlspecialchars($fingerprint($escrow['sealed_key_fingerprint'] ?? null)) ?></code>
          <?= isset($escrow['sealed_at']) ? htmlspecialchars(t_date($escrow['sealed_at'])) : '' ?></span>
      </div>
      <?php endif; ?>
      <div class="meta-row">
        <span class="meta-key"><?= t('Settings unchanged since') ?></span>
        <span class="meta-value"><?= isset($escrow['settings_changed_at']) ? htmlspecialchars(t_date($escrow['settings_changed_at'], true)) . ' UTC' : '–' ?></span>
      </div>
      <p class="warn-text" style="margin-top:1rem"><?= t('The app on your computer checks these against what it remembers on your stick and warns you if they change.') ?></p>
      <?php endif; ?>
    </div>

    <div class="panel danger-zone">
      <div class="panel-title"><?= t('Delete account') ?></div>
      <p class="warn-text"><?= t('Permanently deletes your account and all encrypted data after a waiting period, during which you can cancel. After that it is <strong>irreversible</strong>: your data cannot be recovered.') ?></p>
      <form method="POST" id="delete-form" style="margin-top:1rem">
        <?= csrf_field() ?>
        <input type="hidden" name="action" value="delete_account">
        <div class="btn-row">
          <?php if ($user['totp_enabled'] ?? false): ?>
          <input type="text" name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="<?= t('Code (if asked)') ?>"
                 style="max-width:170px">
          <?php endif; ?>
          <button type="submit" class="btn btn-danger"><?= t('Delete account and all data') ?></button>
        </div>
      </form>
    </div>
  </section>

</main>

<?= js_strings_tag() ?>
<?php if ($totp_setup): ?><script nonce="<?= htmlspecialchars(csp_nonce(), ENT_QUOTES) ?>" src="assets/qrcode.js"></script><?php endif; ?>
<script nonce="<?= htmlspecialchars(csp_nonce(), ENT_QUOTES) ?>">
var L = {};
try { L = JSON.parse(document.getElementById('i18n').textContent); } catch (e) { L = {}; }
function T(s) { return L[s] || s; }

// Sections: one at a time with scripts on (without them every section is shown, one after another).
// The section a form was posted from wins, then the link's #hash, then the overview.
(function () {
  var main = document.querySelector('main');
  var panels = document.querySelectorAll('[data-tab-panel]');
  var links = document.querySelectorAll('[data-tab-link]');
  function names() { return Array.prototype.map.call(panels, function (p) { return p.dataset.tabPanel; }); }
  function show(name, push) {
    if (names().indexOf(name) < 0) { name = 'overview'; }
    panels.forEach(function (p) { p.hidden = p.dataset.tabPanel !== name; });
    links.forEach(function (a) {
      if (a.dataset.tabLink === name) { a.setAttribute('aria-current', 'page'); } else { a.removeAttribute('aria-current'); }
    });
    if (push !== false && location.hash !== '#' + name) { history.replaceState(null, '', '#' + name); }
  }
  main.classList.add('js-tabs');
  show(main.dataset.tab || location.hash.slice(1) || 'overview');
  window.addEventListener('hashchange', function () { show(location.hash.slice(1), false); window.scrollTo(0, 0); });
})();

var deleteForm = document.getElementById('delete-form');
if (deleteForm) {
  deleteForm.addEventListener('submit', function (e) {
    if (!confirm(T('Are you absolutely sure? All your data will be deleted when the waiting period ends.'))) { e.preventDefault(); }
  });
}
// The authenticator app's QR code, drawn here from the otpauth:// address (nothing is sent anywhere)
var qrBox = document.getElementById('totp-qr');
if (qrBox && qrBox.dataset.uri && window.qrcode) {
  var qr = window.qrcode(0, 'M');
  qr.addData(qrBox.dataset.uri);
  qr.make();
  qrBox.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true });
}
document.querySelectorAll('[data-copy]').forEach(function (b) {
  b.addEventListener('click', function () {
    if (!navigator.clipboard) { return; }
    navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function () {
      var label = b.textContent; b.textContent = T('Copied');
      setTimeout(function () { b.textContent = label; }, 2000);
    });
  });
});
</script>
<?= $passkey_options ? passkey_script_tag() : '' ?>
<?= source_link() ?>
</body>
</html>
