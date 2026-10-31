<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/api.php';

session_start_secure();

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$error   = '';
$success = '';
if (isset($_GET['password_changed'])) { $success = t('Password changed. Please sign in again.'); }
if (isset($_GET['deleted']))          { $success = t('Your account and storage were deleted.'); }
$mode    = $_POST['mode'] ?? 'login'; // 'login' or 'register'
$need_totp = false;          // the password was right: show the second step
$passkey_options = null;
$web_passkey = null;         // sign-in with the passkey alone: its step


// The second step of a sign-in keeps the login key (derived in the browser, not the password itself)
// in the server-side session for a few minutes, so the passkey or the code needs no retyping.
const LOGIN2_SECONDS = 300;
function login2(): ?array {
    $s = $_SESSION['login2'] ?? null;
    if (!is_array($s) || time() - ($s['at'] ?? 0) > LOGIN2_SECONDS) {
        unset($_SESSION['login2']);
        return null;
    }
    return $s;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $api = new ApiClient();

    // Signed in by the app (`cryptclient web-login`): the link carries a one-time ticket after the
    // "#", which the browser never sends; the script below posts it here, so it stays out of the
    // address the server and its access log see.
    if ($mode === 'ticket' && is_string($_POST['ticket'] ?? null)) {
        $res = $api->web_ticket_redeem(substr($_POST['ticket'], 0, 2048));
        $me = isset($res['access_token']) ? (new ApiClient($res['access_token']))->me() : [];
        if (isset($me['username'])) {
            save_session($res['access_token'], $me['username']);
            header('Location: dashboard.php');
            exit;
        }
        $error = is_string($res['detail'] ?? null) ? $res['detail'] : t('This sign-in link did not work. Start again in the app.');
        $mode = 'login';
    } elseif ($mode === 'pk_web_begin') {
        // Sign-in with the passkey alone: no password on this page at all
        $username = trim($_POST['username'] ?? '');
        unset($_SESSION['login2'], $_SESSION['pk_login'], $_SESSION['pk_web']);
        $res = $username !== '' ? $api->web_passkey_begin($username) : ['detail' => t('Enter your username.')];
        if (isset($res['options'], $res['session'])) {
            $_SESSION['pk_web'] = ['session' => $res['session'], 'username' => $username, 'at' => time()];
            $web_passkey = ['username' => $username, 'options' => $res['options']];
        } else {
            $error = is_string($res['detail'] ?? null) ? $res['detail'] : ($res['error'] ?? t('Passkey sign-in is not available.'));
        }
        $mode = 'login';

    } elseif ($mode === 'pk_web') {
        $pk = $_SESSION['pk_web'] ?? null;
        unset($_SESSION['pk_web']);
        $credential = posted_credential();
        $res = ($pk && $credential && time() - ($pk['at'] ?? 0) <= LOGIN2_SECONDS)
            ? $api->web_passkey_finish($pk['session'], $credential)
            : ['detail' => t('The passkey sign-in expired. Try again.')];
        if (isset($res['access_token'])) {
            save_session($res['access_token'], $pk['username']);
            header('Location: dashboard.php');
            exit;
        }
        $error = is_string($res['detail'] ?? null) ? t('Passkey sign-in failed:') . ' ' . $res['detail'] : t('Passkey sign-in failed.');
        $mode = 'login';

    } elseif ($mode === 'login') {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        unset($_SESSION['login2'], $_SESSION['pk_login']);

        $res = login_key_ok($password) ? $api->login($username, $password) : ['detail' => t(LOGIN_KEY_ERROR)];
        if (isset($res['access_token'])) {
            save_session($res['access_token'], $username);
            header('Location: dashboard.php');
            exit;
        } elseif (($res['detail'] ?? '') === 'TOTP_REQUIRED') {
            // The password was right: the second step asks only for the passkey or the code
            $_SESSION['login2'] = ['username' => $username, 'key' => $password, 'at' => time()];
            $need_totp = true;
        } else {
            $error = $res['detail'] ?? $res['error'] ?? t('Login failed.');
        }

    } elseif ($mode === 'totp') {
        $step = login2();
        if (!$step) {
            $error = t('The sign-in expired. Sign in again.');
            $mode = 'login';
        } else {
            $res = $api->login($step['username'], $step['key'], trim($_POST['totp_code'] ?? ''));
            if (isset($res['access_token'])) {
                unset($_SESSION['login2'], $_SESSION['pk_login']);
                save_session($res['access_token'], $step['username']);
                header('Location: dashboard.php');
                exit;
            }
            $error = is_string($res['detail'] ?? null) ? $res['detail'] : ($res['error'] ?? t('Sign-in failed.'));
            $need_totp = true;
        }

    } elseif ($mode === 'passkey') {
        $pk = $_SESSION['pk_login'] ?? null;
        unset($_SESSION['pk_login']);
        $credential = posted_credential();
        $res = ($pk && $credential) ? $api->passkey_finish($pk['session'], $credential)
                                    : ['detail' => t('The passkey sign-in expired. Sign in again.')];
        if (isset($res['access_token'])) {
            unset($_SESSION['login2']);
            save_session($res['access_token'], $pk['username']);
            header('Location: dashboard.php');
            exit;
        }
        $error = is_string($res['detail'] ?? null) ? $res['detail'] : ($res['error'] ?? t('Passkey sign-in failed.'));
        $need_totp = login2() !== null;
        $mode = 'login';

    } elseif ($mode === 'register') {
        $username  = trim($_POST['username'] ?? '');
        $email     = trim($_POST['email'] ?? '');
        $password  = $_POST['password'] ?? '';

        $res = login_key_ok($password)
            ? $api->register($username, $email, $password)
            : ['detail' => t(LOGIN_KEY_ERROR)];

        if (isset($res['message']) && !isset($res['error']) && !isset($res['detail'])) {
            $success = $res['message'] ?? t('Account created. Check your e-mail to verify your address, then sign in.');
            $success .= ' ' . t('Next: install the CryptStorage app and run cryptclient setup.');
            $mode    = 'login';
        } else {
            // FastAPI validation errors come as detail array
            if (is_array($res['detail'] ?? null)) {
                $msgs  = array_map(fn($e) => $e['msg'] ?? '', $res['detail']);
                $error = implode(' ', $msgs);
            } else {
                $error = $res['detail'] ?? $res['error'] ?? t('Registration failed.');
            }
        }
    }
}
// A failed password sign-in shows its form again (it is folded away otherwise)
$pw_tried = $error !== '' && ($_POST['mode'] ?? '') === 'login';
// Second step: offer the passkey when the account has one (the password was right, so this reveals nothing)
if ($need_totp && ($step = login2())) {
    $pk = (new ApiClient())->passkey_begin($step['username'], $step['key']);
    if (isset($pk['options'], $pk['session'])) {
        $_SESSION['pk_login'] = ['session' => $pk['session'], 'username' => $step['username']];
        $passkey_options = $pk['options'];
    }
} elseif ($need_totp) {
    $need_totp = false;
    $error = $error ?: t('The sign-in expired. Sign in again.');
}
?>
<!DOCTYPE html>
<html lang="<?= lang() ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= APP_NAME ?></title>
<link rel="stylesheet" href="assets/fonts/fonts.css">
<style>
  html { font-size: 112.5%; }
  :root {
    --bg:       #0a0a0f;
    --surface:  #111118;
    --border:   #1e1e2e;
    --accent:   #00e5a0;
    --accent2:  #005c3f;
    --text:     #e8e8f0;
    --muted:    #a3a3bb;
    --error:    #ff4d6d;
    --success:  #00e5a0;
    --mono:     'Space Mono', monospace;
    --sans:     'DM Sans', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    display: flex;
    /* the card centres itself with margin: auto, so a card taller than a phone screen still scrolls */
    padding: 1rem 1rem 2.5rem;
    overflow-x: hidden;
    position: relative;
  }

  /* Grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(var(--border) 1px, transparent 1px),
      linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 40px 40px;
    opacity: 0.4;
    pointer-events: none;
  }

  /* Glow orb */
  body::after {
    content: '';
    position: fixed;
    width: 600px;
    height: 600px;
    background: radial-gradient(circle, rgba(0,229,160,0.07) 0%, transparent 70%);
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    pointer-events: none;
  }

  .card {
    position: relative;
    z-index: 1;
    background: var(--surface);
    border: 1px solid var(--border);
    width: 100%;
    max-width: 420px;
    margin: auto;
    padding: 2.5rem;
    animation: fadeUp 0.5s ease both;
  }

  @media (max-width: 480px) {
    .card { padding: 1.5rem; }
  }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(20px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .logo {
    font-family: var(--mono);
    font-size: 1rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: 2rem;
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .logo-icon {
    width: 28px;
    height: 28px;
    border: 2px solid var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.82rem;
  }

  .tabs {
    display: flex;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
    gap: 0;
  }

  .tab {
    flex: 1;
    background: none;
    border: none;
    padding: 0.75rem;
    font-family: var(--mono);
    font-size: 0.82rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    cursor: pointer;
    transition: color 0.2s;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }

  .tab.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
  }

  .tab:hover:not(.active) { color: var(--text); }

  .field {
    margin-bottom: 1.25rem;
  }

  label {
    display: block;
    font-family: var(--mono);
    font-size: 0.8rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.5rem;
  }

  input, textarea {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: var(--sans);
    font-size: 0.9rem;
    padding: 0.65rem 0.85rem;
    outline: none;
    transition: border-color 0.2s;
    resize: vertical;
  }

  input:focus, textarea:focus {
    border-color: var(--accent);
  }

  textarea {
    font-family: var(--mono);
    font-size: 0.8rem;
    min-height: 72px;
  }

  .hint {
    font-size: 0.8rem;
    color: var(--muted);
    margin-top: 0.35rem;
  }

  .btn {
    width: 100%;
    background: var(--accent);
    color: #000;
    border: none;
    padding: 0.8rem;
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    cursor: pointer;
    transition: opacity 0.2s, transform 0.1s;
    margin-top: 0.5rem;
  }

  .btn:hover   { opacity: 0.88; }
  .btn:active  { transform: scale(0.99); }
  .btn-secondary { background: transparent; color: var(--accent); border: 1px solid var(--accent2); }

  .step-who { margin-bottom: 1.25rem; color: var(--muted); }
  .step-who strong { color: var(--text); }
  .or { display: flex; align-items: center; gap: 0.75rem; margin: 1.25rem 0 0.5rem; color: var(--muted);
        font-family: var(--mono); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.15em; }
  .or::before, .or::after { content: ''; flex: 1; border-top: 1px solid var(--border); }

  .alert {
    padding: 0.75rem 1rem;
    font-size: 0.82rem;
    margin-bottom: 1.25rem;
    border-left: 3px solid;
  }

  .alert-error   { border-color: var(--error);   background: rgba(255,77,109,0.08); color: var(--error); }
  .alert-success { border-color: var(--success); background: rgba(0,229,160,0.08);  color: var(--success); }
  .recovery { margin: 1rem 0; padding: 1rem; border: 1px solid var(--warn, #ffb020); background: rgba(255,176,32,0.07); }
  .recovery strong { display: block; margin-bottom: .5rem; }
  .recovery code { display: block; font-size: 1.1rem; letter-spacing: .08em; padding: .6rem; margin: .5rem 0;
                   background: rgba(0,0,0,0.35); user-select: all; word-break: break-all; }
  .recovery p { margin: .4rem 0 0; font-size: .85rem; opacity: .85; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">⬡</div>
    <?= htmlspecialchars(APP_NAME) ?>
  </div>

  <?= demo_notice() ?>
  <?= download_link() ?>
  <?php if ($error):   ?><div class="alert alert-error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <?php if ($success): ?><div class="alert alert-success"><?= htmlspecialchars($success) ?></div><?php endif; ?>
  <?php if ($web_passkey): ?>
  <!-- Sign-in with the passkey alone -->
  <p class="step-who"><?= t('Signing in as %s', '<strong>' . htmlspecialchars($web_passkey['username']) . '</strong>') ?></p>
  <div class="field">
    <button type="button" class="btn" data-passkey-start autofocus><?= t('Use passkey') ?></button>
    <div class="hint" data-passkey-status><?= t('Fingerprint, face, PIN, security key or your phone.') ?></div>
    <?= passkey_options_tag($web_passkey['options'], 'get') ?>
    <form method="POST" data-passkey-form>
      <?= csrf_field() ?>
      <input type="hidden" name="mode" value="pk_web">
      <input type="hidden" name="credential" value="">
    </form>
  </div>
  <div class="hint" style="margin-top:1rem"><a href="index.php" style="color:var(--muted)"><?= t('Start over') ?></a></div>
  <?php elseif ($need_totp): ?>
  <!-- Second step: the password was right; now the passkey, or the code as the fallback -->
  <p class="step-who"><?= t('Signing in as %s', '<strong>' . htmlspecialchars(login2()['username'] ?? '') . '</strong>') ?></p>
  <?php if ($passkey_options): ?>
  <div class="field">
    <button type="button" class="btn" data-passkey-start><?= t('Use passkey') ?></button>
    <div class="hint" data-passkey-status><?= t('Fingerprint, face, PIN, security key or your phone.') ?></div>
    <?= passkey_options_tag($passkey_options, 'get') ?>
    <form method="POST" data-passkey-form>
      <?= csrf_field() ?>
      <input type="hidden" name="mode" value="passkey">
      <input type="hidden" name="credential" value="">
    </form>
  </div>
  <div class="or"><span><?= t('or') ?></span></div>
  <?php endif; ?>
  <form method="POST">
    <?= csrf_field() ?>
    <input type="hidden" name="mode" value="totp">
    <div class="field">
      <label><?= t('Code from your authenticator app') ?> <span style="color:var(--muted)"><?= t('(or a backup code)') ?></span></label>
      <input type="text" name="totp_code" inputmode="numeric" autocomplete="one-time-code" maxlength="32" required
             <?= $passkey_options ? '' : 'autofocus' ?>>
    </div>
    <button type="submit" class="btn <?= $passkey_options ? 'btn-secondary' : '' ?>"><?= t('Verify →') ?></button>
  </form>
  <div class="hint" style="margin-top:1rem"><a href="index.php" style="color:var(--muted)"><?= t('Start over') ?></a></div>
  <?php else: ?>
  <div class="tabs">
    <button class="tab <?= $mode === 'login'    ? 'active' : '' ?>" data-mode="login"><?= t('Sign in') ?></button>
    <button class="tab <?= $mode === 'register' ? 'active' : '' ?>" data-mode="register"><?= t('Register') ?></button>
  </div>

  <!-- Without the password: this page comes from the server, so a password typed here is only as
       safe as the server. A passkey alone, or the app, never puts it into the page. -->
  <div id="signin-safe" style="<?= $mode === 'login' ? '' : 'display:none' ?>">
    <form method="POST">
      <?= csrf_field() ?>
      <input type="hidden" name="mode" value="pk_web_begin">
      <div class="field">
        <label><?= t('Username') ?></label>
        <input type="text" name="username" required autocomplete="username webauthn"
               value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
      </div>
      <button type="submit" class="btn"><?= t('Sign in with passkey →') ?></button>
    </form>
    <div class="hint" style="margin-top:.75rem"><?= t('No passkey yet? Run <code>cryptclient web-login</code> on your computer: the app signs you in here without your password.') ?></div>
    <details id="pw-login" style="margin-top:1.25rem"<?= $pw_tried ? ' open' : '' ?>>
      <summary class="hint" style="cursor:pointer"><?= t('Sign in with your password instead') ?></summary>
      <div class="alert alert-error" style="margin-top:.75rem"><?= t('Typing your password here trusts this server: it also sends this page, and a compromised server could read the password and open your files. Prefer a passkey or the app.') ?></div>
    </details>
  </div>
  <div id="reg-warn" class="alert alert-error" style="<?= $mode === 'register' ? '' : 'display:none' ?>"><?= t('Creating the account here sends your password through a page this server controls. If you do not fully trust the server, create it with the app instead (<code>cryptclient setup</code>).') ?></div>

  <form method="POST" id="form" data-derive style="<?= $mode === 'login' && !$pw_tried ? 'display:none' : '' ?>">
    <?= csrf_field() ?>
    <input type="hidden" name="mode" id="mode-input" value="<?= htmlspecialchars($mode) ?>">

    <div class="field">
      <label><?= t('Username') ?></label>
      <input type="text" name="username" required autocomplete="username"
             value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
    </div>

    <div class="field" id="field-email" style="<?= $mode === 'login' ? 'display:none' : '' ?>">
      <label><?= t('Email') ?></label>
      <input type="email" name="email" autocomplete="email"
             value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
    </div>

    <div class="field">
      <label><?= t('Password') ?></label>
      <input type="password" name="password" required autocomplete="current-password"
             data-derive-pw data-min="<?= $mode === 'register' ? '12' : '0' ?>">
      <div class="hint" id="pw-hint" style="<?= $mode === 'login' ? 'display:none' : '' ?>">
        <?= t('Minimum 12 characters. The app gives you a recovery code when it sets up your storage: keep it, it is the only way back if you forget your password.') ?>
      </div>
    </div>

    <div class="field" id="field-pw2" style="<?= $mode === 'login' ? 'display:none' : '' ?>">
      <label><?= t('Confirm password') ?></label>
      <input type="password" name="password2" autocomplete="new-password">
      <div class="hint"><?= t('Your files are encrypted with this password. We cannot reset it for you: if you forget it, only the recovery code from the app brings your files back.') ?></div>
    </div>

    <button type="submit" class="btn" id="submit-btn">
      <?= $mode === 'login' ? t('Sign in →') : t('Create account →') ?>
    </button>
  </form>
  <div class="hint" style="margin-top:1rem"><a href="recover.php" style="color:var(--muted)"><?= t('Forgot your password?') ?></a></div>
  <?php endif; ?>
</div>

<?= js_strings_tag() ?>
<form method="POST" id="ticket-form" hidden>
  <?= csrf_field() ?>
  <input type="hidden" name="mode" value="ticket">
  <input type="hidden" name="ticket" id="ticket-input">
</form>
<script nonce="<?= htmlspecialchars(csp_nonce(), ENT_QUOTES) ?>">
var L = {};
try { L = JSON.parse(document.getElementById('i18n').textContent); } catch (e) { L = {}; }
function T(s) { return L[s] || s; }
(function () {
  // A sign-in handed over by the app: index.php#ticket=... (the part after # never reaches the server).
  // Also on a hash change: opening the link on an already open sign-in page does not reload it.
  function redeem() {
    var m = /^#ticket=([A-Za-z0-9._-]{1,2048})$/.exec(location.hash);
    if (!m) { return; }
    history.replaceState(null, '', location.pathname + location.search);
    document.getElementById('ticket-input').value = m[1];
    document.getElementById('ticket-form').submit();
  }
  window.addEventListener('hashchange', redeem);
  redeem();
})();
function setMode(m) {
  document.getElementById('mode-input').value = m;
  var safe = document.getElementById('signin-safe'), pwLogin = document.getElementById('pw-login');
  document.getElementById('reg-warn').style.display = m === 'register' ? '' : 'none';
  if (safe) { safe.style.display = m === 'login' ? '' : 'none'; }
  document.getElementById('form').style.display = (m === 'register' || (pwLogin && pwLogin.open)) ? '' : 'none';
  document.getElementById('field-email').style.display  = m === 'register' ? '' : 'none';
  var pw2 = document.getElementById('field-pw2');
  if (pw2) { pw2.style.display = m === 'register' ? '' : 'none'; }
  var pw = document.querySelector('input[data-derive-pw]');
  if (pw) { pw.dataset.min = m === 'register' ? '12' : '0'; }
  document.getElementById('pw-hint').style.display      = m === 'register' ? '' : 'none';
  document.getElementById('submit-btn').textContent     = m === 'login' ? T('Sign in →') : T('Create account →');
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', (i === 0 && m === 'login') || (i === 1 && m === 'register'));
  });
}
document.querySelectorAll('[data-mode]').forEach(function (b) {
  b.addEventListener('click', function () { setMode(b.dataset.mode); });
});
var pwDetails = document.getElementById('pw-login');
if (pwDetails) {
  pwDetails.addEventListener('toggle', function () {
    document.getElementById('form').style.display = pwDetails.open ? '' : 'none';
  });
}
</script>
<?= derive_script_tag() ?>
<?= ($passkey_options || $web_passkey) ? passkey_script_tag() : '' ?>
<?= source_link() ?>
</body>
</html>
