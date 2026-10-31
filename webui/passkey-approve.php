<?php
// passkey-approve.php - Approves a sign-in of the cryptclient app with a passkey.
//
// A passkey only works on the web UI's own address, so the app cannot ask for one itself. Instead it
// checks the password with the API, then opens this page with the browser options in the URL fragment
// (the part after #, which the browser never sends to a server):
//     passkey-approve.php#<base64url of {"o": options, "p": port, "s": state, "u": username}>
// After the passkey, the browser posts the answer to http://127.0.0.1:<port>/callback, the app's own
// listener on the same computer. The app then finishes the sign-in with the API, using a session token
// that never leaves the app. A link someone else sends cannot steal a sign-in: the answer only ever goes
// to this computer, and it is useless without the app's session token.
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';

// Like send_security_headers(), but the one form may post to the app on this computer
header("Content-Security-Policy: default-src 'none'; "
     . "script-src 'nonce-" . csp_nonce() . "' 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; "
     . "connect-src 'none'; form-action http://127.0.0.1:*; base-uri 'none'; frame-ancestors 'none'");
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
?>
<!DOCTYPE html>
<html lang="<?= lang() ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= t('Approve sign-in') ?> – <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="stylesheet" href="assets/fonts/fonts.css">
<style>
  html { font-size: 112.5%; }
  :root { --bg:#0a0a0f; --surface:#12121a; --border:#1e1e2e; --accent:#00e5a0; --text:#e8e8f0; --muted:#a3a3bb; --error:#ff4d6d; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; padding:1rem; background:var(--bg); color:var(--text);
         font-family: 'DM Sans', system-ui, sans-serif; }
  .card { margin:auto; width:100%; max-width:30rem; padding:2rem; background:var(--surface); border:1px solid var(--border); }
  h1 { font-size:1.2rem; margin:0 0 1rem; }
  p { line-height:1.5; }
  .btn { width:100%; padding:.8rem; background:var(--accent); color:#000; border:0; font-size:1rem; cursor:pointer; }
  .btn:disabled { opacity:.5; cursor:default; }
  .hint { color:var(--muted); font-size:.9rem; margin-top:.8rem; }
  .alert { padding:.8rem; margin-bottom:1rem; border:1px solid var(--error); color:var(--error); }
  .user { font-family: 'Space Mono', monospace; }
</style>
</head>
<body>
<div class="card">
  <h1><?= t('Approve sign-in to the %s app', htmlspecialchars(APP_NAME)) ?></h1>
  <div class="alert" id="bad" hidden><?= t('This link is not complete. Start the sign-in again in the app.') ?></div>
  <div id="ok" hidden>
    <p><?= t('The app on this computer is signing in as %s. Approve only if you just started it yourself.', '<span class="user" id="user"></span>') ?></p>
    <button type="button" class="btn" data-passkey-start disabled><?= t('Approve with passkey') ?></button>
    <div class="hint" data-passkey-status><?= t('Face ID, fingerprint, a security key, or your phone (scan the QR code).') ?></div>
  </div>
  <script type="application/json" id="passkey-options" data-mode="get">{}</script>
  <form method="POST" data-passkey-form>
    <input type="hidden" name="state" value="">
    <input type="hidden" name="credential" value="">
  </form>
</div>
<script nonce="<?= htmlspecialchars(csp_nonce(), ENT_QUOTES) ?>">
(function () {
  'use strict';
  var d = null;
  try {
    var s = location.hash.slice(1).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) { s += '='; }
    d = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); })));
  } catch (e) { d = null; }
  var port = d && Number(d.p);
  if (!d || !d.o || typeof d.o.challenge !== 'string' || !Number.isInteger(port) || port < 1024 || port > 65535
      || typeof d.s !== 'string' || !/^[0-9a-f]{32,64}$/.test(d.s) || typeof d.u !== 'string') {
    document.getElementById('bad').hidden = false;
    return;
  }
  // Only ever to this computer, whatever the link says
  document.querySelector('form[data-passkey-form]').action = 'http://127.0.0.1:' + port + '/callback';
  document.querySelector('input[name=state]').value = d.s;
  document.getElementById('passkey-options').textContent = JSON.stringify(d.o);
  document.getElementById('user').textContent = d.u;
  document.getElementById('ok').hidden = false;
  document.querySelector('[data-passkey-start]').disabled = false;
  history.replaceState(null, '', location.pathname);   // keep the options out of the history
})();
</script>
<?= js_strings_tag() ?>
<script nonce="<?= htmlspecialchars(csp_nonce(), ENT_QUOTES) ?>" src="assets/passkey.js"></script>
</body>
</html>
