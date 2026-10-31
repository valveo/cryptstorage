<?php
// verify-email.php - Target of the link in the registration e-mail (api/email_verification.py).
// Confirming an address is harmless, so opening the link is enough.
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/api.php';

session_start_secure();

$token = (string)($_GET['token'] ?? '');
$ok    = '';
$error = '';
if (!preg_match('/^[A-Za-z0-9._-]{1,2048}$/', $token)) {
    $error = t('This link is not complete. Open it again from the e-mail.');
} else {
    $res = (new ApiClient())->verify_email($token);
    if (isset($res['message'])) {
        $ok = $res['message'];
    } else {
        $error = $res['detail'] ?? $res['error'] ?? t('Could not verify the address.');
    }
}
?>
<!DOCTYPE html>
<html lang="<?= lang() ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title><?= t('Verify e-mail') ?> – <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="stylesheet" href="assets/fonts/fonts.css">
<style>
  html { font-size: 112.5%; }
  :root { --bg:#0a0a0f; --surface:#12121a; --border:#1e1e2e; --accent:#00e5a0; --text:#e8e8f0; --muted:#a3a3bb; --error:#ff4d6d; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; padding:1rem; background:var(--bg); color:var(--text);
         font-family: 'DM Sans', system-ui, sans-serif; }
  .card { margin:auto; width:100%; max-width:30rem; padding:2rem; background:var(--surface); border:1px solid var(--border); }
  h1 { font-size:1.2rem; margin:0 0 1rem; }
  .alert { padding:.8rem; margin-bottom:1rem; border:1px solid var(--error); color:var(--error); }
  .ok { padding:.8rem; margin-bottom:1rem; border:1px solid var(--accent); color:var(--accent); }
  a { color:var(--muted); }
</style>
</head>
<body>
<div class="card">
  <h1><?= t('Verify your e-mail address') ?></h1>
  <?php if ($ok): ?><div class="ok"><?= htmlspecialchars($ok) ?></div><?php endif; ?>
  <?php if ($error): ?><div class="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <p><a href="index.php">→ <?= t('Sign in') ?></a></p>
</div>
<?= source_link() ?>
</body>
</html>
