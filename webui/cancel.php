<?php
// cancel.php - Stop a waiting SSH key change or account deletion with the link from the e-mail.
// No sign-in: the token in the link is the proof. Opening the link only shows a button, so a mail
// scanner that follows links cannot cancel anything by itself.
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/api.php';

session_start_secure();

$token  = (string)($_POST['token'] ?? $_GET['token'] ?? '');
$token  = preg_match('/^[A-Za-z0-9._-]{1,128}$/', $token) ? $token : '';
$done   = '';
$error  = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_require();
    $res = (new ApiClient())->cancel_change($token);
    if (isset($res['message'])) {
        $done = $res['message'];
    } else {
        $error = $res['detail'] ?? $res['error'] ?? t('Could not cancel.');
    }
}
?>
<!DOCTYPE html>
<html lang="<?= lang() ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title><?= t('Cancel a change') ?> – <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="stylesheet" href="assets/fonts/fonts.css">
<style>
  html { font-size: 112.5%; }
  :root { --bg:#0a0a0f; --surface:#12121a; --border:#1e1e2e; --accent:#00e5a0; --text:#e8e8f0; --muted:#a3a3bb; --error:#ff4d6d; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; padding:1rem; background:var(--bg); color:var(--text);
         font-family: 'DM Sans', system-ui, sans-serif; }
  .card { margin:auto; width:100%; max-width:30rem; padding:2rem; background:var(--surface); border:1px solid var(--border); }
  h1 { font-size:1.2rem; margin:0 0 1rem; }
  .btn { margin-top:1.4rem; width:100%; padding:.8rem; background:var(--accent); color:#04130d; border:0; font-weight:600; cursor:pointer; }
  .alert { padding:.8rem; margin-bottom:1rem; border:1px solid var(--error); color:var(--error); }
  .ok { padding:.8rem; margin-bottom:1rem; border:1px solid var(--accent); color:var(--accent); }
  a { color:var(--muted); }
</style>
</head>
<body>
<div class="card">
  <h1><?= t('Cancel a change to your account') ?></h1>
  <?php if ($done): ?>
    <div class="ok"><?= htmlspecialchars($done) ?></div>
  <?php elseif ($token === ''): ?>
    <div class="alert"><?= t('This link is not complete. Open it again from the e-mail.') ?></div>
  <?php else: ?>
    <?php if ($error): ?><div class="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <p><?= t('Someone asked for a new USB stick key or for the deletion of your account. If it was not you, cancel it here, then change your password.') ?></p>
    <form method="POST">
      <?= csrf_field() ?>
      <input type="hidden" name="token" value="<?= htmlspecialchars($token, ENT_QUOTES) ?>">
      <button type="submit" class="btn"><?= t('Cancel the change') ?></button>
    </form>
  <?php endif; ?>
  <p><a href="index.php">← <?= t('Sign in') ?></a></p>
</div>
<?= source_link() ?>
</body>
</html>
