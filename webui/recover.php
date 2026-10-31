<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/api.php';

session_start_secure();

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

?>
<!DOCTYPE html>
<html lang="<?= lang() ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= t('Recover account') ?> – <?= htmlspecialchars(APP_NAME) ?></title>
<link rel="stylesheet" href="assets/fonts/fonts.css">
<style>
  html { font-size: 112.5%; }
  :root { --bg:#0a0a0f; --surface:#12121a; --border:#1e1e2e; --accent:#00e5a0; --text:#e8e8f0; --muted:#a3a3bb; --error:#ff4d6d; --warn:#ffb020; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; padding:1rem; background:var(--bg); color:var(--text);
         font-family: 'DM Sans', system-ui, sans-serif; }
  .card { margin:auto; width:100%; max-width:440px; padding:2.5rem; background:var(--surface); border:1px solid var(--border); }
  h1 { font-size:1.2rem; margin:0 0 1rem; }
  label { display:block; font-size:.85rem; color:var(--muted); margin:1rem 0 .3rem; }
  input { width:100%; padding:.7rem; background:#0a0a0f; border:1px solid var(--border); color:var(--text); font:inherit; }
  .btn { margin-top:1.4rem; width:100%; padding:.8rem; background:var(--accent); color:#04130d; border:0; font-weight:600; cursor:pointer; }
  .alert { padding:.8rem; margin-bottom:1rem; border:1px solid var(--error); color:var(--error); }
  .hint { font-size:.85rem; color:var(--muted); margin-top:1rem; }
  a { color:var(--muted); }
  .recovery { margin:1rem 0; padding:1rem; border:1px solid var(--warn); background:rgba(255,176,32,0.07); }
  .recovery code { display:block; font-size:1.1rem; letter-spacing:.08em; padding:.6rem; margin:.5rem 0; background:rgba(0,0,0,0.35); user-select:all; word-break:break-all; }
</style>
</head>
<body>
<div class="card" style="max-width:30rem;padding:2rem">
  <h1 style="margin-top:0"><?= t('Forgot your password?') ?></h1>
  <p><?= t('Your files are encrypted on your own computer, so the password cannot be reset here: the server never has it.') ?></p>
  <p><?= t('Open the CryptStorage app and run <code>cryptclient recover</code>. It asks for the <strong>recovery code</strong> you wrote down when you set up your storage, and lets you choose a new password. Your files stay intact.') ?></p>
  <p><?= t('If you never wrote the code down and your organisation keeps a recovery copy, ask your administrator.') ?></p>
  <p><a href="index.php">← <?= t('Back to sign in') ?></a></p>
</div>
<?= source_link() ?>
</body>
</html>
