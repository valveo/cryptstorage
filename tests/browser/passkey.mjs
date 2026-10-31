// Browser test of the passkey flow in the web UI, with Chromium's virtual authenticator (CDP).
// Run through tests/browser/run.sh, which starts the API and the web UI.
import { createRequire } from 'node:module';
const { chromium } = createRequire(import.meta.url)('playwright');   // resolved through NODE_PATH
import { execFileSync, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const WEB = process.env.WEB_URL;
const USER = 'pkbrowser';
const PASSWORD = 'a long enough browser test password';
const code = (kind) => execFileSync(process.env.PYTHON, [new URL('./codes.py', import.meta.url).pathname, kind, USER]).toString().trim();

function check(cond, what) { if (!cond) { throw new Error('FAILED: ' + what); } console.log('ok -', what); }

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
page.on('console', (m) => { if (m.type() === 'error') console.log('console:', m.text()); });
page.on('pageerror', (e) => console.log('page error:', e.message));
page.on('requestfailed', (r) => console.log('request failed:', r.url(), r.failure()?.errorText));
page.on('dialog', (d) => { console.log('dialog:', d.message()); d.dismiss(); });
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
  protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
  isUserVerified: true, automaticPresenceSimulation: true } });

async function signIn(withCode) {
  await page.goto(WEB + '/index.php');
  // the password form is folded away: typing the password there trusts the server
  await page.click('#pw-login summary');
  await page.fill('#form input[name=username]', USER);
  await page.fill('input[name=password]', PASSWORD);
  // the page derives the login key before it posts the form, which can take seconds on a slow machine:
  // wait for the navigation the post makes, not for the load state the page is already in
  await Promise.all([page.waitForNavigation({ timeout: 60000 }), page.click('#submit-btn')]);
  await page.waitForLoadState('networkidle');
  if (withCode) {
    // second step: the password is not asked again
    check(!(await page.isVisible('input[name=password]')), 'second step asks only for the passkey or the code');
    await page.fill('input[name=totp_code]', code('totp'));
    await Promise.all([page.waitForNavigation(), page.click('form:has(input[value=totp]) button')]);
  }
}

try {
  // register through the web UI (the browser derives the login key)
  await page.goto(WEB + '/index.php');
  await page.click('[data-mode=register]');
  await page.fill('#form input[name=username]', USER);
  await page.fill('input[name=email]', USER + '@example.com');
  await page.fill('input[name=password]', PASSWORD);
  await page.fill('input[name=password2]', PASSWORD);
  await page.click('#submit-btn');
  await page.waitForSelector('.alert-success');

  // first sign-in: the server requires two-factor, so only its setup is open
  await signIn(false);
  check(/\/dashboard\.php(#\w*)?$/.test(page.url()), 'signed in with the password, setup required');
  check(!(await page.isVisible('input[type=password]')), 'the dashboard never asks for the password');
  await Promise.all([page.waitForNavigation(), page.click('form:has(input[value=totp_setup]) button')]);
  check(await page.isVisible('#totp-qr svg'), 'the authenticator app setup shows a QR code');
  await page.fill('input[name=code]', code('totp'));
  await page.fill('input[name=email_code]', code('enrol'));
  await Promise.all([page.waitForNavigation(), page.click('form:has(input[value=totp_enable]) button')]);
  check(await page.isVisible('text=Save your backup codes now'), 'authenticator app turned on');

  // add a passkey
  await page.goto(WEB + '/dashboard.php#signin');
  const add = 'form:has(input[value=passkey_begin])';
  await page.fill(add + ' input[name=name]', 'Test laptop');
  await page.fill(add + ' input[name=code]', code('totp'));
  await Promise.all([page.waitForNavigation(), page.click(add + ' button')]);
  await Promise.all([page.waitForNavigation(), page.click('[data-passkey-start]')]);
  check(await page.isVisible('text=Passkey added'), 'passkey created with the virtual authenticator');
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  check(credentials.length === 1 && credentials[0].rpId === 'localhost', 'credential bound to the RP ID');

  // sign out, sign in with the password and the passkey instead of a code
  await page.goto(WEB + '/logout.php');
  await signIn(false);
  check(await page.isVisible('[data-passkey-start]'), 'passkey offered after the password');
  await Promise.all([page.waitForNavigation(), page.click('[data-passkey-start]')]);
  check(/\/dashboard\.php(#\w*)?$/.test(page.url()), 'signed in with the passkey');
  await page.goto(WEB + '/dashboard.php#signin');
  check(await page.isVisible('text=Test laptop'), 'passkey listed on the dashboard');

  // the app (cryptclient) signs in with the passkey through the approve page and its 127.0.0.1 listener
  const app = spawn(process.env.CLI_APP, [], { env: { ...process.env, API_URL: process.env.API_URL,
    CRYPTSTORAGE_USER: USER, CRYPTSTORAGE_PASSWORD: PASSWORD }, stdio: ['ignore', 'pipe', 'inherit'] });
  const appDone = new Promise((resolve) => app.on('exit', resolve));
  const lines = [];
  const opened = new Promise((resolve) => createInterface({ input: app.stdout }).on('line', (l) => {
    lines.push(l); console.log('app:', l);
    if (l.startsWith('OPEN ')) { resolve(l.slice(5)); }
  }));
  const approve = await Promise.race([opened, appDone.then(() => null)]);
  check(approve && approve.includes('/passkey-approve.php#'), 'the app asks the browser to approve');
  await page.goto(approve);
  check(await page.isVisible('text=' + USER), 'the approve page names the account');
  await Promise.all([page.waitForNavigation(), page.click('[data-passkey-start]')]);
  check(page.url().startsWith('http://127.0.0.1:'), 'the answer went only to the app on this computer');
  check(await page.isVisible('text=Signed in'), 'the app reports the sign-in to the browser');
  check(await appDone === 0 && lines.includes('SIGNED IN'), 'the app is signed in with the passkey');

  // the app hands its sign-in to the web UI: no password typed into the page
  const web = lines.find((l) => l.startsWith('WEB '));
  check(web && web.includes('/index.php#ticket='), 'the app gives a web sign-in link (ticket after #)');
  await page.goto(WEB + '/logout.php');
  await page.goto(web.slice(4));
  await page.waitForURL(/dashboard\.php$/, { timeout: 10000 }).catch(() => {});
  check(/\/dashboard\.php(#\w*)?$/.test(page.url()), 'signed in to the web UI by the app');
  await page.goto(WEB + '/logout.php');
  await page.goto(web.slice(4));
  await page.waitForSelector('text=invalid, used or expired', { timeout: 10000 }).catch(() => {});
  check(await page.isVisible('text=invalid, used or expired'), 'the link works once');

  // the passkey alone signs in to the web UI
  await page.goto(WEB + '/logout.php');
  await page.goto(WEB + '/index.php');
  await page.fill('#signin-safe input[name=username]', USER);
  await Promise.all([page.waitForNavigation(), page.click('#signin-safe button')]);
  await Promise.all([page.waitForNavigation(), page.click('[data-passkey-start]')]);
  check(/\/dashboard\.php(#\w*)?$/.test(page.url()), 'signed in with the passkey alone');
  // and confirms a sensitive action without the password
  await page.goto(WEB + '/dashboard.php#signin');
  const remove = 'form:has(input[value=passkey_delete])';
  await Promise.all([page.waitForNavigation(), page.click(remove + ' button')]);
  check(await page.isVisible('text=Passkey removed'), 'a recent passkey sign-in confirms without the password');

  // a link without the app's options does nothing
  await page.goto(WEB + '/passkey-approve.php#bm90IGpzb24');
  check(await page.isVisible('text=This link is not complete'), 'a broken approve link is refused');

  // the code still works as the fallback
  await page.goto(WEB + '/logout.php');
  await signIn(true);
  check(/\/dashboard\.php(#\w*)?$/.test(page.url()), 'signed in with the authenticator app code');
  console.log('ALL OK');
} catch (e) {
  console.error(e.message);
  console.error('page:', page.url(), (await page.textContent('body')).slice(0, 1500));
  process.exitCode = 1;
} finally {
  await browser.close();
}
