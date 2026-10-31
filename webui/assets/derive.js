/*
 * Derives the login key in the browser (docs/design-e2ee.md, section 5a), so the password itself never
 * reaches the server. Must produce exactly what cryptclient/e2ee/keys.go produces:
 *
 *   root    = Argon2id(password, SHA-256("secdisk/kdf/v1\0" + lower(username)), t=3, m=64 MiB, p=4) -> 32 bytes
 *   authKey = HKDF-SHA256(root, salt none, info "secdisk/auth/v1") -> hex
 * The "secdisk/" labels are fixed protocol constants from the product's earlier name: they must match the
 * client's (cryptclient/e2ee/keys.go), and changing them would lock every user out.
 *
 * Needs hash-wasm (assets/argon2.umd.min.js) and WebCrypto.
 */
(function (root) {
  'use strict';
  var enc = new TextEncoder();

  function hex(bytes) {
    return Array.prototype.map.call(bytes, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  async function authKey(username, password) {
    var hw = root.hashwasm;
    var salt = new Uint8Array(await root.crypto.subtle.digest('SHA-256',
      enc.encode('secdisk/kdf/v1\u0000' + username.trim().toLowerCase())));
    var rootKey = await hw.argon2id({
      password: password, salt: salt, parallelism: 4, iterations: 3,
      memorySize: 64 * 1024, hashLength: 32, outputType: 'binary'
    });
    var k = await root.crypto.subtle.importKey('raw', rootKey, 'HKDF', false, ['deriveBits']);
    var bits = await root.crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('secdisk/auth/v1') }, k, 256);
    rootKey.fill(0);
    return hex(new Uint8Array(bits));
  }

  root.cryptstorageDerive = { authKey: authKey };

  // Forms marked data-derive: replace every input[data-derive-pw] by its derived key before sending.
  if (typeof document === 'undefined') { return; }
  // Texts in the page's language (lang.php js_strings_tag); the English text is the fallback
  var L = {};
  try { L = JSON.parse(document.getElementById('i18n').textContent); } catch (e) { L = {}; }
  function T(s, a) { var r = L[s] || s; return a === undefined ? r : r.replace('%s', a); }
  document.querySelectorAll('form[data-derive]').forEach(function (form) {
    form.addEventListener('submit', function (ev) {
      if (ev.defaultPrevented || form.dataset.derived === '1') { return; }
      ev.preventDefault();
      var btn = form.querySelector('button[type=submit]');
      var label = btn ? btn.textContent : '';
      var nameInput = form.querySelector('[name=username]');
      var username = form.dataset.username || (nameInput ? nameInput.value : '');
      if (btn) { btn.disabled = true; btn.textContent = T('Preparing your password securely…'); }
      var fields = Array.prototype.slice.call(form.querySelectorAll('input[data-derive-pw]'));
      var fail = function (msg) {
        if (btn) { btn.disabled = false; btn.textContent = label; }
        alert(msg);
      };
      // The server only ever sees the derived key, so it cannot check the password: do it here.
      for (var i = 0; i < fields.length; i++) {
        var min = parseInt(fields[i].dataset.min || '0', 10);
        if (fields[i].value.length < min) { return fail(T('The password must be at least %s characters.', min)); }
      }
      var again = form.querySelector('input[name=password2]');
      if (again && again.offsetParent !== null && fields[0] && again.value !== fields[0].value) {
        return fail(T('The two passwords do not match.'));
      }
      if (again) { again.value = ''; }
      Promise.all(fields.map(function (f) { return authKey(username, f.value); }))
        .then(function (keys) {
          fields.forEach(function (f, i) { f.value = keys[i]; });
          form.dataset.derived = '1';
          form.submit();
        })
        .catch(function () {
          // Never fall back to sending the real password
          fields.forEach(function (f) { f.value = ''; });
          if (btn) { btn.disabled = false; btn.textContent = label; }
          alert(T('This browser cannot prepare your password securely. Use a current browser.'));
        });
    });
  });
})(typeof window !== 'undefined' ? window : globalThis);
