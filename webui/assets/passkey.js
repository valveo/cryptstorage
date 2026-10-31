/*
 * Passkeys (WebAuthn) in the web UI. The page puts the server's options in
 *   <script type="application/json" id="passkey-options" data-mode="get|create">…</script>
 * and a button [data-passkey-start]. A click asks the browser (Face ID, fingerprint, a security key,
 * or a phone through a QR code), then sends the answer in the hidden field "credential" of
 * form[data-passkey-form]. The options use base64url for binary fields, as py_webauthn writes them.
 */
(function () {
  'use strict';
  var data = document.getElementById('passkey-options');
  var button = document.querySelector('[data-passkey-start]');
  var form = document.querySelector('form[data-passkey-form]');
  var status = document.querySelector('[data-passkey-status]');
  if (!data || !button || !form) { return; }

  // Texts in the page's language (lang.php js_strings_tag); the English text is the fallback
  var L = {};
  try { L = JSON.parse(document.getElementById('i18n').textContent); } catch (e) { L = {}; }
  function T(s, a) { var r = L[s] || s; return a === undefined ? r : r.replace('%s', a); }

  function say(msg) { if (status) { status.textContent = msg; } }

  function fromB64url(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) { s += '='; }
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out.buffer;
  }

  function toB64url(buf) {
    if (!buf) { return null; }
    var bytes = new Uint8Array(buf), bin = '';
    for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function descriptors(list) {
    return (list || []).map(function (d) {
      var out = { type: d.type || 'public-key', id: fromB64url(d.id) };
      if (d.transports) { out.transports = d.transports; }
      return out;
    });
  }

  function answer(cred) {
    var r = cred.response, resp = { clientDataJSON: toB64url(r.clientDataJSON) };
    if (r.attestationObject) {
      resp.attestationObject = toB64url(r.attestationObject);
      if (r.getTransports) { resp.transports = r.getTransports(); }
    } else {
      resp.authenticatorData = toB64url(r.authenticatorData);
      resp.signature = toB64url(r.signature);
      resp.userHandle = toB64url(r.userHandle);
    }
    return {
      id: cred.id, rawId: toB64url(cred.rawId), type: cred.type, response: resp,
      authenticatorAttachment: cred.authenticatorAttachment || null,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    };
  }

  button.addEventListener('click', function () {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      say(T('This browser does not support passkeys. Use another way to sign in.'));
      return;
    }
    var o = JSON.parse(data.textContent), call;
    o.challenge = fromB64url(o.challenge);
    if (data.dataset.mode === 'create') {
      o.user.id = fromB64url(o.user.id);
      o.excludeCredentials = descriptors(o.excludeCredentials);
      call = navigator.credentials.create({ publicKey: o });
    } else {
      o.allowCredentials = descriptors(o.allowCredentials);
      call = navigator.credentials.get({ publicKey: o });
    }
    button.disabled = true;
    say(T('Follow the prompt of your browser or phone…'));
    call.then(function (cred) {
      form.querySelector('input[name=credential]').value = JSON.stringify(answer(cred));
      form.submit();
    }).catch(function (e) {
      button.disabled = false;
      say(e && e.name === 'NotAllowedError'
        ? T('Cancelled, timed out, or no passkey for this account here. Try again, or use another way.')
        : T('The passkey did not work (%s). Try again, or use another way.', e && e.name ? e.name : 'error'));
    });
  });
})();
