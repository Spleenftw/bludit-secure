'use strict';
(() => {
  const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const status = document.getElementById('status');
  for (const button of document.querySelectorAll('[data-key]')) {
    const verify = async () => {
      const box = button.closest('.webauthn');
      const create = button.dataset.key === 'create';
      const kind = create ? 'create' : 'get';
      const request = async (phase, fields = {}) => {
        const url = new URL(box.dataset.base);
        url.searchParams.set('bs', `key-${kind}-${phase}`);
        const response = await fetch(url, {method: 'POST', credentials: 'same-origin', body: new URLSearchParams({secureCsrf: box.dataset.csrf, ...fields})});
        const result = await response.json();
        if (!response.ok || result.error) throw new Error(result.error || 'Verification failed.');
        return result;
      };
      button.disabled = true;
      try {
        if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('This browser does not support passkeys.');
        const args = await request('options');
        args.publicKey.challenge = decode(args.publicKey.challenge);
        if (args.publicKey.user) args.publicKey.user.id = decode(args.publicKey.user.id);
        for (const field of ['allowCredentials', 'excludeCredentials']) {
          for (const cred of args.publicKey[field] || []) cred.id = decode(cred.id);
        }
        const credential = await navigator.credentials[kind](args);
        const fields = {id: encode(credential.rawId), clientDataJSON: encode(credential.response.clientDataJSON)};
        if (create) {
          fields.attestationObject = encode(credential.response.attestationObject);
          fields.label = box.querySelector('.key-label').value;
        } else {
          fields.authenticatorData = encode(credential.response.authenticatorData);
          fields.signature = encode(credential.response.signature);
        }
        const result = await request('finish', fields);
        window.location.assign(result.redirect);
      } catch (error) { status.textContent = error.name === 'NotAllowedError' ? 'Verification cancelled or timed out.' : error.message; }
      finally { button.disabled = false; }
    };
    button.addEventListener('click', verify);
    if (button.closest('[data-auto-passkey="true"]')) {
      // One prompt per completed password/SSO step. Cancellation never loops.
      verify();
    }
  }
})();
