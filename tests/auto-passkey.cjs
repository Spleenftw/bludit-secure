const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
(async () => {
  const source = fs.readFileSync(path.join(__dirname, '../assets/secure.js'), 'utf8');
  let prompts = 0, requests = 0, retry;
  const status = {textContent: ''};
  const box = {dataset: {base: 'https://blog.test/admin/login', csrf: 'test'}};
  const button = {
    dataset: {key: 'get'}, disabled: false,
    closest: () => box,
    addEventListener: (event, handler) => { retry = handler; }
  };
  vm.runInNewContext(source, {
    URL, URLSearchParams, Uint8Array, atob, btoa,
    document: {getElementById: () => status, querySelectorAll: () => [button]},
    window: {PublicKeyCredential: function () {}},
    navigator: {credentials: {get: async () => {
      prompts++;
      const error = new Error('cancel'); error.name = 'NotAllowedError'; throw error;
    }}},
    fetch: async () => {
      requests++;
      return {ok: true, json: async () => ({publicKey: {challenge: 'AQID', allowCredentials: []}})};
    }
  });
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(prompts, 1); assert.equal(requests, 1); assert.equal(button.disabled, false);
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(prompts, 1, 'cancellation must not trigger a prompt loop');
  await retry();
  assert.equal(prompts, 2, 'explicit retry must remain available');
  console.log('OK automatic passkey prompt, cancellation without loop, explicit retry');
})().catch(error => { console.error(error); process.exitCode = 1; });
