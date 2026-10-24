// Node only (C546): browser-key.js, the one browser key module, normalize reads the embed's 48-byte PKCS#8 form and the seed form as one key.
const fs = require('fs'), vm = require('vm'), path = require('path'), assert = require('assert/strict');
const dir = path.join(__dirname, 'assets') + path.sep;
const ctx = {TextEncoder, btoa, atob, crypto: globalThis.crypto, localStorage: null};
const K = vm.runInNewContext(fs.readFileSync(dir + 'memo-core.js', 'utf8') + '\n' + fs.readFileSync(dir + 'browser-key.js', 'utf8') + '\n({core: SwarmMemoCore, keys: SwarmMemoKeys});', ctx);
(async () => {
  const {b64} = K.core;
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const embedKey = {version: 1, service: 'swarmmemo.com', public_key: b64(await crypto.subtle.exportKey('raw', pair.publicKey)), private_key: b64(await crypto.subtle.exportKey('pkcs8', pair.privateKey)), handle: 'h'};
  const shared = await K.keys.normalize(embedKey, 'swarmmemo.com');
  assert.equal(K.core.unb64(shared.private_key).length, 32);
  assert.equal(shared.public_key, embedKey.public_key);
  assert.match(shared.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(shared.handle, 'h');
  assert.deepEqual(await K.keys.normalize(shared, 'swarmmemo.com'), shared, 'idempotent');
  const signed = await K.keys.sign({operation: 'post', text: 'x'}, embedKey, 'swarmmemo.com');
  const signed2 = await K.keys.sign({operation: 'post', text: 'x'}, shared, 'swarmmemo.com');
  assert.ok(signed.signature && signed2.signature);
  const other = await K.keys.generate('swarmmemo.com');
  await assert.rejects(K.keys.normalize({...shared, public_key: other.public_key, fingerprint: ''}, 'swarmmemo.com'), /does not match/);
  await assert.rejects(K.keys.normalize({...shared, service: 'evil.example'}, 'swarmmemo.com'));
  await assert.rejects(K.keys.normalize({...shared, private_key: b64(new Uint8Array(48))}, 'swarmmemo.com'));
  console.log('PASS normalize: embed PKCS#8 and seed forms are one key; mismatches refused');
})().catch(e => { console.error(e); process.exit(1); });
