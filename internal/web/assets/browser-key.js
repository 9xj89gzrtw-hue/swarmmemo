/* SwarmMemo browser key: the one copy of the key code every browser surface
   uses. swarmmemo.com (app.js, Me and the composer), its first-party windows
   (/connect/embed, /gate/pass) and the comment embed on other sites (inside
   /embed/v1.js) all make, read, keep and sign with it. Loaded after
   memo-core.js; adds one global (none on a host page: the embed bundle wraps
   it in its closure).
   One stored format: {version: 1, service, public_key, private_key (the
   32-byte seed), fingerprint, handle}, all base64url. The comment embed once
   kept the 48-byte PKCS#8 form without a fingerprint; normalize() reads that
   form and returns the same key in the shared one. */
const SwarmMemoKeys = (() => {
  'use strict';
  const {b64, unb64, canonical} = SwarmMemoCore;
  const active = 'swarmmemo.identity.v1', saved = 'swarmmemo.identities.v1';
  // The DER head of an Ed25519 PKCS#8 private key; the 32-byte seed follows it.
  const head = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
  const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  const uuid = () => crypto.randomUUID ? crypto.randomUUID() : hex(crypto.getRandomValues(new Uint8Array(16)));
  // The seed of a stored private key, either form; null for anything else.
  function seed(text) {
    let bytes;
    try { bytes = unb64(text); } catch (_) { return null; }
    if (bytes.length === 32) return bytes;
    if (bytes.length === 48 && head.every((b, i) => bytes[i] === b)) return bytes.slice(16);
    return null;
  }
  // A stored key in the shared format: version 1, this service's (or none
  // named), a public key, a seed and a fingerprint. Shape only; sync.
  function wellFormed(key, service) {
    return !!key && key.version === 1 && typeof key.public_key === 'string' && typeof key.private_key === 'string' && /^[a-f0-9]{64}$/.test(key.fingerprint || '') && (!key.service || key.service === service);
  }
  const fingerprint = async raw => hex(await crypto.subtle.digest('SHA-256', raw));
  async function privateKey(key, extractable = false) {
    const bytes = seed(key.private_key);
    if (!bytes) throw Error('This key is not an Ed25519 key.');
    const wrapped = new Uint8Array(48); wrapped.set(head); wrapped.set(bytes, 16);
    return crypto.subtle.importKey('pkcs8', wrapped, {name: 'Ed25519'}, extractable, ['sign']);
  }
  // A new key in the shared format. Stores nothing.
  async function generate(service) {
    const pair = await crypto.subtle.generateKey({name: 'Ed25519'}, true, ['sign', 'verify']);
    const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    return {version: 1, service, public_key: b64(raw), private_key: b64(pkcs8.slice(-32)), fingerprint: await fingerprint(raw), handle: ''};
  }
  // key (either stored form) in the shared format, checked: the seed must
  // make the public key it is stored with. Throws on anything else; an
  // unsupported browser throws NotSupportedError from WebCrypto.
  async function normalize(key, service) {
    if (!key || key.version !== 1 || typeof key.public_key !== 'string' || typeof key.private_key !== 'string' || (key.service && key.service !== service)) throw Error('Not a SwarmMemo key.');
    const raw = unb64(key.public_key), bytes = seed(key.private_key);
    if (raw.length !== 32 || !bytes) throw Error('Not a SwarmMemo key.');
    const jwk = await crypto.subtle.exportKey('jwk', await privateKey(key, true));
    if (jwk.x !== key.public_key) throw Error('The private key does not match its public key.');
    const print = await fingerprint(raw);
    if (key.fingerprint && key.fingerprint !== print) throw Error('The fingerprint does not match the key.');
    return {version: 1, service: key.service || service, public_key: key.public_key, private_key: b64(bytes), fingerprint: print, handle: typeof key.handle === 'string' ? key.handle : ''};
  }
  // The active swarmmemo.com key, or null: well formed, this service's.
  function stored(service) {
    let key = null;
    try { key = JSON.parse(localStorage.getItem(active) || 'null'); } catch (_) { /* Reported as no key. */ }
    return wellFormed(key, service) ? key : null;
  }
  // A new swarmmemo.com key, kept like Me keeps one: the active key and the
  // list of keys in this browser, both read back to be sure they were stored.
  async function create(service) {
    const made = await generate(service);
    const encoded = JSON.stringify(made);
    let list = [];
    try { const parsed = JSON.parse(localStorage.getItem(saved) || '[]'); if (Array.isArray(parsed)) list = parsed; } catch (_) { list = []; }
    list.push(made);
    try {
      localStorage.setItem(saved, JSON.stringify(list));
      localStorage.setItem(active, encoded);
      if (localStorage.getItem(active) !== encoded) throw Error('readback');
    } catch (_) { throw Error('This browser would not store a key for swarmmemo.com (private window or blocked storage). Nothing was signed.'); }
    return made;
  }
  // command signed by key: version 1 canonical bytes, a fresh nonce, now.
  async function sign(command, key, service) {
    const result = {...command, public_key: key.public_key, timestamp: Math.floor(Date.now() / 1000), nonce: uuid()};
    result.signature = b64(await crypto.subtle.sign('Ed25519', await privateKey(key), canonical(result, service)));
    return result;
  }
  return Object.freeze({wellFormed, normalize, generate, fingerprint, privateKey, stored, create, sign, uuid, hex});
})();
