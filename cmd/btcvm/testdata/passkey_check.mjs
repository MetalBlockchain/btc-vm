// Checks the web wallet's passkey protection (TestWebPasskey) against a
// mock authenticator whose PRF output, like CTAP2 hmac-secret, differs with
// and without user verification: new backups require and check a PIN or
// biometric; backups made before still open as they were made. Prints "ok".
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';

globalThis.window = { PublicKeyCredential: function () {} };
globalThis.location = { hostname: 'wallet.example' };
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// The authenticator: uv says whether it verifies the user when asked.
const auth = { uv: true, requests: [] };
const prf = (salt, verified) => createHash('sha256').update(Buffer.from(salt)).update(verified ? 'uv' : 'no-uv').digest();
const authData = (verified) => { const d = new Uint8Array(37); d[32] = 0x01 | (verified ? 0x04 : 0); return d.buffer; };
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {
  credentials: {
    async create({ publicKey }) {
      auth.requests.push(['create', publicKey.authenticatorSelection.userVerification]);
      return { rawId: new Uint8Array([7, 7, 7]).buffer, getClientExtensionResults: () => ({ prf: { enabled: true } }) };
    },
    async get({ publicKey }) {
      auth.requests.push(['get', publicKey.userVerification]);
      const verified = auth.uv && publicKey.userVerification !== 'discouraged';
      return {
        rawId: new Uint8Array([7, 7, 7]).buffer,
        response: { authenticatorData: authData(verified) },
        getClientExtensionResults: () => ({ prf: { results: { first: prf(publicKey.extensions.prf.eval.first, verified) } } }),
      };
    },
  },
} });

const passkey = await import('../web/passkey.js');
const key = new Uint8Array(32).fill(5);

// Protecting requires verification when the passkey is made and used.
const backup = await passkey.protect(key);
assert.deepEqual(auth.requests, [['create', 'required'], ['get', 'required'], ['get', 'required']]);
assert.equal(passkey.madeUnverified(backup), false);
assert.deepEqual(await passkey.unlock(backup), key);

// A security key that doesn't verify the user (no PIN) is refused, both to
// protect and to open.
auth.uv = false;
await assert.rejects(passkey.protect(key), /PIN or biometric/);
await assert.rejects(passkey.unlock(backup), /PIN or biometric/);

// A backup made before (no marker, secret derived without verification)
// still opens as it was made, and is reported as such.
const parts = JSON.parse(Buffer.from(backup.slice('btcvm-passkey:v1:'.length), 'base64url').toString());
const salt = Buffer.from(parts.s, 'base64url');
const base = await crypto.subtle.importKey('raw', prf(salt, false), 'HKDF', false, ['deriveKey']);
const aes = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('btcvm wallet key v1') },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const iv = new Uint8Array(12).fill(1);
const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, key));
const old = 'btcvm-passkey:v1:' + Buffer.from(JSON.stringify({ c: parts.c, s: parts.s, i: Buffer.from(iv).toString('base64url'), d: Buffer.from(sealed).toString('base64url') })).toString('base64url');
assert.equal(passkey.madeUnverified(old), true);
auth.requests = [];
assert.deepEqual(await passkey.unlock(old), key);
assert.deepEqual(auth.requests, [['get', 'preferred']]);

console.log('ok');
