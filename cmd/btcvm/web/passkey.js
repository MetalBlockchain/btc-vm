// Passkey protection for the wallet key. A passkey can't sign Bitcoin
// transactions (it uses a different curve), but with the WebAuthn PRF
// extension it produces a secret only it can reproduce. The wallet key is
// encrypted with that secret, so opening the wallet takes the passkey:
// Face ID, Touch ID, Windows Hello or a security key.
//
// The encrypted key is a "backup": a string that is useless without the
// passkey, so it can be kept anywhere. With a passkey that syncs (iCloud
// Keychain, Google Password Manager), backup plus passkey restore the wallet
// on another device.
//
// Opening the wallet takes the passkey and its PIN or biometric: user
// verification is required, and checked in the authenticator's own flags.
// With a security key, the PRF secret differs with and without verification,
// so a backup made before this (without it, by a key with no PIN) still
// opens as it was made, and the wallet suggests making a new one.

const PREFIX = 'btcvm-passkey:v1:';
const INFO = new TextEncoder().encode('btcvm wallet key v1');

const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

// available reports whether this browser has passkeys at all. Whether the
// passkey provider supports PRF is only known once one is made.
export const available = () => typeof window.PublicKeyCredential === 'function' && Boolean(navigator.credentials);

export const isBackup = (s) => typeof s === 'string' && s.trim().startsWith(PREFIX);

class PasskeyError extends Error {}

// noPRF explains a missing PRF result, saying at which step, since that tells
// a browser that lacks PRF apart from an authenticator that lacks it.
const noPRF = (step, results) => new PasskeyError(
  "This browser and passkey can't encrypt the wallet: they don't support the PRF extension together. " +
  'With a security key such as a YubiKey (5 series), use Chrome, Edge or Firefox; Safari supports it only for iCloud Keychain passkeys. ' +
  `(Details: ${step}; the browser reported ${JSON.stringify(results?.prf ?? null)}.)`);

function failure(err) {
  if (err.name === 'NotAllowedError') return new PasskeyError('The passkey request was cancelled, timed out, or not allowed by the browser.');
  if (err.name === 'InvalidStateError') return new PasskeyError('This security key already has a passkey for this wallet.');
  return new PasskeyError(`${err.name}: ${err.message}`);
}

async function aesKey(prfOutput, salt) {
  const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
}

// userVerified reads the UV bit of an assertion's authenticator data.
const userVerified = (assertion) => {
  const data = assertion?.response?.authenticatorData;
  return Boolean(data && data.byteLength > 32 && (new Uint8Array(data)[32] & 0x04));
};

// prfSecret asks the passkey for its PRF output for salt: with the user
// verified (PIN or biometric), unless verify is false, for a backup made
// before verification was required.
async function prfSecret(credentialId, salt, verify = true) {
  let assertion;
  try {
    assertion = await navigator.credentials.get({
      publicKey: {
        challenge: random(32),
        rpId: location.hostname,
        allowCredentials: credentialId ? [{ type: 'public-key', id: credentialId }] : [],
        userVerification: verify ? 'required' : 'preferred',
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (err) {
    throw failure(err);
  }
  if (verify && !userVerified(assertion)) {
    throw new PasskeyError('The passkey did not verify you with a PIN or biometric, which the wallet requires. Set a PIN on your security key, or use a passkey that has one.');
  }
  const results = assertion?.getClientExtensionResults();
  const out = results?.prf?.results?.first;
  if (!out) throw noPRF('the passkey was made, but returned no PRF output when used', results);
  return { secret: new Uint8Array(out), credentialId: new Uint8Array(assertion.rawId) };
}

// protect makes a passkey for this wallet and returns the key encrypted to
// it, as a backup string.
export async function protect(key) {
  let credential;
  try {
    credential = await navigator.credentials.create({
      publicKey: {
        challenge: random(32),
        rp: { name: 'BTCVM', id: location.hostname },
        user: { id: random(16), name: 'BTCVM wallet', displayName: 'BTCVM wallet' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        // The backup names the credential, so it need not be discoverable:
        // on a security key such as a YubiKey that saves one of its
        // limited slots. Passkey managers make it discoverable anyway.
        authenticatorSelection: { residentKey: 'discouraged', userVerification: 'required' },
        extensions: { prf: {} },
      },
    });
  } catch (err) {
    throw failure(err);
  }
  // Some browsers only report PRF support when it is used, so only an
  // explicit "no" stops here; otherwise the next step finds out.
  const made = credential.getClientExtensionResults();
  if (made?.prf?.enabled === false) throw noPRF('the passkey was made without PRF', made);
  const salt = random(32);
  const { secret } = await prfSecret(new Uint8Array(credential.rawId), salt);
  const iv = random(12);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await aesKey(secret, salt), key));
  secret.fill(0);
  const backup = PREFIX + b64u(new TextEncoder().encode(JSON.stringify({
    c: b64u(new Uint8Array(credential.rawId)), s: b64u(salt), i: b64u(iv), d: b64u(sealed),
    u: 1, // made with the user verified: always opened that way
  })));
  // Check it opens before the caller drops the unencrypted key.
  const reopened = await unlock(backup);
  if (reopened.length !== key.length || reopened.some((b, i) => b !== key[i])) {
    throw new PasskeyError('The encrypted key did not decrypt back to the same key; nothing was changed.');
  }
  return backup;
}

function parseBackup(backup) {
  if (!isBackup(backup)) throw new PasskeyError('That is not a BTCVM passkey backup.');
  try {
    return JSON.parse(new TextDecoder().decode(unb64u(backup.trim().slice(PREFIX.length))));
  } catch {
    throw new PasskeyError('That passkey backup is damaged.');
  }
}

// madeUnverified reports whether a backup was made before the wallet
// required a PIN or biometric: it opens without one.
export function madeUnverified(backup) {
  try {
    return parseBackup(backup).u !== 1;
  } catch {
    return false;
  }
}

// unlock decrypts a backup with its passkey.
export async function unlock(backup) {
  const parts = parseBackup(backup);
  const salt = unb64u(parts.s);
  const { secret } = await prfSecret(unb64u(parts.c), salt, parts.u === 1);
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(parts.i) }, await aesKey(secret, salt), unb64u(parts.d));
    return new Uint8Array(plain);
  } catch {
    throw new PasskeyError("That passkey doesn't open this backup.");
  } finally {
    secret.fill(0);
  }
}
