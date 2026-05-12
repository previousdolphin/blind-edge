import { test } from 'node:test';
import assert from 'node:assert/strict';

import { hexToBytes, bytesToHex } from '../public/hex.js';
import { SecurityManager } from '../public/crypto.js';

async function makeIdentity() {
  const kp = await SecurityManager.generateIdentity();
  const pubHex = await SecurityManager.exportPublicKeyHex(kp.publicKey);
  return { kp, pubHex };
}

async function makeFullIdentity() {
  const ecdh = await SecurityManager.generateIdentity();
  const sign = await SecurityManager.generateSigningIdentity();
  const ecdhPubHex = await SecurityManager.exportPublicKeyHex(ecdh.publicKey);
  const signPubHex = await SecurityManager.exportSignPublicKeyHex(sign.publicKey);
  return { ecdh, sign, ecdhPubHex, signPubHex };
}

test('HKDF info string is symmetric: sender and receiver derive matching keys', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();

  const { ciphertext, iv } = await SecurityManager.encryptMessage(
    'hello bob', bob.kp.publicKey, alice.kp.privateKey, bob.pubHex, alice.pubHex, 1
  );
  const { plaintext } = await SecurityManager.decryptMessage(
    ciphertext, iv, alice.kp.publicKey, bob.kp.privateKey, alice.pubHex, bob.pubHex
  );
  assert.equal(plaintext, 'hello bob');
});

test('encryptMessage wraps payload with v2 counter; decrypt returns it', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();

  for (const c of [1, 2, 3]) {
    const { ciphertext, iv } = await SecurityManager.encryptMessage(
      `msg ${c}`, bob.kp.publicKey, alice.kp.privateKey, bob.pubHex, alice.pubHex, c
    );
    const out = await SecurityManager.decryptMessage(
      ciphertext, iv, alice.kp.publicKey, bob.kp.privateKey, alice.pubHex, bob.pubHex
    );
    assert.equal(out.counter, c);
    assert.equal(out.plaintext, `msg ${c}`);
  }
});

test('decryptMessage returns counter:null for legacy v1 raw plaintext', async () => {
  // Hand-craft a v1-style ciphertext: raw text, no JSON wrapping. We rebuild
  // it using the internal padding format the original code used.
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const aesKey = await SecurityManager._deriveSharedAesKey(
    bob.kp.publicKey, alice.kp.privateKey, bob.pubHex, alice.pubHex
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const raw = 'plain legacy message';
  const msgBytes = new TextEncoder().encode(raw);
  const padded = new Uint8Array(4 + Math.ceil((msgBytes.length + 4) / 256) * 256);
  new DataView(padded.buffer).setUint32(0, msgBytes.length, true);
  padded.set(msgBytes, 4);
  const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, padded);
  const ciphertext = bytesToHex(new Uint8Array(ctBuf));
  const ivHex = bytesToHex(iv);

  const out = await SecurityManager.decryptMessage(
    ciphertext, ivHex, alice.kp.publicKey, bob.kp.privateKey, alice.pubHex, bob.pubHex
  );
  assert.equal(out.counter, null);
  assert.equal(out.plaintext, raw);
});

test('HKDF info string binds per-pair: different pairs derive different keys', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const charlie = await makeIdentity();

  const { ciphertext, iv } = await SecurityManager.encryptMessage(
    'for bob only', bob.kp.publicKey, alice.kp.privateKey, bob.pubHex, alice.pubHex, 1
  );

  // Charlie (with bob's private key, simulating an attacker who somehow swapped
  // identity binding) decrypting with charlie<>alice info string must fail.
  // We invoke decrypt with the WRONG hex pair to confirm info binding is
  // load-bearing — same shared bits would decrypt with the right info.
  await assert.rejects(
    () => SecurityManager.decryptMessage(
      ciphertext, iv, alice.kp.publicKey, bob.kp.privateKey, alice.pubHex, charlie.pubHex
    ),
    /Decryption failed/
  );
});

test('hexToBytes rejects non-hex characters', () => {
  assert.throws(() => hexToBytes('z1'), /non-hex character/);
  assert.throws(() => hexToBytes('01z2'), /non-hex character/);
  assert.throws(() => hexToBytes('  '), /non-hex character/);
});

test('hexToBytes rejects odd-length input', () => {
  assert.throws(() => hexToBytes('0'), /length/);
  assert.throws(() => hexToBytes('abc'), /length/);
});

test('hexToBytes rejects non-string input', () => {
  assert.throws(() => hexToBytes(null), TypeError);
  assert.throws(() => hexToBytes(123), TypeError);
});

test('hexToBytes accepts mixed case', () => {
  assert.deepEqual(Array.from(hexToBytes('AbCdEf01')), [0xab, 0xcd, 0xef, 0x01]);
});

test('hexToBytes/bytesToHex round-trip', () => {
  const original = new Uint8Array([0, 1, 15, 16, 127, 128, 254, 255]);
  assert.equal(bytesToHex(original), '00010f107f80feff');
  assert.deepEqual(Array.from(hexToBytes(bytesToHex(original))), Array.from(original));
});

test('hexToBytes accepts empty string', () => {
  assert.equal(hexToBytes('').byteLength, 0);
});

test('node 20+ exposes ECDSA P-256 in globalThis.crypto.subtle', async () => {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  assert.equal(pair.privateKey.algorithm.name, 'ECDSA');
  assert.equal(pair.privateKey.algorithm.namedCurve, 'P-256');
});

test('ephemeral envelope: signed round-trip', async () => {
  const alice = await makeFullIdentity();
  const bob = await makeFullIdentity();

  const env = await SecurityManager.encryptMessageEphemeral(
    'hi bob', 1, bob.ecdh.publicKey, bob.ecdhPubHex, alice.sign.privateKey
  );
  const out = await SecurityManager.decryptMessageEphemeral(
    env, bob.ecdh.privateKey, bob.ecdhPubHex, alice.sign.publicKey
  );
  assert.equal(out.counter, 1);
  assert.equal(out.plaintext, 'hi bob');
});

test('ephemeral envelope: tampered ciphertext fails signature before decrypt', async () => {
  const alice = await makeFullIdentity();
  const bob = await makeFullIdentity();

  const env = await SecurityManager.encryptMessageEphemeral(
    'hi bob', 1, bob.ecdh.publicKey, bob.ecdhPubHex, alice.sign.privateKey
  );
  // Flip one hex byte in ciphertext
  const tampered = { ...env, ciphertext: env.ciphertext.slice(0, -2) + (env.ciphertext.slice(-2) === 'ff' ? '00' : 'ff') };
  await assert.rejects(
    () => SecurityManager.decryptMessageEphemeral(
      tampered, bob.ecdh.privateKey, bob.ecdhPubHex, alice.sign.publicKey
    ),
    /Signature verification failed/
  );
});

test('ephemeral envelope: tampered signature is rejected', async () => {
  const alice = await makeFullIdentity();
  const bob = await makeFullIdentity();

  const env = await SecurityManager.encryptMessageEphemeral(
    'hi bob', 1, bob.ecdh.publicKey, bob.ecdhPubHex, alice.sign.privateKey
  );
  const tampered = {
    ...env,
    signature: env.signature.slice(0, -2) + (env.signature.slice(-2) === 'ff' ? '00' : 'ff'),
  };
  await assert.rejects(
    () => SecurityManager.decryptMessageEphemeral(
      tampered, bob.ecdh.privateKey, bob.ecdhPubHex, alice.sign.publicKey
    ),
    /Signature verification failed/
  );
});

test('ephemeral envelope: legacy contact (null sign key) skips verification', async () => {
  const alice = await makeFullIdentity();
  const bob = await makeFullIdentity();

  const env = await SecurityManager.encryptMessageEphemeral(
    'hi bob', 1, bob.ecdh.publicKey, bob.ecdhPubHex, alice.sign.privateKey
  );
  const out = await SecurityManager.decryptMessageEphemeral(
    env, bob.ecdh.privateKey, bob.ecdhPubHex, null
  );
  assert.equal(out.plaintext, 'hi bob');
});

test('identity bundle v2 round-trip', async () => {
  const password = 'correct horse battery staple';
  const salt = SecurityManager.generateSalt();
  const masterKey = await SecurityManager.deriveKey(password, salt);

  const ecdh = await SecurityManager.generateIdentity();
  const sign = await SecurityManager.generateSigningIdentity();
  const bundle = await SecurityManager.exportIdentityBundle(ecdh, sign, masterKey, salt);
  const imported = await SecurityManager.importIdentityBundle(bundle, masterKey);

  assert.equal(imported.migratedFromV1, false);
  assert.equal(
    await SecurityManager.exportPublicKeyHex(imported.ecdh.publicKey),
    await SecurityManager.exportPublicKeyHex(ecdh.publicKey)
  );
  assert.equal(
    await SecurityManager.exportSignPublicKeyHex(imported.sign.publicKey),
    await SecurityManager.exportSignPublicKeyHex(sign.publicKey)
  );
});

test('identity bundle v1 → v2 migration mints fresh signing key', async () => {
  // Build a v1 bundle by hand using the legacy schema.
  const password = 'hunter2';
  const salt = SecurityManager.generateSalt();
  const masterKey = await SecurityManager.deriveKey(password, salt);

  const ecdh = await SecurityManager.generateIdentity();
  const jwk = await crypto.subtle.exportKey('jwk', ecdh.privateKey);
  const encryptedPrivateKey = await SecurityManager.encryptVault(jwk, masterKey);
  const publicKeyHex = await SecurityManager.exportPublicKeyHex(ecdh.publicKey);
  const v1Bundle = JSON.stringify({
    version: 1,
    publicKeyHex,
    encryptedPrivateKey,
    salt: bytesToHex(salt),
  });

  const imported = await SecurityManager.importIdentityBundle(v1Bundle, masterKey);
  assert.equal(imported.migratedFromV1, true);
  assert.equal(
    await SecurityManager.exportPublicKeyHex(imported.ecdh.publicKey),
    publicKeyHex
  );
  // Confirm the fresh signing key actually works end-to-end.
  const bob = await makeFullIdentity();
  const env = await SecurityManager.encryptMessageEphemeral(
    'after migration', 1, bob.ecdh.publicKey, bob.ecdhPubHex, imported.sign.privateKey
  );
  const out = await SecurityManager.decryptMessageEphemeral(
    env, bob.ecdh.privateKey, bob.ecdhPubHex, imported.sign.publicKey
  );
  assert.equal(out.plaintext, 'after migration');
});

test('node 20+ exposes ECDH P-256 + HKDF in globalThis.crypto.subtle', async () => {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey']
  );
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: 'ECDH', public: pair.publicKey },
    pair.privateKey,
    256
  );
  assert.equal(bits.byteLength, 32);
});
