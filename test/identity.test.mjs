// Tests for the seed-first identity flow and vault-wrapped recovery entropy.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SecurityManager } from '../public/crypto.js';
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed } from '../public/bip39.js';
import { bytesToHex, hexToBytes } from '../public/hex.js';

test('seed-first creation is deterministic: same words → same keys → same address', async () => {
  const entropy = crypto.getRandomValues(new Uint8Array(16));
  const words = await entropyToMnemonic(entropy);
  assert.equal(words.length, 12);

  // Derive twice from the same words (as a fresh device restore would)
  const seedA = await mnemonicToSeed(words, '');
  const seedB = await mnemonicToSeed(words, '');
  const idA = await SecurityManager.deriveIdentityFromSeed(seedA);
  const idB = await SecurityManager.deriveIdentityFromSeed(seedB);

  const pubA = await SecurityManager.exportPublicKeyHex(idA.ecdh.publicKey);
  const pubB = await SecurityManager.exportPublicKeyHex(idB.ecdh.publicKey);
  assert.equal(pubA, pubB, 'ECDH public keys must match across restores');

  const signA = await SecurityManager.exportSignPublicKeyHex(idA.sign.publicKey);
  const signB = await SecurityManager.exportSignPublicKeyHex(idB.sign.publicKey);
  assert.equal(signA, signB, 'signing public keys must match across restores');

  const hashA = await SecurityManager.getKeyHash(idA.ecdh.publicKey);
  const hashB = await SecurityManager.getKeyHash(idB.ecdh.publicKey);
  assert.equal(hashA, hashB, 'relay address must be stable across restores');
});

test('mnemonic round-trips through entropy with valid checksum', async () => {
  const entropy = crypto.getRandomValues(new Uint8Array(16));
  const words = await entropyToMnemonic(entropy);
  const back = await mnemonicToEntropy(words);
  assert.equal(bytesToHex(new Uint8Array(back)), bytesToHex(entropy));
});

test('identity bundle round-trips with entropy sealed inside the vault', async () => {
  const entropy = crypto.getRandomValues(new Uint8Array(16));
  const entropyHex = bytesToHex(entropy);
  const words = await entropyToMnemonic(entropy);
  const seed = await mnemonicToSeed(words, '');
  const { ecdh, sign } = await SecurityManager.deriveIdentityFromSeed(seed);

  const salt = SecurityManager.generateSalt();
  const masterKey = await SecurityManager.deriveKey('correct horse battery', salt);
  const bundleStr = await SecurityManager.exportIdentityBundle(ecdh, sign, masterKey, salt, entropyHex);

  // Entropy must NOT appear in plaintext anywhere in the stored bundle
  assert.ok(!bundleStr.includes(entropyHex), 'entropy must not be stored in plaintext');

  const imported = await SecurityManager.importIdentityBundle(bundleStr, masterKey);
  assert.equal(imported.entropyHex, entropyHex, 'entropy must round-trip through the vault');
  assert.equal(imported.entropyWasPlaintext, false);

  const pubBefore = await SecurityManager.exportPublicKeyHex(ecdh.publicKey);
  const pubAfter = await SecurityManager.exportPublicKeyHex(imported.ecdh.publicKey);
  assert.equal(pubBefore, pubAfter);
});

test('legacy bundle with plaintext top-level entropy is honored and flagged for rewrap', async () => {
  const entropy = crypto.getRandomValues(new Uint8Array(16));
  const entropyHex = bytesToHex(entropy);
  const words = await entropyToMnemonic(entropy);
  const seed = await mnemonicToSeed(words, '');
  const { ecdh, sign } = await SecurityManager.deriveIdentityFromSeed(seed);

  const salt = SecurityManager.generateSalt();
  const masterKey = await SecurityManager.deriveKey('correct horse battery', salt);
  // Simulate the pre-v1.5 format: no entropy in vault, plaintext field on top
  const bundleStr = await SecurityManager.exportIdentityBundle(ecdh, sign, masterKey, salt);
  const legacyBundle = JSON.parse(bundleStr);
  legacyBundle.entropy = entropyHex;

  const imported = await SecurityManager.importIdentityBundle(JSON.stringify(legacyBundle), masterKey);
  assert.equal(imported.entropyHex, entropyHex);
  assert.equal(imported.entropyWasPlaintext, true, 'caller must be told to rewrap');
});

test('password-era bundle without any entropy unlocks cleanly with entropyHex null', async () => {
  const ecdh = await SecurityManager.generateIdentity();
  const sign = await SecurityManager.generateSigningIdentity();
  const salt = SecurityManager.generateSalt();
  const masterKey = await SecurityManager.deriveKey('correct horse battery', salt);
  const bundleStr = await SecurityManager.exportIdentityBundle(ecdh, sign, masterKey, salt);

  const imported = await SecurityManager.importIdentityBundle(bundleStr, masterKey);
  assert.equal(imported.entropyHex, null, 'no recovery phrase for random-key identities');
  assert.equal(imported.entropyWasPlaintext, false);
});

test('JWK derivation matches the legacy PKCS8 path byte-for-byte (address preservation)', async () => {
  // The original deriveIdentityFromSeed imported the bare scalar as PKCS#8
  // and let Web Crypto compute the public point. That broke on WebKit, so the
  // implementation now computes scalar·G itself and imports via JWK. This test
  // re-runs the legacy PKCS8 path (node supports it) and asserts both paths
  // produce the same public keys — i.e. no existing identity changes address.
  const P256_PKCS8_PREFIX = new Uint8Array([
    0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04,
    0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
  ]);

  for (let trial = 0; trial < 5; trial++) {
    const entropy = crypto.getRandomValues(new Uint8Array(16));
    const seed = await mnemonicToSeed(await entropyToMnemonic(entropy), '');

    // current implementation
    const current = await SecurityManager.deriveIdentityFromSeed(seed);
    const currentEcdhPub = await SecurityManager.exportPublicKeyHex(current.ecdh.publicKey);
    const currentSignPub = await SecurityManager.exportSignPublicKeyHex(current.sign.publicKey);

    // legacy PKCS8 path, reproduced independently
    const hkdfKey = await crypto.subtle.importKey('raw', seed, 'HKDF', false, ['deriveBits']);
    async function legacyPub(info, name) {
      const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(info) },
        hkdfKey, 256
      );
      const der = new Uint8Array(P256_PKCS8_PREFIX.length + 32);
      der.set(P256_PKCS8_PREFIX);
      der.set(new Uint8Array(bits), P256_PKCS8_PREFIX.length);
      const priv = await crypto.subtle.importKey(
        'pkcs8', der.buffer, { name, namedCurve: 'P-256' }, true,
        name === 'ECDH' ? ['deriveBits'] : ['sign']
      );
      const jwk = await crypto.subtle.exportKey('jwk', priv);
      const pub = await crypto.subtle.importKey(
        'jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
        { name, namedCurve: 'P-256' }, true, name === 'ECDH' ? [] : ['verify']
      );
      return bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', pub)));
    }
    assert.equal(currentEcdhPub, await legacyPub('blind-edge-ecdh-v2', 'ECDH'), `ECDH pub mismatch (trial ${trial})`);
    assert.equal(currentSignPub, await legacyPub('blind-edge-ecdsa-v2', 'ECDSA'), `ECDSA pub mismatch (trial ${trial})`);
  }
});

test('restored identity decrypts a message sent to the original', async () => {
  const entropy = crypto.getRandomValues(new Uint8Array(16));
  const words = await entropyToMnemonic(entropy);

  const original = await SecurityManager.deriveIdentityFromSeed(await mnemonicToSeed(words, ''));
  const restored = await SecurityManager.deriveIdentityFromSeed(await mnemonicToSeed(words, ''));
  const sender = await SecurityManager.deriveIdentityFromSeed(
    await mnemonicToSeed(await entropyToMnemonic(crypto.getRandomValues(new Uint8Array(16))), '')
  );

  const recipientPubHex = await SecurityManager.exportPublicKeyHex(original.ecdh.publicKey);
  const recipientPub = await SecurityManager.importPublicKeyHex(recipientPubHex);
  const senderSignPub = await SecurityManager.importSignPublicKeyHex(
    await SecurityManager.exportSignPublicKeyHex(sender.sign.publicKey)
  );

  const envelope = await SecurityManager.encryptMessageEphemeral(
    'survives the restore', 1, recipientPub, recipientPubHex, sender.sign.privateKey
  );
  const { counter, plaintext } = await SecurityManager.decryptMessageEphemeral(
    envelope, restored.ecdh.privateKey, recipientPubHex, senderSignPub
  );
  assert.equal(plaintext, 'survives the restore');
  assert.equal(counter, 1);
});
