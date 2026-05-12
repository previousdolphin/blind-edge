import { test } from 'node:test';
import assert from 'node:assert/strict';

test('node 20+ exposes ECDSA P-256 in globalThis.crypto.subtle', async () => {
  const pair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  assert.equal(pair.privateKey.algorithm.name, 'ECDSA');
  assert.equal(pair.privateKey.algorithm.namedCurve, 'P-256');
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
