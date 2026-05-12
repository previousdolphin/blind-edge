import { test } from 'node:test';
import assert from 'node:assert/strict';

import { hexToBytes, bytesToHex } from '../public/hex.js';

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
