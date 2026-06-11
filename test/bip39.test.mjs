// BIP39 conformance tests. These exist because two real bugs shipped here:
// a 1906-word (truncated) wordlist and a negative-shift repacking error in
// mnemonicToEntropy — together they broke seed-phrase recovery for most
// identities. The official test vectors below would have caught both.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed, validateMnemonicWords } from '../public/bip39.js';

const hex = bytes => Buffer.from(bytes).toString('hex');

test('official vector: zero entropy → "abandon ×11 about"', async () => {
  const words = await entropyToMnemonic(new Uint8Array(16));
  assert.equal(
    words.join(' '),
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  );
});

test('official vector: 0x7f×16 → "legal winner ..." and TREZOR seed', async () => {
  const entropy = new Uint8Array(16).fill(0x7f);
  const words = await entropyToMnemonic(entropy);
  assert.equal(
    words.join(' '),
    'legal winner thank year wave sausage worth useful legal winner thank yellow'
  );
  const seed = await mnemonicToSeed(words, 'TREZOR');
  assert.equal(
    hex(seed),
    '2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607'
  );
});

test('every word index 0..2047 is reachable (full 2048-word list)', async () => {
  // entropy of all 0xff bits forces index 2047 ('zoo') into play
  const words = await entropyToMnemonic(new Uint8Array(16).fill(0xff));
  assert.equal(words[0], 'zoo');
  assert.ok(words.every(w => typeof w === 'string' && w.length > 0));
  assert.ok(validateMnemonicWords(words));
});

test('round-trip fuzz: 100 random entropies survive encode → decode', async () => {
  for (let t = 0; t < 100; t++) {
    const entropy = crypto.getRandomValues(new Uint8Array(16));
    const words = await entropyToMnemonic(entropy);
    assert.ok(words.every(Boolean), 'no undefined words');
    const back = await mnemonicToEntropy(words);
    assert.equal(hex(back), hex(entropy));
  }
});

test('corrupted checksum is rejected', async () => {
  // "abandon" ×12 is the canonical invalid-checksum mnemonic (valid is ×11 + "about")
  const allAbandon = new Array(12).fill('abandon');
  await assert.rejects(() => mnemonicToEntropy(allAbandon), /checksum/i);
});
