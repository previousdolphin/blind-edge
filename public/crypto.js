// SecurityManager — every cryptographic operation in B.E.Chat lives here.
// Native Web Crypto only; no libraries.
//
// Key hierarchy:
//
//   App Password ──PBKDF2-SHA256 (600k, random salt)──▶ masterKey (AES-256-GCM)
//        masterKey wraps the vault: { ecdhPriv, signPriv, entropy }
//
//   BIP39 entropy (16 bytes) ──mnemonic──▶ 12 words
//        seed = PBKDF2-SHA512(words, passphrase)  (bip39.js)
//        seed ──HKDF-SHA256──▶ two deterministic P-256 scalars
//             info "blind-edge-ecdh-v2"  → long-term ECDH keypair (encryption)
//             info "blind-edge-ecdsa-v2" → long-term ECDSA keypair (signing)
//        Same words ⇒ same keys ⇒ same relay address, on any device.
//
// Per-message: ephemeral ECDH → HKDF (info binds BOTH public keys, sorted —
// see _deriveSharedAesKey for why) → AES-256-GCM, padded to 256-byte blocks.
// Forward secrecy is sender-side only: the ephemeral private key is discarded
// after encryption, but the recipient's long-term key still decrypts.
import { hexToBytes, bytesToHex } from './hex.js';

// ─── Minimal P-256 point math (BigInt) ────────────────────────────────────────
// Needed only to turn a deterministic private scalar into its public point.
// WebKit (iOS/macOS Safari) throws DataError on importKey('pkcs8', …) when the
// EC private key has no embedded public point, and a private JWK requires x/y
// — so we compute scalar·G ourselves and import via JWK, which every browser
// accepts. Used once per identity creation/restore (not per message), and only
// on the user's own fresh key, so non-constant-time double-and-add is fine.
const P256 = {
  p:  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  n:  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
};

function _mod(a, m) { const r = a % m; return r < 0n ? r + m : r; }

function _inv(a, m) {
  let [oldR, r] = [_mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return _mod(oldS, m);
}

// Affine point add/double on y² = x³ - 3x + b over GF(p). null = point at infinity.
function _pointAdd(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  const { p } = P256;
  const [x1, y1] = p1, [x2, y2] = p2;
  let l;
  if (x1 === x2) {
    if (_mod(y1 + y2, p) === 0n) return null;
    l = _mod((3n * x1 * x1 - 3n) * _inv(2n * y1, p), p);
  } else {
    l = _mod((y2 - y1) * _inv(x2 - x1, p), p);
  }
  const x3 = _mod(l * l - x1 - x2, p);
  return [x3, _mod(l * (x1 - x3) - y1, p)];
}

function _scalarMultG(k) {
  let result = null;
  let addend = [P256.gx, P256.gy];
  while (k > 0n) {
    if (k & 1n) result = _pointAdd(result, addend);
    addend = _pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

function _bigIntTo32(v) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

function _bytesToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function _b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export class SecurityManager {
  static generateSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
  }

  static async deriveKey(password, salt) {
    const rawKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 },
      rawKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  static async generateIdentity() {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
  }

  static async exportPublicKeyHex(publicKey) {
    const raw = await crypto.subtle.exportKey('raw', publicKey);
    return bytesToHex(new Uint8Array(raw));
  }

  static async importPublicKeyHex(hex) {
    return crypto.subtle.importKey(
      'raw',
      hexToBytes(hex),
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
  }

  static async getKeyHash(publicKey) {
    const raw = await crypto.subtle.exportKey('raw', publicKey);
    const digest = await crypto.subtle.digest('SHA-256', raw);
    return bytesToHex(new Uint8Array(digest));
  }

  // Long-term identity signing key (ECDSA P-256). Web Crypto requires this
  // be a separate key from the ECDH keypair because key usages can't overlap.
  // Ed25519 would be a more modern choice but is not yet ubiquitous in
  // Web Crypto across the no-polyfill browser target.
  static async generateSigningIdentity() {
    return crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
  }

  static async exportSignPublicKeyHex(publicKey) {
    const raw = await crypto.subtle.exportKey('raw', publicKey);
    return bytesToHex(new Uint8Array(raw));
  }

  static async importSignPublicKeyHex(hex) {
    return crypto.subtle.importKey(
      'raw',
      hexToBytes(hex),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
  }

  static async _deriveSharedAesKey(theirPublicKey, ourPrivateKey, theirPubKeyHex, ourPubKeyHex) {
    // WebCrypto ECDH can't directly derive AES-GCM in one step when the
    // intermediate needs to feed into HKDF, so we derive raw bits first.
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: theirPublicKey },
      ourPrivateKey,
      256
    );

    const hkdfKey = await crypto.subtle.importKey(
      'raw',
      sharedBits,
      'HKDF',
      false,
      ['deriveKey']
    );

    // Bind the derived AES key to both participants' public keys. ECDH is
    // commutative, so without this binding Alice and Bob derive the same key
    // for both directions — letting either party decrypt the other's outbound
    // ciphertext (reflection attack). Sorting ensures both sides build the
    // same info string regardless of role.
    const sortedPubs = [theirPubKeyHex, ourPubKeyHex].sort();
    const info = new TextEncoder().encode('blind-edge-v1|' + sortedPubs.join('|'));

    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info,
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  static async encryptMessage(plaintext, recipientPubKey, senderPrivKey, recipientPubKeyHex, senderPubKeyHex, counter) {
    const aesKey = await SecurityManager._deriveSharedAesKey(
      recipientPubKey, senderPrivKey, recipientPubKeyHex, senderPubKeyHex
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Wrap plaintext in a v2 envelope carrying a strictly-monotonic counter.
    // The counter goes inside the AES-GCM ciphertext so the relay can't
    // observe or tamper with it. Pad to next 256-byte boundary to defeat
    // traffic-length analysis.
    // Format: [4-byte LE message length][JSON envelope bytes][random padding]
    const wrapped = JSON.stringify({ v: 2, c: counter, m: plaintext });
    const msgBytes = new TextEncoder().encode(wrapped);
    const msgLen = msgBytes.length;
    const padded = new Uint8Array(4 + Math.ceil((msgLen + 4) / 256) * 256);
    new DataView(padded.buffer).setUint32(0, msgLen, true);
    padded.set(msgBytes, 4);
    crypto.getRandomValues(padded.subarray(4 + msgLen));

    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      padded
    );

    return {
      ciphertext: bytesToHex(new Uint8Array(ciphertextBuf)),
      iv: bytesToHex(iv),
    };
  }

  static async decryptMessage(ciphertext, iv, senderPubKey, recipientPrivKey, senderPubKeyHex, recipientPubKeyHex) {
    const aesKey = await SecurityManager._deriveSharedAesKey(
      senderPubKey, recipientPrivKey, senderPubKeyHex, recipientPubKeyHex
    );

    try {
      const plaintextBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hexToBytes(iv) },
        aesKey,
        hexToBytes(ciphertext)
      );
      // Unpad: read 4-byte LE length prefix, extract that many bytes
      const padded = new Uint8Array(plaintextBuf);
      const msgLen = new DataView(padded.buffer).getUint32(0, true);
      const text = new TextDecoder().decode(padded.subarray(4, 4 + msgLen));
      // v2 envelopes are JSON {v, c, m}. Legacy v1 ciphertexts contain raw
      // plaintext with no counter; return counter:null so the caller can
      // apply its legacy-acceptance policy.
      let inner;
      try { inner = JSON.parse(text); } catch { inner = null; }
      if (inner && typeof inner === 'object' && inner.v === 2 && 'c' in inner) {
        return { counter: inner.c, plaintext: inner.m };
      }
      return { counter: null, plaintext: text };
    } catch {
      throw new Error('Decryption failed — wrong key or corrupted data');
    }
  }

  // Per-message ephemeral ECDH (ECDHE) with sender-signed ephemeral public.
  // Provides forward secrecy on the sender side once the ephemeral private is
  // garbage-collected. Full bidirectional PFS would require an X3DH-style
  // prekey bundle published by the recipient — out of scope for this version.
  static async encryptMessageEphemeral(plaintext, counter, recipientEcdhPub, recipientEcdhPubHex, senderSignPriv) {
    const eph = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    const ephPubHex = await SecurityManager.exportPublicKeyHex(eph.publicKey);

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: recipientEcdhPub },
      eph.privateKey,
      256
    );
    const hkdfKey = await crypto.subtle.importKey(
      'raw', sharedBits, 'HKDF', false, ['deriveKey']
    );
    const sortedPubs = [ephPubHex, recipientEcdhPubHex].sort();
    const info = new TextEncoder().encode('blind-edge-v2|' + sortedPubs.join('|'));
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = JSON.stringify({ v: 2, c: counter, m: plaintext });
    const msgBytes = new TextEncoder().encode(wrapped);
    const msgLen = msgBytes.length;
    const padded = new Uint8Array(4 + Math.ceil((msgLen + 4) / 256) * 256);
    new DataView(padded.buffer).setUint32(0, msgLen, true);
    padded.set(msgBytes, 4);
    crypto.getRandomValues(padded.subarray(4 + msgLen));

    const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, padded);
    const ctBytes = new Uint8Array(ctBuf);

    // Sign ephPub || iv || ciphertext so the signature also binds the body of
    // the message — flipping any of them invalidates the signature.
    const ephPubBytes = hexToBytes(ephPubHex);
    const sigInput = new Uint8Array(ephPubBytes.length + iv.length + ctBytes.length);
    sigInput.set(ephPubBytes, 0);
    sigInput.set(iv, ephPubBytes.length);
    sigInput.set(ctBytes, ephPubBytes.length + iv.length);
    const sigBuf = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      senderSignPriv,
      sigInput
    );

    return {
      ephPubHex,
      ciphertext: bytesToHex(ctBytes),
      iv: bytesToHex(iv),
      signature: bytesToHex(new Uint8Array(sigBuf)),
    };
  }

  static async decryptMessageEphemeral(envelope, recipientEcdhPriv, recipientEcdhPubHex, senderSignPub) {
    const { ephPubHex, ciphertext, iv, signature } = envelope;

    // Verify signature first when available — fails fast on tampered or
    // forged envelopes before we touch the AES-GCM machinery. senderSignPub
    // is null for legacy contacts that have no signing key on file.
    if (senderSignPub) {
      const sigInput = new Uint8Array([
        ...hexToBytes(ephPubHex),
        ...hexToBytes(iv),
        ...hexToBytes(ciphertext),
      ]);
      const ok = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        senderSignPub,
        hexToBytes(signature),
        sigInput
      );
      if (!ok) throw new Error('Signature verification failed');
    }

    const ephPub = await SecurityManager.importPublicKeyHex(ephPubHex);
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephPub },
      recipientEcdhPriv,
      256
    );
    const hkdfKey = await crypto.subtle.importKey(
      'raw', sharedBits, 'HKDF', false, ['deriveKey']
    );
    const sortedPubs = [ephPubHex, recipientEcdhPubHex].sort();
    const info = new TextEncoder().encode('blind-edge-v2|' + sortedPubs.join('|'));
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const ptBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: hexToBytes(iv) },
      aesKey,
      hexToBytes(ciphertext)
    );
    const padded = new Uint8Array(ptBuf);
    const msgLen = new DataView(padded.buffer).getUint32(0, true);
    const text = new TextDecoder().decode(padded.subarray(4, 4 + msgLen));
    const inner = JSON.parse(text);
    return { counter: inner.c, plaintext: inner.m };
  }

  // Derive a deterministic identity from a BIP39 seed (64 bytes from mnemonicToSeed).
  // HKDF expands the seed into two distinct 32-byte scalars, one per keypair.
  // We compute the public point (scalar·G) with the BigInt math above and
  // import both halves as JWK. (An earlier version imported the bare scalar
  // as PKCS#8 and let Web Crypto derive the public key — Chrome and Firefox
  // accept that, but WebKit throws DataError, which broke identity creation
  // on iPhone/iPad/Safari. JWK with explicit x/y works everywhere and yields
  // byte-identical keys, so existing addresses are preserved.)
  static async deriveIdentityFromSeed(seed64) {
    const hkdfKey = await crypto.subtle.importKey('raw', seed64, 'HKDF', false, ['deriveBits']);

    async function scalarKeypair(info, name, usages, verifyUsage) {
      const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(info) },
        hkdfKey, 256
      );
      const d = _mod(_bytesToBigInt(new Uint8Array(bits)), P256.n);
      if (d === 0n) throw new Error('Derived scalar is zero — re-derive with different entropy');
      const point = _scalarMultG(d);
      const base = {
        kty: 'EC', crv: 'P-256',
        x: _b64url(_bigIntTo32(point[0])),
        y: _b64url(_bigIntTo32(point[1])),
      };
      const privateKey = await crypto.subtle.importKey(
        'jwk', { ...base, d: _b64url(_bigIntTo32(d)) },
        { name, namedCurve: 'P-256' }, true, usages
      );
      const publicKey = await crypto.subtle.importKey(
        'jwk', base,
        { name, namedCurve: 'P-256' }, true, verifyUsage
      );
      return { publicKey, privateKey };
    }

    const ecdh = await scalarKeypair('blind-edge-ecdh-v2', 'ECDH', ['deriveKey', 'deriveBits'], []);
    const sign = await scalarKeypair('blind-edge-ecdsa-v2', 'ECDSA', ['sign'], ['verify']);
    return { ecdh, sign };
  }

  // ─── Group encryption ────────────────────────────────────────────────────────

  static async groupEncrypt(text, groupKeyHex, senderSignPriv, groupIdHex, senderHash) {
    const aesKey = await crypto.subtle.importKey(
      'raw', hexToBytes(groupKeyHex), { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ivHex = bytesToHex(iv);

    const sigInput = new TextEncoder().encode(ivHex + groupIdHex + senderHash + text);
    const sigBuf = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, senderSignPriv, sigInput);

    const inner = JSON.stringify({
      type: 'group-msg', group_id: groupIdHex,
      sender_hash: senderHash, text,
      sig: bytesToHex(new Uint8Array(sigBuf)),
      ts: Date.now(),
    });

    const plainBytes = new TextEncoder().encode(inner);
    const plainLen = plainBytes.length;
    const padded = new Uint8Array(4 + Math.ceil((plainLen + 4) / 256) * 256);
    new DataView(padded.buffer).setUint32(0, plainLen, true);
    padded.set(plainBytes, 4);
    crypto.getRandomValues(padded.subarray(4 + plainLen));

    const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, padded);
    return { ciphertext: bytesToHex(new Uint8Array(ctBuf)), iv: ivHex };
  }

  static async groupDecrypt(ciphertext, iv, groupKeyHex) {
    const aesKey = await crypto.subtle.importKey(
      'raw', hexToBytes(groupKeyHex), { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    try {
      const ptBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hexToBytes(iv) }, aesKey, hexToBytes(ciphertext)
      );
      const padded = new Uint8Array(ptBuf);
      const msgLen = new DataView(padded.buffer).getUint32(0, true);
      return JSON.parse(new TextDecoder().decode(padded.subarray(4, 4 + msgLen)));
    } catch {
      return null;
    }
  }

  static async groupVerifySig(inner, iv, signPubKey) {
    const sigInput = new TextEncoder().encode(iv + inner.group_id + inner.sender_hash + inner.text);
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' }, signPubKey, hexToBytes(inner.sig), sigInput
    );
  }

  static async encryptVault(data, masterKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      masterKey,
      new TextEncoder().encode(JSON.stringify(data))
    );

    return {
      ciphertext: bytesToHex(new Uint8Array(ciphertextBuf)),
      iv: bytesToHex(iv),
    };
  }

  static async decryptVault(ciphertext, iv, masterKey) {
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: hexToBytes(iv) },
      masterKey,
      hexToBytes(ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(plaintextBuf));
  }

  // Identity bundle v2: holds both the ECDH (encryption) and ECDSA (signing)
  // long-term keypairs. The two private keys — and, for seed-derived
  // identities, the BIP39 entropy behind the recovery phrase — are wrapped
  // together under the password-derived master key, so the 12 words are only
  // readable after unlock.
  static async exportIdentityBundle(ecdhKeypair, signKeypair, masterKey, salt, entropyHex = null) {
    const ecdhJwk = await crypto.subtle.exportKey('jwk', ecdhKeypair.privateKey);
    const signJwk = await crypto.subtle.exportKey('jwk', signKeypair.privateKey);
    const vault = { ecdhPriv: ecdhJwk, signPriv: signJwk };
    if (entropyHex) vault.entropy = entropyHex;
    const encryptedPrivateKeys = await SecurityManager.encryptVault(vault, masterKey);
    const ecdhPubHex = await SecurityManager.exportPublicKeyHex(ecdhKeypair.publicKey);
    const signPubHex = await SecurityManager.exportSignPublicKeyHex(signKeypair.publicKey);

    return JSON.stringify({
      version: 2,
      ecdhPubHex,
      signPubHex,
      encryptedPrivateKeys,
      salt: bytesToHex(salt),
    });
  }

  static async importIdentityBundle(json, masterKey) {
    const parsed = JSON.parse(json);

    if (parsed.version === 1) {
      // v1 → v2 migration: decrypt the single ECDH JWK, mint a fresh ECDSA
      // signing keypair, and signal the caller to re-export and overwrite the
      // bundle in localStorage. The ECDH key (and therefore the server-facing
      // key hash) is preserved across the migration.
      const jwk = await SecurityManager.decryptVault(
        parsed.encryptedPrivateKey.ciphertext,
        parsed.encryptedPrivateKey.iv,
        masterKey
      );
      const ecdhPriv = await crypto.subtle.importKey(
        'jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
      );
      const ecdhPub = await SecurityManager.importPublicKeyHex(parsed.publicKeyHex);
      const sign = await SecurityManager.generateSigningIdentity();
      return {
        ecdh: { publicKey: ecdhPub, privateKey: ecdhPriv },
        sign,
        salt: hexToBytes(parsed.salt),
        migratedFromV1: true,
        entropyHex: null,
        entropyWasPlaintext: false,
      };
    }

    if (parsed.version !== 2) {
      throw new Error(`Unsupported bundle version: ${parsed.version}`);
    }

    const { ecdhPriv, signPriv, entropy } = await SecurityManager.decryptVault(
      parsed.encryptedPrivateKeys.ciphertext,
      parsed.encryptedPrivateKeys.iv,
      masterKey
    );
    const ecdhPrivateKey = await crypto.subtle.importKey(
      'jwk', ecdhPriv, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
    );
    const signPrivateKey = await crypto.subtle.importKey(
      'jwk', signPriv, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
    );
    const ecdhPublicKey = await SecurityManager.importPublicKeyHex(parsed.ecdhPubHex);
    const signPublicKey = await SecurityManager.importSignPublicKeyHex(parsed.signPubHex);

    // Bundles written before v1.5 stored seed entropy as a plaintext
    // top-level field. Honor it, and report it so the caller can rewrap it
    // inside the encrypted vault on this unlock.
    const legacyEntropy = (!entropy && typeof parsed.entropy === 'string') ? parsed.entropy : null;

    return {
      ecdh: { publicKey: ecdhPublicKey, privateKey: ecdhPrivateKey },
      sign: { publicKey: signPublicKey, privateKey: signPrivateKey },
      salt: hexToBytes(parsed.salt),
      migratedFromV1: false,
      entropyHex: entropy || legacyEntropy || null,
      entropyWasPlaintext: !!legacyEntropy,
    };
  }
}
