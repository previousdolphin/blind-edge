import { hexToBytes, bytesToHex } from './hex.js';

// PKCS8 DER prefix for a P-256 private key (RFC 5958 / SEC 1).
// Structure: PrivateKeyInfo { version=0, ecPublicKey OID, P-256 OID, ECPrivateKey { version=1, privateKey=<32 bytes> } }
// The 32-byte private scalar is appended directly after this prefix.
const P256_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07,
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04,
  0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
]);

function buildP256PKCS8(scalar32) {
  const der = new Uint8Array(P256_PKCS8_PREFIX.length + 32);
  der.set(P256_PKCS8_PREFIX);
  der.set(scalar32.slice(0, 32), P256_PKCS8_PREFIX.length);
  return der.buffer;
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
  // PKCS8 DER import lets Web Crypto compute public key coordinates internally;
  // we then extract x/y from the JWK export to build the usable public key object.
  static async deriveIdentityFromSeed(seed64) {
    const hkdfKey = await crypto.subtle.importKey('raw', seed64, 'HKDF', false, ['deriveBits']);

    async function scalarKeypair(info, name, usages, verifyUsage) {
      const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(info) },
        hkdfKey, 256
      );
      const privateKey = await crypto.subtle.importKey(
        'pkcs8', buildP256PKCS8(new Uint8Array(bits)),
        { name, namedCurve: 'P-256' }, true, usages
      );
      // Export JWK to get x/y (Web Crypto computed them from the scalar)
      const jwk = await crypto.subtle.exportKey('jwk', privateKey);
      const publicKey = await crypto.subtle.importKey(
        'jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y },
        { name, namedCurve: 'P-256' }, true, verifyUsage
      );
      return { publicKey, privateKey };
    }

    const ecdh = await scalarKeypair('blind-edge-ecdh-v2', 'ECDH', ['deriveKey', 'deriveBits'], []);
    const sign = await scalarKeypair('blind-edge-ecdsa-v2', 'ECDSA', ['sign'], ['verify']);
    return { ecdh, sign };
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
  // long-term keypairs. The two private keys are wrapped together under the
  // password-derived master key.
  static async exportIdentityBundle(ecdhKeypair, signKeypair, masterKey, salt) {
    const ecdhJwk = await crypto.subtle.exportKey('jwk', ecdhKeypair.privateKey);
    const signJwk = await crypto.subtle.exportKey('jwk', signKeypair.privateKey);
    const encryptedPrivateKeys = await SecurityManager.encryptVault(
      { ecdhPriv: ecdhJwk, signPriv: signJwk },
      masterKey
    );
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
      };
    }

    if (parsed.version !== 2) {
      throw new Error(`Unsupported bundle version: ${parsed.version}`);
    }

    const { ecdhPriv, signPriv } = await SecurityManager.decryptVault(
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

    return {
      ecdh: { publicKey: ecdhPublicKey, privateKey: ecdhPrivateKey },
      sign: { publicKey: signPublicKey, privateKey: signPrivateKey },
      salt: hexToBytes(parsed.salt),
      migratedFromV1: false,
    };
  }
}
