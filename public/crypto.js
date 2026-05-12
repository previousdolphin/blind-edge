import { hexToBytes, bytesToHex } from './hex.js';

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

  static async exportIdentityBundle(keypair, masterKey, salt) {
    const jwk = await crypto.subtle.exportKey('jwk', keypair.privateKey);
    const encryptedPrivateKey = await SecurityManager.encryptVault(jwk, masterKey);
    const publicKeyHex = await SecurityManager.exportPublicKeyHex(keypair.publicKey);

    return JSON.stringify({
      version: 1,
      publicKeyHex,
      encryptedPrivateKey,
      salt: bytesToHex(salt),
    });
  }

  static async importIdentityBundle(json, masterKey) {
    const parsed = JSON.parse(json);

    if (parsed.version !== 1) {
      throw new Error(`Unsupported bundle version: ${parsed.version}`);
    }

    const jwk = await SecurityManager.decryptVault(
      parsed.encryptedPrivateKey.ciphertext,
      parsed.encryptedPrivateKey.iv,
      masterKey
    );

    const privateKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );

    const publicKey = await SecurityManager.importPublicKeyHex(parsed.publicKeyHex);
    const salt = hexToBytes(parsed.salt);

    return { publicKey, privateKey, salt };
  }
}
