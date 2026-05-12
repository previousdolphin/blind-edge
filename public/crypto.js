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

  static async _deriveSharedAesKey(theirPublicKey, ourPrivateKey) {
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

    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32),
        info: new TextEncoder().encode('blind-edge-v1'),
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  static async encryptMessage(plaintext, recipientPubKey, senderPrivKey) {
    const aesKey = await SecurityManager._deriveSharedAesKey(recipientPubKey, senderPrivKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Pad to next 256-byte boundary to defeat traffic-length analysis.
    // Format: [4-byte LE message length][message bytes][random padding]
    const msgBytes = new TextEncoder().encode(plaintext);
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

  static async decryptMessage(ciphertext, iv, senderPubKey, recipientPrivKey) {
    const aesKey = await SecurityManager._deriveSharedAesKey(senderPubKey, recipientPrivKey);

    try {
      const plaintextBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hexToBytes(iv) },
        aesKey,
        hexToBytes(ciphertext)
      );
      // Unpad: read 4-byte LE length prefix, extract that many bytes
      const padded = new Uint8Array(plaintextBuf);
      const msgLen = new DataView(padded.buffer).getUint32(0, true);
      return new TextDecoder().decode(padded.subarray(4, 4 + msgLen));
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
