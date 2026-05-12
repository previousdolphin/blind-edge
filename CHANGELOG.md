# Changelog

All notable changes to B.E.Chat are documented here.

---

## v1.1.0 — 2025-05-11 Security & UX hardening

### Security — Cryptography

**PBKDF2: 210,000 → 600,000 rounds**
The OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256 is 600,000 iterations. This makes brute-forcing the App Password against the encrypted vault key ~3× harder on modern hardware/GPUs. Existing vault keys are re-derived at your next unlock automatically (the salt is stored with the vault; no migration needed).

**Message padding (traffic-length analysis resistance)**
All messages are now padded to the nearest 256-byte boundary before encryption. An adversary monitoring ciphertext lengths on the wire can no longer distinguish a one-word reply from a paragraph. The format is a 4-byte little-endian length prefix followed by the message bytes, padded to the next 256-byte block with random bytes. The padding is encrypted along with the message and stripped on the recipient's side after authenticated decryption.

### Security — Server (Cloudflare Worker)

**Server-side envelope TTL cron**
A Cloudflare Cron Trigger fires every 6 hours and deletes any envelopes older than 24 hours from the D1 database. Previously the relay had no automatic pruning; this prevents unbounded DB growth and limits how long intercepted ciphertext persists on the relay even if a device never syncs.

**IP-based rate limiting**
The Worker now tracks per-IP request counts in module-level memory. Limits: 30 sends / minute, 180 syncs / minute per IP. Requests over the limit receive a `429 Rate limit exceeded` response. This raises the cost of flooding the relay with garbage ciphertext. Note: per Cloudflare Workers architecture, limits apply per isolate instance; they provide meaningful friction against naive abuse rather than a cryptographic hard cap.

### UX

**Visual key verification — identicons**
Contact avatars and the Your Identity modal now display a deterministic 5×5 symmetric pixel identicon derived from the public key. Comparing identicons out-of-band is faster and more error-resistant than visually scanning 130-character hex strings. The color and pattern are unique to each key; two different keys will produce visually distinct icons.

---

## v1.0.0 — 2025-05-10 Initial release

- Full E2EE layer: ECDH P-256 + HKDF SHA-256 + AES-256-GCM, native Web Crypto API only
- Local-first SQLite via sql.js WASM, persisted to IndexedDB (Safari-compatible)
- Cloudflare Workers + D1 zero-knowledge relay
- PWA: service worker, web app manifest, installable
- Per-conversation message autodestruct (TTL: 1h / 12h / 24h / 7 days)
- Identity export with double-confirmation warning flow
- B.E.Chat logo with chrome bubble letters and blindfolded hero
- In-app "How it works" explainer modal
- Pre-configured demo relay — works without any setup
