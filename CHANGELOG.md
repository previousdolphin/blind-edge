# Changelog

All notable changes to B.E.Chat are documented here.

---

## v1.5.0 — 2026-06-11 Onboarding, trust & installability overhaul

### Fixed — Critical recovery bugs

**BIP39 wordlist was truncated (1906 of 2048 words)**
Any generated phrase hitting a word index ≥ 1906 produced `undefined` words —
roughly half of new seed-derived identities could not be written down or
restored. Replaced with the official BIP39 English list (verified against the
canonical SHA-256) and added conformance tests with official spec vectors.

**`mnemonicToEntropy` bit-packing error**
A negative shift count (`val << (5 - bitShift)` with bitShift > 5, which JS
wraps mod 32) silently corrupted the repacked entropy, failing the checksum
for most real mnemonics — seed-phrase restore was effectively broken. Fixed
with explicit 24-bit window packing; fuzz-tested over 500 round-trips.

**Seed reveal was broken** — `doRevealSeedPhrase` called async
`entropyToMnemonic` without `await`, throwing at runtime.

### Changed — Identity & recovery

- **Seed-first identities**: every new identity is derived from fresh BIP39
  entropy, so every identity has 12 recovery words (previously password-created
  identities had none). Same words → same keys → same address on any device.
- **Recovery entropy is now sealed inside the encrypted vault** (was plaintext
  in localStorage for restored identities). Legacy bundles are rewrapped
  automatically on the next successful unlock.
- Pre-seed identities get an honest in-app note: their backup is the JSON
  export; no retroactive phrase is possible.

### Added — Onboarding & trust surfaces

- Welcome screen explaining the model in three cards before any password prompt
- Post-generation seed-backup step: "I wrote them down" or a first-class
  "Skip — disposable session" burner path, both with plain-language stakes
- "You're ready" screen: identicon, address, and your QR
- "What's on this device" live inventory in Settings (sizes, counts, the honest
  plaintext-at-rest caveat)
- "Show me the actual bytes" — inspect the last real envelope sent to the relay
- Reworked How-it-works explainer: device storage / relay table with metadata
  row / lost-keys / burner mode / honest limitations
- Relay status indicator (connected / unreachable — will retry); sync failures
  are no longer silent
- "Lock & Clear Session" renamed to **Lock** (it never cleared anything) and a
  real **Delete this identity from this device** action added

### Added — Contact exchange

- **QR key exchange**: own-code zero-dependency QR encoder (byte mode, ECC L,
  v1–15, full mask selection; verified against Apple's Vision decoder). QRs
  encode a `#add=` deep link the native camera opens — no in-app scanner needed.
- Share-code flow merged to one tap ("Get a share code") with a live countdown
- Didactic-but-brief security notes at each exchange surface (expandable "why")

### Added — PWA installability

- Real app icons (icon.svg source + 512/192/apple-touch PNGs) — Android
  install was previously broken by missing icon files
- `beforeinstallprompt` capture + "Install as an app" in Settings; guided
  Add-to-Home-Screen sheet for iOS
- Manifest fixes (`id`, `scope`, split any/maskable purposes)

### Added — Repo hygiene

- LICENSE (MIT), SECURITY.md (threat model + scope), CONTRIBUTING.md,
  GitHub Actions test workflow, package.json metadata
- Test suite 18 → 36: BIP39 official vectors, identity vault round-trips,
  QR structural + Reed-Solomon verification
- Module docstrings in crypto.js / storage.js / worker explaining the security
  rationale inline

---

## v1.2.0 — 2026-05-12 Cryptographic protocol upgrade

### Security — Cryptography

**HKDF key-binding fix (reflection attack)**
The original protocol derived the same shared AES key for both Alice→Bob and Bob→Alice messages — a reflection attack where either party could decrypt the other's outbound ciphertext. Fixed by binding the HKDF `info` string to `blind-edge-v1|sorted(ecdhPubA, ecdhPubB)`. Both sides independently compute the same info regardless of role, producing a unique per-pair key.

**Monotonic replay counter**
A strictly-monotonic counter `c` is now embedded inside every AES-GCM ciphertext. The relay cannot observe or tamper with it. Each client tracks the last-seen counter per contact and silently drops any message with `counter ≤ lastSeen`, blocking replay and reorder attacks. Legacy ciphertexts (no counter) are accepted once with a warning and never advance the counter.

**Per-message ephemeral ECDH (ECDHE) — sender-side forward secrecy**
Every outgoing message generates a fresh P-256 ephemeral keypair. The recipient decrypts using ECDH between their static key and the message's ephemeral public key. Once the JS engine garbage-collects the ephemeral private key, past ciphertexts cannot be decrypted even if the sender's long-term key is later compromised. Full bidirectional PFS would require X3DH-style prekey bundles; this provides sender-side PFS with no server changes.

**ECDSA envelope signing**
Each ephemeral envelope is signed with the sender's long-term ECDSA P-256 key over `ephPub ‖ iv ‖ ciphertext`, binding the signature to the entire message body. Verification happens before decryption (fail-fast on forgery). Legacy contacts without a signing key on file skip verification gracefully.

**Identity bundle v2**
Identities now hold two long-term keypairs: ECDH (encryption) and ECDSA (signing), encrypted together under the vault key. v1 bundles are migrated transparently on next unlock — the ECDH key (and therefore your address) is preserved, a fresh signing key is minted, and the upgraded bundle is persisted automatically.

### Key format change

The public key string shared out-of-band is now `ecdhKey:signingKey` (~262 chars). Contacts added with only a legacy ECDH key (130 chars) continue to work in compatibility mode — encrypted but without signature verification.

### Developer

**Test suite** — 18 automated tests via `node:test` covering HKDF binding, counter semantics, tamper detection, legacy compatibility, hex validation, ephemeral round-trips, and bundle migration. Run with `npm test`.

**`hex.js` utility** — `hexToBytes`/`bytesToHex` extracted to a shared module with strict type, charset, and length validation.

---

## v1.1.0 — 2026-05-11 Security & UX hardening

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
