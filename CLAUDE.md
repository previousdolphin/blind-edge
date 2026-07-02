# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

B.E.Chat (Blind-Edge Messenger) is an end-to-end encrypted, local-first messaging PWA with a zero-knowledge relay. Everything — keys, contacts, message history — lives in the browser; the server is a "blind mailbox" that only stores opaque ciphertext addressed to SHA-256 hashes of public keys. There are no accounts and **zero production runtime dependencies**.

## Commands

```bash
npm install          # dev deps only (wrangler, serve) — no runtime deps exist
npm run dev          # serve public/ on localhost:8080 (static, no build step)
npm run worker:dev   # run the Cloudflare relay locally on localhost:8787
npm test             # full test suite (node --test test/*.test.mjs; needs node 20+, CI uses 22)
```

Run a single test file: `node --test test/crypto.test.mjs`. Filter by name: `node --test --test-name-pattern="HKDF" test/crypto.test.mjs`.

Point the running app at a local relay via **Menu → Relay URL → `http://localhost:8787`**.

Worker/D1 lifecycle: `npm run db:create` (creates the D1 DB), `npm run db:init` (applies `worker/schema.sql`), `npm run worker:deploy`. See README "Cloudflare deployment" for the full walkthrough including the `database_id` and `ALLOWED_ORIGINS` steps.

## Architecture

Two independent halves that only communicate through the relay's HTTP contract:

**Frontend** (`public/`, vanilla ES modules, no framework/bundler):
- `crypto.js` — `SecurityManager`, a static-method class wrapping native `window.crypto.subtle`. All cryptography lives here: ephemeral-ECDH per-message encryption, ECDSA envelope signing, HKDF key derivation, the identity vault (PBKDF2 600k → AES-GCM), BIP39 seed → deterministic keypair derivation, and group encryption. Includes a minimal BigInt P-256 implementation for the deterministic seed-derivation path.
- `storage.js` — `StorageManager`, wraps sql.js (SQLite compiled to WASM, CDN-loaded) persisted to IndexedDB. Owns the **local** schema (contacts, messages, groups, group_members, contact_requests, settings, sync_state) and a versioned `_migrate()`. This is the only durable store of user data.
- `app.js` — the entire UI controller and orchestration layer (~1800 lines): onboarding, chat rendering, the sync poll loop (`startSync`/`runSync`), contact/group management, share-code discovery, deep-link handling. `DEMO_WORKER_URL` at the top is the default relay.
- `bip39.js` — self-contained BIP39 (full official 2048-word list). `qr.js` — own-code QR encoder (byte mode, ISO 18004), no dependency. `hex.js` — hex helpers. `sw.js` — service worker / app-shell cache.
- `index.html` (main app shell + inline styles), `intro.html` (marketing/how-it-works), `manifest.json` (PWA).

**Relay** (`worker/`, Cloudflare Workers + D1):
- `index.js` — ~200 lines, four routes: `POST /api/send`, `GET /api/sync`, `POST /api/meet` (register share code), `GET /api/meet` (look up share code). In-memory per-IP rate limiting, strict hex/hash input validation, CORS gated by `ALLOWED_ORIGINS`, and a cron `scheduled()` handler that prunes envelopes >24h and expired rendezvous every 6h.
- `schema.sql` — the **remote** schema: `envelopes` (recipient_hash, sender_hash, ciphertext, iv, created_at) and `rendezvous` (meeting_hash → public_key, TTL). The relay stores nothing else and can decrypt nothing.

The relay contract is deliberately portable (README lists Deno/AWS/Fly/VPS alternatives); `worker/index.js` is the reference implementation, not a hard dependency.

### Crypto model (must understand before touching `crypto.js`)

- Each message uses a fresh ephemeral ECDH keypair; the shared secret feeds HKDF whose `info` string is versioned and bound to **both** sorted public keys (`blind-edge-v1|<sorted pubs>`), then AES-256-GCM. The `encryptMessage`/`decryptMessage` pair wraps plaintext in a `{v:2, c:counter, m:plaintext}` envelope so a strictly-monotonic counter travels *inside* the ciphertext for replay protection; `decryptMessage` returns `counter:null` for legacy v1 raw-plaintext messages. The `*Ephemeral` variants add ECDSA signing/verification.
- Identities are **seed-first**: fresh BIP39 entropy → 12 words → deterministic P-256 ECDH + ECDSA keypairs. The same words reproduce the exact same keys and address on any device. Recovery entropy is sealed inside the encrypted vault, not stored in plaintext.
- There are live **migration paths**: v1→v2 identity bundles (mint a fresh signing key), legacy plaintext-entropy bundles (rewrapped on next unlock), and legacy non-signing contacts (signature verification skipped). Preserve these when editing — tests in `test/identity.test.mjs` and `test/crypto.test.mjs` enforce byte-for-byte address preservation across them.

## Conventions (from CONTRIBUTING.md — these are non-negotiable)

1. **Zero runtime dependencies.** Native Web Crypto and vanilla ES modules only — no npm runtime packages, no bundler. If a feature needs a library, write the minimal subset yourself (`qr.js` is the model). sql.js WASM and fonts load from CDN and never touch message content.
2. **Bump the service worker on every shipped asset change.** Increment `CACHE_NAME` in `public/sw.js` and add any new file to `APP_SHELL`, or users run stale code.
3. **Copy must be truthful.** Every user-facing sentence about crypto or storage must match what the code actually does. When in doubt, understate.
4. **Tests pass; new crypto/encoding code needs tests.** The BIP39 conformance vectors exist because two recovery-breaking bugs shipped without them — treat crypto changes as recovery-critical and test against known vectors.

Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`), subject under 72 chars. Icon PNGs are regenerated from `public/icon.svg` (see CONTRIBUTING.md).
