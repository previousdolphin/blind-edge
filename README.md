<img src="public/logo.svg" alt="B.E.Chat — Blind-Edge Messenger" width="540">

# B.E.Chat — Blind-Edge Messenger

> End-to-end encrypted, local-first messaging with a zero-knowledge relay.
> No accounts. No plaintext on the wire. Deployable in under 5 minutes.

**Built entirely with [Claude Code](https://claude.ai/code)** (originally Opus, and then revised with Fable 5) as a live demonstration of AI-assisted full-stack development — and of a simple idea: a messenger where **everything lives on your device** and the server is a blind mailbox anyone can run.

**Try it now:** [blind-edge.pages.dev](https://blind-edge.pages.dev) — works immediately with the shared demo relay. No sign-up, no email, no phone number.

---

## Try it — 60 seconds, two phones

1. Open [blind-edge.pages.dev](https://blind-edge.pages.dev) on both phones
2. Tap **Create my identity** → set a local password → pick a backup: the **encrypted export file is safest** (sealed with your password), or skip entirely — disposable identities are a feature
3. On the "You're ready" screen, have your friend **scan your QR with their camera app** — it opens B.E.Chat with your key filled in; their app introduces them and you just tap **Accept**
4. Start messaging

Not in the same room? Tap **+ Add → Share code**, get a 6-letter code, and say it out loud over a call. It works for 10 minutes and the relay only ever sees its hash.

---

## Install it like an app

The site is a full PWA — installed, it launches full-screen, works offline, and the browser is far less likely to evict your data.

| Platform | How |
|---|---|
| **iPhone / iPad** | Safari → **Share** (square-with-arrow) → **Add to Home Screen** → Add |
| **Android** | Chrome shows an install prompt, or use **Menu → Install as an app** inside B.E.Chat |
| **Desktop** | Chrome/Edge: install icon in the address bar, or **Menu → Install as an app** |

> iOS note: Safari can evict site data after ~7 days of disuse. Installing to the Home Screen prevents that — and your 12 recovery words protect you regardless.

---

## What the relay can and cannot see

| Field | Relay receives | Relay can read |
|---|---|---|
| Message content | Padded hex ciphertext | **Nothing** |
| Sender | SHA-256 of their public key | A hash — no name, no identity |
| Recipient | SHA-256 of their public key | A hash — no name, no identity |
| Your password | Never transmitted | — |
| Your private keys | Never transmitted | — |
| Your contacts | Never transmitted | — |
| Timing & size | Envelope `created_at`; length padded to 256-byte blocks | When and roughly how much — not who or what |

The relay is a **blind mailbox**. It accepts ciphertext addressed to a key hash and serves it back to whoever presents that hash. It cannot decrypt, has no user table, holds envelopes at most 24 hours, and rate-limits per IP. The app itself will show you the raw envelope it sends — **How it works → "Show me the actual bytes."**

---

## The recovery model

This is the part most apps get wrong, so here it is plainly:

- **The encrypted export is the safest backup** (**ID → Export backup file**, offered during onboarding too). It contains your keys sealed under your App Password — useless to anyone without it, so it survives being stored somewhere imperfect. It holds keys only — not contacts, not messages.
- **Your 12 words are the password-free fallback.** Every identity is derived from fresh BIP39 entropy; restoring the words on any device reproduces the *exact same keys and address* — contacts can still reach you. The flip side: anyone who sees them can be you, so they're never displayed during onboarding — view them in private, behind an explicit two-step reveal, via **ID → Recovery words** (at rest they live encrypted inside the vault).
- **Message history never leaves your devices.** That's the point: there is no server copy to recover — for you *or* for an attacker. Lose the device without a backup and the history is gone; the identity survives via the export or the words.
- **No words, no export, lost device → identity is gone permanently.** Nobody can reset it, because nobody else has it.
- **Burner mode is a feature.** Skip the backup, use an identity for a session, then **Menu → Delete this identity**. Fresh keys take five seconds — new address, clean slate. Old contacts can't reach the new you.

---

## How encryption works

```
  Alice's device                          Blind Relay (any serverless host)
  ──────────────────                      ──────────────────────────────────
  plaintext message
    │
    ├─ generate ephemeral ECDH keypair (per message)
    │
    ├─ ECDH(ephemeralPriv, Bob.ecdhPubKey)
    │  → 256-bit shared secret
    │
    ├─ HKDF(secret, info="blind-edge-v2|sorted(ephPub, bobPub)")
    │  → AES-256-GCM key
    │
    ├─ pad plaintext to 256-byte block boundary
    │
    ├─ AES-256-GCM encrypt {counter, plaintext}
    │
    ├─ ECDSA sign (ephPub ‖ iv ‖ ciphertext) with Alice.signKey
    │
    ▼
  { ephPubHex, ciphertext, iv, signature } ── POST /api/send ──► stored as-is

  Bob's device
  ──────────────────
  GET /api/sync?for=SHA256(Bob.ecdhPubKey) ◄── envelopes for Bob's hash
    │
    ├─ verify ECDSA signature against Alice.signPubKey
    │
    ├─ ECDH(Bob.ecdhPrivKey, ephemeralPubKey)
    │  → same 256-bit shared secret
    │
    ├─ HKDF → same AES-256-GCM key
    │
    ├─ decrypt + unpad → verify counter > lastSeen (replay protection)
    │
    ▼
  plaintext ✓
```

**Groups** use a shared AES-256-GCM key distributed to each member via the existing 1:1 ECDH-encrypted path. Group messages are encrypted once and sent to the relay at `SHA-256(group_id)`; all members poll that address. The relay is unaware it is serving a group. When a member is added or removed, a new random key is generated and distributed only to the current members — the departing member's key is immediately invalidated.

**Primitives — all native [`window.crypto.subtle`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto), zero libraries:**

| Primitive | Purpose |
|---|---|
| ECDH P-256 (ephemeral) | Per-message key agreement — sender-side forward secrecy |
| ECDSA P-256 | Envelope signing — message authenticity |
| HKDF SHA-256 | Key derivation — shared secret → AES key, bound to both public keys; also seed → deterministic keypair |
| AES-256-GCM | Authenticated encryption of message content, group messages, and the identity vault |
| PBKDF2 SHA-256 (600k rounds) | App Password → vault key for private keys + recovery entropy at rest |
| PBKDF2 SHA-512 (2048 rounds) | BIP39 seed phrase → 64-byte seed (standard BIP39 derivation) |
| SHA-256 | Public key → recipient hash (your "address"); share code → relay address |

**QR key exchange** is an own-code, zero-dependency QR encoder (`public/qr.js`, byte mode, ECC L, versions 1–15, full mask selection per ISO 18004). The QR encodes a deep link (`https://…/#add=<publicKeys>`) so the other person's *native camera app* opens B.E.Chat with the key pre-filled — no in-app scanner required, and URL fragments never reach any server.

---

## Stack

| Layer | Technology | Why |
|---|---|---|
| Crypto | Web Crypto API (native) | No dependencies, no supply chain risk |
| Local DB | sql.js + IndexedDB | SQLite in the browser, persistent across sessions |
| QR | Own-code encoder (`qr.js`) | Zero dependencies, SVG output, verified against Apple Vision decoder |
| Relay API | Any serverless platform | ~200 lines of JS — runs anywhere |
| Remote DB | Any SQLite-compatible store | Two tiny tables |
| Frontend | Vanilla JS ES Modules | No bundler, no framework, instant load |
| PWA | Service Worker + Web App Manifest | Installable, offline-capable |

**Production npm dependencies: 0.** The only runtime deps are CDN-loaded (sql.js WASM, Google Fonts) and never touch message content.

---

## Deploy your own

The relay is ~200 lines of plain JavaScript implementing three routes against two SQLite tables. It runs on any platform that can execute JS and talk to a database. The frontend is a static folder — deployable to any static host.

### Relay options

| Platform | Notes |
|---|---|
| **Cloudflare Workers + D1** | Included (`worker/`). Free tier, edge-deployed, zero config beyond auth. |
| **Deno Deploy** | Swap D1 for Deno KV or a Turso SQLite. No wrangler needed. |
| **AWS Lambda + DynamoDB** | Replace D1 queries with DynamoDB SDK calls. |
| **Fly.io / Railway / Render** | Run the worker as a Node.js HTTP server, SQLite on disk. |
| **Any VPS** | Node/Bun + better-sqlite3 behind nginx. |

### Frontend hosting options

Any static host works — the `public/` folder has no build step.

| Platform | Command |
|---|---|
| **Cloudflare Pages** | `npx wrangler pages deploy public --project-name blind-edge` |
| **Netlify** | `netlify deploy --dir public --prod` |
| **Vercel** | `vercel --prod public` |
| **GitHub Pages** | Push `public/` to a `gh-pages` branch |
| **Any CDN / S3** | Upload `public/` and point your domain at it |

---

## Cloudflare deployment — full walkthrough

The `worker/` directory is a ready-to-deploy Cloudflare Workers implementation. If you prefer a different platform, use this as a reference for the relay API contract.

### Prerequisites

- [Node.js 18+](https://nodejs.org)
- A free [Cloudflare account](https://cloudflare.com) — no credit card required for the free tier

### 1. Clone the repo

```bash
git clone https://github.com/previousdolphin/blind-edge.git
cd blind-edge
npm install
```

### 2. Authenticate with Cloudflare

```bash
npx wrangler login
```

This opens a browser window. Log in with your Cloudflare account. When prompted, grant **all** permissions (Workers, D1, Pages). The session is stored locally via `wrangler`.

### 3. Create the D1 database

```bash
npm run db:create
```

Expected output:
```
✅ Successfully created DB 'blind-edge-db' in region ENAM

[[d1_databases]]
binding = "DB"
database_name = "blind-edge-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   ← copy this
```

### 4. Paste the database ID into `worker/wrangler.toml`

```toml
[[d1_databases]]
binding = "DB"
database_name = "blind-edge-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # ← paste here
```

### 5. Push the schema

```bash
npm run db:init
```

**Verify it worked:**
```bash
cd worker && npx wrangler d1 execute blind-edge-db --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table'"
# expect: envelopes, rendezvous
```

### 6. Deploy the Worker

```bash
npm run worker:deploy
```

Expected output:
```
Uploaded blind-edge-api (1.69 sec)
Deployed blind-edge-api triggers (0.77 sec)
  https://blind-edge-api.YOUR-SUBDOMAIN.workers.dev   ← note this URL
  schedule: 0 */6 * * *
```

**Verify it worked** (an empty sync against a dummy address):
```bash
curl "https://blind-edge-api.YOUR-SUBDOMAIN.workers.dev/api/sync?for=$(printf '0%.0s' {1..64})&since=0"
# expect: {"envelopes":[]}
```

### 7. Create the Pages project (so you know your frontend URL)

```bash
npx wrangler pages project create blind-edge --production-branch main
# your URL will be https://blind-edge-XXX.pages.dev (or your custom domain)
```

### 8. Update allowed origins in `worker/wrangler.toml` and redeploy

```toml
[vars]
ALLOWED_ORIGINS = "http://localhost:8080,https://YOUR-PROJECT.pages.dev"
```

```bash
npm run worker:deploy
```

### 9. Point the frontend at your relay and deploy it

In `public/app.js`:
```js
const DEMO_WORKER_URL = 'https://blind-edge-api.YOUR-SUBDOMAIN.workers.dev';
```

```bash
npx wrangler pages deploy public --project-name blind-edge
```

### 10. Test it end-to-end

Open your Pages URL in two different browsers (or browser + phone). Create an identity on each, add each other via QR or share code, and send a message. It should arrive within 15 seconds (the default sync interval). The relay-status dot in the conversations header should read **relay connected**.

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Browser console shows CORS errors; sends fail with no relay response | `ALLOWED_ORIGINS` doesn't exactly match your Pages URL (scheme + host, no trailing slash). Fix `wrangler.toml`, redeploy the worker. |
| `Send failed (403)` | Same CORS/origin issue, or the rate limiter (30 sends/min/IP) — wait a minute. |
| "Code not found or expired" | Share codes live 10 minutes and are deleted on relay restart in dev. Get a fresh one. |
| Stale UI after deploying | The service worker caches the app shell. Bump `CACHE_NAME` in `public/sw.js` for every deploy (this repo does), then reload twice. |
| `npm run db:init` errors about binding | The `database_id` in `wrangler.toml` doesn't match step 3's output. |
| Messages never arrive | Both clients must point at the **same relay** (Menu → Relay URL). Check the relay-status dot. |
| Demo-relay messages vanish after a day | By design: the relay deletes all envelopes after 24h. Delivered messages are already on the recipient's device. |

---

## Relay API contract

Any replacement relay must implement these routes. `worker/index.js` is the reference implementation.

**`POST /api/send`**

```json
{
  "recipient_hash": "<64-char hex SHA-256>",
  "sender_hash":    "<64-char hex SHA-256>",
  "ciphertext":     "<hex, max 131072 chars>",
  "iv":             "<24-char hex>"
}
```

Returns `201 { ok: true, id: <rowId> }` or a 4xx error.

**`GET /api/sync?for=<recipientHash>&since=<timestampMs>`**

Returns `200 { envelopes: [{ id, senderHash, ciphertext, iv, createdAt }] }` (max 50, ascending by `createdAt`).

**`POST /api/meet`** — ephemeral discovery (10-min TTL)

```json
{ "meeting_hash": "<64-char hex SHA-256 of the 6-char code>", "public_key": "<ecdhHex:signHex>" }
```

Returns `201 { ok: true, expires_at: <timestampMs> }`. The relay never sees the raw code — only its hash.

**`GET /api/meet?hash=<64-char hex>`**

Returns `200 { public_key }` or `404` if expired/not found.

The relay must return CORS headers for browser clients. It needs no auth, no user table, and no knowledge of message content.

---

## Local development

```bash
# Serve the frontend on localhost:8080
npm run dev

# In a second terminal — run the Worker locally (Cloudflare)
cd worker && npx wrangler dev

# The local Worker runs at http://localhost:8787
# In the app: Menu → Relay URL → http://localhost:8787
```

```bash
npm test   # 36 tests: crypto protocol, BIP39 vectors, identity vault, QR encoder
```

---

## `worker/wrangler.toml` — reference

```toml
name = "blind-edge-api"
main = "index.js"
compatibility_date = "2024-12-01"

[triggers]
crons = ["0 */6 * * *"]   # prune envelopes older than 24h, every 6 hours

[[d1_databases]]
binding = "DB"
database_name = "blind-edge-db"
database_id = "YOUR-DATABASE-ID"

[vars]
ALLOWED_ORIGINS = "http://localhost:8080,https://YOUR-PROJECT.pages.dev"
MAX_CIPHERTEXT_LENGTH = "131072"
```

---

## Features

- **Zero-knowledge relay** — server stores and forwards ciphertext it cannot read
- **Local-first** — messages written to local IndexedDB instantly; works offline; relay-status indicator when it doesn't
- **No accounts** — identity is a browser-generated keypair locked with your App Password
- **Seed-first identities** — every identity is born from 12 BIP39 words; restore on any device → same keys, same address. Words are stored *encrypted inside the vault*, viewable post-unlock
- **QR key exchange** — zero-dependency QR encoder; the other person scans with their native camera, no in-app scanner needed
- **One-tap share codes** — 6-character codes (10-min TTL) for remote key exchange; relay sees only SHA-256(code); live countdown in the UI
- **Burner mode** — first-class disposable identities: skip backup honestly, delete identity + local data in one tap
- **"What's on this device" panel** — live inventory of exactly what's stored locally, including the honest plaintext-at-rest caveat
- **"Show me the actual bytes"** — inspect the real envelope the app last sent to the relay
- **Group chat** — multi-user groups with a shared AES-256-GCM key, creator-only admin, auto-accept invites; relay is unaware of groups
- **Group key rotation** — new random key generated and distributed on every membership change; removed members cannot read future messages
- **Sender-side forward secrecy** — per-message ephemeral ECDH; past sent messages safe if long-term keys leak
- **Signed envelopes** — ECDSA signature over ephemeral key + ciphertext; tampered messages rejected before decryption
- **Replay protection** — monotonic counter inside every ciphertext; out-of-order or replayed messages dropped
- **Message padding** — all payloads padded to 256-byte blocks; ciphertext length reveals nothing about message length
- **Auto-delete** — per-conversation local expiry (1h / 12h / 24h / 7 days)
- **Server-side envelope TTL** — relay prunes envelopes older than 24 hours; no unbounded accumulation
- **IP rate limiting** — relay enforces 30 sends/min and 180 syncs/min per IP
- **Identity portability** — export/import your encrypted key bundle; gated behind an explicit risk warning
- **Installable PWA** — real icons, install prompt on Android/desktop, guided Add-to-Home-Screen on iOS
- **Identicons** — deterministic pixel-art avatars from public keys for fast out-of-band verification

---

## Limitations (honest, by design)

- **Keys are trusted on first use** — no safety numbers yet. For high-stakes contacts, exchange QRs in person or compare identicons over a channel you trust.
- **Sender-side PFS only** — ephemeral ECDH protects sent messages; full bidirectional PFS (à la Signal's Double Ratchet) would require prekey bundles published by the recipient.
- **Local history is stored readable** — the App Password encrypts your keys, not the message database. Use OS disk encryption and a screen lock.
- **Local history only** — message history does not sync between devices; a restored identity receives only new messages.
- **Relays see metadata** — timing, padded sizes, IPs. The demo relay is shared infrastructure; run your own for production privacy.
- **Text only** — no image/file transfer.
- **Not audited** — this is an open-source protocol demo. Read `SECURITY.md` before trusting it with anything that matters.

---

## Project structure

```
blind-edge/
├── public/                  # Frontend — static, no build step
│   ├── index.html           # App shell + all CSS + onboarding/trust copy
│   ├── app.js               # Orchestration, onboarding flow, sync engine, UI
│   ├── crypto.js            # SecurityManager — all WebCrypto operations
│   ├── bip39.js             # Official 2048-word list, mnemonic encode/decode, seed derivation
│   ├── qr.js                # Zero-dependency QR encoder (byte mode, ECC L, v1–15)
│   ├── hex.js               # Shared hex encoding with strict validation
│   ├── storage.js           # StorageManager — sql.js + IndexedDB, per-identity isolation
│   ├── sw.js                # Service worker (PWA caching)
│   ├── icon.svg / *.png     # App icons (regen recipe in CONTRIBUTING.md)
│   ├── logo.svg             # B.E.Chat logo
│   └── manifest.json        # PWA manifest
├── worker/                  # Reference relay — Cloudflare Workers + D1
│   ├── index.js             # /api/send  /api/sync  /api/meet  + scheduled cleanup
│   ├── schema.sql           # D1 schema (portable SQLite)
│   └── wrangler.toml        # Cloudflare deployment config
├── test/
│   ├── crypto.test.mjs      # Protocol tests (HKDF binding, signatures, replay, padding)
│   ├── bip39.test.mjs       # Official BIP39 vectors + round-trip fuzz
│   ├── identity.test.mjs    # Seed-first determinism + vault round-trips + migration
│   └── qr.test.mjs          # QR structural verification + RS math + inverse pipeline
├── SECURITY.md              # Threat model, scope, reporting
├── CONTRIBUTING.md          # Ground rules (zero deps, sw bumps, icon regen)
├── LICENSE                  # MIT
└── package.json
```

---

## npm scripts

| Script | What it does |
|---|---|
| `npm run dev` | Serve `public/` on `localhost:8080` |
| `npm test` | Run 36 automated tests via node:test |
| `npm run db:create` | *(Cloudflare)* Create a D1 database named `blind-edge-db` |
| `npm run db:init` | *(Cloudflare)* Push `worker/schema.sql` to the remote D1 database |
| `npm run worker:dev` | *(Cloudflare)* Run the Worker locally |
| `npm run worker:deploy` | *(Cloudflare)* Deploy the Worker to the edge |

---

## What Claude built

This entire project was generated by [Claude Code](https://claude.ai/code) from natural-language specifications, then iteratively hardened across follow-up sessions:

- Full cryptographic protocol: PBKDF2 vault, ECDH, ECDHE (per-message ephemeral keys), ECDSA signing, HKDF key binding, AES-256-GCM, monotonic replay counters, 256-byte message padding — all native Web Crypto API, zero libraries
- Seed-first identity: every identity derived from BIP39 entropy (PBKDF2-SHA512 → HKDF → deterministic P-256 keypairs via a PKCS8 DER trick, no EC math library), with recovery entropy sealed inside the encrypted vault
- A zero-dependency QR encoder (Reed-Solomon over GF(256), full mask-penalty selection) verified against Apple's Vision decoder, plus camera-app deep links for key exchange
- Onboarding built around informed consent: what was just created, where it lives, what the relay sees, what backup means — including a first-class disposable-identity path
- Ephemeral share codes: 6-char one-time codes with SHA-256 relay registration, 10-min TTL
- Multi-user group chat: shared AES-256-GCM key, key rotation on every membership change, zero relay changes
- Per-identity IndexedDB isolation; local SQLite via sql.js WASM (cross-browser, including Safari)
- Reference relay on Cloudflare Workers + D1 with parameterized queries, CORS validation, rate limiting, scheduled TTL pruning
- Installable PWA: icons, manifest, install prompts, iOS guidance, cache-first shell + network-first API service worker
- A 36-test suite (node:test) including official BIP39 conformance vectors — which caught and fixed two real recovery-breaking bugs (a truncated wordlist and a bit-packing error)
- B.E.Chat branding: SVG logo with chrome bubble letters and blindfolded hero

---

## License

[MIT](LICENSE) — fork it, deploy it, improve it.
