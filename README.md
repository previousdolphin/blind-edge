<img src="public/logo.svg" alt="B.E.Chat — Blind-Edge Messenger" width="540">

# B.E.Chat — Blind-Edge Messenger

> End-to-end encrypted, local-first messaging with a zero-knowledge relay.  
> No accounts. No plaintext on the wire. Deployable in under 5 minutes.

**Built entirely with [Claude Code](https://claude.ai/code) in a single session** as a live demonstration of AI-assisted full-stack development. The cryptographic core, local database, relay API, and complete PWA were generated, wired together, debugged, and deployed without leaving the terminal.

**Try it now:** [blind-edge.pages.dev](https://blind-edge.pages.dev) — works immediately with the shared demo relay. No sign-up required.

---

## What the server can and cannot see

| Field | Server receives | Server can read |
|---|---|---|
| Message content | Padded hex ciphertext | **Nothing** |
| Sender | SHA-256 of their public key | A hash — no name, no identity |
| Recipient | SHA-256 of their public key | A hash — no name, no identity |
| Your password | Never transmitted | — |
| Your private key | Never transmitted | — |
| Your contacts | Never transmitted | — |
| Message timing | Envelope `created_at` | When, not who or what |

The server is a **blind relay**. It accepts ciphertext addressed to a key hash and serves it back to whoever presents that hash. It cannot decrypt, cannot log identities, and has no user table.

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

**Primitives — all native [`window.crypto.subtle`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto), zero libraries:**

| Primitive | Purpose |
|---|---|
| ECDH P-256 (ephemeral) | Per-message key agreement — sender-side forward secrecy |
| ECDSA P-256 | Envelope signing — message authenticity |
| HKDF SHA-256 | Key derivation — shared secret → AES key, bound to both public keys |
| AES-256-GCM | Authenticated encryption of message content |
| PBKDF2 SHA-256 (600k rounds) | App Password → vault key for private keys at rest |
| SHA-256 | Public key → recipient hash (your "address") |

---

## Stack

| Layer | Technology | Why |
|---|---|---|
| Crypto | Web Crypto API (native) | No dependencies, no supply chain risk |
| Local DB | sql.js + IndexedDB | SQLite in the browser, persistent across sessions |
| Relay API | Any serverless platform | ~100 lines of JS — runs anywhere |
| Remote DB | Any SQLite-compatible store | One table, two columns indexed |
| Frontend | Vanilla JS ES Modules | No bundler, no framework, instant load |
| PWA | Service Worker + Web App Manifest | Installable, offline-capable |

**Production npm dependencies: 0.** The only runtime deps are CDN-loaded (sql.js WASM, Google Fonts) and never touch message content.

---

## Try it — no setup required

The app ships pre-configured with a shared demo relay:

1. Open [blind-edge.pages.dev](https://blind-edge.pages.dev)
2. Create an identity (or import one)
3. Tap **Key** → **Copy Key** — your key is two P-256 public keys joined by a colon (`ecdhKey:signingKey`). Share this string out-of-band with your contact (Signal, in person, etc.)
4. Have them share their key string → tap **+ Add**, paste it, give them a name
5. Start messaging

> **Key format:** The combined key string is ~262 characters (`130 hex + : + 130 hex`). Both parties need the full string for signature verification. A 130-char ECDH-only key also works in legacy mode — encrypted but not signed.

The demo relay is operational but **shared** — deploy your own for private production use.

---

## Deploy your own

The relay is ~100 lines of plain JavaScript implementing two routes (`POST /api/send`, `GET /api/sync`) against a single SQLite table. It runs on any platform that can execute JS and talk to a database. The frontend is a static folder — deployable to any static host.

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

### 7. Update allowed origins in `worker/wrangler.toml`

```toml
[vars]
ALLOWED_ORIGINS = "http://localhost:8080,https://YOUR-PROJECT.pages.dev"
```

Then redeploy: `npm run worker:deploy`

### 8. Update the default relay URL in `public/app.js`

```js
const DEMO_WORKER_URL = 'https://blind-edge-api.YOUR-SUBDOMAIN.workers.dev';
```

### 9. Deploy the frontend

```bash
# First time only
npx wrangler pages project create blind-edge --production-branch main

# Deploy
npx wrangler pages deploy public --project-name blind-edge
```

### 10. Test it

Open your Pages URL in two different browsers. Create an identity on each, exchange public keys, add each other as contacts, and send a message. It should arrive within 15 seconds (the default sync interval).

---

## Relay API contract

Any replacement relay must implement these two routes. The `worker/index.js` is the reference implementation.

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

Returns `200 { envelopes: [{ id, senderHash, ciphertext, iv, createdAt }] }`.

The relay must return CORS headers for browser clients. It needs no auth, no user table, and no knowledge of message content.

---

## Local development

```bash
# Serve the frontend on localhost:8080
npm run dev

# In a second terminal — run the Worker locally (Cloudflare)
cd worker && npx wrangler dev --remote

# The local Worker runs at http://localhost:8787
# In the app, go to Settings → Worker URL → http://localhost:8787
```

---

## `worker/wrangler.toml` — reference

```toml
name = "blind-edge-api"
main = "index.js"
compatibility_date = "2024-12-01"

[triggers]
crons = ["0 */6 * * *"]   # prune envelopes older than 24h every 6 hours

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
- **Local-first** — messages written to local IndexedDB instantly; works offline
- **No accounts** — identity is a browser-generated keypair locked with your App Password
- **Sender-side forward secrecy** — per-message ephemeral ECDH; past messages safe if long-term key leaks
- **Signed envelopes** — ECDSA signature over ephemeral key + ciphertext; tampered messages rejected before decryption
- **Replay protection** — monotonic counter inside every ciphertext; out-of-order or replayed messages dropped
- **Message padding** — all payloads padded to 256-byte blocks; ciphertext length reveals nothing about message length
- **Message autodestruct** — per-conversation TTL (1h / 12h / 24h / 7 days) prunes locally on schedule
- **Server-side envelope TTL** — relay prunes envelopes older than 24 hours on a schedule; no unbounded accumulation
- **IP rate limiting** — relay enforces 30 sends/min and 180 syncs/min per IP
- **Identity portability** — export/import your encrypted key bundle to move between devices
- **Secure export flow** — key export requires explicit checkbox confirmation with a risk warning
- **Installable PWA** — add to home screen on iOS/Android/desktop
- **Identicons** — deterministic pixel-art avatars from public keys for fast out-of-band verification

---

## Limitations (by design)

- **Text only** — no image/file transfer
- **Sender-side PFS only** — ephemeral ECDH protects the sender's past messages; full bidirectional PFS (à la Signal's Double Ratchet) would require prekey bundles published by the recipient
- **Manual key exchange** — contacts are added by sharing a public key string out-of-band; no discovery server
- **No group messaging** — strictly pairwise conversations
- **Local history only** — message history does not sync between devices; only new messages arrive after import
- **Shared relay** — the demo relay is shared infrastructure; run your own for production privacy

---

## Project structure

```
blind-edge/
├── public/              # Frontend — static, no build step
│   ├── index.html       # App shell + all CSS
│   ├── app.js           # Orchestration, sync engine, UI
│   ├── crypto.js        # SecurityManager — all WebCrypto operations
│   ├── hex.js           # Shared hex encoding with strict validation
│   ├── storage.js       # StorageManager — sql.js + IndexedDB
│   ├── sw.js            # Service worker (PWA caching)
│   ├── logo.svg         # B.E.Chat logo
│   └── manifest.json    # PWA manifest
├── worker/              # Reference relay — Cloudflare Workers + D1
│   ├── index.js         # POST /api/send  GET /api/sync  scheduled cleanup
│   ├── schema.sql       # D1 schema (portable SQLite)
│   └── wrangler.toml    # Cloudflare deployment config
├── test/
│   └── crypto.test.mjs  # 18 automated crypto tests (npm test)
└── package.json
```

---

## npm scripts

| Script | What it does |
|---|---|
| `npm run dev` | Serve `public/` on `localhost:8080` |
| `npm test` | Run 18 automated crypto tests via node:test |
| `npm run db:create` | *(Cloudflare)* Create a D1 database named `blind-edge-db` |
| `npm run db:init` | *(Cloudflare)* Push `worker/schema.sql` to the remote D1 database |
| `npm run worker:dev` | *(Cloudflare)* Run the Worker locally |
| `npm run worker:deploy` | *(Cloudflare)* Deploy the Worker to the edge |

---

## What Claude built in one session

This entire project was generated by [Claude Code](https://claude.ai/code) from a natural-language specification — then iteratively hardened across follow-up sessions. The work covered:

- Full cryptographic protocol: PBKDF2 vault, ECDH, ECDHE (per-message ephemeral keys), ECDSA signing, HKDF key binding, AES-256-GCM, monotonic replay counters, 256-byte message padding — all native Web Crypto API, zero libraries
- Local SQLite via sql.js WASM with IndexedDB persistence (cross-browser, including Safari)
- Reference relay implementation on Cloudflare Workers + D1 with parameterized queries, CORS validation, rate limiting, and scheduled TTL pruning
- PWA manifest and service worker with cache-first shell + network-first API strategy
- Complete UI: auth flows, contact management, live chat, settings, modals, toast notifications, identicons
- Security hardening: identity export warning, per-conversation autodestruct, v1→v2 identity migration
- 18-test automated suite via node:test
- B.E.Chat branding: SVG logo with chrome bubble letters and blindfolded hero

---

## License

MIT — fork it, deploy it, improve it.
