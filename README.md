<img src="public/logo.svg" alt="B.E.Chat — Blind-Edge Messenger" width="540">

# B.E.Chat — Blind-Edge Messenger

> End-to-end encrypted, local-first messaging with a zero-knowledge relay.  
> No accounts. No plaintext on the wire. Deployable in under 5 minutes.

**Built entirely with [Claude Code](https://claude.ai/code) in a single session** as a live demonstration of AI-assisted full-stack development. The cryptographic core, local database, Cloudflare Worker API, and complete PWA were generated, wired together, debugged, and deployed without leaving the terminal.

**Try it now:** [blind-edge.pages.dev](https://blind-edge.pages.dev) — works immediately with the shared demo relay. No sign-up required.

---

## What the server can and cannot see

| Field | Server receives | Server can read |
|---|---|---|
| Message content | Hex ciphertext | **Nothing** |
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
  Alice's device                          Relay (Cloudflare Worker + D1)
  ──────────────────                      ────────────────────────────────
  plaintext message
    │
    ├─ ECDH(Alice.privKey, Bob.pubKey)
    │  → 256-bit shared secret
    │
    ├─ HKDF(secret, info="blind-edge-v1")
    │  → AES-256-GCM key
    │
    ▼
  { ciphertext, iv } ─── POST /api/send ─► stored as-is, unreadable

  Bob's device
  ──────────────────
  GET /api/sync?for=SHA256(Bob.pubKey) ◄── envelopes for Bob's hash
    │
    ├─ ECDH(Bob.privKey, Alice.pubKey)
    │  → same shared secret  (ECDH is commutative)
    │
    ├─ HKDF → same AES-256-GCM key
    │
    ▼
  plaintext ✓
```

**Primitives used — all native [`window.crypto.subtle`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto), zero libraries:**

| Primitive | Purpose |
|---|---|
| ECDH P-256 | Key agreement — shared secret from two keypairs |
| HKDF SHA-256 | Key derivation — shared secret → AES key |
| AES-256-GCM | Authenticated encryption of message content |
| PBKDF2 SHA-256 (600k rounds) | App Password → vault key for private key at rest |
| SHA-256 | Public key → recipient hash (your "address") |

---

## Stack

| Layer | Technology | Why |
|---|---|---|
| Crypto | Web Crypto API (native) | No dependencies, no supply chain risk |
| Local DB | sql.js + IndexedDB | SQLite in the browser, persistent across sessions |
| Relay API | Cloudflare Workers | Edge-deployed, serverless, generous free tier |
| Remote DB | Cloudflare D1 | Serverless SQLite, same free tier |
| Frontend | Vanilla JS ES Modules | No bundler, no framework, instant load |
| PWA | Service Worker + Web App Manifest | Installable, offline-capable |

**Production npm dependencies: 0.** The only runtime deps are CDN-loaded (sql.js WASM, Google Fonts) and never touch message content.

---

## Try it — no setup required

The app ships pre-configured with a shared demo relay:

1. Open [blind-edge.pages.dev](https://blind-edge.pages.dev)
2. Create an identity (or import one)
3. Tap **Key** → copy your public key → share it with your contact out-of-band
4. Have them share theirs → tap **+ Add** to add them as a contact
5. Start messaging

The demo relay is operational but **shared** — use your own Worker for private production use.

---

## Deploy your own — full walkthrough

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

> **Apple Silicon / Mac:** Wrangler authenticates via browser — no API token needed for local dev.

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

Open `worker/wrangler.toml` and replace the placeholder:

```toml
[[d1_databases]]
binding = "DB"
database_name = "blind-edge-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # ← paste here
```

### 5. Push the schema to the remote database

```bash
npm run db:init
```

Expected output:
```
🌀 Executing on remote database blind-edge-db (...)
🚣 Executed 2 queries in ~3ms (5 rows written)
```

This creates the `envelopes` table and its index. Run it once — it uses `CREATE TABLE IF NOT EXISTS` so it's safe to re-run.

### 6. Deploy the Worker

```bash
npm run worker:deploy
```

Expected output:
```
Uploaded blind-edge-api (1.69 sec)
Deployed blind-edge-api triggers (0.77 sec)
  https://blind-edge-api.YOUR-SUBDOMAIN.workers.dev   ← note this URL
```

Your Worker is now live. The URL format is always `https://blind-edge-api.ACCOUNT-SUBDOMAIN.workers.dev`.

### 7. Update the allowed origins in `worker/wrangler.toml`

Open `worker/wrangler.toml` and update `ALLOWED_ORIGINS` with your Pages domain once you know it (after step 9):

```toml
[vars]
ALLOWED_ORIGINS = "http://localhost:8080,https://YOUR-PROJECT.pages.dev"
```

Then redeploy the worker: `npm run worker:deploy`

### 8. Update the default relay URL in `public/app.js`

Open `public/app.js` and replace the demo URL with your own:

```js
const DEMO_WORKER_URL = 'https://blind-edge-api.YOUR-SUBDOMAIN.workers.dev';
```

### 9. Deploy the frontend to Cloudflare Pages

```bash
# First time — create the Pages project
npx wrangler pages project create blind-edge --production-branch main

# Deploy the public/ folder
npx wrangler pages deploy public --project-name blind-edge
```

Expected output:
```
✨ Deployment complete!
  https://blind-edge.pages.dev
```

### 10. Test it

Open your Pages URL in two different browsers (or two devices). Create an identity on each, exchange public keys, add each other as contacts, and send a message. It should arrive within 15 seconds (the default sync interval).

---

## Local development

```bash
# Serve the frontend on localhost:8080
npm run dev

# In a second terminal — run the Worker locally against the remote D1
cd worker && npx wrangler dev --remote

# The local Worker runs at http://localhost:8787
# In the app, go to Settings → Worker URL → http://localhost:8787
```

> The Worker **must** use `--remote` to access the real D1 database. Without it, it runs against a local SQLite file and messages won't sync between devices.

---

## `worker/wrangler.toml` — full reference

```toml
name = "blind-edge-api"
main = "index.js"
compatibility_date = "2024-12-01"

[[d1_databases]]
binding = "DB"
database_name = "blind-edge-db"
database_id = "YOUR-DATABASE-ID"    # from: npm run db:create

[vars]
# Comma-separated list of allowed frontend origins (no trailing slash)
ALLOWED_ORIGINS = "http://localhost:8080,https://YOUR-PROJECT.pages.dev"

# Maximum ciphertext hex length (~64KB default)
MAX_CIPHERTEXT_LENGTH = "131072"
```

---

## Features

- **Zero-knowledge relay** — server stores and forwards ciphertext it cannot read
- **Local-first** — messages written to local IndexedDB instantly; works offline
- **No accounts** — identity is a browser-generated keypair locked with your App Password
- **Message autodestruct** — per-conversation TTL (1h / 12h / 24h / 7 days) prunes locally on schedule
- **Identity portability** — export/import your encrypted key bundle to move between devices
- **Secure export flow** — key export requires explicit checkbox confirmation with a detailed risk warning
- **Installable PWA** — add to home screen on iOS/Android/desktop
- **Pending retry** — outgoing messages marked `pending` are retried on every sync cycle
- **Message padding** — all payloads padded to 256-byte blocks before encryption; ciphertext length reveals nothing about message length
- **Server-side envelope TTL** — Cloudflare Cron Trigger prunes envelopes older than 24 hours every 6 hours; relay never accumulates ciphertext indefinitely
- **IP rate limiting** — Worker enforces 30 sends/min and 180 syncs/min per IP to resist relay flooding
- **Identicons** — contacts and your own identity display a deterministic pixel-art avatar derived from the public key, making out-of-band key verification faster and less error-prone than comparing raw hex

---

## Limitations (by design)

- **Text only** — no image/file transfer
- **No forward secrecy** — ECDH keys are static per identity; a future version could layer a Double Ratchet on top
- **Manual key exchange** — contacts are added by sharing public key hex out-of-band; no discovery server
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
│   ├── storage.js       # StorageManager — sql.js + IndexedDB
│   ├── sw.js            # Service worker (PWA caching)
│   ├── logo.svg         # B.E.Chat logo
│   └── manifest.json    # PWA manifest
├── worker/              # Cloudflare Worker — blind relay
│   ├── index.js         # POST /api/send  GET /api/sync
│   ├── schema.sql       # D1 schema
│   └── wrangler.toml    # Deployment config
└── package.json         # Scripts: dev, db:create, db:init, worker:deploy
```

---

## npm scripts

| Script | What it does |
|---|---|
| `npm run dev` | Serve `public/` on `localhost:8080` |
| `npm run db:create` | Create a new Cloudflare D1 database named `blind-edge-db` |
| `npm run db:init` | Push `worker/schema.sql` to the remote D1 database |
| `npm run worker:dev` | Run the Worker locally (use `--remote` flag for real D1) |
| `npm run worker:deploy` | Deploy the Worker to Cloudflare's edge |

---

## What Claude built in one session

This entire project was generated by [Claude Code](https://claude.ai/code) from a natural-language specification. The session covered:

- Full cryptographic layer (PBKDF2, ECDH, HKDF, AES-GCM, SHA-256) using only the native Web Crypto API
- Local SQLite via sql.js WASM with IndexedDB persistence (cross-browser compatible)
- Cloudflare Worker with D1 — parameterized queries, CORS validation, hex/hash input sanitization
- PWA manifest and service worker with cache-first shell + network-first API strategy
- Complete UI: auth flows, contact management, live chat, settings, modals, toast notifications
- Cloudflare D1 database creation, schema migration, and Worker deployment via wrangler CLI
- Cloudflare Pages deployment for the static frontend
- Security hardening: identity export warning with checkbox confirmation, per-conversation autodestruct
- B.E.Chat branding: SVG logo with chrome bubble letters and blindfolded hero

---

## License

MIT — fork it, deploy it, improve it.
