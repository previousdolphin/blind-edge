# Contributing

PRs welcome. Ground rules keep this project what it is: a small, auditable,
zero-dependency protocol demo.

## Non-negotiables

1. **Zero runtime dependencies.** The frontend uses native Web Crypto and
   vanilla ES modules only. No npm runtime packages, no bundler. (sql.js WASM
   and fonts load from CDN and never touch message content.) If a feature needs
   a library, write the minimal subset yourself — see `public/qr.js` for the
   pattern.
2. **Bump the service worker on every shipped asset change.** Increment
   `CACHE_NAME` in `public/sw.js` and add any new files to `APP_SHELL`,
   or users will run stale code.
3. **Copy must be truthful.** Every user-facing sentence about crypto or
   storage must match what the code actually does. When in doubt, understate.
4. **Tests pass.** `npm test` (node 20+). New crypto or encoding code needs
   tests — the BIP39 conformance vectors in `test/bip39.test.mjs` exist because
   two recovery-breaking bugs shipped without them.

## Dev setup

```bash
npm install          # dev deps only (wrangler, serve)
npm run dev          # frontend on localhost:8080
npm run worker:dev   # relay on localhost:8787 (separate terminal)
npm test             # full suite
```

Point the app at the local relay: **Menu → Relay URL → `http://localhost:8787`**.

## Icon regeneration

`public/icon.svg` is the source. To regenerate the PNGs (macOS, no
ImageMagick needed):

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
  --screenshot=public/icon-512.png --window-size=512,512 \
  "file://$PWD/public/icon.svg"
sips -z 192 192 public/icon-512.png --out public/icon-192.png
sips -z 180 180 public/icon-512.png --out public/apple-touch-icon.png
```

## Commit style

Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`). Keep the
subject under 72 chars; explain *why* in the body when it isn't obvious.
