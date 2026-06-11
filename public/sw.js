const CACHE_NAME = 'blind-edge-v12';
const APP_SHELL = [
  '/',
  '/index.html',
  '/app.js',
  '/bip39.js',
  '/crypto.js',
  '/storage.js',
  '/hex.js',
  '/qr.js',
  '/manifest.json',
  '/logo.svg',
  '/icon.svg',
  '/icon-192.png',
  '/icon-512.png',
  '/apple-touch-icon.png'
];

// ------------------------------------------------------------------ //
// Install: cache the app shell                                         //
// ------------------------------------------------------------------ //
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL))
  );
  // Take over immediately — don't wait for old tabs to close
  self.skipWaiting();
});

// ------------------------------------------------------------------ //
// Activate: prune stale caches                                         //
// ------------------------------------------------------------------ //
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_NAME)
          .map(k => caches.delete(k))
      )
    )
  );
  // Claim all open clients so the new SW is active immediately
  self.clients.claim();
});

// ------------------------------------------------------------------ //
// Fetch: routing strategy                                              //
// ------------------------------------------------------------------ //
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip cross-origin requests (CDN, fonts, etc.) — let the browser
  // handle its own HTTP cache for those.
  if (url.origin !== self.location.origin) {
    return;
  }

  // Network-first for API calls so messages are always fresh.
  // Fall back to cache (useful for offline stale reads, though the
  // Worker API likely won't have a useful cached response).
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(
      fetch(request)
        .then(response => {
          // Cache a copy of successful API responses
          if (response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
          }
          return response;
        })
        .catch(() => caches.match(request))
    );
    return;
  }

  // Cache-first for all app-shell assets.
  // On a miss, fetch from the network and cache the result.
  event.respondWith(
    caches.match(request).then(cached => {
      if (cached) return cached;

      return fetch(request).then(response => {
        // Only cache valid same-origin responses
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, clone));
        }
        return response;
      });
    })
  );
});
