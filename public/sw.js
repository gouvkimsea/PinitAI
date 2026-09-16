// ScamCheck AI - Offline Support Service Worker
const CACHE_NAME = 'scamcheck-v2';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/favicon.svg',
  '/logo.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Only intercept and cache idempotent GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  // Do not intercept API requests or scan endpoints
  const url = new URL(event.request.url);
  if (
    url.port === '8000' ||
    url.port === '5000' ||
    url.pathname.startsWith('/api') ||
    url.pathname.startsWith('/analyze') ||
    url.pathname.startsWith('/analysis')
  ) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      return (
        cachedResponse ||
        fetch(event.request).catch(() => {
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html');
          }
        })
      );
    })
  );
});
