// Pinit AI - Resilient Offline Support Service Worker
const CACHE_NAME = 'pinit-v3';

// Install event: activate immediately
self.addEventListener('install', () => {
  self.skipWaiting();
});

// Activate event: purge all old caches immediately
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event: Network-First for HTML navigation; bypass for API and dev
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') {
    return;
  }

  const url = new URL(event.request.url);

  // Bypass service worker for local development ports and API calls
  if (
    url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' ||
    url.port === '8000' ||
    url.port === '5000' ||
    url.port === '4000' ||
    url.port === '5173' ||
    url.port === '4173' ||
    url.pathname.startsWith('/api') ||
    url.pathname.startsWith('/analyze') ||
    url.pathname.startsWith('/analysis')
  ) {
    return;
  }

  // Network-First for navigation (HTML documents): always fetch latest HTML with new asset hashes
  if (event.request.mode === 'navigate' || url.pathname === '/' || url.pathname === '/index.html') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response && response.status === 200) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseClone));
          }
          return response;
        })
        .catch(() => {
          return caches.match(event.request).then((cached) => cached || caches.match('/index.html'));
        })
    );
    return;
  }

  // For other requests, try network first to prevent serving stale 404 chunk hashes
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200) {
          const responseClone = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, responseClone));
        }
        return networkResponse;
      })
      .catch(() => {
        return caches.match(event.request);
      })
  );
});
