// coi-serviceworker.js — rend la page "cross-origin isolated" sur hébergeur statique
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  const req = event.request;
  event.respondWith((async () => {
    const res = await fetch(req, { cache: 'no-store', credentials: 'same-origin' });
    const newHeaders = new Headers(res.headers);
    // Ajoute les en-têtes requis pour SharedArrayBuffer / WASM threads
    newHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');
    newHeaders.set('Cross-Origin-Embedder-Policy', 'require-corp');
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers: newHeaders });
  })());
});
