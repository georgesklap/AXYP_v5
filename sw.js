/* ΑΞΥΠ service worker: αποθηκεύει μόνο τα αρχεία της εφαρμογής. Τα δεδομένα τα διαχειρίζεται το app.js. */
const SHELL = 'axyp-shell-v1';
const FILES = ['./', 'index.html', 'style.css', 'app.js', 'manifest.webmanifest',
  'icons/icon-192.png', 'icons/icon-512.png', 'icons/maskable-512.png', 'icons/apple-touch-icon.png', 'icons/favicon-32.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(SHELL).then(c => c.addAll(FILES)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k.startsWith('axyp-shell-') && k !== SHELL).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.includes('/data/')) return;              // δεδομένα: πάντα από το δίκτυο (το app.js κρατά αντίγραφο)
  e.respondWith(fetch(e.request).then(r => {                 // δίκτυο πρώτα, ώστε οι ενημερώσεις εφαρμογής να φτάνουν άμεσα
    if (r.ok) { const cp = r.clone(); caches.open(SHELL).then(c => c.put(e.request, cp)); }
    return r;
  }).catch(() => caches.match(e.request).then(m => m || caches.match('index.html'))));
});
