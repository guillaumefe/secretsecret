# DEPLOY.md — Secure Deployment Guide

This guide explains how to deploy the CBOX web app and its Argon2 strict worker safely on any host, and how to enable cache-busting with hashed assets while keeping the worker’s exact URL allowlist consistent.

TL;DR:
- Serve all assets over HTTPS, same origin, with correct MIME types.
- The worker only loads `argon2-bundled.min.js` and `argon2.wasm` from an exact allowlist of absolute URLs.
- If file names or query strings change, update the allowlist inside `argon-worker.js`.
- On hosts without custom headers (e.g., GitHub Pages), keep filenames stable or use the included COOP/COEP service worker (`register-coi-sw.js`).

---

## 1) Files to deploy

Serve the following from the same origin (preferably the same directory):

- `index.html`
- `styles.css`
- `app.js`
- `argon-worker.js`
- `argon2-bundled.min.js`
- `argon2.wasm`
- `eff_large_wordlist.txt`
- `favicon.ico`

Optional:
- `argon-worker-permissive.js` (only if explicitly chosen)
- `register-coi-sw.js` (COOP/COEP shim on header-less hosts)
- Additional icons and documentation

Deployment under a sub-path is supported, e.g. `https://example.com/cbox/`.

---

## 2) Required MIME types

```
.wasm  → application/wasm
.js    → application/javascript
.css   → text/css; charset=utf-8
.html  → text/html; charset=utf-8
.txt   → text/plain; charset=utf-8
```

Note: If the server returns `text/javascript` for `.js`, either configure the server to use `application/javascript` or relax the worker’s JS MIME check (see §8).

---

## 3) Security headers (recommended)

If custom headers are supported, set:

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  worker-src 'self';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self';
  font-src 'self';
  object-src 'none';
  base-uri 'none';
  form-action 'self';
  frame-ancestors 'none';
  require-trusted-types-for 'script';
  trusted-types worker-url;

Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=(), usb=()
```

If headers cannot be set (e.g., GitHub Pages), keep `register-coi-sw.js` referenced in `index.html` to install a service worker that provides COOP/COEP semantics.

---

## 4) Caching

- Static assets (JS, WASM, CSS, fonts, images):  
  `Cache-Control: public, max-age=31536000, immutable`
- HTML entry point (`index.html`):  
  `Cache-Control: no-cache`

---

## 5) Strict worker allowlist behavior

Excerpt from `argon-worker.js`:

```js
const ALLOWED_JS_PATH   = 'argon2-bundled.min.js';
const ALLOWED_WASM_PATH = 'argon2.wasm';

const BASE = new URL('./', self.location.href);
const ALLOWED = Object.freeze(new Set([
  new URL(ALLOWED_JS_PATH,   BASE).toString(),
  new URL(ALLOWED_WASM_PATH, BASE).toString()
]));
```

- The worker resolves these to absolute URLs and only fetches/imports those exact URLs.
- Same-origin, no redirects, MIME and size bounds are enforced.
- If names or query strings change, update the allowlist to match the final absolute URLs.

---

## 6) Platform notes

### GitHub Pages
- No custom headers. Use `register-coi-sw.js` for COOP/COEP shim.
- `.nojekyll` should be present.
- GitHub Pages serves `.wasm` as `application/wasm` and `.js` as `application/javascript`.
- If using hashed filenames or query strings, update the allowlist accordingly.

### Nginx (example)

```nginx
types {
  application/wasm wasm;
  application/javascript js;
}

location /cbox/ {
  add_header Cross-Origin-Opener-Policy same-origin;
  add_header Cross-Origin-Embedder-Policy require-corp;
  add_header Cross-Origin-Resource-Policy same-origin;
  add_header X-Content-Type-Options nosniff;
  add_header X-Frame-Options DENY;
  add_header Referrer-Policy no-referrer;
}

location ~* .(js|css|wasm|png|jpg|svg|ico)$ {
  add_header Cache-Control "public, max-age=31536000, immutable";
}

location = /cbox/index.html {
  add_header Cache-Control "no-cache";
}
```

### Apache (example)

```apache
AddType application/wasm .wasm
AddType application/javascript .js

<FilesMatch ".(js|css|wasm|png|jpg|svg|ico)$">
  Header set Cache-Control "public, max-age=31536000, immutable"
</FilesMatch>

<Files "index.html">
  Header set Cache-Control "no-cache"
</Files>

Header set Cross-Origin-Opener-Policy "same-origin"
Header set Cross-Origin-Embedder-Policy "require-corp"
Header set Cross-Origin-Resource-Policy "same-origin"
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "DENY"
Header set Referrer-Policy "no-referrer"
```

### Cloudflare Pages / Netlify
- Use the provided `_headers` file to set cache and isolation headers.
- Verify `.wasm` is served as `application/wasm`.

---

## 7) Hashed assets (two patterns)

Either hashed filenames or stable filenames with hashed query strings are acceptable. In both cases, update the worker allowlist to the exact absolute URLs.

### A) Hashed filenames
Example output:
- `argon2-bundled.min.3f1a7dca.js`
- `argon2.3f1a7dca.wasm`

Update in `argon-worker.js`:
```js
const ALLOWED_JS_PATH   = 'argon2-bundled.min.3f1a7dca.js';
const ALLOWED_WASM_PATH = 'argon2.3f1a7dca.wasm';
```

### B) Stable filenames + query hash
Example URLs:
- `argon2-bundled.min.js?v=3f1a7dca`
- `argon2.wasm?v=3f1a7dca`

Update the allowlist with the full URLs (including `?v=`):

```js
const ALLOWED = Object.freeze(new Set([
  new URL('argon2-bundled.min.js?v=3f1a7dca', BASE).toString(),
  new URL('argon2.wasm?v=3f1a7dca', BASE).toString()
]));
```

---

## 8) Common pitfalls

1. JS MIME too strict  
   Current strict check in `argon-worker.js` expects `application/javascript`. To accept `text/javascript` as well, replace:

   Current:
   ```js
   const ctjs = (head.headers.get('content-type') || '').toLowerCase();
   const strictJsMime = 'application/javascript';
   if (!ctjs.startsWith(strictJsMime)) {
     throw new Error(`Bad JS MIME: expected ${strictJsMime}, got "${ctjs || 'unknown'}"`);
   }
   ```

   Portable:
   ```js
   const ctjs = (head.headers.get('content-type') || '').toLowerCase();
   if (!(ctjs.startsWith('application/javascript') || ctjs.startsWith('text/javascript'))) {
     throw new Error('Bad JS MIME for argon2 wrapper');
   }
   ```

2. Query strings blocked  
   Queries are permitted only if the full absolute URL including the query is present in the `ALLOWED` set.

3. Directory differences  
   The worker uses `BASE = new URL('./', self.location.href)`. Keep assets in the same directory as the worker or adjust paths consistently.

---

## 9) Automated build scripts (optional)

Scripts below compute content hashes and patch `argon-worker.js`. Node.js is required.

### A) Filename-hash mode

Create `tools/hash-and-patch.sh`:

```bash
set -euo pipefail
JS=argon2-bundled.min.js
WASM=argon2.wasm

hash_js=$(node -e "console.log(require('crypto').createHash('sha256').update(require('fs').readFileSync('$JS')).digest('hex').slice(0,8))")
hash_wasm=$(node -e "console.log(require('crypto').createHash('sha256').update(require('fs').readFileSync('$WASM')).digest('hex').slice(0,8))")

js_hashed="argon2-bundled.min.$hash_js.js"
wasm_hashed="argon2.$hash_wasm.wasm"

cp "$JS"   "$js_hashed"
cp "$WASM" "$wasm_hashed"

node - <<'NODE' "$hash_js" "$hash_wasm"
const fs=require('fs');let s=fs.readFileSync('argon-worker.js','utf8');
s=s.replace(/const ALLOWED_JS_PATHs*=s*'.*?';/,   "const ALLOWED_JS_PATH = 'argon2-bundled.min.%JS%.js';");
s=s.replace(/const ALLOWED_WASM_PATHs*=s*'.*?';/, "const ALLOWED_WASM_PATH = 'argon2.%WASM%.wasm';");
s=s.replace('%JS%',   process.argv[1]);
s=s.replace('%WASM%', process.argv[2]);
fs.writeFileSync('argon-worker.js', s);
NODE

echo "Hashed assets:"
echo "  $js_hashed"
echo "  $wasm_hashed"
echo "Worker allowlist updated."
```

### B) Query-hash mode

Create `tools/queryhash-and-patch.sh`:

```bash
set -euo pipefail
JS=argon2-bundled.min.js
WASM=argon2.wasm

hash_js=$(node -e "console.log(require('crypto').createHash('sha256').update(require('fs').readFileSync('$JS')).digest('hex').slice(0,8))")
hash_wasm=$(node -e "console.log(require('crypto').createHash('sha256').update(require('fs').readFileSync('$WASM')).digest('hex').slice(0,8))")

node - <<'NODE' "$hash_js" "$hash_wasm"
const fs=require('fs');
let s=fs.readFileSync('argon-worker.js','utf8');

const newAllowed = `
const ALLOWED = Object.freeze(new Set([
  new URL('argon2-bundled.min.js?v=%JS%', BASE).toString(),
  new URL('argon2.wasm?v=%WASM%', BASE).toString()
]));
`.trim();

s=s.replace(/const ALLOWED = Object.freeze([sS]*?);n/, newAllowed + "n");
s=s.replace('%JS%', process.argv[1]).replace('%WASM%', process.argv[2]);
fs.writeFileSync('argon-worker.js', s);
NODE

echo "Allowlist now expects:"
echo "  argon2-bundled.min.js?v=$hash_js"
echo "  argon2.wasm?v=$hash_wasm"
echo "Update any preloads if present."
```

---

## 10) Subresource Integrity (optional)

If using stable filenames and a platform that honors SRI:

```bash
for f in argon-worker.js app.js; do
  echo -n "$f: "
  openssl dgst -sha384 -binary "$f" | openssl base64 -A | sed 's/^/sha384-/'
done
```

Reference in `index.html`:
```html
<script src="./app.js" integrity="sha384-BASE64..." crossorigin="anonymous"></script>
```

---

## 11) Post-deploy checks

- Network panel:
  - `argon2.wasm`: `Content-Type: application/wasm`, `Content-Length` present, status 200, no redirect.
  - `argon2-bundled.min.js` (or hashed): appropriate JS MIME, `Content-Length` present, status 200, no redirect.
- Worker:
  - `init` completes successfully.
  - `kdf` completes successfully.
- If using query-hash, the URLs match the allowlist exactly (including `?v=`).

---

## 12) Hardening summary

- Prefer deploying only the strict worker.
- Keep assets same-origin; avoid redirects.
- Enforce COOP/COEP via headers when possible; otherwise use `register-coi-sw.js`.
- Use hashed assets with immutable caching.

---

### Appendix: relaxing JS MIME in the worker (if required)

Replace the strict JS MIME check:

```js
const ctjs = (head.headers.get('content-type') || '').toLowerCase();
const strictJsMime = 'application/javascript';
if (!ctjs.startsWith(strictJsMime)) {
  throw new Error(`Bad JS MIME: expected ${strictJsMime}, got "${ctjs || 'unknown'}"`);
}
```

with:

```js
const ctjs = (head.headers.get('content-type') || '').toLowerCase();
if (!(ctjs.startsWith('application/javascript') || ctjs.startsWith('text/javascript'))) {
  throw new Error('Bad JS MIME for argon2 wrapper');
}
```
