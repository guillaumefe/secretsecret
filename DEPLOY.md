# DEPLOY.md

Production deployment instructions.

## Files to deploy
Serve the following files under a single HTTPS origin:

```
index.html
styles.css
app.js
argon-worker.js
argon-worker-permissive.js
argon2-bundled.min.js
argon2.wasm
eff_large_wordlist.txt
favicon.ico
```

Relative paths are used internally, so deployment under a subpath is supported.

## Required MIME types
Ensure correct MIME types:

```
.wasm → application/wasm
.js → text/javascript; charset=utf-8
.css → text/css; charset=utf-8
.html → text/html; charset=utf-8
```

## Required security headers

Apply these **response** headers to all assets **except** the permissive worker:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=(), usb=()
```

### Permissive worker only
Apply this CSP **only** to `/argon-worker-permissive.js`:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'
```

## HTTP caching
Immutable assets:

```
Cache-Control: public, max-age=31536000, immutable
```

Suitable for: `.js`, `.css`, `.wasm`, `.ico`

## HTTPS requirement
Always serve over HTTPS. Redirect HTTP to HTTPS.

