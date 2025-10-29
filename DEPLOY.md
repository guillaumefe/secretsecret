# DEPLOY.md — Secure Deployment Guide

This document describes how to securely deploy the CBOX application in production.

HTTPS is required.

---------------------------------------------------------------------

## Files to deploy

Serve the following files over HTTPS from a single origin:

- index.html
- styles.css
- app.js
- argon-worker.js
- argon2-bundled.min.js
- argon2.wasm
- eff_large_wordlist.txt
- favicon.ico

Optional (recommended only when site-specific CSP overrides are supported):

- argon-worker-permissive.js
- argon-worker.js.map (optional)
- argon-worker-permissive.js.map (optional)

Deployment under a sub-path is supported, for example:

https://example.com/cbox/

---------------------------------------------------------------------

## Required MIME types

```
.wasm → application/wasm
.js   → text/javascript; charset=utf-8
.css  → text/css; charset=utf-8
.html → text/html; charset=utf-8
```

---------------------------------------------------------------------

## Required production security headers (all files except permissive worker)

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
Download-Options: noopen
```

Requirements:
- Trusted Types enforced
- No framing allowed
- Same-origin isolation (COOP/COEP) required for WASM and SharedArrayBuffer
- Subresource Integrity recommended for JS and worker scripts

---------------------------------------------------------------------

## CSP for permissive worker (only if deployed)

Apply ONLY to the file:

https://example.com/cbox/argon-worker-permissive.js

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'wasm-unsafe-eval';
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
```

Do not add 'wasm-unsafe-eval' to the app-level CSP.

Prefer serving this file from an isolated subdomain:

```
https://wasm-compat.example.com/argon-worker-permissive.js
```

---------------------------------------------------------------------

## Caching

Cache static assets forever:

```
Cache-Control: public, max-age=31536000, immutable
```

For entry point:

```
index.html → Cache-Control: no-cache
```

---------------------------------------------------------------------

## Worker fallback policy

If the hosting environment does not support per-file CSP overrides:

Do not deploy the permissive worker file.

In app.js, disable fallback:

```js
async function getArgonWorker() {
  return await startArgonWorker('./argon-worker.js');
}
```

This ensures strict CSP is always enforced.

---------------------------------------------------------------------

## Transport security

Required:

- HTTPS everywhere
- Redirect HTTP → HTTPS
- TLS 1.2 or newer

Recommended:

- HSTS enabled:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---------------------------------------------------------------------

## Operational security notes

- Deploy SRI attributes on script tags when hashes are known.
- Ensure no third-party scripts are added without CSP review.
- Do not allow this app to be framed on any domain.
- Confirm COOP/COEP set correctly or WASM optimization may fail.
- Test that strict worker loads successfully in target environments.
