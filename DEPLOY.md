## Server-side notes (headers)

These response headers are required for correct operation, including the automatic fallback behavior.

### Main page and strict worker  
Applied to: `/`, `/app.js`, `/argon-worker.js`, `/argon2-bundled.min.js`, `/argon2.wasm`, `/styles.css`, `/eff_large_wordlist.txt`

```
Content-Security-Policy: default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
X-Content-Type-Options: nosniff
```

### Permissive worker only  
Applied to: `/argon-worker-permissive.js`

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
X-Content-Type-Options: nosniff
```

This setup keeps the page strict while allowing a targeted fallback for platforms that still require `'wasm-unsafe-eval'`.
