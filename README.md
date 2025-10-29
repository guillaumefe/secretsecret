# 🔐 Secret Secret

Client-side encryption web application.

## Overview
This application performs all cryptographic operations locally in the browser.  
No plaintext or ciphertext is sent to any server.

## Features
- AES-GCM encryption and decryption
- Argon2 key derivation
- Downloadable encrypted files
- No backend dependencies

## Requirements
A modern browser with:
- WebAssembly support
- Web Workers enabled
- JavaScript enabled
- Secure context (HTTPS)

## Usage
1. Serve the application over HTTPS.
2. Open `index.html` in a supported browser.
3. Provide input and passphrase to generate encrypted output.

## Security
- All operations occur locally.
- No third-party network requests.
- Strict Content Security Policy enforced (see `DEPLOY.md`).

## Source Structure
```
index.html                  Main interface
styles.css                  Application styling
app.js                      Main logic
argon-worker.js             Primary WASM worker
argon-worker-permissive.js  Fallback worker
argon2-bundled.min.js       Argon2 implementation
argon2.wasm                 WebAssembly module
eff_large_wordlist.txt      Wordlist for strength estimation
favicon.ico                 Application icon
```

## License
GNU General Public License v3.0
