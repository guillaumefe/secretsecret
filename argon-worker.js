/**
 * Strict worker: runs under the same CSP as the page (no 'wasm-unsafe-eval').
 * - No eval, no blob:, same-origin scripts only.
 * - If a browser/platform needs 'wasm-unsafe-eval' to initialize Argon2,
 *   the main app should fall back to /argon-worker-permissive.js instead.
 *
 * Message protocol (main thread -> worker):
 *   { cmd: 'init', payload: { jsURL, wasmURL } }
 *   { cmd: 'kdf',  payload: { passBytes, salt, mMiB, t, p } }
 *
 * Message protocol (worker -> main thread):
 *   { ok:true,  cmd:'init' }
 *   { ok:true,  cmd:'kdf', key: Uint8Array(32) }  // transferred (zero-copy)
 *   { ok:false, error: '...' }
 */

let loaded = false;

// Emscripten module object used by argon2 glue code.
// The main thread will pass URLs; we wire locateFile to the exact wasm URL.
self.Module = self.Module || {};

self.onmessage = async (e) => {
  const { cmd, payload } = e.data || {};
  try {
    // ---- Initialization: load argon2 glue + probe WASM availability ----
    if (cmd === 'init') {
      // Use explicit URLs from the main thread when provided; otherwise defaults.
      const jsURL   = (payload && payload.jsURL)   || '/argon2-bundled.min.js';
      const wasmURL = (payload && payload.wasmURL) || '/argon2.wasm';

      // Ensure the Emscripten glue resolves the .wasm file to the correct path.
      self.Module.locateFile = (path) =>
        path.endsWith('.wasm') ? wasmURL : path;

      // Load the Argon2 glue (uses instantiateStreaming if available).
      // Under strict CSP this must be same-origin and free of eval requirements.
      importScripts(jsURL);

      // Quick probe: compute a tiny Argon2 hash to ensure WASM is ready.
      const salt = new Uint8Array(16);
      const pass = new Uint8Array(1);
      const res = await self.argon2.hash({
        pass,
        salt,
        time: 1,
        mem: 32 * 1024,
        hashLen: 32,
        parallelism: 1,
        type: self.argon2.ArgonType.Argon2id
      });
      if (!res || !res.hash) throw new Error('WASM probe failed');

      // Best-effort wipe of probe inputs
      try { salt.fill(0); } catch {}
      try { pass.fill(0); } catch {}

      loaded = true;
      self.postMessage({ ok: true, cmd: 'init' });
      return;
    }

    // ---- KDF: Argon2id(passBytes, salt) -> 32-byte key ----
    if (cmd === 'kdf') {
      if (!loaded) throw new Error('Argon2 not loaded');
      const { passBytes, salt, mMiB, t, p } = payload;

      // Compute Argon2id with provided parameters.
      const res = await self.argon2.hash({
        pass: new Uint8Array(passBytes),
        salt: new Uint8Array(salt),
        time: t,
        mem: mMiB * 1024,
        hashLen: 32,
        parallelism: p,
        type: self.argon2.ArgonType.Argon2id
      });

      // Create a fresh transferable buffer for the key (avoid retaining argon2's internal buffer).
      const out = new Uint8Array(res.hash.byteLength);
      out.set(new Uint8Array(res.hash));

      // Best-effort wipe of the intermediate result and inputs.
      try { new Uint8Array(res.hash).fill(0); } catch {}
      try { new Uint8Array(passBytes).fill(0); } catch {}
      try { new Uint8Array(salt).fill(0); } catch {}

      // If the wrapper ever exposes cleanup hooks, call them here (safe no-ops otherwise).
      // Example skeleton:
      // try {
      //   if (self.argon2 && typeof self.argon2._clear === 'function') {
      //     self.argon2._clear();
      //   }
      // } catch {}

      // Transfer the key buffer to the main thread (zero-copy move).
      self.postMessage({ ok: true, cmd: 'kdf', key: out }, [ out.buffer ]);

      // Encourage early cleanup (the main thread also calls terminate()).
      try { self.close(); } catch {}
      return;
    }

    // ---- Unknown command fallback ----
    self.postMessage({ ok: false, error: 'Unknown command' });
  } catch (err) {
    // Return a neutral error (details remain in devtools if opened).
    self.postMessage({ ok: false, error: (err && err.message) || String(err) });
  }
};
