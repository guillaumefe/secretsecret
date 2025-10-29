/**
 * Permissive worker: identical logic to the strict worker,
 * but this specific file is served with an HTTP CSP that adds (ONLY for this URL):
 *   script-src 'self' 'wasm-unsafe-eval'
 *
 * DO NOT relax the page-level CSP. Keep this exception scoped to this file only.
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
self.Module = self.Module || {};

self.onmessage = async (e) => {
  const { cmd, payload } = e.data || {};
  try {
    // ---- Initialization: load argon2 glue + probe WASM availability ----
    if (cmd === 'init') {
      const jsURL   = (payload && payload.jsURL)   || '/argon2-bundled.min.js';
      const wasmURL = (payload && payload.wasmURL) || '/argon2.wasm';

      // Ensure the Emscripten glue resolves the .wasm file to the correct path.
      self.Module.locateFile = (path) =>
        path.endsWith('.wasm') ? wasmURL : path;

      // Load the Argon2 glue (some engines require 'wasm-unsafe-eval' here).
      importScripts(jsURL);

      // Probe: tiny Argon2 hash to ensure WASM initialization worked.
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

      const res = await self.argon2.hash({
        pass: new Uint8Array(passBytes),
        salt: new Uint8Array(salt),
        time: t,
        mem: mMiB * 1024,
        hashLen: 32,
        parallelism: p,
        type: self.argon2.ArgonType.Argon2id
      });

      // Create a fresh transferable buffer for the key.
      const out = new Uint8Array(res.hash.byteLength);
      out.set(new Uint8Array(res.hash));

      // Wipe the intermediate result and inputs.
      try { new Uint8Array(res.hash).fill(0); } catch {}
      try { new Uint8Array(passBytes).fill(0); } catch {}
      try { new Uint8Array(salt).fill(0); } catch {}

      // Optional wrapper cleanup hook (safe if absent).
      // try {
      //   if (self.argon2 && typeof self.argon2._clear === 'function') {
      //     self.argon2._clear();
      //   }
      // } catch {}

      // Transfer the key buffer (zero-copy) and close the worker for early cleanup.
      self.postMessage({ ok: true, cmd: 'kdf', key: out }, [ out.buffer ]);
      try { self.close(); } catch {}
      return;
    }

    // ---- Unknown command fallback ----
    self.postMessage({ ok: false, error: 'Unknown command' });
  } catch (err) {
    self.postMessage({ ok: false, error: (err && err.message) || String(err) });
  }
};
