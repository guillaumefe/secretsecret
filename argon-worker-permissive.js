// Permissive worker: identical logic, but this file should be served
// with an HTTP CSP that adds ONLY for this URL:
//   script-src 'self' 'wasm-unsafe-eval'
// Do not relax the page-level CSP.

let loaded = false;

// Will be finalized on 'init' using the wasmURL provided by the main app.
self.Module = self.Module || {};

self.onmessage = async (e) => {
  const { cmd, payload } = e.data || {};
  try {
    if (cmd === 'init') {
      // Allow main thread to pass explicit URLs; fall back to defaults.
      const jsURL   = (payload && payload.jsURL)   || '/argon2-bundled.min.js';
      const wasmURL = (payload && payload.wasmURL) || '/argon2.wasm';

      // Point the Emscripten loader at the correct WASM path.
      self.Module.locateFile = (path) =>
        path.endsWith('.wasm') ? wasmURL : path;

      // Load the Argon2 glue (may require 'wasm-unsafe-eval' on some engines).
      importScripts(jsURL);

      // Probe: one short hash just to ensure WASM is ready.
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
      if (!res || !res.hash) throw new Error('Probe failed');
      salt.fill(0); pass.fill(0);
      loaded = true;
      self.postMessage({ ok: true, cmd: 'init' });
      return;
    }

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
      const out = new Uint8Array(res.hash);
      try { new Uint8Array(passBytes).fill(0); } catch {}
      try { new Uint8Array(salt).fill(0); } catch {}
      self.postMessage({ ok: true, cmd: 'kdf', key: out }, [ out.buffer ]);
      return;
    }

    self.postMessage({ ok:false, error:'Unknown command' });
  } catch(err){
    self.postMessage({ ok:false, error: (err && err.message) || String(err) });
  }
};
