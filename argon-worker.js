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

// Emscripten module
self.Module = self.Module || {};

self.onmessage = async (e) => {
  const { cmd, payload } = e.data || {};

  try {
    // =============== INIT =================
    if (cmd === 'init') {
      const jsURL   = (payload && payload.jsURL)   || '/argon2-bundled.min.js';
      const wasmURL = (payload && payload.wasmURL) || '/argon2.wasm';

      // Correct resolution of .wasm, no blob/data:
      self.Module.locateFile = (path) =>
        path.endsWith('.wasm') ? wasmURL : path;

      // Enforce safe WASM instantiation under strict CSP
      self.Module.instantiateWasm = (imports, onSuccess) => {
        (async () => {
          try {
            if ('instantiateStreaming' in WebAssembly) {
              const res = await fetch(wasmURL, { credentials: 'same-origin' });
              if (!res.ok) throw new Error(`HTTP ${res.status}`);
              const { instance, module } = await WebAssembly.instantiateStreaming(res, imports);
              onSuccess(instance);
              return { instance, module };
            }
          } catch (e) {
            console.warn('[argon2] streaming failed; fallback to ArrayBuffer:', e);
          }

          const bytes = await (await fetch(wasmURL, { credentials: 'same-origin' })).arrayBuffer();
          const { instance, module } = await WebAssembly.instantiate(bytes, imports);
          onSuccess(instance);
          return { instance, module };
        })();

        return {}; // Emscripten will resolve via promise
      };

      // Load argon2 JS wrapper (same-origin)
      importScripts(jsURL);

      // Probe tiny Argon2 hash to ensure WASM ready
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

      try { salt.fill(0); pass.fill(0); } catch {}

      loaded = true;
      self.postMessage({ ok: true, cmd: 'init' });
      return;
    }

    // =============== KDF =================
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

      // Copy into clean transferable buffer
      const out = new Uint8Array(res.hash.byteLength);
      out.set(new Uint8Array(res.hash));

      // Best-effort wipes
      try { new Uint8Array(res.hash).fill(0); } catch {}
      try { new Uint8Array(passBytes).fill(0); } catch {}
      try { new Uint8Array(salt).fill(0); } catch {}

      // Zero-copy transfer to main
      self.postMessage({ ok: true, cmd: 'kdf', key: out }, [ out.buffer ]);

      // Terminate worker after result (ephemeral model)
      try { self.close(); } catch {}
      return;
    }

    // =============== Unknown =================
    self.postMessage({ ok: false, error: 'Unknown command' });

  } catch (err) {
    self.postMessage({ ok: false, error: (err && err.message) || String(err) });
  }
};
