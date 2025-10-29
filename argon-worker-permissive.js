// Permissive worker: identical logic, but this file should be served
// with an HTTP CSP that adds ONLY for this URL:
//   script-src 'self' 'wasm-unsafe-eval'
// Do not relax the page-level CSP.

let loaded = false;

self.Module = self.Module || {};
self.Module.locateFile = (path) =>
  path.endsWith('.wasm') ? '/argon2.wasm' : path;

self.onmessage = async (e) => {
  const { cmd, payload } = e.data || {};
  try {
    if (cmd === 'init') {
      importScripts('/argon2-bundled.min.js');
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
