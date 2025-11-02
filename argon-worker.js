/**
 * Argon2 strict worker
 * - No eval/Function; no blob:/data:; same-origin & exact-allowlist only.
 * - importScripts is allowlisted during init, then permanently disabled.
 * - Bounded, timed fetch with MIME checks; safe instantiateStreaming only when size is known.
 * - Validates KDF params and input sizes; single-shot KDF then hard shutdown.
 * - Generic error messages; fail-fast on any unexpected event.
 */

let loaded = false;
let initializing = false;
let shuttingDown = false;

/* ===== Build-time pins (use hashed filenames or full absolute URLs) =====
   If you deploy under a subfolder, these may be relative to this worker.
   You may also set them to full absolute URLs; the allowlist matches EXACT strings. */
const ALLOWED_JS_PATH    = './argon2-bundled.min.js';     // or 'argon2-bundled.min.js?v=2025-10-08'
const ALLOWED_WASM_PATH  = './argon2.wasm';      // hashed filename strongly recommended

/* ===== Bounds / ceilings ===== */
const MAX_WASM_BYTES = 16 * 1024 * 1024; // 16 MiB
const MAX_JS_BYTES   =  2 * 1024 * 1024; // 2 MiB
const FETCH_TIMEOUT_MS = 10_000;

const ARGON_MIN_MIB = 256, ARGON_MAX_MIB = 1024;
const ARGON_MIN_T   =   3, ARGON_MAX_T   =   10;
const P_MIN = 1, P_MAX = 4;

/* ===== Base & exact allowlist ===== */
const BASE = new URL('./', self.location.href);
const ALLOWED = Object.freeze(new Set([
  new URL(ALLOWED_JS_PATH,   BASE).toString(),
  new URL(ALLOWED_WASM_PATH, BASE).toString()
]));

/* ===== Kill dynamic code globally ===== */
try {
  const __throw = () => { throw new Error('eval disabled'); };
  self.eval = __throw;
  self.Function = __throw;
} catch {}

/* ===== Fail-fast on unexpected errors ===== */
self.addEventListener('error',               () => { if (!shuttingDown) { shuttingDown = true; try { self.close(); } catch {} } });
self.addEventListener('unhandledrejection',  () => { if (!shuttingDown) { shuttingDown = true; try { self.close(); } catch {} } });
self.addEventListener('messageerror',        () => { if (!shuttingDown) { shuttingDown = true; try { self.close(); } catch {} } });

/* ===== Emscripten container ===== */
self.Module = self.Module || {};

/* ===== Helpers ===== */
function mustAllow(url) {
  const u = new URL(url, BASE);
  if (u.origin !== self.location.origin) throw new Error('blocked');
  if (u.protocol !== 'https:' && self.location.protocol === 'https:') {
    throw new Error('insecure-scheme');
  }
  const abs = u.toString();                  // exact match (query/hash allowed ONLY if included in ALLOWED as-is)
  if (!ALLOWED.has(abs)) throw new Error('not-allowlisted');
  return abs;
}

async function fetchSameOrigin(u, { timeoutMs = FETCH_TIMEOUT_MS, maxBytes = Infinity } = {}) {
  const ac = new AbortController();
  const to = setTimeout(() => ac.abort('timeout'), timeoutMs);
  try {
    const res = await fetch(u, {
      mode: 'same-origin',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      signal: ac.signal,
      headers: { 'Accept': u.endsWith('.wasm') ? 'application/wasm' : 'application/javascript' }
    });
    if (!res.ok) throw new Error('http');
    if (res.type !== 'basic') throw new Error('resp-type'); // must be same-origin
    if (new URL(res.url).toString() !== u) throw new Error('url-mismatch');
    const cl = res.headers.get('content-length');
    if (cl && Number.isFinite(+cl) && +cl > maxBytes) throw new Error('too-large');
    return res;
  } finally {
    try { clearTimeout(to); } catch {}
  }
}

function validateParams({ mMiB, t, p }) {
  if (!Number.isInteger(mMiB) || mMiB < ARGON_MIN_MIB || mMiB > ARGON_MAX_MIB) throw new Error('kdf-bad-mem');
  if (!Number.isInteger(t)    || t    < ARGON_MIN_T   || t    > ARGON_MAX_T  ) throw new Error('kdf-bad-time');
  if (!Number.isInteger(p)    || p    < P_MIN         || p    > P_MAX        ) throw new Error('kdf-bad-par');
}

/* ===== Message protocol ===== */
self.onmessage = async (e) => {
  if (shuttingDown) return;
  const { cmd, payload } = e.data || {};
  let initTimer, settled = false;
  const settle = (msg) => { if (!settled) { settled = true; try { self.postMessage(msg); } catch {} } };

  try {
    // ---------------- INIT ----------------
    if (cmd === 'init') {
      if (loaded) { settle({ ok: true, cmd: 'init' }); return; }
      if (initializing) { settle({ ok: false, error: 'failure' }); return; }
      initializing = true;

      initTimer = setTimeout(() => {
        initializing = false;
        settle({ ok: false, error: 'failure' });
        shuttingDown = true; try { self.close(); } catch {}
        self.onmessage = null;
      }, FETCH_TIMEOUT_MS);

      // Resolve & pin URLs via allowlist
      const jsURL   = mustAllow((payload && payload.jsURL)   || new URL(ALLOWED_JS_PATH,   BASE).toString());
      const wasmURL = mustAllow((payload && payload.wasmURL) || new URL(ALLOWED_WASM_PATH, BASE).toString());

      // Guard importScripts during init only
      const realImport = self.importScripts;
      self.importScripts = (...urls) => { for (const u of urls) realImport(mustAllow(u)); };

      // Preflight JS (MIME + size ceiling)
      const head = await fetchSameOrigin(jsURL, { maxBytes: MAX_JS_BYTES });
      const ctjs = (head.headers.get('content-type') || '').toLowerCase();
      if (!ctjs.startsWith('application/javascript')) {
        throw new Error('bad-js-mime');
      }

      // Emscripten hooks: force same URL for the WASM, forbid blob:/data:
      self.Module.locateFile = (path) => (path.endsWith('.wasm') ? wasmURL : path);

      self.Module.instantiateWasm = (imports, onSuccess) => {
        (async () => {
          try {
            if ('instantiateStreaming' in WebAssembly) {
              const res = await fetchSameOrigin(wasmURL, { maxBytes: MAX_WASM_BYTES });
              const ct = (res.headers.get('content-type') || '').toLowerCase();
              if (!ct.startsWith('application/wasm')) throw new Error('bad-wasm-mime');
              const cl = res.headers.get('content-length');
              // Only use streaming when a trustworthy Content-Length ≤ MAX exists
              if (cl && Number.isFinite(+cl) && +cl <= MAX_WASM_BYTES) {
                const { instance, module } = await WebAssembly.instantiateStreaming(res, imports);
                onSuccess(instance);
                return { instance, module };
              }
            }
          } catch {
            // fall through to bounded ArrayBuffer path
          }
          const res2 = await fetchSameOrigin(wasmURL, { maxBytes: MAX_WASM_BYTES });
          const ct2 = (res2.headers.get('content-type') || '').toLowerCase();
          if (!ct2.startsWith('application/wasm')) throw new Error('bad-wasm-mime2');
          const bytes = await res2.arrayBuffer();
          if (bytes.byteLength > MAX_WASM_BYTES) throw new Error('wasm-too-large');
          if (WebAssembly.validate && !WebAssembly.validate(bytes)) throw new Error('wasm-invalid');
          const { instance, module } = await WebAssembly.instantiate(bytes, imports);
          onSuccess(instance);
          return { instance, module };
        })();
        return {}; // async completion
      };

      // Load the wrapper JS
      importScripts(jsURL);

      // Probe Argon2 quickly
      const salt = new Uint8Array(16);
      const pass = new Uint8Array(1);
      const probe = await self.argon2.hash({
        pass, salt,
        time: 1,
        mem: 8 * 1024,     // 8 MiB
        hashLen: 16,
        parallelism: 1,
        type: self.argon2.ArgonType.Argon2id
      });
      if (!probe || !probe.hash) throw new Error('probe-failed');
      try { salt.fill(0); pass.fill(0); new Uint8Array(probe.hash).fill(0); } catch {}

      // Freeze surfaces & disable dynamic loading forever
      try {
        if (self.Module) Object.freeze(self.Module);
        if (self.argon2) Object.freeze(self.argon2);
        Object.defineProperty(self, 'importScripts', {
          value: function(){ throw new Error('disabled'); },
          writable: false, configurable: false
        });
        Object.freeze(mustAllow);
        Object.freeze(fetchSameOrigin);
        Object.freeze(validateParams);
      } catch {}

      loaded = true;
      try { clearTimeout(initTimer); } catch {}
      initializing = false;
      settle({ ok: true, cmd: 'init' });
      return;
    }

    // ---------------- KDF ----------------
    if (cmd === 'kdf') {
      if (!loaded) throw new Error('not-loaded');
      if (!payload || typeof payload !== 'object') throw new Error('bad-payload');

      const { passBytes, salt, mMiB, t, p, ...extra } = payload;
      if (Object.keys(extra).length) throw new Error('extra');
      if (!passBytes || !salt) throw new Error('missing');

      const passU8 = ArrayBuffer.isView(passBytes)
        ? new Uint8Array(passBytes.buffer, passBytes.byteOffset, passBytes.byteLength)
        : new Uint8Array(passBytes);
      const saltU8 = ArrayBuffer.isView(salt)
        ? new Uint8Array(salt.buffer, salt.byteOffset, salt.byteLength)
        : new Uint8Array(salt);

      if (passU8.byteLength === 0 || passU8.byteLength > (1 * 1024 * 1024)) throw new Error('pass-size');
      if (saltU8.byteLength < 8 || saltU8.byteLength > 64) throw new Error('salt-size');
      validateParams({ mMiB, t, p });

      const res = await self.argon2.hash({
        pass: passU8,
        salt: saltU8,
        time: t,
        mem: mMiB * 1024,
        hashLen: 32,
        parallelism: p,
        type: self.argon2.ArgonType.Argon2id
      });

      const out = new Uint8Array(res.hash.byteLength);
      out.set(new Uint8Array(res.hash));

      // best-effort wipes
      try { new Uint8Array(res.hash).fill(0); } catch {}
      try { passU8.fill(0); } catch {}
      try { saltU8.fill(0); } catch {}

      self.postMessage({ ok: true, cmd: 'kdf', key: out }, [ out.buffer ]);

      // Ephemeral model: hard shutdown after result
      shuttingDown = true; try { self.close(); } catch {}
      self.onmessage = null;
      try {
        Object.defineProperty(self, 'onmessage', { value: null, writable: false, configurable: false });
      } catch { self.onmessage = null; }
      return;
    }

    // ---------------- Unknown ----------------
    settle({ ok: false, error: 'failure' });

  } catch (_) {
    // Generic error (no details leaked)
    try { clearTimeout(initTimer); } catch {}
    settle({ ok: false, error: 'failure' });
    shuttingDown = true; try { self.close(); } catch {}
    self.onmessage = null;
  }
};
