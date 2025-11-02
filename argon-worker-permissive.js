/**
 * Permissive-but-hardened Argon2 worker.
 * 
 * Purpose: runs ONLY when the strict worker fails (e.g., engines that require
 * 'wasm-unsafe-eval' for Emscripten glue). This file must be served with a
 * per-file CSP that adds the exception:
 *
 *   Content-Security-Policy:
 *     default-src 'none';
 *     script-src 'self' 'wasm-unsafe-eval';
 *     connect-src 'self';
 *     worker-src 'self';
 *     img-src 'none';
 *     style-src 'none';
 *     font-src 'none';
 *     object-src 'none';
 *     base-uri 'none';
 *     frame-ancestors 'none';
 *     require-trusted-types-for 'script';
 *     trusted-types worker-url
 *
 * The page-level CSP remains strict (no 'wasm-unsafe-eval' there).
 *
 * Message protocol (main thread -> worker):
 *   { cmd: 'init', payload: { jsURL, wasmURL } }
 *   { cmd: 'kdf',  payload: { passBytes, salt, mMiB, t, p } }
 *
 * Message protocol (worker -> main thread):
 *   { ok:true,  cmd:'init' }
 *   { ok:true,  cmd:'kdf', key: Uint8Array(32) } // transferred (zero-copy)
 *   { ok:false, error:'...' }
 */

let loaded = false;
let initializing = false;
let shuttingDown = false;

// ---------- pinned asset names (adjust if you rename files) ----------
const JS_PATH   = './argon2-bundled.min.js';
const WASM_PATH = './argon2.wasm';

// ---------- bounds ----------
const ARGON_MIN_MIB = 256, ARGON_MAX_MIB = 1024;
const ARGON_MIN_T   = 3,   ARGON_MAX_T   = 10;
const P_MIN = 1, P_MAX = 4;

const MAX_WASM_BYTES = 16 * 1024 * 1024; // 16 MiB
const MAX_JS_BYTES   = 2  * 1024 * 1024; // 2 MiB

// ---------- base + allowlist ----------
const BASE = new URL('./', self.location.href);
const ALLOWED = Object.freeze(new Set([
  new URL(JS_PATH,   BASE).toString(),
  new URL(WASM_PATH, BASE).toString()
]));

// ---------- hard-disable dynamic code (the CSP exception is for Emscripten-internal WASM init only) ----------
const __throwEval = () => { throw new Error('eval disabled'); };
try { self.eval = __throwEval; self.Function = __throwEval; } catch {}

// ---------- resolver with exact-URL allowlist ----------
function mustAllow(url) {
  const u = new URL(url, BASE);
  if (u.origin !== self.location.origin) throw new Error('cross-origin blocked');
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('forbidden protocol');
  // If top-level is HTTPS, do not allow downgrade to HTTP
  if (self.location.protocol === 'https:' && u.protocol !== 'https:') {
    throw new Error('insecure-scheme');
  }
  const abs = u.toString();
  if (!ALLOWED.has(abs)) throw new Error('resource not allowlisted: ' + u.pathname);
  return abs;
}

// ---------- guarded fetch for entire lifetime ----------
async function fetchSameOrigin(u, { timeoutMs = 10_000, maxBytes = Infinity } = {}) {
  const ac = new AbortController();
  const tid = setTimeout(() => ac.abort('timeout'), timeoutMs);
  try {
    const res = await fetch(u, {
      mode: 'same-origin',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      signal: ac.signal,
      headers: { 'Accept': u.endsWith('.wasm') ? 'application/wasm' : 'application/javascript' }
    });
    if (!res.ok || res.status !== 200) throw new Error(`HTTP ${res.status}`);
    if (res.redirected) throw new Error('redirect refused');
    if (res.type !== 'basic') throw new Error('unexpected response type');
    if (new URL(res.url).toString() !== u) throw new Error('url mismatch');

    const cl = res.headers.get('content-length');
    if (cl && Number.isFinite(+cl) && +cl > maxBytes) throw new Error('response too large');

    return res;
  } finally { try { clearTimeout(tid); } catch {} }
}

// Lock down fetch
self.fetch = async (input) => {
  const raw = typeof input === 'string' ? input : (input?.url || '');
  const abs = mustAllow(raw);
  return fetchSameOrigin(abs, { timeoutMs: 10_000 });
};
try { Object.defineProperty(self, 'fetch', { writable: false, configurable: false }); } catch {}

// ---------- param validation ----------
function validateParams({ mMiB, t, p }) {
  if (!Number.isInteger(mMiB) || mMiB < ARGON_MIN_MIB || mMiB > ARGON_MAX_MIB) {
    throw new Error('Argon2 memory out of range');
  }
  if (!Number.isInteger(t) || t < ARGON_MIN_T || t > ARGON_MAX_T) {
    throw new Error('Argon2 time out of range');
  }
  if (!Number.isInteger(p) || p < P_MIN || p > P_MAX) {
    throw new Error('Argon2 parallelism out of range');
  }
}

// ---------- defensive shutdown on unexpected errors ----------
self.addEventListener('messageerror', () => { try { self.close(); } catch {}; shuttingDown = true; self.onmessage = null; });
self.addEventListener('error',        () => { try { self.close(); } catch {}; shuttingDown = true; self.onmessage = null; });
self.addEventListener('unhandledrejection', () => { try { self.close(); } catch {}; shuttingDown = true; self.onmessage = null; });

// ---------- Emscripten surface ----------
self.Module = self.Module || {};

self.onmessage = async (e) => {
  if (shuttingDown) return;
  const { cmd, payload } = e.data || {};
  let timer;

  try {
    // ================= INIT =================
    if (cmd === 'init') {
      if (loaded) { try { self.postMessage({ ok: true, cmd: 'init' }); } catch {} return; }
      if (initializing) { try { self.postMessage({ ok: false, error: 'Already initializing' }); } catch {} return; }
      initializing = true;

      // single-resolution guard + init timeout
      let settled = false;
      const settle = (msg) => { if (!settled) { settled = true; try { self.postMessage(msg); } catch {} } };
      timer = setTimeout(() => {
        if (!settled) {
          initializing = false;
          settle({ ok: false, error: 'Init timeout' });
          try { self.close(); } catch {}
          shuttingDown = true; self.onmessage = null;
        }
      }, 10_000);

      // URLs (ignore untrusted payload fields; resolve through allowlist)
      const jsURL   = mustAllow((payload && payload.jsURL)   || new URL(JS_PATH, BASE).toString());
      const wasmURL = mustAllow((payload && payload.wasmURL) || new URL(WASM_PATH, BASE).toString());

      // importScripts allowlisted only during init
      const realImport = self.importScripts;
      self.importScripts = (...urls) => { for (const u of urls) realImport(mustAllow(u)); };

      // Emscripten hooks
      self.Module.locateFile = (path) => (path.endsWith('.wasm') ? wasmURL : path);
      self.Module.instantiateWasm = (imports, onSuccess) => {
        (async () => {
          try {
            if ('instantiateStreaming' in WebAssembly) {
              const res = await fetchSameOrigin(wasmURL, { maxBytes: MAX_WASM_BYTES });
              const ct = (res.headers.get('content-type') || '').toLowerCase();
              const cl = res.headers.get('content-length');
              if (!ct.startsWith('application/wasm')) throw new Error('bad wasm mime');
              if (cl && Number.isFinite(+cl) && +cl <= MAX_WASM_BYTES) {
                const { instance, module } = await WebAssembly.instantiateStreaming(res, imports);
                onSuccess(instance);
                return { instance, module };
              }
              // otherwise fall through to ArrayBuffer path
            }
          } catch {
            // ignore and fall back
          }
          const res2 = await fetchSameOrigin(wasmURL, { maxBytes: MAX_WASM_BYTES });
          const ct2 = (res2.headers.get('content-type') || '').toLowerCase();
          if (!ct2.startsWith('application/wasm')) throw new Error('bad wasm mime (buffer)');
          const bytes = await res2.arrayBuffer();
          if (bytes.byteLength > MAX_WASM_BYTES) throw new Error('wasm too large');
          if (WebAssembly.validate && !WebAssembly.validate(bytes)) throw new Error('invalid wasm');
          const { instance, module } = await WebAssembly.instantiate(bytes, imports);
          onSuccess(instance);
          return { instance, module };
        })();
        return {}; // async path
      };

      // Preflight JS wrapper
      const head = await fetchSameOrigin(jsURL, { maxBytes: MAX_JS_BYTES });
      const ctjs = (head.headers.get('content-type') || '').toLowerCase();
      if (!ctjs.startsWith('application/javascript')) throw new Error('bad js mime');
      const cljs = head.headers.get('content-length');
      if (cljs && (!Number.isFinite(+cljs) || +cljs > MAX_JS_BYTES)) throw new Error('js too large');

      // Load glue (requires 'wasm-unsafe-eval' per-file CSP in some engines)
      importScripts(jsURL);

      // Probe WASM with a tiny hash
      if (!self.argon2 || typeof self.argon2.hash !== 'function' || !self.argon2.ArgonType) {
        throw new Error('argon2 wrapper not initialized');
      }
      const salt = new Uint8Array(16);
      const pass = new Uint8Array(1);
      const probe = await self.argon2.hash({
        pass, salt,
        time: 1,
        mem: 8 * 1024,   // 8 MiB
        hashLen: 16,
        parallelism: 1,
        type: self.argon2.ArgonType.Argon2id
      });
      if (!probe || !probe.hash) throw new Error('wasm probe failed');
      try { salt.fill(0); pass.fill(0); new Uint8Array(probe.hash).fill(0); } catch {}

      // Freeze critical surfaces & disable further dynamic loading
      try {
        if (self.Module) Object.freeze(self.Module);
        Object.freeze(ALLOWED); Object.freeze(BASE);
        Object.defineProperty(self, 'importScripts', {
          value: function(){ throw new Error('importScripts disabled after init'); },
          writable: false, configurable: false
        });
        if (self.argon2) Object.freeze(self.argon2);
        Object.freeze(mustAllow);
        Object.freeze(fetchSameOrigin);
        Object.freeze(validateParams);
      } catch {}

      loaded = true;
      initializing = false;
      try { clearTimeout(timer); } catch {}
      settle({ ok: true, cmd: 'init' });
      return;
    }

    // ================= KDF =================
    if (cmd === 'kdf') {
      if (initializing) throw new Error('init in progress');
      if (!loaded) throw new Error('Argon2 not loaded');

      if (typeof payload !== 'object' || payload === null) throw new Error('invalid payload');
      const { passBytes, salt, mMiB, t, p, ...extra } = payload;
      if (Object.keys(extra).length) throw new Error('unexpected fields');
      if (!(passBytes && salt)) throw new Error('missing pass/salt');

      // exact views on provided buffers
      const passU8 = ArrayBuffer.isView(passBytes)
        ? new Uint8Array(passBytes.buffer, passBytes.byteOffset, passBytes.byteLength)
        : new Uint8Array(passBytes);
      const saltU8 = ArrayBuffer.isView(salt)
        ? new Uint8Array(salt.buffer, salt.byteOffset, salt.byteLength)
        : new Uint8Array(salt);

      if (passU8.byteLength === 0) throw new Error('empty password');
      if (passU8.byteLength > 1 * 1024 * 1024) throw new Error('password too large');
      if (saltU8.byteLength < 8 || saltU8.byteLength > 64) throw new Error('salt length out of bounds');

      validateParams({ mMiB, t, p });

      // single-resolution guard for response
      let settled = false;
      const settle = (msg, xfer) => { if (!settled) { settled = true; try { self.postMessage(msg, xfer || []); } catch {} } };

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

      settle({ ok: true, cmd: 'kdf', key: out }, [ out.buffer ]);

      // ephemeral model: shutdown
      try { self.close(); } catch {}
      shuttingDown = true; self.onmessage = null;
      try {
        Object.defineProperty(self, 'onmessage', { value: null, writable: false, configurable: false });
      } catch { self.onmessage = null; }
      return;
    }

    // ================= Unknown =================
    try { self.postMessage({ ok: false, error: 'Unknown command' }); } catch {}

  } catch (_) {
    initializing = false;
    try { if (timer) clearTimeout(timer); } catch {}
    try { self.postMessage({ ok: false, error: 'failure' }); } catch {}
    try { self.close(); } catch {}
    shuttingDown = true; self.onmessage = null;
  }
};
