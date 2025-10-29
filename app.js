// ===== Constants and parameters =====

// Build-time flag: set to false in hard-CSP builds
// When false → strict worker only → any CSP/WASM failure is a hard failure
const ALLOW_PERMISSIVE_FALLBACK = true;

const ARGON2_JS_PATH   = './argon2-bundled.min.js';
const ARGON2_WASM_PATH = './argon2.wasm';
const WORDLIST_PATH = './eff_large_wordlist.txt'; // UTF-8 wordlist, 1 word per line (may have indexes)
let __WORDSET__ = undefined;
let __WORDLOG2__ = undefined;

// File and chunking
const MAX_INPUT_BYTES   = 512 * 1024 * 1024;        // 512 MiB bound for ZIP extraction DoS guard
const MAX_BUNDLE_BYTES = MAX_INPUT_BYTES; 
const FIXED_CHUNK_SIZE  = 4 * 1024 * 1024;          // 4 MiB fixed-size chunks
const FILE_BUNDLE_EXT   = '.cboxbundle';
const FILE_SINGLE_EXT   = '.cbox';

// Argon2 auto-tuning targets and bounds
const AUTO_TARGET_MS_MIN = 900;
const AUTO_TARGET_MS_MAX = 1800;
const HEALTHY_P_MIN      = 1;
const HEALTHY_P_MAX      = 4;
const ARGON_MIN_MIB      = 256;
const ARGON_MAX_MIB      = 1024;
const ARGON_MIN_T        = 3;
const ARGON_MAX_T        = 10;

// Max amount of text we render directly in the UI (1 MiB)
const MAX_PREVIEW = 1 * 1024 * 1024;

// ===== Utilities =====

/**
 * Shorthand query selector.
 */
const $  = (s) => document.querySelector(s);

/**
 * Shared text encoder/decoder for UTF-8 conversions.
 */
const TE = new TextEncoder();
const TD = new TextDecoder();

/**
 * Clamp a number within [min, max].
 */
function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

/**
 * Best-effort wipe of a Uint8Array.
 */
function wipeBytes(u8) {
  try { if (u8 && u8.fill) u8.fill(0); } catch {}
}

/**
 * Revoke an object URL soon (after downloads start).
 */
function revokeSoon(url, delay = 1500) {
  try {
    if (!url) return;
    // If we track URLs, skip scheduling if it's already been removed (defense-in-depth).
    try {
      if (__urlsToRevoke && typeof __urlsToRevoke.has === 'function' && !__urlsToRevoke.has(url)) {
        // ensure it's not lying around
        try { __urlsToRevoke.delete(url); } catch {}
        return;
      }
    } catch {}

    const tid = setTimeout(() => {
      try { URL.revokeObjectURL(url); } catch {}
      try { __urlsToRevoke && __urlsToRevoke.delete && __urlsToRevoke.delete(url); } catch {}
      try { clearTimeout(tid); } catch {}
    }, delay);
  } catch {}
}

/**
 * Encode a 32-bit big-endian unsigned integer into a 4-byte Uint8Array.
 */
function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/**
 * Encode a 16-bit little-endian unsigned integer into a 2-byte Uint8Array.
 */
function u16le(n) {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, n, true);
  return b;
}

/**
 * Encode a 32-bit little-endian unsigned integer into a 4-byte Uint8Array.
 */
function u32le(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

/**
 * Minimal environment-aware logger toggled by query flag or localhost.
 * Silent in production by default.
 */
const DEBUG = location.hostname === 'localhost';
function logError(...args) { if (DEBUG) { try { console.error(...args); } catch {} } }
function logWarn (...args) { if (DEBUG) { try { console.warn (...args); } catch {} } }
function logInfo (...args) { if (DEBUG) { try { console.info (...args); } catch {} } }
function showErrorBanner(text) {
  const el = document.getElementById('errBanner');
  if (!el) return;
  setText(el, text || 'An unexpected error occurred.');
  el.hidden = false;
  // auto-hide after a short period if you like
  setTimeout(() => { try { el.hidden = true; setText(el, ''); } catch {} }, 8000);
}

/**
 * Clear password inputs and strength readout for hygiene.
 */
function clearPasswords() {
  try { $('#encPassword').value = ''; } catch {}
  try { $('#decPassword').value = ''; } catch {}
  try { setText('#pwdStrength', ''); } catch {}
}

/**
 * Base64 helpers (browser-safe).
 */
function bytesToBase64(u8) {
  let bin = ''; const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
  }
  return btoa(bin);
}
function base64ToBytes(b64) {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function randU32() { return crypto.getRandomValues(new Uint32Array(1))[0]; }
function b64 (u8) { return bytesToBase64(u8); }
function b64d(s)  { return base64ToBytes(s); }

/**
 * Detect basic device capabilities
 */
function deviceProfile() {
  const cores = navigator.hardwareConcurrency || 2;
  const memGiB = navigator.deviceMemory || 4; // Approximation
  const isMobile = /Android|iPhone|iPad|Mobile/i.test(navigator.userAgent);
  return { cores, memGiB, isMobile };
}

/**
 * Choose safe limits based on device capabilities
 */
function chooseCaps() {
  const { cores, memGiB, isMobile } = deviceProfile();

  // Overall max input size
  const maxInput = (isMobile || memGiB <= 4)
    ? 64 * 1024 * 1024       // Low-end device
    : (memGiB <= 8)
      ? 128 * 1024 * 1024    // Mid-range device
      : 256 * 1024 * 1024;   // Desktop / high-end laptop

  // Argon2 auto-tuning limits
  const minMemMiB = (isMobile || memGiB <= 4) ? 64 : 128;
  const maxMemMiB = (isMobile || memGiB <= 4) ? 256 : 512;
  const maxParallel = Math.min(HEALTHY_P_MAX, Math.max(1, Math.floor(cores / 2)));

  return { maxInput, minMemMiB, maxMemMiB, maxParallel };
}

/**
 * Uniform timing delay + generic messaging for sensitive failures.
 * Mitigates timing side-channels and avoids revealing specific error causes.
 */
function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function secureFail(ctx) {
  await sleep(400); // fixed minimum latency for failure paths

  // Generic error message to reduce oracle surface
  setLive(`${ctx} failed or file is corrupted.`);
  showErrorBanner(`${ctx} failed or file is corrupted.`);
}



// ===== Trusted Types Safe DOM Helpers =====

/**
 * Remove all child nodes from an element.
 */
function clearNode(selOrEl) {
  const el = (typeof selOrEl === 'string')
    ? document.querySelector(selOrEl)
    : selOrEl;
  if (!el) return;

  // Revoke any blob: URLs inside before removing nodes
  try {
    const anchors = el.querySelectorAll ? el.querySelectorAll('a[href^="blob:"]') : [];
    let revoked = 0;
    anchors.forEach(a => {
      const href = a.getAttribute('href');
      if (href) {
        try { URL.revokeObjectURL(href); } catch {}
        try { __urlsToRevoke && __urlsToRevoke.delete && __urlsToRevoke.delete(href); } catch {}
        revoked++;
      }
    });
    logInfo && logInfo('[clearNode] revoked blob links', { revoked, sel: typeof selOrEl === 'string' ? selOrEl : el.id || 'node' });
  } catch {}

  if (typeof el.replaceChildren === 'function') {
    el.replaceChildren();
  } else {
    while (el.firstChild) el.removeChild(el.firstChild);
  }
}


/**
 * Set plain text content on an element safely (no HTML interpretation).
 */
function setText(selOrEl, text) {
  const el = (typeof selOrEl === 'string')
    ? document.querySelector(selOrEl)
    : selOrEl;
  if (el) el.textContent = text ?? '';
}



// ===== Errors =====

/**
 * Custom error type for envelope/ZIP/KDF related errors.
 */
class EnvelopeError extends Error {
  constructor(code, message) { super(message); this.name = 'EnvelopeError'; this.code = code; }
}



// ===== Accessibility helpers =====

/**
 * Update live region with status text.
 */
function setLive(msg) {
  const el = $('#liveInfo'); if (el) setText(el, msg);
}

/**
 * Update a CSS progress bar and its ARIA now value.
 */
function setProgress(target, val) {
  const el = (typeof target === 'string') ? document.querySelector(target) : target;
  if (!el) return;
  const v = clamp(val, 0, 100);

  // Snap to the nearest 5% to reduce class count
  const step = Math.round(v / 5) * 5;

  // Update ARIA state
  el.setAttribute('aria-valuenow', String(step));

  // Remove any existing p-* class
  for (const c of [...el.classList]) {
    if (c.startsWith('p-')) el.classList.remove(c);
  }

  // Add the new class (e.g. p-45)
  el.classList.add(`p-${step}`);
}



// ===== Download helpers =====

/**
 * Track object URLs we create so they can be revoked on "panic".
 */
const __urlsToRevoke = new Set();

/**
 * Render a download button bound to a Blob, with a hidden anchor that triggers the download.
 */
function addDownload(containerSel, blob, filename, label) {
  const container = $(containerSel);
  if (!container) return;

  try {
    const old = container.querySelectorAll('a[href^="blob:"]');
    logInfo('[addDownload] existing blob links in container', { count: old.length });
    old.forEach(a => {
      const href = a.getAttribute('href');
      if (href) {
        try { URL.revokeObjectURL(href); } catch {}
        try { __urlsToRevoke && __urlsToRevoke.delete && __urlsToRevoke.delete(href); } catch {}
      }
      try { a.remove(); } catch {}
    });
    const oldBtns = container.querySelectorAll('button');
    logInfo('[addDownload] removing old buttons', { count: oldBtns.length });
    oldBtns.forEach(b => { try { b.remove(); } catch {} });
  } catch (e) {
    logWarn('[addDownload] cleanup warn', e);
  }

  let url;
  try {
    url = URL.createObjectURL(blob);
    logInfo('[addDownload] created object URL', { trackedBefore: __urlsToRevoke.size + 0 });
  } catch (e) {
    logError('[addDownload] URL.createObjectURL failed', e, { blobSize: blob && blob.size });
    throw e;
  }
  __urlsToRevoke.add(url);
  logInfo('[addDownload] tracking URL', { trackedAfter: __urlsToRevoke.size });

  try {
    const MAX_TRACKED = 20;
    while (__urlsToRevoke.size > MAX_TRACKED) {
      const first = __urlsToRevoke.values().next().value;
      if (!first) break;
      try { URL.revokeObjectURL(first); } catch {}
      __urlsToRevoke.delete(first);
    }
  } catch (e) {
    logWarn('[addDownload] capping tracked URLs warn', e);
  }

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.className = 'sr-only';

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'btn secondary';
  setText(btn, label || ('Download ' + filename));
  btn.onclick = () => {
    try { a.click(); } catch (e) { logError('[addDownload] anchor click failed', e); }
    requestAnimationFrame(() => {
      try { URL.revokeObjectURL(url); } catch {}
      try { __urlsToRevoke.delete(url); } catch {}
      logInfo('[addDownload] revoked after click', { trackedNow: __urlsToRevoke.size });
    });
  };

  container.appendChild(btn);
  container.appendChild(a);
  logInfo('[addDownload] appended elements');
}


// ===== Hashing =====

/**
 * SHA-256 of a byte array (Uint8Array), returns Uint8Array(32).
 */
async function sha256(u8) {
  const h = await crypto.subtle.digest('SHA-256', u8);
  return new Uint8Array(h);
}

/**
 * SHA-256 of a byte array, returned as lower-hex string.
 */
async function sha256Hex(u8) {
  const b = await sha256(u8);
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

/**
 * Timing-safe comparison of two equal-length Uint8Array or hex strings.
 * Returns true only if all bytes match.
 */
function timingSafeEqual(a, b) {
  if (typeof a === 'string' && typeof b === 'string') {
    if (a.length !== b.length) return false;
    let out = 0;
    for (let i = 0; i < a.length; i++) out |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    return out === 0;
  }
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= (a[i] ^ b[i]);
  return out === 0;
}



// ===== Worker selection (strict vs permissive) =====
//
// Production-safe policy (no user/manual toggles):
//  - Always attempt the strict worker first (./argon-worker.js).
//  - Only auto-fallback to the permissive worker (./argon-worker-permissive.js)
//    when the strict worker fails *for reasons that strongly indicate* a CSP
//    or WebAssembly-engine restriction.
//  - There are no query flags, globals, or switches to force permissive mode.
//  - This makes permissive mode effectively "break-glass by environment":
//      it activates only when the runtime truly cannot run the strict worker.
//
// Security notes:
//  - Keep the page’s CSP strict. Serve a *relaxed CSP only on the permissive worker file*.
//  - Keep your Trusted Types policy whitelisting only these script URLs:
//      /app.js, /argon-worker.js, /argon-worker-permissive.js, /argon2-bundled.min.js
//  - This ensures permissive mode is possible *only* as a last-resort on devices
//    where strict WASM cannot initialize, and cannot be enabled intentionally.

/**
 * Heuristic: identify errors typically caused by CSP/WASM restrictions.
 * We only consider permissive fallback on these failures.
 */
function looksLikeWasmCspError(err) {
  const msg = String((err && (err.message || err)) || '').toLowerCase();
  const name = (err && err.name) || '';
  return (
    msg.includes('wasm-unsafe-eval') ||
    msg.includes('content security policy') ||
    (msg.includes('webassembly') && (msg.includes('blocked') || msg.includes('not permitted') || msg.includes('disallow'))) ||
    (msg.includes('compile') && msg.includes('wasm')) ||
    msg.includes('disallowed by embedder') ||     // + Safari/Chromium variants
    msg.includes('code generation') ||            // + “Wasm code generation …”
    name === 'SecurityError' ||
    name === 'DOMException'
  );
}

async function startArgonWorker(url) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let w;
    try {
      // Trusted Types policy for Worker script URLs
      const workerPolicy = (window.trustedTypes && trustedTypes.createPolicy('worker-url', {
        createScriptURL: (u) => {
          const abs = new URL(u, location.href);
          // Allow only same-origin + specific worker script files
          const okOrigin = abs.origin === location.origin;
          const okPath =
            abs.pathname.endsWith('/argon-worker.js') ||
            abs.pathname.endsWith('/argon-worker-permissive.js');
          if (!okOrigin || !okPath) {
            throw new TypeError('Rejected Worker ScriptURL');
          }
          return abs.toString();
        }
      })) || { createScriptURL: (u) => u }; // Fallback when Trusted Types is unavailable
 
      w = new Worker(workerPolicy.createScriptURL(url));
    } catch (syncErr) {
      // CSP/TT/URL can block synchronously
      reject(syncErr);
      return;
    }

    const to = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { w.terminate(); } catch {}
        reject(new Error('worker_init_timeout'));
      }
    }, 10000);

    const onMsg = (e) => {
      const d = e.data || {};
      if (d.cmd === 'init') {
        clearTimeout(to);
        w.removeEventListener('message', onMsg);
        if (!settled) { settled = true; resolve(w); }
      }
    };

    w.addEventListener('message', onMsg);

    w.onerror = (e) => {
      if (!settled) {
        settled = true;
        clearTimeout(to);
        try { w.terminate(); } catch {}
        const err = (e && e.error) || new Error(e && e.message ? e.message : 'worker_error');
        reject(err);
      }
    };

    // Optional: capture message deserialization errors
    w.onmessageerror = (e) => {
      if (!settled) {
        settled = true;
        clearTimeout(to);
        try { w.terminate(); } catch {}
        reject(new Error('worker_message_error'));
      }
    };

    w.postMessage({ cmd: 'init', payload: { jsURL: ARGON2_JS_PATH, wasmURL: ARGON2_WASM_PATH } });
  });
}

/**
 * Attempt strict worker first; auto-fallback to permissive only when strictly necessary.
 */
 async function getArgonWorker() {
   try {
     return await startArgonWorker('./argon-worker.js'); // strict
   } catch (err) {
     // If it doesn't look like a CSP/WASM capability failure, permissive won't help.
     if (!looksLikeWasmCspError(err)) throw err;
     // Hard-disable permissive fallback if the build flag is off
     if (!ALLOW_PERMISSIVE_FALLBACK) throw err;

     // Last-chance: try permissive worker (served with its own relaxed CSP).
     // No flags or query params control this: it's purely environmental.
     try {
       console.warn('[argon2] Strict worker blocked by CSP/WASM; attempting permissive worker…');
       return await startArgonWorker('./argon-worker-permissive.js');
     } catch (err2) {
      // If permissive also fails, surface the original context + secondary error.
      const combo = new Error(
        'permissive_fallback_failed: strict=' +
        String(err && (err.message || err)) +
        '; permissive=' +
        String(err2 && (err2.message || err2))
      );
      combo.name = 'WorkerFallbackError';
      throw combo;
    }
  }
}

/**
 * Derive a 32-byte key using Argon2id in a Worker, with provided salt and parameters.
 * Accepts string or Uint8Array password; always normalizes strings to NFKC.
 */
async function deriveArgon2id(password, salt, params) {
  if (typeof password === 'string') password = password.normalize('NFKC');
  validateArgon(params);

  const worker = await getArgonWorker();
  const passBytes = TE.encode(password);

  const keyBytes = await new Promise((resolve, reject) => {
    const on = (e) => {
      const d = e.data || {};
      if (d.cmd === 'kdf') {
        worker.removeEventListener('message', on);
        try { worker.terminate(); } catch {}
        if (d.ok && d.key) resolve(new Uint8Array(d.key));
        else reject(new Error(d.error || 'Argon2 failure'));
      }
    };
    worker.addEventListener('message', on);

    const saltCopy = new Uint8Array(salt);
    worker.postMessage(
      { cmd: 'kdf', payload: { passBytes, salt: saltCopy, ...params } },
      [ passBytes.buffer, saltCopy.buffer ]
    );
  });

  try { passBytes.fill(0); } catch {}
  return keyBytes;
}

/**
 * Import a raw 32-byte key as AES-GCM CryptoKey.
 */
async function importAesKey(raw32) {
  return crypto.subtle.importKey('raw', raw32, { name: 'AES-GCM', length: 256 }, false, [ 'encrypt', 'decrypt' ]);
}



// ===== Auto-tuning =====

/**
 * Run a single Argon2id derivation for timing purposes with the given parameters.
 * Returns a duration in milliseconds, or Infinity on failure.
 */
async function benchOnce(params) {
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const t0 = performance.now();
    const kb = await deriveArgon2id('bench-pass', salt, params);
    wipeBytes(kb); wipeBytes(salt);
    return performance.now() - t0;
  } catch { return Infinity; }
}

/**
 * Auto-tune parameters to target a runtime window. Returns the best match found.
 */
async function autoTuneStrong() {
  const cores       = Math.max(1, Math.min(HEALTHY_P_MAX, (navigator.hardwareConcurrency || 2)));
  const candidateMs = [ ARGON_MIN_MIB, 384, 512, 768, 1024 ];
  const candidateT  = [ ARGON_MIN_T, 4, 5, 6 ];
  let best = null;

  for (const mMiB of candidateMs) {
    for (const t of candidateT) {
      const p  = Math.min(cores, HEALTHY_P_MAX);
      const ms = await benchOnce({ mMiB, t, p });
      if (!isFinite(ms)) continue;
      const inWindow = (ms >= AUTO_TARGET_MS_MIN && ms <= AUTO_TARGET_MS_MAX);
      if (inWindow) { return { mMiB, t, p, ms }; }
      const target = (AUTO_TARGET_MS_MIN + AUTO_TARGET_MS_MAX) / 2;
      if (!best || Math.abs(ms - target) < Math.abs(best.ms - target)) {
        best = { mMiB, t, p, ms };
      }
    }
  }
  return best || { mMiB: 512, t: 5, p: Math.min(cores, HEALTHY_P_MAX), ms: 0 };
}

/**
 * Introduce a small random jitter to memory parameter to reduce uniformity.
 */
function jitterMemory(m) {
  const jitter = (randU32() % 9) - 4;
  const out = clamp(m + jitter, ARGON_MIN_MIB, ARGON_MAX_MIB);
  return out;
}



// ===== Rate-limit UX (simple token bucket per action kind) =====

/**
 * Rate limits configuration: max actions per windowMs.
 */
const RATE = {
  bench:   { windowMs: 30000, max: 1 }, // allow 1 auto-tune per 30s
  decrypt: { windowMs: 10000, max: 2 }  // allow 2 decrypts per 10s
};

/**
 * Internal timestamps queues per rate-limited kind.
 */
const _rl = {};

/**
 * Attempt to acquire permission to perform an action of "kind".
 * Returns { ok: true } if allowed, or { ok: false, wait } with remaining ms to wait.
 */
function allow(kind) {
  const now  = Date.now();
  const conf = RATE[kind];
  const q    = (_rl[kind] ||= []);
  // purge old timestamps outside the window
  while (q.length && now - q[0] > conf.windowMs) q.shift();
  if (q.length >= conf.max) {
    const wait = conf.windowMs - (now - q[0]);
    return { ok: false, wait };
  }
  q.push(now);
  return { ok: true, wait: 0 };
}

/**
 * Disable a button and display a countdown suffix during cooldown.
 */
function cooldownButton(btnSel, ms) {
  const btn = document.querySelector(btnSel);
  if (!btn) return;
  const saved = btn.textContent;
  btn.disabled = true;
  btn.setAttribute('aria-disabled', 'true');
  let left = Math.ceil(ms / 1000);
  const id = setInterval(() => {
    setText(btn, `${saved} (${left--}s)`);
    if (left < 0) {
      clearInterval(id);
      btn.disabled = false;
      btn.removeAttribute('aria-disabled');
      setText(btn, saved);
    }
  }, 1000);
}



// ===== Fixed-size chunking =====

/**
 * Split a Uint8Array into fixed-size 4 MiB chunks. Always returns at least one chunk.
 */
function chunkFixed(u8) {
  const chunks = [];
  for (let i = 0; i < u8.length; i += FIXED_CHUNK_SIZE) {
    chunks.push(u8.subarray(i, Math.min(u8.length, i + FIXED_CHUNK_SIZE)));
  }
  if (chunks.length === 0) chunks.push(new Uint8Array(0));
  return chunks;
}

/**
 * Pad a smaller buffer to the fixed chunk size with cryptographic random bytes.
 */
function padToFixed(u8) {
  const out = new Uint8Array(FIXED_CHUNK_SIZE);
  out.set(u8, 0);
  if (u8.length < FIXED_CHUNK_SIZE) {
    // Fill the remainder with cryptographically‐strong random bytes in <=64 KiB chunks
    const MAX = 65536; // browser limit for getRandomValues
    let offset = u8.length;
    while (offset < FIXED_CHUNK_SIZE) {
      const n = Math.min(MAX, FIXED_CHUNK_SIZE - offset);
      crypto.getRandomValues(out.subarray(offset, offset + n));
      offset += n;
    }
  }
  return out;
}



// ===== Envelope format (version 4) =====

const MAGIC = TE.encode('CBOX4');

/**
 * Encode metadata object as additional authenticated data (AAD).
 */
function metaAAD(metaObj) {
  return TE.encode(JSON.stringify(metaObj));
}

/**
 * Validate Argon2 parameter bounds; throw on unsupported values.
 */
function validateArgon({ mMiB, t, p }) {
  if (!Number.isFinite(mMiB) || mMiB < ARGON_MIN_MIB || mMiB > ARGON_MAX_MIB) throw new EnvelopeError('arg_memory',   'Unsupported Argon2 memory');
  if (!Number.isFinite(t)    || t    < ARGON_MIN_T   || t    > ARGON_MAX_T  ) throw new EnvelopeError('arg_time',     'Unsupported Argon2 time');
  if (!Number.isFinite(p)    || p    < HEALTHY_P_MIN || p    > HEALTHY_P_MAX) throw new EnvelopeError('arg_parallel', 'Unsupported Argon2 parallelism');
}

/**
 * Seal a fixed-size chunk using AES-GCM with AAD-bound metadata.
 * Returns a new Uint8Array containing [MAGIC | metaLenBE | meta | cipher].
 */
async function sealFixedChunk({ password, payloadChunk, chunkIndex, totalChunks, totalPlainLen, params }) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));

  // Inner meta is prepended length + JSON + fixed payload
  const innerMeta = { v: 1, kind: 'fixed', fixedSize: FIXED_CHUNK_SIZE, chunkIndex, totalChunks, totalPlainLen };
  const innerMetaBytes = TE.encode(JSON.stringify(innerMeta));
  const header4        = u32be(innerMetaBytes.length);
  const plainPre       = new Uint8Array(4 + innerMetaBytes.length + FIXED_CHUNK_SIZE);
  plainPre.set(header4, 0);
  plainPre.set(innerMetaBytes, 4);
  const fixed = padToFixed(payloadChunk);
  plainPre.set(fixed, 4 + innerMetaBytes.length);

  const metaObj = {
    enc_v: 4, algo: 'AES-GCM',
    iv: b64(iv), salt: b64(salt),
    kdf: { kdf: 'Argon2id', v: 1, mMiB: params.mMiB, t: params.t, p: params.p },
    bundleId: params.bundleId // <— anti-replay binding
  };
  const aad = metaAAD(metaObj);

  const keyBytes = await deriveArgon2id(password, salt, params);
  const key      = await importAesKey(keyBytes);
  const ct       = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plainPre));

  const metaBytes = aad;
  const head = new Uint8Array(MAGIC.length + 4 + metaBytes.length);
  head.set(MAGIC, 0);
  new DataView(head.buffer, MAGIC.length, 4).setUint32(0, metaBytes.length, false);
  head.set(metaBytes, MAGIC.length + 4);

  const out = new Uint8Array(head.length + ct.length);
  out.set(head, 0); out.set(ct, head.length);

  wipeBytes(keyBytes); wipeBytes(salt); wipeBytes(iv); wipeBytes(fixed); wipeBytes(plainPre);
  return out;
}

/**
 * Open and authenticate a sealed fixed-size chunk.
 * Returns { meta, innerMeta, fixedChunk } if successful.
 */
async function openFixedChunk({ password, bytes, expectedBundleId }) {
  if (bytes.length < 9) throw new EnvelopeError('format', 'Invalid envelope');
  if (TD.decode(bytes.subarray(0, 5)) !== 'CBOX4') throw new EnvelopeError('magic', 'Unknown format');

  const metaLen = new DataView(bytes.buffer, bytes.byteOffset + 5, 4).getUint32(0, false);
  const metaEnd = 9 + metaLen;
  if (metaEnd > bytes.length) throw new EnvelopeError('meta_trunc', 'Corrupted metadata');

  const metaBytes = bytes.subarray(9, metaEnd);
  if (metaBytes.length > 4096) throw new EnvelopeError('meta_big', 'Metadata too large');

  let meta;
  try {
    meta = JSON.parse(TD.decode(metaBytes));
  } catch {
    throw new EnvelopeError('meta_parse', 'Malformed metadata');
  }

  const salt = b64d(meta.salt || '');
  const iv   = b64d(meta.iv || '');

  if (salt.length !== 16) throw new EnvelopeError('salt_len', 'Bad salt length');
  if (iv.length   !== 12) throw new EnvelopeError('iv_len',   'Bad IV length');

  // Version & algorithm pinning
  if (meta.enc_v !== 4) throw new EnvelopeError('enc_v', 'Unsupported envelope version');
  if (meta.algo !== 'AES-GCM') throw new EnvelopeError('algo', 'Unsupported AEAD');

  // Enforce anti-replay if caller provided an expected bundleId
  if (expectedBundleId !== undefined) {
    if (typeof meta.bundleId !== 'string' || meta.bundleId !== expectedBundleId) {
      throw new EnvelopeError('bundle_mismatch', 'BundleId mismatch');
    }
  }

  const k = meta.kdf || {};
  if (k.kdf !== 'Argon2id') throw new EnvelopeError('kdf', 'Unsupported KDF');
  if (k.v !== 1)            throw new EnvelopeError('kdf_v', 'Unsupported KDF version');
  validateArgon({ mMiB: k.mMiB, t: k.t, p: k.p });

  const keyBytes = await deriveArgon2id(password, salt, { mMiB: k.mMiB, t: k.t, p: k.p });
  const key      = await importAesKey(keyBytes);

  const cipher = bytes.subarray(metaEnd);
  const clear  = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: metaBytes, tagLength: 128 },
    key, cipher
  ));
  wipeBytes(keyBytes);

  if (clear.length < 4) throw new EnvelopeError('clear_short', 'Malformed plaintext');
  const innerLen = new DataView(clear.buffer, clear.byteOffset, 4).getUint32(0, false);
  const innerEnd = 4 + innerLen;
  if (innerEnd > clear.length) throw new EnvelopeError('inner_trunc', 'Truncated inner meta');

  const innerMetaBytes = clear.subarray(4, innerEnd);
  let innerMeta;
  try {
    innerMeta = JSON.parse(TD.decode(innerMetaBytes));
  } catch {
    throw new EnvelopeError('inner_parse', 'Malformed inner meta');
  }

  const fixedPayload = clear.subarray(innerEnd, innerEnd + FIXED_CHUNK_SIZE);
  const out = new Uint8Array(fixedPayload.length);
  out.set(fixedPayload);

  try { clear.fill(0); } catch {}
  return { meta, innerMeta, fixedChunk: out };
}



// ===== Minimal ZIP (store-only) =====
//
// We only build and read "store" (method=0) entries.
// Extraction validates every header and offset before slicing.
// No data descriptors (GP bit 3 must be 0). No ZIP64.

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    t[n] = c >>> 0;
  }
  return t;
})();

/**
 * Compute CRC-32 (IEEE 802.3) for a byte array.
 */
function crc32(u8) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < u8.length; i++) {
    c = CRC_TABLE[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

/**
 * MS-DOS date/time fields used by ZIP headers.
 */
function dosDT(d = new Date()) {
  const s2 = Math.floor(d.getSeconds() / 2);
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | s2,
    date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()
  };
}

/**
 * Build a store-only ZIP from an array of { name, bytes } entries.
 */
function buildZip(files) {
  const locals = [], centrals = []; let offset = 0;
  for (const f of files) {
    const nameBytes = TE.encode(f.name.replaceAll('\\', '/'));
    const data = f.bytes;
    const crc  = crc32(data);
    const { time, date } = dosDT();

    // Local File Header (LFH)
    const LFH = [
      u32le(0x04034b50), u16le(20), u16le(0), u16le(0),
      u16le(time), u16le(date), u32le(crc),
      u32le(data.length), u32le(data.length),
      u16le(nameBytes.length), u16le(0)
    ];
    locals.push(...LFH, nameBytes, data);
    const localLen = LFH.reduce((s, b) => s + b.length, 0) + nameBytes.length + data.length;

    // Central Directory Header (CDH)
    const CDH = [
      u32le(0x02014b50), u16le(20), u16le(20), u16le(0), u16le(0),
      u16le(time), u16le(date), u32le(crc),
      u32le(data.length), u32le(data.length),
      u16le(nameBytes.length), u16le(0), u16le(0), u16le(0), u16le(0),
      u32le(0), u32le(offset)
    ];
    centrals.push(...CDH, nameBytes);
    offset += localLen;
  }

  const centralSize   = centrals.reduce((s, b) => s + b.length, 0);
  const centralOffset = locals.reduce((s, b) => s + b.length, 0);
  const EOCD = [
    u32le(0x06054b50), u16le(0), u16le(0),
    u16le(files.length), u16le(files.length),
    u32le(centralSize), u32le(centralOffset), u16le(0)
  ];

  const total = locals.reduce((s, b) => s + b.length, 0) + centralSize + EOCD.reduce((s, b) => s + b.length, 0);
  const out   = new Uint8Array(total); let p = 0;
  for (const part of [...locals, ...centrals, ...EOCD]) { out.set(part, p); p += part.length; }
  return out;
}

/**
 * Safe little-endian readers for DataView with bounds checks.
 */
function readU16(dv, off) { if (off + 2 > dv.byteLength) throw new EnvelopeError('zip_bounds', 'U16 OOB'); return dv.getUint16(off, true); }
function readU32(dv, off) { if (off + 4 > dv.byteLength) throw new EnvelopeError('zip_bounds', 'U32 OOB'); return dv.getUint32(off, true); }

// parseEOCDAndCentralDirectory
// Validates EOCD + Central Directory (store-only). Ensures CD and LFH offsets are coherent.
// Throws on any structural issue; returns a minimal name→LFH offset index for optional use.
function parseEOCDAndCentralDirectory(u8) {
  const EOCD_SIG = 0x06054b50;
  const CD_SIG   = 0x02014b50;
  const LFH_SIG  = 0x04034b50;

  const searchStart = Math.max(0, u8.length - (65535 + 22));
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

  let eocdOff = -1;
  for (let i = u8.length - 22; i >= searchStart; i--) {
    if (dv.getUint32(i, true) === EOCD_SIG) { eocdOff = i; break; }
  }
  if (eocdOff < 0) throw new EnvelopeError('zip_eocd', 'EOCD not found');

  const totalEntries = dv.getUint16(eocdOff + 10, true);
  const cdSize       = dv.getUint32(eocdOff + 12, true);
  const cdOffset     = dv.getUint32(eocdOff + 16, true);

  if (cdOffset + cdSize > u8.length) {
    throw new EnvelopeError('zip_cd_bounds', 'Central Directory exceeds buffer');
  }

  const index = new Map();
  let p = cdOffset;
  for (let n = 0; n < totalEntries; n++) {
    if (p + 46 > u8.length) throw new EnvelopeError('zip_cd_short', 'CDH truncated');
    if (dv.getUint32(p, true) !== CD_SIG) throw new EnvelopeError('zip_cd_sig', 'Bad CDH signature');

    const compMethod   = dv.getUint16(p + 10, true);
    const nameLen      = dv.getUint16(p + 28, true);
    const extraLen     = dv.getUint16(p + 30, true);
    const commentLen   = dv.getUint16(p + 32, true);
    const relOffsetLFH = dv.getUint32(p + 42, true);

    if (compMethod !== 0) throw new EnvelopeError('zip_cd_method', 'Compression not supported');

    const nameStart = p + 46;
    const nameEnd   = nameStart + nameLen;
    const nextCD    = nameEnd + extraLen + commentLen;
    if (nextCD > u8.length) throw new EnvelopeError('zip_cd_oob', 'CDH OOB');

    if (relOffsetLFH + 30 > u8.length) throw new EnvelopeError('zip_lfh_oob', 'LFH OOB');
    if (dv.getUint32(relOffsetLFH, true) !== LFH_SIG) throw new EnvelopeError('zip_lfh_sig', 'Bad LFH signature');

    const nameBytes = u8.subarray(nameStart, nameEnd);
    const name = TD.decode(nameBytes);
    index.set(name, relOffsetLFH);

    p = nextCD;
  }

  if ((p - cdOffset) !== cdSize) {
    throw new EnvelopeError('zip_cd_size', 'Central Directory size mismatch');
  }
  return index;
}

/**
 * Strict store-only ZIP extractor with hard bounds and path hygiene.
 * Throws on unsupported features (compression, data descriptor, ZIP64, etc.).
 */
async function extractZipEntriesStrict(u8) {
  // Validate EOCD + Central Directory coherence first
  const cdIndex = parseEOCDAndCentralDirectory(u8); // throws on invalid structures

  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const entries = [];
  let i = 0;
  const LIMIT = u8.length;

  // DoS protection: cumulative uncompressed size limit
  let totalDeclared = 0;
  const LIMIT_TOTAL = (window.__MAX_INPUT_BYTES_DYNAMIC || MAX_BUNDLE_BYTES);

  while (i + 30 <= LIMIT) {
    const sig = readU32(dv, i);
    if (sig !== 0x04034b50) break;

    const versionNeeded = readU16(dv, i + 4);
    const gpFlags       = readU16(dv, i + 6);
    const method        = readU16(dv, i + 8);
    const compSize      = readU32(dv, i + 18);
    const uncompSize    = readU32(dv, i + 22);
    const nameLen       = readU16(dv, i + 26);
    const extraLen      = readU16(dv, i + 28);

    if ((gpFlags & 0x0008) !== 0)
      throw new EnvelopeError('zip_dd', 'Data descriptor not allowed');
    if (method !== 0)
      throw new EnvelopeError('zip_method', 'Compression method not supported');

    const headerLen  = 30;
    const nameStart  = i + headerLen;
    const nameEnd    = nameStart + nameLen;
    const extraStart = nameEnd;
    const extraEnd   = extraStart + extraLen;
    const dataStart  = extraEnd;
    const dataEnd    = dataStart + compSize;

    if (nameLen === 0)
      throw new EnvelopeError('zip_noname', 'Entry without a name');
    if (nameEnd > LIMIT || extraEnd > LIMIT || dataEnd > LIMIT)
      throw new EnvelopeError('zip_oob', 'Entry exceeds buffer');
    if (compSize !== uncompSize)
      throw new EnvelopeError('zip_len', 'Store entry must have equal comp/uncomp sizes');

    // DoS protection: reject oversized declared content
    totalDeclared += uncompSize;
    if (totalDeclared > LIMIT_TOTAL)
      throw new EnvelopeError('zip_total', 'ZIP total size exceeds limit');

    const nameBytes = u8.subarray(nameStart, nameEnd);
    const name = TD.decode(nameBytes);
    if (name.includes('..') || name.startsWith('/') || name.includes('\\'))
      throw new EnvelopeError('zip_path', 'Suspicious entry name');

    const data = u8.subarray(dataStart, dataEnd);

    // CRC-32 verification (LFH)
    const declaredCRC = readU32(dv, i + 14);
    const actualCRC = crc32(data);
    if (declaredCRC !== actualCRC) {
      throw new EnvelopeError('zip_crc', 'CRC mismatch in ZIP entry');
    }

    entries.push({ name, bytes: new Uint8Array(data) });

    i = dataEnd;
    if (entries.length > 2000)
      throw new EnvelopeError('zip_toomany', 'Too many entries');
  }

  if (entries.length === 0)
    throw new EnvelopeError('zip_empty', 'No entries found');

  return entries;
}



// ===== Manifest (authenticated) =====

/**
 * (Legacy helper) Produce an authenticated manifest envelope (not used in final bundle path;
 * kept for completeness and potential future compositions).
 */
async function sealManifest({ password, params, chunkHashes, totalPlainLen }) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));

  const inner = {
    v: 1, kind: 'manifest',
    chunkSize: FIXED_CHUNK_SIZE,
    totalPlainLen,
    totalChunks: chunkHashes.length,
    chunkHashes,
    createdAt: new Date().toISOString()
  };
  const innerBytes = TE.encode(JSON.stringify(inner));
  const header4    = u32be(innerBytes.length);
  const plainPre   = new Uint8Array(4 + innerBytes.length);
  plainPre.set(header4, 0);
  plainPre.set(innerBytes, 4);

  const metaObj = {
    enc_v: 4, algo: 'AES-GCM',
    iv: b64(iv), salt: b64(salt),
    kdf: { kdf: 'Argon2id', v: 1, mMiB: params.mMiB, t: params.t, p: params.p }
  };
  const aad = metaAAD(metaObj);

  const keyBytes = await deriveArgon2id(password, salt, params);
  const key      = await importAesKey(keyBytes);
  const ct       = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plainPre));

  const head = new Uint8Array(MAGIC.length + 4 + aad.length);
  head.set(MAGIC, 0);
  new DataView(head.buffer, MAGIC.length, 4).setUint32(0, aad.length, false);
  head.set(aad, MAGIC.length + 4);

  const out = new Uint8Array(head.length + ct.length);
  out.set(head, 0); out.set(ct, head.length);

  wipeBytes(keyBytes); wipeBytes(salt); wipeBytes(iv); wipeBytes(plainPre);
  return out;
}



// ===== Heuristic UTF-8 detection =====

/**
 * Quick textual heuristic to decide if a buffer is likely UTF-8(-ish) text.
 */
function looksLikeUtf8Text(u8) {
  let ascii = 0, ctrl = 0;
  for (let i = 0; i < Math.min(u8.length, 8192); i++) {
    const b = u8[i];
    if (b === 9 || b === 10 || b === 13) { ascii++; continue; }
    if (b >= 32 && b < 127) { ascii++; continue; }
    if (b < 9 || (b > 13 && b < 32)) { ctrl++; }
  }
  return ascii >= ctrl * 4;
}



// ===== UI state =====

const encBar = '#encBar', decBar = '#decBar';
let tunedParams = null;
let wordlist    = null;



// ===== Wordlist & passphrase generation =====

/**
 * Load wordlist (auto-detect EFF indexed "12345  word" or plain one-word-per-line)
 */
async function loadWordlist() {
  try {
    const res = await fetch(WORDLIST_PATH);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    let txt = await res.text();

    // Enlève un éventuel BOM
    if (txt.charCodeAt(0) === 0xFEFF) txt = txt.slice(1);

    const tmp  = [];
    const seen = new Set();

    for (const rawLine of txt.split(/\r?\n/)) {
      let line = rawLine.trim();
      if (!line) continue;
      if (line.startsWith('#')) continue; // tolère commentaires

      // EFF: "12345  word"  → garde la 2e colonne si présente
      // Sinon: "word"
      const m = line.match(/^(?:\d{5}\s+)?(.+)$/);
      if (!m) continue;

      const word = m[1].normalize('NFKC').toLowerCase().trim();
      if (!word) continue;

      if (!seen.has(word)) { seen.add(word); tmp.push(word); }
    }

    if (tmp.length < 2048) throw new Error('wordlist too small');

    wordlist     = tmp;
    __WORDSET__  = new Set(tmp);
    __WORDLOG2__ = Math.log2(tmp.length);
  } catch (e) {
    logWarn('Wordlist load failed:', e);
    wordlist = null;
    __WORDSET__ = undefined;
    __WORDLOG2__ = undefined;
  }
}

/**
 * Sample a random word from the loaded wordlist.
 */
function rngWord() {
  const i = crypto.getRandomValues(new Uint32Array(1))[0] % wordlist.length;
  return wordlist[i];
}

/**
 * Rough entropy (bits) via wordlist tokens or character-class pool size.
 */
function estimatePasswordEntropyBits(pw) {
  if (!pw) return 0;

  // Diceware detection when a wordlist is loaded and passphrase uses spaces, hyphens or underscores.
  const parts = pw.split(/[\s\-_]+/).map(s => s.trim()).filter(Boolean);
  const hasWL = Array.isArray(wordlist) && wordlist.length > 0 && typeof __WORDLOG2__ === 'number' && __WORDLOG2__ > 0;
  if (hasWL && parts.length > 1) {
    const set = (__WORDSET__ !== undefined) ? __WORDSET__ : new Set(wordlist);
    const allWords = parts.every(token => set.has(token.normalize('NFKC').toLowerCase().trim()));
    if (allWords) return parts.length * __WORDLOG2__;
  }

  // Character-class estimate fallback
  let alpha = 0;
  if (/[a-z]/.test(pw)) alpha += 26;
  if (/[A-Z]/.test(pw)) alpha += 26;
  if (/[0-9]/.test(pw)) alpha += 10;
  if (/[^A-Za-z0-9]/.test(pw)) alpha += 33;
  if (alpha === 0) return 0;
  return pw.length * Math.log2(alpha);
}

/**
 * Generate a Diceware-like passphrase (n words) if wordlist available,
 * otherwise fallback to base64url string (~192-bit raw).
 */
function genPassphraseWords(n = 8) {
  if (wordlist && wordlist.length >= 2048) {
    const words = Array.from({ length: n }, () => rngWord());
    return words.join('-');
  }
  const raw = new Uint8Array(24);
  crypto.getRandomValues(raw);
  const b64 = btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
  return b64;
}



// ===== Password strength (lightweight estimation) =====

/**
 * Render a plain English strength string in the UI based on entropy estimate.
 */
function renderStrength(pw) {
  const el = $('#pwdStrength');
  const bits = Math.round(estimatePasswordEntropyBits(pw));
  if (bits === 0) { setText(el, ''); return; }

  let msg = `Estimated entropy: ~${bits} bits.`;
  if      (bits <  60) msg += ' Weak.';
  else if (bits <  75) msg += ' Moderate.';
  else if (bits < 100) msg += ' Strong.';
  else                 msg += ' Very strong.';
  if (bits < 75) msg += ' Consider using the generator.';
  setText(el, msg);
}



// ===== UI reset/selectors =====

/**
 * Reset encryption panel inputs and progress.
 */
function resetEncryptUI(preservePassword = false) {
  if (!preservePassword) {
    try { $('#encPassword').value = ''; } catch {}
  }
  $('#encText').value = '';
  $('#encFiles').value = '';
  clearNode('#encResults');
  setText('#encHash', '');
  setText('#encPlainHash', '');
  setText('#pwdStrength', '');
  setProgress(encBar, 0);

  // Hide output section if visible, but DO NOT remove its DOM so bundle + hash remain across tabs
  const out = $('#encOutputs');
  if (out) {
    out.classList.add('hidden');
    out.classList.remove('visible');
  }

  // Hide encryption progress container (progress bars should not be visible unless active)
  try {
    const encProgress = document.querySelector('#encBar')?.parentElement;
    if (encProgress) encProgress.style.display = 'none';
  } catch {}

  // Optional: Clear file list UI
  const list = $('#encFileList');
  if (list) setText(list, '');

  // --- resetEncryptUI ---
  try {
    const btn = $('#btnEncrypt');
    const pw = ($('#encPassword').value || '').trim();
    const text = ($('#encText').value || '').trim();
    const files = $('#encFiles').files;
    const ok = (pw.length > 0) && (text.length > 0 || (files && files.length > 0));

    btn.disabled = !ok;
    if (btn.disabled) btn.setAttribute('aria-disabled', 'true');
    else btn.removeAttribute('aria-disabled');
  } catch {}

}


/**
 * Reset decryption panel inputs and progress.
 */
function resetDecryptUI(opts = {}) {
  const { preservePassword = true, preserveFile = true } = opts;

  // clear previous outputs only (results, text, integrity, errors)
  try { clearNode('#decResults'); } catch {}
  try { setText('#decText',''); } catch {}
  try { setText('#decIntegrity',''); } catch {}
  try { setText('#decFileErr',''); } catch {}

  // keep password unless explicitly told otherwise
  if (!preservePassword) {
    try { $('#decPassword').value = ''; } catch {}
  }

  // keep chosen file unless explicitly told otherwise
  if (!preserveFile) {
    try { $('#decFile').value = ''; } catch {}
    try { setText('#decFileName',''); } catch {}
  }

  // --- resetDecryptUI ---
  try {
    const btn = $('#btnDecrypt');
    const pw = ($('#decPassword').value || '').trim();
    const file = ($('#decFile').files || [])[0];
    const ok = (pw.length > 0) && !!file;

    btn.disabled = !ok;
    if (btn.disabled) btn.setAttribute('aria-disabled', 'true');
    else btn.removeAttribute('aria-disabled');
  } catch {}

}


/**
 * Switch between Encrypt and Decrypt tabs and reset both panels.
 */
function selectTab(which) {
  const encTab   = $('#tabEncrypt'), decTab = $('#tabDecrypt');
  const encPanel = $('#panelEncrypt'), decPanel = $('#panelDecrypt');

  if (which === 'enc') {
    encTab.setAttribute('aria-selected', 'true');  decTab.setAttribute('aria-selected', 'false');
    encPanel.hidden = false; decPanel.hidden = true;
  } else {
    decTab.setAttribute('aria-selected', 'true');  encTab.setAttribute('aria-selected', 'false');
    decPanel.hidden = false; encPanel.hidden = true;
  }

  // IMPORTANT: do not reset the encrypt/decrypt UIs here — preserve outputs & bundle & hashes.
  // However, always ensure encryption password is re-hidden after any tab change.
  try {
    const encPwd = $('#encPassword');
    const encToggle = $('#encPwdToggle');
    if (encPwd) {
      encPwd.type = 'password';
      if (encToggle) {
        setText(encToggle, 'Show');
        encToggle.setAttribute('aria-pressed', 'false');
      }
    }
  } catch (e) { /* non-fatal UI tweak */ }

  // Also ensure decrypt preview isn't accidentally visible until a result exists.
  const decText = $('#decText'), decResults = $('#decResults');
  if (decText && decText.textContent.trim() === '') {
    try { decText.hidden = true; } catch {}
  }
  // If there is content in decResults (a result was produced), keep it visible across tab switches.
  if (decResults && decResults.childElementCount > 0) {
    decResults.classList.remove('hidden');
  }
}

/**
 * Switch encryption content input mode (Text vs Files).
 */
function selectContentTab(which) {
  const tBtn=$('#encTabText'), fBtn=$('#encTabFiles');
  const tPanel=$('#encPanelText'), fPanel=$('#encPanelFiles');
  if (which === 'text') {
    tBtn.setAttribute('aria-selected','true');  fBtn.setAttribute('aria-selected','false');
    tPanel.hidden = false; fPanel.hidden = true;
  } else {
    fBtn.setAttribute('aria-selected','true');  tBtn.setAttribute('aria-selected','false');
    fPanel.hidden = false; tPanel.hidden = true;
  }
  clearNode('#encResults');
  setText('#encHash', '');
  setText('#encPlainHash', '');
}



// ===== Auto-tune with budget and cancel support =====

let benchAbort = false;

/**
 * Attach cancel handler for the benchmark button at DOM ready.
 */
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('btnCancelBench');
  if (btn) btn.addEventListener('click', () => { benchAbort = true; setLive('Benchmark interrupted'); });
});

/**
 * Auto-tune with a time budget and user cancel. Falls back to the best measured candidate if budget exceeded.
 */
async function autoTuneStrongWithBudget(budgetMs = 2500) {
  benchAbort = false;
  const btn = document.getElementById('btnCancelBench');
  if (btn) btn.hidden = false;

  const tStart = performance.now();
  try {
    const cores       = Math.max(1, Math.min(HEALTHY_P_MAX, (navigator.hardwareConcurrency || 2)));
    const candidateMs = [ ARGON_MIN_MIB, 384, 512, 768, 1024 ];
    const candidateT  = [ ARGON_MIN_T, 4, 5, 6 ];
    let best = null;

    for (const mMiB of candidateMs) {
      for (const t of candidateT) {
        if (benchAbort || (performance.now() - tStart) > budgetMs) throw new Error('bench_budget');
        const p  = Math.min(cores, HEALTHY_P_MAX);
        const ms = await benchOnce({ mMiB, t, p });
        // Yield back to the event loop to keep UI responsive.
        await new Promise(r => setTimeout(r, 0));
        if (!isFinite(ms)) continue;
        const target = (AUTO_TARGET_MS_MIN + AUTO_TARGET_MS_MAX) / 2;
        if (!best || Math.abs(ms - target) < Math.abs(best.ms - target)) best = { mMiB, t, p, ms };
        if (ms >= AUTO_TARGET_MS_MIN && ms <= AUTO_TARGET_MS_MAX) return { mMiB, t, p, ms };
      }
    }
    return best || { mMiB: 512, t: 5, p: Math.min(cores, HEALTHY_P_MAX), ms: 0 };
  } finally {
    if (btn) btn.hidden = true;
  }
}



// ===== Capability probe + auto-tune init =====

/**
 * Checks whether the browser provides the minimum crypto and Worker features required to run safely.
 */
function cryptoRuntimeOk() {
  try {
    const hasSubtle = !!(crypto && crypto.subtle && crypto.getRandomValues);
    const hasWorker = typeof Worker === 'function';
    return hasSubtle && hasWorker;
  } catch { return false; }
}

/**
 * Initialize UI, load wordlist, rate-limit the benchmark, run auto-tune with budget,
 * and store tuned parameters. Disable buttons on failure.
 */
async function init() {
  try {
    // Disable clearly on startup (ARIA + native)
    $('#btnEncrypt').setAttribute('aria-disabled','true');
    $('#btnDecrypt').setAttribute('aria-disabled','true');
    if ($('#btnEncrypt')) $('#btnEncrypt').disabled = true;
    if ($('#btnDecrypt')) $('#btnDecrypt').disabled = true;

    setLive('Initializing…');
    
    if (!cryptoRuntimeOk()) {
      setLive('This browser lacks required crypto/worker features.');
      const be = $('#btnEncrypt'), bd = $('#btnDecrypt');
      if (be) { be.setAttribute('aria-disabled','true'); be.disabled = true; }
      if (bd) { bd.setAttribute('aria-disabled','true'); bd.disabled = true; }
      return;
    }

    await loadWordlist();

    // Benchmark rate-limit check
    const gate = allow('bench');
    if (!gate.ok) {
      // Fallback params so the app remains usable
      const caps = chooseCaps();
      const guessedMiB = clamp(jitterMemory(512), caps.minMemMiB, caps.maxMemMiB);
      const guessedP = clamp(Math.min((navigator.hardwareConcurrency || 2), HEALTHY_P_MAX), 1, caps.maxParallel);
    
      // clamp to global hard mins/maxes BEFORE enabling UI
      tunedParams = {
        mMiB: clamp(guessedMiB, ARGON_MIN_MIB, ARGON_MAX_MIB),
        t:    clamp(5,           ARGON_MIN_T,   ARGON_MAX_T),
        p:    clamp(guessedP,    HEALTHY_P_MIN, HEALTHY_P_MAX)
      };
      window.__MAX_INPUT_BYTES_DYNAMIC = caps.maxInput;
    
      setLive(`Auto (fallback): ${tunedParams.mMiB} MiB, t=${tunedParams.t}, p=${tunedParams.p}`);
    
      // Re-enable buttons so the app can run with fallback parameters
      const be = $('#btnEncrypt'), bd = $('#btnDecrypt');
      if (be) { be.removeAttribute('aria-disabled'); be.disabled = false; }
      if (bd) { bd.removeAttribute('aria-disabled'); bd.disabled = false; }
    
      // IMPORTANT: do not return; we keep going with fallback params
    }

    // Auto-tune with a time budget; safe fallback on failure
    const tuned = await autoTuneStrongWithBudget(2500)
      .catch(() => ({ mMiB: 512, t: 5, p: 2, ms: 0 }));

    // Apply adaptive limits based on device profile
    const caps = chooseCaps();
    tuned.mMiB = clamp(tuned.mMiB, caps.minMemMiB, caps.maxMemMiB);
    tuned.p    = clamp(tuned.p, 1, caps.maxParallel);
    window.__MAX_INPUT_BYTES_DYNAMIC = caps.maxInput;

    tuned.mMiB = jitterMemory(tuned.mMiB);
    tunedParams = {
      mMiB: clamp(tuned.mMiB, ARGON_MIN_MIB, ARGON_MAX_MIB),
      t: clamp(tuned.t, ARGON_MIN_T, ARGON_MAX_T),
      p: clamp(tuned.p, HEALTHY_P_MIN, HEALTHY_P_MAX)
    };
    setLive(`Auto: ${tunedParams.mMiB} MiB, t=${tunedParams.t}, p=${tunedParams.p}`);

    // Fully re-enable buttons (ARIA + native)
    const be = $('#btnEncrypt'), bd = $('#btnDecrypt');
    if (be) { be.removeAttribute('aria-disabled'); be.disabled = false; }
    if (bd) { bd.removeAttribute('aria-disabled'); bd.disabled = false; }

  } catch (e) {
    setLive('This device cannot load Argon2/WASM. Encryption disabled.');
    // Keep disabled (ARIA + native)
    const be = $('#btnEncrypt'), bd = $('#btnDecrypt');
    if (be) { be.setAttribute('aria-disabled','true'); be.disabled = true; }
    if (bd) { bd.setAttribute('aria-disabled','true'); bd.disabled = true; }
    logError(e);
    clearPasswords();
  }
}




// ===== Build helpers =====

/**
 * Produce canonical chunk filenames.
 */
function chunkNames(n) {
  return Array.from({ length: n }, (_, i) => `part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`);
}

/**
 * Chunking util for arbitrary bytes into FIXED_CHUNK_SIZE.
 */
function chunkFixedGeneric(u8) {
  const chunks = [];
  for (let i = 0; i < u8.length; i += FIXED_CHUNK_SIZE) {
    chunks.push(u8.subarray(i, Math.min(u8.length, i + FIXED_CHUNK_SIZE)));
  }
  return chunks.length ? chunks : [ new Uint8Array(0) ];
}


// ===== Encrypt flow =====

/**
 * Encrypt text or files into a manifest-bound multi-part envelope bundle (.cboxbundle),
 * or a single .cbox if only one chunk.
 */
async function doEncrypt() {
  let payloadBytes = null, bundle = null;
  try {
    logInfo('[enc] start');
    try { logInfo('[enc] tracked URLs before', { tracked: __urlsToRevoke ? __urlsToRevoke.size : 'n/a' }); } catch {}

    // Show encryption progress only while running
    try {
      const encProgress = document.querySelector('#encBar')?.parentElement;
      if (encProgress) encProgress.style.display = 'block';
    } catch {}

    setProgress(encBar, 5);

    // Only clear OUTPUTS — keep inputs AND password !
    clearNode('#encResults');
    setText('#encHash','');
    setText('#encPlainHash','');
    logInfo('[enc] outputs cleared');

    const pw = $('#encPassword').value || '';
    if (!pw) throw new EnvelopeError('input', 'missing');
    const password = pw.normalize('NFKC');

    // Source selection: text or files
    let sourceKind = '';
    let fileList   = null;
    const textMode = !$('#encPanelText').hidden;
    if (textMode) {
      const raw = $('#encText').value;
      if (!raw) throw new EnvelopeError('input', 'missing');
      payloadBytes = TE.encode(raw);
      sourceKind = 'text';
    } else {
      const files = Array.from($('#encFiles').files || []);
      if (files.length === 0) throw new EnvelopeError('input', 'missing');
      let total = 0; const items = [];
      for (const f of files) {
        const buf = new Uint8Array(await f.arrayBuffer());
        const maxIn = window.__MAX_INPUT_BYTES_DYNAMIC || MAX_INPUT_BYTES;
        total += buf.length;
        if (total > maxIn) {
          throw new EnvelopeError('input_large', 'Total input too large for this device');
        }
        items.push({ name: f.name, bytes: buf, type: f.type || 'application/octet-stream' });
      }
      fileList = items.map(x => ({
        name: x.name,
        size: x.bytes.length,
        type: x.type || 'application/octet-stream'
      }));
      if (items.length === 1) {
        payloadBytes = items[0].bytes;
      } else {
        const zip = buildZip(items.map(p => ({ name: p.name, bytes: p.bytes })));
        items.forEach(p => wipeBytes(p.bytes));
        payloadBytes = zip;
      }
      sourceKind = 'files';
    }

    if (payloadBytes.length > (window.__MAX_INPUT_BYTES_DYNAMIC || MAX_INPUT_BYTES)) {
      throw new EnvelopeError('input_large', 'Input too large for this device');
    }
    logInfo('[enc] input prepared', {
      sourceKind,
      totalPlainLen: payloadBytes.length,
      textMode
    });

    const totalPlainLen = payloadBytes.length;
    const chunks        = chunkFixed(payloadBytes);
    const totalChunks   = chunks.length;
    logInfo('[enc] chunked', { totalChunks, chunkSize: FIXED_CHUNK_SIZE, totalPlainLen });

    // Random bundleId
    const bundleIdBytes = crypto.getRandomValues(new Uint8Array(16));
    const bundleId = b64(bundleIdBytes);

    const wholeHashHex = await sha256Hex(payloadBytes);

    setProgress(encBar, 15);
    const sealedParts    = [];
    const perChunkHashes = [];
    for (let i = 0; i < totalChunks; i++) {
      const c = chunks[i];
      const isLast   = (i === totalChunks - 1);
      const sliceEnd = isLast ? (totalPlainLen - (FIXED_CHUNK_SIZE * (totalChunks - 1))) : FIXED_CHUNK_SIZE;
      const slice    = c.subarray(0, sliceEnd);

      perChunkHashes.push(await sha256Hex(slice));

      const part = await sealFixedChunk({
        password,
        payloadChunk: c,
        chunkIndex: i,
        totalChunks,
        totalPlainLen,
        params: { ...tunedParams, bundleId }
      });

      sealedParts.push({ name: `part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`, bytes: part });

      setProgress(encBar, 15 + Math.floor(70 * (i + 1) / totalChunks));
      if ((i & 1) === 0) { await new Promise(r => setTimeout(r, 0)); }
    }

    // MANIFEST chunks
    const manifestInner = {
      v: 1,
      kind: 'manifest',
      bundleId,
      chunkSize: FIXED_CHUNK_SIZE,
      totalPlainLen,
      totalChunks,
      chunkHashes: perChunkHashes,
      wholePlainHash: wholeHashHex,
      source: { kind: sourceKind, files: fileList || null },
      createdAt: new Date().toISOString()
    };
    const manifestBytes  = TE.encode(JSON.stringify(manifestInner));
    const manChunksClear = chunkFixedGeneric(manifestBytes); // slices
    const manSealedParts = [];
    for (let i = 0; i < manChunksClear.length; i++) {
      const padded = padToFixed(manChunksClear[i]);
      const sealed = await sealFixedChunk({
        password,
        payloadChunk: padded,
        chunkIndex: i,
        totalChunks: manChunksClear.length,
        totalPlainLen: manifestBytes.length,
        params: { ...tunedParams, bundleId }
      });
      manSealedParts.push({ name: `MANIFEST.part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`, bytes: sealed });
    }

    // Authenticated manifest index
    const manChunkHashes = [];
    for (const c of manChunksClear) manChunkHashes.push(await sha256Hex(c));
    const manifestIndexInner = {
      v: 1,
      kind: 'manifest_index',
      totalChunks: manChunksClear.length,
      totalLen: manifestBytes.length,
      chunkSize: FIXED_CHUNK_SIZE,
      chunkHashes: manChunkHashes
    };
    const manIndexBytes  = TE.encode(JSON.stringify(manifestIndexInner));
    const manIndexChunks = chunkFixedGeneric(manIndexBytes);
    const manIndexSealed = [];
    for (let i = 0; i < manIndexChunks.length; i++) {
      const chunk = padToFixed(manIndexChunks[i]);
      const sealed = await sealFixedChunk({
        password,
        payloadChunk: chunk,
        chunkIndex: i,
        totalChunks: manIndexChunks.length,
        totalPlainLen: manIndexBytes.length,
        params: { ...tunedParams, bundleId }
      });
      manIndexSealed.push({
        name: `MANIFEST_INDEX.part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`,
        bytes: sealed
      });
    }

    const filesOut = [
      ...sealedParts,
      ...manSealedParts,
      ...manIndexSealed
    ];
    logInfo('[enc] filesOut', { count: filesOut.length });

    let bundleZip;
    try {
      bundleZip = buildZip(filesOut);
      logInfo('[enc] buildZip ok', { zipBytes: bundleZip.length });
    } catch (e) {
      logError('[enc] buildZip failed', e);
      throw e;
    }

    // Wipe & drop buffers now that everything is in the ZIP
    try {
      for (const f of filesOut) { f?.bytes?.fill?.(0); }
    } catch {}
    filesOut.length = 0;
    sealedParts.length = 0;
    manSealedParts.length = 0;
    manIndexSealed.length = 0;

    bundle = bundleZip;

    let outBlob;
    try {
      outBlob = new Blob([bundleZip], { type: 'application/octet-stream' });
      logInfo('[enc] Blob created', { blobSize: outBlob.size });
    } catch (e) {
      logError('[enc] Blob creation failed', e, { zipBytes: bundleZip?.length||null });
      throw e;
    }

    try {
      addDownload('#encResults', outBlob, `secret${FILE_BUNDLE_EXT}`, 'Download bundle');
      logInfo('[enc] addDownload ok', { tracked: __urlsToRevoke?.size });
    } catch (e) {
      logError('[enc] addDownload failed', e);
      throw e;
    }

    const bundleHash = await sha256Hex(bundleZip);

    // Fancy SHA UI
    const hashContainer = document.querySelector('#encHash');
    if (hashContainer) {
      clearNode(hashContainer);

      const label = document.createElement('div');
      label.className = 'muted';
      setText(label, 'Bundle SHA-256:');

      const codeWrap = document.createElement('div');
      codeWrap.style.display = 'flex';
      codeWrap.style.alignItems = 'center';
      codeWrap.style.gap = '8px';
      codeWrap.style.marginTop = '6px';

      const shaCode = document.createElement('code');
      shaCode.style.fontFamily = 'monospace, monospace';
      shaCode.style.padding = '6px 8px';
      shaCode.style.borderRadius = '8px';
      shaCode.style.background = 'rgba(255,255,255,0.02)';
      shaCode.textContent = bundleHash;

      const copyBtn = document.createElement('button');
      copyBtn.className = 'btn secondary';
      copyBtn.type = 'button';
      setText(copyBtn, 'Copy');
      copyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(bundleHash);
          setLive('Bundle SHA copied to clipboard.');
        } catch {
          setLive('Copy failed.');
        }
      };

      codeWrap.appendChild(shaCode);
      codeWrap.appendChild(copyBtn);
      hashContainer.appendChild(label);
      hashContainer.appendChild(codeWrap);
    }

    const out = $('#encOutputs');
    if (out) {
      out.classList.remove('hidden');
      out.classList.add('visible');
      const firstBtn = out.querySelector('button');
      if (firstBtn) firstBtn.focus();
    }

    setProgress(encBar, 100);
    setLive('Encryption complete (bundle bound by manifest index).');
    logInfo('[enc] success');

  } catch (err) {
    logError('[enc] failed', err);
    await secureFail('Encryption');
    setProgress(encBar, 0);
    clearPasswords();
  } finally {
    try {
      const encProgress = document.querySelector('#encBar')?.parentElement;
      if (encProgress) encProgress.style.display = 'none';
    } catch {}

    try { logInfo('[enc] finally: tracked URLs', { tracked: __urlsToRevoke?.size }); } catch {}
    try {
      const resEl = document.querySelector('#encResults');
      const blobs = resEl ? resEl.querySelectorAll('a[href^="blob:"]').length : 0;
      logInfo('[enc] finally: blobs in #encResults', { blobs });
    } catch {}

    if (payloadBytes) wipeBytes(payloadBytes);
    if (bundle) wipeBytes(bundle);
  }
}

function updateEncryptButtonState() {
  const btn = $('#btnEncrypt');
  if (!btn) return;

  const pw = $('#encPassword').value.trim();
  const text = $('#encText').value.trim();
  const files = $('#encFiles').files;

  const hasPassword = pw.length > 0;
  const hasInput = (text.length > 0) || (files && files.length > 0);

  btn.disabled = !(hasPassword && hasInput);
}

function updateDecryptButtonState() {
  const btn = $('#btnDecrypt');
  if (!btn) return;

  const pw = $('#decPassword').value.trim();
  const f = $('#decFile').files?.[0] || null;

  const hasPassword = pw.length > 0;
  const hasFile = !!f;

  btn.disabled = !(hasPassword && hasFile);
}

function maskPasswordField(inputSel, toggleSel) {
  const p = (typeof inputSel === 'string') ? document.querySelector(inputSel) : inputSel;
  if (!p) return;
  p.type = 'password';
  const t = (typeof toggleSel === 'string') ? document.querySelector(toggleSel) : toggleSel;
  if (t) {
    setText(t, 'Show');               // garde la logique existante (texte anglais)
    t.setAttribute('aria-pressed','false');
  }
}



// ===== Validate index set =====

/**
 * Ensure chunk indices are continuous from 0..max without duplicates.
 */
function validateIndexSetFromNames(entries) {
  const partNames = entries.filter(e => /^part-\d{6}\.cbox$/i.test(e.name)).map(e => e.name);
  const idxs = partNames.map(n => parseInt(n.slice(5, 11), 10));
  const set  = new Set(idxs);

  if (set.size !== idxs.length) throw new EnvelopeError('dup_idx', 'Duplicate indices');
  if (set.size === 0)           throw new EnvelopeError('no_parts', 'No data chunks');

  const max = Math.max(...idxs);
  const min = Math.min(...idxs);
  if (min !== 0) throw new EnvelopeError('min_idx', 'Minimum index not zero');

  for (let i = 0; i <= max; i++) { if (!set.has(i)) throw new EnvelopeError('hole_idx','Missing index in sequence'); }
  return { idxs, max };
}



// ===== Post-decrypt rendering =====

/**
 * Incremental text decoding to keep the UI responsive on mid-sized buffers.
 */
async function decodeChunked(u8, chunkSize = 64 * 1024) {
  const td = new TextDecoder();
  let out = '';
  for (let i = 0; i < u8.length; i += chunkSize) {
    out += td.decode(u8.subarray(i, i + chunkSize), { stream: i + chunkSize < u8.length });
    // Yield periodically to keep the event loop responsive
    if (((i / chunkSize) | 0) % 8 === 0) {
      await new Promise(r => setTimeout(r, 0));
    }
  }
  out += td.decode();
  return out;
}

/**
 * If the recovered payload looks like text, render it and offer a text download;
 * otherwise offer a binary download.
 */
async function tryRenderOrDownload(bytes, containerSel, textSel) {
  const decResults = document.querySelector('#decResults');
  const decTextEl = document.querySelector('#decText');

  const isUtf8Text = looksLikeUtf8Text(bytes);
  if (isUtf8Text) {
    if (bytes.length > MAX_PREVIEW) {
      addDownload(
        containerSel,
        new Blob([bytes], { type: 'text/plain;charset=utf-8' }),
        'decrypted.txt',
        'Download text'
      );
      setText(textSel, 'Large text content — download provided.');
      // Reveal the results container since we have a result (download).
      if (decResults) decResults.classList.remove('hidden');
      if (decTextEl) decTextEl.hidden = true;
      return;
    }
    const t = await decodeChunked(bytes);
    setText(textSel, t);
    addDownload(
      containerSel,
      new Blob([t], { type: 'text/plain;charset=utf-8' }),
      'decrypted.txt',
      'Download text'
    );
    // Reveal the results now that we have content
    if (decResults) decResults.classList.remove('hidden');
    if (decTextEl) decTextEl.hidden = false;
  } else {
    addDownload(
      containerSel,
      new Blob([bytes], { type: 'application/octet-stream' }),
      'decrypted.bin',
      'Download file'
    );
    if (decResults) decResults.classList.remove('hidden');
    if (decTextEl) decTextEl.hidden = true;
  }
}




// ===== Decrypt flow (manifest + strict checks) =====

/**
 * Decrypt a .cbox (single) or .cboxbundle (multipart) file and verify integrity
 * against the authenticated manifest. Implements basic UX rate-limit.
 */
async function doDecrypt() {
  let zipU8 = null;
  let recovered = null;

  let entries = null;
  let decryptBtn = null;
  let prevDisabled = false;

  try {
    logInfo('[dec] start');

    // Clear previous decryption outputs (keep user password so retry is easy)
    logInfo('[dec] reset UI outputs');
    resetDecryptUI({ preservePassword: true, preserveFile: true });

    // Show decryption progress container only while active
    try {
      const decProgress = document.querySelector('#decBar')?.parentElement;
      if (decProgress) { decProgress.style.display = 'block'; logInfo('[dec] progress shown'); }
    } catch (e) { logWarn('[dec] progress show warn', e); }

    // UX rate-limit
    const gate = allow('decrypt');
    if (!gate.ok) {
      logWarn('[dec] rate-limited', { wait: gate.wait });
      cooldownButton('#btnDecrypt', gate.wait);
      setProgress(decBar, 0);
      try {
        const decProgress = document.querySelector('#decBar')?.parentElement;
        if (decProgress) { decProgress.style.display = 'none'; logInfo('[dec] progress hidden (rate-limit)'); }
      } catch (e) { logWarn('[dec] progress hide warn (rate-limit)', e); }
      throw new EnvelopeError('rate_limit', 'cooldown');
    }

    setProgress(decBar, 10);

    // Anti double-click during processing
    decryptBtn = document.querySelector('#btnDecrypt');
    prevDisabled = !!decryptBtn?.disabled;
    if (decryptBtn) {
      decryptBtn.disabled = true;
      decryptBtn.setAttribute('aria-disabled', 'true');
      logInfo('[dec] btnDecrypt disabled for processing');
    }

    // Clean output containers
    clearNode('#decResults'); setText('#decText', ''); setText('#decIntegrity', '');
    logInfo('[dec] outputs cleared');

    // Read inputs
    const pw = $('#decPassword').value || '';
    if (!pw) {
      logWarn('[dec] missing password');
      setText('#decFileErr', 'Please enter your passphrase.');
      setProgress(decBar, 0);
      try { const decProgress = document.querySelector('#decBar')?.parentElement; if (decProgress) decProgress.style.display = 'none'; } catch {}
      try { document.getElementById('decPassword')?.focus(); } catch {}
      // restore button state and bail out cleanly
      try { if (decryptBtn) { decryptBtn.disabled = !!prevDisabled; if (!prevDisabled) decryptBtn.removeAttribute('aria-disabled'); } } catch {}
      logInfo('[dec] abort: no password');
      return;
    }
    const password = pw.normalize('NFKC');

    const f = $('#decFile').files?.[0];
    if (!f)  {
      logWarn('[dec] missing file');
      setText('#decFileErr', 'Please choose a .cbox or .cboxbundle file.');
      setProgress(decBar, 0);
      try { const decProgress = document.querySelector('#decBar')?.parentElement; if (decProgress) decProgress.style.display = 'none'; } catch {}
      try { document.getElementById('decDrop')?.focus(); } catch {}
      try { if (decryptBtn) { decryptBtn.disabled = !!prevDisabled; if (!prevDisabled) decryptBtn.removeAttribute('aria-disabled'); } } catch {}
      logInfo('[dec] abort: no file selected');
      return;
    }

    const name = f.name.toLowerCase();

    // Inputs validated, ensure progress visible
    try {
      const decProgress = document.querySelector('#decBar')?.parentElement;
      if (decProgress) { decProgress.style.display = 'block'; logInfo('[dec] progress shown'); }
    } catch (e) { logWarn('[dec] progress show warn', e); }

    const fSize = f.size|0;
    logInfo('[dec] input file', { name, size: fSize });

    // -------- Single fixed-chunk .cbox path --------
    if (name.endsWith(FILE_SINGLE_EXT)) {
      logInfo('[dec] mode=single .cbox');
      const env    = new Uint8Array(await f.arrayBuffer());
      logInfo('[dec] single env bytes', { bytes: env.length });

      const opened = await openFixedChunk({ password, bytes: env });
      const meta   = opened.innerMeta;

      logInfo('[dec] single innerMeta', {
        kind: meta?.kind, idx: meta?.chunkIndex, total: meta?.totalChunks,
        totalPlainLen: meta?.totalPlainLen
      });

      if (meta.kind !== 'fixed') throw new EnvelopeError('kind', 'Unexpected type');

      const idx = meta.chunkIndex|0, total = meta.totalChunks|0, fixed = opened.fixedChunk;
      if (idx !== 0 || total !== 1) throw new EnvelopeError('idx_single', 'Inconsistent index/total');

      if (!Number.isFinite(meta.totalPlainLen) ||
          meta.totalPlainLen < 0 ||
          meta.totalPlainLen > FIXED_CHUNK_SIZE) {
        throw new EnvelopeError('single_len', 'Invalid size for single chunk');
      }

      const sliceEnd = meta.totalPlainLen|0;
      const payload  = fixed.subarray(0, sliceEnd);
      logInfo('[dec] single payload', { sliceEnd });

      // Let tryRenderOrDownload decide (text/html preview vs download)
      await tryRenderOrDownload(payload, '#decResults', '#decText');
      setText('#decIntegrity', `Single-chunk decrypted. Size: ${payload.length} bytes.`);
      try { opened.fixedChunk.fill(0); } catch {}
      try { env.fill(0); } catch {}

      setProgress(decBar, 100);
      setLive('Decryption complete.');
      logInfo('[dec] single decryption success');

      // Reveal results and hide progress container after success
      try {
        const decResults = document.getElementById('decResults');
        const decTextEl  = document.getElementById('decText');
        if (decResults) decResults.classList.remove('hidden');
        if (decTextEl && (decTextEl.textContent || '').trim() !== '') decTextEl.hidden = false;
        const decProgress = document.querySelector('#decBar')?.parentElement;
        if (decProgress) { decProgress.style.display = 'none'; logInfo('[dec] progress hidden (single done)'); }
      } catch (e) { logWarn('[dec] results reveal warn (single)', e); }

      const det = document.getElementById('decDetails');
      if (det) {
        det.open = true;
        const firstBtn = document.querySelector('#decResults button');
        if (firstBtn) firstBtn.focus();
        else det.querySelector('summary')?.focus();
        det.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
      try { $('#decFile').value = ''; setText('#decFileName',''); } catch {}
      return;
    }

    // -------- Bundle (.cboxbundle) path --------
    if (!name.endsWith(FILE_BUNDLE_EXT)) {
      logWarn('[dec] unsupported file extension', { name });
      throw new EnvelopeError('input', 'unsupported');
    }

    zipU8 = new Uint8Array(await f.arrayBuffer());
    logInfo('[dec] zip bytes', { bytes: zipU8.length });
    entries = await extractZipEntriesStrict(zipU8);
    logInfo('[dec] zip parsed', { entries: entries.length });

    // Build a name index and detect duplicates
    const byName = new Map(entries.map(e => [e.name, e]));
    if (byName.size !== entries.length) {
      logWarn('[dec] duplicate entry names detected');
      throw new EnvelopeError('zip_dupe', 'Duplicate entry names in bundle');
    }

    // Only allow expected entry name patterns
    const allowed = [
      /^part-\d{6}\.cbox$/i,
      /^MANIFEST\.part-\d{6}\.cbox$/i,
      /^MANIFEST_INDEX\.part-\d{6}\.cbox$/i
    ];
    let unexpected = 0;
    for (const e of entries) {
      const ok = allowed.some(rx => rx.test(e.name));
      if (!ok) unexpected++;
    }
    if (unexpected) {
      logWarn('[dec] unexpected entries in ZIP', { unexpected });
      throw new EnvelopeError('zip_extra', `Unexpected entry in bundle`);
    }

    // Count categories for logs
    const countParts   = entries.filter(e=>/^part-\d{6}\.cbox$/i.test(e.name)).length;
    const countMan     = entries.filter(e=>/^MANIFEST\.part-\d{6}\.cbox$/i.test(e.name)).length;
    const countManIdx  = entries.filter(e=>/^MANIFEST_INDEX\.part-\d{6}\.cbox$/i.test(e.name)).length;
    logInfo('[dec] entry categories', { dataParts: countParts, manifestParts: countMan, manifestIndexParts: countManIdx });

    // Free raw ZIP buffer early
    try { zipU8.fill(0); } catch {}
    zipU8 = null;

    // ---- 1) MANIFEST via INDEX (multi-part) + PARTS ----
    const idxEntries = entries
      .filter(e => /^MANIFEST_INDEX\.part-\d{6}\.cbox$/i.test(e.name))
      .sort((a, b) => a.name.localeCompare(b.name));
    logInfo('[dec] idxEntries', { count: idxEntries.length });

    let expectedBundleId = null; // learned from first MANIFEST_INDEX part
    if (idxEntries.length === 0) {
      logWarn('[dec] no manifest index');
      throw new EnvelopeError('no_manifest_index', 'Manifest index missing');
    }

    // Decrypt & rebuild the index buffer
    let idxLen = null;
    const idxSlices = [];
    for (let i = 0; i < idxEntries.length; i++) {
      const opened = await openFixedChunk({ password, bytes: idxEntries[i].bytes });

      const bi = opened.meta && opened.meta.bundleId;
      if (i === 0) {
        if (typeof bi !== 'string' || bi.length === 0) {
          logWarn('[dec] bundleId missing on index part 0');
          throw new EnvelopeError('bundle_missing', 'Missing bundleId');
        }
        expectedBundleId = bi;
        logInfo('[dec] learned bundleId for index', { bundleIdPrefix: String(bi).slice(0, 8) });
      } else {
        if (bi !== expectedBundleId) {
          logWarn('[dec] mixed bundleId in index', { i });
          throw new EnvelopeError('bundle_mix', 'Mixed bundleId across manifest index parts');
        }
      }

      const inner = opened.innerMeta;
      logInfo('[dec] index part meta', { i, kind: inner.kind, idx: inner.chunkIndex, total: inner.totalChunks, totalPlainLen: inner.totalPlainLen });

      if (inner.kind !== 'fixed') throw new EnvelopeError('idx_part', `Manifest index part ${i}: unexpected type`);
      if (inner.chunkIndex !== i) throw new EnvelopeError('idx_part', `Manifest index part ${i}: wrong index`);
      if (inner.totalChunks !== idxEntries.length) throw new EnvelopeError('idx_part', `Manifest index part ${i}: totalChunks mismatch`);

      if (idxLen === null) {
        idxLen = inner.totalPlainLen | 0;
        if (!Number.isFinite(idxLen) || idxLen < 0) {
          logWarn('[dec] invalid manifest index length', { idxLen });
          throw new EnvelopeError('bad_manifest_index', 'Invalid manifest index length');
        }
      }

      const isLast   = (i === idxEntries.length - 1);
      const sliceEnd = isLast ? (idxLen - (FIXED_CHUNK_SIZE * (idxEntries.length - 1))) : FIXED_CHUNK_SIZE;
      if (sliceEnd < 0 || sliceEnd > FIXED_CHUNK_SIZE) {
        logWarn('[dec] invalid index slice size', { i, sliceEnd });
        throw new EnvelopeError('idx_part', `Manifest index part ${i}: invalid slice size`);
      }

      const slice = opened.fixedChunk.subarray(0, sliceEnd);
      const copy  = new Uint8Array(slice.length);
      copy.set(slice);
      idxSlices.push(copy);

      try { opened.fixedChunk.fill(0); } catch {}
    }

    const idxBuf = new Uint8Array(idxLen);
    let offset = 0;
    for (const s of idxSlices) { idxBuf.set(s, offset); offset += s.length; }

    let manIndex;
    try {
      manIndex = JSON.parse(TD.decode(idxBuf));
      logInfo('[dec] parsed manifest index', {
        kind: manIndex?.kind,
        totalChunks: manIndex?.totalChunks,
        totalLen: manIndex?.totalLen,
        chunkSize: manIndex?.chunkSize
      });
    } catch (e) {
      logError('[dec] index parse error', e);
      throw new EnvelopeError('index_parse', 'Malformed manifest index');
    } finally {
      try { idxBuf.fill(0); } catch {}
      for (const s of idxSlices) { try { s.fill(0); } catch {} }
      idxSlices.length = 0;
    }

    if (manIndex.kind !== 'manifest_index') throw new EnvelopeError('index_kind', 'Unexpected manifest index kind');
    const mTotal = manIndex.totalChunks|0;
    const mLen   = manIndex.totalLen|0;
    const mSize  = manIndex.chunkSize|0;
    if (mSize !== FIXED_CHUNK_SIZE) throw new EnvelopeError('index_chunksize', 'Manifest chunk size mismatch');

    if (!Number.isFinite(mTotal) || mTotal <= 0) throw new EnvelopeError('index_total', 'Invalid manifest index totalChunks');
    if (!Array.isArray(manIndex.chunkHashes) || manIndex.chunkHashes.length !== mTotal) throw new EnvelopeError('index_hashes', 'Manifest index chunkHashes mismatch');
    for (let i = 0; i < manIndex.chunkHashes.length; i++) {
      if (!/^[0-9a-f]{64}$/i.test(manIndex.chunkHashes[i])) {
        logWarn('[dec] invalid manifest index hash', { i });
        throw new EnvelopeError('index_hash', `Invalid index hash at ${i}`);
      }
    }

    // Decrypt + verify each MANIFEST part
    let manifestRecovered = new Uint8Array(mLen);
    let mWritten = 0;
    for (let i = 0; i < mTotal; i++) {
      const entry = byName.get(`MANIFEST.part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`);
      if (!entry) { logWarn('[dec] missing manifest part', { i }); throw new EnvelopeError('missing_manifest_part', `Manifest chunk ${i} missing`); }

      const opened = await openFixedChunk({
        password,
        bytes: entry.bytes,
        expectedBundleId
      });

      const bm = opened.meta && opened.meta.bundleId;
      if (bm !== expectedBundleId) {
        logWarn('[dec] bundleId mismatch in manifest part', { i });
        throw new EnvelopeError('bundle_mismatch', `Manifest chunk ${i}: bundleId mismatch`);
      }

      const inner  = opened.innerMeta;
      if (inner.kind !== 'fixed') throw new EnvelopeError('man_part_kind',  `Manifest chunk ${i}: unexpected type`);
      if (inner.chunkIndex !== i) throw new EnvelopeError('man_part_idx',   `Manifest chunk ${i}: wrong index`);
      if (inner.totalChunks !== mTotal) throw new EnvelopeError('man_part_total', `Manifest chunk ${i}: totalChunks mismatch`);
      if (inner.totalPlainLen !== mLen) throw new EnvelopeError('man_part_len',   `Manifest chunk ${i}: totalLen mismatch`);

      const isLast   = (i === mTotal - 1);
      const sliceEnd = isLast ? (mLen - (FIXED_CHUNK_SIZE * (mTotal - 1))) : FIXED_CHUNK_SIZE;
      const slice    = opened.fixedChunk.subarray(0, sliceEnd);

      const h = await sha256Hex(slice);
      const expected = manIndex.chunkHashes[i];
      if (!timingSafeEqual(h, expected)) {
        logWarn('[dec] manifest hash mismatch', { i });
        throw new EnvelopeError('man_hash_mismatch', `Manifest chunk ${i}: unexpected hash`);
      }

      manifestRecovered.set(slice, i * FIXED_CHUNK_SIZE);
      mWritten += slice.length;
      try { opened.fixedChunk.fill(0); } catch {}

      setProgress(decBar, 10 + Math.floor(10 * (i + 1) / mTotal));
      if ((i & 1) === 0) { await new Promise(r => setTimeout(r, 0)); }
    }
    if (mWritten !== mLen) { logWarn('[dec] manifest rebuild size mismatch', { mWritten, mLen }); throw new EnvelopeError('man_rebuild_size', 'Incorrect manifest reconstructed size'); }

    let manifest;
    try {
      manifest = JSON.parse(TD.decode(manifestRecovered));
      logInfo('[dec] parsed manifest', {
        kind: manifest?.kind,
        totalChunks: manifest?.totalChunks,
        totalPlainLen: manifest?.totalPlainLen,
        chunkSize: manifest?.chunkSize
      });
    } catch (e) {
      logError('[dec] manifest parse error', e);
      throw new EnvelopeError('bad_manifest', 'Invalid manifest JSON');
    } finally {
      try { manifestRecovered.fill(0); } catch {}
    }

    // Manifest sanity checks
    if (manifest.kind !== 'manifest') throw new EnvelopeError('bad_manifest_kind', 'Unexpected manifest kind');
    if (!Number.isFinite(manifest.totalChunks) || manifest.totalChunks <= 0) throw new EnvelopeError('bad_manifest_total', 'Invalid totalChunks');
    if (!Number.isFinite(manifest.totalPlainLen) || manifest.totalPlainLen < 0) throw new EnvelopeError('bad_manifest_len', 'Invalid totalPlainLen');
    if (manifest.chunkSize !== FIXED_CHUNK_SIZE) throw new EnvelopeError('bad_manifest_chunksize', 'Chunk size mismatch');
    if (!Array.isArray(manifest.chunkHashes) || manifest.chunkHashes.length !== manifest.totalChunks) throw new EnvelopeError('bad_manifest_hashes', 'chunkHashes length mismatch');
    for (let i = 0; i < manifest.chunkHashes.length; i++) {
      if (!/^[0-9a-f]{64}$/i.test(manifest.chunkHashes[i])) {
        logWarn('[dec] invalid hash in manifest', { i });
        throw new EnvelopeError('bad_hash', `Invalid hash at manifest index ${i}`);
      }
    }
    if (!/^[0-9a-f]{64}$/i.test(manifest.wholePlainHash || '')) throw new EnvelopeError('bad_whole_hash', 'Invalid wholePlainHash');

    // ---- 2) Validate indices (data parts) ----
    const { idxs, max } = validateIndexSetFromNames(entries);
    logInfo('[dec] data index set', { count: idxs.length, max });
    if ((max + 1) !== manifest.totalChunks) throw new EnvelopeError('total_mismatch', 'totalChunks mismatch');

    // ---- 3) Decrypt and verify each data chunk ----
    const totalLen = manifest.totalPlainLen | 0;
    recovered = new Uint8Array(totalLen);
    let written = 0;

    for (let i = 0; i < manifest.totalChunks; i++) {
      const entry = byName.get(`part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`);
      if (!entry) { logWarn('[dec] missing data chunk', { i }); throw new EnvelopeError('missing_part', `Chunk ${i} missing`); }

      const opened = await openFixedChunk({
        password,
        bytes: entry.bytes,
        expectedBundleId
      });

      const bd = opened.meta && opened.meta.bundleId;
      if (bd !== expectedBundleId) {
        logWarn('[dec] bundleId mismatch in data part', { i });
        throw new EnvelopeError('bundle_mismatch', `Chunk ${i}: bundleId mismatch`);
      }

      const inner  = opened.innerMeta;
      if (inner.kind !== 'fixed') throw new EnvelopeError('part_kind',  `Chunk ${i}: unexpected type`);
      if (inner.chunkIndex !== i) throw new EnvelopeError('part_idx',   `Chunk ${i}: wrong internal index`);
      if (inner.totalChunks !== manifest.totalChunks)     throw new EnvelopeError('part_total', `Chunk ${i}: totalChunks mismatch`);
      if (inner.totalPlainLen !== manifest.totalPlainLen) throw new EnvelopeError('part_len',   `Chunk ${i}: totalPlainLen mismatch`);

      const isLast   = (i === manifest.totalChunks - 1);
      const sliceEnd = isLast ? (manifest.totalPlainLen - (FIXED_CHUNK_SIZE * (manifest.totalChunks - 1))) : FIXED_CHUNK_SIZE;
      const slice    = opened.fixedChunk.subarray(0, sliceEnd);

      const h = await sha256Hex(slice);
      const expected = manifest.chunkHashes[i];
      if (!timingSafeEqual(h, expected)) {
        logWarn('[dec] data hash mismatch', { i });
        throw new EnvelopeError('hash_mismatch', `Chunk ${i}: unexpected hash`);
      }

      recovered.set(slice, i * FIXED_CHUNK_SIZE);
      written += slice.length;
      try { opened.fixedChunk.fill(0); } catch {}

      setProgress(decBar, 20 + Math.floor(70 * (i + 1) / manifest.totalChunks));
      if ((i & 1) === 0) { await new Promise(r => setTimeout(r, 0)); }
    }

    if (written !== manifest.totalPlainLen) {
      logWarn('[dec] rebuilt total size mismatch', { written, expected: manifest.totalPlainLen });
      throw new EnvelopeError('rebuild_size', 'Incorrect reconstructed size');
    }

    // ---- 4) Verify whole-plaintext hash (silent in UI) ----
    const whole = await sha256Hex(recovered);
    const ok = timingSafeEqual(whole, manifest.wholePlainHash);
    logInfo('[dec] whole hash check', { ok });
    setText('#decIntegrity', ok ? 'Integrity OK.' : 'Alert: plaintext hash mismatch.');

    // ---- 5) Render / download ----
    let handled = false;
    if (manifest?.source?.kind === 'files' && Array.isArray(manifest.source.files)) {
      if (manifest.source.files.length === 1) {
        // Single original file: restore original name + MIME
        const meta0 = manifest.source.files[0] || {};
        const safeName = String(meta0.name || 'file').replace(/[\/\\]/g, '');
        const mime = meta0.type || 'application/octet-stream';
        addDownload(
          '#decResults',
          new Blob([recovered], { type: mime }),
          safeName,
          'Download file'
        );
        handled = true;
        logInfo('[dec] rendered single file download', { name: safeName, mime });
      } else {
        // Multi-file: you encrypted a ZIP at source -> return ZIP
        addDownload(
          '#decResults',
          new Blob([recovered], { type: 'application/zip' }),
          'files.zip',
          'Download archive'
        );
        handled = true;
        logInfo('[dec] rendered multi-file zip download');
      }
    }

    if (!handled) {
      // Fallback: render text/HTML if it looks like text; else generic download
      const looksText = looksLikeUtf8Text(recovered);
      logInfo('[dec] rendering generic', { looksText, bytes: recovered.length });
      await tryRenderOrDownload(recovered, '#decResults', '#decText');
    }

    setProgress(decBar, 100);
    setLive('Decryption complete.');
    logInfo('[dec] success');

    // Reveal results and hide progress container after success
    try {
      const decResults = document.getElementById('decResults');
      const decTextEl  = document.getElementById('decText');
      if (decResults) decResults.classList.remove('hidden');
      if (decTextEl && (decTextEl.textContent || '').trim() !== '') decTextEl.hidden = false;
      const decProgress = document.querySelector('#decBar')?.parentElement;
      if (decProgress) { decProgress.style.display = 'none'; logInfo('[dec] progress hidden (done)'); }
    } catch (e) { logWarn('[dec] results reveal warn', e); }

    const det = document.getElementById('decDetails');
    if (det) {
      det.open = true;
      const firstBtn = document.querySelector('#decResults button');
      if (firstBtn) firstBtn.focus();
      else det.querySelector('summary')?.focus();
      det.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }

    try { $('#decFile').value = ''; setText('#decFileName', ''); } catch {}
  } catch (err) {
    // Log with extra metadata when possible
    const meta = { name: (err && err.name) || null, code: (err && err.code) || null, msg: (err && err.message) || String(err) };
    logError('[dec] failed', meta, err);
    await secureFail('Decryption');
    setProgress(decBar, 0);
    clearPasswords();
    // always hide progress container on error
    try {
      const decProgress = document.querySelector('#decBar')?.parentElement;
      if (decProgress) { decProgress.style.display = 'none'; logInfo('[dec] progress hidden (error)'); }
    } catch (e) { logWarn('[dec] progress hide warn (error)', e); }
  } finally {
    // ---- UI restore (anti double-click) ----
    try {
      if (decryptBtn) {
        decryptBtn.disabled = !!prevDisabled;
        if (!prevDisabled) decryptBtn.removeAttribute('aria-disabled');
        logInfo('[dec] btnDecrypt restored', { disabled: !!prevDisabled });
      }
    } catch (e) { logWarn('[dec] btn restore warn', e); }

    // Ensure progress is hidden on any exit path
    try {
      const decProgress = document.querySelector('#decBar')?.parentElement;
      if (decProgress) { decProgress.style.display = 'none'; logInfo('[dec] progress hidden (finally)'); }
    } catch (e) { logWarn('[dec] progress hide warn (finally)', e); }

    // ---- Wipe encrypted chunk buffers (from ZIP or direct .cbox) ----
    try {
      let wiped = 0;
      for (const e of entries || []) { if (e?.bytes?.fill) { e.bytes.fill(0); wiped++; } }
      logInfo('[dec] wiped encrypted buffers', { wiped });
    } catch (e) { logWarn('[dec] wipe buffers warn', e); }

    // ---- Drop references so GC can reclaim ----
    entries = null;

    // ---- Existing memory wipes ----
    if (zipU8)     { wipeBytes(zipU8); logInfo('[dec] wiped zipU8'); }
    if (recovered) { logInfo('[dec] recovered bytes length', { bytes: recovered.length }); wipeBytes(recovered); logInfo('[dec] wiped recovered'); }
    zipU8 = null;
    recovered = null;

    // Keep results visible only if there is content; otherwise keep hidden
    try {
      const decResults = document.getElementById('decResults');
      const decTextEl  = document.getElementById('decText');
      const resChildren = decResults ? decResults.childElementCount : 0;
      const hasText = decTextEl ? ((decTextEl.textContent || '').trim() !== '') : false;
      if (decResults && resChildren === 0) decResults.classList.add('hidden');
      if (decTextEl && !hasText) decTextEl.hidden = true;
      logInfo('[dec] final visibility', { resChildren, hasText });
    } catch (e) { logWarn('[dec] final visibility warn', e); }
  }
}


// ===== Trusted Types: strong default policy + GitHub Pages compatibility =====
//
// Keep `require-trusted-types-for 'script'` in the page CSP.
// This policy:
//  - blocks createHTML / createScript (no innerHTML/eval injection)
//  - only allows same-origin ScriptURL
//  - supports relative paths and subfolders (GitHub Pages)

(function setupTrustedTypes() {
  if (!window.trustedTypes || trustedTypes.defaultPolicy) return;
  try {
    trustedTypes.createPolicy('default', {
      createHTML(_html) {
        throw new TypeError('Blocked createHTML by default Trusted Types policy');
      },
      createScript(_js) {
        throw new TypeError('Blocked createScript by default Trusted Types policy');
      },
      createScriptURL(url) {
        // Correctly resolves relative paths and GitHub Pages subfolders
        const u = new URL(url, location.href);

        // 1) Require same origin
        if (u.origin !== location.origin) {
          throw new TypeError('Only same-origin ScriptURL allowed');
        }

        // 2) Whitelist allowed JS files (works with subfolders)
        const allowed =
          u.pathname.endsWith('/app.js') ||
          u.pathname.endsWith('/argon-worker.js') ||
          u.pathname.endsWith('/argon-worker-permissive.js') ||
          u.pathname.endsWith('/argon2-bundled.min.js');

        if (!allowed) {
          throw new TypeError('ScriptURL path not whitelisted: ' + u.pathname);
        }

        return u.toString();
      }
    });
  } catch (e) {
    logWarn && logWarn('Trusted Types default policy not installed:', e);
  }
})();



// ===== Panic / Clear all =====

/**
 * Clear all local UI state, wipe progress, and revoke created object URLs.
 */
function panicClear() {
  try {
    resetEncryptUI();
    resetDecryptUI();
    clearPasswords();

    $('#encText').value = '';
    $('#encFiles').value = '';
    $('#decFile').value  = '';
    setText('#decFileName', '');
    clearNode('#decResults');
    clearNode('#encResults');
    setText('#decText', '');
    setText('#encHash', '');
    setText('#encPlainHash', '');
    setText('#decIntegrity', '');
    setProgress(encBar, 0);
    setProgress(decBar, 0);
    setLive('All local state cleared. Decryption results removed.');

    for (const url of __urlsToRevoke) {
      try { URL.revokeObjectURL(url); } catch {}
      __urlsToRevoke.delete(url);
    }
  } catch (e) {
    logWarn('panicClear issue:', e);
  }
}

// --- Revoke any pending object URLs on pagehide/unload ---
function revokeAllObjectURLsNow() {
  try {
    let count = 0;
    for (const url of __urlsToRevoke) {
      try { URL.revokeObjectURL(url); } catch {}
      count++;
    }
    __urlsToRevoke.clear();
    logInfo && logInfo('[revokeAllObjectURLsNow] revoked all', { count });
  } catch {}
}



// ===== Drag & Drop (mobile & desktop accessibility) =====

/**
 * Make a dropzone trigger an <input type="file"> (click or keyboard).
 */
function wireDrop(zoneId, inputId, listId){
  const zone  = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  const list  = listId ? document.getElementById(listId) : null;
  if (!zone || !input) return;

  // Trigger system picker on click or keyboard activation
  const openPicker = () => input.click();
  zone.addEventListener('click', openPicker);
  zone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openPicker();
    }
  });

  // Highlight dropzone when dragging files over it
  ['dragenter', 'dragover'].forEach(ev =>
    zone.addEventListener(ev, (e) => {
      e.preventDefault();
      zone.classList.add('drag');
    })
  );

  // Remove highlight when leaving or dropping
  ['dragleave', 'drop'].forEach(ev =>
    zone.addEventListener(ev, (e) => {
      e.preventDefault();
      zone.classList.remove('drag');
    })
  );

  // Assign dropped files to input and trigger change
  zone.addEventListener('drop', (e) => {
    input.files = e.dataTransfer?.files || input.files;
    input.dispatchEvent(new Event('change', { bubbles:true }));
  });

  // Update UI when files are selected (optional list of file names)
  input.addEventListener('change', () => {
    if (list) {
      clearNode(list);
      [...(input.files || [])].forEach(f => {
        const li = document.createElement('li');
        setText(li, `${f.name} (${(f.size / 1024).toFixed(1)} KB)`);
        list.appendChild(li);
      });
    }

    // Update selected filename in decrypt panel
    if (inputId === 'decFile') {
      const nameEl = document.getElementById('decFileName');
      if (nameEl) setText(nameEl, input.files?.[0]?.name || '');
    }
  });
}



// ===== Events & UX bootstrap =====

/**
 * Generate a strong passphrase and reveal it, updating the strength helper.
 */
function genPassphrase() {
  const p = $('#encPassword');
  p.value = genPassphraseWords(8);
  maskPasswordField('#encPassword', '#encPwdToggle');
  renderStrength(p.value);
  setLive('Passphrase generated.');
}

/**
 * DOMContentLoaded wiring for all UI controls and initialization.
 */
document.addEventListener('DOMContentLoaded', () => {
  // Tabs
  $('#tabEncrypt').addEventListener('click', () => selectTab('enc'));
  $('#tabEncrypt').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') selectTab('enc'); });
  $('#tabDecrypt').addEventListener('click', () => selectTab('dec'));
  $('#tabDecrypt').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') selectTab('dec'); });

  // Content sub-tabs
  $('#encTabText').addEventListener('click', () => selectContentTab('text'));
  $('#encTabFiles').addEventListener('click', () => selectContentTab('files'));
  $('#encTabText').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') selectContentTab('text'); });
  $('#encTabFiles').addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') selectContentTab('files'); });

  // Password visibility toggles
  $('#encPwdToggle').addEventListener('click', () => {
    const p = $('#encPassword'); const b = $('#encPwdToggle');
    const show = p.type === 'password'; p.type = show ? 'text' : 'password';
    setText(b, show ? 'Hide' : 'Show');
    b.setAttribute('aria-pressed', String(show));
  });
  $('#decPwdToggle').addEventListener('click', () => {
    const p = $('#decPassword'); const b = $('#decPwdToggle');
    const show = p.type === 'password'; p.type = show ? 'text' : 'password';
    setText(b, show ? 'Hide' : 'Show');
    b.setAttribute('aria-pressed', String(show));
  });

  // Passphrase generator and strength meter
  $('#encPwdGen').addEventListener('click', genPassphrase);
  $('#encPassword').addEventListener('input', (e) => renderStrength(e.target.value));

  // Panel clears
  $('#btnClearEncrypt').addEventListener('click', () => {
       resetEncryptUI();
       setLive('Encryption UI cleared.');
     });
    
  $('#btnClearDecrypt').addEventListener('click', () => {
    resetDecryptUI();
    setLive('Decryption UI cleared.');
  });

  // Action reset
  $('#encPassword').addEventListener('input', updateEncryptButtonState);
  $('#encText').addEventListener('input', updateEncryptButtonState);
  $('#encFiles').addEventListener('change', updateEncryptButtonState);
  $('#decPassword').addEventListener('input', updateDecryptButtonState);
  $('#decFile').addEventListener('change', updateDecryptButtonState);

  // Main actions
  $('#btnEncrypt').addEventListener('click', doEncrypt);
  $('#btnDecrypt').addEventListener('click', doDecrypt);

  // Panic / Clear all
  const panicBtn = $('#btnPanic');
  if (panicBtn) panicBtn.addEventListener('click', panicClear);

  // Dropzones (tap/click selection + drag-and-drop)
  wireDrop('encDrop','encFiles','encFileList');
  wireDrop('decDrop','decFile');

  // Revoke any pending object URLs on pagehide/unload
  window.addEventListener('pagehide', revokeAllObjectURLsNow);
  window.addEventListener('unload', revokeAllObjectURLsNow);

  // Also revoke URLs when the tab goes to the background
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') {
      for (const url of __urlsToRevoke) {
        try { URL.revokeObjectURL(url); } catch {}
      }
      __urlsToRevoke.clear();
    }
  });

  // Prevent page navigation when dropping files outside our dropzones
  ['dragover', 'drop'].forEach(ev => {
    window.addEventListener(ev, (e) => {
      const t = e.target;
      const insideDropzone =
        t && typeof t.closest === 'function' &&
        (t.closest('#encDrop') || t.closest('#decDrop'));
      if (!insideDropzone) {
        e.preventDefault();
      }
    });
  });

  // Initialize
  init();
});



// ===== Minimal jank badge (UX-only, optional) =====
//
// Shows a small badge when long tasks (>120ms) are detected, hides it 2s after
// the last signal. Uses PerformanceObserver when available, otherwise a simple
// event-loop latency heuristic.

(function jankBadge() {
  let badge = document.getElementById('lagBadge');
  if (!badge) {
    const host = document.querySelector('header') || document.body;
    badge = document.createElement('span');
    badge.id = 'lagBadge';
    badge.className = 'badge-warn';
    badge.hidden = true;
    badge.setAttribute('aria-live', 'polite');
    setText(badge, '⚠️ Performance slowdown detected…');
    host.appendChild(badge);
  }

  let hideT;
  function show() {
    badge.hidden = false;
    clearTimeout(hideT);
    hideT = setTimeout(() => { badge.hidden = true; }, 2000);
  }

  if ('PerformanceObserver' in window) {
    try {
      const po = new PerformanceObserver((list) => {
        if (list.getEntries().some(e => e.duration > 120)) show();
      });
      po.observe({ entryTypes: ['longtask'] });
      return;
    } catch {}
  }

  // Fallback: measure event loop drift
  let last = performance.now();
  const T  = 100;  // nominal interval
  const TH = 150;  // tolerated extra delay before signalling jank
  setInterval(() => {
    const now = performance.now();
    const drift = now - last - T;
    if (drift > TH) show();
    last = now;
  }, T);
})();