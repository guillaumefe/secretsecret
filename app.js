// ===== Constants and parameters =====

const ARGON2_JS_PATH   = './argon2-bundled.min.js';
const ARGON2_WASM_PATH = './argon2.wasm';
const WORDLIST_PATH = './eff_large_wordlist.txt'; // UTF-8 wordlist, 1 word per line (may have indexes)
let __WORDSET__ = undefined;
let __WORDLOG2__ = undefined;

// File and chunking
const MAX_INPUT_BYTES   = 100 * 1024 * 1024;        // 100 MiB bound for input payload
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
function revokeSoon(url) {
  try { setTimeout(() => URL.revokeObjectURL(url), 1500); } catch {}
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

/**
 * Clear password inputs and strength readout for hygiene.
 */
function clearPasswords() {
  try { $('#encPassword').value = ''; } catch {}
  try { $('#decPassword').value = ''; } catch {}
  try { $('#pwdStrength').textContent = ''; } catch {}
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
  const el = $('#liveInfo'); if (el) el.textContent = msg;
}

/**
 * Update a CSS progress bar and its ARIA now value.
 */
function setProgress(barSel, val) {
  const el = document.querySelector(barSel);
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
  const url = URL.createObjectURL(blob);
  __urlsToRevoke.add(url);

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.className = 'sr-only';

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'btn secondary';
  btn.textContent = label || ('Download ' + filename);
  btn.onclick = () => { a.click(); revokeSoon(url); };

  container.appendChild(btn);
  container.appendChild(a);
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



// ===== Worker selection (strict vs permissive) =====

/*
  We prefer a strict worker (./argon-worker.js).
  If initialization fails (likely due to missing 'wasm-unsafe-eval' for that platform’s WASM engine),
  we fallback to ./argon-worker-permissive.js, which must be served with a CSP that adds:
    script-src 'self' 'wasm-unsafe-eval'
  Only that worker should get the relaxed directive — never the page.
*/

/**
 * Start an Argon2 worker and wait for its init probe. Reject on timeout or load error.
 */
async function startArgonWorker(url) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const w = new Worker(url);
    const to = setTimeout(() => {
      if (!settled) { settled = true; try { w.terminate(); } catch {} ; reject(new Error('worker_init_timeout')); }
    }, 10000);

    w.onmessage = (e) => {
      const d = e.data || {};
      if (d.cmd === 'init') {
        clearTimeout(to);
        if (!settled) { settled = true; resolve(w); }
      }
    };
    w.onerror = (e) => {
      if (!settled) { settled = true; clearTimeout(to); try { w.terminate(); } catch {} ; reject(e); }
    };

    w.postMessage({ cmd: 'init', payload: { jsURL: ARGON2_JS_PATH, wasmURL: ARGON2_WASM_PATH } });
  });
}

/**
 * Attempt strict worker, fallback to permissive worker if strict init fails.
 */
async function getArgonWorker() {
  try {
    return await startArgonWorker('./argon-worker.js');       // strict
  } catch {
    return await startArgonWorker('./argon-worker-permissive.js'); // permissive
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
  let left = Math.ceil(ms / 1000);
  const id = setInterval(() => {
    btn.textContent = `${saved} (${left--}s)`;
    if (left < 0) { clearInterval(id); btn.disabled = false; btn.textContent = saved; }
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
    crypto.getRandomValues(out.subarray(u8.length));
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
    kdf: { kdf: 'Argon2id', v: 1, mMiB: params.mMiB, t: params.t, p: params.p }
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
async function openFixedChunk({ password, bytes }) {
  if (bytes.length < 9) throw new EnvelopeError('format', 'Invalid envelope');
  if (TD.decode(bytes.subarray(0, 5)) !== 'CBOX4') throw new EnvelopeError('magic', 'Unknown format');

  const metaLen = new DataView(bytes.buffer, bytes.byteOffset + 5, 4).getUint32(0, false);
  const metaEnd = 9 + metaLen;
  if (metaEnd > bytes.length) throw new EnvelopeError('meta_trunc', 'Corrupted metadata');

  const metaBytes = bytes.subarray(9, metaEnd);
  let meta;
  try { meta = JSON.parse(TD.decode(metaBytes)); }
  catch { throw new EnvelopeError('meta_parse', 'Malformed metadata'); }

  const salt = b64d(meta.salt || '');
  const iv   = b64d(meta.iv || '');
  const k    = meta.kdf || {};
  if (k.kdf !== 'Argon2id') throw new EnvelopeError('kdf', 'Unsupported KDF');
  validateArgon({ mMiB: k.mMiB, t: k.t, p: k.p });

  const keyBytes = await deriveArgon2id(password, salt, { mMiB: k.mMiB, t: k.t, p: k.p });
  const key      = await importAesKey(keyBytes);

  const cipher = bytes.subarray(metaEnd);
  const clear  = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: metaBytes, tagLength: 128 }, key, cipher));
  wipeBytes(keyBytes);

  if (clear.length < 4) throw new EnvelopeError('clear_short', 'Malformed plaintext');
  const innerLen = new DataView(clear.buffer, clear.byteOffset, 4).getUint32(0, false);
  const innerEnd = 4 + innerLen;
  if (innerEnd > clear.length) throw new EnvelopeError('inner_trunc', 'Truncated inner meta');

  const innerMetaBytes = clear.subarray(4, innerEnd);
  let innerMeta;
  try { innerMeta = JSON.parse(TD.decode(innerMetaBytes)); }
  catch { throw new EnvelopeError('inner_parse', 'Malformed inner meta'); }

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

/**
 * Strict store-only ZIP extractor with hard bounds and path hygiene.
 * Throws on unsupported features (compression, data descriptor, ZIP64, etc.).
 */
async function extractZipEntriesStrict(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const entries = [];
  let i = 0;
  const LIMIT = u8.length;

  while (i + 30 <= LIMIT) {
    const sig = readU32(dv, i);
    if (sig !== 0x04034b50) break; // stop at first non-LFH

    const versionNeeded = readU16(dv, i + 4); // sanity only
    const gpFlags       = readU16(dv, i + 6);
    const method        = readU16(dv, i + 8);
    const compSize      = readU32(dv, i + 18);
    const uncompSize    = readU32(dv, i + 22);
    const nameLen       = readU16(dv, i + 26);
    const extraLen      = readU16(dv, i + 28);

    // Reject data descriptors and non-store methods
    if ((gpFlags & 0x0008) !== 0) throw new EnvelopeError('zip_dd',    'Data descriptor not allowed');
    if (method !== 0)              throw new EnvelopeError('zip_method','Compression method not supported');

    const headerLen = 30;
    const nameStart = i + headerLen;
    const nameEnd   = nameStart + nameLen;
    const extraStart= nameEnd;
    const extraEnd  = extraStart + extraLen;
    const dataStart = extraEnd;
    const dataEnd   = dataStart + compSize;

    // Bounds checks
    if (nameLen === 0) throw new EnvelopeError('zip_noname','Entry without a name');
    if (nameEnd > LIMIT || extraEnd > LIMIT || dataEnd > LIMIT) throw new EnvelopeError('zip_oob','Entry exceeds buffer');
    if (compSize !== uncompSize) throw new EnvelopeError('zip_len','Store entry must have equal comp/uncomp sizes');

    const nameBytes = u8.subarray(nameStart, nameEnd);
    const name = TD.decode(nameBytes);
    // Basic name hygiene
    if (name.includes('..') || name.startsWith('/') || name.includes('\\')) throw new EnvelopeError('zip_path','Suspicious entry name');

    const data = u8.subarray(dataStart, dataEnd);
    entries.push({ name, bytes: new Uint8Array(data) });

    // Advance
    i = dataEnd;
    // Hard stop guard: prevent looping over arbitrary junk
    if (entries.length > 2000) throw new EnvelopeError('zip_toomany','Too many entries');
  }

  if (entries.length === 0) throw new EnvelopeError('zip_empty','No entries found');
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
    const res = await fetch(WORDLIST_PATH, { cache: 'no-store' });
    if (!res.ok) throw new Error('wordlist missing');
    const text = await res.text();

    const lines = text.split(/\r?\n/);
    const tmp = [];
    const seen = new Set();

    // Detect if majority of non-empty lines begin with a numeric code
    let indexedCount = 0, sampleCount = 0;
    for (const ln of lines) {
      const s = ln.trim();
      if (!s) continue;
      const first = s.split(/\s+/)[0];
      sampleCount++;
      if (/^\d+$/.test(first)) indexedCount++;
      if (sampleCount >= 20) break; // small sample is enough
    }
    const isIndexed = indexedCount > sampleCount * 0.6; // threshold

    for (const ln of lines) {
      const s = ln.trim();
      if (!s) continue;

      let tok;
      const parts = s.split(/\s+/);
      if (isIndexed && parts.length >= 2 && /^\d+$/.test(parts[0])) {
        // EFF-style indexed line
        tok = parts.slice(1).join(' ');
      } else {
        // plain wordlist
        tok = s;
      }

      tok = tok.normalize('NFKC').toLowerCase().trim();
      if (!tok) continue;
      if (!seen.has(tok)) { seen.add(tok); tmp.push(tok); }
    }

    if (tmp.length < 2048) throw new Error('wordlist too small');

    wordlist = tmp;
    __WORDSET__ = new Set(wordlist);
    __WORDLOG2__ = Math.log2(Math.max(1, wordlist.length));
  } catch (e) {
    wordlist = null;
    __WORDSET__ = undefined;
    __WORDLOG2__ = undefined;
    throw e;
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
  if (bits === 0) { el.textContent = ''; return; }

  let msg = `Estimated entropy: ~${bits} bits.`;
  if      (bits <  60) msg += ' Weak.';
  else if (bits <  75) msg += ' Moderate.';
  else if (bits < 100) msg += ' Strong.';
  else                 msg += ' Very strong.';
  if (bits < 75) msg += ' Consider using the generator.';
  el.textContent = msg;
}



// ===== UI reset/selectors =====

/**
 * Reset encryption panel inputs and progress.
 */
function resetEncryptUI() {
  $('#encPassword').value = '';
  $('#encText').value = '';
  $('#encFiles').value = '';
  $('#encResults').innerHTML = '';
  $('#encHash').textContent = '';
  $('#encPlainHash').textContent = '';
  $('#pwdStrength').textContent = '';
  setProgress(encBar, 0);

  // Hide output section if visible
  const out = $('#encOutputs');
  if (out) {
    out.classList.add('hidden');
    out.classList.remove('visible');
  }

  // (optional) Clear file list if used
  const list = $('#encFileList');
  if (list) list.textContent = '';
}


/**
 * Reset decryption panel inputs and progress.
 */
function resetDecryptUI() {
  $('#decPassword').value   = '';
  $('#decFile').value       = '';
  $('#decResults').innerHTML= '';
  $('#decText').textContent = '';
  $('#decIntegrity').textContent = '';
  setProgress(decBar, 0);
}

/**
 * Switch between Encrypt and Decrypt tabs and reset both panels.
 */
function selectTab(which) {
  const encTab   = $('#tabEncrypt'), decTab   = $('#tabDecrypt');
  const encPanel = $('#panelEncrypt'), decPanel = $('#panelDecrypt');
  if (which === 'enc') {
    encTab.setAttribute('aria-selected', 'true');  decTab.setAttribute('aria-selected', 'false');
    encPanel.hidden = false; decPanel.hidden = true;
  } else {
    decTab.setAttribute('aria-selected', 'true');  encTab.setAttribute('aria-selected', 'false');
    decPanel.hidden = false; encPanel.hidden = true;
  }
  resetEncryptUI(); resetDecryptUI();
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
  $('#encResults').innerHTML = '';
  $('#encHash').textContent = '';
  $('#encPlainHash').textContent = '';
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

    await loadWordlist();

    // Benchmark rate-limit check
    const gate = allow('bench');
    if (!gate.ok) {
      setLive(`Auto-tune on cooldown. Try again in ~${Math.ceil(gate.wait/1000)}s.`);
      return;
    }

    // Auto-tune with a time budget; safe fallback on failure
    const tuned = await autoTuneStrongWithBudget(2500)
      .catch(() => ({ mMiB: 512, t: 5, p: 2, ms: 0 }));
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



// ===== Encrypt flow =====

/**
 * Encrypt text or files into a manifest-bound multi-part envelope bundle (.cboxbundle),
 * or a single .cbox if only one chunk.
 */
async function doEncrypt() {
  let payloadBytes = null, bundle = null;
  try {
    setProgress(encBar, 5);
    $('#encResults').innerHTML = ''; $('#encHash').textContent = ''; $('#encPlainHash').textContent = '';

    const pw = $('#encPassword').value || '';
    if (!pw) { alert('Please provide a passphrase.'); return; }
    const password = pw.normalize('NFKC');

    // Source selection: text or files
    let sourceKind = '';
    let fileList   = null;
    const textMode = !$('#encPanelText').hidden;
    if (textMode) {
      const raw = $('#encText').value;
      if (!raw) { alert('Enter some text.'); return; }
      payloadBytes = TE.encode(raw);
      sourceKind = 'text';
    } else {
      const files = Array.from($('#encFiles').files || []);
      if (files.length === 0) { alert('Choose at least one file.'); return; }
      let total = 0; const items = [];
      for (const f of files) {
        const buf = new Uint8Array(await f.arrayBuffer());
        total += buf.length; if (total > MAX_INPUT_BYTES) throw new EnvelopeError('input_large', 'Total input too large');
        items.push({ name: f.name, bytes: buf, type: f.type || 'application/octet-stream' });
      }
      fileList = items.map(x => ({ name: x.name, size: x.bytes.length }));
      if (items.length === 1) {
        payloadBytes = items[0].bytes;
      } else {
        const zip = buildZip(items.map(p => ({ name: p.name, bytes: p.bytes })));
        items.forEach(p => wipeBytes(p.bytes));
        payloadBytes = zip;
      }
      sourceKind = 'files';
    }

    if (payloadBytes.length > MAX_INPUT_BYTES) throw new EnvelopeError('input_large', 'Input too large');

    const totalPlainLen = payloadBytes.length;
    const chunks        = chunkFixed(payloadBytes);
    const totalChunks   = chunks.length;

    // Whole-plaintext hash for manifest binding
    const wholeHashHex = await sha256Hex(payloadBytes);

    // Per-slice hash + sealed parts
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
        password, payloadChunk: c, chunkIndex: i, totalChunks, totalPlainLen, params: tunedParams
      });
      sealedParts.push({ name: `part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`, bytes: part });

      setProgress(encBar, 15 + Math.floor(70 * (i + 1) / totalChunks));

      // Yield to keep the UI responsive for long inputs
      if ((i & 1) === 0) { await new Promise(r => setTimeout(r, 0)); }
    }

    // Authenticated manifest as a fixed "chunk" (padded/truncated to FIXED_CHUNK_SIZE)
    const manifestInner = {
      v: 1,
      kind: 'manifest',
      chunkSize: FIXED_CHUNK_SIZE,
      totalPlainLen,
      totalChunks,
      chunkHashes: perChunkHashes,
      wholePlainHash: wholeHashHex,
      source: { kind: sourceKind, files: fileList || null },
      createdAt: new Date().toISOString()
    };
    const manifestBytes  = TE.encode(JSON.stringify(manifestInner));
    const manifestPadded = manifestBytes.length <= FIXED_CHUNK_SIZE ? manifestBytes : manifestBytes.subarray(0, FIXED_CHUNK_SIZE);
    const manifestSealed = await sealFixedChunk({
      password,
      payloadChunk: manifestPadded,
      chunkIndex: totalChunks,
      totalChunks: totalChunks + 1,
      totalPlainLen: totalPlainLen,
      params: tunedParams
    });

    const filesOut  = [ ...sealedParts, { name: 'MANIFEST.cbox', bytes: manifestSealed } ];
    const bundleZip = buildZip(filesOut);
    bundle = bundleZip;

    addDownload('#encResults', new Blob([bundleZip], { type: 'application/octet-stream' }), `secret${FILE_BUNDLE_EXT}`, 'Download bundle');
    $('#encHash').textContent       = `SHA-256 (bundle): ${await sha256Hex(bundleZip)}`;
    $('#encPlainHash').textContent  = `SHA-256 (plaintext): ${wholeHashHex}`;

    // Show outputs container now that results are available
    const out = $('#encOutputs');
    if (out) {
      out.classList.remove('hidden');
      out.classList.add('visible');
      const firstBtn = out.querySelector('button');
      if (firstBtn) firstBtn.focus();
    }

    setProgress(encBar, 100);
    $('#encText').value      = '';
    $('#encFiles').value     = '';
    $('#encPassword').value  = '';
    $('#pwdStrength').textContent = '';
    setLive('Encryption complete (bundle bound by manifest).');
  } catch (err) {
    logError(err);
    alert('Encryption failed: ' + (err?.message || err));
    setProgress(encBar, 0);
    clearPasswords();
  } finally {
    if (payloadBytes) wipeBytes(payloadBytes);
    if (bundle) wipeBytes(bundle);
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
 * If the recovered payload looks like text, render it and offer a text download;
 * otherwise offer a binary download.
 */
function tryRenderOrDownload(bytes, containerSel, textSel) {
  const isUtf8Text = looksLikeUtf8Text(bytes);
  if (isUtf8Text) {
    const t = TD.decode(bytes);
    $(textSel).textContent = t;
    addDownload(containerSel, new Blob([t], { type: 'text/plain;charset=utf-8' }), 'decrypted.txt', 'Download text');
  } else {
    addDownload(containerSel, new Blob([bytes], { type: 'application/octet-stream' }), 'decrypted.bin', 'Download file');
  }
}



// ===== Decrypt flow (manifest + strict checks) =====

/**
 * Decrypt a .cbox (single) or .cboxbundle (multipart) file and verify integrity
 * against the authenticated manifest. Implements basic UX rate-limit.
 */
async function doDecrypt() {
  let zipU8 = null; let recovered = null;
  try{
    // Rate-limit decrypt attempts
    const gate = allow('decrypt');
    if (!gate.ok) {
      alert(`Too many attempts in a short period. Please wait ~${Math.ceil(gate.wait/1000)}s.`);
      cooldownButton('#btnDecrypt', gate.wait);
      setProgress(decBar, 0);
      return;
    }

    setProgress(decBar, 10);
    $('#decResults').innerHTML = ''; $('#decText').textContent = ''; $('#decIntegrity').textContent = '';

    const pw = $('#decPassword').value || '';
    if (!pw) { alert('Please provide the passphrase.'); return; }
    const password = pw.normalize('NFKC');

    const f = $('#decFile').files?.[0];
    if (!f) { alert('Choose a .cbox or .cboxbundle file.'); return; }
    const name = f.name.toLowerCase();

    if (name.endsWith(FILE_SINGLE_EXT)) {
      // Single chunk case. Decrypt and render.
      const env    = new Uint8Array(await f.arrayBuffer());
      const opened = await openFixedChunk({ password, bytes: env });
      const meta   = opened.innerMeta;
      if (meta.kind !== 'fixed') throw new EnvelopeError('kind', 'Unexpected type');

      const idx = meta.chunkIndex|0, total = meta.totalChunks|0, fixed = opened.fixedChunk;
      if (idx !== 0 || total !== 1) throw new EnvelopeError('idx_single', 'Inconsistent index/total');

      const sliceEnd = meta.totalPlainLen;
      const payload  = fixed.subarray(0, sliceEnd);
      tryRenderOrDownload(payload, '#decResults', '#decText');
      $('#decIntegrity').textContent = `Single-chunk decrypted. Size: ${payload.length} bytes.`;
      setProgress(decBar, 100);
      setLive('Decryption complete.');

      // Expand results; focus first action (download) if present, else the summary; gentle scroll.
      const det = document.getElementById('decDetails');
      if (det) {
        det.open = true;
        const firstBtn = document.querySelector('#decResults button');
        if (firstBtn) firstBtn.focus();
        else det.querySelector('summary')?.focus();
        det.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
      return;
    }

    if (!name.endsWith(FILE_BUNDLE_EXT)) {
      alert('Unsupported file type.');
      setProgress(decBar, 0);
      return;
    }

    // Read ZIP and extract strict entries
    zipU8 = new Uint8Array(await f.arrayBuffer());
    const entries = await extractZipEntriesStrict(zipU8);

    // 1) Manifest
    const manifestEntry = entries.find(e => e.name === 'MANIFEST.cbox');
    if (!manifestEntry) throw new EnvelopeError('no_manifest', 'Manifest missing');

    const manifestOpened = await openFixedChunk({ password, bytes: manifestEntry.bytes });
    const manifest = manifestOpened.innerMeta;
    if (!manifest || manifest.kind !== 'manifest') throw new EnvelopeError('bad_manifest', 'Invalid manifest');

    // 2) Validate indices
    const { idxs, max } = validateIndexSetFromNames(entries);
    if ((max + 1) !== manifest.totalChunks) throw new EnvelopeError('total_mismatch', 'totalChunks mismatch');

    // 3) Decrypt and verify each chunk against manifest
    const totalLen = manifest.totalPlainLen | 0;
    recovered = new Uint8Array(totalLen);
    let written = 0;

    for (let i = 0; i < manifest.totalChunks; i++) {
      const entry = entries.find(e => e.name === `part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`);
      if (!entry) throw new EnvelopeError('missing_part', `Chunk ${i} missing`);

      const opened = await openFixedChunk({ password, bytes: entry.bytes });
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
      if (h !== expected) throw new EnvelopeError('hash_mismatch', `Chunk ${i}: unexpected hash`);

      recovered.set(slice, i * FIXED_CHUNK_SIZE);
      written += slice.length;

      setProgress(decBar, 10 + Math.floor(80 * (i + 1) / manifest.totalChunks));

      // Yield to keep the UI responsive
      if ((i & 1) === 0) { await new Promise(r => setTimeout(r, 0)); }
    }

    if (written !== manifest.totalPlainLen) throw new EnvelopeError('rebuild_size', 'Incorrect reconstructed size');

    // 4) Verify whole-plaintext hash
    const whole = await sha256Hex(recovered);
    const ok = (whole === manifest.wholePlainHash);
    $('#decIntegrity').textContent = ok
      ? `Integrity OK. SHA-256(plaintext)=${whole}`
      : `Alert: Unexpected SHA-256(plaintext) (expected ${manifest.wholePlainHash}, got ${whole})`;

    // 5) Render / download
    tryRenderOrDownload(recovered, '#decResults', '#decText');
    setProgress(decBar, 100);
    setLive('Decryption complete.');

    // 6) Expand results; focus first action (download) if present, else the summary; gentle scroll.
    const det = document.getElementById('decDetails');
    if (det) {
      det.open = true;
      const firstBtn = document.querySelector('#decResults button');
      if (firstBtn) firstBtn.focus();
      else det.querySelector('summary')?.focus();
      det.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  } catch (err) {
    logError(err);
    alert('Decryption failed: ' + (err?.message || err));
    setProgress(decBar, 0);
    clearPasswords();
  } finally {
    if (zipU8)     wipeBytes(zipU8);
    if (recovered) wipeBytes(recovered);
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
    $('#decResults').innerHTML = '';
    $('#encResults').innerHTML = '';
    $('#decText').textContent = '';
    $('#encHash').textContent = '';
    $('#encPlainHash').textContent = '';
    $('#decIntegrity').textContent = '';
    setProgress(encBar, 0);
    setProgress(decBar, 0);
    setLive('All local state cleared.');

    for (const url of __urlsToRevoke) {
      try { URL.revokeObjectURL(url); } catch {}
      __urlsToRevoke.delete(url);
    }
  } catch (e) {
    logWarn('panicClear issue:', e);
  }
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
      list.innerHTML = '';
      [...(input.files || [])].forEach(f => {
        const li = document.createElement('li');
        li.textContent = `${f.name} (${(f.size / 1024).toFixed(1)} KB)`;
        list.appendChild(li);
      });
    }

    // Update selected filename in decrypt panel
    if (inputId === 'decFile') {
      const nameEl = document.getElementById('decFileName');
      if (nameEl) nameEl.textContent = input.files?.[0]?.name || '';
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
  p.type = 'text';
  $('#encPwdToggle').textContent = 'Hide';
  $('#encPwdToggle').setAttribute('aria-pressed','true');
  renderStrength(p.value);
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
    b.textContent = show ? 'Hide' : 'Show';
    b.setAttribute('aria-pressed', String(show));
  });
  $('#decPwdToggle').addEventListener('click', () => {
    const p = $('#decPassword'); const b = $('#decPwdToggle');
    const show = p.type === 'password'; p.type = show ? 'text' : 'password';
    b.textContent = show ? 'Hide' : 'Show';
    b.setAttribute('aria-pressed', String(show));
  });

  // Passphrase generator and strength meter
  $('#encPwdGen').addEventListener('click', genPassphrase);
  $('#encPassword').addEventListener('input', (e) => renderStrength(e.target.value));

  // Panel clears
  $('#btnClearEncrypt').addEventListener('click', resetEncryptUI);
  $('#btnClearDecrypt').addEventListener('click', resetDecryptUI);

  // Main actions
  $('#btnEncrypt').addEventListener('click', doEncrypt);
  $('#btnDecrypt').addEventListener('click', doDecrypt);

  // Panic / Clear all
  const panicBtn = $('#btnPanic');
  if (panicBtn) panicBtn.addEventListener('click', panicClear);

  // Dropzones (tap/click selection + drag-and-drop)
  wireDrop('encDrop','encFiles','encFileList');
  wireDrop('decDrop','decFile');

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
    badge.textContent = '⚠️ Performance slowdown detected…';
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
