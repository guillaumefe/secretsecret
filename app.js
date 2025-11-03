/* =================== Identity and format =================== */

export const CRYPTO_NS   = 'data';   // namespace string used everywhere
export const FORMAT_VER  = '4';      // human-readable version tag

export function buildMagic(ns, ver) {
  if (typeof ns !== 'string' || !ns.length) throw new TypeError('bad ns');
  const s = `${ns.toUpperCase()}${String(ver)}`;
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

// Helpers
function u8startsWith(buf, pre) {
  if (buf.length < pre.length) return false;
  for (let i = 0; i < pre.length; i++) if (buf[i] !== pre[i]) return false;
  return true;
}
function u8hex(u8) {
  return Array.from(u8, b => b.toString(16).padStart(2,'0')).join('');
}

// Base candidate (current version)
export const MAGIC = buildMagic(CRYPTO_NS, FORMAT_VER);

// Current magic and a forward-compatible candidates list.
// To roll forward later, append another buildMagic(CRYPTO_NS, '5'), etc.
// Future versions can be listed here without caring about order
const RAW_MAGIC_CANDIDATES = [
  MAGIC,
  // buildMagic(CRYPTO_NS, 5), // example future
];

// Normalize (dedupe + sort longest→shortest + prefix warnings)
function normalizeMagicCandidates(list) {
  const seen = new Set();
  const uniq = [];
  for (const u8 of list) {
    const key = u8hex(u8);
    if (!seen.has(key)) { seen.add(key); uniq.push(u8); }
  }
  uniq.sort((a,b) => b.length - a.length);
  for (let i = 0; i < uniq.length; i++) {
    for (let j = i+1; j < uniq.length; j++) {
      if (u8startsWith(uniq[i], uniq[j])) {
        console.warn("[MAGIC] prefix overlap detected");
      }
    }
  }
  return Object.freeze(uniq);
}

export const MAGIC_CANDIDATES = normalizeMagicCandidates(RAW_MAGIC_CANDIDATES);

// Derive accepted format versions automatically from MAGIC suffix
function extractVersionFromMagic(u8) {
  let s = "";
  for (let i=0; i<u8.length; i++) s += String.fromCharCode(u8[i]);
  const m = s.match(/(\d+)$/);
  return m ? Number(m[1]) : NaN;
}

// Derive accepted numeric versions from MAGIC_CANDIDATES’ last char(s).
export const ACCEPTED_VERSIONS = Object.freeze(
  MAGIC_CANDIDATES.map(extractVersionFromMagic).filter(Number.isFinite)
);

/* =================== KDF label helpers (namespace-bound) =================== */

function nsLabel(suffix) {
  // All HKDF "info" labels and metadata tags are namespaced
  return `${CRYPTO_NS}/${suffix}`;
}

/* =================== HKDF split and deterministic IV =================== */

/* ******************************************************
 * HKDF helpers (one-time master → subkeys/IVs)
 *  - hkdfExpand: WebCrypto HKDF-Expand (SHA-256)
 *  - hkdfSplit : derive encryption and IV subkeys from master
 ****************************************************** */

export async function hkdfExpand(baseKeyBytes, saltBytes, infoBytes, outLen) {
  const ikm  = await crypto.subtle.importKey('raw', baseKeyBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: infoBytes },
    ikm,
    outLen * 8
  );
  return new Uint8Array(bits);
}

export async function hkdfSplit(master32, bundleSalt) {
  const kEnc32 = await hkdfExpand(master32, bundleSalt, TE.encode(nsLabel('kEnc')), 32);
  const kIv32  = await hkdfExpand(master32, bundleSalt, TE.encode(nsLabel('kIv')),  32);
  return { kEnc32, kIv32 };
}

/* ******************************************************
 * Deterministic 96-bit IV per chunk via HKDF
 *  - Stable for (kIv32, bundleId, chunkIndex)
 ****************************************************** */
export async function deriveIv96(kIv32, bundleId, chunkIndex, domain = CRYPTO_NS) {
  const prefix = TE.encode(nsLabel(`iv/${domain}/`));
  const bid    = TE.encode(bundleId);
  const info   = new Uint8Array(prefix.length + bid.length + 4);
  let p = 0;
  info.set(prefix, p); p += prefix.length;
  info.set(bid,    p); p += bid.length;
  new DataView(info.buffer, info.byteOffset + p, 4).setUint32(0, chunkIndex >>> 0, false);
  return hkdfExpand(kIv32, new Uint8Array(0), info, 12);
}

/* =================== Envelope header matching and parsing =================== */

function matchMagicOrThrow(bytes) {
  if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
  // Try candidates in order; return the first that matches
  for (const cand of MAGIC_CANDIDATES) {
    const L = cand.length;
    if (bytes.length >= L + 4) {
      let ok = true;
      for (let i = 0; i < L; i++) if (bytes[i] !== cand[i]) { ok = false; break; }
      if (ok) return L; // magic length
    }
  }
  throw new EnvelopeError('magic', 'Unknown format');
}

function parseEnvelopeHeaderOrThrow(bytes) {
  if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);

  const MAGIC_LEN = matchMagicOrThrow(bytes);
  if (bytes.length < MAGIC_LEN + 4) {
    throw new EnvelopeError('format', 'Invalid envelope');
  }

  const metaLen   = new DataView(bytes.buffer, bytes.byteOffset + MAGIC_LEN, 4).getUint32(0, false);
  const metaStart = MAGIC_LEN + 4;
  const metaEnd   = metaStart + metaLen;

  if (metaLen <= 0 || metaLen > 4096) throw new EnvelopeError('meta_big', 'Metadata too large');
  if (metaEnd > bytes.length)         throw new EnvelopeError('meta_trunc', 'Corrupted metadata');

  const metaBytes = bytes.subarray(metaStart, metaEnd);
  let meta;
  try { meta = JSON.parse(TD.decode(metaBytes)); }
  catch { throw new EnvelopeError('meta_parse', 'Malformed metadata'); }

  return { meta, metaBytes, metaEnd, MAGIC_LEN };
}

/* =================== Deterministic-envelope opener (bundle keys) =================== */

/* ******************************************************
 * openFixedChunkDet
 *  - Decrypts a fixed-size chunk using bundle-level:
 *      - kEncKey (AES-256-GCM)
 *      - kIv32 (HKDF IV key) to rebuild IV deterministically
 *  - Verifies bundleId and inner meta
 ****************************************************** */
export async function openFixedChunkDet({
  kEncKey, kIv32, bytes, expectedBundleId, chunkIndex, domain = CRYPTO_NS
}) {
  // 1) Parse and validate outer header
  const { meta, metaBytes, metaEnd } = parseEnvelopeHeaderOrThrow(bytes);
  ensureAlgoAndVersionOrThrow(meta);
  ensureNamespaceOrThrow(meta);

  if (expectedBundleId !== undefined && meta.bundleId !== expectedBundleId) {
    throw new EnvelopeError('bundle_mismatch', 'BundleId mismatch');
  }

  // 2) Derive deterministic IV and decrypt
  const ivU8 = await deriveIv96(kIv32, meta.bundleId || '', (chunkIndex >>> 0), domain);
  if (DEBUG && ivU8.length !== 12) throw new EnvelopeError('iv_len', 'IV must be 96-bit');

  const cipher = bytes.subarray(metaEnd);
  if (cipher.length < 16) throw new EnvelopeError('cipher_short', 'Ciphertext too short');

  const clear = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivU8, additionalData: metaBytes, tagLength: 128 },
    kEncKey,
    cipher
  ));

  // 3) Parse inner meta (prefixed length + JSON)
  if (clear.length < 4) throw new EnvelopeError('clear_short', 'Malformed plaintext');
  const innerLen = new DataView(clear.buffer, clear.byteOffset, 4).getUint32(0, false);
  const innerEnd = 4 + innerLen;
  if (innerEnd > clear.length) throw new EnvelopeError('inner_trunc', 'Truncated inner meta');

  let innerMeta;
  try {
    innerMeta = JSON.parse(TD.decode(clear.subarray(4, innerEnd)));
  } catch {
    throw new EnvelopeError('inner_parse', 'Malformed inner meta');
  }

  // Sanity checks on inner meta
  if (
    innerMeta?.kind !== 'fixed' ||
    innerMeta?.fixedSize !== FIXED_CHUNK_SIZE ||
    !Number.isSafeInteger(innerMeta?.totalChunks) ||
    !Number.isSafeInteger(innerMeta?.totalPlainLen) ||
    !Number.isSafeInteger(innerMeta?.chunkIndex) ||
    (innerMeta.chunkIndex !== (chunkIndex >>> 0))
  ) {
    throw new EnvelopeError('inner_meta_invalid', 'Invalid inner meta');
  }

  // Ensure fixed payload fits completely after inner meta
  if (innerEnd + FIXED_CHUNK_SIZE > clear.length) {
    throw new EnvelopeError('inner_fixed_trunc', 'Fixed chunk truncated');
  }

  // 4) Extract fixed-size payload and compute useful length
  const fixedPayload = clear.subarray(innerEnd, innerEnd + FIXED_CHUNK_SIZE);

  const totalChunks   = innerMeta.totalChunks >>> 0;
  const chunkIdx      = innerMeta.chunkIndex >>> 0;
  const totalPlainLen = innerMeta.totalPlainLen >>> 0;

  const bytesBefore = (totalChunks - 1) * FIXED_CHUNK_SIZE;
  const isLast      = (chunkIdx === totalChunks - 1);

  const usefulLen = isLast
    ? Math.max(0, totalPlainLen - bytesBefore)
    : FIXED_CHUNK_SIZE;

  if (usefulLen < 0 || usefulLen > FIXED_CHUNK_SIZE) {
    throw new EnvelopeError('inner_useful_len', 'Invalid useful length');
  }

  // Copy out the whole fixed chunk (for callers that need full block),
  // and also provide a convenient view for the useful plaintext slice.
  const out = new Uint8Array(fixedPayload.length);
  out.set(fixedPayload);
  const fixedChunkUseful = out.subarray(0, usefulLen);

  // 5) Scrub and return
  try { clear.fill(0); } catch {}

  return {
    meta,
    innerMeta,
    fixedChunk: out,
    fixedChunkUseful,              // Uint8Array view of the meaningful bytes
    fixedChunkUsefulLen: usefulLen, // kept for compatibility
    usefulLen                      // same value as above
  };
}

/* =================== Password-envelope opener (legacy per-envelope Argon2id) =================== */

/**
 * openFixedChunk
 * Password-based envelope opener (legacy single-file mode).
 * 
 * Validates:
 * - MAGIC + metadata structure (via parseEnvelopeHeaderOrThrow)
 * - Namespace consistency (ns)
 * - AES-GCM (enc_v, algo)
 * - Argon2id presence and parameter bounds
 * - Base64-encoded salt and IV structure
 * - Inner metadata structure and declared payload size
 */
export async function openFixedChunk({ password, bytes, params }) {
  const { meta, metaBytes, metaEnd } = parseEnvelopeHeaderOrThrow(bytes);

  ensureAlgoAndVersionOrThrow(meta);
  ensureNamespaceOrThrow(meta);

  if (!meta.kdf || meta.kdf.kdf !== 'Argon2id') {
    throw new EnvelopeError('kdf', 'Unsupported KDF');
  }
  if (!meta.salt) {
    throw new EnvelopeError('salt', 'Missing KDF salt');
  }

  // Validate and decode IV / salt
  let ivU8, saltU8;
  try { ivU8 = b64d(String(meta.iv)); }
  catch { throw new EnvelopeError('iv', 'Invalid IV encoding'); }
  if (!ivU8 || ivU8.length !== 12) {
    throw new EnvelopeError('iv_len', 'IV must be 96-bit');
  }

  try { saltU8 = b64d(String(meta.salt)); }
  catch { throw new EnvelopeError('salt', 'Invalid salt encoding'); }
  if (saltU8.length < 16 || saltU8.length > 64) {
    throw new EnvelopeError('salt_len', 'Unsupported salt length');
  }

  // Validate and select KDF parameters
  const kdfParams = {
    mMiB: Number(meta.kdf.mMiB ?? params?.mMiB ?? tunedParams?.mMiB),
    t:    Number(meta.kdf.t    ?? params?.t    ?? tunedParams?.t),
    p:    Number(meta.kdf.p    ?? params?.p    ?? tunedParams?.p)
  };
  validateArgon(kdfParams);

  // Derive per-envelope AES-GCM key
  const keyBytes = await deriveArgon2id(password, saltU8, kdfParams);
  const key      = await importAesKey(keyBytes);

  const cipher = bytes.subarray(metaEnd);
  if (cipher.length < 16) {
    throw new EnvelopeError('cipher_short', 'Ciphertext too short');
  }

  // AES-GCM decryption
  const clear = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivU8, additionalData: metaBytes, tagLength: 128 },
    key,
    cipher
  ));

  if (clear.length < 4) throw new EnvelopeError('clear_short', 'Malformed plaintext');

  // Read inner metadata length (big-endian U32)
  const innerLen = new DataView(clear.buffer, clear.byteOffset, 4).getUint32(0, false);
  const innerEnd = 4 + innerLen;
  if (innerEnd > clear.length) throw new EnvelopeError('inner_trunc', 'Truncated inner metadata');

  // Parse inner metadata (plaintext)
  let innerMeta;
  try {
    innerMeta = JSON.parse(TD.decode(clear.subarray(4, innerEnd)));
  } catch {
    throw new EnvelopeError('inner_parse', 'Malformed inner metadata');
  }

  // Validate inner metadata and payload layout
  if (innerMeta?.kind !== 'fixed' ||
      innerMeta?.fixedSize !== FIXED_CHUNK_SIZE ||
      !Number.isSafeInteger(innerMeta?.totalChunks) ||
      !Number.isSafeInteger(innerMeta?.totalPlainLen)) {
    throw new EnvelopeError('inner_meta_invalid', 'Invalid inner metadata');
  }

  if (innerEnd + FIXED_CHUNK_SIZE > clear.length) {
    throw new EnvelopeError('inner_fixed_trunc', 'Fixed chunk truncated');
  }

  const fixedPayload = clear.subarray(innerEnd, innerEnd + FIXED_CHUNK_SIZE);

  const out = new Uint8Array(fixedPayload.length);
  out.set(fixedPayload);

  // Wipe sensitive buffers
  try { clear.fill(0); } catch {}
  try { keyBytes.fill(0); } catch {}

  return { meta, innerMeta, fixedChunk: out };
}

/* =================== Detector (decides det vs pw) =================== */

export function detectDetEnvelope(bytes) {
  const { meta } = parseEnvelopeHeaderOrThrow(bytes);
  const isDet = (meta?.kdf?.kdf === 'HKDF') && (meta?.salt == null);
  return { kind: isDet ? 'det' : 'pw', meta };
}

/* =================== Writers must also use the NS in metadata =================== */

// Example snippet when creating metadata (AAD) for a sealed part:
// const metaObj = {
//   enc_v: Number(FORMAT_VER),
//   algo: 'AES-GCM',
//   iv: b64(ivU8),
//   salt: null,                     // or b64(salt) for per-envelope paths
//   kdf: { kdf: 'HKDF', v: 1, from: 'Argon2id-once' }, // or { kdf: 'Argon2id', ... }
//   bundleId,
//   ns: CRYPTO_NS                   // namespace marker
// };
// const aad = TE.encode(JSON.stringify(metaObj));

function ensureNamespaceOrThrow(meta) {
  if (meta.ns !== CRYPTO_NS) {
    throw new EnvelopeError('ns_mismatch', 'Namespace mismatch');
  }
}

function ensureAlgoAndVersionOrThrow(meta) {
  if (!ACCEPTED_VERSIONS.includes(Number(meta.enc_v)) || meta.algo !== 'AES-GCM') {
    throw new EnvelopeError('algo', 'Unsupported AEAD');
  }
}

// ===== Other constants and parameters =====

// Build-time flag: set to false in hard-CSP builds
// When false → strict worker only → any CSP/WASM failure is a hard failure
const ALLOW_PERMISSIVE_FALLBACK = true;
let __permissiveFallbackUsed = false;

const REQUIRE_WASM_STRICT = true;

const ARGON2_JS_PATH   = './argon2-bundled.min.js';
const ARGON2_WASM_PATH = './argon2.wasm';
const WORDLIST_PATH = './eff_large_wordlist.txt'; // UTF-8 wordlist, 1 word per line (may have indexes)
let __WORDSET__ = undefined;
let __WORDLOG2__ = undefined;

// File and chunking
const MAX_INPUT_BYTES   = 512 * 1024 * 1024;        // 512 MiB bound for ZIP extraction DoS guard
const MAX_BUNDLE_BYTES = MAX_INPUT_BYTES; 
const FIXED_CHUNK_SIZE  = 4 * 1024 * 1024;          // 4 MiB fixed-size chunks
const FILE_BUNDLE_EXT   = '.bundle';
const FILE_SINGLE_EXT   = '.data';

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
// ====================================================================
// Trusted Script URL (single source of truth)
// - Exact allowlist on absolute pathnames (works in subdir deployments)
// - Same-origin only; no query/hash; no data:/blob:/filesystem:
// - One default TT policy + one worker-url TT policy
// - Safe manual fallback when TT is unavailable
// - No duplicate globals; frozen state; tiny self-tests
// ====================================================================

(() => {
  "use strict";

  // ---------- Utilities (no redefinitions elsewhere) ----------------
  const toAbsURL = (rel) => new URL(String(rel), self.location.href);
  const toAbsPath = (rel) => toAbsURL(rel).pathname;

  // Normalize and freeze an allowlist of absolute paths
  const RAW_ALLOWED_REL = [
    "./app.js",
    "./argon-worker.js",
    "./argon-worker-permissive.js",
    "./argon2-bundled.min.js",
    "./argon2.wasm",     // ✅ nécessaire : permet au worker de charger le WASM
  ];
  const ALLOWED_SCRIPT_PATHS = Object.freeze(new Set(RAW_ALLOWED_REL.map(toAbsPath)));

  // Disallow dangerous schemes explicitly (defense-in-depth)
  const DISALLOWED_SCHEMES = Object.freeze(new Set(["data:", "blob:", "filesystem:"]));

  function assertSameOriginNoSearchHash(urlObj) {
    if (urlObj.origin !== self.location.origin) {
      throw new TypeError("TrustedTypes: only same-origin ScriptURL allowed");
    }
    if (urlObj.search || urlObj.hash) {
      throw new TypeError("TrustedTypes: query/hash not allowed for ScriptURL");
    }
    for (const bad of DISALLOWED_SCHEMES) {
      if (urlObj.href.startsWith(bad)) {
        throw new TypeError(`TrustedTypes: disallowed URL scheme (${bad})`);
      }
    }
  }

  function assertPathAllowed(urlObj) {
    const p = urlObj.pathname;
    if (!ALLOWED_SCRIPT_PATHS.has(p)) {
      try { console.warn("[TT] Blocked ScriptURL path:", p, "(not in allowlist)"); } catch {}
      throw new TypeError("TrustedTypes: ScriptURL path not whitelisted");
    }
  }

  function validateAndStringifyScriptURL(input) {
    const u = toAbsURL(input);
    assertSameOriginNoSearchHash(u);
    assertPathAllowed(u);
    return u.toString();
  }

  // ---------- Trusted Types policies (if supported) ------------------
  let workerUrlPolicy = null;

  (function setupTrustedTypes() {
    const tt = self.trustedTypes;
    if (!tt) return;

    const allowScriptURL = (raw) => validateAndStringifyScriptURL(raw);

    try {
      const already = (typeof tt.getPolicy === "function") ? tt.getPolicy("default") : tt.defaultPolicy;
      if (!already) {
        tt.createPolicy("default", {
          createHTML()   { throw new TypeError("TrustedTypes: createHTML blocked"); },
          createScript() { throw new TypeError("TrustedTypes: createScript blocked"); },
          createScriptURL: allowScriptURL,
        });
      }
    } catch (e) {
      try { console.warn("[TT] default policy install failed (non-fatal):", e); } catch {}
    }

    try {
      workerUrlPolicy =
        (typeof tt.getPolicy === "function" && tt.getPolicy("worker-url")) ||
        tt.createPolicy("worker-url", { createScriptURL: allowScriptURL });
    } catch (e) {
      try { console.warn("[TT] worker-url policy not installed (may already exist):", e); } catch {}
      try {
        workerUrlPolicy = (typeof tt.getPolicy === "function") ? tt.getPolicy("worker-url") : workerUrlPolicy;
      } catch {}
    }
  })();

  function makeTrustedScriptURL(relativePath) {
    if (workerUrlPolicy && typeof workerUrlPolicy.createScriptURL === "function") {
      return workerUrlPolicy.createScriptURL(relativePath);
    }
    return validateAndStringifyScriptURL(relativePath);
  }

  const diagnostics = Object.freeze({
    allowedPaths: Object.freeze([...ALLOWED_SCRIPT_PATHS]),
    hasTrustedTypes: !!self.trustedTypes,
    policyNames: (() => {
      try {
        if (!self.trustedTypes || typeof self.trustedTypes.getPolicyNames !== "function") return [];
        return Object.freeze(self.trustedTypes.getPolicyNames());
      } catch { return []; }
    })(),
  });

  const API = Object.freeze({ makeTrustedScriptURL, diagnostics });

  Object.defineProperty(self, "__ScriptURL", {
    value: API,
    writable: false,
    configurable: false,
    enumerable: false,
  });

  try {
    const ok = makeTrustedScriptURL("./argon-worker.js");
    if (!ok) throw new Error("Self-test: failed to produce a ScriptURL for allowed path");
    let threw = false;
    try { makeTrustedScriptURL("./not-allowed.js"); } catch { threw = true; }
    if (!threw) throw new Error("Self-test: did not block a non-allowlisted path");
  } catch (e) {
    try { console.error("[TT] Self-test failed:", e); } catch {}
  }
})();


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
function redacted(o) {
  if (DEBUG) return o;
  if (o && typeof o === 'object') {
    const c = { ...o };
    if ('fileName' in c) c.fileName = '[redacted]';
    if ('meta' in c) c.meta = '[redacted]';
    return c;
  }
  return o;
}
function logError(...args) { if (DEBUG) { try { console.error(...args); } catch {} } }
function logWarn (...args) { if (DEBUG) { try { console.warn (...args.map(redacted)); } catch {} } }
function logInfo (...args) { if (DEBUG) { try { console.info (...args.map(redacted)); } catch {} } }
function showErrorBanner(text) {
  const el = document.getElementById('errBanner');
  if (!el) return;
  setText(el, text || 'An unexpected error occurred.');
  el.hidden = false;
  // auto-hide after a short period if you like
  setTimeout(() => { try { el.hidden = true; setText(el, ''); } catch {} }, 8000);
}

// === EnvelopeError (global) ===
(() => {
  if (typeof globalThis.EnvelopeError === 'function') return;
  class EnvelopeError extends Error {
    constructor(code, message, opts = {}) {
      if (opts && 'cause' in opts) {
        try { super(message, { cause: opts.cause }); }
        catch { super(message); this.cause = opts.cause; }
      } else {
        super(message);
      }
      this.name = 'EnvelopeError';
      Object.defineProperties(this, {
        code:     { value: code, enumerable: true, writable: true },
        fileName: { value: opts.fileName, enumerable: !!opts.fileName, writable: true },
        meta:     { value: opts.meta, enumerable: !!opts.meta, writable: true },
      });
      if (opts.cause && !('cause' in this)) {
        Object.defineProperty(this, 'cause', { value: opts.cause, enumerable: true });
      }
    }
  }
  globalThis.EnvelopeError = EnvelopeError;
})();

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
  const desktopGuess = (!isMobile && !navigator.deviceMemory) ? 8 : memGiB; // suppose 8 GiB si inconnu

  const mem = (isMobile ? memGiB : desktopGuess) || 4;

  // Overall max input size
  const maxInput = (isMobile || mem <= 4) ?  96 * 1024 * 1024
                    : (mem <= 8)          ? 160 * 1024 * 1024
                                           : 256 * 1024 * 1024;

  const minMemMiB = (isMobile || mem <= 4) ? 64 : 128;
  const maxMemMiB = (isMobile || mem <= 4) ? 256 : 512;
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

async function secureFail(ctx, overrideMsg) {
  await sleep(400); // fixed minimum latency for failure paths
  const generic = `${ctx} failed or file is corrupted.`;
  const msg = DEBUG && overrideMsg ? overrideMsg : generic;

  logInfo('[secureFail]', { ctx, msg });
  setLive(msg);
  showErrorBanner(msg);

  // Hide all progress bars (scoped + decrypt)
  try { showEncProgress('text',  false); } catch {}
  try { showEncProgress('files', false); } catch {}
  try { showProgress('decBar',   false); } catch {}

  // Optionally reset ARIA-now to 0 so screen readers don’t announce stale values
  try { setProgress(document.getElementById('encBarText'),  0); } catch {}
  try { setProgress(document.getElementById('encBarFiles'), 0); } catch {}
  try { setProgress('#decBar', 0); } catch {}

  // Hide results ONLY if they are actually empty (no stale UI)
  try { hideIfEmpty('#encOutputsText',  '#encResultsText'); } catch {}
  try { hideIfEmpty('#encOutputsFiles', '#encResultsFiles'); } catch {}
  try { hideIfEmpty('#decDetails',      '#decResults, #decText'); } catch {}
}

function normalizeEncError(err) {
  try {
    const code = err && err.code;
    const name = err && err.name;
    const raw  = (err && (err.msg || err.message)) || '';
    const text = (raw || '').toString();
    
    // — frequent / known cases —
    if (code === 'input_large' || /Total input too large/i.test(text))
      return 'Total input is too large for this device.';

    if (code === 'too_many_entries' || /too many files|central directory/i.test(text))
      return 'Too many files in the batch.';

    if (code === 'zip_crc' || /CRC mismatch/i.test(text))
      return 'Integrity error (CRC) in the bundle. Try a smaller batch.';

    if (code === 'oom' || /out of memory|heap out of memory|Cannot allocate memory/i.test(text))
      return 'Not enough memory. Close other tabs or split the batch.';

    if (/QuotaExceededError|No space left on device|ENOSPC/i.test(text))
      return 'No storage space available (browser quota).';

    if (code === 'aborted' || name === 'AbortError' || /user aborted|AbortError/i.test(text))
      return 'Operation aborted by user.';

    if (/writer.*closed|stream.*locked|already.*locked/i.test(text))
      return 'Output stream closed or unavailable during encryption.';

    if (/Maximum call stack size exceeded/i.test(text))
      return 'Call stack exceeded (too many files or deeply nested structure).';

    if (/NetworkError|ERR_NETWORK|Failed to fetch/i.test(text))
      return 'Network error during encryption.';

    // Final fallback
    logError('[DEBUG]', err);
    return 'Encryption failed or file is corrupted.';
  } catch {
    logError('[DEBUG]', err);
    return 'Encryption failed or file is corrupted.';
  }
}

// Safe regex-escape
function rxEscape(s){ return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// Name builders (single source of truth)
function namePart(i){ return `part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`; }
function nameManifestPart(i){ return `MANIFEST.part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`; }
function nameIndexPart(i){ return `MANIFEST_INDEX.part-${String(i).padStart(6,'0')}${FILE_SINGLE_EXT}`; }
function nameHeader(){ return `BUNDLE_HEADER${FILE_SINGLE_EXT}`; }

// Dynamic regex (case-insensitive)
const RX_SINGLE_EXT     = new RegExp(rxEscape(FILE_SINGLE_EXT) + '$', 'i');
const RX_BUNDLE_EXT     = new RegExp(rxEscape(FILE_BUNDLE_EXT) + '$', 'i');
const RX_PART           = new RegExp(`^part-\\d{6}${rxEscape(FILE_SINGLE_EXT)}$`, 'i');
const RX_MANIFEST_PART  = new RegExp(`^MANIFEST\\.part-\\d{6}${rxEscape(FILE_SINGLE_EXT)}$`, 'i');
const RX_INDEX_PART     = new RegExp(`^MANIFEST_INDEX\\.part-\\d{6}${rxEscape(FILE_SINGLE_EXT)}$`, 'i');
const RX_ANY_EXPECTED   = [RX_PART, RX_MANIFEST_PART, RX_INDEX_PART, new RegExp(`^${rxEscape(nameHeader())}$`, 'i')];

function preflightInputs(files) {
  const total = files.reduce((s,f)=>s+ (f.size||0), 0);
  const count = files.length;
  const dm = navigator.deviceMemory || 4; // en GiB – très grossier

  // Heuristiques prudentes
  const maxBytes = Math.min(1.5e9, dm * 0.6 * 1024*1024*1024); // ~60% de la RAM annoncée, plafonné ~1.5GB
  const maxCount = 2000;

  if (count > maxCount) throw new EnvelopeError('too_many_entries', `Too many files (${count})`);
  if (total > maxBytes)  throw new EnvelopeError('input_large', 'Total input too large for this device');
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

  // --- Make container and its <details> parent visible ---
  try {
    // The result container is hidden by default
    container.classList.remove('hidden');
    container.classList.add('visible');

    // Open and reveal its parent <details> (Results), if any
    const det = container.closest('details');
    if (det) {
      det.classList.remove('hidden');
      det.classList.add('visible');
      det.setAttribute('open', '');
    }
  } catch (e) {
    logWarn('[addDownload] visibility update warn', e);
  }
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

/**
 * Start the Argon2 Web Worker and wait for its "init" handshake.
 * - Validates URL via __ScriptURL.makeTrustedScriptURL (TT or safe fallback).
 * - Uses module workers (works with strict CSP + TT).
 * - Cleans up listeners and timers on resolve/reject.
 * - Wraps errors into EnvelopeError with clear codes.
 *
 * @param {string} urlRel - Relative path to the worker (e.g., "./argon-worker.js").
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs=10000] - Handshake timeout.
 * @returns {Promise<Worker>}
 */
async function startArgonWorker(urlRel, opts = {}) {
  const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 10_000;

  // ---- Resolve/validate the worker URL through the central hardening API
  let workerURL;
  try {
    // Produces TrustedScriptURL (when TT available) or a validated absolute string otherwise
    if (!self.__ScriptURL || typeof __ScriptURL.makeTrustedScriptURL !== 'function') {
      throw new EnvelopeError('worker_url_blocked', 'Trusted URL helper missing');
    }
    workerURL = __ScriptURL.makeTrustedScriptURL(urlRel);
  } catch (e) {
    // Keep the path visible in diagnostics when possible
    const pathname = (() => {
      try { return new URL(urlRel, location.href).pathname; } catch { return String(urlRel); }
    })();
    throw (e instanceof EnvelopeError)
      ? e
      : new EnvelopeError('worker_url_blocked', 'Worker URL validation failed', { cause: e, fileName: pathname });
  }

  // ---- Construct the worker
  let w;
  try {
    // Prefer module workers (safer with CSP + no classic inline importScripts)
    w = new Worker(workerURL, { type: 'module', name: 'argon2-worker' });
  } catch (e) {
    // Construction can fail synchronously due to CSP/TT/URL issues
    const pathname = (() => {
      try { return new URL(String(workerURL), location.href).pathname; } catch { return String(urlRel); }
    })();
    throw new EnvelopeError('worker_init', 'Failed to construct Argon2 worker', { cause: e, fileName: pathname });
  }

  // ---- Await handshake ("init") with robust cleanup
  return new Promise((resolve, reject) => {
    let settled = false;

    const cleanup = (terminate = false) => {
      try { w.removeEventListener('message', onMsg); } catch {}
      try { w.removeEventListener('error', onErr); } catch {}
      try { w.removeEventListener('messageerror', onMsgErr); } catch {}
      clearTimeout(to);
      if (terminate) {
        try { w.terminate(); } catch {}
      }
    };

    const to = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup(true);
      reject(new EnvelopeError('worker_init_timeout', 'Argon2 worker handshake timed out'));
    }, timeoutMs);

    const onMsg = (e) => {
      const d = e?.data || {};
      if (d.cmd === 'init') {
        if (settled) return;
        settled = true;
        cleanup(false);
        resolve(w);
      }
    };

    const onErr = (e) => {
      if (settled) return;
      settled = true;
      cleanup(true);
      // Prefer original error if present
      const base = (e && e.error) ? e.error : new Error(e?.message || 'worker_error');
      reject(new EnvelopeError('worker_error', 'Argon2 worker emitted an error', { cause: base }));
    };

    const onMsgErr = () => {
      if (settled) return;
      settled = true;
      cleanup(true);
      reject(new EnvelopeError('worker_message_error', 'Argon2 worker message deserialization failed'));
    };

    w.addEventListener('message', onMsg);
    w.addEventListener('error', onErr);
    w.addEventListener('messageerror', onMsgErr);

    // Kick off worker-side initialization
    try {
      w.postMessage({
        cmd: 'init',
        payload: { jsURL: ARGON2_JS_PATH, wasmURL: ARGON2_WASM_PATH }
      });
    } catch (e) {
      if (settled) return;
      settled = true;
      cleanup(true);
      reject(new EnvelopeError('worker_init', 'Failed to post init message to worker', { cause: e }));
    }
  });
}

/**
 * Attempt strict worker first; auto-fallback to permissive only when strictly necessary.
 */
async function getArgonWorker() {
  try {
    return await startArgonWorker('./argon-worker.js');
  } catch (err) {
    const isTimeoutOrWorkerFail =
      (err && err.code === 'worker_init_timeout') ||
      (err && err.code === 'worker_init') ||
      (err && err.code === 'worker_error') ||
      (err && err.code === 'worker_message_error');
  
    const eligible = looksLikeWasmCspError(err) || isTimeoutOrWorkerFail;
  
    if (!eligible) throw err;
    if (!ALLOW_PERMISSIVE_FALLBACK) throw err;
  
    try {
      console.warn('[argon2] Strict worker indisponible; tentative en mode permissif…');
      const w = await startArgonWorker('./argon-worker-permissive.js');
      __permissiveFallbackUsed = true;
      try {
        showErrorBanner(
          'Running in degraded mode (permissive worker). Cryptography remains safe, but CSP/worker was restricted.'
        );
      } catch {}
      return w;
    } catch (e2) {
      const combo = new EnvelopeError('worker_fallback_failed', 'Permissive worker also failed', { cause: e2 });
      try { combo.meta = { first: err, second: e2 }; } catch {}
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

// --- helper minimal, à poser au-dessus du handler (ou dans tes helpers)
function kdfIsReady() {
  return tunedParams &&
         Number.isFinite(tunedParams.mMiB) &&
         Number.isFinite(tunedParams.t) &&
         Number.isFinite(tunedParams.p);
}

function waitForKdfReady(timeoutMs = 8000, intervalMs = 50) {
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    const id = setInterval(() => {
      if (kdfIsReady()) { clearInterval(id); resolve(true); }
      else if (performance.now() - t0 > timeoutMs) {
        clearInterval(id);
        reject(new EnvelopeError('argon_missing', 'Argon2 parameters are missing'));
      }
    }, intervalMs);
  });
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

function choosePadBucket() {
  const MAX_IN = window.__MAX_INPUT_BYTES_DYNAMIC || MAX_INPUT_BYTES; // ex: 64–256 MiB selon device
  const MiB = 1024 * 1024;

  // On borne le bucket entre 1 MiB et 8 MiB, et on force un multiple du chunk fixe.
  const target = Math.min(8 * MiB, Math.max(1 * MiB, Math.floor(MAX_IN / 8))); 
  const rounded = Math.max(FIXED_CHUNK_SIZE, Math.floor(target / FIXED_CHUNK_SIZE) * FIXED_CHUNK_SIZE);

  return rounded; // p.ex. 4 MiB, 8 MiB… mais jamais plus que ce que supporte le device
}


// ===== Envelope format =====

/**
 * Encode metadata object as additional authenticated data (AAD).
 */
function metaAAD(metaObj) {
  return TE.encode(JSON.stringify(metaObj));
}

/**
 * Validate Argon2 parameter bounds; throw on unsupported values.
 */
function validateArgon(params) {
  // ✅ Correction de la déstructuration
  if (!params || typeof params !== 'object') {
    throw new EnvelopeError('argon_params_missing', 'Argon2 parameters are missing');
  }

  const { mMiB, t, p } = params;

  if (!Number.isFinite(mMiB) || mMiB < ARGON_MIN_MIB || mMiB > ARGON_MAX_MIB)
    throw new EnvelopeError('arg_memory',   'Unsupported Argon2 memory');

  if (!Number.isFinite(t)    || t    < ARGON_MIN_T   || t    > ARGON_MAX_T)
    throw new EnvelopeError('arg_time',     'Unsupported Argon2 time');

  if (!Number.isFinite(p)    || p    < HEALTHY_P_MIN || p    > HEALTHY_P_MAX)
    throw new EnvelopeError('arg_parallel', 'Unsupported Argon2 parallelism');
}

/* ******************************************************
 * sealFixedChunkDet
 *  - Encrypt a fixed-size chunk with AES-GCM (bundle-level keys)
 ****************************************************** */
async function sealFixedChunkDet({ kEncKey, kIv32, bundleId, payloadChunk, chunkIndex, totalChunks, totalPlainLen, domain = CRYPTO_NS }) {
  const ivU8 = await deriveIv96(kIv32, bundleId, chunkIndex, domain);

  if (DEBUG && ivU8.length !== 12)
    throw new EnvelopeError('iv_len', 'IV must be 96-bit');

  const innerMeta = { v: 1, kind: 'fixed', fixedSize: FIXED_CHUNK_SIZE, chunkIndex, totalChunks, totalPlainLen };
  const innerMetaBytes = TE.encode(JSON.stringify(innerMeta));
  const header4 = u32be(innerMetaBytes.length);
  const plainPre = new Uint8Array(4 + innerMetaBytes.length + FIXED_CHUNK_SIZE);
  plainPre.set(header4, 0);
  plainPre.set(innerMetaBytes, 4);
  plainPre.set(payloadChunk, 4 + innerMetaBytes.length);

  const metaObj = {
    enc_v: Number(FORMAT_VER),
    algo: 'AES-GCM',
    iv: b64(ivU8),                     // informational only
    salt: null,
    kdf: { kdf: 'HKDF', v: 1, from: 'Argon2id-once' },
    bundleId,
    ns: CRYPTO_NS
  };
  const aad = metaAAD(metaObj);

  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivU8, additionalData: aad, tagLength: 128 },
    kEncKey, plainPre
  ));

  const head = new Uint8Array(MAGIC.length + 4 + aad.length);
  head.set(MAGIC, 0);
  new DataView(head.buffer, MAGIC.length, 4).setUint32(0, aad.length, false);
  head.set(aad, MAGIC.length + 4);

  const out = new Uint8Array(head.length + ct.length);
  out.set(head, 0); out.set(ct, head.length);

  try { plainPre.fill(0); } catch {}
  return out;
}


// ===== Minimal ZIP (store-only) =====
//
// We only build and read "store" (method=0) entries.
// Extraction validates every header and offset before slicing.
// store-only, CD-authoritative; DD tolerated (via CD values)
// (GPBF bit 3 may be set → ignore LFH sizes/CRC, trust CD)

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

// --- CRC32 incremental update (util pour stream) ---
function crc32Update(crc, u8) {
  let c = crc ^ 0xFFFFFFFF;
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
    const gpbf   = dv.getUint16(p + 8,  true);
    const crc    = dv.getUint32(p + 16, true);
    const csize  = dv.getUint32(p + 20, true);
    const usize  = dv.getUint32(p + 24, true);
    index.set(name, { lfhOffset: relOffsetLFH, gpbf, crc, compSize: csize, size: usize });    

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
    let   compSize      = readU32(dv, i + 18);
    let   uncompSize    = readU32(dv, i + 22);
    const nameLen       = readU16(dv, i + 26);
    const extraLen      = readU16(dv, i + 28);

    if (method !== 0)
      throw new EnvelopeError('zip_method', 'Compression method not supported');

    const headerLen  = 30;
    const nameStart  = i + headerLen;
    const nameEnd    = nameStart + nameLen;
    const extraStart = nameEnd;
    const extraEnd   = extraStart + extraLen;
    const nameBytes  = u8.subarray(nameStart, nameEnd);
    const name       = TD.decode(nameBytes);

    // En mode data-descriptor, on écrase comp/uncomp/CRC avec ceux du CD
    let declaredCRC  = readU32(dv, i + 14);
    if ((gpFlags & 0x0008) !== 0) {
      const cd = cdIndex.get(name);
      if (!cd) throw new EnvelopeError('zip_cd_missing', 'CD entry not found for DD file');
      compSize    = cd.compSize;
      uncompSize  = cd.size;
      declaredCRC = cd.crc;
    }

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

    if (name.includes('..') || name.startsWith('/') || name.includes('\\'))
      throw new EnvelopeError('zip_path', 'Suspicious entry name');

    const data = u8.subarray(dataStart, dataEnd);

    // CRC-32 verification
    const actualCRC = crc32(data);
    if (declaredCRC !== actualCRC) {
      throw new EnvelopeError('zip_crc', 'CRC mismatch in ZIP entry');
    }

    entries.push({ name, bytes: new Uint8Array(data) });

    // En DD, il peut y avoir un data descriptor juste après dataEnd
    if ((gpFlags & 0x0008) !== 0) {
      // Descriptor avec signature 0x08074b50 → 16 octets (4+4+4+4)
      // On le *tolère*, mais pas nécessaire de le revalider ici
      const sig = (dataEnd + 4 <= LIMIT) ? readU32(dv, dataEnd) : 0;
      if (sig === 0x08074b50) i = dataEnd + 16;
      else i = dataEnd; // signature absente tolérée (certains writers)
    } else {
      i = dataEnd;
    }

    if (entries.length > 2000)
      throw new EnvelopeError('zip_toomany', 'Too many entries');
  }

  if (entries.length === 0)
    throw new EnvelopeError('zip_empty', 'No entries found');

  return entries;
}

// --- Minimal sink: segments accumulator ---
class SegmentsSink {
  constructor() {
    this.parts = [];
    this.size = 0;
  }
  async write(u8) {
    const copy = (u8 instanceof Uint8Array) ? u8.slice() : new Uint8Array(u8);
    this.parts.push(copy);
    this.size += copy.length;          // <-- important: COPIED size
  }
  toUint8Array() {
    const out = new Uint8Array(this.size);
    let p = 0;
    for (const part of this.parts) { out.set(part, p); p += part.length; }
    return out;
  }
}

// --- Store-only streaming ZIP (without data descriptor) ---
class StoreZipWriter {
  constructor(sink) {
    this.sink = sink;
    this.offset = 0;
    this.centrals = [];
  }

  // helpers (if not already present)
  _u16(v){ const b=new Uint8Array(2); new DataView(b.buffer).setUint16(0,v,true); return b; }
  _u32(v){ const b=new Uint8Array(4); new DataView(b.buffer).setUint32(0,v,true); return b; }
  _str(s){ return new TextEncoder().encode(s); }
  _concat(...parts){ const n=parts.reduce((a,p)=>a+p.length,0); const out=new Uint8Array(n); let o=0; for(const p of parts){ out.set(p,o); o+=p.length; } return out; }
  _crc32 = (function(){ // table + incremental (if you already have a crc32Update fn, use it)
    const tbl=new Uint32Array(256).map((_,i)=>{let c=i; for(let k=0;k<8;k++) c=(c&1)?(0xEDB88320^(c>>>1)):(c>>>1); return c>>>0;});
    return (crc,u8)=>{ crc^=0xFFFFFFFF; for(let i=0;i<u8.length;i++) crc=tbl[(crc^u8[i])&0xFF]^(crc>>>8); return (crc^0xFFFFFFFF)>>>0; };
  })();

  async addFile(name, size, crc32, bytesProducer) {
    const nameBytes = TE.encode(String(name).replaceAll('\\','/'));
    const { time, date } = dosDT();
  
    const useKnownSizes = (typeof size === 'number' && typeof crc32 === 'number');
  
    // --- 1) Local File Header ---
    const gpbf   = useKnownSizes ? 0x0000 : 0x0008;  // bit 3 = data descriptor
    const method = 0x0000;                           // store
    const LFH = [
      u32le(0x04034b50), u16le(20), u16le(gpbf), u16le(method),
      u16le(time), u16le(date),
      u32le(useKnownSizes ? crc32 : 0),
      u32le(useKnownSizes ? size  : 0),
      u32le(useKnownSizes ? size  : 0),
      u16le(nameBytes.length), u16le(0)
    ];
    for (const part of LFH) { await this.sink.write(part); }
    await this.sink.write(nameBytes);
  
    const lfhOffset = this.offset;
    const headerLen = LFH.reduce((a,p)=>a+p.length,0) + nameBytes.length;
    this.offset += headerLen;
  
    // --- 2) Stream data ---
    let runningCRC = 0 >>> 0;
    let written    = 0 >>> 0;
    for await (const chunk of bytesProducer()) {
      const u8 = (chunk instanceof Uint8Array) ? chunk : new Uint8Array(chunk);
      runningCRC = crc32Update(runningCRC, u8);
      written = (written + u8.length) >>> 0;
      await this.sink.write(u8);
      this.offset += u8.length;
    }
  
    // If we had known sizes, "written" must match "size"
    if (useKnownSizes && written !== size) {
      throw new EnvelopeError('zip_stream_size', `Size changed while writing "${name}" (expected ${size}, got ${written})`, { fileName: name });
    }
  
    // --- 3) Data descriptor if necessary ---
    if (!useKnownSizes) {
      const DD = [
        u32le(0x08074b50),             // signature (recommended)
        u32le(runningCRC),
        u32le(written),
        u32le(written)
      ];
      for (const part of DD) { await this.sink.write(part); }
      this.offset += DD.reduce((a,p)=>a+p.length,0);
    }
  
    // --- 4) Register for Central Directory ---
    const finalCRC  = useKnownSizes ? crc32 : runningCRC;
    const finalSize = useKnownSizes ? size  : written;
    const CDH = [
      u32le(0x02014b50), u16le(20), u16le(20),
      u16le(gpbf), u16le(method),
      u16le(time), u16le(date),
      u32le(finalCRC),
      u32le(finalSize), u32le(finalSize),
      u16le(nameBytes.length), u16le(0), u16le(0), u16le(0), u16le(0),
      u32le(0), u32le(lfhOffset)  // rel offset LFH
    ];
    this.centrals.push({ CDH, nameBytes });
  }

  async finish() {
    // Central directory
    let centralSize = 0;
    for (const {CDH, nameBytes} of this.centrals) {
      for (const part of CDH) { await this.sink.write(part); centralSize += part.length; }
      await this.sink.write(nameBytes); centralSize += nameBytes.length;
    }
    const centralOffset = this.offset;
    this.offset += centralSize;

    // EOCD
    const EOCD = [
      u32le(0x06054b50), u16le(0), u16le(0),
      u16le(this.centrals.length), u16le(this.centrals.length),
      u32le(centralSize), u32le(centralOffset), u16le(0)
    ];
    for (const part of EOCD) { await this.sink.write(part); }

    // If sink is buffered (SegmentsSink), return final U8.
    // Else (FileStreamSink), try .close() and return null.
    if (typeof this.sink.toUint8Array === 'function') {
      return this.sink.toUint8Array();
    }
    if (typeof this.sink.close === 'function') {
      try { await this.sink.close(); } catch {}
    }
    return null;
  }  
}

// File System Access adapter → same interface { write(u8) } as SegmentsSink
class FileStreamSink {
  constructor(fsWritable) { this.w = fsWritable; }
  async write(u8) {
    if (!(u8 instanceof Uint8Array)) u8 = new Uint8Array(u8);
    await this.w.write(u8);            // the API internally takes its own copy
  }
  async close() {
    try { await this.w.close(); } catch {}
  }
}


// Automatically chooses the best sink: FS (O(1)) otherwise memory (SegmentsSink)
async function getBundleSink(suggestedName = 'secret' + FILE_BUNDLE_EXT) {
  if (window.showSaveFilePicker) {
    try {
      const handle = await showSaveFilePicker({
        suggestedName,
        types: [{ description: 'Cipher bundle', accept: { 'application/octet-stream': [FILE_BUNDLE_EXT] } }]
      });
      const writable = await handle.createWritable();
      const sink = new FileStreamSink(writable);
      return { sink, kind: 'fs', close: () => sink.close() };
    } catch (e) {
      logWarn('[sink] SaveFilePicker cancelled or failed, falling back to memory', e);
      const sink = new SegmentsSink();
      return { sink, kind: 'mem', close: null };
    }
  }
  // no FS API: memory fallback
  const sink = new SegmentsSink();
  return { sink, kind: 'mem', close: null };
}


// ===== Manifest (authenticated) =====

/* ******************************************************
 * sealBundleHeaderWithPassword
 *  - Password-based header to bootstrap multi-chunk container keys
 *  - Inner JSON: { v:1, kind:'bundle_header', bundleId, bundleSaltB64 }
 ****************************************************** */
async function sealBundleHeaderWithPassword({ password, params, bundleId, bundleSaltB64 }) {
  // 1) Validate KDF params (mMiB/t/p bounds etc.)
  validateArgon(params);

  // 2) Normalize password if it's a string (consistent with other paths)
  if (typeof password === 'string') {
    password = password.normalize('NFKC');
  }

  // 3) Minimal sanity on inputs persisted in inner JSON
  if (typeof bundleId !== 'string' || bundleId.length === 0) {
    throw new EnvelopeError('bundle_id', 'Invalid bundleId');
  }
  if (typeof bundleSaltB64 !== 'string' || bundleSaltB64.length === 0) {
    throw new EnvelopeError('bundle_salt', 'Invalid bundleSaltB64');
  }
  // ensure bundleSaltB64 decodes (length is informational here, but reject nonsense)
  try {
    const dec = b64d(bundleSaltB64);
    if (dec.length < 16 || dec.length > 64) {
      throw new EnvelopeError('bundle_salt_len', 'Unsupported bundleSalt length');
    }
  } catch (e) {
    if (e instanceof EnvelopeError) throw e;
    throw new EnvelopeError('bundle_salt_b64', 'Malformed bundleSaltB64', { cause: e });
  }

  // 4) Fresh per-envelope salt/IV for the header AEAD
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));

  // 5) Inner JSON
  const inner = { v: 1, kind: 'bundle_header', bundleId, bundleSaltB64 };
  const innerBytes = TE.encode(JSON.stringify(inner));
  const header4    = u32be(innerBytes.length);
  const plainPre   = new Uint8Array(4 + innerBytes.length);
  plainPre.set(header4, 0);
  plainPre.set(innerBytes, 4);

  // 6) AAD / metadata
  const metaObj = {
    enc_v: Number(FORMAT_VER),
    algo: 'AES-GCM',
    iv: b64(iv),
    salt: b64(salt),
    kdf: { kdf: 'Argon2id', v: 1, mMiB: params.mMiB, t: params.t, p: params.p },
    ns: CRYPTO_NS
  };
  const aad = metaAAD(metaObj);

  // 7) Derive & encrypt
  const keyBytes = await deriveArgon2id(password, salt, params);
  const key      = await importAesKey(keyBytes);
  const ct       = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plainPre
  ));

  // 8) Envelope (MAGIC + metaLen + meta + ct)
  const head = new Uint8Array(MAGIC.length + 4 + aad.length);
  head.set(MAGIC, 0);
  new DataView(head.buffer, MAGIC.length, 4).setUint32(0, aad.length, false);
  head.set(aad, MAGIC.length + 4);

  const out = new Uint8Array(head.length + ct.length);
  out.set(head, 0); out.set(ct, head.length);

  // 9) Hygiene
  wipeBytes(keyBytes); wipeBytes(salt); wipeBytes(iv); wipeBytes(plainPre);

  return out;
}


/* ******************************************************
 * openBundleHeaderWithPassword
 *  - Open password-based header and return { bundleId, bundleSaltB64 }
 *  - Dynamic MAGIC length and version/namespace checks
 ****************************************************** */
async function openBundleHeaderWithPassword({ password, bytes, params }) {
  // Parse and validate the outer envelope header (handles MAGIC candidates)
  const { meta, metaBytes, metaEnd } = parseEnvelopeHeaderOrThrow(bytes);

  // AEAD / version / namespace checks
  ensureAlgoAndVersionOrThrow(meta);
  ensureNamespaceOrThrow(meta);

  // KDF checks (Argon2id per-envelope)
  if (!meta.kdf || meta.kdf.kdf !== 'Argon2id') {
    throw new EnvelopeError('kdf', 'Unsupported KDF');
  }
  if (meta.salt == null || meta.iv == null) {
    throw new EnvelopeError('salt_iv', 'Missing KDF salt or IV');
  }

  // Decode + validate IV / salt just like password mode
  let ivU8, saltU8;
  try { ivU8 = b64d(String(meta.iv)); }
  catch { throw new EnvelopeError('iv', 'Invalid IV encoding'); }
  if (!ivU8 || ivU8.length !== 12) {
    throw new EnvelopeError('iv_len', 'IV must be 96-bit');
  }

  try { saltU8 = b64d(String(meta.salt)); }
  catch { throw new EnvelopeError('salt', 'Invalid salt encoding'); }
  if (saltU8.length < 16 || saltU8.length > 64) {
    throw new EnvelopeError('salt_len', 'Unsupported salt length');
  }

  // Validate Argon2 parameters
  const kdfParams = {
    mMiB: Number(meta.kdf.mMiB),
    t:    Number(meta.kdf.t),
    p:    Number(meta.kdf.p),
  };
  validateArgon(kdfParams);

  let keyBytes;
  try {
    // Derive key and import
    keyBytes = await deriveArgon2id(password, saltU8, kdfParams);
    const key = await importAesKey(keyBytes);

    // Cipher slice sanity
    const cipher = bytes.subarray(metaEnd);
    if (cipher.length < 16) {
      throw new EnvelopeError('cipher_short', 'Ciphertext too short');
    }

    // Decrypt
    const clear = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivU8, additionalData: metaBytes, tagLength: 128 },
      key, cipher
    ));

    // Parse inner header
    if (clear.length < 4) throw new EnvelopeError('clear_short', 'Malformed plaintext');
    const innerLen = new DataView(clear.buffer, clear.byteOffset, 4).getUint32(0, false);
    const innerEnd = 4 + innerLen;
    if (innerEnd > clear.length) throw new EnvelopeError('inner_trunc', 'Truncated inner meta');

    let inner;
    try {
      inner = JSON.parse(TD.decode(clear.subarray(4, innerEnd)));
    } catch {
      throw new EnvelopeError('inner_parse', 'Malformed inner JSON');
    } finally {
      try { clear.fill(0); } catch {}
    }

    // Basic structure checks
    if (inner.kind !== 'bundle_header' ||
        typeof inner.bundleId !== 'string' ||
        typeof inner.bundleSaltB64 !== 'string') {
      throw new EnvelopeError('bad_header', 'Invalid bundle header');
    }

    return { bundleId: inner.bundleId, bundleSaltB64: inner.bundleSaltB64 };
  } finally {
    // Always wipe key material even on failure paths
    try { if (keyBytes) keyBytes.fill(0); } catch {}
  }
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

// ---------------------------
// Filename & content checks
// ---------------------------

// Dangerous executable extensions (case-insensitive)
const DANGEROUS_EXT = /\.(exe|msi|bat|cmd|com|scr|ps1|psm1|vbs|js|jse|wsf|sh|apk|app|pkg|dmg|elf|msc)$/i;

// BiDi / control characters often abused to hide extension
const BIDI_CTRL = /[\u0000-\u001F\u007F\u200E\u200F\u202A-\u202E\u2066-\u2069]/;

// Minimal filename sanitizer for ZIP rebuilds
function sanitizeZipFilename(name, used = new Set()) {
  if (!name || typeof name !== 'string') name = 'file';

  // Normalize + strip control/BiDi chars
  let s = name.normalize('NFKC').replace(BIDI_CTRL, '');

  // Unify separators and drop absolute/parent refs
  s = s.replace(/[\\]+/g, '/');       // backslashes → '/'
  s = s.replace(/\/{2,}/g, '/');      // collapse '//' 
  s = s.replace(/^\/+/, '');          // drop leading '/'
  s = s.split('/').filter(seg => seg && seg !== '.' && seg !== '..').join('/');

  // Force basename-only to avoid Zip Slip risks
  s = s.split('/').pop() || 'file';

  // Trim whitespace/dots at ends (ambiguous on some filesystems)
  s = s.replace(/^[\s.]+|[\s.]+$/g, '');

  // Very conservative fallback if empty after cleaning
  if (!s) s = 'file';

  // Optional: cap length a bit
  if (s.length > 180) s = s.slice(0, 180);

  // Ensure uniqueness within the archive
  let out = s, n = 2;
  const dot = out.lastIndexOf('.');
  const base = dot > 0 ? out.slice(0, dot) : out;
  const ext  = dot > 0 ? out.slice(dot) : '';
  while (used.has(out)) {
    out = `${base} (${n++})${ext}`;
  }
  used.add(out);
  return out;
}

/**
 * Returns { ok: boolean, why: string } describing suspicious filename heuristics.
 */
function hasSuspiciousName(name) {
  if (!name || typeof name !== 'string') return { ok: false, why: 'No filename suggested' };
  const s = name.normalize('NFKC');

  if (BIDI_CTRL.test(s)) return { ok: false, why: 'Filename contains special Unicode control characters' };
  if (/[ \.]{2,}$/.test(s)) return { ok: false, why: 'Filename ends with ambiguous whitespace/dots' };
  if (DANGEROUS_EXT.test(s)) return { ok: false, why: 'Filename suggests an executable or installer' };

  const parts = s.split('.');
  if (parts.length >= 3) {
    const last = parts[parts.length - 1];
    const prev = parts[parts.length - 2];
    if (DANGEROUS_EXT.test('.' + last) && /^(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|txt|rtf|csv|zip)$/i.test(prev)) {
      return { ok: false, why: 'Filename contains a double extension that can be misleading' };
    }
  }
  return { ok: true };
}

/**
 * Heuristic binary signature checks for common executable formats:
 * - PE (MZ), ELF, Mach-O, shebang scripts.
 * Returns true if the sample looks like an executable or script.
 */
function looksExecutableBytes(u8) {
  if (!(u8 && u8.length >= 4)) return false;

  // PE "MZ"
  if (u8[0] === 0x4D && u8[1] === 0x5A) return true;

  // ELF 0x7F 'E' 'L' 'F'
  if (u8[0] === 0x7F && u8[1] === 0x45 && u8[2] === 0x4C && u8[3] === 0x46) return true;

  // Mach-O / Universal magic numbers (various values)
  const readU32 = (off) => {
    if (off + 3 >= u8.length) return null;
    return (u8[off] << 24) | (u8[off + 1] << 16) | (u8[off + 2] << 8) | (u8[off + 3]);
  };
  const magic = readU32(0);
  const MACHO_MAGICS = new Set([0xFEEDFACE, 0xCAFEBABE, 0xFEEDFACF, 0xCEFAEDFE, 0xBEBAFECA, 0xCFFAEDFE]);
  if (MACHO_MAGICS.has(magic)) return true;

  // Shebang for scripts "#!"
  if (u8[0] === 0x23 && u8[1] === 0x21) return true;

  return false;
}

/**
 * Minimal prompt wrapper that returns a Promise<boolean>:
 * true = user chose to continue; false = abort.
 */
function promptUserConfirm(message) {
  return new Promise((resolve) => {
    try {
      const ok = window.confirm(message + '\n\nPress OK to continue, Cancel to stop.');
      resolve(Boolean(ok));
    } catch {
      resolve(false);
    }
  });
}


// ===== UI state =====

const decBar = '#decBar';
let tunedParams = null;

let wordlist    = null;

function getEncMode() {
  // Returns 'text' when the Text panel is visible, else 'files'
  return !$('#encPanelText').hidden ? 'text' : 'files';
}

function encIds(mode = getEncMode()) {
  // Map to the <details> wrappers and the new progress wrappers
  if (mode === 'text') {
    return {
      outputs: '#encDetailsText',   // <details>
      results: '#encResultsText',
      hash:    '#encHashText',
      bar:     'encBarText',        // inner bar id (no '#')
      prog:    '#encProgText'       // progress wrapper div
    };
  }
  return {
    outputs: '#encDetailsFiles',    // <details>
    results: '#encResultsFiles',
    hash:    '#encHashFiles',
    bar:     'encBarFiles',
    prog:    '#encProgFiles'
  };
}

// Show/hide a specific bar by id (reuses your showProgress API)
function showEncProgress(mode, visible) {
  const { bar, outputs } = encIds(mode);

  // Keep your existing wrapper/show logic
  showProgress(bar, visible);

  // IMPORTANT: when progress is visible, unhide this mode's output container
  if (visible) {
    const out = document.querySelector(outputs);
    if (out) {
      out.classList.remove('hidden');
      out.classList.add('visible');
    }
  }
}



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
function resetEncryptUI(opts = {}) {
  const {
    preservePassword = false, // by default, clear the password on Encrypt
    preserveInputs   = false, // text/files inputs
  } = opts;

  const mode = getEncMode();      // 'text' | 'files'
  const ids  = encIds(mode);      // { outputs, results, hash, bar }

  // Clear Encrypt-specific outputs and state
  try { clearNode(ids.results); } catch {}
  try { setText(ids.hash, ''); } catch {}
  {
    const s = document.querySelector(`${ids.outputs} > summary`);
    if (s) s.hidden = true;   // pour cacher
  }
  document.querySelector(ids.outputs)?.classList.add('hidden');
  document.querySelector(ids.hash)?.classList.add('hidden');
  try { setText('#pwdStrength', ''); } catch {}
  try {
    const barEl = (typeof ids.bar === 'string') ? document.getElementById(ids.bar) : ids.bar;
    setProgress(barEl, 0);
  } catch {}

  // Clear inputs (text/files) if not preserved
  if (!preserveInputs) {
    try { $('#encText').value = ''; } catch {}
    try { $('#encFiles').value = ''; } catch {}
    try { setText('#encFileList', ''); } catch {}
  }

  // Password: clear if not preserved, always re-hide field and reset toggle
  if (!preservePassword) {
    try { $('#encPassword').value = ''; } catch {}
  }
  try {
    const pw = $('#encPassword'); if (pw) pw.type = 'password';
    const t  = $('#encPwdToggle'); if (t) { setText(t, 'Show'); t.setAttribute('aria-pressed','false'); }
  } catch {}

  // Always hide progress bar on reset (scoped)
  showEncProgress(mode, false);

  // Hide Encrypt result containers and previews explicitly
  try {
    const detText   = document.querySelector('#encDetailsText');
    const detFiles  = document.querySelector('#encDetailsFiles');
    const resText   = document.querySelector('#encResultsText');
    const resFiles  = document.querySelector('#encResultsFiles');
    const prevText  = document.querySelector('#encPreviewText');
    const prevFiles = document.querySelector('#encPreviewFiles');

    // Hide details sections
    if (detText)  detText.classList.add('hidden');
    if (detFiles) detFiles.classList.add('hidden');

    // Hide result rows
    if (resText)  resText.classList.add('hidden');
    if (resFiles) resFiles.classList.add('hidden');

    // Clear + hide previews
    if (prevText)  { setText(prevText, '');  prevText.classList.add('hidden'); }
    if (prevFiles) { setText(prevFiles, ''); prevFiles.classList.add('hidden'); }
  } catch {}

  // Hide results container only if empty (scoped)
  hideIfEmpty(ids.outputs, ids.results);

  // Revoke object URLs and remove blob links/buttons in the scoped results
  try {
    for (const url of [...__urlsToRevoke]) {
      try { URL.revokeObjectURL(url); } catch {}
      __urlsToRevoke.delete(url);
    }
    const resEl = (typeof ids.results === 'string')
      ? document.querySelector(ids.results)
      : ids.results;
    if (resEl) {
      resEl.querySelectorAll('a[href^="blob:"]').forEach(a => { try { a.remove(); } catch {} });
      resEl.querySelectorAll('button').forEach(b => { try { b.remove(); } catch {} });
    }
  } catch (e) {
    logWarn('[resetEncryptUI] revoke anchors warn', e);
  }

  // Recompute Encrypt button state
  try {
    const pwVal = ($('#encPassword').value || '').trim();
    const text  = ($('#encText').value || '').trim();
    const files = $('#encFiles').files;
    const ok = (pwVal.length > 0) && (text.length > 0 || (files && files.length > 0));
    const btn = $('#btnEncrypt');
    btn.disabled = !ok;
    if (btn.disabled) btn.setAttribute('aria-disabled', 'true');
    else btn.removeAttribute('aria-disabled');
  } catch {}

  // Accessibility live message
  try { setLive('Encryption UI cleared.'); } catch {}
}


/**
 * Reset decryption panel inputs and progress.
 */
function resetDecryptUI(opts = {}) {
  const {
    preservePassword = false, // by default, clear the password on Decrypt
    preserveFile     = false, // selected encrypted file or bundle
  } = opts;

  // Clear Decrypt-specific outputs and state
  try { clearNode('#decResults'); } catch {}
  try { setText('#decText', ''); } catch {}
  try {
    const t = document.querySelector('#decText');
    if (t) t.hidden = true;
    const res = document.querySelector('#decResults');
    if (res) res.classList.add('hidden');
  } catch {}
  try { setText('#decIntegrity', ''); } catch {}
  try { setText('#decFileErr', ''); } catch {}
  try { setProgress('#decBar', 0); } catch {} // ← fixed (use selector)

  // File input: clear if not preserved (+ filename label)
  if (!preserveFile) {
    try { $('#decFile').value = ''; } catch {}
    try { setText('#decFileName',''); } catch {}
  }

  // Password: clear if not preserved; always re-hide field and reset toggle
  if (!preservePassword) {
    try { $('#decPassword').value = ''; } catch {}
  }
  try {
    const pw = $('#decPassword'); if (pw) pw.type = 'password';
    const t = $('#decPwdToggle'); if (t) { setText(t, 'Show'); t.setAttribute('aria-pressed','false'); }
  } catch {}

  // Always hide progress bar on reset
  showProgress('decBar', false);

  // Hide results container if empty (target an existing container)
  // If you prefer to keep it simple, you can remove this line.
  try { hideIfEmpty('#decDetails', '#decResults, #decText'); } catch {}

  // Revoke object URLs and remove any blob links/buttons in decResults
  try {
    for (const url of [...__urlsToRevoke]) {
      try { URL.revokeObjectURL(url); } catch {}
      __urlsToRevoke.delete(url);
    }
    const resEl = document.querySelector('#decResults');
    if (resEl) {
      resEl.querySelectorAll('a[href^="blob:"]').forEach(a => { try { a.remove(); } catch {} });
      resEl.querySelectorAll('button').forEach(b => { try { b.remove(); } catch {} });
    }
  } catch (e) {
    logWarn('[resetDecryptUI] revoke anchors warn', e);
  }

  // Recompute Decrypt button state
  try {
    const pw = ($('#decPassword').value || '').trim();
    const file = ($('#decFile').files || [])[0];
    const ok = (pw.length > 0) && !!file;
    const btn = $('#btnDecrypt');
    btn.disabled = !ok;
    if (btn.disabled) btn.setAttribute('aria-disabled', 'true');
    else btn.removeAttribute('aria-disabled');
  } catch {}

  // Accessibility live message
  try { setLive('Decryption UI cleared.'); } catch {}
}



/**
 * Switch between Encrypt and Decrypt tabs and reset both panels.
 */
function selectTab(which) {
  const encTab   = $('#tabEncrypt');
  const decTab   = $('#tabDecrypt');
  const encPanel = $('#panelEncrypt');
  const decPanel = $('#panelDecrypt');

  if (which === 'enc') {
    encTab.setAttribute('aria-selected', 'true');
    decTab.setAttribute('aria-selected', 'false');
    encPanel.hidden = false;
    decPanel.hidden = true;

    // Show the correct encryption RESULTS wrapper based on current content tab
    const isText = !document.getElementById('encPanelText').hidden;

    const encDetailsText  = document.querySelector('#encDetailsText');
    const encDetailsFiles = document.querySelector('#encDetailsFiles');

    // Normalize both, then show only the relevant one if it has something inside
    const textEmpty  = !(document.querySelector('#encResultsText')?.childElementCount > 0) &&
                       !((document.querySelector('#encPreviewText')?.textContent || '').trim().length > 0) &&
                       !((document.querySelector('#encHashText')?.textContent || '').trim().length > 0);

    const filesEmpty = !(document.querySelector('#encResultsFiles')?.childElementCount > 0) &&
                       !((document.querySelector('#encPreviewFiles')?.textContent || '').trim().length > 0) &&
                       !((document.querySelector('#encHashFiles')?.textContent || '').trim().length > 0);

    // Hide both by default
    encDetailsText?.classList.add('hidden');
    encDetailsText?.classList.remove('visible');
    encDetailsText?.removeAttribute('open');

    encDetailsFiles?.classList.add('hidden');
    encDetailsFiles?.classList.remove('visible');
    encDetailsFiles?.removeAttribute('open');

    // Only show/open the one that matches current sub-tab AND is not empty
    if (isText && !textEmpty) {
      encDetailsText?.classList.remove('hidden');
      encDetailsText?.classList.add('visible');
      encDetailsText?.setAttribute('open','');
    } else if (!isText && !filesEmpty) {
      encDetailsFiles?.classList.remove('hidden');
      encDetailsFiles?.classList.add('visible');
      encDetailsFiles?.setAttribute('open','');
    }

    // Hide both encrypt progress wrappers; doEncrypt() will show the right one
    document.querySelector('#encProgText')?.classList.add('hidden');
    document.querySelector('#encProgFiles')?.classList.add('hidden');
    showEncProgress('text',  false);
    showEncProgress('files', false);

  } else {
    decTab.setAttribute('aria-selected', 'true');
    encTab.setAttribute('aria-selected', 'false');
    decPanel.hidden = false;
    encPanel.hidden = true;
  }

  // Decrypt details: open only if there is content
  (function syncDecDetails() {
    const det  = document.querySelector('#decDetails');
    if (!det) return;
    const res  = document.querySelector('#decResults');
    const text = document.querySelector('#decText');
    const hasRes  = !!(res && res.childElementCount > 0);
    const hasText = !!(text && (text.textContent || '').trim().length > 0);
    det.open = (hasRes || hasText);
    if (res)  res.classList.toggle('hidden', !hasRes);
    if (text) text.hidden = !hasText;
  })();

  // Re-mask encryption password
  try {
    const encPwd = $('#encPassword');
    const toggle = $('#encPwdToggle');
    if (encPwd) {
      encPwd.type = 'password';
      if (toggle) {
        setText(toggle, 'Show');
        toggle.setAttribute('aria-pressed', 'false');
      }
    }
  } catch {}

  // Always hide progress bars when switching panels
  showEncProgress('text',  false);
  showEncProgress('files', false);
  showProgress('decBar',   false);
}

/**
 * Switch encryption content input mode (Text vs Files).
 */
function selectContentTab(which) {
  const tBtn   = $('#encTabText');
  const fBtn   = $('#encTabFiles');
  const tPanel = $('#encPanelText');
  const fPanel = $('#encPanelFiles');

  // NOTE: outputs are now <details>, not #encOutputs*
  const outText  = document.querySelector('#encDetailsText');
  const outFiles = document.querySelector('#encDetailsFiles');

  const selIsText = (which === 'text');

  // Tabs / panels (ARIA)
  tBtn.setAttribute('aria-selected', selIsText ? 'true' : 'false');
  fBtn.setAttribute('aria-selected', selIsText ? 'false' : 'true');
  tPanel.hidden = !selIsText;
  fPanel.hidden =  selIsText;

  // Normalize both details
  outText?.classList.remove('visible');
  outFiles?.classList.remove('visible');
  outText?.classList.add('hidden');
  outFiles?.classList.add('hidden');
  outText?.removeAttribute('open');
  outFiles?.removeAttribute('open');

  // Show/open only the active details if it already has content
  const textHasContent =
      (document.querySelector('#encResultsText')?.childElementCount > 0) ||
      ((document.querySelector('#encPreviewText')?.textContent || '').trim().length > 0) ||
      ((document.querySelector('#encHashText')?.textContent || '').trim().length > 0);

  const filesHasContent =
      (document.querySelector('#encResultsFiles')?.childElementCount > 0) ||
      ((document.querySelector('#encPreviewFiles')?.textContent || '').trim().length > 0) ||
      ((document.querySelector('#encHashFiles')?.textContent || '').trim().length > 0);

  if (selIsText && textHasContent) {
    outText?.classList.remove('hidden');
    outText?.classList.add('visible');
    outText?.setAttribute('open','');
  } else if (!selIsText && filesHasContent) {
    outFiles?.classList.remove('hidden');
    outFiles?.classList.add('visible');
    outFiles?.setAttribute('open','');
  }

  // Hide both encrypt progress wrappers; doEncrypt() will show the correct one
  document.querySelector('#encProgText')?.classList.add('hidden');
  document.querySelector('#encProgFiles')?.classList.add('hidden');
  showEncProgress('text',  false);
  showEncProgress('files', false);

  updateEncryptButtonState();
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
    const hasWorker = (typeof Worker === 'function');

    // Vérifie WebAssembly quand on est en mode strict
    const hasWasm =
      (typeof WebAssembly === 'object') &&
      (typeof WebAssembly.instantiate === 'function');

    // Si REQUIRE_WASM_STRICT est vrai, on exige WASM aussi
    return hasSubtle && hasWorker && (!REQUIRE_WASM_STRICT || hasWasm);
  } catch {
    return false;
  }
}

/**
 * Initialize UI, load wordlist, rate-limit the benchmark, run auto-tune with budget,
 * and store tuned parameters. Disable buttons on failure.
 */
// en haut du fichier (à côté de la ligne où tu as déjà):
// let tunedParams = null;
let __tpResolve;                                       // 🔹 Ajout
const tunedParamsReady = new Promise(res => {          // 🔹 Ajout
  __tpResolve = res;
});

async function init() {
  try {
    // Disable clearly on startup (ARIA + native)
    $('#btnEncrypt').setAttribute('aria-disabled','true');
    $('#btnDecrypt').setAttribute('aria-disabled','true');
    if ($('#btnEncrypt')) $('#btnEncrypt').disabled = true;
    if ($('#btnDecrypt')) $('#btnDecrypt').disabled = true;

    setLive('Optimizing...');
    
    if (!cryptoRuntimeOk()) {
      const hasWasm = (typeof WebAssembly === 'object') && (typeof WebAssembly.instantiate === 'function');
    
      if (REQUIRE_WASM_STRICT) {
        const msg = 'WebAssembly is required for secure encryption. Operation aborted.';
        setLive(msg);
        showErrorBanner(msg);
        $('#btnEncrypt')?.setAttribute('disabled', 'true');
        $('#btnDecrypt')?.setAttribute('disabled', 'true');

        throw new EnvelopeError('wasm_required', msg);
      }
    
      // Permissive fallback allowed → sécurité réduite
      const msg = hasWasm
        ? 'Reduced crypto capabilities detected.'
        : 'WebAssembly unavailable — degraded security mode.';
      setLive(msg);
    
      showWarningBanner(
        "Security warning — degraded mode: WebAssembly unavailable. " +
        "Password protection is significantly weaker."
      );
    
      return;
    }

    await loadWordlist();

    // Benchmark rate-limit check
    const gate = allow('bench');
    if (!gate.ok) {
      // Safe fallback params
      const caps = chooseCaps();
      const guessedMiB = clamp(jitterMemory(512), caps.minMemMiB, caps.maxMemMiB);
      const guessedP = clamp(Math.min((navigator.hardwareConcurrency || 2), HEALTHY_P_MAX), 1, caps.maxParallel);
    
      tunedParams = {
        mMiB: clamp(guessedMiB, ARGON_MIN_MIB, ARGON_MAX_MIB),
        t:    clamp(5,           ARGON_MIN_T,   ARGON_MAX_T),
        p:    clamp(guessedP,    HEALTHY_P_MIN, HEALTHY_P_MAX)
      };

      window.__MAX_INPUT_BYTES_DYNAMIC = caps.maxInput;
      setLive(`Auto (fallback): ${tunedParams.mMiB} MiB, t=${tunedParams.t}, p=${tunedParams.p}`);

      __tpResolve?.(tunedParams);

      const be = $('#btnEncrypt'), bd = $('#btnDecrypt');
      if (be) { be.removeAttribute('aria-disabled'); be.disabled = false; }
      if (bd) { bd.removeAttribute('aria-disabled'); bd.disabled = false; }
    }

    // Auto-tune with a time budget
    const tuned = await autoTuneStrongWithBudget(2500)
      .catch(() => ({ mMiB: 512, t: 5, p: 2, ms: 0 }));

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

    __tpResolve?.(tunedParams);

    (function validateExts(){
      if (typeof FILE_SINGLE_EXT !== 'string' || !FILE_SINGLE_EXT.startsWith('.')) {
        throw new Error('Invalid FILE_SINGLE_EXT');
      }
      if (typeof FILE_BUNDLE_EXT !== 'string' || !FILE_BUNDLE_EXT.startsWith('.')) {
        throw new Error('Invalid FILE_BUNDLE_EXT');
      }
    })();

    // Re-enable buttons
    const be = $('#btnEncrypt'), bd = $('#btnDecrypt');
    if (be) { be.removeAttribute('aria-disabled'); be.disabled = false; }
    if (bd) { bd.removeAttribute('aria-disabled'); bd.disabled = false; }

    updateEncryptButtonState();
    updateDecryptButtonState();

  } catch (e) {
    setLive('This device cannot load Argon2/WASM. Encryption disabled.');
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

// Safer, cancellable CRC+size over a File/Blob stream.
// Options:
//  - signal: AbortSignal to allow cancellation
//  - maxBytes: hard upper bound; aborts if exceeded
//  - useBYOB: try ReadableStream BYOB reader to reduce allocations (best-effort)
async function computeCrcAndSizeFromFile(file, { signal, maxBytes, useBYOB = true } = {}) {
  // Pre-check size if the environment gives it (File.size is a safe hint)
  const announced = Number(file?.size ?? 0);
  if (Number.isFinite(announced) && maxBytes && announced > maxBytes) {
    throw new EnvelopeError('input_large', `Announced size exceeds limit (${announced} > ${maxBytes})`);
  }

  let crc = 0xFFFFFFFF >>> 0;
  let sizeBig = 0n;

  // Prefer BYOB to limit allocations if the stream supports it
  const sourceStream = file.stream();
  let reader = null;
  let byob = false;
  try {
    if (useBYOB && typeof sourceStream.getReader === 'function' && 'ReadableStreamBYOBReader' in window) {
      reader = sourceStream.getReader({ mode: 'byob' });
      byob = true;
    } else {
      reader = sourceStream.getReader();
    }

    const table = CRC_TABLE || null; // optional precomputed table
    const buf = byob ? new Uint8Array(64 * 1024) : null;

    while (true) {
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');

      const read = byob
        ? await reader.read(buf)
        : await reader.read();

      if (read.done) break;

      const chunk = byob
        ? (read.value || buf).subarray(0, read.value?.byteLength ?? 0)
        : (read.value instanceof Uint8Array ? read.value : new Uint8Array(read.value));

      // size accounting (as BigInt to avoid precision loss)
      sizeBig += BigInt(chunk.byteLength);
      if (maxBytes && sizeBig > BigInt(maxBytes)) {
        throw new EnvelopeError('input_large', 'Stream exceeds allowed limit');
      }

      // CRC32 update (table fast-path if available)
      let c = crc >>> 0;
      if (table) {
        for (let i = 0; i < chunk.length; i++) {
          c = (table[(c ^ chunk[i]) & 0xFF] ^ (c >>> 8)) >>> 0;
        }
      } else {
        c = crc32Update(c, chunk) >>> 0;
      }
      crc = c;
    }
  } catch (e) {
    try { await reader?.cancel?.(e); } catch {}
    throw e;
  } finally {
    try { reader?.releaseLock?.(); } catch {}
  }

  crc = (crc ^ 0xFFFFFFFF) >>> 0;

  // Return both: precise BigInt + best-effort Number (null when unsafe)
  const size = (sizeBig <= BigInt(Number.MAX_SAFE_INTEGER)) ? Number(sizeBig) : null;
  return { crc, size, sizeBig };
}

function fileChunkProducer(file, { signal } = {}) {
  return async function* () {
    const r = file.stream().getReader();
    try {
      while (true) {
        if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
        const { value, done } = await r.read();
        if (done) break;
        yield (value instanceof Uint8Array) ? value : new Uint8Array(value);
      }
    } catch (e) {
      try { await r.cancel?.(e); } catch {}
      throw new EnvelopeError('input_stream', `Error while reading "${file.name}"`, { cause: e, fileName: file.name });
    } finally {
      try { r.releaseLock?.(); } catch {}
    }
  };
}

// ===== Encrypt flow =====

/* ******************************************************
 * doEncrypt
 *  - Text mode: single Argon2 (bundle) → HKDF → sealFixedChunkDet
 *  - Files mode (streaming): streaming pipeline (Store ZIP → fixed chunks → AES-GCM Det)
 *  - Outputs: encrypted bundle (ZIP store-only) with O(1) RAM usage when File System Access API is available
 ****************************************************** */
async function doEncrypt() {
  let payloadBytes = null;
  let bundleBytes  = null;
  let plaintextHashHex = null;
  let plaintextIsZip = false;

  try {
    logInfo('[enc] start');

    const mode = getEncMode();      // 'text' or 'files' (based on visible panel)
    const ids  = encIds(mode);
    const other = encIds(mode === 'text' ? 'files' : 'text');

    // Ensure only the active <details> is visible/open
    const otherDetails = document.querySelector(other.outputs);
    if (otherDetails) {
      otherDetails.classList.add('hidden');
      otherDetails.classList.remove('visible');
      otherDetails.removeAttribute('open');
    }

    const details = document.querySelector(ids.outputs);
    if (details) {
      details.classList.remove('hidden');
      details.classList.add('visible');
      details.setAttribute('open', '');
    }

    // Show only the active progress wrapper; hide the other
    document.querySelector(other.prog)?.classList.add('hidden');
    const activeProg = document.querySelector(ids.prog);
    if (activeProg) {
      activeProg.classList.remove('hidden');
      activeProg.style.display = 'block';
    }

    // Show the active progress bar
    showEncProgress(mode, true);
    setProgress(document.getElementById(ids.bar), 5);

    // Clear this mode’s outputs before starting
    clearNode(ids.results);
    setText(ids.hash, ''); // this is where the hashbox will be rendered later

    const pw = $('#encPassword').value || '';
    if (!pw) throw new EnvelopeError('input', 'missing');
    const password = pw.normalize('NFKC');

    // Determine input source from panel visibility
    const textMode = (mode === 'text');
    if (textMode) {
      /* ******************************************************
       * TEXT MODE — One-time KDF and deterministic chunk sealing
       ****************************************************** */
      const raw = $('#encText').value;
      if (!raw) throw new EnvelopeError('input', 'missing');
      payloadBytes = TE.encode(raw);

      if (payloadBytes.length > (window.__MAX_INPUT_BYTES_DYNAMIC || MAX_INPUT_BYTES)) {
        throw new EnvelopeError('input_large', 'Input too large for this device');
      }

      // Optional size padding (bucket)
      const enableSizePadding = false;      // toggle on hardened builds as needed
      let PAD_TO = choosePadBucket();
      // Garder la valeur effectivement utilisée (peut être ajustée plus bas)
      let PAD_TO_EFFECTIVE = PAD_TO;
      
      // Keep the real length for manifest/UX
      const realPlainLen = payloadBytes.length;
      
      // Optional whole-plaintext hash over the real (unpadded) content
      const wholeHashHexReal = await sha256Hex(payloadBytes);

      const originalBytes = payloadBytes;  // keep reference so we can revert cleanly
      let sizePadded = false;              // explicit init
      
      if (enableSizePadding) {
        const paddedLen    = Math.ceil(realPlainLen / PAD_TO) * PAD_TO;
        const needPadBytes = Math.max(0, paddedLen - realPlainLen);
      
        // Quick exit: no padding needed
        if (needPadBytes === 0) {
          sizePadded = false;
        } else {
          // Check device cap BEFORE allocating
          const maxIn = window.__MAX_INPUT_BYTES_DYNAMIC || MAX_INPUT_BYTES;
          if (paddedLen > maxIn) {
            // Automatically shrink the padding bucket to stay within limits
            const MiB = 1024 * 1024;
            const headroom = Math.max(0, maxIn - realPlainLen);
          
            // Largest multiple of FIXED_CHUNK_SIZE that fits within the headroom
            let newBucket = Math.floor(headroom / FIXED_CHUNK_SIZE) * FIXED_CHUNK_SIZE;
            const MIN_BUCKET = 1 * MiB;
          
            if (newBucket < MIN_BUCKET) {
              // Not enough room to apply padding
              payloadBytes = originalBytes;
              sizePadded = false;
              logWarn("[enc] padding auto-disabled due to device cap; using realPlainLen only");
              setLive("Size padding automatically disabled to fit device limit.");
              PAD_TO_EFFECTIVE = PAD_TO;
            } else {
              // Ensure bucket is at least one full chunk
              if (newBucket < FIXED_CHUNK_SIZE) newBucket = FIXED_CHUNK_SIZE;
          
              const paddedLen2 = Math.ceil(realPlainLen / newBucket) * newBucket;
              const needPadBytes2 = Math.max(0, paddedLen2 - realPlainLen);
          
              if (needPadBytes2 === 0) {
                payloadBytes = originalBytes;
                sizePadded = false;
                setLive("No size padding required.");
                PAD_TO_EFFECTIVE = newBucket;
              } else {
                const pad = new Uint8Array(needPadBytes2);
                crypto.getRandomValues(pad);
          
                const combined = new Uint8Array(paddedLen2);
                combined.set(originalBytes, 0);
                combined.set(pad, realPlainLen);
          
                try { pad.fill(0); } catch {}
          
                payloadBytes = combined;
                sizePadded = true;
          
                try { originalBytes.fill(0); } catch {}
          
                logInfo("[enc] size padding adjusted", { bucket: newBucket, paddedLen: paddedLen2 });
                setLive("Size padding automatically adjusted to device capacity.");
                PAD_TO_EFFECTIVE = newBucket;
              }
            }
          } else {
            // Path when paddedLen is already within limits
            const pad = new Uint8Array(needPadBytes);
            crypto.getRandomValues(pad);
          
            const combined = new Uint8Array(paddedLen);
            combined.set(originalBytes, 0);
            combined.set(pad, realPlainLen);
          
            try { pad.fill(0); } catch {}
          
            payloadBytes = combined;
            sizePadded = true;
            try { originalBytes.fill(0); } catch {}
            PAD_TO_EFFECTIVE = PAD_TO;
          }
        }
      }
      
      // From here, totalPlainLen reflects the padded length (if any)
      const totalPlainLen = payloadBytes.length;
      const chunks = chunkFixed(payloadBytes);
      const totalChunks = chunks.length;
      
      // Anti-replay binding and bundle-level KDF
      const bundleIdBytes = crypto.getRandomValues(new Uint8Array(16));
      const bundleId = b64(bundleIdBytes);
      
      /* ******************************************************
       * One-time bundle KDF (Argon2id once → HKDF split)
       ****************************************************** */
      const bundleSalt = crypto.getRandomValues(new Uint8Array(16));
      const master32   = await deriveArgon2id(password, bundleSalt, tunedParams);
      const { kEnc32, kIv32 } = await hkdfSplit(master32, bundleSalt);
      const K_ENC = await importAesKey(kEnc32);
      
      /* ******************************************************
       * Chunk sealing (deterministic IVs via HKDF, no per-chunk Argon2)
       ****************************************************** */
      const sealedParts = [];
      const perChunkHashes = [];
      setProgress(document.getElementById(ids.bar), 15); 
      
      for (let i = 0; i < totalChunks; i++) {
        const c = chunks[i];
        const isLast   = (i === totalChunks - 1);
        const sliceEnd = isLast
          ? (totalPlainLen - (FIXED_CHUNK_SIZE * (totalChunks - 1)))
          : FIXED_CHUNK_SIZE;
        const slice    = c.subarray(0, sliceEnd);

        perChunkHashes.push(await sha256Hex(slice));

        const part = await sealFixedChunkDet({
          kEncKey: K_ENC,
          kIv32,
          bundleId,
          payloadChunk: c,
          chunkIndex: i,
          totalChunks,
          totalPlainLen
        });

        sealedParts.push({
          name: namePart(i),
          bytes: part
        });

        setProgress(document.getElementById(ids.bar), 15 + Math.floor(50 * (i + 1) / totalChunks)); 
        if ((i & 1) === 0) await new Promise(r => setTimeout(r, 0));
      }

      /* ******************************************************
       * MANIFEST (includes bundleSaltB64) sealed with bundle keys
       ****************************************************** */
      if (!Number.isSafeInteger(totalPlainLen) || !Number.isSafeInteger(realPlainLen)) {
        throw new EnvelopeError('bad_len', 'Length not a safe integer');
      }
      
      const manifestInner = {
        v: 1, kind: 'manifest',
      
        // Binding
        bundleId,
        bundleSaltB64: b64(bundleSalt),
      
        // Chunking
        chunkSize: FIXED_CHUNK_SIZE,
        totalPlainLen,                 // effective (maybe padded)
        totalChunks,
        chunkHashes: perChunkHashes,
      
        // Integrity of real (unpadded) content
        wholePlainHash: wholeHashHexReal,   // sha256(real content)
        hashAlg: 'sha256',
      
        // Padding metadata
        realPlainLen,
        sizePadded: (typeof sizePadded === 'boolean') ? sizePadded : true,
        padBytes: Math.max(0, totalPlainLen - realPlainLen),
        padBucket: enableSizePadding ? PAD_TO_EFFECTIVE : null,
      
        // Crypto descriptor
        aead: 'AES-256-GCM',
        kdf: { outer: 'Argon2id', split: 'HKDF' },
      
        // Provenance
        source: { kind: 'text', files: null },
        createdAt: new Date().toISOString()
      };
      
      const manifestBytes  = TE.encode(JSON.stringify(manifestInner));
      const manChunksClear = chunkFixedGeneric(manifestBytes);
      const manSealedParts = [];
      for (let i = 0; i < manChunksClear.length; i++) {
        const sealed = await sealFixedChunkDet({
          kEncKey: K_ENC,
          kIv32,
          bundleId,
          payloadChunk: padToFixed(manChunksClear[i]),
          chunkIndex: i,
          totalChunks: manChunksClear.length,
          totalPlainLen: manifestBytes.length,
          domain: 'manifest'
        });
        manSealedParts.push({
          name: nameManifestPart(i),
          bytes: sealed
        });
      }

      /* ******************************************************
       * MANIFEST_INDEX sealed with bundle keys
       ****************************************************** */
      const manChunkHashes = [];
      for (const c of manChunksClear) manChunkHashes.push(await sha256Hex(c));
      const manifestIndexInner = {
        v: 1, kind: 'manifest_index',
        totalChunks: manChunksClear.length,
        totalLen: manifestBytes.length,
        chunkSize: FIXED_CHUNK_SIZE,
        chunkHashes: manChunkHashes
      };
      const manIndexBytes  = TE.encode(JSON.stringify(manifestIndexInner));
      const manIndexChunks = chunkFixedGeneric(manIndexBytes);
      const manIndexSealed = [];
      for (let i = 0; i < manIndexChunks.length; i++) {
        const sealed = await sealFixedChunkDet({
          kEncKey: K_ENC,
          kIv32,
          bundleId,
          payloadChunk: padToFixed(manIndexChunks[i]),
          chunkIndex: i,
          totalChunks: manIndexChunks.length,
          totalPlainLen: manIndexBytes.length,
          domain: 'index'
        });
        manIndexSealed.push({
          name: nameIndexPart(i),
          bytes: sealed
        });
      }

      // Password-based bootstrap header (to recover bundleId + bundleSaltB64)
      const headerBytes = await sealBundleHeaderWithPassword({
        password,
        params: tunedParams,
        bundleId,
        bundleSaltB64: b64(bundleSalt)
      });
      const headerEntry = { name: nameHeader(), bytes: headerBytes };

      /* ******************************************************
       * Build bundle ZIP (store-only) and present download
       ****************************************************** */
      const filesOut = [ headerEntry, ...sealedParts, ...manSealedParts, ...manIndexSealed ];
      const bundleZip = buildZip(filesOut, { store: true });

      // Wipe sealed parts memory
      try { for (const f of filesOut) f?.bytes?.fill?.(0); } catch {}

      // Wipe keying material (bytes)
      try { master32.fill(0); } catch {}
      try { kEnc32.fill(0); } catch {}
      try { kIv32.fill(0); } catch {}

      const outBlob = new Blob([bundleZip], { type: 'application/octet-stream' });
      addDownload(ids.results, outBlob, `secret${FILE_BUNDLE_EXT}`, 'Download bundle');

      const bundleHash = await sha256Hex(bundleZip);
      renderSimpleHashes({
        bundleHashHex: bundleHash,
        plaintextHashHex: wholeHashHexReal,
        plaintextIsZip: false
      }, ids);

      setProgress(document.getElementById(ids.bar), 100);
      setLive('Encryption complete.');
      const outEl = document.querySelector(ids.outputs);
      if (outEl) { outEl.classList.remove('hidden'); outEl.classList.add('visible'); }
      showEncProgress(mode, false);
      return;
    }

    /* ******************************************************
     * FILES MODE (STREAMING) — StoreZipWriter + File System Access
     ****************************************************** */
    const files = Array.from($('#encFiles').files || []);
    if (files.length === 0) throw new EnvelopeError('input', 'missing');

    // DoS bound on announced sizes
    {
      const maxIn = window.__MAX_INPUT_BYTES_DYNAMIC || MAX_INPUT_BYTES;
      let totalAnnounce = 0;
      for (const f of files) {
        totalAnnounce += f.size|0;
        if (totalAnnounce > maxIn) throw new EnvelopeError('input_large', 'Total input too large for this device');
      }
    }

    // Before choosing sink, compute a plaintext hash when feasible
    {
      const maxIn = window.__MAX_INPUT_BYTES_DYNAMIC || MAX_INPUT_BYTES;
      if (files.length === 1) {
        // Hash of the single clear file (only if it fits in memory bound)
        const f0 = files[0];
        if (Number(f0.size || 0) <= maxIn) {
          const u8 = new Uint8Array(await f0.arrayBuffer());
          plaintextHashHex = await sha256Hex(u8);
          try { u8.fill(0); } catch {}
        } else {
          plaintextHashHex = null;
        }
        plaintextIsZip = false;
      } else {
        // Hash of a clear STORE ZIP reconstructed in memory (only if total ≤ bound)
        let total = 0;
        for (const f of files) { total += Number(f.size || 0); }
        if (total <= maxIn) {
          const sinkTmp = new SegmentsSink();
          const writerTmp = new StoreZipWriter(sinkTmp);
          let idx = 0;
          for (const f of files) {
            const internalName = `${String(idx).padStart(3,'0')}.bin`;
            await writerTmp.addFile(internalName, null, null, fileChunkProducer(f));
            idx++;
          }
          const zipPlain = await writerTmp.finish();
          plaintextHashHex = await sha256Hex(zipPlain);
          try { zipPlain.fill(0); } catch {}
        } else {
          plaintextHashHex = null;
        }
        plaintextIsZip = true;
      }
    }

    // Choose output sink: O(1) with File System Access when available, else memory
    const { sink, close, kind } = await getBundleSink('secret' + FILE_BUNDLE_EXT);

    // Streaming encryption — directly writes the encrypted bundle
    const res = await encryptMultiFilesStreaming({
      files,
      password,
      tunedParams,
      outSink: sink
    });

    // UI result depending on sink kind
    if (kind === 'fs') {
      await close?.();
      renderSimpleHashes({
        bundleHashHex: null,
        plaintextHashHex: plaintextHashHex,
        plaintextIsZip: plaintextIsZip
      }, ids);
      setLive('Encryption complete (saved to disk).');
      const outEl = document.querySelector(ids.outputs);
      if (outEl) { outEl.classList.remove('hidden'); outEl.classList.add('visible'); }
      setProgress(document.getElementById(ids.bar), 100);
      showEncProgress(mode, false);
      return;
    } else {
      bundleBytes = res.bundleU8 || (typeof sink.toUint8Array === 'function' ? sink.toUint8Array() : null);
      if (!bundleBytes) throw new Error('No bundle bytes available');

      const outBlob = new Blob([bundleBytes], { type: 'application/octet-stream' });
      addDownload(ids.results, outBlob, `secret${FILE_BUNDLE_EXT}`, 'Download bundle');

      const bundleHash = await sha256Hex(bundleBytes);
      renderSimpleHashes({
        bundleHashHex: bundleHash,
        plaintextHashHex: plaintextHashHex,
        plaintextIsZip: plaintextIsZip
      }, ids);
      
      setProgress(document.getElementById(ids.bar), 100);
      setLive('Encryption complete.');
      const outEl = document.querySelector(ids.outputs);
      if (outEl) { outEl.classList.remove('hidden'); outEl.classList.add('visible'); }
      showEncProgress(mode, false);
      return;
    }

  } catch (err) {
    await secureFail('Encryption', normalizeEncError(err));
    try {
      const modeNow = getEncMode();
      const barId   = encIds(modeNow).bar;
      const barEl   = document.getElementById(barId);
      if (barEl) setProgress(barEl, 0);
    } catch {}
  } finally {
    try {
      const modeNow = getEncMode();
      showEncProgress(modeNow, false);
    } catch {}
    try {
      const modeNow = getEncMode();
      const barId   = encIds(modeNow).bar;
      const p       = document.getElementById(barId)?.parentElement;
      if (p) p.style.display = 'none';
    } catch {}
    if (payloadBytes) wipeBytes(payloadBytes);
    if (bundleBytes)  wipeBytes(bundleBytes);
  }
}

async function computeFileSha256Hex(file, limitBytes) {
  const size = Number(file?.size || 0);
  if (!Number.isFinite(size) || size < 0) return null;
  if (limitBytes && size > limitBytes) return null; // too large to hold in memory safely
  const u8 = new Uint8Array(await file.arrayBuffer());
  const hex = await sha256Hex(u8);
  try { u8.fill(0); } catch {}
  return hex;
}

// Build a STORE-only ZIP in memory (opaque internal names, like the streaming path)
// and return sha256 hex of that clear ZIP
async function computeZipSha256HexForFiles(files, limitBytes) {
  // sanity / announced total
  let total = 0;
  for (const f of files) {
    total += Number(f.size || 0);
    if (limitBytes && total > limitBytes) return null;
  }

  const sink = new SegmentsSink();
  const writer = new StoreZipWriter(sink);

  let fileIdx = 0;
  for (const f of files) {
    // match the opaque internal naming used in encryptMultiFilesStreaming()
    const internalName = String(fileIdx).padStart(6, '0') + '.bin';
    await writer.addFile(internalName, null, null, fileChunkProducer(f));
    fileIdx++;
  }
  const zipU8 = await writer.finish();
  if (!zipU8) return null;
  const hex = await sha256Hex(zipU8);
  try { zipU8.fill(0); } catch {}
  return hex;
}

// === Helpers UI: progress + hide-if-empty + hashes ===
function showProgress(barId, visible) {
  try {
    const bar     = document.getElementById(barId);
    const wrapper = bar ? bar.parentElement : null;
    if (!wrapper) return;
    wrapper.style.display = visible ? 'block' : 'none';
    wrapper.classList.toggle('hidden', !visible);
  } catch {}
}



// Simple two-line hash display (English, no icons)
// ids is optional; when provided, use its scoped selector for the hash box.
function renderSimpleHashes({ bundleHashHex, plaintextHashHex, plaintextIsZip }, ids) {
  // Prefer the scoped hash element from encIds(mode), else fall back to #encHash
  const hashSel = ids?.hash || '#encHash';
  const out = (typeof hashSel === 'string') ? document.querySelector(hashSel) : hashSel;
  if (!out) return;

  const enc = bundleHashHex ?? 'None';
  const plb = 'Plaintext SHA-256' + (plaintextIsZip ? ' (ZIP)' : '');
  const pla = plaintextHashHex ?? 'None';

  // 2 leading spaces before values for aligned look
  const text =
`Encrypted SHA-256 (bundle):
  ${enc}

${plb}:
  ${pla}`;

  out.textContent = text;      // textContent: no HTML injection
  out.classList.add('hashbox', 'card');
  out.classList.remove('hidden');
  out.closest('details')?.classList.remove('hidden');
  {
    const s = document.querySelector(`${ids.outputs} > summary`);
    if (s) s.hidden = false;  // pour réafficher
  }
}

/**
 * Builds the clear ZIP as a stream (store-only), feeds it into chunk-based encryption,
 * and writes the encrypted bundle as a stream (store-only) on the fly.
 * Returns {bundleU8, manifest, manifestIndex}.
 */
async function encryptMultiFilesStreaming({ files, password, tunedParams, outSink }) {
  // 0) BUNDLE writer (output): use the one provided (FS or memory)
  const bundleSink   = outSink || new SegmentsSink();
  const bundleWriter = new StoreZipWriter(bundleSink);

  /* ******************************************************
  * One-time KDF at bundle start (files streaming)
  ****************************************************** */
  const bundleIdBytes = crypto.getRandomValues(new Uint8Array(16));
  const bundleId = b64(bundleIdBytes);

  const bundleSalt = crypto.getRandomValues(new Uint8Array(16));
  const master32   = await deriveArgon2id(password, bundleSalt, tunedParams);
  const { kEnc32, kIv32 } = await hkdfSplit(master32, bundleSalt);
  const K_ENC = await importAesKey(kEnc32);
  
  /* ******************************************************
   * Write password-based bootstrap header into bundle
   ****************************************************** */
  const headerBytes = await sealBundleHeaderWithPassword({
    password,
    params: tunedParams,
    bundleId,
    bundleSaltB64: b64(bundleSalt)
  });
  const headerCrc = crc32(headerBytes);
  await bundleWriter.addFile(nameHeader(), headerBytes.length, headerCrc, async function*(){ yield headerBytes.slice(); });
  try { headerBytes.fill(0); } catch {}

  //  Build the clear ZIP as a stream while encrypting fixed-size chunks
  //  Encrypted parts (part-******) are emitted directly into the bundle
  //  A clear-chunk accumulator assembles FIXED_CHUNK_SIZE for each sealed part
  let plainTotalLen = 0;
  let partIndex = 0;
  const perChunkHashes = [];

  let pending = new Uint8Array(0);

  async function flushSealChunk(fixedChunk, isLastChunk, totalChunksEstimateUnknown=false) {
    const sliceEnd = isLastChunk
      ? (plainTotalLen - (FIXED_CHUNK_SIZE * (partIndex)))
      : FIXED_CHUNK_SIZE;

    const innerSlice = fixedChunk.subarray(0, sliceEnd);
    perChunkHashes.push(await sha256Hex(innerSlice));

    const sealed = await sealFixedChunkDet({
      kEncKey: K_ENC, kIv32,
      bundleId,
      payloadChunk: fixedChunk,
      chunkIndex: partIndex,
      totalChunks: isLastChunk ? (partIndex + 1) : 0,
      totalPlainLen: isLastChunk ? plainTotalLen : 0,
      domain: 'data'
    });    

    // Add the encrypted part entry (part-******) into the bundle (store-only) immediately
    const entryName = `part-${String(partIndex).padStart(6,'0')}${FILE_SINGLE_EXT}`;
    const crc = crc32(sealed);
    await bundleWriter.addFile(entryName, sealed.length, crc, async function*(){ yield sealed.slice(); });

    // scrub
    try { sealed.fill(0); } catch {}
    partIndex++;
  }

  // 2a) Clear chunking mechanic → FIXED_CHUNK_SIZE
  async function feedPlain(u8, done=false) {
    if (u8.length === 0 && !done) return;
    // concat pending + u8
    if (pending.length === 0) {
      pending = u8;
    } else {
      const merged = new Uint8Array(pending.length + u8.length);
      merged.set(pending, 0); merged.set(u8, pending.length);
      pending = merged;
    }
    // extract fixed blocks
    while (pending.length >= FIXED_CHUNK_SIZE) {
      const block = pending.subarray(0, FIXED_CHUNK_SIZE);
      const pad = padToFixed(block);
      await flushSealChunk(pad, false);
      pending = pending.subarray(FIXED_CHUNK_SIZE);
    }
    // if end of stream: seal the last one (even if 0)
    /* ******************************************************
    * feedPlain: flush last chunk only if needed
    ****************************************************** */
    if (done) {
      if (pending.length > 0 || plainTotalLen === 0) {
        // note: keep a single empty chunk only if total is 0
        const last = padToFixed(pending);
        await flushSealChunk(last, true);
      }
      pending = new Uint8Array(0);
    }
  }

  // 2b) Build the clear source → depending on 1 file vs multiple
  const sourceFilesMeta = [];

  if (files.length === 1) {
    // === FAST-PATH 1 FILE: no clear ZIP, directly encrypt file data ===
    const f = files[0];
    sourceFilesMeta.push({ name: f.name, type: f.type }); // keep type for MIME on output

    const r = f.stream().getReader();
    try {
      while (true) {
        const { value, done } = await r.read();
        if (done) break;
        const u8 = value instanceof Uint8Array ? value : new Uint8Array(value);
        plainTotalLen += u8.length;               // important: update clear size
        await feedPlain(u8, false);
      }
    } finally {
      try { r.releaseLock?.(); } catch {}
    }
    await feedPlain(new Uint8Array(0), true);    // final flush

  } else {
    // === MULTI-FILES CASE: clear ZIP streaming as before ===
    const zipPlainWriter = new StoreZipWriter({
      write: async (u8) => {
        plainTotalLen += u8.length;
        await feedPlain(u8, false);
      }
    });

    // Use opaque internal entry names to avoid exposing original file metadata in the clear ZIP.
    // Store a mapping (index -> original metadata) in sourceFilesMeta which will be put in the encrypted manifest.
    let fileIdx = 0;
    for (const f of files) {
      sourceFilesMeta.push({
        idx: fileIdx,
        name: f.name,
        size: Number(f.size || 0),
        type: f.type || 'application/octet-stream'
      });
      const internalName = `000${String(fileIdx).padStart(3,'0')}.bin`.replace(/^0+/, (m)=> m); // e.g. "000000.bin" if you prefer pad 6
      // write clear ZIP with opaque internal name (original metadata stays in the encrypted manifest)
      await zipPlainWriter.addFile(internalName, null, null, fileChunkProducer(f));
      fileIdx++;
    }

    // write CD + EOCD of clear ZIP (into pipe also)
    const zipPlainFinalBytes = await zipPlainWriter.finish();
    if (zipPlainFinalBytes && zipPlainFinalBytes.length) {
      plainTotalLen += zipPlainFinalBytes.length;
      await feedPlain(zipPlainFinalBytes, false);
    }
    // signal end to chunker
    await feedPlain(new Uint8Array(0), true);
  }

  // 3) MANIFEST + INDEX (small → RAM OK)
  /* ******************************************************
   * MANIFEST sealing (streaming path) with bundle-level keys
   ****************************************************** */
  if (!Number.isSafeInteger(plainTotalLen) || !Number.isSafeInteger(partIndex)) {
    throw new EnvelopeError('bad_len', 'Length not a safe integer');
  }
  
  const manifestInner = {
    v: 1,
    kind: 'manifest',
  
    // Binding
    bundleId,
    bundleSaltB64: b64(bundleSalt),
  
    // Chunking
    chunkSize: FIXED_CHUNK_SIZE,
    totalPlainLen: plainTotalLen,
    totalChunks: partIndex,
    chunkHashes: perChunkHashes,
  
    // Whole-file hash not computed in streaming
    wholePlainHash: null,
    hashAlg: 'sha256',
  
    // Padding disabled on this path
    realPlainLen: plainTotalLen,
    sizePadded: false,
    padBytes: 0,
  
    // Crypto descriptor (doc)
    aead: 'AES-256-GCM',
    kdf: { outer: 'Argon2id', split: 'HKDF' },
  
    // Provenance
    source: { kind: 'files', files: sourceFilesMeta },
    createdAt: new Date().toISOString()
  };

  const manifestBytes  = TE.encode(JSON.stringify(manifestInner));
  const manChunksClear = chunkFixedGeneric(manifestBytes);
  for (let i = 0; i < manChunksClear.length; i++) {
    const sealed = await sealFixedChunkDet({
      kEncKey: K_ENC,
      kIv32,
      bundleId,
      payloadChunk: padToFixed(manChunksClear[i]),
      chunkIndex: i,
      totalChunks: manChunksClear.length,
      totalPlainLen: manifestBytes.length,
      domain: 'manifest'
    });
    const name = nameManifestPart(i);
    const crc  = crc32(sealed);
    await bundleWriter.addFile(name, sealed.length, crc, async function*(){ yield sealed.slice(); });
    try { sealed.fill(0); } catch {}
  }

  /* ******************************************************
  * MANIFEST_INDEX sealing (streaming path) with bundle-level keys
  ****************************************************** */
  const manChunkHashes = [];
  for (const c of manChunksClear) manChunkHashes.push(await sha256Hex(c));
  const manifestIndexInner = {
    v: 1, kind: 'manifest_index',
    totalChunks: manChunksClear.length,
    totalLen: manifestBytes.length,
    chunkSize: FIXED_CHUNK_SIZE,
    chunkHashes: manChunkHashes
  };
  const manIndexBytes  = TE.encode(JSON.stringify(manifestIndexInner));
  const manIndexChunks = chunkFixedGeneric(manIndexBytes);

  for (let i = 0; i < manIndexChunks.length; i++) {
    const sealed = await sealFixedChunkDet({
      kEncKey: K_ENC,
      kIv32,
      bundleId,
      payloadChunk: padToFixed(manIndexChunks[i]),
      chunkIndex: i,
      totalChunks: manIndexChunks.length,
      totalPlainLen: manIndexBytes.length,
      domain: 'index'
    });
    const name = nameIndexPart(i);
    const crc  = crc32(sealed);
    await bundleWriter.addFile(name, sealed.length, crc, async function*(){ yield sealed.slice(); });
    try { sealed.fill(0); } catch {}
  }

  /* ******************************************************
   * Finalize bundle ZIP
   ****************************************************** */
  const bundleU8 = await bundleWriter.finish();
  try { pending.fill(0); } catch {}
  return { bundleU8, manifest: manifestInner, manifestIndex: manifestIndexInner };
}

function updateEncryptButtonState() {
  const btn = $('#btnEncrypt');
  if (!btn) return;

  const pw = ($('#encPassword').value || '').trim();

  const textPanelVisible  = !$('#encPanelText').hidden;
  const filesPanelVisible = !$('#encPanelFiles').hidden;

  let hasInput = false;
  if (textPanelVisible) {
    hasInput = ($('#encText').value || '').trim().length > 0;
  } else if (filesPanelVisible) {
    const files = $('#encFiles').files;
    hasInput = !!(files && files.length > 0);
  }
  
  const kdfReady =
    tunedParams &&
    Number.isFinite(tunedParams.mMiB) &&
    Number.isFinite(tunedParams.t) &&
    Number.isFinite(tunedParams.p);

  const enabled = pw.length > 0 && hasInput && kdfReady;

  btn.disabled = !enabled;
  if (enabled) btn.removeAttribute('aria-disabled');
  else btn.setAttribute('aria-disabled', 'true');
}

function hideIfEmpty(containerSel, contentSelectors) {
  try {
    const container = document.querySelector(containerSel);
    if (!container) return;

    // Resolve selectors (string or array or comma list)
    let selectors = [];
    if (typeof contentSelectors === 'string') {
      selectors = contentSelectors.split(',').map(s => s.trim());
    } else if (Array.isArray(contentSelectors)) {
      selectors = contentSelectors;
    }

    // Collect visible content nodes
    const nodes = selectors
      .flatMap(sel => Array.from(document.querySelectorAll(sel)))
      .filter(Boolean);

    // If no node found → consider empty
    if (nodes.length === 0) {
      container.classList.add('hidden');
      return;
    }

    // Check emptiness: no children AND no text
    const isNodeEmpty = (n) => {
      const hasChildren = n.childElementCount > 0;
      const hasText = (n.textContent || '').trim().length > 0;
      return !(hasChildren || hasText);
    };

    const allEmpty = nodes.every(isNodeEmpty);

    container.classList.toggle('hidden', allEmpty);
  } catch (e) {
    console.warn('[hideIfEmpty] failed:', e);
  }
}

function updateDecryptButtonState() {
  const btn = $('#btnDecrypt');
  if (!btn) return;

  const pw = ($('#decPassword')?.value || '').trim();
  const file = ($('#decFile')?.files || [])[0];

  const enabled = pw.length > 0 && !!file;

  btn.disabled = !enabled;
  if (enabled) {
    btn.removeAttribute('aria-disabled');
  } else {
    btn.setAttribute('aria-disabled', 'true');
  }
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
  const partNames = entries.filter(e => RX_PART.test(e.name)).map(e => e.name);
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

/* ******************************************************
 * doDecrypt
 *  - Single envelope:
 *      • openFixedChunk (password) → preview or download
 *  - Bundle:
 *      • Open bundle header with openBundleHeaderWithPassword (password)
 *        → (bundleId, bundleSaltB64)
 *      • Derive bundle-level keys once (Argon2id → HKDF → kEnc/kIv32)
 *      • Open manifest index with openFixedChunkDet (bundle keys)
 *      • Open manifest with openFixedChunkDet (bundle keys)
 *        + verify entries against index
 *      • Decrypt each data part with openFixedChunkDet (bundle keys)
 *        and stream plaintext to disk (O(1) RAM)
 ****************************************************** */
async function doDecrypt() {
  let zipU8 = null;
  let entries = null;
  let decryptBtn = null;
  let prevDisabled = false;

  try {
    logInfo('[dec] start');

    // Clear previous outputs first (this currently hides the bar)
    resetDecryptUI({ preservePassword: true, preserveFile: true });

    // Now show the bar and set initial progress
    showProgress('decBar', true);
    setProgress('#decBar', 10);

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
      setProgress('#decBar', 0);
      try {
        const decProgress = document.querySelector('#decBar')?.parentElement;
        if (decProgress) { decProgress.style.display = 'none'; logInfo('[dec] progress hidden (rate-limit)'); }
      } catch (e) { logWarn('[dec] progress hide warn (rate-limit)', e); }
      throw new EnvelopeError('rate_limit', 'cooldown');
    }

    setProgress('#decBar', 10);

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

    // Inputs
    const pw = $('#decPassword').value || '';
    if (!pw) {
      logWarn('[dec] missing password');
      setText('#decFileErr', 'Please enter your passphrase.');
      setProgress('#decBar', 0);
      try { const decProgress = document.querySelector('#decBar')?.parentElement; if (decProgress) decProgress.style.display = 'none'; } catch {}
      try { document.getElementById('decPassword')?.focus(); } catch {}
      try { if (decryptBtn) { decryptBtn.disabled = !!prevDisabled; if (!prevDisabled) decryptBtn.removeAttribute('aria-disabled'); } } catch {}
      logInfo('[dec] abort: no password');
      return;
    }
    const password = pw.normalize('NFKC');

    const f = $('#decFile').files?.[0];
    if (!f)  {
      logWarn('[dec] missing file');
      setText('#decFileErr', `Please choose a ${FILE_SINGLE_EXT} or ${FILE_BUNDLE_EXT} file.`);
      setProgress('#decBar', 0);
      try { const decProgress = document.querySelector('#decBar')?.parentElement; if (decProgress) decProgress.style.display = 'none'; } catch {}
      try { document.getElementById('decDrop')?.focus(); } catch {}
      try { if (decryptBtn) { decryptBtn.disabled = !!prevDisabled; if (!prevDisabled) decryptBtn.removeAttribute('aria-disabled'); } } catch {}
      logInfo('[dec] abort: no file selected');
      return;
    }

    const name = f.name.toLowerCase();

    // Ensure progress visible
    try {
      const decProgress = document.querySelector('#decBar')?.parentElement;
      if (decProgress) { decProgress.style.display = 'block'; logInfo('[dec] progress shown'); }
    } catch (e) { logWarn('[dec] progress show warn', e); }

    const fSize = f.size|0;
    logInfo('[dec] input file', { name, size: fSize });

    if (RX_SINGLE_EXT.test(name)) {
      const isFragment =
        RX_PART.test(f.name) || RX_MANIFEST_PART.test(f.name) || RX_INDEX_PART.test(f.name);
      if (isFragment) {
        throw new EnvelopeError(
          'bundle_fragment',
          `This ${FILE_SINGLE_EXT} is a bundle fragment. Please select the ${FILE_BUNDLE_EXT} file.`
        );
      }
      logInfo(`[dec] mode=single ${FILE_SINGLE_EXT}`);

      // --- SIZE GUARD (single-envelope mode) ---
      // dynamic bound based on the device, with a "reasonable" ceiling for a single chunk
      const capsMax = window.__MAX_INPUT_BYTES_DYNAMIC || MAX_BUNDLE_BYTES; // MAX_BUNDLE_BYTES = MAX_INPUT_BYTES
      const MAX_SINGLE_ENVELOPE_BYTES = Math.min(
        FIXED_CHUNK_SIZE + (1 * 1024 * 1024), // header padding margin
        capsMax
      );
      if (f.size > MAX_SINGLE_ENVELOPE_BYTES) {
        throw new EnvelopeError(
          'input_large',
          `Envelope too large for this device (limit: ~${MAX_SINGLE_ENVELOPE_BYTES} bytes)`
        );
      }

      const env = new Uint8Array(await f.arrayBuffer());
      logInfo('[dec] single env bytes', { bytes: env.length });
    
      let probe;
      try {
        probe = await detectDetEnvelope(env);
      } catch (e) {
        logWarn('[dec] envelope probe failed', e);
      }
    
      if (probe?.kind === 'det') {
        throw new EnvelopeError(
          'det_envelope',
          `This ${FILE_SINGLE_EXT} is a bundle fragment (HKDF, no per-envelope salt). Open the ${FILE_BUNDLE_EXT} instead.`
        );
      }
    
      // --- Per-envelope path: password-based encryption (Argon2id), independent envelopes ---
      const opened = await openFixedChunk({ password, bytes: env });
      const meta   = opened.innerMeta;
    
      logInfo('[dec] single innerMeta', {
        kind: meta?.kind, idx: meta?.chunkIndex, total: meta?.totalChunks,
        totalPlainLen: meta?.totalPlainLen
      });
    
      if (meta.kind !== 'fixed') throw new EnvelopeError('kind', 'Unexpected type');
    
      const idx   = meta.chunkIndex | 0;
      const total = meta.totalChunks | 0;
      if (total > 0 && (idx < 0 || idx >= total)) {
        throw new EnvelopeError('idx_range', 'Chunk index out of range');
      }
    
      if (!Number.isFinite(meta.totalPlainLen) ||
          meta.totalPlainLen < 0 ||
          meta.totalPlainLen > FIXED_CHUNK_SIZE) {
        throw new EnvelopeError('single_len', 'Invalid size for single chunk');
      }
    
      const sliceEnd = meta.totalPlainLen | 0;
      const payload  = opened.fixedChunk.subarray(0, sliceEnd);
      logInfo('[dec] single payload', { sliceEnd });
    
      // Preview or download
      await tryRenderOrDownload(payload, '#decResults', '#decText');
      setText('#decIntegrity', `Single-chunk decrypted. Size: ${payload.length} bytes.`);
      try { opened.fixedChunk.fill(0); } catch {}
      try { env.fill(0); } catch {}
    
      setProgress('#decBar', 100);
      setLive('Decryption complete.');
      logInfo('[dec] single decryption success');
    
      try {
        const decResults = document.getElementById('decResults');
        const decTextEl  = document.getElementById('decText');
        if (decResults) { decResults.classList.remove('hidden'); decResults.classList.add('visible'); }
        if (decTextEl && (decTextEl.textContent || '').trim() !== '') {
          decTextEl.hidden = false;
          decTextEl.classList.add('visible');
        }
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

    /* ******************************************************
     * Bundle mode (deterministic): open header → derive encryption/IV keys → open index → open manifest → stream decrypted payload with O(1) RAM
     ****************************************************** */
    if (!RX_BUNDLE_EXT.test(name)) {
      logWarn('[dec] unsupported file extension', { name });
      throw new EnvelopeError('input', 'unsupported');
    }

    // --- SIZE GUARD (bundle file) ---
    // relies on the device capability detected by init(); fallback to the global hard limit
    const MAX_BUNDLE_BYTES_DYNAMIC = window.__MAX_INPUT_BYTES_DYNAMIC || MAX_BUNDLE_BYTES;
    if (f.size > MAX_BUNDLE_BYTES_DYNAMIC) {
      throw new EnvelopeError('input_large', 'Bundle too large for this device');
    }

    zipU8 = new Uint8Array(await f.arrayBuffer());
    logInfo('[dec] zip bytes', { bytes: zipU8.length });
    entries = await extractZipEntriesStrict(zipU8);
    logInfo('[dec] zip parsed', { entries: entries.length });

    // Build name index and detect duplicates
    const byName = new Map(entries.map(e => [e.name, e]));
    if (byName.size !== entries.length) {
      logWarn('[dec] duplicate entry names detected');
      throw new EnvelopeError('zip_dupe', 'Duplicate entry names in bundle');
    }

    // Only allow expected entry name patterns
    const allowed = [ new RegExp(`^${rxEscape(nameHeader())}$`, 'i'), RX_PART, RX_MANIFEST_PART, RX_INDEX_PART ];

    let unexpected = 0;
    for (const e of entries) {
      const ok = allowed.some(rx => rx.test(e.name));
      if (!ok) unexpected++;
    }
    if (unexpected) {
      logWarn('[dec] unexpected entries in ZIP', { unexpected });
      throw new EnvelopeError('zip_extra', `Unexpected entry in bundle`);
    }

    // Free raw ZIP buffer early
    try { zipU8.fill(0); } catch {}
    zipU8 = null;

    /* ******************************************************
    * Bootstrap: open password-based bundle header (encrypted container)
    ****************************************************** */
    const headerEntry = entries.find(e => e.name.toLowerCase() === nameHeader().toLowerCase());
    if (!headerEntry) {
      logWarn('[dec] missing bootstrap header');
      throw new EnvelopeError('no_header', 'Missing bundle header');
    }
    const header = await openBundleHeaderWithPassword({
      password,
      bytes: headerEntry.bytes,
      params: tunedParams
    });
    const expectedBundleId = header.bundleId;

    // Derive bundle keys once (Argon2 → HKDF) from header.bundleSaltB64
    const bundleSalt_fromHeader = b64d(header.bundleSaltB64);
    const master32   = await deriveArgon2id(password, bundleSalt_fromHeader, tunedParams);
    const { kEnc32, kIv32 } = await hkdfSplit(master32, bundleSalt_fromHeader);
    const K_ENC = await importAesKey(kEnc32);

    /* ******************************************************
    * Open MANIFEST_INDEX with bundle-level keys (Det)
    ****************************************************** */
    const idxEntries = entries
      .filter(e => RX_INDEX_PART.test(e.name))
      .sort((a, b) => a.name.localeCompare(b.name));
    if (idxEntries.length === 0) {
      logWarn('[dec] no manifest index');
      throw new EnvelopeError('no_manifest_index', 'Manifest index missing');
    }

    let idxLen = null;
    const idxSlices = [];
    for (let i = 0; i < idxEntries.length; i++) {
      const opened = await openFixedChunkDet({
        kEncKey: K_ENC,
        kIv32,
        bytes: idxEntries[i].bytes,
        expectedBundleId,
        chunkIndex: i,
        domain: 'index'
      });

      const inner = opened.innerMeta;
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

    // Rebuild and parse manIndex JSON
    const idxBuf = new Uint8Array(idxLen);
    let offset = 0;
    for (const s of idxSlices) { idxBuf.set(s, offset); offset += s.length; }
    let manIndex;
    try {
      manIndex = JSON.parse(TD.decode(idxBuf));
    } finally {
      try { idxBuf.fill(0); } catch {}
      for (const s of idxSlices) { try { s.fill(0); } catch {} }
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

    /* ******************************************************
     * 3) Open MANIFEST with bundle-level keys (Det) and verify against INDEX
     ****************************************************** */
    let manifestRecovered = new Uint8Array(mLen);
    let mWritten = 0;

    for (let i = 0; i < mTotal; i++) {
      const entry = byName.get(nameManifestPart(i));
      if (!entry) {
        logWarn('[dec] missing manifest part', { i });
        throw new EnvelopeError('missing_manifest_part', `Manifest chunk ${i} missing`);
      }

      const opened = await openFixedChunkDet({
        kEncKey: K_ENC,
        kIv32,
        bytes: entry.bytes,
        expectedBundleId,
        chunkIndex: i,
        domain: 'manifest'
      });

      const inner = opened.innerMeta;
      if (inner.kind !== 'fixed') throw new EnvelopeError('man_part_kind',  `Manifest chunk ${i}: unexpected type`);
      if (inner.chunkIndex !== i) throw new EnvelopeError('man_part_idx',   `Manifest chunk ${i}: wrong index`);
      if (inner.totalChunks !== mTotal) throw new EnvelopeError('man_part_total', `Manifest chunk ${i}: totalChunks mismatch`);
      if (inner.totalPlainLen !== mLen) throw new EnvelopeError('man_part_len',   `Manifest chunk ${i}: totalLen mismatch`);

      const isLast   = (i === mTotal - 1);
      const sliceEnd = isLast ? (mLen - (FIXED_CHUNK_SIZE * (mTotal - 1))) : FIXED_CHUNK_SIZE;
      if (sliceEnd < 0 || sliceEnd > FIXED_CHUNK_SIZE) {
        logWarn('[dec] invalid manifest slice size', { i, sliceEnd });
        throw new EnvelopeError('man_slice_size', `Manifest part ${i}: invalid slice size`);
      }

      const slice = opened.fixedChunk.subarray(0, sliceEnd);

      // Integrity against MANIFEST_INDEX
      const h = await sha256Hex(slice);
      const expected = manIndex.chunkHashes[i];
      if (!timingSafeEqual(h, expected)) {
        logWarn('[dec] manifest hash mismatch', { i });
        throw new EnvelopeError('man_hash_mismatch', `Manifest chunk ${i}: unexpected hash`);
      }

      manifestRecovered.set(slice, i * FIXED_CHUNK_SIZE);
      mWritten += slice.length;
      try { opened.fixedChunk.fill(0); } catch {}

      setProgress('#decBar', 10 + Math.floor(10 * (i + 1) / mTotal));
      if ((i & 1) === 0) await new Promise(r => setTimeout(r, 0));
    }
    if (mWritten !== mLen) {
      logWarn('[dec] manifest rebuild size mismatch', { mWritten, mLen });
      throw new EnvelopeError('man_rebuild_size', 'Incorrect manifest reconstructed size');
    }

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
    if (manifest.wholePlainHash != null && !/^[0-9a-f]{64}$/i.test(manifest.wholePlainHash)) {
      throw new EnvelopeError('bad_whole_hash', 'Invalid wholePlainHash');
    }

    // Optional sanity: manifest salt must match header salt
    if (manifest.bundleSaltB64 !== header.bundleSaltB64) {
      throw new EnvelopeError('bad_manifest', 'Manifest salt does not match header');
    }

    // ===== Padding-aware manifest checks =====
    const hasReal = Object.prototype.hasOwnProperty.call(manifest, 'realPlainLen');
    const realLen = Number(manifest.realPlainLen);
    const totalLen = Number(manifest.totalPlainLen);
    
    if (hasReal) {
      if (!Number.isFinite(realLen) || realLen < 0) {
        throw new EnvelopeError('bad_manifest_len', 'Invalid realPlainLen');
      }
      if (realLen > totalLen) {
        throw new EnvelopeError('bad_manifest_len', 'realPlainLen exceeds totalPlainLen');
      }
      if (manifest.sizePadded === false && realLen !== totalLen) {
        throw new EnvelopeError('bad_manifest_len', 'Unexpected size mismatch for unpadded bundle');
      }
    }

    /* ******************************************************
     * Validate indices (data parts)
     ****************************************************** */
    const { idxs, max } = validateIndexSetFromNames(entries);
    logInfo('[dec] data index set', { count: idxs.length, max });
    if ((max + 1) !== manifest.totalChunks) throw new EnvelopeError('total_mismatch', 'totalChunks mismatch');

    /* ******************************************************
     * Stream plaintext output: File System Access (O(1) RAM) or memory fallback
     ****************************************************** */
    async function getPlainSink(suggestedName = 'files.zip') {
      if (window.showSaveFilePicker) {
        const handle = await showSaveFilePicker({
          suggestedName,
          types: [{
            description: 'Decrypted Output',
            accept: { 'application/octet-stream': ['.zip', '.bin', '.txt'] }
          }]
        });
        const writable = await handle.createWritable();
        return new FileStreamSink(writable);
      }
      return new SegmentsSink(); // memory fallback
    }

    // Suggested output filename (original intent)
    let outName =
      (manifest?.source?.kind === 'files' && Array.isArray(manifest.source.files) && manifest.source.files.length > 1)
          ? 'files.zip'
          : (manifest?.source?.kind === 'text'
              ? 'decrypted.txt'
              : (manifest?.source?.files?.[0]?.name || 'decrypted.bin'));
    
    // Filename heuristic: warn user if suggested name looks suspicious and allow abort.
    // If user continues, replace the suggested name with a safe default (zip/txt/bin).
    const nameCheck = hasSuspiciousName(outName);
    if (!nameCheck.ok) {
      const msg = `Warning: suggested filename looks suspicious: ${nameCheck.why}\n\n` +
                  `If you continue, a safe filename will be used for saving.`;
      const cont = await promptUserConfirm(msg);
      if (!cont) {
        throw new EnvelopeError('user_abort', 'User cancelled due to suspicious filename');
      }
      // Force safe default
      if (manifest?.source?.kind === 'files' && manifest.source.files.length > 1) outName = 'files.zip';
      else if (manifest?.source?.kind === 'text') outName = 'decrypted.txt';
      else outName = 'decrypted.bin';
    }
    
    // Additional manifest-level check: warn if declared source files include executable-like names.
    if (Array.isArray(manifest?.source?.files) && manifest.source.files.length > 0) {
      for (const sf of manifest.source.files) {
        const fname = String(sf?.name || '');
        if (DANGEROUS_EXT.test(fname)) {
          const msg = `Warning: package contains file named "${fname}", which appears to be an executable.\n\n` +
                      `Press OK to continue and save decrypted output, or Cancel to abort.`;
          const cont = await promptUserConfirm(msg);
          if (!cont) throw new EnvelopeError('user_abort', 'User cancelled due to executable file in manifest');
          break;
        }
      }
    }
    
    const plainSink = await getPlainSink(outName);
    
    // ===== Prepare trimming (remove size padding on decrypt) =====
    const wantTrim =
      hasReal &&
      Number.isFinite(realLen) &&
      realLen >= 0 &&
      realLen <= totalLen;
    
    let remainingToWrite = wantTrim ? realLen : totalLen;
    logInfo('[dec] trim setup', { wantTrim, realLen, totalLen });

    /* ******************************************************
     * Decrypt, verify and stream each data chunk
     ****************************************************** */
    let warnedAboutExecutable = false;
    let written = 0;
    for (let i = 0; i < manifest.totalChunks; i++) {
      const entry = byName.get(namePart(i));
      if (!entry) { logWarn('[dec] missing data chunk', { i }); throw new EnvelopeError('missing_part', `Chunk ${i} missing`); }

      // Open with bundle-level keys (no per-chunk Argon2)
      const opened = await openFixedChunkDet({
        kEncKey: K_ENC,
        kIv32,
        bytes: entry.bytes,
        expectedBundleId,
        chunkIndex: i,
        domain: 'data'
      });

      const inner  = opened.innerMeta;
      if (inner.kind !== 'fixed') throw new EnvelopeError('part_kind',  `Chunk ${i}: unexpected type`);
      if (inner.chunkIndex !== i) throw new EnvelopeError('part_idx',   `Chunk ${i}: wrong internal index`);

      const isLastPart = (i === manifest.totalChunks - 1);
      if (inner.totalChunks && inner.totalChunks !== manifest.totalChunks) {
        throw new EnvelopeError('part_total', `Chunk ${i}: totalChunks mismatch`);
      }
      if (inner.totalPlainLen) {
        if (isLastPart) {
          if (inner.totalPlainLen !== manifest.totalPlainLen) {
            throw new EnvelopeError('part_len', `Chunk ${i}: totalPlainLen mismatch (last)`);
          }
        } else {
          if (inner.totalPlainLen > manifest.totalPlainLen) {
            throw new EnvelopeError('part_len', `Chunk ${i}: totalPlainLen exceeds manifest`);
          }
        }
      }

      const sliceEnd = isLastPart
        ? (manifest.totalPlainLen - (FIXED_CHUNK_SIZE * (manifest.totalChunks - 1)))
        : FIXED_CHUNK_SIZE;
      const slice    = opened.fixedChunk.subarray(0, sliceEnd);

      // Per-chunk integrity check
      const h = await sha256Hex(slice);
      const expected = manifest.chunkHashes[i];
      if (!timingSafeEqual(h, expected)) {
        logWarn('[dec] data hash mismatch', { i });
        throw new EnvelopeError('hash_mismatch', `Chunk ${i}: unexpected hash`);
      }
      
      // User warning: content appears executable/script; OK to continue, Cancel to stop.
      if (!warnedAboutExecutable) {
        const sample = slice.subarray(0, Math.min(slice.length, 4096));
        if (looksExecutableBytes(sample) ||
          DANGEROUS_EXT.test(String(outName || ''))) {
            const cont = await promptUserConfirm(
              'The decrypted content appears to be an executable or script. Opening or running such files can be dangerous.'
            );
            if (!cont) throw new EnvelopeError('user_abort', 'User cancelled after executable warning');
            if (!outName || !outName.endsWith('.zip')) outName = 'decrypted.bin';
            showErrorBanner('Caution: executable-like content detected. Proceeding as binary.');
            warnedAboutExecutable = true;
        }
      }
      
      // Write only unpadded plaintext
      let toWrite = slice.length;
      if (wantTrim) {
        toWrite = Math.min(toWrite, Math.max(0, remainingToWrite));
      }
      
      if (toWrite > 0) {
        await plainSink.write(slice.subarray(0, toWrite));
        written += toWrite;
        if (wantTrim) remainingToWrite -= toWrite;
      }
      
      if (wantTrim && remainingToWrite <= 0) {
        try { opened.fixedChunk.fill(0); } catch {}
        break;
      }

      try { opened.fixedChunk.fill(0); } catch {}

      setProgress('#decBar', 20 + Math.floor(70 * (i + 1) / manifest.totalChunks));
      if ((i & 1) === 0) await new Promise(r => setTimeout(r, 0));
    }

    if (typeof plainSink.close === 'function') {
      try { await plainSink.close(); } catch {}
    }

    // Wipe keying material (bytes)
    try { master32.fill(0); } catch {}
    try { kEnc32.fill(0); } catch {}
    try { kIv32.fill(0); } catch {}

    /* ******************************************************
     * Present results (memory fallback or saved-to-disk)
     ****************************************************** */
    if (plainSink instanceof SegmentsSink) {
      const u8 = plainSink.toUint8Array();
      // Defensive trim for memory fallback
      let offeredBytes = u8;
      if (hasReal && realLen <= offeredBytes.length) {
        offeredBytes = offeredBytes.subarray(0, realLen);
      }
      
      // Attempt to rebuild a ZIP with original filenames using the encrypted manifest mapping.
      // If this is not a multi-file package or rebuild fails, fall back to the current behavior.
      let offeredMime =
        (manifest?.source?.kind === 'files' && manifest.source.files?.length > 1)
          ? 'application/zip'
          : (manifest?.source?.kind === 'text'
              ? 'text/plain;charset=utf-8'
              : (manifest?.source?.files?.[0]?.type || 'application/octet-stream'));
      let offeredName = outName;
    
      if (manifest?.source?.kind === 'files' && Array.isArray(manifest.source.files) && manifest.source.files.length > 1) {
        try {
          const clearEntries = await extractZipEntriesStrict(u8); // [{ name, bytes }, ...]
          const fileMap = new Map(
            (manifest.source.files || [])
              .filter(m => Number.isFinite(m.idx))
              .map(m => [Number(m.idx), m])
          );
    
          const rebuildSink = new SegmentsSink();
          const writer = new StoreZipWriter(rebuildSink);
          const usedNames = new Set();
    
          for (const e of clearEntries) {
            // Internal opaque pattern like "000000.bin" → extract numeric index
            const m = e.name.match(/0*?(\d+)\.bin$/i);
            const idx = m ? Number(m[1]) : null;
            const desired = (idx !== null && fileMap.has(idx)) ? String(fileMap.get(idx).name) : e.name;
            const outEntryName = sanitizeZipFilename(desired, usedNames);
            const crc = crc32(e.bytes);
            await writer.addFile(outEntryName, e.bytes.length, crc, async function* () { yield e.bytes.slice(); });
          }
    
          const rebuiltZip = await writer.finish();
          offeredBytes = rebuiltZip;
          offeredMime  = 'application/zip';
          offeredName  = 'files.zip';
        } catch (e) {
          // Fall back silently to anonymous ZIP if rebuild is not possible.
        }
      }
    
      if (manifest?.source?.kind === 'text') {
        // Show text preview (up to MAX_PREVIEW) and provide a .txt download
        await tryRenderOrDownload(offeredBytes, '#decResults', '#decText');
        const decResults = document.getElementById('decResults');
        if (decResults) { decResults.classList.remove('hidden'); decResults.classList.add('visible'); }
        const decTextEl = document.getElementById('decText');
        if (decTextEl && (decTextEl.textContent || '').trim() !== '') {
          decTextEl.hidden = false;
          decTextEl.classList.add('visible');
        }
      } else {
        addDownload('#decResults', new Blob([offeredBytes], { type: offeredMime }), offeredName, 'Download');
        const decResults = document.getElementById('decResults');
        if (decResults) { decResults.classList.remove('hidden'); decResults.classList.add('visible'); }
        const decTextEl = document.getElementById('decText');
        if (decTextEl) {
          decTextEl.hidden = true;
          decTextEl.classList.remove('visible');
          setText('#decText', '');
        }
      }
    
      // Whole-file hash verification (only possible in memory fallback)
      if (manifest.wholePlainHash) {
        const whole = await sha256Hex(offeredBytes);
        const ok = timingSafeEqual(whole, manifest.wholePlainHash);
        //setText('#decIntegrity', ok ? 'Integrity OK (unpadded plaintext).' : 'Alert: plaintext hash mismatch.');
        setText('#decIntegrity', ok ? 'Integrity OK.' : 'Alert: plaintext hash mismatch.');
      } else {
        setText('#decIntegrity', wantTrim ? 'Integrity: chunk-level verified (in memory)(OK).'
                                          : 'Integrity: chunk-level verified - No padding required (in memory)(OK).');
      }
    } else {
      // Saved directly to disk
      setText('#decIntegrity', wantTrim
        ? 'Integrity: chunk-level verified (written to disk)(OK).'
        : 'Integrity: chunk-level verified - No padding required (written to disk)(OK).');
      const decResults = document.getElementById('decResults');
      if (decResults) { decResults.classList.remove('hidden'); decResults.classList.add('visible'); }
      const decTextEl = document.getElementById('decText');
      if (decTextEl) {
        decTextEl.hidden = true;
        decTextEl.classList.remove('visible');
        setText('#decText', '');
      }
    }

    setProgress('#decBar', 100);
    setLive('Decryption complete.');
    logInfo('[dec] success');

    try {
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
    await secureFail('Decryption', normalizeEncError(err));
    setProgress('#decBar', 100);
    clearPasswords();
    try {
      const decProgress = document.querySelector('#decBar')?.parentElement;
      if (decProgress) { decProgress.style.display = 'none'; logInfo('[dec] progress hidden (error)'); }
    } catch (e) { logWarn('[dec] progress hide warn (error)', e); }
  } finally {
    // Restore button state
    try {
      if (decryptBtn) {
        decryptBtn.disabled = !!prevDisabled;
        if (!prevDisabled) decryptBtn.removeAttribute('aria-disabled');
        logInfo('[dec] btnDecrypt restored', { disabled: !!prevDisabled });
      }
    } catch (e) { logWarn('[dec] btn restore warn', e); }

    // Ensure progress hidden on exit
    try {
      const decProgress = document.querySelector('#decBar')?.parentElement;
      if (decProgress) { decProgress.style.display = 'none'; logInfo('[dec] progress hidden (finally)'); }
    } catch (e) { logWarn('[dec] progress hide warn (finally)', e); }

    // Wipe encrypted chunk buffers (from ZIP or direct encrypted container)
    try {
      let wiped = 0;
      for (const e of entries || []) { if (e?.bytes?.fill) { e.bytes.fill(0); wiped++; } }
      logInfo('[dec] wiped encrypted buffers', { wiped });
    } catch (e) { logWarn('[dec] wipe buffers warn', e); }

    // Drop references so GC can reclaim
    entries = null;

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


// ===== Panic / Clear all =====

/**
 * Clear all local UI state, wipe progress, and revoke created object URLs.
 */
function panicClear() {
  try {
    // Reset both panels (also hides their progress bars)
    resetEncryptUI();
    resetDecryptUI();
    clearPasswords();

    // Input fields
    try { $('#encText').value = ''; } catch {}
    try { $('#encFiles').value = ''; } catch {}
    try { $('#decFile').value  = ''; } catch {}
    try { setText('#decFileName', ''); } catch {}

    // ENCRYPT outputs (explicitly clear + hide everything)
    try { clearNode('#encResultsText'); } catch {}
    try { clearNode('#encResultsFiles'); } catch {}
    try { setText('#encHashText',  ''); } catch {}
    try { setText('#encHashFiles', ''); } catch {}
    try {
      const detText   = document.querySelector('#encDetailsText');
      const detFiles  = document.querySelector('#encDetailsFiles');
      const resText   = document.querySelector('#encResultsText');
      const resFiles  = document.querySelector('#encResultsFiles');
      const prevText  = document.querySelector('#encPreviewText');
      const prevFiles = document.querySelector('#encPreviewFiles');

      if (detText)  detText.classList.add('hidden');
      if (detFiles) detFiles.classList.add('hidden');
      if (resText)  resText.classList.add('hidden');
      if (resFiles) resFiles.classList.add('hidden');

      if (prevText)  { setText(prevText, '');  prevText.classList.add('hidden'); }
      if (prevFiles) { setText(prevFiles, ''); prevFiles.classList.add('hidden'); }
    } catch {}

    // DECRYPT outputs
    try { clearNode('#decResults'); } catch {}
    try { setText('#decText', ''); } catch {}
    try {
      const t   = document.querySelector('#decText');    if (t)   t.hidden = true;
      const res = document.querySelector('#decResults'); if (res) res.classList.add('hidden');
    } catch {}
    try { setText('#decIntegrity', ''); } catch {}

    // Hide and reset progress bars (scoped)
    try { showEncProgress('text',  false); } catch {}
    try { showEncProgress('files', false); } catch {}
    try { showProgress('decBar', false); } catch {}
    try { setProgress('#encBarText',  0); } catch {}
    try { setProgress('#encBarFiles', 0); } catch {}
    try { setProgress('#decBar',      0); } catch {}

    setLive('All local state cleared.');

    // Revoke all object URLs created earlier
    try {
      for (const url of __urlsToRevoke) {
        try { URL.revokeObjectURL(url); } catch {}
      }
      __urlsToRevoke.clear();
    } catch {}

    // Ensure any residual blob anchors/buttons are removed
    try {
      ['#encResultsText', '#encResultsFiles', '#decResults'].forEach(sel => {
        const el = document.querySelector(sel);
        if (!el) return;
        el.querySelectorAll('a[href^="blob:"]').forEach(a => { try { a.remove(); } catch {} });
        el.querySelectorAll('button').forEach(b => { try { b.remove(); } catch {} });
      });
    } catch {}

    // Reset Encrypt password visibility toggle (UX)
    try {
      const pw = $('#encPassword'); if (pw) pw.type = 'password';
      const t  = $('#encPwdToggle'); if (t) { setText(t, 'Show'); t.setAttribute('aria-pressed','false'); }
    } catch {}

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
  const isNativeLabel = zone.tagName === 'LABEL' && zone.getAttribute('for') === inputId;

  if (!isNativeLabel) {
    const openPicker = () => {
      const wasHidden = input.hasAttribute('hidden');
      if (wasHidden) input.removeAttribute('hidden');     // dé-cache temporairement
  
      if (typeof input.showPicker === 'function') input.showPicker();
      else input.click();
  
      if (wasHidden) input.setAttribute('hidden', '');    // re-cache
    };
    zone.addEventListener('click', openPicker);
  }
  
  // Accessibilité clavier : Enter/Espace
  zone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (typeof input.showPicker === 'function') input.showPicker();
      else input.click();
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
  updateEncryptButtonState();
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
       const resultsContainer = $('#resultsContainer');
       if (resultsContainer) resultsContainer.hidden = true;
       setLive('UI cleared.');
     });
    
  $('#btnClearDecrypt').addEventListener('click', () => {
    resetDecryptUI();
    setLive('UI cleared.');
  });

  // Action reset
  $('#encPassword').addEventListener('input', updateEncryptButtonState);
  $('#encText').addEventListener('input', updateEncryptButtonState);
  $('#encFiles').addEventListener('change', updateEncryptButtonState);
  $('#decPassword').addEventListener('input', updateDecryptButtonState);
  $('#decFile').addEventListener('change', updateDecryptButtonState);

  // Main actions
  $('#btnEncrypt').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    if (btn.disabled) return;
    btn.disabled = true;
  
    try {
      await waitForKdfReady(8000); // 8s max; ajuste si tu veux
    } catch (err) {
      await secureFail('Encryption', normalizeEncError(err));
      btn.disabled = false;
      return;
    }
  
    const files = $('#encFiles')?.files;
    try {
      if (files && files.length) preflightInputs([...files]);
    } catch (err) {
      await secureFail('Encryption', normalizeEncError(err));
      btn.disabled = false;
      return;
    }
  
    encBusy = true;
    try {
      await doEncrypt();
    } finally {
      encBusy = false;
      btn.disabled = false;
    }
  });
  
  $('#btnDecrypt').addEventListener('click', doDecrypt);

  // Panic / Clear all
  const panicBtn = $('#btnPanic');
  if (panicBtn) panicBtn.addEventListener('click', () => {
    panicClear();
    const resultsContainer = $('#resultsContainer');
    if (resultsContainer) resultsContainer.hidden = true;
  });

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

  // ——— Garde global pour traiter seulement si un chiffrement est en cours
  let encBusy = false;
  
  window.addEventListener('unhandledrejection', async (ev) => {
    if (!encBusy) return;
    logError('[enc] unhandledrejection', ev.reason);
    await secureFail('Encryption', normalizeEncError(ev.reason));
  });
  
  window.addEventListener('error', async (ev) => {
    if (!encBusy) return;
    logError('[enc] window error', ev.error || ev.message);
    const e = ev.error || new Error(String(ev.message));
    await secureFail('Encryption', normalizeEncError(e));
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
