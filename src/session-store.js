'use strict';

const crypto = require('crypto');
const fs     = require('fs');

// Maximum entries before the store warns and stops recording.
// Prevents unbounded memory growth in large test suites.
const MAX_ENTRIES = parseInt(process.env.ACCGUARD_MAX_ENTRIES || "10000", 10);

const ID_PATTERNS = [
  { type: 'uuid',    re: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi },
  { type: 'integer', re: /(?<![.\d])(\d{1,20})(?![.\d])/g },
];

function fingerprintToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

// Returns { raw, type, cookieName } or null.
// type is 'bearer', 'other-auth', or 'cookie' — used by replay to send the
// second token in the correct format.
//
// Auth scheme generalization: accguard doesn't need to understand the scheme —
// it only needs to know "this request carried auth" and "this is its fingerprint."
// Bearer gets special handling because replay knows how to substitute it.
// All other Authorization schemes (Basic, Digest, Token, ApiKey) are recorded
// with type 'other-auth' — replay will warn that substitution is not supported
// for this scheme and the request will be replayed without auth (likely 401).
// X-API-Key is handled via ACCGUARD_API_KEY_HEADER env var (default: x-api-key).
function extractToken(headers) {
  // Guard against array-valued Authorization headers — Node's http module
  // usually gives a string, but some test frameworks or proxy middleware
  // concatenate duplicate headers into an array.
  // Iterate to find the first non-empty value — a malformed empty first element
  // (e.g. ['', 'Bearer bob-jwt']) would otherwise silently drop the valid token.
  const authHeader = Array.isArray(headers['authorization'])
    ? headers['authorization'].find(v => v && v.trim()) || ''
    : headers['authorization'];
  const auth = authHeader || '';

  if (auth.toLowerCase().startsWith('bearer ')) {
    const raw = auth.slice(7).trim();
    // Only return bearer if the extracted value is non-empty.
    // An empty Authorization: Bearer header (stale/malformed) should fall
    // through to cookie auth rather than recording the wrong auth type.
    if (raw) return { raw, type: 'bearer', cookieName: null };
  }

  // Non-Bearer Authorization schemes — Basic, Digest, Token, ApiKey, etc.
  // Record the raw value for fingerprinting so the request IS stored and replayable.
  // Replay will attempt substitution with TOKEN_B using the same scheme prefix.
  //
  // Guards — fall through to cookie/API-key auth when:
  //   1. auth is empty or whitespace-only
  //   2. auth is just a known scheme name with no value (e.g. "Basic", "Token", "Digest")
  //      These are stale/malformed headers — same class as the empty Bearer case.
  const KNOWN_SCHEMES = new Set(['bearer', 'basic', 'digest', 'token', 'apikey', 'api-key']);
  const authTrimmed = auth.trim();
  const isBearerNoValue = authTrimmed.toLowerCase() === 'bearer' ||
                          authTrimmed.toLowerCase().startsWith('bearer ');
  // A bare known scheme with no credential value — fall through
  const isBareScheme = KNOWN_SCHEMES.has(authTrimmed.toLowerCase());
  if (authTrimmed && !isBearerNoValue && !isBareScheme) {
    return { raw: authTrimmed, type: 'other-auth', cookieName: null };
  }

  // X-API-Key header — common non-Authorization API key pattern.
  // Configurable via ACCGUARD_API_KEY_HEADER (default: x-api-key).
  // Guard against array-valued headers — same pattern as Authorization.
  const apiKeyHeader = (process.env.ACCGUARD_API_KEY_HEADER || 'x-api-key').toLowerCase();
  const apiKeyRaw = Array.isArray(headers[apiKeyHeader])
    ? headers[apiKeyHeader].find(v => v && v.trim()) || ''
    : headers[apiKeyHeader] || '';
  if (apiKeyRaw.trim()) {
    return { raw: apiKeyRaw.trim(), type: 'api-key', cookieName: null, apiKeyHeader };
  }

  const cookie = headers['cookie'] || '';

  // Cookie name resolution — three levels, first match wins:
  //
  // 1. ACCGUARD_COOKIE_NAME env var — operator knows their app, use exactly.
  // 2. Generic session names — fast path for simple/custom apps.
  // 3. Framework defaults — explicit curated list of known framework cookie names.
  //    Not a substring match (avoids grabbing csrftoken, xsrf-token, etc.).
  //    Covers: Express, Laravel, PHP, Java EE, NextAuth, ASP.NET, Rails,
  //    Django, Flask, and __Secure- prefixed variants.
  //
  // If none match, the request is recorded without a token and skipped for replay.
  // Set ACCGUARD_COOKIE_NAME to force a specific name for unusual frameworks.

  const COOKIE_OVERRIDE = process.env.ACCGUARD_COOKIE_NAME
    ? new Set([process.env.ACCGUARD_COOKIE_NAME.toLowerCase()])
    : null;

  const SESSION_NAMES_GENERIC = new Set([
    'session', 'token', 'auth', 'jwt', 'sid',
  ]);

  const SESSION_NAMES_FRAMEWORKS = new Set([
    // Express / Connect
    'connect.sid',
    // Laravel
    'laravel_session',
    // PHP
    'phpsessid',
    // Java EE
    'jsessionid',
    // NextAuth.js
    'next-auth.session-token',
    '__secure-next-auth.session-token',
    // ASP.NET
    'asp.net_sessionid',
    '.aspnetcore.session',
    // Rails
    '_session_id',
    // Django
    'sessionid',
    // Flask
    'session',  // already in generic, harmless duplicate
  ]);

  const ACTIVE_NAMES = COOKIE_OVERRIDE || SESSION_NAMES_GENERIC;

  for (const part of cookie.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const name  = part.slice(0, eqIdx).trim().toLowerCase();
    const value = part.slice(eqIdx + 1).trim();
    if ((ACTIVE_NAMES.has(name) || SESSION_NAMES_FRAMEWORKS.has(name)) && value) {
      // Note: value is taken as everything after the first '=' in this segment.
      // Cookie attributes like expires= or path= are separated by ';' and handled
      // by the outer split, so they do not bleed into the token value.
      // Known boundary behavior: malformed cookies without proper ';' separators
      // will include trailing text in the raw value. Documented, not fixed.
      return { raw: value, type: 'cookie', cookieName: name };
    }
  }

  return null;
}

// Extracts resource IDs from a URL path.
// Handles integers, UUIDs, and slug-style IDs (ord-1001, user-alice, pay-1).
function extractResourceIds(urlPath) {
  const ids = [];

  for (const { type, re } of ID_PATTERNS) {
    let m;
    re.lastIndex = 0;
    while ((m = re.exec(urlPath)) !== null) {
      ids.push({ type, value: m[0] });
    }
  }

  // Slug IDs: letters+digits separated by hyphens
  const segments = urlPath.split('/').filter(Boolean);
  for (const seg of segments) {
    if (/^[a-z][a-z0-9]*(-[a-z0-9]+)+$/.test(seg)) {
      ids.push({ type: 'slug', value: seg });
    }
  }

  return ids.filter((id, i, arr) => arr.findIndex(x => x.value === id.value) === i);
}

class SessionStore {
  constructor() {
    this.entries    = [];
    this._capped    = false;
  }

  record({ method, url, headers, statusCode, contentLength, contentHash, rawHash }) {
    // Memory guard — warn once and stop recording if limit reached
    if (this.entries.length >= MAX_ENTRIES) {
      if (!this._capped) {
        console.warn(
          `[accguard] Session store reached ${MAX_ENTRIES} entries — ` +
          `stopping recording. Increase MAX_ENTRIES if needed.`
        );
        this._capped = true;
      }
      return;
    }

    const tokenInfo = extractToken(headers);
    if (!tokenInfo) return;

    const parsed      = new URL(url, 'http://localhost');
    const resourceIds = extractResourceIds(parsed.pathname + parsed.search);

    // Extract scheme prefix for other-auth types so replay can reconstruct
    // the Authorization header with the correct scheme (Basic, Token, ApiKey, etc.)
    // Scheme-less tokens (no space in value, e.g. "Authorization: rawtoken") get
    // an empty scheme — replay sends "Authorization: TOKEN_B" with no prefix.
    const authScheme = tokenInfo.type === 'other-auth'
      ? (tokenInfo.raw.includes(' ') ? tokenInfo.raw.split(' ')[0] : '')
      : null;

    this.entries.push({
      method:             method.toUpperCase(),
      path:               parsed.pathname,
      query:              parsed.search,
      tokenHash:          fingerprintToken(tokenInfo.raw),
      tokenType:          tokenInfo.type,
      cookieName:         tokenInfo.cookieName,
      apiKeyHeader:       tokenInfo.apiKeyHeader || null,
      userAgent:          headers['user-agent'] || null,
      originalAuthScheme: authScheme,
      resourceIds,
      statusCode,
      contentLength: contentLength || 0,
      contentHash:   contentHash   || null,
      rawHash:       rawHash       || null,
      recordedAt:    Date.now(),
    });
  }

  // Returns deduplicated replayable entries.
  // Deduplication key: method + path + query + tokenHash.
  // Prevents 15 identical findings when a test suite hits the same
  // endpoint repeatedly in beforeEach hooks — preserves signal clarity.
  replayable() {
    const seen = new Set();
    return this.entries.filter(e => {
      if (!e.resourceIds.length) return false;
      if (!['GET'].includes(e.method)) return false;
      const key = `${e.method}:${e.path}:${e.query}:${e.tokenHash}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  knownTokens() {
    return [...new Set(this.entries.map(e => e.tokenHash))];
  }

  // FIX: wrapped in try/catch — file write failure is surfaced clearly,
  // not silently crashed. Findings already printed to terminal are safe.
  saveTo(filePath) {
    try {
      fs.writeFileSync(filePath, JSON.stringify({
        version:     '0.9.2',
        generatedAt: new Date().toISOString(),
        totalCount:  this.entries.length,
        entries:     this.entries,
      }, null, 2), 'utf8');
    } catch (err) {
      console.error(`[accguard] Could not save session store to ${filePath}: ${err.message}`);
    }
  }

  // FIX: separate guards for file read and JSON parse — each gives a precise
  // error message so developers know exactly what went wrong.
  static loadFrom(filePath) {
    let raw;
    try {
      raw = fs.readFileSync(filePath, 'utf8');
    } catch (err) {
      throw new Error(`Could not read session store at ${filePath}: ${err.message}`);
    }

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new Error(`Session store at ${filePath} is not valid JSON: ${err.message}`);
    }

    if (!parsed.entries || !Array.isArray(parsed.entries)) {
      throw new Error(`Session store at ${filePath} has unexpected format — missing entries array.`);
    }

    const store = new SessionStore();
    store.entries = parsed.entries;
    return store;
  }

  size() { return this.entries.length; }
}

module.exports = { SessionStore, extractToken, extractResourceIds, fingerprintToken };
