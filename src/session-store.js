'use strict';

const crypto = require('crypto');
const fs     = require('fs');

const ID_PATTERNS = [
  { type: 'uuid',    re: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi },
  { type: 'integer', re: /(?<![.\d])(\d{1,20})(?![.\d])/g },
];

function fingerprintToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

// Returns { raw, type, cookieName } or null.
// type is 'bearer' or 'cookie' — used by replay to send the
// second token in the correct format.
function extractToken(headers) {
  const auth = headers['authorization'] || '';
  if (auth.toLowerCase().startsWith('bearer ')) {
    return { raw: auth.slice(7).trim(), type: 'bearer', cookieName: null };
  }

  const cookie = headers['cookie'] || '';
  const sessionMatch = cookie.match(/(?:session|token|auth|jwt|sid)=([^;]+)/i);
  if (sessionMatch) {
    const cookieName = cookie.match(/([a-z_][a-z0-9_-]*)=/i)?.[1] || 'session';
    return { raw: sessionMatch[1].trim(), type: 'cookie', cookieName };
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
    this.entries = [];
  }

  record({ method, url, headers, statusCode, contentLength, contentHash }) {
    const tokenInfo = extractToken(headers);
    if (!tokenInfo) return;

    const parsed      = new URL(url, 'http://localhost');
    const resourceIds = extractResourceIds(parsed.pathname + parsed.search);

    this.entries.push({
      method:        method.toUpperCase(),
      path:          parsed.pathname,
      query:         parsed.search,
      tokenHash:     fingerprintToken(tokenInfo.raw),
      tokenType:     tokenInfo.type,
      cookieName:    tokenInfo.cookieName,
      resourceIds,
      statusCode,
      contentLength: contentLength || 0,
      contentHash:   contentHash   || null,
      recordedAt:    Date.now(),
    });
  }

  // Only GET/HEAD requests with resource IDs are candidates for replay
  replayable() {
    return this.entries.filter(e =>
      e.resourceIds.length > 0 &&
      ['GET', 'HEAD'].includes(e.method)
    );
  }

  knownTokens() {
    return [...new Set(this.entries.map(e => e.tokenHash))];
  }

  saveTo(filePath) {
    fs.writeFileSync(filePath, JSON.stringify({
      version:     '0.9.0',
      generatedAt: new Date().toISOString(),
      totalCount:  this.entries.length,
      entries:     this.entries,
    }, null, 2), 'utf8');
  }

  static loadFrom(filePath) {
    const raw   = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const store = new SessionStore();
    store.entries = raw.entries;
    return store;
  }

  size() { return this.entries.length; }
}

module.exports = { SessionStore, extractToken, extractResourceIds, fingerprintToken };
