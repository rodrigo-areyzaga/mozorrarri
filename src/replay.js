'use strict';

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');
const { URL } = require('url');
const { buildExposureSummary } = require('./exposure-summary');

// Shell-safe quoting for curl reproduction commands.
// Wraps a value in single quotes, escaping any embedded single quotes.
// This prevents shell injection when URLs or headers contain backticks,
// $(...), or other shell metacharacters.
// Example: "foo'bar" → "'foo'\''bar'"
function shellQuote(s) {
  return "'" + String(s).replace(/'/g, "'\''") + "'";
}

// ── Semantic comparison ───────────────────────────────────────────────────────
//
// Two responses are considered identical when their normalised JSON hashes
// match — not when their byte sizes are similar.
//
// sortKeys ensures {b:1,a:2} and {a:2,b:1} produce the same hash.
// The body itself is never stored — only the fingerprint.
// ─────────────────────────────────────────────────────────────────────────────

// Identity fields that make an array element a stable, addressable record.
// Arrays of objects containing any of these fields are hashed order-insensitively —
// a reordered collection of the same records is still the same exposed data for
// BOLA purposes. Arrays of primitives and anonymous objects stay order-sensitive.
const IDENTITY_FIELDS = new Set(['id','uuid','_id','orderId','userId','accountId','transactionId']);

function hasIdentityField(obj) {
  return obj && typeof obj === 'object' && !Array.isArray(obj) &&
    Object.keys(obj).some(k => IDENTITY_FIELDS.has(k));
}

function sortKeys(val) {
  if (Array.isArray(val)) {
    const mapped = val.map(sortKeys);
    // Order-insensitive for arrays of objects with identity fields:
    // sort elements by their canonical JSON representation so that
    // [record1, record2] and [record2, record1] produce the same hash.
    if (mapped.length > 0 && mapped.every(el => hasIdentityField(el))) {
      return mapped.slice().sort((a, b) =>
        JSON.stringify(a) < JSON.stringify(b) ? -1 : 1
      );
    }
    // Arrays of primitives or anonymous objects — order-sensitive.
    return mapped;
  }
  if (val && typeof val === 'object') return Object.fromEntries(
    Object.keys(val).sort().map(k => [k, sortKeys(val[k])])
  );
  // Normalize strings to NFC — NFC and NFD are the same string in different
  // byte representations. macOS filesystems emit NFD; most servers emit NFC.
  if (typeof val === 'string') return val.normalize('NFC');
  return val;
}

// Detect integer literals in JSON that exceed Number.MAX_SAFE_INTEGER.
// JSON.parse silently rounds these — distinct IDs collide into one hash.
// We scan the raw string before parsing; if found, fall back to raw-byte hash
// so precision is preserved at the byte level.
const BIG_INT_RE = /(?<!["\w])([0-9]{16,})(?![\w"])/g;

function hasBigInts(str) {
  BIG_INT_RE.lastIndex = 0;
  let m;
  while ((m = BIG_INT_RE.exec(str)) !== null) {
    if (m[1].length > 16) return true; // 17+ digits always exceed MAX_SAFE
    if (BigInt(m[1]) > BigInt(Number.MAX_SAFE_INTEGER)) return true;
  }
  return false;
}

function contentHash(body, contentType) {
  if (!body || body.length === 0) return 'empty';

  // Match all JSON content-type variants: application/json, application/vnd.api+json,
  // application/json;charset=utf-8, etc.
  if (contentType && /json/i.test(contentType)) {
    const str = body.toString('utf8');

    // Big-int guard: raw integer literals beyond MAX_SAFE_INTEGER lose precision
    // through JSON.parse. Fall back to raw-byte hash to keep distinct IDs distinct.
    if (hasBigInts(str)) {
      return 'raw:' + crypto.createHash('sha256').update(body).digest('hex');
    }

    try {
      const parsed     = JSON.parse(str);
      const normalized = JSON.stringify(sortKeys(parsed));
      return 'json:' + crypto.createHash('sha256').update(normalized).digest('hex');
    } catch { /* fall through */ }
  }

  return 'raw:' + crypto.createHash('sha256').update(body).digest('hex');
}

// ── Auth headers ──────────────────────────────────────────────────────────────
// Replay using the same delivery mechanism that was recorded —
// bearer header or session cookie.

function authHeaders(secondToken, entry) {
  const type = entry.tokenType || 'bearer';
  if (type === 'cookie') {
    return { 'cookie': `${entry.cookieName || 'session'}=${secondToken}` };
  }
  if (type === 'api-key') {
    return { [entry.apiKeyHeader || 'x-api-key']: secondToken };
  }
  if (type === 'other-auth') {
    // Preserve the original scheme prefix (Basic, Digest, Token, ApiKey...)
    // and substitute the token value after the first space.
    // If TOKEN_B looks like a full scheme+value (e.g. "Basic dXNlcjpwYXNz"),
    // use it directly. Otherwise prepend the original scheme prefix.
    const origScheme = entry.originalAuthScheme || '';
    if (secondToken.includes(' ')) {
      return { 'authorization': secondToken }; // TOKEN_B is scheme+value
    }
    return { 'authorization': origScheme ? `${origScheme} ${secondToken}` : secondToken };
  }
  return { 'authorization': `Bearer ${secondToken}` };
}

// ── Confidence assessment ─────────────────────────────────────────────────────

// Returns true if a parsed JSON value carries no per-user identity data.
// Trivial payloads — empty arrays, empty objects, null, booleans, bare numbers —
// can hash-match legitimately when two users both have nothing to see.
// Confirmed as a real false positive class by adversarial harness.
function isTrivialPayload(body, contentType) {
  if (!body || body.length === 0) return true;
  if (!/json/i.test(contentType || '')) return false;
  try {
    const parsed = JSON.parse(body.toString('utf8'));
    if (parsed === null)                                       return true;
    if (typeof parsed === 'boolean' || typeof parsed === 'number') return true;
    if (Array.isArray(parsed) && parsed.length === 0)          return true;
    if (typeof parsed === 'object' && Object.keys(parsed).length === 0) return true;
  } catch { /* not JSON — not trivial */ }
  return false;
}

function assessFinding(original, replay) {
  if (replay.statusCode < 200  || replay.statusCode >= 300) return 'none';
  if (original.statusCode < 200 || original.statusCode >= 300) return 'none';

  // Semantic hash match — highest confidence.
  if (original.contentHash && replay.contentHash &&
      original.contentHash !== 'empty' &&
      original.contentHash === replay.contentHash) {

    // Downgrade trivial payloads — [] {} null etc. carry no per-user data.
    // A hash match on a trivial payload is not evidence of unauthorized exposure.
    // Downgraded to 'needs-review' rather than suppressed — still visible, not confirmed.
    if (isTrivialPayload(replay.body, replay.contentType)) return 'needs-review';

    return 'confirmed';
  }

  // Hash family consistency check — catches the case where the recording and
  // replay end up in different hash families (json: vs raw:) due to the big-int
  // safety fallback or content-type mismatch, even though the underlying bytes
  // are identical.
  //
  // Example: original response has no big-ints → hashed as json:
  //          server adds a big-int trace ID to replay response → hashed as raw:
  //          The two hashes are in different families and can never match, even
  //          if the rest of the payload is identical.
  //
  // The store records rawHash (raw-byte SHA-256) alongside contentHash.
  // If families differ, compare rawHash values — exact byte comparison only.
  // No normalization in this fallback — preserves the soundness guarantee.
  if (original.contentHash && replay.contentHash &&
      original.contentHash !== 'empty' && replay.contentHash !== 'empty') {
    const origFamily   = original.contentHash.split(':')[0];
    const replayFamily = replay.contentHash.split(':')[0];
    if (origFamily !== replayFamily) {
      // Compare raw-byte hashes — both must be available
      const origRaw   = original.rawHash;
      const replayRaw = replay.rawHash ||
        (replay.body ? 'raw:' + crypto.createHash('sha256').update(replay.body).digest('hex') : null);
      if (origRaw && replayRaw && origRaw === replayRaw) {
        if (isTrivialPayload(replay.body, replay.contentType)) return 'needs-review';
        return 'confirmed';
      }
    }
  }

  // Size proximity fallback — only when no hashes are available at all.
  const originalHasHash = original.contentHash && original.contentHash !== 'empty';
  const replayHasHash   = replay.contentHash   && replay.contentHash   !== 'empty';
  if (!originalHasHash && !replayHasHash) {
    if (replay.body && replay.body.length >= 10 &&
        original.contentLength > 20) {
      const ratio = replay.body.length / original.contentLength;
      if (ratio > 0.95 && ratio < 1.05) return 'possible';
    }
  }

  return 'none';
}

// ── Replay one request ────────────────────────────────────────────────────────

function replayRequest({ targetUrl, entry, secondToken }) {
  return new Promise((resolve, reject) => {
    const target  = new URL(targetUrl);
    const options = {
      hostname: target.hostname,
      port:     target.port || (target.protocol === 'https:' ? 443 : 80),
      path:     entry.path + entry.query,
      method:   entry.method,
      headers: {
        'accept':          'application/json',
        'accept-encoding': 'identity', // force uncompressed — matches recorded hash
        // Preserve original User-Agent — servers that vary response content by UA
        // (bot detection, content adaptation) would produce different hashes if
        // we sent accguard/0.10.1. Use the original UA to maximize replay fidelity.
        'user-agent':      entry.userAgent || 'accguard/0.10.1',
        ...authHeaders(secondToken, entry),
      },
    };

    const transport = target.protocol === 'https:' ? https : http;
    const req = transport.request(options, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const body        = Buffer.concat(chunks);
        const contentType = res.headers['content-type'] || '';
        resolve({
          statusCode:   res.statusCode,
          body,
          bodyLength:   body.length,
          contentType,
          contentHash:  contentHash(body, contentType),
          rawHash:      'raw:' + crypto.createHash('sha256').update(body).digest('hex'),
        });
      });
    });

    req.on('error', reject);
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

// ── Main replay pass ──────────────────────────────────────────────────────────

async function runReplay({ store, targetUrl, secondToken, logger }) {
  const log      = logger || console;
  const entries  = store.replayable();
  const findings = [];

  // Run timestamp for finding IDs — ISO compact format for human readability.
  // All findings in this run share the same timestamp prefix.
  const runTimestamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  let findingSeq = 0;

  if (!secondToken) {
    log.log('[accguard] ACCGUARD_TOKEN_B not set — skipping replay.');
    return findings;
  }

  // Token B liveness canary — verify the second token can authenticate
  // before running the full replay. An expired or invalid TOKEN_B causes every
  // replay to 401, producing a false clean run with zero findings.
  try {
    const canaryUrl = new URL(targetUrl);
    const canaryResult = await new Promise((resolve, reject) => {
      const transport = canaryUrl.protocol === 'https:' ? require('https') : require('http');
      const req = transport.request({
        hostname: canaryUrl.hostname,
        port:     canaryUrl.port || 80,
        path:     '/',
        method:   'HEAD',
        headers:  { ...authHeaders(secondToken, entries[0] || { tokenType: 'bearer', cookieName: null }),
                    'user-agent': (entries[0] && entries[0].userAgent) || 'accguard/0.10.1-canary' },
      }, res => resolve(res.statusCode));
      req.on('error', reject);
      req.setTimeout(3000, () => { req.destroy(); reject(new Error('timeout')); });
      req.end();
    });
    // 401/403 strongly suggests TOKEN_B is invalid or expired
    if (canaryResult === 401 || canaryResult === 403) {
      log.log('[accguard] WARNING: TOKEN_B canary returned ' + canaryResult + ' — token may be invalid or expired.');
      log.log('[accguard] All replays may return ' + canaryResult + ', producing a false clean run.');
      log.log('[accguard] Verify ACCGUARD_TOKEN_B is a valid, non-expired session token.');
    } else {
      log.log('[accguard] ✓ TOKEN_B canary authenticated (status ' + canaryResult + ')');
    }
  } catch (err) {
    log.log('[accguard] Token B canary check failed: ' + err.message + ' — proceeding anyway.');
  }

  log.log(`[accguard] Replaying ${entries.length} requests as user B...`);

  for (const entry of entries) {
    let result;
    try {
      result = await replayRequest({ targetUrl, entry, secondToken });
    } catch (err) {
      log.log(`[accguard] Replay error on ${entry.path}: ${err.message}`);
      continue;
    }

    const confidence = assessFinding(entry, result);

    // Generate the correct curl reproduction command for each auth type.
    // Non-variable parts (cookie name, scheme prefix, header name) are shellQuoted
    // so the output is safe by construction even if they contain metacharacters.
    // TOKEN_B is kept as a shell variable reference — operator substitutes at runtime.
    const tokenType = entry.tokenType || 'bearer';
    let authFlag;
    if (tokenType === 'cookie') {
      // -b 'cookieName=$TOKEN_B' — single-quoted name, variable expands outside
      authFlag = `-b ${shellQuote((entry.cookieName || 'session') + '=')}$TOKEN_B`;
    } else if (tokenType === 'api-key') {
      const hdr = entry.apiKeyHeader || 'x-api-key';
      authFlag = `-H ${shellQuote(hdr + ': ')}$TOKEN_B`;
    } else if (tokenType === 'other-auth') {
      const scheme = entry.originalAuthScheme || '';
      if (scheme && scheme.includes(' ')) {
        // Scheme-less Authorization (no space in value) — entire value was treated as
        // scheme during extraction. Replay with raw value as-is; TOKEN_B replaces it.
        authFlag = `-H ${shellQuote('Authorization: ')}$TOKEN_B`;
      } else {
        // Normal scheme+value form — prefix with scheme, TOKEN_B is the credential value.
        const prefix = scheme ? scheme + ' ' : '';
        authFlag = `-H ${shellQuote('Authorization: ' + prefix)}$TOKEN_B`;
      }
    } else {
      authFlag = `-H 'Authorization: Bearer '$TOKEN_B`;
    }

    if (confidence === 'none') continue;

    // Unauthenticated reclassifier — NOT a suppressor.
    // If an anonymous request returns the same hash as the authenticated responses,
    // the finding is reclassified as possible-missing-authentication rather than BOLA.
    // This preserves total auth bypass (X2) at higher visibility — not silently dropped.
    // Adversarial harness confirmed suppression would destroy the most severe finding class.
    let finalConfidence = confidence;
    let findingType     = 'broken-access-control';
    if (confidence === 'confirmed') {
      try {
        // True anonymous request — no auth header at all.
        // replayRequest with secondToken='' still sends Authorization: Bearer  or Cookie: session=
        // which is a malformed auth request, not unauthenticated. Build the request directly.
        const anonResult = await new Promise((resolve, reject) => {
          const target = new URL(targetUrl);
          const transport = target.protocol === 'https:' ? require('https') : require('http');
          const req = transport.request({
            hostname: target.hostname,
            port:     target.port || 80,
            path:     entry.path + entry.query,
            method:   entry.method,
            headers: {
              'accept':          'application/json',
              'accept-encoding': 'identity',
              // Use original User-Agent — same as replay to avoid bot-detection
              // content variation causing a classification mismatch.
              'user-agent':      entry.userAgent || 'accguard/0.10.1-anon',
              // No Authorization or Cookie header — truly unauthenticated
            },
          }, res => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
              const body    = Buffer.concat(chunks);
              const cType = res.headers['content-type'] || '';
              resolve({
                statusCode:  res.statusCode,
                body,
                contentHash: contentHash(body, cType),
                rawHash:     'raw:' + crypto.createHash('sha256').update(body).digest('hex'),
              });
            });
          });
          req.on('error', reject);
          req.setTimeout(3000, () => { req.destroy(); reject(new Error('timeout')); });
          req.end();
        });
        // Check for match — direct hash comparison first, then cross-family rawHash fallback.
        // The anon response may arrive with a different content-type than the replay
        // (e.g., text/plain to unauthenticated, application/json to authenticated),
        // which puts them in different hash families (raw: vs json:).
        // Mirror the same cross-family logic used in assessFinding.
        const hashesMatch = (
          anonResult.contentHash &&
          anonResult.contentHash !== 'empty' &&
          anonResult.contentHash === result.contentHash
        ) || (
          // Cross-family fallback — compare raw bytes when families differ
          anonResult.rawHash && result.rawHash &&
          anonResult.rawHash === result.rawHash &&
          anonResult.contentHash.split(':')[0] !== result.contentHash.split(':')[0]
        );

        if (hashesMatch) {
          // Anonymous got the same data — could be public OR total auth bypass.
          // Reclassify rather than suppress — operator must verify.
          finalConfidence = 'confirmed';
          findingType     = 'possible-missing-authentication';
        }
      } catch { /* canary failed — keep original classification */ }
    }

    // needs-review findings are a separate type, not BOLA
    const actualType = confidence === 'needs-review' ? 'needs-review' : findingType;
    const actualSeverity = actualType === 'possible-missing-authentication' ? 'critical'
                         : actualType === 'needs-review'                    ? 'info'
                         : 'high';

    // Determine match type and the evidence hash from a SINGLE source of truth
    // so they can never drift apart. semanticMatch requires both content hashes
    // to exist and be equal (undefined === undefined must NOT count as a match).
    const semanticMatch = !!(result.contentHash && entry.contentHash &&
                             result.contentHash === entry.contentHash);
    const rawMatch      = !!(entry.rawHash && result.rawHash &&
                             entry.rawHash === result.rawHash);

    const matchType = semanticMatch ? 'semantic-hash'
                    : rawMatch       ? 'raw-hash-fallback'
                    : 'size-proximity';

    // Evidence hash — the hash that actually proved the match.
    // Derived from the same booleans as matchType: the invariant
    // exposureSummary.summaryGeneratedFromHash === evidence.matchedHash holds
    // by construction because both read this one value.
    const evidenceHash = semanticMatch ? result.contentHash
                       : rawMatch       ? result.rawHash
                       : result.contentHash;

    // Exposure Summary — derived metadata for confirmed BOLA findings only.
    // Does not affect detection. Does not store raw values or bodies.
    // Runs only when: actualType === 'broken-access-control' AND finalConfidence === 'confirmed'
    const exposureSummary =
      actualType === 'broken-access-control' && finalConfidence === 'confirmed'
        ? buildExposureSummary(result.body, result.contentType, evidenceHash)
        : null;

    // Finding ID — stable reference for reports.
    // Format: AG-<runTimestamp>-<3-digit sequence>
    findingSeq++;
    const findingId = `AG-${runTimestamp}-${String(findingSeq).padStart(3, '0')}`;

    const finding = {
      findingId,
      severity:       actualSeverity,
      type:           actualType,
      confidence:     confidence === 'needs-review' ? 'needs-review' : finalConfidence,
      method:         entry.method,
      path:           entry.path + entry.query,
      resourceIds:    entry.resourceIds,
      tokenType:      entry.tokenType || 'bearer',
      originalStatus: entry.statusCode,
      replayStatus:   result.statusCode,
      originalSize:   entry.contentLength,
      replaySize:     result.bodyLength,
      matchType,
      evidence: {
        originalContentHash: entry.contentHash || null,
        replayContentHash:   result.contentHash || null,
        originalRawHash:     entry.rawHash || null,
        replayRawHash:       result.rawHash || null,
        matchedHash:         evidenceHash,
        matchType,
      },
      request: {
        method:            entry.method,
        path:              entry.path + entry.query,
        queryPresent:      entry.query !== '',
        authMechanism:     entry.tokenType || 'bearer',
        userAgentPreserved: !!(entry.userAgent),
      },
      recordedAt:     entry.recordedAt,
      replayedAt:     new Date().toISOString(),
      curl:           `curl -s ${authFlag} ${shellQuote(targetUrl + entry.path + entry.query)}`,
    };

    // Attach exposure summary only if non-null (confirmed BOLA with JSON body)
    if (exposureSummary) {
      finding.exposureSummary = exposureSummary;
    }

    findings.push(finding);
  }

  return findings;
}

module.exports = { runReplay, assessFinding, contentHash, sortKeys };
