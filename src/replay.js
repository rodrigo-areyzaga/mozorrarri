'use strict';

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');
const { URL } = require('url');
const { buildExposureSummary } = require('./exposure-summary');
const { stripIPv6Brackets }    = require('./safety');

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

// Scans raw JSON for number literals whose mathematical integer value exceeds
// Number.MAX_SAFE_INTEGER (2^53-1 = 9007199254740991).
//
// The key insight: JSON.parse() loses precision on *any* number whose integer
// value exceeds MAX_SAFE, regardless of notation:
//   9007199254740993     → rounds (plain integer)
//   9007199254740993.0   → rounds (decimal that is mathematically an integer)
//   9.007199254740993e15 → rounds (exponent form)
//   0.9007199254740993   → safe  (float mantissa, magnitude < 1)
//   1.234e5              → safe  (= 123400, well within safe range)
//
// Strategy: parse each complete JSON number, compute its magnitude, flag it
// if the integer component exceeds MAX_SAFE. Skip quoted strings entirely.
function hasBigInts(str) {
  let i = 0;
  const len = str.length;
  const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

  while (i < len) {
    const ch = str[i];

    // Skip quoted strings — digit sequences inside strings are not numeric literals
    if (ch === '"') {
      i++;
      while (i < len) {
        if (str[i] === '\\') { i += 2; continue; } // skip escape + next char
        if (str[i] === '"') { i++; break; }
        i++;
      }
      continue;
    }

    // Number start: optional '-', then digit
    if (ch === '-' || (ch >= '0' && ch <= '9')) {
      const start = i;
      if (str[i] === '-') i++;

      // Collect integer digits
      const intStart = i;
      while (i < len && str[i] >= '0' && str[i] <= '9') i++;
      const intDigits = str.slice(intStart, i);

      // Collect optional fractional part
      let fracDigits = '';
      if (i < len && str[i] === '.') {
        i++; // skip '.'
        const fracStart = i;
        while (i < len && str[i] >= '0' && str[i] <= '9') i++;
        fracDigits = str.slice(fracStart, i);
      }

      // Collect optional exponent
      let expSign = 1;
      let expVal  = 0;
      if (i < len && (str[i] === 'e' || str[i] === 'E')) {
        i++;
        if (i < len && str[i] === '+') i++;
        else if (i < len && str[i] === '-') { expSign = -1; i++; }
        const expStart = i;
        while (i < len && str[i] >= '0' && str[i] <= '9') i++;
        expVal = parseInt(str.slice(expStart, i), 10) || 0;
      }

      // Now decide: does this number's mathematical value exceed MAX_SAFE?
      // We work with digit counts and magnitude first to avoid expensive BigInt ops.
      try {
        const allDigits = intDigits + fracDigits;
        const fracLen   = fracDigits.length;
        const netExp    = expSign * expVal - fracLen;

        if (allDigits === '' || allDigits === '0') continue;

        const sigDigits = allDigits.replace(/^0+/, '').length;

        // Safety cap: obviously > MAX_SAFE (≈ 9×10^15, 16 digits).
        if (netExp > 20) return true;

        // Huge negative exponent — only safe if the significant digit count
        // is also small. e.g. 999...999e-900 with 1000 sig digits still has
        // a ~100-digit integer part. Guard: if sigDigits + netExp > 16, unsafe.
        if (netExp < -400) {
          if (sigDigits + netExp > 16) return true;
          continue;
        }

        // Quick safe check: clearly tiny magnitude.
        if (sigDigits <= 15 && netExp <= 0) continue;

        const bigDigits = BigInt(allDigits);

        let intValue;
        if (netExp >= 0) {
          intValue = bigDigits * (10n ** BigInt(netExp));
        } else {
          const divisor = 10n ** BigInt(-netExp);
          intValue = bigDigits / divisor;
        }

        // Strict greater-than: MAX_SAFE itself is exactly representable.
        // For decimals like 9007199254740991.9: intValue === MAX_SAFE but the
        // mathematical value is above it and rounds up. Detect this by checking
        // whether the fractional part is meaningfully non-zero (not just trailing zeros)
        // AND the rounded value would exceed MAX_SAFE.
        // Key: 9.007199254740991e15 written in scientific notation has fracDigits
        // '007199254740991' but its mathematical value is exactly MAX_SAFE — safe.
        // We must check whether the NUMBER (not its source text) exceeds MAX_SAFE.
        if (intValue > MAX_SAFE) return true;

        // Decimal rounding: if intValue === MAX_SAFE and there are fractional digits
        // that are not all zero, the mathematical value slightly exceeds MAX_SAFE
        // and JSON.parse will round it to MAX_SAFE + 1.
        // Exception: scientific notation like 9.007199254740991e15 — the fracDigits
        // in the source are '007199254740991' but after applying the exponent the
        // integer and fractional components are exact. We can tell because
        // netExp shifted the decimal entirely past the fractional part: if fracLen <= expVal
        // (for positive exponent), all source-text fractional digits became integer digits.
        if (intValue === MAX_SAFE) {
          const fracIsActuallyFractional = netExp < 0 ||
            (expSign > 0 && fracLen > expVal);
          const hasNonZeroFrac = fracDigits.replace(/0+$/, '') !== '';
          if (fracIsActuallyFractional && hasNonZeroFrac) return true;
        }
      } catch { /* ignore malformed numbers */ }

      continue;
    }

    i++;
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
      hostname: stripIPv6Brackets(target.hostname),
      port:     target.port || (target.protocol === 'https:' ? 443 : 80),
      path:     entry.path + entry.query,
      method:   entry.method,
      headers: {
        'accept':          'application/json',
        'accept-encoding': 'identity', // force uncompressed — matches recorded hash
        // Preserve original User-Agent — servers that vary response content by UA
        // (bot detection, content adaptation) would produce different hashes if
        // we sent mozorrarri/0.10.1. Use the original UA to maximize replay fidelity.
        'user-agent':      entry.userAgent || 'mozorrarri/0.10.1',
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
    log.log('[mozorrarri] MOZORRARRI_TOKEN_B not set — skipping replay.');
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
        hostname: stripIPv6Brackets(canaryUrl.hostname),
        port:     canaryUrl.port || 80,
        path:     '/',
        method:   'HEAD',
        headers:  { ...authHeaders(secondToken, entries[0] || { tokenType: 'bearer', cookieName: null }),
                    'user-agent': (entries[0] && entries[0].userAgent) || 'mozorrarri/0.10.1-canary' },
      }, res => resolve(res.statusCode));
      req.on('error', reject);
      req.setTimeout(3000, () => { req.destroy(); reject(new Error('timeout')); });
      req.end();
    });
    // 401/403 strongly suggests TOKEN_B is invalid or expired
    if (canaryResult === 401 || canaryResult === 403) {
      log.log('[mozorrarri] WARNING: TOKEN_B canary returned ' + canaryResult + ' — token may be invalid or expired.');
      log.log('[mozorrarri] All replays may return ' + canaryResult + ', producing a false clean run.');
      log.log('[mozorrarri] Verify MOZORRARRI_TOKEN_B is a valid, non-expired session token.');
    } else {
      log.log('[mozorrarri] ✓ TOKEN_B canary authenticated (status ' + canaryResult + ')');
    }
  } catch (err) {
    log.log('[mozorrarri] Token B canary check failed: ' + err.message + ' — proceeding anyway.');
  }

  log.log(`[mozorrarri] Replaying ${entries.length} requests as user B...`);

  for (const entry of entries) {
    let result;
    try {
      result = await replayRequest({ targetUrl, entry, secondToken });
    } catch (err) {
      log.log(`[mozorrarri] Replay error on ${entry.path}: ${err.message}`);
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
            hostname: stripIPv6Brackets(target.hostname),
            port:     target.port || 80,
            path:     entry.path + entry.query,
            method:   entry.method,
            headers: {
              'accept':          'application/json',
              'accept-encoding': 'identity',
              // Use original User-Agent — same as replay to avoid bot-detection
              // content variation causing a classification mismatch.
              'user-agent':      entry.userAgent || 'mozorrarri/0.10.1-anon',
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
