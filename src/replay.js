'use strict';

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');
const { URL } = require('url');

// ── Semantic comparison ───────────────────────────────────────────────────────
//
// Two responses are considered identical when their normalised JSON hashes
// match — not when their byte sizes are similar.
//
// sortKeys ensures {b:1,a:2} and {a:2,b:1} produce the same hash.
// The body itself is never stored — only the fingerprint.
// ─────────────────────────────────────────────────────────────────────────────

function sortKeys(val) {
  if (Array.isArray(val))             return val.map(sortKeys);
  if (val && typeof val === 'object') return Object.fromEntries(
    Object.keys(val).sort().map(k => [k, sortKeys(val[k])])
  );
  return val;
}

function contentHash(body, contentType) {
  if (!body || body.length === 0) return 'empty';

  if (contentType && contentType.includes('application/json')) {
    try {
      const parsed     = JSON.parse(body.toString('utf8'));
      const normalized = JSON.stringify(sortKeys(parsed));
      return 'json:' + crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
    } catch { /* fall through */ }
  }

  return 'raw:' + crypto.createHash('sha256').update(body).digest('hex').slice(0, 16);
}

// ── Auth headers ──────────────────────────────────────────────────────────────
// Replay using the same delivery mechanism that was recorded —
// bearer header or session cookie.

function authHeaders(secondToken, entry) {
  if ((entry.tokenType || 'bearer') === 'cookie') {
    return { 'cookie': `${entry.cookieName || 'session'}=${secondToken}` };
  }
  return { 'authorization': `Bearer ${secondToken}` };
}

// ── Confidence assessment ─────────────────────────────────────────────────────

function assessFinding(original, replay) {
  if (replay.statusCode < 200  || replay.statusCode >= 300) return 'none';
  if (original.statusCode < 200 || original.statusCode >= 300) return 'none';
  if (!replay.body || replay.body.length < 10) return 'none';

  // Semantic hash match — highest confidence
  if (original.contentHash && replay.contentHash &&
      original.contentHash !== 'empty' &&
      original.contentHash === replay.contentHash) {
    return 'confirmed';
  }

  // Size proximity fallback — only when no hashes available at all
  const originalHasHash = original.contentHash && original.contentHash !== 'empty';
  const replayHasHash   = replay.contentHash   && replay.contentHash   !== 'empty';
  if (!originalHasHash && !replayHasHash) {
    if (original.contentLength > 20 && replay.body.length > 0) {
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
        'accept':     'application/json',
        'user-agent': 'accguard/0.9',
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
          statusCode:  res.statusCode,
          body,
          bodyLength:  body.length,
          contentHash: contentHash(body, contentType),
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

  if (!secondToken) {
    log.log('[accguard] ACCGUARD_TOKEN_B not set — skipping replay.');
    return findings;
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
    if (confidence === 'none') continue;

    const authFlag = (entry.tokenType || 'bearer') === 'cookie'
      ? `-b "${entry.cookieName || 'session'}=$TOKEN_B"`
      : `-H "Authorization: Bearer $TOKEN_B"`;

    findings.push({
      severity:       'high',
      type:           'broken-access-control',
      confidence,
      method:         entry.method,
      path:           entry.path + entry.query,
      resourceIds:    entry.resourceIds,
      tokenType:      entry.tokenType || 'bearer',
      originalStatus: entry.statusCode,
      replayStatus:   result.statusCode,
      originalSize:   entry.contentLength,
      replaySize:     result.bodyLength,
      matchType:      result.contentHash === entry.contentHash ? 'semantic-hash' : 'size-proximity',
      curl:           `curl -s ${authFlag} "${targetUrl}${entry.path}${entry.query}"`,
    });
  }

  return findings;
}

module.exports = { runReplay, assessFinding, contentHash, sortKeys };
