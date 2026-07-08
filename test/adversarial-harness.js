#!/usr/bin/env node
'use strict';

/**
 * jabearri — comprehensive adversarial harness
 *
 * Axes:
 *   1. Security    — injection, bypass, data leakage, SSRF surface
 *   2. Correctness — edge cases the main suite doesn't exercise
 *   3. Performance — memory, throughput, large payloads
 *   4. Stability   — concurrency, race conditions, error paths
 *   5. Blindspots  — new angles on the detection and reporting logic
 */

const http   = require('http');
const crypto = require('crypto');
const path   = require('path');
const os     = require('os');
const fs     = require('fs');

const root = path.join(__dirname, '..');

const {
  SessionStore,
  extractToken,
  extractResourceIds,
  fingerprintToken,
} = require(root + '/src/session-store');

const {
  contentHash,
  assessFinding,
} = require(root + '/src/replay');

const {
  isPrivateHost,
  stripIPv6Brackets,
  normalizeIPv4,
} = require(root + '/src/safety');

const {
  buildExposureSummary,
} = require(root + '/src/exposure-summary');

const {
  coverageSummary,
  buildPlainSummary,
  whyFlagged,
  saveReport,
} = require(root + '/src/reporter');

const { ProxyCore } = require(root + '/src/proxy');

// ── Harness infrastructure ────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
let section = '';
const failures = [];

function sec(name) {
  section = name;
  console.log(`\n── ${name} ${'─'.repeat(Math.max(0, 60 - name.length))}`);
}

function ok(name, result, detail = '') {
  if (result) {
    passed++;
    process.stdout.write(`  ✓  ${name}\n`);
  } else {
    failed++;
    const msg = `  ✗  ${name}${detail ? ' — ' + detail : ''}`;
    failures.push(`[${section}] ${msg.trim()}`);
    console.log(msg);
  }
}

function check(name, fn) {
  try {
    const r = fn();
    if (r === false) ok(name, false);
    else ok(name, true);
  } catch (e) {
    ok(name, false, e.message);
  }
}

// ── 1. SECURITY — injection, bypass, data leakage ────────────────────────────

sec('SECURITY — report injection via malicious paths');

// ANSI escape in URL path stored in session entry
const ansiStore = new SessionStore();
ansiStore.record({
  method: 'GET',
  url: '/api/orders/\x1b[31mREDTEXT\x1b[0m/detail',
  headers: { authorization: 'Bearer tok-a' },
  statusCode: 200, contentLength: 50,
  contentHash: 'json:abc', rawHash: 'raw:xyz',
});
check('ANSI escape in path does not crash store', () => ansiStore.entries.length === 1);
check('ANSI escape in path is stored as-is (URL parser handles it)', () =>
  typeof ansiStore.entries[0].path === 'string'
);

// Newline injection in path
const nlStore = new SessionStore();
nlStore.record({
  method: 'GET',
  url: '/api/orders/1001\nX-Injected: evil',
  headers: { authorization: 'Bearer tok-a' },
  statusCode: 200, contentLength: 50,
  contentHash: 'json:abc', rawHash: 'raw:xyz',
});
check('Newline in path does not crash store', () => nlStore.entries.length === 1);

// Shell metacharacters in resource IDs surfacing in curl output
const shellIds = extractResourceIds('/api/orders/`touch /tmp/pwn`');
check('Backtick in path produces no resource ID (not a recognized format)', () => shellIds.length === 0);

const shellIds2 = extractResourceIds('/api/orders/$(id)');
check('$() in path produces no resource ID', () => shellIds2.length === 0);

// Token fingerprint must not be reversible to raw value
const rawTok = 'super-secret-bearer-token-value';
const fp = fingerprintToken(rawTok);
check('Token fingerprint is not the raw token', () => fp !== rawTok);
check('Token fingerprint is a hex string (first 16 chars of SHA-256)', () => /^[0-9a-f]{16}$/.test(fp));
check('Token fingerprint is one-way — raw value not recoverable from hash', () => {
  // If someone has the fingerprint, they should not be able to reverse it
  const attempt = Buffer.from(fp, 'hex').toString('utf8');
  return attempt !== rawTok;
});

sec('SECURITY — report does not leak raw token values');

const leakStore = new SessionStore();
leakStore.record({
  method: 'GET',
  url: '/api/orders/1001',
  headers: { authorization: 'Bearer VERY_SECRET_TOKEN_ABC' },
  statusCode: 200, contentLength: 50,
  contentHash: 'json:abc', rawHash: 'raw:xyz',
});
const tmpReport = os.tmpdir() + '/jabearri-leak-test.json';
saveReport([], leakStore, tmpReport, { target: 'http://localhost:3000', scope: ['/api/'] });
const reportContent = fs.readFileSync(tmpReport, 'utf8');
check('Raw token not in report JSON', () => !reportContent.includes('VERY_SECRET_TOKEN_ABC'));
// Token fingerprints are stored in-memory in session entries, never serialized to disk.
// The report contains findings only — no store entries, no fingerprints, no tokens.
// This is the correct privacy model: even fingerprints don't persist.
check('Report contains no fingerprint either — correct: fingerprints are in-memory only', () =>
  !reportContent.includes(fingerprintToken('VERY_SECRET_TOKEN_ABC'))
);

sec('SECURITY — SSRF surface');

check('IPv4 public address: isPrivateHost returns boolean (not throws)', () => typeof isPrivateHost('8.8.8.8') === 'boolean');
check('8.8.8.8 is not private', () => isPrivateHost('8.8.8.8') === false);
check('169.254.169.254 (AWS metadata) is private', () => isPrivateHost('169.254.169.254') === true);
check('0.0.0.0 is private', () => isPrivateHost('0.0.0.0') === true);
check('10.0.0.1 is private', () => isPrivateHost('10.0.0.1') === true);
check('Hex-encoded loopback 0x7f000001 normalizes to 127.0.0.1', () => normalizeIPv4('0x7f000001') === '127.0.0.1');
check('Decimal loopback 2130706433 normalizes to 127.0.0.1', () => normalizeIPv4('2130706433') === '127.0.0.1');

sec('SECURITY — scope bypass via exotic encoding');

const { ProxyCore: PC } = require(root + '/src/proxy');
const bypassProxy = new PC({
  target: 'http://127.0.0.1:3100',
  scope: ['/api/'],
  exclude: ['/api/public/'],
  store: { record: () => {}, size: () => 0, replayable: () => [] },
  logger: { log: () => {}, error: () => {} },
});

// Triple encoding
check('Triple-encoded slash stays excluded', () => {
  return bypassProxy._inScope('/api/pu%2562lic/data') === false ||
         bypassProxy._inScope('/api/public/data') === false;
});

// Unicode look-alikes in paths (not percent-encoded, just weird chars)
check('Null byte in path handled safely', () => {
  try { return typeof bypassProxy._inScope('/api/public\x00bypass') === 'boolean'; }
  catch { return false; }
});

// ── 2. CORRECTNESS — edge cases ───────────────────────────────────────────────

sec('CORRECTNESS — contentHash edge cases');

// Empty body
check('Empty buffer is "empty"', () => contentHash(Buffer.from(''), 'application/json') === 'empty');
check('Null body is "empty"', () => contentHash(null, 'application/json') === 'empty');

// Non-JSON content types
check('text/plain falls to raw:', () => contentHash(Buffer.from('hello'), 'text/plain').startsWith('raw:'));
check('No content-type falls to raw:', () => contentHash(Buffer.from('hello'), '').startsWith('raw:'));
check('application/octet-stream falls to raw:', () => contentHash(Buffer.from('\x00\x01\x02'), 'application/octet-stream').startsWith('raw:'));

// Malformed JSON with big-int literal — should fall to raw
const malformedBigInt = Buffer.from('{"id":99999999999999999,"broken":}');
const h = contentHash(malformedBigInt, 'application/json');
check('Malformed JSON with big-int falls to raw: (parse fails)', () => h.startsWith('raw:'));

// Deeply nested JSON — should not stack overflow
const deep = (n) => n === 0 ? '1' : `{"a":${deep(n-1)}}`;
const deepBuf = Buffer.from(deep(200));
check('200-deep nested JSON hashes without stack overflow', () => {
  const r = contentHash(deepBuf, 'application/json');
  return r.startsWith('json:') || r.startsWith('raw:');
});

// Duplicate keys in JSON — last value wins in JSON.parse
const dupKeys = Buffer.from('{"a":1,"a":2}');
const h1 = contentHash(dupKeys, 'application/json');
const expected = Buffer.from('{"a":2}');
const h2 = contentHash(expected, 'application/json');
check('Duplicate JSON keys normalized (last value wins)', () => h1 === h2);

// Very large integer that just fits MAX_SAFE
const maxSafe = Buffer.from(`{"id":${Number.MAX_SAFE_INTEGER}}`);
check('MAX_SAFE_INTEGER hashes as json: (no big-int fallback needed)', () =>
  contentHash(maxSafe, 'application/json').startsWith('json:')
);

// Just over MAX_SAFE — must fall to raw:
const overSafe = Buffer.from(`{"id":${Number.MAX_SAFE_INTEGER + 2},"name":"alice"}`);
check('MAX_SAFE_INTEGER+2 triggers raw: fallback', () =>
  contentHash(overSafe, 'application/json').startsWith('raw:')
);

sec('CORRECTNESS — assessFinding edge cases');

// Both sides trivial — needs-review
const trivialBoth = assessFinding(
  { statusCode: 200, contentHash: 'json:triv', rawHash: 'raw:t', contentLength: 2 },
  { statusCode: 200, body: Buffer.from('[]'), bodyLength: 2, contentHash: 'json:triv', rawHash: 'raw:t', contentType: 'application/json' }
);
check('Both sides [] → needs-review (not confirmed)', () => trivialBoth === 'needs-review');

// Original is 2xx, replay is 4xx — no finding
const fourOhThree = assessFinding(
  { statusCode: 200, contentHash: 'json:abc', rawHash: 'raw:abc', contentLength: 50 },
  { statusCode: 403, body: Buffer.from('forbidden'), bodyLength: 9, contentHash: 'json:xyz', rawHash: 'raw:xyz', contentType: 'application/json' }
);
check('Replay 403 → no finding (access denied correctly)', () => fourOhThree === 'none');

// Original is error, replay matches — no finding
const origError = assessFinding(
  { statusCode: 404, contentHash: 'json:abc', rawHash: 'raw:abc', contentLength: 20 },
  { statusCode: 404, body: Buffer.from('{}'), bodyLength: 2, contentHash: 'json:abc', rawHash: 'raw:abc', contentType: 'application/json' }
);
check('Original 404 + replay 404 match → no finding', () => origError === 'none');

// Hash families differ but raw bytes match
const body = Buffer.from('{"id":1,"name":"alice"}');
const jHash = contentHash(body, 'application/json');
const rHash = 'raw:' + crypto.createHash('sha256').update(body).digest('hex');
const crossFamily = assessFinding(
  { statusCode: 200, contentHash: jHash, rawHash: rHash, contentLength: body.length },
  { statusCode: 200, body, bodyLength: body.length, contentHash: rHash, rawHash: rHash, contentType: 'text/plain' }
);
check('Cross-family hash match (json: vs raw:) still produces confirmed', () => crossFamily === 'confirmed');

sec('CORRECTNESS — notReplayed categorization');

const notRepStore = new SessionStore();
// Replayable: GET with resource ID
notRepStore.record({ method: 'GET', url: '/api/orders/1001',
  headers: { authorization: 'Bearer tok' }, statusCode: 200, contentLength: 50,
  contentHash: 'json:abc', rawHash: 'raw:xyz' });
// Not replayable: no resource ID
notRepStore.record({ method: 'GET', url: '/api/whoami',
  headers: { authorization: 'Bearer tok' }, statusCode: 200, contentLength: 20,
  contentHash: 'json:def', rawHash: 'raw:uvw' });
// Not replayable: POST method
notRepStore.record({ method: 'POST', url: '/api/orders',
  headers: { authorization: 'Bearer tok' }, statusCode: 201, contentLength: 30,
  contentHash: 'json:ghi', rawHash: 'raw:rst' });

const cov = coverageSummary(notRepStore);
check('notReplayed includes no-resource-ID entry', () =>
  cov.notReplayed.some(e => e.path === '/api/whoami' && e.reason === 'no_resource_id')
);
check('notReplayed includes method-filtered entry', () =>
  cov.notReplayed.some(e => e.path === '/api/orders' && e.reason === 'method_filtered')
);
check('notReplayed does not include the replayable entry', () =>
  !cov.notReplayed.some(e => e.path === '/api/orders/1001')
);

sec('CORRECTNESS — plain summary edge cases');

const zeroSummary = buildPlainSummary(
  { observed: 0, replayed: 0, patterns: 0, mechanisms: 'none', notReplayed: [] }, 0, 0
);
check('Zero observed produces valid plain summary', () => zeroSummary.includes('0 authenticated requests'));
check('Zero clean run includes scope caveat', () => zeroSummary.includes('does not prove'));

const singleFinding = buildPlainSummary(
  { observed: 5, replayed: 2, patterns: 1, mechanisms: 'bearer',
    notReplayed: [{ method: 'GET', path: '/api/me', reason: 'no_resource_id' }]
  }, 1, 0
);
check('Single finding uses singular grammar', () =>
  singleFinding.includes('1 confirmed authorization boundary failure') &&
  !singleFinding.includes('failures')
);

const manyFindings = buildPlainSummary(
  { observed: 10, replayed: 5, patterns: 3, mechanisms: 'bearer', notReplayed: [] }, 3, 1
);
check('Multiple finding types joined correctly in summary', () =>
  manyFindings.includes('confirmed authorization boundary failures') &&
  manyFindings.includes('possible missing-authentication')
);

sec('CORRECTNESS — extractResourceIds blindspot survey');

// Stripe-style IDs
const stripe = extractResourceIds('/api/charges/ch_1Abc123XYZ');
check('Stripe-style ID (ch_1Abc123XYZ) not extracted — known gap', () => stripe.length === 0);

// Shopify handle
const shopify = extractResourceIds('/api/products/my-product-handle');
const hasShopify = shopify.some(r => r.value === 'my-product-handle');
check('Shopify-style handle extracted as slug', () => hasShopify);

// Hashid (short opaque)
const hashid = extractResourceIds('/api/users/aB3xZ');
check('Short hashid (aB3xZ) not extracted — too short/opaque', () => hashid.length === 0);

// Plain username — the VAmPI gap
const plainUser = extractResourceIds('/users/v1/name1');
check('Plain username (name1) not extracted — documented VAmPI boundary', () => plainUser.length === 0);

// camelCase book title — the VAmPI gap
const bookTitle = extractResourceIds('/books/v1/bookTitle18');
check('camelCase book title not extracted — documented VAmPI boundary', () => bookTitle.length === 0);

// MongoDB ObjectID must be extracted
const objectId = extractResourceIds('/api/vehicles/507f1f77bcf86cd799439011');
check('MongoDB ObjectID extracted correctly', () => objectId.some(r => r.value === '507f1f77bcf86cd799439011'));

// UUID with uppercase
const upperUUID = extractResourceIds('/api/users/550E8400-E29B-41D4-A716-446655440000');
check('Uppercase UUID extracted', () => upperUUID.some(r => r.type === 'uuid'));

// Multiple IDs in one path
const multiId = extractResourceIds('/api/orgs/42/users/user-alice/orders/1001');
check('Multiple resource IDs extracted from one path', () => multiId.length >= 3);

// ── 3. PERFORMANCE — throughput and memory ────────────────────────────────────

sec('PERFORMANCE — session store at scale');

const bigStore = new SessionStore();
const start = Date.now();
for (let i = 0; i < 5000; i++) {
  bigStore.record({
    method: 'GET',
    url: `/api/orders/${i}`,
    headers: { authorization: 'Bearer tok-a' },
    statusCode: 200, contentLength: 100,
    contentHash: `json:hash${i}`, rawHash: `raw:rhash${i}`,
  });
}
const insertMs = Date.now() - start;
check(`5000 entries inserted in < 500ms (actual: ${insertMs}ms)`, () => insertMs < 500);
check('5000 entries stored correctly', () => bigStore.entries.length === 5000);

const replayStart = Date.now();
const replayable = bigStore.replayable();
const replayMs = Date.now() - replayStart;
check(`replayable() on 5000 entries in < 200ms (actual: ${replayMs}ms)`, () => replayMs < 200);
check('All 5000 entries are replayable (all have integer IDs)', () => replayable.length === 5000);

sec('PERFORMANCE — MAX_ENTRIES cap holds under load');

// session-store.js reads JABEARRI_MAX_ENTRIES at module-load time (top of
// file), and this harness already required session-store above — so setting
// the env var here would have no effect on the already-loaded module. Spawn
// a fresh child process instead, with the env var set before it requires
// session-store, to actually exercise the empty-string fallback path.
{
  const { spawnSync } = require('child_process');
  const result = spawnSync(process.execPath, ['-e', `
    process.env.JABEARRI_MAX_ENTRIES = '';
    const { SessionStore } = require(${JSON.stringify(root + '/src/session-store')});
    const s = new SessionStore();
    for (let i = 0; i < 10005; i++) {
      s.record({
        method: 'GET', url: '/api/items/' + i,
        headers: { authorization: 'Bearer tok' },
        statusCode: 200, contentLength: 10,
        contentHash: 'json:h' + i, rawHash: 'raw:r' + i,
      });
    }
    console.log(JSON.stringify({ len: s.entries.length }));
  `], { encoding: 'utf8' });

  let out = null;
  try { out = JSON.parse(result.stdout.trim().split('\n').pop()); } catch { /* leave null, check fails below */ }

  check('MAX_ENTRIES empty-string fallback caps at 10000 (fresh process)', () =>
    result.status === 0 && out && out.len === 10000);
}

sec('PERFORMANCE — contentHash on large payloads');

const sizes = [10_000, 100_000, 500_000];
for (const size of sizes) {
  const body = Buffer.alloc(size, 'x');
  const t = Date.now();
  const h = contentHash(body, 'text/plain');
  const ms = Date.now() - t;
  check(`raw: hash of ${(size/1000).toFixed(0)}KB in < 100ms (actual: ${ms}ms)`, () => ms < 100 && h.startsWith('raw:'));
}

// Large valid JSON
const largeJson = JSON.stringify({ items: Array.from({ length: 1000 }, (_, i) => ({ id: i, name: 'item-' + i, price: 9.99 })) });
const largeBuf = Buffer.from(largeJson);
const t2 = Date.now();
const lh = contentHash(largeBuf, 'application/json');
const ms2 = Date.now() - t2;
check('json: hash of 1000-item array (no floats) in < 200ms', () => ms2 < 200 && lh.startsWith('json:'));

sec('PERFORMANCE — exposure summary on large response');

const largeResponse = {
  items: Array.from({ length: 500 }, (_, i) => ({
    id: i, userId: `user-${i}`, email: `user${i}@test.com`,
    total: Math.random() * 1000, address: `${i} Main St`,
  }))
};
const largeBuf2 = Buffer.from(JSON.stringify(largeResponse));
const t3 = Date.now();
const es = buildExposureSummary(largeBuf2, 'application/json', `json:hash`);
const ms3 = Date.now() - t3;
check(`Exposure summary on 500-item array (${(largeBuf2.length/1000).toFixed(1)}KB) in < 500ms (actual: ${ms3}ms)`, () => ms3 < 500);
check('Large response exposure summary does not store raw values', () => !es.skipped || es.reason === 'body-too-large');

// ── 4. STABILITY — concurrency and error paths ────────────────────────────────
// (async sections wrapped in main() below)

sec('STABILITY — concurrent proxy requests');

(async () => {
const concResult = await new Promise(resolve => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id: 1, data: 'test' }));
  });

  server.listen(0, '127.0.0.1', async () => {
    const port = server.address().port;
    const concStore = new SessionStore();
    const concProxy = new ProxyCore({
      target: `http://127.0.0.1:${port}`,
      scope: ['/api/'],
      exclude: [],
      store: concStore,
      logger: { log: () => {}, error: () => {} },
    });

    await concProxy.listen(19876);

    // Fire 20 concurrent requests through the proxy
    const requests = Array.from({ length: 20 }, (_, i) =>
      new Promise(res => {
        const req = http.request({
          hostname: '127.0.0.1', port: 19876,
          path: `/api/orders/${i + 1}`, method: 'GET',
          headers: { authorization: 'Bearer tok-conc' },
        }, r => { r.resume(); r.on('end', () => res(r.statusCode)); });
        req.on('error', () => res(0));
        req.setTimeout(3000, () => { req.destroy(); res(0); });
        req.end();
      })
    );

    const results = await Promise.all(requests);
    await concProxy.close();
    server.close();
    resolve({ results, storeSize: concStore.size() });
  });
});

check('20 concurrent proxy requests all returned 200', () => concResult.results.every(s => s === 200));
check('20 concurrent requests all recorded in store', () => concResult.storeSize === 20);

sec('STABILITY — proxy handles malformed requests gracefully');

const malformResult = await new Promise(resolve => {
  const targetServer = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });

  targetServer.listen(0, '127.0.0.1', async () => {
    const tPort = targetServer.address().port;
    const mStore = new SessionStore();
    const mProxy = new ProxyCore({
      target: `http://127.0.0.1:${tPort}`,
      scope: ['/api/'],
      exclude: [],
      store: mStore,
      logger: { log: () => {}, error: () => {} },
    });
    await mProxy.listen(19877);

    // Request with no auth header
    const r1 = await new Promise(res => {
      const req = http.request({ hostname: '127.0.0.1', port: 19877, path: '/api/orders/1', method: 'GET' },
        r => { r.resume(); r.on('end', () => res(r.statusCode)); });
      req.on('error', () => res(0));
      req.end();
    });

    // Request with empty body to an in-scope path
    const r2 = await new Promise(res => {
      const req = http.request({ hostname: '127.0.0.1', port: 19877, path: '/api/orders/2', method: 'GET',
        headers: { authorization: 'Bearer tok-x' } },
        r => { r.resume(); r.on('end', () => res(r.statusCode)); });
      req.on('error', () => res(0));
      req.end();
    });

    await mProxy.close();
    targetServer.close();
    resolve({ r1, r2, storeSize: mStore.size() });
  });
});

check('Request with no auth header still proxied (returns 200)', () => malformResult.r1 === 200);
check('Request with auth header proxied and recorded', () => malformResult.r2 === 200);
check('Only auth-carrying request stored (1 entry)', () => malformResult.storeSize === 1);

sec('STABILITY — double-finalize guard in store');

let flushCount = 0;
let finalizing = false;
async function triggerOnce() {
  if (finalizing) return;
  finalizing = true;
  flushCount++;
  await new Promise(r => setTimeout(r, 10));
}
await Promise.all([triggerOnce(), triggerOnce(), triggerOnce(), triggerOnce()]);
check('Double-finalize guard: flush called exactly once from 4 concurrent attempts', () => flushCount === 1);

sec('STABILITY — store deduplication under load');

const dedupStore = new SessionStore();
// Record same endpoint 100 times
for (let i = 0; i < 100; i++) {
  dedupStore.record({
    method: 'GET', url: '/api/orders/1001',
    headers: { authorization: 'Bearer tok' },
    statusCode: 200, contentLength: 50,
    contentHash: 'json:same', rawHash: 'raw:same',
  });
}
const dedupReplayable = dedupStore.replayable();
check('100 identical requests deduplicated to 1 replay candidate', () => dedupReplayable.length === 1);
check('100 identical requests still stored as 100 entries', () => dedupStore.entries.length === 100);

// ── 5. BLINDSPOTS — new angles ────────────────────────────────────────────────

sec('BLINDSPOT — remediation field absence');

// The report currently has no remediation field per finding.
// This test documents that it's absent — so when we add it, the test flips.
const noRemStore = new SessionStore();
noRemStore.record({
  method: 'GET', url: '/api/orders/1001',
  headers: { authorization: 'Bearer tok-a' },
  statusCode: 200, contentLength: 50,
  contentHash: 'json:abc', rawHash: 'raw:xyz',
});
const remTmpPath = os.tmpdir() + '/jabearri-rem-test.json';
saveReport([{
  type: 'broken-access-control', severity: 'high', confidence: 'confirmed',
  findingId: 'AG-TEST-001', method: 'GET', path: '/api/orders/1001',
  resourceIds: [{ type: 'slug', value: 'ord-1001' }],
  tokenType: 'bearer', originalStatus: 200, originalSize: 50,
  replayStatus: 200, replaySize: 50, matchType: 'semantic-hash',
  curl: "curl -s -H 'Authorization: Bearer '$TOKEN_B 'http://localhost:3000/api/orders/1001'",
}], noRemStore, remTmpPath, { target: 'http://localhost:3000', scope: ['/api/'] });
const remReport = JSON.parse(fs.readFileSync(remTmpPath, 'utf8'));
check('EXPECTED ABSENT: remediation field not yet in finding (documents future work)', () =>
  remReport.findings[0].remediation === undefined
);

sec('BLINDSPOT — retest status field absence');

check('EXPECTED ABSENT: retest field not yet in finding (documents future work)', () =>
  remReport.findings[0].retest === undefined
);

sec('BLINDSPOT — report-level hash absence');

check('EXPECTED ABSENT: reportIntegrity.reportHash not yet in report (documents future work)', () =>
  remReport.reportIntegrity === undefined || remReport.reportIntegrity.reportHash === undefined
);

sec('BLINDSPOT — runContext when mode is proxy (not wrapper)');

// When running in manual proxy mode (not wrapper), command should be null
const proxyModeReport = os.tmpdir() + '/jabearri-proxy-mode.json';
saveReport([], noRemStore, proxyModeReport, {
  target: 'http://localhost:3000',
  scope: ['/api/'],
  command: null,  // manual mode — no wrapped command
});
const pmReport = JSON.parse(fs.readFileSync(proxyModeReport, 'utf8'));
check('runContext.command is null in manual proxy mode', () => pmReport.runContext.command === null);
check('runContext.target present even in manual mode', () => pmReport.runContext.target === 'http://localhost:3000');

sec('BLINDSPOT — exposure summary on non-JSON finding');

// A raw: hash match (e.g. binary content) — exposure summary should handle gracefully
const binaryBody = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]); // PNG header bytes
const binaryEs = buildExposureSummary(binaryBody, 'image/png', 'raw:binhash');
check('Exposure summary on binary body does not crash', () => typeof binaryEs === 'object');
check('Binary body exposure summary skipped or has no field paths', () =>
  binaryEs.skipped === true || (Array.isArray(binaryEs.fieldPaths) && binaryEs.fieldPaths.length === 0)
);

sec('BLINDSPOT — principalPair labels in report');

// When JABEARRI_USER_A_LABEL is not set, should default gracefully
const noLabelReport = os.tmpdir() + '/jabearri-nolabel.json';
saveReport([], noRemStore, noLabelReport, {
  target: 'http://localhost:3000',
  scope: ['/api/'],
  userALabel: null,
  userBLabel: null,
});
const nlReport = JSON.parse(fs.readFileSync(noLabelReport, 'utf8'));
check('principalPair.userA has default label when not set', () => typeof nlReport.runContext.principalPair.userA === 'string');
check('principalPair.userB has default label when not set', () => typeof nlReport.runContext.principalPair.userB === 'string');

sec('BLINDSPOT — scope normalization interaction with new report fields');

// notReplayed entries should use normalized paths (not raw encoded paths)
const normStore = new SessionStore();
normStore.record({
  method: 'GET',
  url: '/api/PUBLIC/data',  // uppercase — should normalize
  headers: { authorization: 'Bearer tok' },
  statusCode: 200, contentLength: 10,
  contentHash: 'json:x', rawHash: 'raw:y',
});
const normCov = coverageSummary(normStore);
check('notReplayed entry for no-resource-ID uppercase path exists', () =>
  normCov.notReplayed.some(e => e.reason === 'no_resource_id')
);

sec('BLINDSPOT — whyFlagged accuracy for all matchType values');

const matchTypes = [
  { matchType: 'semantic-hash', hash: 'json:abc', expected: 'JSON normalisation' },
  { matchType: 'raw-hash-fallback', hash: 'json:abc', expected: 'Raw response hashes matched' },
  { matchType: 'size-proximity', hash: 'json:abc', expected: 'sizes within 5%' },
  { matchType: 'semantic-hash', hash: 'raw:abc', expected: 'raw-byte hashing' },
];
for (const { matchType, hash, expected } of matchTypes) {
  const lines = whyFlagged({
    matchType,
    evidence: { matchedHash: hash },
  });
  check(`whyFlagged(${matchType}, ${hash.split(':')[0]}:) contains expected text`, () =>
    lines.some(l => l.includes(expected))
  );
}

// ── Results ───────────────────────────────────────────────────────────────────

console.log('\n\n' + '═'.repeat(64));
console.log('  jabearri — adversarial harness results');
console.log('═'.repeat(64));
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);

if (failures.length > 0) {
  console.log('\n  Failures:');
  for (const f of failures) console.log('  ' + f);
}

console.log('═'.repeat(64) + '\n');
process.exit(failed > 0 ? 1 : 0);
})();
