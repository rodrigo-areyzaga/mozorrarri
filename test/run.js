'use strict';

const http = require('http');
const root = __dirname + '/..';

// ── Harness ───────────────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) { process.stdout.write(`  ✓  ${label}\n`); passed++; }
  else           { process.stderr.write(`  ✗  ${label}\n`); failed++; }
}

function section(name) {
  process.stdout.write(`\n── ${name} ${'─'.repeat(Math.max(0, 50 - name.length))}\n`);
}

// ── safety.js ─────────────────────────────────────────────────────────────────
section('safety.js');
const { isPrivateHost, verifyScope, verifyTarget } = require(root + '/src/safety');

verifyTarget('https://localhost:3000')
  .then(() => assert(false, 'HTTPS target should throw'))
  .catch(err => {
    assert(err.message.includes('HTTP traffic only'),    'HTTPS target gives clear error');
    assert(err.message.includes('http://localhost:3000'),'HTTPS error suggests HTTP alternative');
  });

assert(isPrivateHost('127.0.0.1'),      'loopback 127.0.0.1 is private');
assert(isPrivateHost('localhost'),      'localhost is private');
assert(isPrivateHost('10.0.0.1'),       '10.x is private');
assert(isPrivateHost('192.168.1.50'),   '192.168.x is private');
assert(!isPrivateHost('8.8.8.8'),       '8.8.8.8 is NOT private');
assert(!isPrivateHost('93.184.216.34'), 'example.com IP is NOT private');

try { verifyScope(null);     assert(false, 'null scope should throw'); }
catch { assert(true, 'null scope throws'); }

try { verifyScope([]);       assert(false, 'empty scope should throw'); }
catch { assert(true, 'empty scope throws'); }

try { verifyScope(['/api/']); assert(true, 'valid scope passes'); }
catch { assert(false, 'valid scope should not throw'); }

// ── session-store.js ──────────────────────────────────────────────────────────
section('session-store.js');
const { SessionStore, extractToken, extractResourceIds, fingerprintToken } = require(root + '/src/session-store');

// Token extraction — returns { raw, type, cookieName } or null
const bearer = extractToken({ authorization: 'Bearer abc123' });
assert(bearer !== null,            'extracts Bearer token');
assert(bearer.raw === 'abc123',    'bearer raw value correct');
assert(bearer.type === 'bearer',   'bearer type identified');
assert(bearer.cookieName === null, 'bearer has no cookieName');

const cookie = extractToken({ cookie: 'session=xyz789; other=foo' });
assert(cookie !== null,            'extracts session cookie');
assert(cookie.raw === 'xyz789',    'cookie raw value correct');
assert(cookie.type === 'cookie',   'cookie type identified');
assert(cookie.cookieName !== null, 'cookie has cookieName');

assert(extractToken({}) === null,  'returns null when no token');

// Resource ID extraction
const ids1 = extractResourceIds('/api/orders/1042');
assert(ids1.some(i => i.value === '1042'), 'extracts integer ID');

const ids2 = extractResourceIds('/api/users/a3f2c1d0-e5b6-4f78-9012-abcdef012345');
assert(ids2.some(i => i.type === 'uuid'), 'extracts UUID');

const ids3 = extractResourceIds('/api/health');
assert(ids3.length === 0, 'no IDs on clean path');

const ids4 = extractResourceIds('/api/orders/ord-1001');
assert(ids4.some(i => i.type === 'slug' && i.value === 'ord-1001'), 'extracts slug ID');

const ids5 = extractResourceIds('/api/users/user-alice');
assert(ids5.some(i => i.value === 'user-alice'), 'extracts string slug ID');

// Fingerprint
const fp1 = fingerprintToken('secret');
const fp2 = fingerprintToken('secret');
const fp3 = fingerprintToken('other');
assert(fp1 === fp2,           'fingerprint is deterministic');
assert(fp1 !== fp3,           'different tokens have different fingerprints');
assert(!fp1.includes('secret'),'fingerprint does not contain original token');

// Store recording
const store = new SessionStore();
store.record({ method: 'GET', url: '/api/orders/1042', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 120, contentHash: 'json:abc' });
store.record({ method: 'GET', url: '/api/orders/1043', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 130, contentHash: 'json:def' });
store.record({ method: 'GET', url: '/api/health',      headers: {},                                statusCode: 200, contentLength:  20 });
assert(store.size() === 2,              'records authenticated requests only');
assert(store.replayable().length === 2, 'both entries are replayable');
assert(store.knownTokens().length === 1,'one distinct token seen');

const entry = store.entries[0];
assert(entry.tokenType === 'bearer',   'tokenType recorded');
assert(entry.contentHash === 'json:abc','contentHash stored');

const cookieStore = new SessionStore();
cookieStore.record({ method: 'GET', url: '/api/profile/99', headers: { cookie: 'session=sess-xyz' }, statusCode: 200, contentLength: 80 });
assert(cookieStore.entries[0].tokenType === 'cookie', 'cookie tokenType recorded');
assert(cookieStore.entries[0].cookieName !== null,    'cookieName recorded');

// ── replay.js — semantic comparison ───────────────────────────────────────────
section('replay.js — semantic comparison');
const { assessFinding, contentHash, sortKeys } = require(root + '/src/replay');

// sortKeys normalises key order
assert(
  JSON.stringify(sortKeys({ b:2, a:1 })) === JSON.stringify(sortKeys({ a:1, b:2 })),
  'sortKeys normalises key order'
);

// contentHash
const b1 = Buffer.from('{"id":1,"name":"Alice"}');
const b2 = Buffer.from('{"name":"Alice","id":1}');
const h1 = contentHash(b1, 'application/json');
const h2 = contentHash(b2, 'application/json');
assert(h1.startsWith('json:'), 'JSON produces json: hash');
assert(h1 === h2,              'same JSON different key order = same hash');

const b3 = Buffer.from('{"id":2,"name":"Bob"}');
assert(h1 !== contentHash(b3, 'application/json'), 'different JSON = different hash');

const hRaw = contentHash(Buffer.from('<html>test</html>'), 'text/html');
assert(hRaw.startsWith('raw:'), 'non-JSON produces raw: hash');

// assessFinding
assert(
  assessFinding(
    { statusCode: 200, contentLength: 100, contentHash: 'json:abc' },
    { statusCode: 200, body: Buffer.from('x'.repeat(100)), bodyLength: 100, contentHash: 'json:abc' }
  ) === 'confirmed',
  'matching hash = confirmed'
);

assert(
  assessFinding(
    { statusCode: 200, contentLength: 100, contentHash: 'json:abc' },
    { statusCode: 200, body: Buffer.from('x'.repeat(100)), bodyLength: 100, contentHash: 'json:xyz' }
  ) === 'none',
  'different hash = none (no false positive on similar size)'
);

assert(
  assessFinding(
    { statusCode: 200, contentLength: 200, contentHash: 'json:abc' },
    { statusCode: 403, body: Buffer.from('forbidden'), bodyLength: 9, contentHash: 'json:err' }
  ) === 'none',
  '403 replay = none'
);

assert(
  assessFinding(
    { statusCode: 200, contentLength: 200, contentHash: 'json:abc' },
    { statusCode: 200, body: Buffer.from(''), bodyLength: 0, contentHash: 'empty' }
  ) === 'none',
  'empty replay body = none'
);

// ── reporter.js — coverage summary ───────────────────────────────────────────
section('reporter.js — coverage summary');
const { coverageSummary } = require(root + '/src/reporter');

const covStore = new SessionStore();
covStore.record({ method: 'GET', url: '/api/orders/1001',   headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 100, contentHash: 'json:abc' });
covStore.record({ method: 'GET', url: '/api/orders/1002',   headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 100, contentHash: 'json:def' });
covStore.record({ method: 'GET', url: '/api/payment/pay-1', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength:  80, contentHash: 'json:ghi' });

const cov = coverageSummary(covStore);
assert(cov.observed === 3,           'coverage: observed count correct');
assert(cov.replayed === 3,           'coverage: replayed count correct');
assert(cov.patterns >= 2,            'coverage: detects multiple resource patterns');
assert(cov.mechanisms === 'bearer',  'coverage: auth mechanism identified');

const emptyCov = coverageSummary(new SessionStore());
assert(emptyCov.observed === 0,      'coverage: empty store returns zeros');
assert(emptyCov.mechanisms === 'none','coverage: empty store shows no mechanisms');

// ── Integration: proxy + fake app ─────────────────────────────────────────────
section('integration — proxy + fake app');

// Minimal fake app with one deliberate IDOR bug
function makeFakeApp(port) {
  const TOKENS = { 'tok-a': 'user-a', 'tok-b': 'user-b' };
  const ORDERS = {
    '1001': { id: '1001', owner: 'user-a', item: 'Laptop', total: 999 },
    '2001': { id: '2001', owner: 'user-b', item: 'Mouse',  total:  29 },
  };

  function getUser(req) {
    const auth = (req.headers['authorization'] || '').replace(/^bearer\s+/i, '').trim();
    return TOKENS[auth] ? { id: TOKENS[auth] } : null;
  }

  function send(res, status, data) {
    const body = JSON.stringify(data);
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
    res.end(body);
  }

  const srv = http.createServer((req, res) => {
    const user = getUser(req);
    const p    = req.url.split('?')[0];

    if (p === '/api/health') return send(res, 200, { ok: true });
    if (!user) return send(res, 401, { error: 'unauthorized' });

    const m = p.match(/^\/api\/orders\/(\d+)$/);
    if (m) {
      const order = ORDERS[m[1]];
      if (!order) return send(res, 404, { error: 'not found' });
      // BUG: no ownership check
      return send(res, 200, order);
    }

    if (p === '/api/profile') return send(res, 200, { id: user.id });
    send(res, 404, { error: 'not found' });
  });

  return new Promise(resolve => srv.listen(port, '127.0.0.1', () => resolve(srv)));
}

async function runIntegration() {
  const appServer = await makeFakeApp(3099);
  const iStore    = new SessionStore();
  const { ProxyCore } = require(root + '/src/proxy');

  const proxy = new ProxyCore({
    target:  'http://127.0.0.1:3099',
    scope:   ['/api/'],
    exclude: ['/api/health'],
    store:   iStore,
    logger:  { log: () => {}, error: () => {} },
  });
  await proxy.listen(8899);

  function req(path, token) {
    return new Promise((resolve, reject) => {
      const r = http.request({
        hostname: '127.0.0.1', port: 8899, path, method: 'GET',
        headers: token ? { authorization: `Bearer ${token}` } : {},
      }, res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }); }
          catch { resolve({ status: res.statusCode, body: {} }); }
        });
      });
      r.on('error', reject);
      r.end();
    });
  }

  // Proxy forwards correctly
  const health = await req('/api/health');
  assert(health.status === 200, 'health check passes through');

  const unauth = await req('/api/orders/1001', null);
  assert(unauth.status === 401, 'unauthenticated request returns 401');

  const order = await req('/api/orders/1001', 'tok-a');
  assert(order.status === 200,         'user A fetches their own order');
  assert(order.body.item === 'Laptop', 'correct order returned');

  // Session store
  assert(iStore.size() >= 1, 'store recorded authenticated requests');

  const healthEntry = iStore.entries.find(e => e.path === '/api/health');
  assert(!healthEntry, 'excluded path not recorded');

  const orderEntry = iStore.entries.find(e => e.path === '/api/orders/1001');
  assert(!!orderEntry,                                      'order request recorded');
  assert(orderEntry.resourceIds.some(r => r.value === '1001'), 'resource ID extracted');
  assert(!JSON.stringify(orderEntry).includes('tok-a'),    'raw token not stored');
  assert(orderEntry.tokenType === 'bearer',                'token type recorded');
  assert(orderEntry.contentHash !== null,                  'content hash recorded');
  assert(orderEntry.contentHash.startsWith('json:'),       'content hash is semantic');

  // Replay detects IDOR
  const { runReplay } = require(root + '/src/replay');
  const findings = await runReplay({
    store:       iStore,
    targetUrl:   'http://127.0.0.1:3099',
    secondToken: 'tok-b',
    logger:      { log: () => {} },
  });

  const idor = findings.find(f => f.path.includes('/api/orders/1001'));
  assert(!!idor,                          'IDOR on /api/orders/1001 detected');
  assert(idor.severity === 'high',        'finding is high severity');
  assert(idor.confidence === 'confirmed', 'confidence is confirmed');
  assert(idor.matchType === 'semantic-hash', 'match type is semantic-hash');
  assert(!!idor.curl,                     'finding includes curl command');
  assert(idor.tokenType === 'bearer',     'token type in finding');

  // No false positive on non-parameterised endpoints
  const profileFinding = findings.find(f => f.path === '/api/profile');
  assert(!profileFinding, 'no false positive on /api/profile');

  await proxy.close();
  appServer.close();
}

runIntegration()
  .then(() => {
    section('results');
    process.stdout.write(`\n  Passed: ${passed}\n`);
    process.stdout.write(`  Failed: ${failed}\n`);
    if (failed > 0) { process.stderr.write('\n  Some tests failed.\n\n'); process.exit(1); }
    else            { process.stdout.write('\n  All tests passed.\n\n');  process.exit(0); }
  })
  .catch(err => {
    process.stderr.write(`\n  Integration test threw: ${err.message}\n${err.stack}\n`);
    process.exit(1);
  });
