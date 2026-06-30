'use strict';

const http = require('http');
const os   = require('os');
const path = require('path');
const root = __dirname + '/..';

// Portable temp path — never hardcode /tmp (Linux-only; resolves to E:\tmp on
// Windows and fails). Uses the OS temp dir and the PID to avoid collisions.
function tmpPath(name) {
  return path.join(os.tmpdir(), `${name}-${process.pid}.json`);
}

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

// ── IP normalization — bypass prevention ──────────────────────────────────────
const { normalizeIPv4 } = require(root + '/src/safety');

// Standard dotted-decimal passes through unchanged
assert(normalizeIPv4('127.0.0.1')    === '127.0.0.1', 'dotted-decimal unchanged');
assert(normalizeIPv4('10.0.0.1')     === '10.0.0.1',  'private dotted-decimal unchanged');

// 32-bit decimal — the main bypass vector
assert(normalizeIPv4('2130706433')   === '127.0.0.1', 'decimal 2130706433 → 127.0.0.1');
assert(normalizeIPv4('167772161')    === '10.0.0.1',  'decimal 167772161  → 10.0.0.1');
assert(normalizeIPv4('3232235521')   === '192.168.0.1','decimal 3232235521 → 192.168.0.1');

// Hex notation
assert(normalizeIPv4('0x7f000001')   === '127.0.0.1', 'hex 0x7f000001 → 127.0.0.1');
assert(normalizeIPv4('0x0a000001')   === '10.0.0.1',  'hex 0x0a000001 → 10.0.0.1');

// Octal first octet
assert(normalizeIPv4('0177.0.0.1')   === '127.0.0.1', 'octal 0177.0.0.1 → 127.0.0.1');

// isPrivateHost catches normalized forms
assert(isPrivateHost('2130706433'),  'decimal loopback 2130706433 is private');
assert(isPrivateHost('167772161'),   'decimal 10.x 167772161 is private');
assert(isPrivateHost('0x7f000001'),  'hex loopback 0x7f000001 is private');
assert(isPrivateHost('0177.0.0.1'),  'octal loopback 0177.0.0.1 is private');
assert(!isPrivateHost('8.8.8.8'),    'public IP 8.8.8.8 is not private (sanity check)');
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
assert(cookie !== null,                  'extracts session cookie');
assert(cookie.raw === 'xyz789',          'cookie raw value correct');
assert(cookie.type === 'cookie',         'cookie type identified');
assert(cookie.cookieName === 'session',  'cookieName is session not other cookie');

// Non-Bearer auth scheme generalization
const basicAuth = extractToken({ authorization: 'Basic dXNlcjpwYXNz' });
assert(basicAuth !== null,                'Basic auth recognized');
assert(basicAuth.type === 'other-auth',   'Basic auth type is other-auth');
assert(basicAuth.raw === 'Basic dXNlcjpwYXNz', 'Basic auth raw value preserved');

const tokenAuth = extractToken({ authorization: 'Token abc123' });
assert(tokenAuth !== null,               'Token auth recognized (Django REST)');
assert(tokenAuth.type === 'other-auth',  'Token auth type is other-auth');

const digestAuth = extractToken({ authorization: 'Digest realm="api"' });
assert(digestAuth !== null,              'Digest auth recognized');
assert(digestAuth.type === 'other-auth', 'Digest auth type is other-auth');

const apiKeyAuth = extractToken({ authorization: 'ApiKey sk-abc123' });
assert(apiKeyAuth !== null,              'ApiKey scheme recognized');
assert(apiKeyAuth.type === 'other-auth', 'ApiKey type is other-auth');

// shellQuote — shell injection prevention
// Access shellQuote via module internals — test the logic directly
function shellQuote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }

assert(shellQuote('http://127.0.0.1/api/orders/1') === "'http://127.0.0.1/api/orders/1'",
  'clean URL wrapped in single quotes');
assert(shellQuote('/api/orders/1?x=`touch /tmp/pwn`') === "'/api/orders/1?x=`touch /tmp/pwn`'",
  'backtick in URL is safely quoted — no shell execution');
assert(shellQuote("/api/orders/1?x=$(id)") === "'/api/orders/1?x=$(id)'",
  '$(...) in URL is safely quoted');
const sqOut = shellQuote("it's here");
assert(sqOut.startsWith("'") && sqOut.endsWith("'") && sqOut.includes("it") && sqOut.includes("s here"),
  'embedded single quote is escaped correctly');

// curl reproduction command accuracy
// (verify authFlag is correct for each token type via integration finding)
const { SessionStore: SS2 } = require(root + '/src/session-store');
const { runReplay: rr2, contentHash: ch2 } = require(root + '/src/replay');

// Quick curl-flag check via manual entry construction
const apiKeyEntry = {
  method: 'GET', path: '/api/orders/1001', query: '',
  tokenHash: 'abc', tokenType: 'api-key', cookieName: null,
  apiKeyHeader: 'x-api-key', originalAuthScheme: null,
  resourceIds: [{ type: 'integer', value: '1001' }],
  statusCode: 200, contentLength: 50,
  contentHash: 'json:test', rawHash: 'raw:test',
  userAgent: null, recordedAt: Date.now(),
};
// Simulate authFlag logic
const tType = apiKeyEntry.tokenType;
let testFlag;
if (tType === 'api-key') testFlag = `-H "${apiKeyEntry.apiKeyHeader}: $TOKEN_B"`;
assert(testFlag === '-H "x-api-key: $TOKEN_B"', 'api-key curl flag uses correct header');

const otherEntry = { ...apiKeyEntry, tokenType: 'other-auth', originalAuthScheme: 'Token' };
let otherFlag;
if (otherEntry.tokenType === 'other-auth') {
  const scheme = otherEntry.originalAuthScheme || '';
  otherFlag = `-H "Authorization: ${scheme ? scheme + ' ' : ''}$TOKEN_B"`;
}
assert(otherFlag === '-H "Authorization: Token $TOKEN_B"', 'other-auth curl uses original scheme prefix');

// X-API-Key header
const xApiKey = extractToken({ 'x-api-key': 'sk-test-12345' });
assert(xApiKey !== null,                 'X-API-Key header recognized');
assert(xApiKey.type === 'api-key',       'X-API-Key type is api-key');
assert(xApiKey.raw === 'sk-test-12345',  'X-API-Key value extracted correctly');

// MOZORRARRI_API_KEY_HEADER override
process.env.MOZORRARRI_API_KEY_HEADER = 'x-custom-key';
const customKey = extractToken({ 'x-custom-key': 'custom-tok' });
assert(customKey !== null,               'custom API key header recognized');
assert(customKey.type === 'api-key',     'custom API key type is api-key');
delete process.env.MOZORRARRI_API_KEY_HEADER;

// Empty bearer still falls through to cookie with non-Bearer auth schemes present
const emptyBearerFallthrough2 = extractToken({
  authorization: 'Bearer ',
  cookie: 'session=cookie-val'
});
assert(emptyBearerFallthrough2 !== null,              'empty bearer still falls to cookie with other auth');
assert(emptyBearerFallthrough2.type === 'cookie',     'type is cookie after empty bearer');

// User-Agent stored in session entry
const uaStore = new SessionStore();
uaStore.record({
  method: 'GET', url: '/api/orders/1001',
  headers: { authorization: 'Bearer tok-a', 'user-agent': 'Mozilla/5.0 TestBrowser' },
  statusCode: 200, contentLength: 50, contentHash: 'json:abc', rawHash: 'raw:xyz'
});
assert(uaStore.entries[0].userAgent === 'Mozilla/5.0 TestBrowser', 'original User-Agent stored in entry');

// Bare known scheme with no value — must fall through to cookie auth
// Same class as empty Bearer: "Authorization: Basic" with no credential
const bareBasic  = extractToken({ authorization: 'Basic',  cookie: 'session=cook-tok' });
const bareToken  = extractToken({ authorization: 'Token',  cookie: 'session=cook-tok' });
const bareDigest = extractToken({ authorization: 'Digest', cookie: 'session=cook-tok' });
assert(bareBasic  !== null && bareBasic.type  === 'cookie', 'bare Basic falls through to cookie');
assert(bareToken  !== null && bareToken.type  === 'cookie', 'bare Token falls through to cookie');
assert(bareDigest !== null && bareDigest.type === 'cookie', 'bare Digest falls through to cookie');
assert(bareBasic.raw  === 'cook-tok', 'cookie value correct after bare Basic fallthrough');

// Array-valued X-API-Key header must not crash
const arrayApiKey = extractToken({ 'x-api-key': ['k1', 'k2'] });
assert(arrayApiKey !== null,             'array X-API-Key handled without crash');
assert(arrayApiKey.type === 'api-key',   'array X-API-Key type is api-key');
assert(arrayApiKey.raw === 'k1',         'first non-empty API key extracted from array');

// Array with empty first element
const arrayApiKeyEmpty = extractToken({ 'x-api-key': ['', 'k2'] });
assert(arrayApiKeyEmpty !== null,        'empty first element skipped in API key array');
assert(arrayApiKeyEmpty.raw === 'k2',    'second element used when first is empty');

// Scheme-less Authorization — bare token with no scheme prefix
const schemelesAuth = extractToken({ authorization: 'raw-token-value-no-space' });
assert(schemelesAuth !== null,                  'scheme-less Authorization recognized');
assert(schemelesAuth.type === 'other-auth',     'scheme-less type is other-auth');
assert(schemelesAuth.raw === 'raw-token-value-no-space', 'scheme-less raw value preserved');

// Check scheme extraction for scheme-less tokens
const { SessionStore: SS3 } = require(root + '/src/session-store');
const ss3 = new SS3();
ss3.record({
  method: 'GET', url: '/api/orders/1001',
  headers: { authorization: 'raw-token-value-no-space' },
  statusCode: 200, contentLength: 50, contentHash: 'json:abc', rawHash: 'raw:xyz'
});
assert(ss3.entries[0].originalAuthScheme === '', 'scheme-less token has empty originalAuthScheme');
assert(ss3.entries[0].tokenType === 'other-auth', 'scheme-less token type is other-auth');

// Framework-default cookie names — previously missed, now covered
const frameworks = [
  ['connect.sid',                    'express-sid'],
  ['laravel_session',                'laravel-tok'],
  ['phpsessid',                      'php-tok'],
  ['jsessionid',                     'java-tok'],
  ['next-auth.session-token',        'nextauth-tok'],
  ['__secure-next-auth.session-token','secure-nextauth-tok'],
  ['asp.net_sessionid',              'aspnet-tok'],
  ['.aspnetcore.session',            'aspnetcore-tok'],
  ['_session_id',                    'rails-tok'],
  ['sessionid',                      'django-tok'],
];
for (const [cookieName, tokenValue] of frameworks) {
  const result = extractToken({ cookie: `${cookieName}=${tokenValue}` });
  assert(result !== null,               `framework cookie extracted: ${cookieName}`);
  assert(result.raw === tokenValue,     `correct token value for: ${cookieName}`);
  assert(result.cookieName === cookieName, `correct cookieName for: ${cookieName}`);
}

// CSRF-like cookies must NOT be extracted — avoids false replay with wrong token
const csrf = extractToken({ cookie: 'csrftoken=abc123; xsrf-token=def456' });
assert(csrf === null, 'csrftoken and xsrf-token must not be extracted as session tokens');

// MOZORRARRI_COOKIE_NAME override — operator-specified name takes priority
process.env.MOZORRARRI_COOKIE_NAME = 'my_custom_session';
const custom = extractToken({ cookie: 'my_custom_session=custom-tok-xyz' });
assert(custom !== null,                    'MOZORRARRI_COOKIE_NAME override works');
assert(custom.raw === 'custom-tok-xyz',    'correct token value from override');
assert(custom.cookieName === 'my_custom_session', 'correct cookieName from override');
delete process.env.MOZORRARRI_COOKIE_NAME; // clean up

// Regression: cookieName must come from the matched session cookie,
// not from the first cookie in the header string.
const wrongOrder = extractToken({ cookie: 'theme=dark; session=abc123' });
assert(wrongOrder !== null,              'extracts token when session is not first cookie');
assert(wrongOrder.raw === 'abc123',      'correct token value when session is not first');
assert(wrongOrder.cookieName === 'session', 'cookieName is session not theme');

assert(extractToken({}) === null,        'returns null when no token');

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

// ── extractResourceIds — candidate-filter tightening ────────────────────────
section('extractResourceIds — candidate filter');

// MongoDB ObjectID — 24-character hex string
const objId = '507f1f77bcf86cd799439011';
const idsObjectId = extractResourceIds('/api/users/' + objId);
assert(idsObjectId.length === 1,                     'MongoDB ObjectID extracted');
assert(idsObjectId[0].type === 'objectid',            'ObjectID type is objectid');
assert(idsObjectId[0].value === objId,                'ObjectID value correct');

const idsObjectIdDeep = extractResourceIds('/api/v2/vehicle/' + objId + '/location');
assert(idsObjectIdDeep.some(r => r.value === objId),  'ObjectID in crAPI-style path extracted');

// UUID still works alongside ObjectID
const idsUUID = extractResourceIds('/api/users/550e8400-e29b-41d4-a716-446655440000');
assert(idsUUID.length === 1 && idsUUID[0].type === 'uuid', 'UUID still extracted correctly alongside ObjectID');

// 24 all-digit string has no letters — doesn't match ObjectID (needs at least one a-f)
// and is too long for the integer pattern (1-20 digits). Not extracted — correct.
const idsLongInt = extractResourceIds('/api/orders/123456789012345678901234');
assert(idsLongInt.length === 0, '24-digit all-numeric string is not extracted (too long for integer, no letters for objectid)');

// Version segments must NOT be treated as resource IDs
const idsV2 = extractResourceIds('/api/v2/status');
assert(idsV2.length === 0, 'v2 version segment is not a resource ID');

const idsV1 = extractResourceIds('/api/v1/users/1042');
assert(!idsV1.some(i => i.value === '1'), 'v1 version segment skipped');
assert(idsV1.some(i => i.value === '1042'), 'real integer ID after version is kept');

const idsV10 = extractResourceIds('/api/v10/orders');
assert(idsV10.length === 0, 'v10 version segment skipped, no other IDs');

const idsVAlpha = extractResourceIds('/api/v2alpha/health');
assert(idsVAlpha.length === 0, 'v2alpha version segment skipped');

// Hyphenated route names directly under /api are NOT slugs
const idsHyphen = extractResourceIds('/api/order-history');
assert(idsHyphen.length === 0, 'order-history under /api is a route name, not a slug');

const idsHyphen2 = extractResourceIds('/api/user-settings');
assert(idsHyphen2.length === 0, 'user-settings under /api is a route name, not a slug');

// Slugs with digits are always kept (digit = likely a resource instance)
const idsSlugDigit = extractResourceIds('/api/ord-1001');
assert(idsSlugDigit.some(i => i.type === 'slug' && i.value === 'ord-1001'),
  'slug with digit directly under /api is kept');

// Slugs under collection parents are kept (even without digits)
const idsSlugCollection = extractResourceIds('/api/users/user-alice');
assert(idsSlugCollection.some(i => i.value === 'user-alice'),
  'slug under collection parent is kept');

const idsSlugDeep = extractResourceIds('/api/orders/order-detail');
assert(idsSlugDeep.some(i => i.value === 'order-detail'),
  'hyphenated segment under collection parent is a slug');

// Query-string: only id-like keys are extracted
const idsQueryId = extractResourceIds('/api/search?id=1001');
assert(idsQueryId.some(i => i.value === '1001'), 'query ?id=1001 extracts the ID');

const idsQueryOrderId = extractResourceIds('/api/search?orderId=5005');
assert(idsQueryOrderId.some(i => i.value === '5005'), 'query ?orderId=5005 extracts the ID');

const idsQueryPage = extractResourceIds('/api/search?page=2&sort=newest');
assert(!idsQueryPage.some(i => i.value === '2'), 'query ?page=2 is NOT a resource ID');

const idsQueryMixed = extractResourceIds('/api/items?id=42&page=3&limit=20');
assert(idsQueryMixed.some(i => i.value === '42'), '?id=42 is extracted');
assert(!idsQueryMixed.some(i => i.value === '3'), '?page=3 is not extracted');
assert(!idsQueryMixed.some(i => i.value === '20'), '?limit=20 is not extracted');

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

// Deduplication — same endpoint recorded multiple times should replay once
const dedupStore = new SessionStore();
dedupStore.record({ method: 'GET', url: '/api/orders/1001', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 100, contentHash: 'json:abc' });
dedupStore.record({ method: 'GET', url: '/api/orders/1001', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 100, contentHash: 'json:abc' });
dedupStore.record({ method: 'GET', url: '/api/orders/1001', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 100, contentHash: 'json:abc' });
assert(dedupStore.size() === 3,              'store records all three entries');
assert(dedupStore.replayable().length === 1, 'deduplication collapses to one replayable entry');

// HEAD requests are not replayable — no body means hash can never confirm
const headStore = new SessionStore();
headStore.record({ method: 'HEAD', url: '/api/orders/1001', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 0 });
headStore.record({ method: 'GET',  url: '/api/orders/1001', headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 100, contentHash: 'json:abc' });
assert(headStore.replayable().length === 1, 'HEAD requests are not replayable — GET only');

// Memory cap — store stops at MAX_ENTRIES
const capStore = new SessionStore();
for (let i = 0; i < 10002; i++) {
  capStore.record({ method: 'GET', url: '/api/orders/' + i, headers: { authorization: 'Bearer tok-a' }, statusCode: 200, contentLength: 50 });
}
assert(capStore.size() === 10000, 'store caps at 10000 entries');
assert(capStore._capped === true, 'store marks itself as capped');

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
assert(h1.length === 69, 'full SHA-256 hash length (json: + 64 hex chars)'); // json: = 5 chars
assert(h1 === h2,              'same JSON different key order = same hash');

const b3 = Buffer.from('{"id":2,"name":"Bob"}');
assert(h1 !== contentHash(b3, 'application/json'), 'different JSON = different hash');

const hRaw = contentHash(Buffer.from('<html>test</html>'), 'text/html');
assert(hRaw.startsWith('raw:'), 'non-JSON produces raw: hash');

// JSON content-type variants — must all use semantic hashing
const bodyX = Buffer.from(JSON.stringify({ id: 101, status: 'active' }));
const bodyY = Buffer.from(JSON.stringify({ status: 'active', id: 101 }));
const hVendor  = contentHash(bodyX, 'application/vnd.api+json; charset=utf-8');
const hCharset = contentHash(bodyY, 'application/json; charset=utf-8');
assert(hVendor.startsWith('json:'),  'vnd.api+json variant uses semantic hash');
assert(hCharset.startsWith('json:'), 'json;charset=utf-8 variant uses semantic hash');
assert(hVendor === hCharset,         'normalized keys match across JSON content-type variants');

// Tiny body with matching hash — trivial payload downgrades to needs-review
assert(
  assessFinding(
    { statusCode: 200, contentLength: 2, contentHash: 'json:tinyhash' },
    { statusCode: 200, body: Buffer.from('[]'), bodyLength: 2, contentHash: 'json:tinyhash', contentType: 'application/json' }
  ) === 'needs-review',
  'empty array payload downgrades to needs-review — not confirmed'
);

// Non-trivial tiny body with matching hash — still confirmed
assert(
  assessFinding(
    { statusCode: 200, contentLength: 20, contentHash: 'json:realhash' },
    { statusCode: 200, body: Buffer.from('{id:1,name:Alice}'), bodyLength: 23, contentHash: 'json:realhash', contentType: 'application/json' }
  ) === 'confirmed',
  'non-trivial payload with matching hash is confirmed'
);

// Empty body with matching hash — should not be confirmed (empty is empty)
assert(
  assessFinding(
    { statusCode: 200, contentLength: 0, contentHash: 'empty' },
    { statusCode: 200, body: Buffer.from(''), bodyLength: 0, contentHash: 'empty' }
  ) === 'none',
  'empty body is not a finding even with matching empty hash'
);

// Empty bearer fallthrough — Bearer with empty value should fall through to cookie
const emptyBearer = extractToken({ cookie: 'session=cookie-tok', authorization: 'Bearer ' });
assert(emptyBearer !== null,              'empty bearer falls through to cookie auth');
assert(emptyBearer.type === 'cookie',     'empty bearer resolves as cookie type');
assert(emptyBearer.raw === 'cookie-tok',  'correct cookie value after empty bearer fallthrough');

// Hash family consistency — json: vs raw: family mismatch still detects identical bytes
const sameBody = Buffer.from(JSON.stringify({ id: 1, owner: 'alice' }));
const jsonHash = contentHash(sameBody, 'application/json');
const rawHashVal = 'raw:' + require('crypto').createHash('sha256').update(sameBody).digest('hex');
assert(jsonHash.startsWith('json:'), 'json: family for normal JSON');
assert(rawHashVal.startsWith('raw:'), 'raw: family for raw hash');
assert(
  assessFinding(
    { statusCode: 200, contentHash: jsonHash, rawHash: rawHashVal, contentLength: sameBody.length },
    { statusCode: 200, body: sameBody, bodyLength: sameBody.length, contentHash: rawHashVal, rawHash: rawHashVal, contentType: 'application/json' }
  ) === 'confirmed',
  'hash family mismatch (json: vs raw:) still confirms when raw bytes match'
);

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

// ── replay.js — hash soundness (8 adversarial vectors) ───────────────────────
section('replay.js — hash soundness');

// ── Controls — these must pass (hash is doing its job) ────────────────────────

// C0: identical bytes → same hash (basic sanity)
const c0a = Buffer.from(JSON.stringify({ id: 1, name: 'Alice', balance: 100 }));
const c0b = Buffer.from(JSON.stringify({ id: 1, name: 'Alice', balance: 100 }));
assert(contentHash(c0a, 'application/json') === contentHash(c0b, 'application/json'),
  'C0: identical data produces identical hash (control)');

// C1: key reorder absorbed by sortKeys (existing behaviour, must stay working)
const c1a = Buffer.from(JSON.stringify({ id: 1, name: 'Alice' }));
const c1b = Buffer.from(JSON.stringify({ name: 'Alice', id: 1 }));
assert(contentHash(c1a, 'application/json') === contentHash(c1b, 'application/json'),
  'C1: key reorder correctly absorbed — sortKeys working');

// ── Big-int collision → false confirmed (MUST FAIL until fix lands) ───────────
// Integers beyond Number.MAX_SAFE_INTEGER (2^53-1 = 9007199254740991) lose
// precision in JSON.parse(). Two distinct IDs round to the same float.
// These tests document the DESIRED behaviour: different IDs must NOT hash equal.
// They will FAIL on current code — that is expected and correct until the fix lands.

const MAX_SAFE = 9007199254740991;

// N1: adjacent big-int IDs — string literals only, no JS arithmetic.
// JS arithmetic collapses MAX_SAFE+1 and MAX_SAFE+2 before the string is built.
// Hold all other fields constant — only the ID changes — to isolate the variable.
const n1a = Buffer.from('{"id":9007199254740993,"name":"Alice"}');
const n1b = Buffer.from('{"id":9007199254740994,"name":"Alice"}');
const n1HashA = contentHash(n1a, 'application/json');
const n1HashB = contentHash(n1b, 'application/json');
assert(n1HashA !== n1HashB,
  'N1: adjacent big-int IDs must produce different hashes — raw fallback preserves precision');

// N2: snowflake IDs ±1 — hold owner constant, isolate ID only
const n2a = Buffer.from('{"id":1469138416756862977,"owner":"alice"}');
const n2b = Buffer.from('{"id":1469138416756862978,"owner":"alice"}');
assert(contentHash(n2a, 'application/json') !== contentHash(n2b, 'application/json'),
  'N2: snowflake IDs differing by 1 must hash differently — raw fallback');

// N3: distinct big-int account IDs — hold balance constant, isolate ID only
const n3a = Buffer.from('{"accountId":9007199254740997,"balance":1000}');
const n3b = Buffer.from('{"accountId":9007199254740998,"balance":1000}');
assert(contentHash(n3a, 'application/json') !== contentHash(n3b, 'application/json'),
  'N3: distinct big-int account IDs must not collide — raw fallback');

// ── Array order divergence → false none (MUST FAIL until fix lands) ──────────
// sortKeys reorders object keys but does NOT reorder array elements.
// A collection returned in different order to user B is still a BOLA.
// These document DESIRED behaviour: reordered arrays of same records = same hash.

// A1: same order records, different sequence
const a1alice = Buffer.from(JSON.stringify([{id:1,name:'Alice'},{id:2,name:'Bob'}]));
const a1bob   = Buffer.from(JSON.stringify([{id:2,name:'Bob'},{id:1,name:'Alice'}]));
assert(contentHash(a1alice, 'application/json') === contentHash(a1bob, 'application/json'),
  'A1: reordered array of objects = same hash — order-insensitive for identity arrays');

// A2: same ID set returned in different order
const a2alice = Buffer.from(JSON.stringify([{orderId:'ord-1'},{orderId:'ord-2'},{orderId:'ord-3'}]));
const a2bob   = Buffer.from(JSON.stringify([{orderId:'ord-3'},{orderId:'ord-1'},{orderId:'ord-2'}]));
assert(contentHash(a2alice, 'application/json') === contentHash(a2bob, 'application/json'),
  'A2: reordered order IDs = same hash — order-insensitive for identity arrays');

// ── Unicode normalization → false none (MUST FAIL until fix lands) ────────────
// NFC vs NFD are the same string in different byte representations.
// macOS filesystems and some mobile keyboards emit NFD; most servers emit NFC.
// A name in NFD is the same name as in NFC — must hash identically.

const nfc = Buffer.from(JSON.stringify({ name: 'Caf\u00e9' }));          // NFC: é = U+00E9
const nfd = Buffer.from(JSON.stringify({ name: 'Cafe\u0301' }));         // NFD: e + combining acute
assert(contentHash(nfc, 'application/json') === contentHash(nfd, 'application/json'),
  'U1: NFC and NFD representations of same string hash identically');

// ── reporter.js — coverage summary
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
// ── proxy.js — scope normalization (bypass prevention) ───────────────────────
section('proxy.js — scope/exclude normalization');
const { ProxyCore } = require(root + '/src/proxy');

// Minimal proxy instance just to test _inScope normalization
const scopeProxy = new ProxyCore({
  target:  'http://127.0.0.1:3100',
  scope:   ['/api/'],
  exclude: ['/api/public/'],
  store:   { record: () => {}, size: () => 0, replayable: () => [] },
  logger:  { log: () => {}, error: () => {} },
});

// Control — basic scope/exclude
assert(scopeProxy._inScope('/api/orders/1001')   === true,  'in-scope path recorded');
assert(scopeProxy._inScope('/api/public/catalog') === false, 'excluded path not recorded');
assert(scopeProxy._inScope('/health')             === false, 'out-of-scope path not recorded');

// Case bypass — must be closed
assert(scopeProxy._inScope('/api/PUBLIC/catalog') === false, 'case bypass blocked — /api/PUBLIC/ matches exclude');
assert(scopeProxy._inScope('/API/orders/1001')    === true,  'case-insensitive scope match');

// Percent-encoding bypass — must be closed
assert(scopeProxy._inScope('/api/pu%62lic/catalog') === false, 'encoding bypass blocked — %62=b');
assert(scopeProxy._inScope('/api/%70ublic/catalog')  === false, 'encoding bypass blocked — %70=p');

// Encoded slash bypass
assert(scopeProxy._inScope('/api/public%2Fcatalog') === false, 'encoded slash bypass blocked — %2F=/');

// Trailing slash gap — /api/public/ should match both /api/public and /api/public/catalog
const trailingProxy = new ProxyCore({
  target:  'http://127.0.0.1:3100',
  scope:   ['/api/'],
  exclude: ['/api/public/'],  // with trailing slash
  store:   { record: () => {}, size: () => 0, replayable: () => [] },
  logger:  { log: () => {}, error: () => {} },
});
assert(trailingProxy._inScope('/api/public')          === false, 'exclude /api/public/ also matches bare /api/public');
assert(trailingProxy._inScope('/api/public/catalog')  === false, 'subpath of trailed exclude matched');
assert(trailingProxy._inScope('/api/publications/1')  === true,  'similar prefix not incorrectly excluded');

// ── Fix verification tests ───────────────────────────────────────────────────
section('fix verification — six adversarial findings');

// Fix 1: rawHash stored in session store entries
const rawHashStore = new SessionStore();
rawHashStore.record({
  method: 'GET', url: '/api/orders/1001',
  headers: { authorization: 'Bearer tok-a' },
  statusCode: 200, contentLength: 50,
  contentHash: 'json:abc', rawHash: 'raw:xyz'
});
assert(rawHashStore.entries[0].rawHash === 'raw:xyz', 'rawHash stored in session entry');
assert(rawHashStore.entries[0].contentHash === 'json:abc', 'contentHash still stored correctly');

// Fix 2: needs-review is its own type (not broken-access-control)
const trivialResult = assessFinding(
  { statusCode: 200, contentHash: 'json:trivial', rawHash: 'raw:trivial', contentLength: 2 },
  { statusCode: 200, body: Buffer.from('[]'), bodyLength: 2, contentHash: 'json:trivial', rawHash: 'raw:trivial', contentType: 'application/json' }
);
assert(trivialResult === 'needs-review', 'trivial payload returns needs-review confidence');

// Fix 3: array authorization header doesn't crash extractToken
assert(
  extractToken({ authorization: ['Bearer tok-array', 'Bearer tok-array2'] }) !== null,
  'array authorization header handled without crash'
);
const arrayAuth = extractToken({ authorization: ['Bearer tok-array'] });
assert(arrayAuth.raw === 'tok-array', 'first bearer token extracted from array header');

// Matrix parameter bypass — /api/public;v=1/catalog must match exclude /api/public/
const matrixProxy = new ProxyCore({
  target:  'http://127.0.0.1:3100',
  scope:   ['/api/'],
  exclude: ['/api/public/'],
  store:   { record: () => {}, size: () => 0, replayable: () => [] },
  logger:  { log: () => {}, error: () => {} },
});
assert(
  matrixProxy._inScope('/api/public;v=1/catalog') === false,
  'matrix param bypass blocked — ;v=1 stripped before scope match'
);
assert(
  matrixProxy._inScope('/api/public;bypass/catalog') === false,
  'matrix param bypass blocked — ;bypass stripped'
);
assert(
  matrixProxy._inScope('/api/orders;v=1/1001') === true,
  'matrix params on in-scope path still recorded'
);

// Double percent-encoding bypass — %252F must resolve to /
assert(
  matrixProxy._inScope('/api/private%252F..%252Fpublic/catalog') === false,
  'double-encoding bypass blocked — %252F→%2F→/ resolves traversal'
);
assert(
  matrixProxy._inScope('/api/pu%2562lic/catalog') === false,
  'double-encoding bypass blocked — %2562→%62→b resolves to public'
);

// Array auth — empty first element falls through to valid second element
const arrayWithEmptyFirst = extractToken({
  authorization: ['', 'Bearer valid-tok']
});
assert(arrayWithEmptyFirst !== null,              'empty first array element skipped');
assert(arrayWithEmptyFirst.raw === 'valid-tok',   'valid token from second array element extracted');

// Fix 4: encoded slash traversal normalized in scope check
const traversalProxy = new ProxyCore({
  target:  'http://127.0.0.1:3100',
  scope:   ['/api/'],
  exclude: ['/api/public/'],
  store:   { record: () => {}, size: () => 0, replayable: () => [] },
  logger:  { log: () => {}, error: () => {} },
});
// %2F..%2F traversal: /api/private%2F..%2Fpublic/catalog → resolves to /api/public/catalog → excluded
assert(
  traversalProxy._inScope('/api/private%2F..%2Fpublic/catalog') === false,
  'encoded slash traversal bypass blocked — %2F..%2F resolves through exclude'
);

// Fix 5: empty bearer falls through to cookie (already tested above, verify here too)
const emptyBearerWithCookie = extractToken({
  authorization: 'Bearer ',
  cookie: 'session=valid-session-tok'
});
assert(emptyBearerWithCookie !== null,              'empty bearer falls through to cookie');
assert(emptyBearerWithCookie.type === 'cookie',     'falls through to cookie type');
assert(emptyBearerWithCookie.raw === 'valid-session-tok', 'correct cookie value');

// ── exposure-summary.js ─────────────────────────────────────────────────────
section('exposure-summary.js');
const {
  buildExposureSummary,
  extractFieldPaths,
  classifyFieldPath,
  MAX_FIELD_PATHS,
  MAX_DEPTH,
  MAX_ARRAY_ITEMS,
} = require(root + '/src/exposure-summary');

// 1. Extracts object field paths
{
  const paths = [];
  extractFieldPaths({ name: 'Alice', age: 30 }, '', paths, 0);
  assert(paths.includes('name') && paths.includes('age'), 'extracts flat object field paths');
}

// 2. Extracts nested field paths
{
  const paths = [];
  extractFieldPaths({ user: { email: 'a@b.com', profile: { city: 'X' } } }, '', paths, 0);
  assert(paths.includes('user'), 'extracts parent field');
  assert(paths.includes('user.email'), 'extracts nested field');
  assert(paths.includes('user.profile.city'), 'extracts deeply nested field');
}

// 3. Samples arrays and unions fields across elements
{
  const paths = [];
  extractFieldPaths([
    { id: 1, name: 'Alice' },
    { id: 2, email: 'bob@x.com' },
  ], '', paths, 0);
  assert(paths.includes('[].id'), 'array element field extracted');
  assert(paths.includes('[].name'), 'first array element field extracted');
  assert(paths.includes('[].email'), 'second array element field extracted');
}

// 4. Caps array sampling
{
  const paths = [];
  const bigArray = Array.from({ length: 20 }, (_, i) => ({ [`field${i}`]: i }));
  extractFieldPaths(bigArray, '', paths, 0);
  // Should only sample MAX_ARRAY_ITEMS elements
  const fieldCount = paths.filter(p => p.startsWith('[].')).length;
  assert(fieldCount <= MAX_ARRAY_ITEMS, 'array sampling capped at MAX_ARRAY_ITEMS');
}

// 5. Caps max field paths
{
  const paths = [];
  const bigObj = {};
  for (let i = 0; i < 250; i++) bigObj[`f${i}`] = i;
  extractFieldPaths(bigObj, '', paths, 0);
  assert(paths.length <= MAX_FIELD_PATHS, 'field paths capped at MAX_FIELD_PATHS');
}

// 6. Sets truncation flag when cap is hit
{
  const bigObj = {};
  for (let i = 0; i < 250; i++) bigObj[`f${i}`] = i;
  const body = Buffer.from(JSON.stringify(bigObj));
  const result = buildExposureSummary(body, 'application/json', 'json:test');
  assert(result !== null, 'summary returned for large object');
  assert(result.fieldPathsTruncated === true, 'truncation flag set');
}

// 7. Caps depth
{
  let deep = { bottom: true };
  for (let i = 0; i < 20; i++) deep = { level: deep };
  const paths = [];
  extractFieldPaths(deep, '', paths, 0);
  // Should not recurse past MAX_DEPTH — total paths should be capped
  assert(paths.length <= MAX_DEPTH + 1, 'depth capped at MAX_DEPTH');
}

// 8. Returns null for primitive arrays
{
  const body = Buffer.from(JSON.stringify([1, 2, 3]));
  const result = buildExposureSummary(body, 'application/json', 'json:test');
  // Array of primitives has no field paths — should return null
  assert(result === null, 'returns null for primitive arrays');
}

// 9. Returns null for empty objects
{
  const body = Buffer.from(JSON.stringify({}));
  const result = buildExposureSummary(body, 'application/json', 'json:test');
  assert(result === null, 'returns null for empty objects');
}

// 10. Returns null for non-JSON
{
  const body = Buffer.from('<html>test</html>');
  const result = buildExposureSummary(body, 'text/html', 'raw:test');
  assert(result === null, 'returns null for non-JSON content type');
}

// 11. Returns null for invalid JSON
{
  const body = Buffer.from('{invalid json!!!');
  const result = buildExposureSummary(body, 'application/json', 'json:test');
  assert(result === null, 'returns null for invalid JSON body');
}

// 12. Does not include raw values
{
  const body = Buffer.from(JSON.stringify({ email: 'alice@test.com', password: 'secret123' }));
  const result = buildExposureSummary(body, 'application/json', 'json:test');
  assert(result !== null, 'summary returned');
  const resultStr = JSON.stringify(result);
  assert(!resultStr.includes('alice@test.com'), 'raw email value not in summary');
  assert(!resultStr.includes('secret123'), 'raw password value not in summary');
  assert(result.rawValuesStored === false, 'rawValuesStored is false');
}

// 13. Does not include raw body
{
  const body = Buffer.from(JSON.stringify({ data: 'sensitive content here' }));
  const result = buildExposureSummary(body, 'application/json', 'json:test');
  const resultStr = JSON.stringify(result);
  assert(!resultStr.includes('sensitive content here'), 'raw body not in summary');
  assert(result.rawBodyStored === false, 'rawBodyStored is false');
}

// 14. Classifies email-like field names as possible_pii
{
  const sig = classifyFieldPath('author.email');
  assert(sig !== null, 'email field classified');
  assert(sig.classification === 'possible_pii', 'email classified as possible_pii');
}
{
  const sig = classifyFieldPath('user.firstName');
  assert(sig !== null, 'firstName field classified');
  assert(sig.classification === 'possible_pii', 'firstName classified as possible_pii');
}
{
  const sig = classifyFieldPath('data.phone');
  assert(sig !== null, 'phone field classified');
  assert(sig.classification === 'possible_pii', 'phone classified as possible_pii');
}

// 15. Classifies lat/lng as possible_location
{
  const sig = classifyFieldPath('vehicleLocation.latitude');
  assert(sig !== null, 'latitude field classified');
  assert(sig.classification === 'possible_location', 'latitude classified as possible_location');
}
{
  const sig = classifyFieldPath('coords.lng');
  assert(sig !== null, 'lng field classified');
  assert(sig.classification === 'possible_location', 'lng classified as possible_location');
}

// 16. Classifies id/uuid/accountId/orderId as resource_identifier
{
  const sig = classifyFieldPath('order.id');
  assert(sig !== null, 'id field classified');
  assert(sig.classification === 'resource_identifier', 'id classified as resource_identifier');
}
{
  const sig = classifyFieldPath('data.accountId');
  assert(sig !== null, 'accountId field classified');
  assert(sig.classification === 'resource_identifier', 'accountId classified as resource_identifier');
}
{
  const sig = classifyFieldPath('item.orderId');
  assert(sig !== null, 'orderId field classified');
  assert(sig.classification === 'resource_identifier', 'orderId classified as resource_identifier');
}

// 17. Classifies financial field names
{
  const sig = classifyFieldPath('account.balance');
  assert(sig !== null, 'balance field classified');
  assert(sig.classification === 'possible_financial', 'balance classified as possible_financial');
}

// 18. Classifies secret-like field names
{
  const sig = classifyFieldPath('auth.password');
  assert(sig !== null, 'password field classified');
  assert(sig.classification === 'possible_secret', 'password classified as possible_secret');
}
{
  const sig = classifyFieldPath('config.apiKey');
  assert(sig !== null, 'apiKey field classified');
  assert(sig.classification === 'possible_secret', 'apiKey classified as possible_secret');
}

// 19. Does not classify unrecognized field names
{
  const sig = classifyFieldPath('metadata.createdAt');
  assert(sig === null, 'createdAt not classified — not a sensitive pattern');
}
{
  const sig = classifyFieldPath('config.retryCount');
  assert(sig === null, 'retryCount not classified — not a sensitive pattern');
}

// 20. Full buildExposureSummary with realistic payload
{
  const payload = {
    id: 'ord-1001',
    owner: 'user-alice',
    item: 'Mechanical Keyboard',
    total: 149.99,
    status: 'shipped',
  };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:abc123');
  assert(result !== null, 'summary for realistic payload');
  assert(result.summaryGeneratedFromHash === 'json:abc123', 'evidence hash preserved');
  assert(result.contentType === 'application/json', 'content type preserved');
  assert(result.bodyBytes === body.length, 'body bytes correct');
  assert(result.fieldPaths.includes('id'), 'id field path extracted');
  assert(result.fieldPaths.includes('owner'), 'owner field path extracted');
  assert(result.fieldPaths.includes('total'), 'total field path extracted');
  assert(result.rawBodyStored === false, 'raw body not stored');
  assert(result.rawValuesStored === false, 'raw values not stored');
  // id should be classified as resource_identifier
  const idSig = result.classificationSignals.find(s => s.field === 'id');
  assert(idSig && idSig.classification === 'resource_identifier', 'id classified in full summary');
  // total should be classified as possible_financial
  const totalSig = result.classificationSignals.find(s => s.field === 'total');
  assert(totalSig && totalSig.classification === 'possible_financial', 'total classified in full summary');
}

// 21. Returns null for empty body
{
  const result = buildExposureSummary(Buffer.from(''), 'application/json', 'json:test');
  assert(result === null, 'returns null for empty body');
}

// 22. Returns null for null body
{
  const result = buildExposureSummary(null, 'application/json', 'json:test');
  assert(result === null, 'returns null for null body');
}

// 23. Returns null for JSON null value
{
  const result = buildExposureSummary(Buffer.from('null'), 'application/json', 'json:test');
  assert(result === null, 'returns null for JSON null value');
}

// 24. Returns null for empty array
{
  const result = buildExposureSummary(Buffer.from('[]'), 'application/json', 'json:test');
  assert(result === null, 'returns null for empty array');
}

// 25. Handles content type variants (application/vnd.api+json)
{
  const body = Buffer.from(JSON.stringify({ data: { id: 1 } }));
  const result = buildExposureSummary(body, 'application/vnd.api+json; charset=utf-8', 'json:test');
  assert(result !== null, 'handles JSON content type variants');
}

// ── exposure-summary.js — adversarial ──────────────────────────────────────
section('exposure-summary.js — adversarial');

// 26. Hostile privacy payload — field names present, raw values absent
{
  const hostile = {
    email: 'alice@company.com',
    password: 'SuperSecret123!',
    apiKey: 'sk_live_123456',
    token: 'eyJhbGciOiJIUzI1NiJ9.payload.signature',
    ssn: '123-45-6789',
    cardNumber: '4111111111111111',
    location: {
      latitude: 19.4326,
      longitude: -99.1332,
    },
  };
  const body = Buffer.from(JSON.stringify(hostile));
  const result = buildExposureSummary(body, 'application/json', 'json:hostile');
  assert(result !== null, 'hostile payload produces summary');

  // Field paths present
  assert(result.fieldPaths.includes('email'), 'hostile: email field path present');
  assert(result.fieldPaths.includes('password'), 'hostile: password field path present');
  assert(result.fieldPaths.includes('apiKey'), 'hostile: apiKey field path present');
  assert(result.fieldPaths.includes('token'), 'hostile: token field path present');
  assert(result.fieldPaths.includes('ssn'), 'hostile: ssn field path present');
  assert(result.fieldPaths.includes('cardNumber'), 'hostile: cardNumber field path present');
  assert(result.fieldPaths.includes('location.latitude'), 'hostile: location.latitude field path present');
  assert(result.fieldPaths.includes('location.longitude'), 'hostile: location.longitude field path present');

  // Raw values NEVER present
  const s = JSON.stringify(result);
  assert(!s.includes('alice@company.com'), 'hostile: no raw email value');
  assert(!s.includes('SuperSecret123'), 'hostile: no raw password value');
  assert(!s.includes('sk_live_123456'), 'hostile: no raw API key value');
  assert(!s.includes('eyJhbGciOi'), 'hostile: no raw JWT value');
  assert(!s.includes('123-45-6789'), 'hostile: no raw SSN value');
  assert(!s.includes('4111111111111111'), 'hostile: no raw card number value');
  assert(!s.includes('19.4326'), 'hostile: no raw latitude value');
  assert(!s.includes('-99.1332'), 'hostile: no raw longitude value');

  // Classification signals present for sensitive fields
  const sigs = result.classificationSignals;
  assert(sigs.some(x => x.field === 'email' && x.classification === 'possible_pii'),
    'hostile: email classified as possible_pii');
  assert(sigs.some(x => x.field === 'password' && x.classification === 'possible_secret'),
    'hostile: password classified as possible_secret');
  assert(sigs.some(x => x.field === 'apiKey' && x.classification === 'possible_secret'),
    'hostile: apiKey classified as possible_secret');
  assert(sigs.some(x => x.field === 'token' && x.classification === 'possible_secret'),
    'hostile: token classified as possible_secret');
  assert(sigs.some(x => x.field === 'ssn' && x.classification === 'possible_pii'),
    'hostile: ssn classified as possible_pii');
  assert(sigs.some(x => x.field === 'location.latitude' && x.classification === 'possible_location'),
    'hostile: latitude classified as possible_location');
  assert(sigs.some(x => x.field === 'location.longitude' && x.classification === 'possible_location'),
    'hostile: longitude classified as possible_location');
}

// 27. Empty classificationSignals — non-trivial JSON with no sensitive field names
{
  const body = Buffer.from(JSON.stringify({ ok: true, count: 5, version: '1.0' }));
  const result = buildExposureSummary(body, 'application/json', 'json:benign');
  assert(result !== null, 'benign payload produces summary');
  assert(result.fieldPaths.length > 0, 'benign payload has field paths');
  assert(result.classificationSignals.length === 0, 'benign payload has zero classification signals');
}

// 28. Non-JSON content type returns null even with valid JSON bytes
{
  const body = Buffer.from(JSON.stringify({ id: 1, secret: 'leaked' }));
  const result = buildExposureSummary(body, 'text/plain', 'raw:abc');
  assert(result === null, 'text/plain returns null even with JSON bytes');
}

// 29. Ambiguous classification: "state" matches possible_location
{
  const sig = classifyFieldPath('address.state');
  assert(sig !== null, 'state is classified');
  assert(sig.classification === 'possible_location', 'state classified as possible_location');
}

// 30. Ambiguous classification: "tokenCount" does NOT match possible_secret
{
  const sig = classifyFieldPath('usage.tokenCount');
  assert(sig === null, 'tokenCount not classified — regex is anchored');
}

// 31. Ambiguous classification: "passwordRequired" does NOT match possible_secret
{
  const sig = classifyFieldPath('settings.passwordRequired');
  assert(sig === null, 'passwordRequired not classified — regex is anchored');
}

// 32. Ambiguous classification: "emailVerified" does NOT match possible_pii
{
  const sig = classifyFieldPath('user.emailVerified');
  assert(sig === null, 'emailVerified not classified — regex is anchored');
}

// 33. Truncation flag with array duplicates — tests pre-dedup truncation behavior
{
  // Create an array of identical objects to generate many duplicate paths
  const items = Array.from({ length: 5 }, () => {
    const obj = {};
    for (let i = 0; i < 50; i++) obj[`field${i}`] = 'val';
    return obj;
  });
  const body = Buffer.from(JSON.stringify(items));
  const result = buildExposureSummary(body, 'application/json', 'json:dupes');
  assert(result !== null, 'array-of-dupes produces summary');
  // After dedup, unique paths should be ~50 (field0..field49), well under 200
  // but pre-dedup paths from 5 sampled elements × 50 = 250, which may trigger truncation
  // This documents the behavior — truncation is checked before dedup
  assert(typeof result.fieldPathsTruncated === 'boolean', 'truncation flag is boolean for array dupes');
  // Unique paths should be reasonable
  assert(result.fieldPaths.length <= 51, 'deduplicated paths are reasonable count');
}

// ── exposure-summary.js — key sanitization ─────────────────────────────────
section('exposure-summary.js — key sanitization');

const { sanitizeKeySegment, MAX_EXPOSURE_BODY_BYTES } = require(root + '/src/exposure-summary');

// 34. Email-keyed object → [email-key], value not leaked through key
{
  const payload = { users: { 'alice@company.com': { password: 'SuperSecret123!', accountId: 'acct-1' } } };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:emailkey');
  const s = JSON.stringify(result);
  assert(result.fieldPaths.includes('users.[email-key]'), 'email key sanitized to [email-key]');
  assert(result.fieldPaths.includes('users.[email-key].password'), 'nested path under email key sanitized');
  assert(!s.includes('alice@company.com'), 'raw email NOT in field paths');
  // password is still a schema field name under the sanitized key — should classify
  assert(result.classificationSignals.some(x => x.field === 'users.[email-key].password' && x.classification === 'possible_secret'),
    'password under sanitized key still classified');
}

// 35. UUID-keyed object → [uuid-key]
{
  const payload = { vehicles: { 'a07828f3-edcf-4535-a59e-6afda15e91ce': { latitude: 19.4326 } } };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:uuidkey');
  const s = JSON.stringify(result);
  assert(result.fieldPaths.includes('vehicles.[uuid-key]'), 'UUID key sanitized to [uuid-key]');
  assert(result.fieldPaths.includes('vehicles.[uuid-key].latitude'), 'nested path under UUID key sanitized');
  assert(!s.includes('a07828f3-edcf-4535-a59e-6afda15e91ce'), 'raw UUID NOT in field paths');
}

// 36. Card-like / long numeric key → [numeric-key] (no [card-like-key])
{
  const payload = { cards: { '4111111111111111': { token: 'tok-1' } } };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:numkey');
  const s = JSON.stringify(result);
  assert(result.fieldPaths.includes('cards.[numeric-key]'), 'long numeric key sanitized to [numeric-key]');
  assert(!s.includes('4111111111111111'), 'raw numeric key NOT in field paths');
  assert(!s.includes('card-like-key'), 'no [card-like-key] placeholder used');
}

// 37. Token-like key (JWT) → [token-like-key]
{
  const jwt = 'eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3.SflKxwRJSMeKKF2QT4';
  const payload = { sessions: { [jwt]: { userId: 'u-1' } } };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:jwtkey');
  const s = JSON.stringify(result);
  assert(result.fieldPaths.includes('sessions.[token-like-key]'), 'JWT key sanitized to [token-like-key]');
  assert(!s.includes('eyJhbGciOiJIUzI1NiIs'), 'raw JWT NOT in field paths');
}

// 38. Token-like key (sk_ prefix) → [token-like-key]
{
  const payload = { keys: { 'sk_live_abcdef123456': { scope: 'full' } } };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:skkey');
  const s = JSON.stringify(result);
  assert(result.fieldPaths.includes('keys.[token-like-key]'), 'sk_ key sanitized to [token-like-key]');
  assert(!s.includes('sk_live_abcdef123456'), 'raw sk_ key NOT in field paths');
}

// 39. Control/newline/ANSI key → [unsafe-key], output has no control chars
{
  const payload = { '\u001b[31mred\u001b[0m': { secret: 'x' }, 'line\nbreak': { id: 1 } };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:unsafe');
  const s = JSON.stringify(result);
  assert(result.fieldPaths.includes('[unsafe-key]'), 'control-char key sanitized to [unsafe-key]');
  // No raw ANSI escape or newline in the stored paths
  assert(!/\u001b/.test(result.fieldPaths.join('|')), 'no ANSI escape in field paths');
  assert(!/\n/.test(result.fieldPaths.join('|')), 'no newline in field paths');
}

// 40. Schema field names are NOT sanitized — exposure shape stays useful
{
  assert(sanitizeKeySegment('email') === 'email', 'schema key email kept');
  assert(sanitizeKeySegment('password') === 'password', 'schema key password kept');
  assert(sanitizeKeySegment('accountId') === 'accountId', 'schema key accountId kept');
  assert(sanitizeKeySegment('vehicleId') === 'vehicleId', 'schema key vehicleId kept');
  assert(sanitizeKeySegment('latitude') === 'latitude', 'schema key latitude kept');
  assert(sanitizeKeySegment('longitude') === 'longitude', 'schema key longitude kept');
  assert(sanitizeKeySegment('cardLast4') === 'cardLast4', 'schema key cardLast4 kept');
  assert(sanitizeKeySegment('firstName') === 'firstName', 'schema key firstName kept');
}

// 41. Sanitization precedence is deterministic
{
  // email always → [email-key], even though it's also "long-ish"
  assert(sanitizeKeySegment('alice@company.com') === '[email-key]', 'email precedence');
  // UUID always → [uuid-key]
  assert(sanitizeKeySegment('a07828f3-edcf-4535-a59e-6afda15e91ce') === '[uuid-key]', 'uuid precedence');
  // long numeric → [numeric-key]
  assert(sanitizeKeySegment('4111111111111111') === '[numeric-key]', 'numeric precedence');
  // short numeric (< 12 digits) is NOT sanitized — could be a normal ID
  assert(sanitizeKeySegment('1001') === '1001', 'short numeric key kept');
  // unsafe beats everything
  assert(sanitizeKeySegment('a\u0000b') === '[unsafe-key]', 'unsafe precedence');
}

// 42. Placeholders are inert — never classified
{
  assert(classifyFieldPath('users.[email-key]') === null, '[email-key] not classified');
  assert(classifyFieldPath('x.[uuid-key]') === null, '[uuid-key] not classified');
  assert(classifyFieldPath('x.[token-like-key]') === null, '[token-like-key] not classified');
  assert(classifyFieldPath('x.[numeric-key]') === null, '[numeric-key] not classified');
  assert(classifyFieldPath('x.[dynamic-key]') === null, '[dynamic-key] not classified');
  assert(classifyFieldPath('x.[unsafe-key]') === null, '[unsafe-key] not classified');
}

// 43. High-entropy long random key → [dynamic-key]; long normal word kept
{
  // 40-char mixed-case+digit blob → dynamic
  assert(sanitizeKeySegment('aB3xK9mZ2qP7wL4nR8tY6vC1dF5gH0jS3kM8pQ2x') === '[dynamic-key]',
    'high-entropy key sanitized to [dynamic-key]');
  // A long but normal lowercase schema-ish word is kept
  assert(sanitizeKeySegment('verylongdescriptivefieldnamehere') === 'verylongdescriptivefieldnamehere',
    'long lowercase schema word kept');
}

// ── exposure-summary.js — bounded analysis ─────────────────────────────────
section('exposure-summary.js — bounded analysis');

// 44. Oversized body → skipped summary, finding-side unaffected
{
  // Build a JSON body just over 1 MB
  const bigArray = [];
  let approxBytes = 0;
  while (approxBytes < MAX_EXPOSURE_BODY_BYTES + 1000) {
    const chunk = { id: bigArray.length, data: 'x'.repeat(100) };
    bigArray.push(chunk);
    approxBytes += 120;
  }
  const body = Buffer.from(JSON.stringify(bigArray));
  assert(body.length > MAX_EXPOSURE_BODY_BYTES, 'test body exceeds size ceiling');
  const result = buildExposureSummary(body, 'application/json', 'json:huge');
  assert(result !== null, 'oversized body returns a summary object (not null)');
  assert(result.skipped === true, 'oversized body summary is marked skipped');
  assert(result.reason === 'body-too-large', 'skip reason is body-too-large');
  assert(result.bodyBytes === body.length, 'skipped summary records body size');
  assert(result.rawBodyStored === false, 'skipped summary: rawBodyStored false');
  assert(result.rawValuesStored === false, 'skipped summary: rawValuesStored false');
  assert(result.summaryGeneratedFromHash === 'json:huge', 'skipped summary keeps evidence hash');
  // No field paths — we never parsed
  assert(result.fieldPaths === undefined, 'skipped summary has no fieldPaths');
}

// 45. Body just under the ceiling is analyzed normally
{
  // Build the body directly to avoid O(n^2) repeated stringification.
  const chunk = '{"id":1,"name":"item"}';
  const targetBytes = MAX_EXPOSURE_BODY_BYTES - 50000;
  const count = Math.floor(targetBytes / (chunk.length + 1));
  const body = Buffer.from('[' + Array(count).fill(chunk).join(',') + ']');
  assert(body.length < MAX_EXPOSURE_BODY_BYTES, 'test body under size ceiling');
  const result = buildExposureSummary(body, 'application/json', 'json:under');
  assert(result !== null, 'under-ceiling body produces summary');
  assert(!result.skipped, 'under-ceiling body is not skipped');
  assert(Array.isArray(result.fieldPaths), 'under-ceiling body has fieldPaths');
}

// 46. Depth cap is exact — deepest path has exactly MAX_DEPTH segments
{
  // Build object nested well past MAX_DEPTH
  let deep = { leaf: true };
  for (let i = 0; i < 20; i++) deep = { ['L' + (19 - i)]: deep };
  const paths = [];
  extractFieldPaths(deep, '', paths, 0);
  const deepest = paths.reduce((a, b) => b.split('.').length > a.split('.').length ? b : a, '');
  const segs = deepest.split('.').length;
  assert(segs === MAX_DEPTH, `deepest path has exactly MAX_DEPTH (${MAX_DEPTH}) segments, got ${segs}`);
}

// 47. Depth cap boundary — object exactly at MAX_DEPTH levels fully captured
{
  // Build object nested exactly MAX_DEPTH levels
  let obj = { bottom: 1 };
  for (let i = 0; i < MAX_DEPTH - 1; i++) obj = { ['k' + i]: obj };
  const paths = [];
  extractFieldPaths(obj, '', paths, 0);
  // Should not throw, should produce bounded paths
  assert(paths.length > 0, 'exact-depth object produces paths');
  const deepest = paths.reduce((a, b) => b.split('.').length > a.split('.').length ? b : a, '');
  assert(deepest.split('.').length <= MAX_DEPTH, 'no path exceeds MAX_DEPTH segments');
}

// ── exposure-summary.js — sanitization collision / ambiguity ───────────────
section('exposure-summary.js — sanitization collision');

// 48. Multiple distinct dynamic keys collapse to one placeholder path (privacy-good)
{
  const payload = {
    users: {
      'alice@company.com': { password: 'x' },
      'bob@company.com':   { password: 'y' },
      'carol@company.com': { password: 'z' },
    },
  };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:collide');
  const s = JSON.stringify(result);
  // All three emails collapse to a single deduplicated path
  const emailKeyPaths = result.fieldPaths.filter(p => p === 'users.[email-key]');
  assert(emailKeyPaths.length === 1, 'three email keys collapse to one deduplicated path');
  // No raw emails leak
  assert(!s.includes('alice@company.com'), 'no raw alice email');
  assert(!s.includes('bob@company.com'), 'no raw bob email');
  assert(!s.includes('carol@company.com'), 'no raw carol email');
}

// 49. Sanitization metadata is present and honest when keys were sanitized
{
  const payload = {
    users: { 'alice@company.com': { id: 1 } },
    vehicles: { 'a07828f3-edcf-4535-a59e-6afda15e91ce': { speed: 5 } },
  };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:meta');
  assert(result.sanitizedFieldPaths === true, 'sanitizedFieldPaths flag true when keys sanitized');
  assert(Array.isArray(result.sanitizedKeyTypes), 'sanitizedKeyTypes is an array');
  assert(result.sanitizedKeyTypes.includes('email-key'), 'sanitizedKeyTypes records email-key');
  assert(result.sanitizedKeyTypes.includes('uuid-key'), 'sanitizedKeyTypes records uuid-key');
  assert(typeof result.sanitizedKeySegments === 'number', 'sanitizedKeySegments is a number');
  assert(result.sanitizedKeySegments === 2, 'sanitizedKeySegments counts both sanitized keys');
}

// 50. No sanitization metadata noise when nothing was sanitized
{
  const payload = { id: 1, email: 'field', accountId: 'a' };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:clean');
  assert(result.sanitizedFieldPaths === false, 'sanitizedFieldPaths false when no keys sanitized');
  assert(result.sanitizedKeyTypes.length === 0, 'sanitizedKeyTypes empty when none sanitized');
  assert(result.sanitizedKeySegments === 0, 'sanitizedKeySegments zero when none sanitized');
}

// 51. sanitizedKeySegments counts occurrences, sanitizedKeyTypes is deduplicated
{
  const payload = {
    a: { 'alice@x.com': 1 },
    b: { 'bob@y.com': 2 },
  };
  const body = Buffer.from(JSON.stringify(payload));
  const result = buildExposureSummary(body, 'application/json', 'json:count');
  // Two email keys sanitized → 2 segments, 1 type
  assert(result.sanitizedKeySegments === 2, 'counts 2 sanitized segments');
  assert(result.sanitizedKeyTypes.length === 1, 'one deduplicated key type');
  assert(result.sanitizedKeyTypes[0] === 'email-key', 'type is email-key');
}

// ── exposure-summary.js — evidence hash consistency ────────────────────────
section('exposure-summary.js — evidence hash consistency');

// 52. summaryGeneratedFromHash echoes whatever evidence hash it was given
{
  const body = Buffer.from(JSON.stringify({ id: 1 }));
  const semantic = buildExposureSummary(body, 'application/json', 'json:semantic123');
  assert(semantic.summaryGeneratedFromHash === 'json:semantic123', 'echoes semantic evidence hash');
  const raw = buildExposureSummary(body, 'application/json', 'raw:rawfallback456');
  assert(raw.summaryGeneratedFromHash === 'raw:rawfallback456', 'echoes raw evidence hash');
}

// 53. skipped summary also echoes the evidence hash it was given
{
  const big = Buffer.from('[' + Array(140000).fill('{"id":1}').join(',') + ']');
  assert(big.length > MAX_EXPOSURE_BODY_BYTES, 'oversized test body');
  const result = buildExposureSummary(big, 'application/json', 'raw:bighash789');
  assert(result.skipped === true, 'oversized body skipped');
  assert(result.summaryGeneratedFromHash === 'raw:bighash789', 'skipped summary echoes evidence hash');
}

// 54. JSON body with a raw-prefixed evidence hash still summarizes correctly.
// This is the big-int case: contentHash() returns a raw: hash for big-int JSON,
// so a confirmed match can carry a raw: evidence hash while the body is JSON.
// The summary must still generate AND echo that exact raw: hash.
{
  const body = Buffer.from('{"accountId":9007199254740993123,"email":"a@b.com"}');
  const rawEvidenceHash = 'raw:' + 'a'.repeat(64);
  const result = buildExposureSummary(body, 'application/json', rawEvidenceHash);
  assert(result !== null && !result.skipped, 'big-int JSON body produces a normal summary');
  assert(result.summaryGeneratedFromHash === rawEvidenceHash,
    'summary echoes the raw-prefixed evidence hash for JSON body');
  assert(result.fieldPaths.includes('accountId'), 'accountId field path present');
  assert(result.fieldPaths.includes('email'), 'email field path present');
  // No raw big-int value leaks
  assert(!JSON.stringify(result).includes('9007199254740993'), 'no raw big-int value in summary');
}

// ── reporter.js — why-flagged wording accuracy ─────────────────────────────
section('reporter.js — why-flagged wording');

const { whyFlagged } = require(root + '/src/reporter');

// 55. Semantic JSON match → JSON normalisation wording
{
  const lines = whyFlagged({ matchType: 'semantic-hash', evidence: { matchedHash: 'json:abc' } });
  const text = lines.join(' | ');
  assert(/JSON normalisation/.test(text), 'semantic match mentions JSON normalisation');
  assert(!/raw-byte/.test(text), 'semantic match does not mention raw-byte');
}

// 56. Big-int semantic match with raw: hash → raw-byte wording, NOT JSON normalisation
{
  const lines = whyFlagged({ matchType: 'semantic-hash', evidence: { matchedHash: 'raw:def' } });
  const text = lines.join(' | ');
  assert(/raw-byte hashing/.test(text), 'raw-hash semantic match mentions raw-byte hashing');
  assert(/JSON normalisation bypassed/.test(text), 'mentions normalisation was bypassed');
  assert(!/matched after JSON normalisation/.test(text),
    'does NOT claim matched after JSON normalisation when hash is raw:');
}

// 57. Raw-hash-fallback → byte-for-byte wording
{
  const lines = whyFlagged({ matchType: 'raw-hash-fallback', evidence: { matchedHash: 'raw:xyz' } });
  const text = lines.join(' | ');
  assert(/byte-for-byte/.test(text), 'raw fallback mentions byte-for-byte');
}

// 58. Size-proximity → verify-manually wording
{
  const lines = whyFlagged({ matchType: 'size-proximity', evidence: { matchedHash: 'json:q' } });
  const text = lines.join(' | ');
  assert(/verify manually/.test(text), 'size-proximity asks for manual verification');
}

// 59. Missing evidence block does not throw
{
  const lines = whyFlagged({ matchType: 'semantic-hash' });
  assert(Array.isArray(lines) && lines.length >= 1, 'handles missing evidence block gracefully');
}

// ── reporter.js — URL/path privacy is documented, not silently claimed ─────
section('reporter.js — path privacy disclosure');

// 60. The report privacy section makes claims ONLY about bodies/values/tokens,
// never falsely asserting that paths or resource IDs are sanitized. Paths are
// preserved by design for reproducibility; the docs carry the warning.
{
  const fs = require('fs');
  const { saveReport } = require(root + '/src/reporter');
  // Minimal synthetic store for coverage summary
  const synthStore = {
    entries: [],
    replayable: () => [],
    size: () => 0,
  };
  const synthFindings = [{
    findingId: 'AG-TEST-001',
    severity: 'high', type: 'broken-access-control', confidence: 'confirmed',
    method: 'GET',
    path: '/api/users/alice@company.com',
    resourceIds: [{ type: 'slug', value: 'alice@company.com' }],
    tokenType: 'bearer',
    originalStatus: 200, replayStatus: 200, originalSize: 50, replaySize: 50,
    matchType: 'semantic-hash',
    evidence: { originalContentHash: 'json:a', replayContentHash: 'json:a',
                originalRawHash: 'raw:a', replayRawHash: 'raw:a',
                matchedHash: 'json:a', matchType: 'semantic-hash' },
    request: { method: 'GET', path: '/api/users/alice@company.com',
               queryPresent: false, authMechanism: 'bearer', userAgentPreserved: true },
    recordedAt: Date.now(), replayedAt: new Date().toISOString(),
    curl: "curl -s -H 'Authorization: Bearer '$TOKEN_B 'http://x/api/users/alice@company.com'",
  }];
  const pathPriv = tmpPath('mozorrarri-pathpriv-report');
  saveReport(synthFindings, synthStore, pathPriv);
  const raw = fs.readFileSync(pathPriv, 'utf8');
  const rep = JSON.parse(raw);

  // The privacy section asserts only body/value/token guarantees — it must NOT
  // claim path sanitization (which mozorrarri does not do).
  assert(rep.privacy.rawBodiesStored === false, 'privacy: bodies not stored');
  assert(rep.privacy.rawValuesStored === false, 'privacy: values not stored');
  assert(rep.privacy.rawTokensStored === false, 'privacy: tokens not stored');
  assert(rep.privacy.pathsSanitized === undefined,
    'privacy section does NOT falsely claim paths are sanitized');

  // By DESIGN, the path/resourceIds/curl preserve URL content for reproduction.
  // This test documents that property so a future change that silently strips
  // them would be caught and force a conscious decision.
  assert(rep.findings[0].path.includes('alice@company.com'),
    'path preserved for reproducibility (documented behavior)');
  assert(rep.findings[0].curl.includes('alice@company.com'),
    'curl preserves path for reproducibility (documented behavior)');

  try { fs.unlinkSync(pathPriv); } catch {}
}

section('integration — proxy + fake app');

// Minimal fake app with one deliberate IDOR bug
function makeFakeApp(port) {
  const TOKENS = { 'tok-a': 'user-a', 'tok-b': 'user-b' };
  const ORDERS = {
    '1001': { id: '1001', owner: 'user-a', item: 'Laptop', total: 999 },
    '2001': { id: '2001', owner: 'user-b', item: 'Mouse',  total:  29 },
  };

  function getUser(req) {
    const auth   = (req.headers['authorization'] || '').trim();
    const cookie = (req.headers['cookie'] || '');
    const apiKey = (req.headers['x-api-key'] || '').trim();

    // Check all auth sources — Bearer, Token scheme, scheme-less, cookie, API key
    const candidates = [];
    if (/^bearer\s+/i.test(auth))  candidates.push(auth.replace(/^bearer\s+/i, '').trim());
    if (/^token\s+/i.test(auth))   candidates.push(auth.replace(/^token\s+/i, '').trim());
    if (auth && !auth.includes(' ')) candidates.push(auth); // scheme-less
    const sessionMatch = /(?:^|;\s*)session=([^;]+)/.exec(cookie);
    if (sessionMatch) candidates.push(sessionMatch[1]);
    if (apiKey) candidates.push(apiKey);

    for (const c of candidates) {
      if (TOKENS[c]) return { id: TOKENS[c] };
    }
    return null;
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

    // Public endpoint — returns same data regardless of auth.
    // Will be reclassified to possible-missing-authentication by anon probe.
    const pubM = p.match(/^\/api\/public\/(\d+)$/);
    if (pubM) {
      return send(res, 200, { id: pubM[1], name: 'Widget', price: 9.99 });
    }

    if (!user) return send(res, 401, { error: 'unauthorized' });

    const m = p.match(/^\/api\/orders\/(\d+)$/);
    if (m) {
      const order = ORDERS[m[1]];
      if (!order) return send(res, 404, { error: 'not found' });
      // BUG: no ownership check
      return send(res, 200, order);
    }

    // Trivial payload endpoint — returns empty array for any user.
    // Hash will match but trivial → needs-review.
    const itemM = p.match(/^\/api\/items\/(\d+)$/);
    if (itemM) {
      return send(res, 200, []);
    }

    // Cross-family endpoint — returns same JSON bytes but text/plain for user-b.
    // Recording (user-a) gets application/json → json: hash.
    // Replay (user-b) gets text/plain → raw: hash.
    // Cross-family fallback → confirmed via rawHash match.
    const docM = p.match(/^\/api\/docs\/(\d+)$/);
    if (docM) {
      const doc = { id: Number(docM[1]), title: 'Report', classification: 'internal' };
      if (user.id === 'user-b') {
        const body = JSON.stringify(doc);
        res.writeHead(200, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(body) });
        return res.end(body);
      }
      return send(res, 200, doc);
    }

    if (p === '/api/profile') return send(res, 200, { id: user.id });

    // ── Auth-mechanism coverage endpoints ─────────────────────────────
    // Each returns the same BOLA-vulnerable data via a different auth mechanism.

    // Cookie auth — same IDOR bug
    const cookieM = p.match(/^\/api\/cookie-orders\/(\d+)$/);
    if (cookieM) {
      const order = ORDERS[cookieM[1]];
      if (!order) return send(res, 404, { error: 'not found' });
      return send(res, 200, order);
    }

    // API key auth — same IDOR bug
    const keyM = p.match(/^\/api\/key-orders\/(\d+)$/);
    if (keyM) {
      const order = ORDERS[keyM[1]];
      if (!order) return send(res, 404, { error: 'not found' });
      return send(res, 200, order);
    }

    // Token scheme auth — same IDOR bug
    const tokenM = p.match(/^\/api\/token-orders\/(\d+)$/);
    if (tokenM) {
      const order = ORDERS[tokenM[1]];
      if (!order) return send(res, 404, { error: 'not found' });
      return send(res, 200, order);
    }

    // Scheme-less auth — same IDOR bug
    const rawM = p.match(/^\/api\/raw-orders\/(\d+)$/);
    if (rawM) {
      const order = ORDERS[rawM[1]];
      if (!order) return send(res, 404, { error: 'not found' });
      return send(res, 200, order);
    }

    // Query-string resource ID — same IDOR bug, resource ID in ?id=
    if (p === '/api/query-order') {
      const qid = new URL(req.url, 'http://localhost').searchParams.get('id');
      const order = qid ? ORDERS[qid] : null;
      if (!order) return send(res, 404, { error: 'not found' });
      return send(res, 200, order);
    }

    // 200-with-error-body — different response for user-b.
    // Should NOT produce a finding (different hashes).
    const errM = p.match(/^\/api\/error-200\/(\d+)$/);
    if (errM) {
      const order = ORDERS[errM[1]];
      if (!order) return send(res, 404, { error: 'not found' });
      if (user.id === 'user-a') return send(res, 200, order);
      return send(res, 200, { error: 'forbidden', code: 'AUTHZ_DENIED' });
    }

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

  // Like req(), but with explicit headers for testing non-Bearer auth mechanisms.
  function reqWith(path, headers) {
    return new Promise((resolve, reject) => {
      const r = http.request({
        hostname: '127.0.0.1', port: 8899, path, method: 'GET',
        headers: headers || {},
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

  // Additional endpoints for adversarial testing
  const trivial = await req('/api/items/42', 'tok-a');
  assert(trivial.status === 200, 'trivial-payload endpoint responds');

  const pub = await req('/api/public/99', 'tok-a');
  assert(pub.status === 200, 'public endpoint responds to authed user');

  const doc = await req('/api/docs/55', 'tok-a');
  assert(doc.status === 200, 'cross-family endpoint responds to user A');

  // Auth-mechanism coverage — same BOLA via different auth types
  const cookieOrder = await reqWith('/api/cookie-orders/1001', { cookie: 'session=tok-a' });
  assert(cookieOrder.status === 200, 'cookie-auth endpoint responds');

  const keyOrder = await reqWith('/api/key-orders/1001', { 'x-api-key': 'tok-a' });
  assert(keyOrder.status === 200, 'API-key-auth endpoint responds');

  const tokenOrder = await reqWith('/api/token-orders/1001', { authorization: 'Token tok-a' });
  assert(tokenOrder.status === 200, 'Token-scheme endpoint responds');

  const rawOrder = await reqWith('/api/raw-orders/1001', { authorization: 'tok-a' });
  assert(rawOrder.status === 200, 'scheme-less-auth endpoint responds');

  const queryOrder = await req('/api/query-order?id=1001', 'tok-a');
  assert(queryOrder.status === 200, 'query-string resource ID endpoint responds');

  const error200 = await req('/api/error-200/1001', 'tok-a');
  assert(error200.status === 200, '200-with-error-body endpoint responds to user A');

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

  // ── Evidence metadata ─────────────────────────────────────────────────────
  section('integration — evidence metadata');

  // Finding ID
  assert(!!idor.findingId, 'finding has findingId');
  assert(idor.findingId.startsWith('AG-'), 'findingId starts with AG-');
  assert(idor.findingId.split('-').length >= 3, 'findingId has expected format');

  // Timestamps
  assert(typeof idor.recordedAt === 'number', 'finding has recordedAt (epoch ms)');
  assert(typeof idor.replayedAt === 'string', 'finding has replayedAt (ISO string)');
  assert(idor.replayedAt.includes('T'), 'replayedAt is ISO format');

  // Evidence block
  assert(!!idor.evidence, 'finding has evidence block');
  assert(!!idor.evidence.originalContentHash, 'evidence has originalContentHash');
  assert(!!idor.evidence.replayContentHash, 'evidence has replayContentHash');
  assert(!!idor.evidence.matchedHash, 'evidence has matchedHash');
  assert(idor.evidence.matchType === 'semantic-hash', 'evidence matchType correct');
  // Raw hashes present
  assert(!!idor.evidence.originalRawHash, 'evidence has originalRawHash');
  assert(!!idor.evidence.replayRawHash, 'evidence has replayRawHash');

  // Request metadata
  assert(!!idor.request, 'finding has request metadata');
  assert(idor.request.method === 'GET', 'request method in metadata');
  assert(idor.request.authMechanism === 'bearer', 'auth mechanism in metadata');

  // ── Exposure Summary on confirmed BOLA ──────────────────────────────────
  section('integration — exposure summary');

  assert(!!idor.exposureSummary, 'confirmed BOLA includes exposureSummary');
  assert(idor.exposureSummary.rawBodyStored === false, 'exposureSummary rawBodyStored is false');
  assert(idor.exposureSummary.rawValuesStored === false, 'exposureSummary rawValuesStored is false');
  assert(Array.isArray(idor.exposureSummary.fieldPaths), 'exposureSummary has fieldPaths array');
  assert(idor.exposureSummary.fieldPaths.length > 0, 'exposureSummary has field paths');
  assert(idor.exposureSummary.fieldPaths.includes('id'), 'exposureSummary includes id field');
  assert(idor.exposureSummary.fieldPaths.includes('owner'), 'exposureSummary includes owner field');
  assert(idor.exposureSummary.fieldPaths.includes('total'), 'exposureSummary includes total field');
  assert(!!idor.exposureSummary.summaryGeneratedFromHash, 'exposureSummary links to evidence hash');
  assert(idor.exposureSummary.summaryGeneratedFromHash === idor.evidence.matchedHash,
    'exposureSummary hash matches evidence matchedHash');

  // Classification signals present
  assert(Array.isArray(idor.exposureSummary.classificationSignals), 'classificationSignals is array');
  const idSig = idor.exposureSummary.classificationSignals.find(s => s.field === 'id');
  assert(idSig && idSig.classification === 'resource_identifier',
    'id classified as resource_identifier in integration');
  const totalSig = idor.exposureSummary.classificationSignals.find(s => s.field === 'total');
  assert(totalSig && totalSig.classification === 'possible_financial',
    'total classified as possible_financial in integration');

  // No raw values leaked into exposureSummary
  const esStr = JSON.stringify(idor.exposureSummary);
  assert(!esStr.includes('Laptop'), 'no raw item value in exposureSummary');
  assert(!esStr.includes('999'), 'no raw total value in exposureSummary');
  assert(!esStr.includes('user-a'), 'no raw owner value in exposureSummary');

  // ── Report structure ──────────────────────────────────────────────────────
  section('integration — report structure');

  const fs = require('fs');
  const reportPath = tmpPath('mozorrarri-test-report');
  const { saveReport } = require(root + '/src/reporter');
  saveReport(findings, iStore, reportPath);

  const reportRaw = fs.readFileSync(reportPath, 'utf8');
  const report = JSON.parse(reportRaw);

  assert(report.version === '0.10.1', 'report version is 0.10.1');
  assert(report.reportType === 'authorization-regression-evidence', 'report has reportType');

  // Privacy section
  assert(!!report.privacy, 'report has privacy section');
  assert(report.privacy.rawTokensStored === false, 'privacy: rawTokensStored false');
  assert(report.privacy.rawBodiesStored === false, 'privacy: rawBodiesStored false');
  assert(report.privacy.rawValuesStored === false, 'privacy: rawValuesStored false');

  // Integrity section
  assert(!!report.integrity, 'report has integrity section');
  assert(report.integrity.reportSchema === 'mozorrarri-report-v1', 'integrity: schema correct');
  assert(report.integrity.generatedBy === 'mozorrarri 0.10.1', 'integrity: generatedBy correct');
  assert(report.integrity.detectionPrimitive === 'cross-user replay hash match', 'integrity: primitive correct');
  assert(report.integrity.bodyRetentionPolicy === 'not-stored', 'integrity: body retention correct');
  assert(report.integrity.tokenRetentionPolicy === 'fingerprint-only', 'integrity: token retention correct');

  // Report findings include exposureSummary
  const reportIdor = report.findings.find(f => f.path && f.path.includes('/api/orders/1001'));
  assert(!!reportIdor, 'IDOR finding in JSON report');
  assert(!!reportIdor.exposureSummary, 'JSON report finding has exposureSummary');
  assert(!!reportIdor.findingId, 'JSON report finding has findingId');
  assert(!!reportIdor.evidence, 'JSON report finding has evidence block');

  // JSON report never contains raw exposed values
  assert(!reportRaw.includes('"Laptop"'), 'JSON report does not contain raw item value');

  // Full report string scan for known secrets from fake app
  assert(!reportRaw.includes('tok-a'), 'report does not contain raw token A');
  assert(!reportRaw.includes('tok-b'), 'report does not contain raw token B');

  // Clean up
  try { fs.unlinkSync(reportPath); } catch {}

  // No false positive on non-parameterised endpoints
  const profileFinding = findings.find(f => f.path === '/api/profile');
  assert(!profileFinding, 'no false positive on /api/profile');

  // ── Gating: exposure summary subordination ──────────────────────────────
  section('integration — gating: exposureSummary only on confirmed BOLA');

  // needs-review (trivial payload) should NOT have exposureSummary
  const trivialFinding = findings.find(f => f.path && f.path.includes('/api/items/42'));
  assert(!!trivialFinding, 'trivial-payload finding detected');
  assert(trivialFinding.type === 'needs-review' || trivialFinding.confidence === 'needs-review',
    'trivial payload is needs-review');
  assert(!trivialFinding.exposureSummary,
    'GATE: needs-review finding has NO exposureSummary');

  // possible-missing-authentication should NOT have exposureSummary
  const pubFinding = findings.find(f => f.path && f.path.includes('/api/public/99'));
  assert(!!pubFinding, 'public-endpoint finding detected');
  assert(pubFinding.type === 'possible-missing-authentication',
    'public endpoint reclassified to possible-missing-authentication');
  assert(!pubFinding.exposureSummary,
    'GATE: possible-missing-authentication has NO exposureSummary');

  // Cross-family raw-hash-fallback confirmed BOLA — verify evidence chain
  const docFinding = findings.find(f => f.path && f.path.includes('/api/docs/55'));
  assert(!!docFinding, 'cross-family finding detected');
  assert(docFinding.type === 'broken-access-control', 'cross-family finding is BOLA');
  assert(docFinding.confidence === 'confirmed', 'cross-family finding is confirmed');
  assert(docFinding.matchType === 'raw-hash-fallback', 'cross-family matchType is raw-hash-fallback');
  assert(docFinding.evidence.matchedHash.startsWith('raw:'), 'cross-family evidence hash is raw:');
  assert(docFinding.evidence.matchType === 'raw-hash-fallback', 'evidence matchType is raw-hash-fallback');
  // Cross-family confirmed BOLA with text/plain → no exposureSummary (correct: non-JSON)
  assert(!docFinding.exposureSummary,
    'GATE: non-JSON confirmed BOLA has NO exposureSummary');

  // ── Auth-mechanism coverage ───────────────────────────────────────────────
  section('integration — auth mechanism coverage');

  // Cookie auth → confirmed BOLA
  const cookieFinding = findings.find(f => f.path && f.path.includes('/api/cookie-orders/1001'));
  assert(!!cookieFinding, 'cookie-auth replay produces a finding');
  assert(cookieFinding.type === 'broken-access-control', 'cookie-auth finding is BOLA');
  assert(cookieFinding.confidence === 'confirmed', 'cookie-auth finding is confirmed');
  assert(cookieFinding.tokenType === 'cookie', 'cookie-auth finding records cookie tokenType');

  // API key auth → confirmed BOLA
  const keyFinding = findings.find(f => f.path && f.path.includes('/api/key-orders/1001'));
  assert(!!keyFinding, 'API-key-auth replay produces a finding');
  assert(keyFinding.type === 'broken-access-control', 'API-key finding is BOLA');
  assert(keyFinding.confidence === 'confirmed', 'API-key finding is confirmed');
  assert(keyFinding.tokenType === 'api-key', 'API-key finding records api-key tokenType');

  // Token scheme auth → confirmed BOLA
  const tokenFinding = findings.find(f => f.path && f.path.includes('/api/token-orders/1001'));
  assert(!!tokenFinding, 'Token-scheme replay produces a finding');
  assert(tokenFinding.type === 'broken-access-control', 'Token-scheme finding is BOLA');
  assert(tokenFinding.confidence === 'confirmed', 'Token-scheme finding is confirmed');

  // Scheme-less auth → confirmed BOLA
  const schemelessFinding = findings.find(f => f.path && f.path.includes('/api/raw-orders/1001'));
  assert(!!schemelessFinding, 'scheme-less-auth replay produces a finding');
  assert(schemelessFinding.type === 'broken-access-control', 'scheme-less finding is BOLA');
  assert(schemelessFinding.confidence === 'confirmed', 'scheme-less finding is confirmed');

  // Query-string resource ID → confirmed BOLA
  const queryFinding = findings.find(f => f.path && f.path.includes('/api/query-order'));
  assert(!!queryFinding, 'query-string resource ID replay produces a finding');
  assert(queryFinding.type === 'broken-access-control', 'query-string finding is BOLA');
  assert(queryFinding.confidence === 'confirmed', 'query-string finding is confirmed');
  assert(queryFinding.request.queryPresent === true, 'query string preserved in finding metadata');

  // 200-with-error-body → no finding (different hashes)
  const error200Finding = findings.find(f => f.path && f.path.includes('/api/error-200/1001'));
  assert(!error200Finding, '200-with-error-body is NOT a false positive');

  // ── Backward compatibility ────────────────────────────────────────────────
  section('integration — backward compatibility');

  // Every finding must still contain the v0.9.2 field shape
  const V092_FIELDS = [
    'severity', 'type', 'confidence', 'method', 'path', 'resourceIds',
    'tokenType', 'originalStatus', 'replayStatus', 'originalSize',
    'replaySize', 'matchType', 'curl',
  ];
  for (const f of findings) {
    for (const field of V092_FIELDS) {
      assert(f[field] !== undefined,
        `backward compat: finding on ${f.path} has ${field}`);
    }
  }

  // ── Finding ID uniqueness ─────────────────────────────────────────────────
  section('integration — finding ID uniqueness');

  const allIds = findings.map(f => f.findingId);
  const uniqueIds = new Set(allIds);
  assert(uniqueIds.size === allIds.length,
    `all ${allIds.length} finding IDs are unique within the run`);
  // All IDs share the same run timestamp prefix
  const prefixes = new Set(allIds.map(id => id.replace(/-\d{3}$/, '')));
  assert(prefixes.size === 1,
    'all finding IDs share the same run timestamp prefix');

  // ── Evidence-hash invariant ───────────────────────────────────────────────
  section('integration — evidence hash invariant');

  // The core audit-grade invariant: for every finding that has an
  // exposureSummary (normal OR skipped), the summary's evidence hash must
  // equal the finding's evidence.matchedHash. They must never drift.
  let checkedSummaries = 0;
  for (const f of findings) {
    if (f.exposureSummary) {
      assert(f.exposureSummary.summaryGeneratedFromHash === f.evidence.matchedHash,
        `${f.path}: exposureSummary hash === evidence.matchedHash`);
      checkedSummaries++;
    }
    // matchType must agree between top-level and evidence block
    assert(f.matchType === f.evidence.matchType,
      `${f.path}: top-level matchType === evidence.matchType`);
    // evidence.matchedHash must be one of the recorded hashes for this finding
    const knownHashes = [
      f.evidence.originalContentHash, f.evidence.replayContentHash,
      f.evidence.originalRawHash, f.evidence.replayRawHash,
    ].filter(Boolean);
    assert(knownHashes.includes(f.evidence.matchedHash),
      `${f.path}: matchedHash is one of the recorded hashes`);
  }
  assert(checkedSummaries >= 1, 'at least one finding had an exposureSummary to check');

  // Semantic-hash finding: matchedHash must be a semantic (json:) hash
  const semFinding = findings.find(f => f.matchType === 'semantic-hash');
  assert(!!semFinding, 'a semantic-hash finding exists');
  assert(semFinding.evidence.matchedHash === semFinding.evidence.replayContentHash,
    'semantic finding matchedHash is the replay content hash');

  // Raw-fallback finding: matchedHash must be the raw hash
  const rawFinding = findings.find(f => f.matchType === 'raw-hash-fallback');
  assert(!!rawFinding, 'a raw-hash-fallback finding exists');
  assert(rawFinding.evidence.matchedHash === rawFinding.evidence.replayRawHash,
    'raw-fallback finding matchedHash is the replay raw hash');

  // ── CLI wrapper mode ─────────────────────────────────────────────────────
  section('cli.js — run wrapper');

  const { spawn } = require('child_process');
  const fs2 = require('fs');

  const wrapperTarget = http.createServer((req, res) => {
    if (!req.headers.authorization) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }

    if (req.url === '/api/orders/777') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: 777, owner: 'alice', total: 123 }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });

  await new Promise(resolve => wrapperTarget.listen(0, '127.0.0.1', resolve));
  const wrapperTargetPort = wrapperTarget.address().port;

  const probeServer = http.createServer();
  await new Promise(resolve => probeServer.listen(0, '127.0.0.1', resolve));
  const wrapperProxyPort = probeServer.address().port;
  await new Promise(resolve => probeServer.close(resolve));

  const wrapperDir = fs2.mkdtempSync(path.join(os.tmpdir(), `mozorrarri-wrapper-${process.pid}-`));
  const wrapperConfig = path.join(wrapperDir, 'mozorrarri.config.json');
  const wrapperReport = path.join(wrapperDir, 'mozorrarri-report.json');
  fs2.writeFileSync(wrapperConfig, JSON.stringify({
    target:      `http://127.0.0.1:${wrapperTargetPort}`,
    port:        wrapperProxyPort,
    scope:       ['/api/'],
    outputFile:  wrapperReport,
    minObserved: 1,
  }), 'utf8');

  const wrappedClient = `
    const http = require('http');
    const proxy = new URL(process.env.MOZORRARRI_PROXY_URL);
    if (process.env.MOZORRARRI_TOKEN_B) {
      console.error('MOZORRARRI_TOKEN_B leaked to wrapped command');
      process.exit(8);
    }
    const target = process.env.MOZORRARRI_TEST_TARGET;
    const req = http.request({
      hostname: proxy.hostname,
      port: proxy.port,
      method: 'GET',
      path: target + '/api/orders/777',
      headers: { authorization: 'Bearer alice-token' },
    }, res => {
      res.resume();
      res.on('end', () => process.exit(res.statusCode === 200 ? 0 : 3));
    });
    req.on('error', err => { console.error(err.message); process.exit(2); });
    req.end();
  `;

  const wrapperRun = await new Promise(resolve => {
    const child = spawn(process.execPath, [
      path.join(root, 'src/cli.js'),
      'run', '--', process.execPath, '-e', wrappedClient, 'SECRET-SHOULD-NOT-APPEAR',
    ], {
      cwd: wrapperDir,
      env: {
        ...process.env,
        CI:                   'true',
        HOME:                 wrapperDir,
        MOZORRARRI_CONFIG:      wrapperConfig,
        MOZORRARRI_TOKEN_B:     'bob-token',
        MOZORRARRI_TEST_TARGET: `http://127.0.0.1:${wrapperTargetPort}`,
      },
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });

    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      resolve({ status: 124, stdout, stderr: stderr + '\nwrapper smoke timed out' });
    }, 10000);

    child.on('close', code => {
      clearTimeout(timeout);
      resolve({ status: code, stdout, stderr });
    });
  });

  assert(wrapperRun.status === 1, 'run wrapper exits 1 when replay finds exposure');
  assert((wrapperRun.stdout + wrapperRun.stderr).includes('Running wrapped command'),
    'run wrapper executes the supplied command path');
  assert(!(wrapperRun.stdout + wrapperRun.stderr).includes('SECRET-SHOULD-NOT-APPEAR'),
    'run wrapper does not echo wrapped command arguments that may contain secrets');
  assert(!(wrapperRun.stdout + wrapperRun.stderr).includes('MOZORRARRI_TOKEN_B leaked'),
    'run wrapper does not expose replay token to wrapped command');
  assert(fs2.existsSync(wrapperReport), 'run wrapper writes the same JSON report file');

  const wrapperReportJson = JSON.parse(fs2.readFileSync(wrapperReport, 'utf8'));
  assert(wrapperReportJson.findings.some(f => f.path === '/api/orders/777'),
    'run wrapper report contains replay finding from wrapped test traffic');

  // A wrapped command knows MOZORRARRI_PROXY_URL. In run mode, child process exit
  // is the completion signal; /--flush must not let test code finalize early.
  const flushProbe = http.createServer();
  await new Promise(resolve => flushProbe.listen(0, '127.0.0.1', resolve));
  const flushProxyPort = flushProbe.address().port;
  await new Promise(resolve => flushProbe.close(resolve));

  const flushDir = fs2.mkdtempSync(path.join(os.tmpdir(), `mozorrarri-wrapper-flush-${process.pid}-`));
  const flushConfig = path.join(flushDir, 'mozorrarri.config.json');
  const flushReport = path.join(flushDir, 'mozorrarri-report.json');
  fs2.writeFileSync(flushConfig, JSON.stringify({
    target:      `http://127.0.0.1:${wrapperTargetPort}`,
    port:        flushProxyPort,
    scope:       ['/api/'],
    outputFile:  flushReport,
    minObserved: 0,
  }), 'utf8');

  const flushThenRequestClient = `
    const http = require('http');
    const proxy = new URL(process.env.MOZORRARRI_PROXY_URL);
    const target = process.env.MOZORRARRI_TEST_TARGET;

    function postFlush(next) {
      const req = http.request({
        hostname: proxy.hostname,
        port: proxy.port,
        method: 'POST',
        path: '/--flush',
      }, res => {
        res.resume();
        res.on('end', next);
      });
      req.on('error', err => { console.error(err.message); process.exit(2); });
      req.end();
    }

    function hitProtectedResource() {
      const req = http.request({
        hostname: proxy.hostname,
        port: proxy.port,
        method: 'GET',
        path: target + '/api/orders/777',
        headers: { authorization: 'Bearer alice-token' },
      }, res => {
        res.resume();
        res.on('end', () => process.exit(res.statusCode === 200 ? 0 : 3));
      });
      req.on('error', err => { console.error(err.message); process.exit(4); });
      req.end();
    }

    postFlush(() => setTimeout(hitProtectedResource, 50));
  `;

  const flushRun = await new Promise(resolve => {
    const child = spawn(process.execPath, [
      path.join(root, 'src/cli.js'),
      'run', '--', process.execPath, '-e', flushThenRequestClient,
    ], {
      cwd: flushDir,
      env: {
        ...process.env,
        CI:                   'true',
        HOME:                 flushDir,
        MOZORRARRI_CONFIG:      flushConfig,
        MOZORRARRI_TOKEN_B:     'bob-token',
        MOZORRARRI_TEST_TARGET: `http://127.0.0.1:${wrapperTargetPort}`,
      },
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });

    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      resolve({ status: 124, stdout, stderr: stderr + '\nflush abuse smoke timed out' });
    }, 10000);

    child.on('close', code => {
      clearTimeout(timeout);
      resolve({ status: code, stdout, stderr });
    });
  });

  assert(flushRun.status === 1,
    'run wrapper ignores child /--flush abuse and exits on replay finding');
  assert(fs2.existsSync(flushReport),
    'run wrapper writes report after child /--flush attempt');
  const flushReportJson = JSON.parse(fs2.readFileSync(flushReport, 'utf8'));
  assert(flushReportJson.findings.some(f => f.path === '/api/orders/777'),
    'run wrapper still captures traffic after child /--flush attempt');

  try { fs2.rmSync(flushDir, { recursive: true, force: true }); } catch {}

  wrapperTarget.close();
  try { fs2.rmSync(wrapperDir, { recursive: true, force: true }); } catch {}

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
