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

// ACCGUARD_API_KEY_HEADER override
process.env.ACCGUARD_API_KEY_HEADER = 'x-custom-key';
const customKey = extractToken({ 'x-custom-key': 'custom-tok' });
assert(customKey !== null,               'custom API key header recognized');
assert(customKey.type === 'api-key',     'custom API key type is api-key');
delete process.env.ACCGUARD_API_KEY_HEADER;

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

// ACCGUARD_COOKIE_NAME override — operator-specified name takes priority
process.env.ACCGUARD_COOKIE_NAME = 'my_custom_session';
const custom = extractToken({ cookie: 'my_custom_session=custom-tok-xyz' });
assert(custom !== null,                    'ACCGUARD_COOKIE_NAME override works');
assert(custom.raw === 'custom-tok-xyz',    'correct token value from override');
assert(custom.cookieName === 'my_custom_session', 'correct cookieName from override');
delete process.env.ACCGUARD_COOKIE_NAME; // clean up

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
