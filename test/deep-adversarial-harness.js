#!/usr/bin/env node
'use strict';

/**
 * mozorrarri — deep adversarial harness
 *
 * Targets the four real bugs found in the previous review round:
 *   1. hasBigInts false-triggering on float mantissas → raw: hash instead of json:
 *   2. Exponent-form unsafe integers not detected → hash collision
 *   3. Matrix params breaking resource-ID extraction → no replay candidate
 *   4. MongoDB ObjectIDs in query params not extracted → no replay candidate
 *
 * Plus deeper probes on each fix to verify it holds under adversarial input.
 */

const crypto = require('crypto');
const path   = require('path');

const root = path.join(__dirname, '..');

const { contentHash } = require(root + '/src/replay');
const { extractResourceIds } = require(root + '/src/session-store');

let passed = 0;
let failed = 0;
const failures = [];

function sec(name) {
  console.log(`\n── ${name} ${'─'.repeat(Math.max(0, 60 - name.length))}`);
}

function ok(name, result, detail = '') {
  if (result) {
    passed++;
    process.stdout.write(`  ✓  ${name}\n`);
  } else {
    failed++;
    const msg = `  ✗  ${name}${detail ? ' — ' + detail : ''}`;
    failures.push(msg);
    console.log(msg);
  }
}

function check(name, fn) {
  try {
    const r = fn();
    ok(name, r !== false);
  } catch (e) {
    ok(name, false, e.message);
  }
}

// ── 1. hasBigInts — float mantissa fix ───────────────────────────────────────

sec('BUG 1: hasBigInts float mantissa false trigger');

// Float mantissas must NOT trigger raw: fallback
const floatCases = [
  ['score field', '{"score":0.12345678901234567}'],
  ['price field', '{"price":19.999999999999998}'],
  ['lat/lng',     '{"lat":37.7749295123456789}'],
  ['ratio',       '{"ratio":0.3333333333333333}'],
  ['negative float', '{"v":-0.12345678901234567}'],
  ['float in array',  '[0.12345678901234567, 1.23456789012345678]'],
  ['multiple floats', '{"a":0.12345678901234,"b":0.98765432109876}'],
];

for (const [label, json] of floatCases) {
  const h = contentHash(Buffer.from(json), 'application/json');
  ok(`Float mantissa (${label}) hashes as json:`, h.startsWith('json:'),
    `got ${h.split(':')[0]}:`);
}

// Same data, same hash across runs — no false-negative from float mantissa
const body1 = Buffer.from('{"id":1,"score":0.12345678901234567,"name":"alice"}');
const body2 = Buffer.from('{"id":1,"score":0.12345678901234567,"name":"alice"}');
check('Identical JSON with float mantissa: same hash both times', () =>
  contentHash(body1, 'application/json') === contentHash(body2, 'application/json')
);

// Two different users, same protected data including a float field — must confirm
const aliceBody = Buffer.from('{"orderId":"ord-1","total":149.99999999999997,"owner":"alice"}');
const bobBody   = Buffer.from('{"orderId":"ord-1","total":149.99999999999997,"owner":"alice"}');
check('Alice and Bob get identical response with float field: same hash → finding fires', () =>
  contentHash(aliceBody, 'application/json') === contentHash(bobBody, 'application/json')
);

// Two DIFFERENT floats must produce different hashes
const f1 = Buffer.from('{"v":0.1234567890123456}');
const f2 = Buffer.from('{"v":0.1234567890123457}');
check('Different float values produce different hashes', () =>
  contentHash(f1, 'application/json') !== contentHash(f2, 'application/json')
);

// ── 2. hasBigInts — exponent forms ───────────────────────────────────────────

sec('BUG 1b: hasBigInts exponent-form unsafe integers');

// These two are semantically different IDs but JSON.parse rounds them to the same float
// They should trigger raw: fallback (exponent form of a big int)
const expUnsafe1 = Buffer.from('{"id":9007199254740993e0,"owner":"alice"}');
const expUnsafe2 = Buffer.from('{"id":9007199254740994e0,"owner":"alice"}');
const h1 = contentHash(expUnsafe1, 'application/json');
const h2 = contentHash(expUnsafe2, 'application/json');
ok('Exponent-form big int (9007199254740993e0) triggers raw: or distinct hashes',
  h1.startsWith('raw:') || h1 !== h2,
  `h1=${h1.split(':')[0]}:`
);

// Safe exponent forms — should NOT trigger raw:
const safeExp = [
  ['1e2 (=100)',     '{"count":1e2}'],
  ['2.5e3 (=2500)', '{"amount":2.5e3}'],
  ['1.718e15 — below MAX_SAFE', '{"ts":1.718e15}'],
];
for (const [label, json] of safeExp) {
  const h = contentHash(Buffer.from(json), 'application/json');
  check(`Safe exponent (${label}) hashes as json:`, () => h.startsWith('json:'));
}

// Actual unsafe exponent form — integer value > MAX_SAFE
const unsafeExpBody = Buffer.from('{"ts":9.007199254740993e15}');
const unsafeExpHash = contentHash(unsafeExpBody, 'application/json');
ok('Unsafe exponent (9.007199254740993e15 > MAX_SAFE) triggers raw:',
  unsafeExpHash.startsWith('raw:'), `got ${unsafeExpHash.split(':')[0]}:`
);

// Unsafe decimal integers — 9007199254740992.0 is mathematically an integer > MAX_SAFE
const unsafeDecimals = [
  ['9007199254740992.0', '{"id":9007199254740992.0}'],
  ['9007199254740993.0', '{"id":9007199254740993.0}'],
  ['-9007199254740993.0','{"id":-9007199254740993.0}'],
];
for (const [label, json] of unsafeDecimals) {
  const h = contentHash(Buffer.from(json), 'application/json');
  ok(`Unsafe decimal integer (${label}) triggers raw:`,
    h.startsWith('raw:'), `got ${h.split(':')[0]}:`
  );
}
// Two distinct unsafe decimals must not collide
const ud1 = Buffer.from('{"id":9007199254740992.0,"owner":"alice"}');
const ud2 = Buffer.from('{"id":9007199254740993.0,"owner":"alice"}');
check('Distinct unsafe decimal integers produce different hashes', () =>
  contentHash(ud1, 'application/json') !== contentHash(ud2, 'application/json')
);

// ── 3. Matrix params in extractResourceIds ────────────────────────────────────

sec('BUG 2: Matrix params breaking resource-ID extraction');

// Matrix params must be stripped before ID extraction
const matrixCases = [
  ['/api/orders/1001;v=1',               '1001',                   'integer'],
  ['/api/orders/ord-1001;jsessionid=abc', 'ord-1001',              'slug'],
  ['/api/users/user-alice;token=xyz',     'user-alice',            'slug'],
  ['/api/vehicles/507f1f77bcf86cd799439011;v=2', '507f1f77bcf86cd799439011', 'objectid'],
  ['/api/users/550e8400-e29b-41d4-a716-446655440000;expand=true', '550e8400-e29b-41d4-a716-446655440000', 'uuid'],
];

for (const [path, expectedValue, expectedType] of matrixCases) {
  const ids = extractResourceIds(path);
  ok(`Matrix param stripped: ${path.split('/').pop()} → ${expectedType} extracted`,
    ids.some(r => r.value === expectedValue && r.type === expectedType),
    `got: ${JSON.stringify(ids)}`
  );
}

// Matrix param on its own (no ID before it) should not produce false IDs
const noIdMatrix = extractResourceIds('/api/orders;v=1');
ok('Matrix param alone (no preceding ID) produces no resource ID', noIdMatrix.length === 0,
  `got: ${JSON.stringify(noIdMatrix)}`
);

// Multiple matrix params
const multiMatrix = extractResourceIds('/api/orders/1001;v=1;expand=true;token=abc');
ok('Multiple matrix params stripped: integer ID still extracted',
  multiMatrix.some(r => r.value === '1001'), `got: ${JSON.stringify(multiMatrix)}`
);

// ── 4. MongoDB ObjectID in query params ──────────────────────────────────────

sec('BUG 3: MongoDB ObjectID in query params not extracted');

const objectIdCases = [
  ['/api/orders?_id=507f1f77bcf86cd799439011',          '507f1f77bcf86cd799439011'],
  ['/api/orders?object_id=507f1f77bcf86cd799439011',    '507f1f77bcf86cd799439011'],
  ['/api/orders?objectId=507f1f77bcf86cd799439011',     '507f1f77bcf86cd799439011'],
  ['/api/orders?mongo_id=507f1f77bcf86cd799439011',     '507f1f77bcf86cd799439011'],
];

for (const [path, expectedId] of objectIdCases) {
  const ids = extractResourceIds(path);
  ok(`ObjectID in query param (${path.split('?')[1].split('=')[0]}) extracted`,
    ids.some(r => r.value === expectedId && r.type === 'objectid'),
    `got: ${JSON.stringify(ids)}`
  );
}

// ObjectID in path still works (regression check)
const pathObjectId = extractResourceIds('/api/vehicles/507f1f77bcf86cd799439011');
ok('ObjectID in path still extracted (regression)', pathObjectId.some(r => r.value === '507f1f77bcf86cd799439011'));

// All-digit 24-char string in query param should NOT be extracted as objectid
const allDigitQuery = extractResourceIds('/api/orders?_id=123456789012345678901234');
ok('All-digit 24-char string in query param not extracted as objectid',
  !allDigitQuery.some(r => r.type === 'objectid')
);

// ── 5. Extended query-param extraction ───────────────────────────────────────

sec('BUG 4: Query-param extraction — bracket notation, plural, camelCase, comma-sep');

const queryParamCases = [
  ['/api/orders?ids[]=1001',                        '1001',                   'integer', 'array bracket notation'],
  ['/api/orders?user_ids=42',                       '42',                     'integer', 'snake_case plural'],
  ['/api/orders?userIds=42',                        '42',                     'integer', 'camelCase plural'],
  ['/api/orders?filter[id]=1001',                   '1001',                   'integer', 'bracket filter[id]'],
  ['/api/orders?filter[order_id]=ord-1001',         'ord-1001',               'slug',    'bracket filter[order_id]'],
  ['/api/orders?filter[_id]=507f1f77bcf86cd799439011', '507f1f77bcf86cd799439011', 'objectid', 'bracket filter[_id] ObjectID'],
];

for (const [url, expectedVal, expectedType, label] of queryParamCases) {
  const ids = extractResourceIds(url);
  ok(`Query param (${label}) extracted`,
    ids.some(r => r.value === expectedVal && r.type === expectedType),
    `got: ${JSON.stringify(ids)}`
  );
}

// Comma-separated IDs — all should be extracted
const commaIds = extractResourceIds('/api/orders?ids=1001,1002,1003');
ok('Comma-separated IDs — first ID extracted', commaIds.some(r => r.value === '1001'));
ok('Comma-separated IDs — second ID extracted', commaIds.some(r => r.value === '1002'));
ok('Comma-separated IDs — third ID extracted', commaIds.some(r => r.value === '1003'));

// Non-ID params should still NOT be extracted
const nonIds = extractResourceIds('/api/orders?page=2&limit=10&sort=newest&format=json');
ok('Non-ID query params (page, limit, sort, format) not extracted', nonIds.length === 0,
  `got: ${JSON.stringify(nonIds)}`
);

sec('INTERACTION: matrix params + query params + ObjectID');

const combined = extractResourceIds('/api/vehicles/507f1f77bcf86cd799439011;v=2?mongo_id=aabbccddeeff001122334455');
ok('Matrix param stripped AND query ObjectID extracted in same URL',
  combined.some(r => r.value === '507f1f77bcf86cd799439011') &&
  combined.some(r => r.value === 'aabbccddeeff001122334455')
);

// ── 6. hasBigInts — quoted strings must never trigger ─────────────────────────

sec('REGRESSION: quoted strings with 16+ digits never trigger raw:');

const quotedBigDigits = [
  ['{"phone":"9007199254740993"}',     'quoted phone number'],
  ['{"ssn":"123456789012345678"}',     'quoted SSN-like'],
  ['{"token":"9999999999999999"}',     'quoted 16-digit token'],
  ['{"id":"9007199254740993","n":"x"}','quoted id alongside other fields'],
];

for (const [json, label] of quotedBigDigits) {
  const h = contentHash(Buffer.from(json), 'application/json');
  ok(`Quoted big digit string (${label}) → json: not raw:`,
    h.startsWith('json:'), `got ${h.split(':')[0]}:`
  );
}

// ── 7. contentHash determinism across all fixed cases ─────────────────────────

sec('DETERMINISM: fixed cases produce stable hashes across calls');

const deterministicCases = [
  '{"id":1,"score":0.99999999999999989,"name":"alice"}',
  '{"items":[{"id":1,"price":9.99},{"id":2,"price":19.99}]}',
  '{"ts":1718000000,"data":{"value":0.12345678901234567}}',
];

for (const json of deterministicCases) {
  const buf = Buffer.from(json);
  const h1 = contentHash(buf, 'application/json');
  const h2 = contentHash(buf, 'application/json');
  const h3 = contentHash(buf, 'application/json');
  ok(`Deterministic hash: ${json.slice(0, 40)}...`,
    h1 === h2 && h2 === h3, `h1=${h1.slice(0,20)} h2=${h2.slice(0,20)}`
  );
}

// ── Results ───────────────────────────────────────────────────────────────────

// ── 6. Huge exponent crash prevention ────────────────────────────────────────

sec('STABILITY: Huge JSON exponents must not crash contentHash');

const hugeExpCases = [
  ['1e999999999',      '{"v":1e999999999}'],
  ['1e-999999999',     '{"v":1e-999999999}'],
  ['9.1e999999999',   '{"v":9.1e999999999}'],
  ['-1e999999999',    '{"v":-1e999999999}'],
];

for (const [label, json] of hugeExpCases) {
  let result, crashed = false;
  try { result = contentHash(Buffer.from(json), 'application/json'); }
  catch (e) { crashed = true; }
  ok(`Huge exponent (${label}) does not crash`, !crashed, 'threw RangeError');
  if (!crashed) ok(`Huge exponent (${label}) returns valid hash`, result.startsWith('json:') || result.startsWith('raw:'));
}

const hugePos = contentHash(Buffer.from('{"id":1e999999999}'), 'application/json');
ok('Huge positive exponent triggers raw: fallback', hugePos.startsWith('raw:'), `got ${hugePos.split(':')[0]}:`);

const hugeNeg = contentHash(Buffer.from('{"v":1e-999999999}'), 'application/json');
ok('Huge negative exponent (tiny fraction) hashes as json:', hugeNeg.startsWith('json:'), `got ${hugeNeg.split(':')[0]}:`);

// ── 7. Tenant/org/project query ID extraction ─────────────────────────────────

sec('DETECTION: Tenant/org/project query param IDs');

const tenantCases = [
  ['/api/reports?tenant_id=42',               '42',         'integer', 'tenant_id'],
  ['/api/reports?tenantId=42',                '42',         'integer', 'tenantId camelCase'],
  ['/api/reports?orgId=42',                   '42',         'integer', 'orgId'],
  ['/api/reports?org_id=42',                  '42',         'integer', 'org_id'],
  ['/api/reports?project_id=prj-1001',        'prj-1001',   'slug',    'project_id'],
  ['/api/reports?projectId=prj-1001',         'prj-1001',   'slug',    'projectId'],
  ['/api/reports?ownerId=user-123',           'user-123',   'slug',    'ownerId'],
  ['/api/reports?workspaceId=42',             '42',         'integer', 'workspaceId'],
  ['/api/reports?organization_id=42',         '42',         'integer', 'organization_id'],
  ['/api/reports?memberId=42',                '42',         'integer', 'memberId'],
  ['/api/reports?group_id=42',               '42',         'integer', 'group_id'],
  ['/api/reports?company_id=42',             '42',         'integer', 'company_id'],
  ['/api/reports?filter[tenant_id]=t-123',   't-123',      'slug',    'bracket filter[tenant_id]'],
];
for (const [url, val, type, label] of tenantCases) {
  const ids = extractResourceIds(url);
  ok(`Tenant/org query (${label}) extracted`,
    ids.some(r => r.value === val && r.type === type),
    `got: ${JSON.stringify(ids)}`
  );
}
// comma-sep team_ids — both extracted
const tids = extractResourceIds('/api/reports?team_ids=42,43');
ok('team_ids comma-sep: both values extracted', tids.some(r => r.value === '42') && tids.some(r => r.value === '43'));

console.log('\n\n' + '═'.repeat(64));
console.log('  mozorrarri — deep adversarial harness results');
console.log('═'.repeat(64));
console.log(`  Passed: ${passed}`);
console.log(`  Failed: ${failed}`);

if (failures.length > 0) {
  console.log('\n  Failures:');
  for (const f of failures) console.log('  ' + f);
}

console.log('═'.repeat(64) + '\n');
process.exit(failed > 0 ? 1 : 0);
