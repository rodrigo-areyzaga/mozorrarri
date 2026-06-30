'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// ShopLab automated demo
//
// One command. No setup. Under 90 seconds.
//
// What it does:
//   1. Starts ShopLab on port 3100
//   2. Starts mozorrarri proxy on port 8877
//   3. Exercises the API as Alice (user A)
//   4. Replays every request as Bob (user B)
//   5. Reports confirmed unauthorized data replays
//   6. Shuts everything down
// ─────────────────────────────────────────────────────────────────────────────

const root = __dirname + '/..';
const { SessionStore }              = require(root + '/src/session-store');
const { ProxyCore }                 = require(root + '/src/proxy');
const { runReplay }                 = require(root + '/src/replay');
const { printFindings, saveReport } = require(root + '/src/reporter');
const { verifyTarget, verifyScope } = require(root + '/src/safety');
const http = require('http');

const SHOPLAB_PORT = 3100;
const PROXY_PORT   = 8877;
const TARGET       = `http://127.0.0.1:${SHOPLAB_PORT}`;
const TOKEN_ALICE  = 'tok-alice';
const TOKEN_BOB    = 'tok-bob';

function req(port, path, token, method, body) {
  return new Promise((resolve, reject) => {
    const b = body ? JSON.stringify(body) : null;
    const r = http.request({
      hostname: '127.0.0.1', port, path,
      method:   method || 'GET',
      headers: {
        'content-type': 'application/json',
        ...(token ? { 'authorization': 'Bearer ' + token } : {}),
        ...(b     ? { 'content-length': Buffer.byteLength(b) } : {}),
      },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ s: res.statusCode, len: Buffer.concat(chunks).length }));
    });
    r.on('error', reject);
    r.setTimeout(5000, () => { r.destroy(); reject(new Error('timeout')); });
    if (b) r.write(b);
    r.end();
  });
}

async function run() {
  const divider = '═'.repeat(60);
  console.log('\n' + divider);
  console.log('  ShopLab × mozorrarri — demo');
  console.log(divider + '\n');

  // 1. Start ShopLab — explicitly call listen() since required as a module
  process.env.SHOPLAB_PORT = String(SHOPLAB_PORT);
  const shop = require(root + '/test/shoplab');
  await new Promise((resolve, reject) => {
    shop.once('error', reject);
    shop.listen(SHOPLAB_PORT, '127.0.0.1', resolve);
  });
  console.log(`[1/4] ShopLab ready   → http://127.0.0.1:${SHOPLAB_PORT}`);

  // 2. Start mozorrarri
  await verifyTarget(TARGET);
  verifyScope(['/api/']);

  const store = new SessionStore();
  const proxy = new ProxyCore({
    target:  TARGET,
    scope:   ['/api/'],
    exclude: ['/api/health', '/api/products', '/api/auth/'],
    store,
    logger:  { log: () => {}, error: console.error },
  });
  await proxy.listen(PROXY_PORT);
  console.log(`[2/4] mozorrarri ready  → http://127.0.0.1:${PROXY_PORT}`);

  // 3. Exercise as Alice through proxy
  console.log('[3/4] Running scenario as Alice...\n');
  const calls = [
    ['GET', '/api/me',                TOKEN_ALICE],
    ['GET', '/api/users/user-alice',  TOKEN_ALICE],
    ['GET', '/api/orders',            TOKEN_ALICE],
    ['GET', '/api/orders/ord-1001',   TOKEN_ALICE],
    ['GET', '/api/orders/ord-1002',   TOKEN_ALICE],
    ['GET', '/api/payment',           TOKEN_ALICE],
    ['GET', '/api/payment/pay-1',     TOKEN_ALICE],
    ['GET', '/api/documents',         TOKEN_ALICE],
    ['GET', '/api/documents/doc-101', TOKEN_ALICE],
  ];

  for (const [method, path, token] of calls) {
    const r = await req(PROXY_PORT, path, token, method);
    console.log(`  ${method.padEnd(6)} ${path.padEnd(36)} → ${r.s}`);
  }

  console.log(`\n  Recorded: ${store.size()} requests | Replayable: ${store.replayable().length}`);

  // 4. Replay as Bob
  console.log('\n[4/4] Replaying as Bob...');
  await proxy.close();

  const findings = await runReplay({
    store,
    targetUrl:   TARGET,
    secondToken: TOKEN_BOB,
    logger:      { log: () => {} },
  });

  printFindings(findings, store);
  saveReport(findings, store, 'shoplab-report.json');

  console.log(divider);
  const classes = new Set(findings.map(f => f.path.replace(/[a-z0-9-]+$/i, ":id"))).size;
  console.log(`  ${findings.length} unauthorized access attempts confirmed across ${classes} IDOR endpoint pattern${classes > 1 ? "s" : ""}.`);
  console.log(divider + '\n');

  shop.close();
  process.exit(findings.length > 0 ? 0 : 1);
}

run().catch(err => {
  console.error('\n[demo] Error:', err.message);
  process.exit(1);
});
