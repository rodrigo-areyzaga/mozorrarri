#!/usr/bin/env node
'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// accguard demo
//
// git clone https://github.com/rodrigo-areyzaga/accguard
// cd accguard
// node demo.js
//
// No install. No config. No accounts.
// Under 90 seconds from clone to first finding.
// ─────────────────────────────────────────────────────────────────────────────

const root = __dirname;
const { SessionStore }              = require(root + '/src/session-store');
const { ProxyCore }                 = require(root + '/src/proxy');
const { runReplay }                 = require(root + '/src/replay');
const { printFindings, saveReport } = require(root + '/src/reporter');
const { verifyTarget, verifyScope } = require(root + '/src/safety');
const http = require('http');

const VERSION      = '0.10.1';
const SHOPLAB_PORT = 3100;
const PROXY_PORT   = 8877;
const TARGET       = `http://127.0.0.1:${SHOPLAB_PORT}`;
const TOKEN_ALICE  = 'tok-alice';
const TOKEN_BOB    = 'tok-bob';

// ── HTTP helper ───────────────────────────────────────────────────────────────

function req(port, path, token, method) {
  return new Promise((resolve, reject) => {
    const r = http.request({
      hostname: '127.0.0.1', port, path,
      method:   method || 'GET',
      headers: {
        'content-type': 'application/json',
        ...(token ? { 'authorization': 'Bearer ' + token } : {}),
      },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ s: res.statusCode, len: Buffer.concat(chunks).length }));
    });
    r.on('error', reject);
    r.setTimeout(5000, () => { r.destroy(); reject(new Error('timeout')); });
    r.end();
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function run() {
  const line = '─'.repeat(58);

  console.log('\n' + line);
  console.log(`  accguard v${VERSION} — authorization regression testing`);
  console.log('  ShopLab demo · 4 hidden IDOR vulnerabilities');
  console.log(line + '\n');

  // 1. Start ShopLab — explicitly call listen() since we require it as a module
  process.env.SHOPLAB_PORT = String(SHOPLAB_PORT);
  const shop = require(root + '/test/shoplab');

  await new Promise((resolve, reject) => {
    shop.once('error', reject);
    shop.listen(SHOPLAB_PORT, '127.0.0.1', resolve);
  });

  console.log(`  ✓  ShopLab running   http://127.0.0.1:${SHOPLAB_PORT}`);
  console.log(`     Open it in your browser — looks like a normal shop.`);
  console.log(`     Four IDOR vulnerabilities are completely invisible in the UI.\n`);

  // 2. Start accguard proxy
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
  console.log(`  ✓  accguard proxy     http://127.0.0.1:${PROXY_PORT}\n`);

  // 3. Exercise the API as Alice — everything looks normal
  console.log(`  Running authenticated session as Alice...\n`);

  const calls = [
    ['/api/me',                TOKEN_ALICE, 'own profile'],
    ['/api/users/user-alice',  TOKEN_ALICE, 'own user record'],
    ['/api/orders',            TOKEN_ALICE, 'own order list'],
    ['/api/orders/ord-1001',   TOKEN_ALICE, 'order detail'],
    ['/api/orders/ord-1002',   TOKEN_ALICE, 'order detail'],
    ['/api/payment',           TOKEN_ALICE, 'own payment methods'],
    ['/api/payment/pay-1',     TOKEN_ALICE, 'payment detail'],
    ['/api/documents',         TOKEN_ALICE, 'own documents'],
    ['/api/documents/doc-101', TOKEN_ALICE, 'document detail'],
  ];

  for (const [path, token, label] of calls) {
    const r = await req(PROXY_PORT, path, token);
    console.log(`  ${r.s === 200 ? '✓' : '✗'}  ${label.padEnd(26)} ${r.s}`);
  }

  console.log(`\n  Observed: ${store.size()} requests · Replayable: ${store.replayable().length}\n`);

  // 4. Replay as Bob — find what the UI hides
  console.log(`  Replaying every request as Bob...\n`);
  await proxy.close();

  const findings = await runReplay({
    store,
    targetUrl:   TARGET,
    secondToken: TOKEN_BOB,
    logger:      { log: () => {} },
  });

  printFindings(findings, store);
  saveReport(findings, store, 'accguard-demo-report.json');

  // 5. Summary
  console.log(line);
  if (findings.length === 0) {
    console.log('  No unauthorized data replays detected.');
  } else {
    const classes = new Set(findings.map(f => f.path.replace(/[a-z0-9-]+$/i, ':id'))).size;
    console.log(`  ${findings.length} unauthorized access attempts confirmed across ${classes} IDOR endpoint pattern${classes > 1 ? 's' : ''}.`);
    console.log(`  Each finding above includes a curl command to reproduce it.`);
    console.log(`  Full report saved to accguard-demo-report.json`);
  }
  console.log(line + '\n');

  shop.close();
  process.exit(findings.length > 0 ? 0 : 1);
}

run().catch(err => {
  console.error('\n  Error:', err.message);
  console.error('  Make sure nothing is already running on ports 3100 or 8877.\n');
  process.exit(1);
});
