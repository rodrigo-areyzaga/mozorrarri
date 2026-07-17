'use strict';

const http = require('http');
const { SessionStore } = require('./src/session-store');
const { ProxyCore } = require('./src/proxy');
const { runReplay } = require('./src/replay');
const { verifyTarget, verifyScope } = require('./src/safety');

const PORT = process.env.PORT || 3000;
const SHOPLAB_PORT = 3101;
const PROXY_PORT = 8878;
const TARGET = `http://127.0.0.1:${SHOPLAB_PORT}`;
const TOKEN_ALICE = 'tok-alice';
const TOKEN_BOB = 'tok-bob';

function req(port, path, token) {
  return new Promise((resolve, reject) => {
    const r = http.request({
      hostname: '127.0.0.1', port, path,
      method: 'GET',
      headers: { 'content-type': 'application/json',
        ...(token ? { 'authorization': 'Bearer ' + token } : {}) },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ s: res.statusCode }));
    });
    r.on('error', reject);
    r.setTimeout(5000, () => { r.destroy(); reject(new Error('timeout')); });
    r.end();
  });
}

async function runDemo() {
  process.env.SHOPLAB_PORT = String(SHOPLAB_PORT);

  // Clear require cache so ShopLab can be re-required on each run
  delete require.cache[require.resolve('./test/shoplab')];
  const shop = require('./test/shoplab');

  await new Promise((resolve, reject) => {
    shop.once('error', reject);
    shop.listen(SHOPLAB_PORT, '127.0.0.1', resolve);
  });

  await verifyTarget(TARGET);
  verifyScope(['/api/']);

  const store = new SessionStore();
  const proxy = new ProxyCore({
    target: TARGET,
    scope: ['/api/'],
    exclude: ['/api/health', '/api/products', '/api/auth/'],
    store,
    logger: { log: () => {}, error: () => {} },
  });

  await proxy.listen(PROXY_PORT);

  const calls = [
    ['/api/me', TOKEN_ALICE],
    ['/api/users/user-alice', TOKEN_ALICE],
    ['/api/orders', TOKEN_ALICE],
    ['/api/orders/ord-1001', TOKEN_ALICE],
    ['/api/orders/ord-1002', TOKEN_ALICE],
    ['/api/payment', TOKEN_ALICE],
    ['/api/payment/pay-1', TOKEN_ALICE],
    ['/api/documents', TOKEN_ALICE],
    ['/api/documents/doc-101', TOKEN_ALICE],
  ];

  for (const [path, token] of calls) {
    await req(PROXY_PORT, path, token);
  }

  await proxy.close();

  const findings = await runReplay({
    store,
    targetUrl: TARGET,
    secondToken: TOKEN_BOB,
    logger: { log: () => {} },
  });

  shop.close();

  return {
    observed: store.size(),
    replayable: store.replayable().length,
    findings: findings.map(f => ({
      findingId: f.findingId,
      severity: f.severity,
      path: f.path,
      method: f.method,
      exposedFields: f.exposureSummary ? f.exposureSummary.fieldPaths : [],
      signals: f.exposureSummary ? f.exposureSummary.classificationSignals : [],
      evidenceHash: f.evidence ? f.evidence.matchedHash : null,
      curl: f.curl,
    })),
  };
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url === '/run' && req.method === 'GET') {
    try {
      const result = await runDemo();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', version: '0.10.2' }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(PORT, () => {
  console.log(`jabearri demo server running on port ${PORT}`);
});