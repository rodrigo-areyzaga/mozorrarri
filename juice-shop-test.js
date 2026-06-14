#!/usr/bin/env node
'use strict';

// Juice Shop test script for accguard
// Creates Alice and Bob, logs both in, then makes authenticated GET requests
// as Alice through the accguard proxy. accguard replays with Bob's token.
//
// This script is designed to run via: accguard run -- node juice-shop-test.js
// The proxy URL comes from HTTP_PROXY (set automatically by the wrapper).

const http = require('http');

const TARGET   = 'http://localhost:3000';
const PROXY    = process.env.HTTP_PROXY || process.env.http_proxy || 'http://127.0.0.1:8877';

const ALICE = { email: 'alice-accguard@test.com', password: 'Alice1234!', securityAnswer: 'green' };
const BOB   = { email: 'bob-accguard@test.com',   password: 'Bob1234!',   securityAnswer: 'blue'  };

// ── HTTP helpers ─────────────────────────────────────────────────────────────

function request(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.request({
      hostname: parsed.hostname,
      port:     parsed.port,
      path:     parsed.pathname + parsed.search,
      method:   opts.method || 'GET',
      headers:  opts.headers || {},
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        let json;
        try { json = JSON.parse(body); } catch { json = null; }
        resolve({ status: res.statusCode, body, json, headers: res.headers });
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('timeout')); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// Send directly to Juice Shop (not through proxy) — for registration and login
async function directPost(path, data) {
  return request(TARGET + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
}

// Send through accguard proxy — for authenticated GET requests
async function proxiedGet(path, token) {
  const proxyUrl = new URL(PROXY);
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: proxyUrl.hostname,
      port:     proxyUrl.port,
      path:     path,
      method:   'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
      },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        let json;
        try { json = JSON.parse(body); } catch { json = null; }
        resolve({ status: res.statusCode, body, json });
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('timeout')); });
    req.end();
  });
}

// ── User setup ───────────────────────────────────────────────────────────────

async function registerUser(user) {
  const res = await directPost('/api/Users/', {
    email: user.email,
    password: user.password,
    passwordRepeat: user.password,
    securityQuestion: { id: 1, question: 'Your eldest siblings middle name?' },
    securityAnswer: user.securityAnswer,
  });
  if (res.status === 201) {
    console.log(`  ✓ registered ${user.email}`);
    return res.json.data;
  } else if (res.status === 400 && (res.body.includes('already exists') || res.body.includes('must be unique'))) {
    console.log(`  · ${user.email} already registered`);
    return null;
  } else {
    console.log(`  ✗ register ${user.email} failed: ${res.status} ${res.body.slice(0, 200)}`);
    return null;
  }
}

async function loginUser(user) {
  const res = await directPost('/rest/user/login', {
    email: user.email,
    password: user.password,
  });
  if (res.status === 200 && res.json && res.json.authentication) {
    console.log(`  ✓ logged in ${user.email}`);
    return res.json.authentication.token;
  } else {
    console.log(`  ✗ login ${user.email} failed: ${res.status} ${res.body.slice(0, 200)}`);
    return null;
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\n  Juice Shop accguard test');
  console.log('  ' + '─'.repeat(44));
  console.log(`  Target : ${TARGET}`);
  console.log(`  Proxy  : ${PROXY}`);
  console.log('');

  // Step 1: Register users
  console.log('  [1/4] Registering users...');
  await registerUser(ALICE);
  await registerUser(BOB);

  // Step 2: Login both
  console.log('\n  [2/4] Logging in...');
  const aliceToken = await loginUser(ALICE);
  const bobToken   = await loginUser(BOB);

  if (!aliceToken || !bobToken) {
    console.error('\n  ✗ Could not get tokens for both users. Aborting.');
    process.exit(1);
  }

  console.log(`\n  Alice auth: ready`);
  console.log(`  Bob auth:   ready`);

  // Step 3: Make authenticated requests as Alice through the proxy
  console.log('\n  [3/4] Making authenticated requests as Alice through proxy...');

  const endpoints = [
    // User-scoped endpoints — these should be BOLA-vulnerable in Juice Shop
    '/rest/basket/1',
    '/rest/basket/2',
    '/rest/basket/3',
    '/api/BasketItems/',
    '/api/Addresss/',
    '/api/Cards/',
    '/api/Recycles/',
    '/rest/user/whoami',
    // Product reviews — may or may not be user-scoped
    '/rest/products/1/reviews',
    '/rest/products/2/reviews',
  ];

  for (const ep of endpoints) {
    try {
      const res = await proxiedGet(ep, aliceToken);
      const status = res.status;
      const size = res.body ? res.body.length : 0;
      const marker = status >= 200 && status < 300 ? '✓' : '·';
      console.log(`    ${marker} ${ep} → ${status} (${size} bytes)`);
    } catch (err) {
      console.log(`    ✗ ${ep} → ${err.message}`);
    }
  }

  // Step 4: Done — accguard wrapper will trigger replay automatically
  console.log('\n  [4/4] Test requests complete.');
  console.log('  accguard will now replay these as Bob and compare responses.\n');
}

main().catch(err => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
