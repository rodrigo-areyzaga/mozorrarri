#!/usr/bin/env node
'use strict';

// Run this FIRST to create Alice and Bob and get their tokens.
// Then use Bob's token as ACCGUARD_TOKEN_B when running the main test.

const http = require('http');
const TARGET = 'http://localhost:3000';

function post(path, data) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1', port: 3000, path, method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
        catch { resolve(null); }
      });
    });
    req.on('error', reject);
    req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(JSON.stringify(data));
    req.end();
  });
}

async function setup() {
  console.log('\n  Juice Shop — user setup\n');

  const tokens = {};
  for (const user of [
    { email: 'alice-accguard@test.com', password: 'Alice1234!' },
    { email: 'bob-accguard@test.com',   password: 'Bob1234!'   },
  ]) {
    // Register (ignore if already exists)
    await post('/api/Users/', {
      email: user.email,
      password: user.password,
      passwordRepeat: user.password,
      securityQuestion: { id: 1, question: 'Your eldest siblings middle name?' },
      securityAnswer: 'test',
    }).catch(() => {});

    // Login
    const res = await post('/rest/user/login', {
      email: user.email,
      password: user.password,
    });

    if (res && res.authentication && res.authentication.token) {
      console.log(`  ✓ ${user.email} — logged in`);
      tokens[user.email] = res.authentication.token;
    } else {
      console.log(`  ✗ ${user.email} — login failed`);
    }
  }

  const bobToken = tokens['bob-accguard@test.com'];
  if (bobToken) {
    console.log('\n  ── Bob\'s token (for ACCGUARD_TOKEN_B) ──────────────');
    console.log(`  ${bobToken}`);
    console.log('  ────────────────────────────────────────────────────');
    console.log('\n  This token is printed for local Juice Shop validation only.');
    console.log('  Do not commit, share, or log it in CI.\n');
  } else {
    console.log('\n  ✗ Could not get Bob\'s token.\n');
  }
}

setup().catch(e => { console.error(e.message); process.exit(1); });
