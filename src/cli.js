#!/usr/bin/env node
'use strict';

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');

const { verifyTarget, verifyScope } = require('./safety');
const { SessionStore }              = require('./session-store');
const { ProxyCore }                 = require('./proxy');
const { runReplay }                 = require('./replay');
const { printFindings, saveReport } = require('./reporter');

const VERSION         = '0.10.0';
const CONSENT_FILE    = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.accguard_consent');
const REQUIRED_PHRASE = 'I own or have written authorization to test the target system';

// Detect CI environments — GitHub Actions, CircleCI, Jenkins, GitLab CI,
// Travis, and most others set CI=true automatically.
const IS_CI = process.env.CI === 'true' || process.env.CI === '1';

// ── Authorization gate ────────────────────────────────────────────────────────
// In CI environments the gate is skipped — no TTY, no interactive prompt.
// The CI operator accepted responsibility by configuring the workflow.
// In local environments the gate is interactive on first run only.

async function requireConsent() {
  if (fs.existsSync(CONSENT_FILE)) return;

  if (IS_CI) {
    // Write consent automatically in CI — operator accepted by configuring the job
    try {
      fs.writeFileSync(CONSENT_FILE, JSON.stringify({
        agreedAt: new Date().toISOString(),
        phrase:   'CI environment — operator accepted authorization responsibility',
        ci:       true,
      }), 'utf8');
    } catch { /* non-fatal */ }
    console.log('[accguard] CI environment detected — authorization gate skipped.');
    console.log('[accguard] By running accguard in CI you confirm you own or have');
    console.log('[accguard] written authorization to test the target system.\n');
    return;
  }

  console.log('\n' + '═'.repeat(66));
  console.log(`  accguard v${VERSION} — authorization required`);
  console.log('═'.repeat(66));
  console.log('\n  This tool probes your application for access control');
  console.log('  vulnerabilities. You must only use it against systems');
  console.log('  you own or have explicit written permission to test.');
  console.log('\n  Unauthorized use may violate:');
  console.log('    · Computer Fraud and Abuse Act (US)');
  console.log('    · Computer Misuse Act (UK)');
  console.log('    · Equivalent laws in your jurisdiction');
  console.log('\n  Type the following sentence exactly to continue:\n');
  console.log(`  "${REQUIRED_PHRASE}"\n`);

  const rl     = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise(resolve => rl.question('  > ', resolve));
  rl.close();

  if (answer.trim() !== REQUIRED_PHRASE) {
    console.log('\n  Phrase did not match. Exiting.\n');
    process.exit(1);
  }

  try {
    fs.writeFileSync(CONSENT_FILE, JSON.stringify({
      agreedAt: new Date().toISOString(),
      phrase:   REQUIRED_PHRASE,
    }), 'utf8');
    console.log('\n  Consent recorded. accguard is ready to use.\n');
  } catch (err) {
    console.warn(`\n  Warning: could not save consent record: ${err.message}`);
    console.warn('  You will be asked to confirm again on the next run.\n');
  }
}

// ── Config loading ────────────────────────────────────────────────────────────

function loadConfig() {
  const configPath = path.resolve(process.env.ACCGUARD_CONFIG || 'accguard.config.json');

  if (!fs.existsSync(configPath)) {
    console.error(`[accguard] No config found at ${configPath}`);
    console.error('[accguard] Create accguard.config.json — see README for format.');
    process.exit(1);
  }

  let raw;
  try {
    raw = fs.readFileSync(configPath, 'utf8');
  } catch (err) {
    console.error(`[accguard] Could not read config at ${configPath}: ${err.message}`);
    process.exit(1);
  }

  try {
    return JSON.parse(raw);
  } catch (err) {
    console.error(`[accguard] Config file is not valid JSON: ${err.message}`);
    console.error(`[accguard] Check ${configPath} for syntax errors.`);
    process.exit(1);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  await requireConsent();

  const config = loadConfig();
  const {
    target,
    scope,
    exclude     = [],
    port        = 8877,
    outputFile  = 'accguard-report.json',
    minObserved = 0,   // exit non-zero if fewer than this many requests observed
  } = config;

  const secondToken = process.env.ACCGUARD_TOKEN_B;

  try {
    await verifyTarget(target);
    verifyScope(scope);
  } catch (err) {
    console.error(`\n[accguard] ${err.message}\n`);
    process.exit(1);
  }

  const store = new SessionStore();
  const proxy = new ProxyCore({ target, scope, exclude, store, onFlush: () => triggerFlush() });

  try {
    await proxy.listen(port);
  } catch (err) {
    console.error(`[accguard] Could not start proxy on port ${port}: ${err.message}`);
    console.error(`[accguard] Is something already running on port ${port}?`);
    process.exit(1);
  }

  console.log(`\n  accguard v${VERSION}`);
  console.log(`  ${'─'.repeat(44)}`);
  console.log(`  Proxy       : http://127.0.0.1:${port}`);
  console.log(`  Target      : ${target}`);
  console.log(`  Scope       : ${scope.join(', ')}`);
  console.log(`  Replay      : ${secondToken ? 'enabled' : 'disabled (set ACCGUARD_TOKEN_B)'}`);
  console.log(`  Min observed: ${minObserved > 0 ? minObserved : 'not set'}`);
  console.log(`  ${'─'.repeat(44)}`);
  console.log(`  Set HTTP_PROXY=http://127.0.0.1:${port} and run your tests.`);
  console.log(`  Press Ctrl+C or POST /--flush when done.\n`);

  const triggerFlush = async () => {
    console.log('\n[accguard] Stopping proxy and running replay...');

    try {
      await proxy.close();
    } catch (err) {
      console.error(`[accguard] Error closing proxy: ${err.message}`);
    }

    // ── minObserved floor ─────────────────────────────────────────────────────
    // If fewer than minObserved requests were recorded, the proxy may have been
    // bypassed silently. Exit non-zero so CI fails visibly rather than green.
    if (minObserved > 0 && store.size() < minObserved) {
      console.error(`\n[accguard] PROXY BYPASS DETECTED`);
      console.error(`[accguard] Expected at least ${minObserved} authenticated requests.`);
      console.error(`[accguard] Only ${store.size()} were observed.`);
      console.error(`[accguard] Check that HTTP_PROXY is set and your HTTP client respects it.`);
      console.error(`[accguard] Note: Node fetch (undici), axios, and Playwright require`);
      console.error(`[accguard] explicit proxy configuration — see README troubleshooting.\n`);
      process.exit(2); // exit 2 = proxy bypass (distinct from exit 1 = findings)
    }

    if (!secondToken) {
      console.log('[accguard] ACCGUARD_TOKEN_B not set — skipping replay.');
      console.log('[accguard] Set it to a second user\'s session token to enable checks.');
      process.exit(0);
    }

    let findings = [];
    try {
      findings = await runReplay({ store, targetUrl: target, secondToken });
    } catch (err) {
      console.error(`[accguard] Replay failed: ${err.message}`);
    }

    printFindings(findings, store);
    if (outputFile) saveReport(findings, store, outputFile);
    process.exit(findings.length > 0 ? 1 : 0);
  };

  process.on('SIGINT',  triggerFlush);
  process.on('SIGTERM', triggerFlush);
}

main().catch(err => {
  console.error('[accguard] Fatal:', err.message);
  process.exit(1);
});
