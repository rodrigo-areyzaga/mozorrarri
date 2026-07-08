#!/usr/bin/env node
'use strict';

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const { spawn }  = require('child_process');

const { verifyTarget, verifyScope } = require('./safety');
const { SessionStore }              = require('./session-store');
const { ProxyCore }                 = require('./proxy');
const { runReplay }                 = require('./replay');
const { printFindings, saveReport } = require('./reporter');

const VERSION         = '0.10.2';
const CONSENT_FILE    = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.jabearri_consent');
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
    console.log('[jabearri] CI environment detected — authorization gate skipped.');
    console.log('[jabearri] By running jabearri in CI you confirm you own or have');
    console.log('[jabearri] written authorization to test the target system.\n');
    return;
  }

  if (!process.stdin.isTTY) {
    console.error('[jabearri] Authorization confirmation requires an interactive terminal.');
    console.error('[jabearri] In CI, set CI=true. Locally, run jabearri from a terminal');
    console.error('[jabearri] and type the required phrase.');
    process.exit(2);
  }

  console.log('\n' + '═'.repeat(66));
  console.log(`  jabearri v${VERSION} — authorization required`);
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
    console.log('\n  Consent recorded. jabearri is ready to use.\n');
  } catch (err) {
    console.warn(`\n  Warning: could not save consent record: ${err.message}`);
    console.warn('  You will be asked to confirm again on the next run.\n');
  }
}

// ── Config loading ────────────────────────────────────────────────────────────

function loadConfig() {
  const configPath = path.resolve(process.env.JABEARRI_CONFIG || 'jabearri.config.json');

  if (!fs.existsSync(configPath)) {
    console.error(`[jabearri] No config found at ${configPath}`);
    console.error('[jabearri] Create jabearri.config.json — see README for format.');
    process.exit(1);
  }

  let raw;
  try {
    raw = fs.readFileSync(configPath, 'utf8');
  } catch (err) {
    console.error(`[jabearri] Could not read config at ${configPath}: ${err.message}`);
    process.exit(1);
  }

  try {
    return JSON.parse(raw);
  } catch (err) {
    console.error(`[jabearri] Config file is not valid JSON: ${err.message}`);
    console.error(`[jabearri] Check ${configPath} for syntax errors.`);
    process.exit(1);
  }
}

// ── Command wrapper mode ─────────────────────────────────────────────────────

function parseArgs(argv) {
  if (argv[0] !== 'run') {
    return { mode: 'proxy', command: null, commandArgs: [] };
  }

  if (argv[1] !== '--' || argv.length < 3) {
    console.error('[jabearri] Usage: jabearri run -- <test command>');
    console.error('[jabearri] Example: JABEARRI_TOKEN_B=... jabearri run -- npm test');
    process.exit(1);
  }

  return {
    mode:        'run',
    command:     argv[2],
    commandArgs: argv.slice(3),
  };
}

function proxyEnv(port) {
  const proxyUrl = `http://127.0.0.1:${port}`;
  const env = { ...process.env };

  // The wrapped tests need the proxy address, not the replay credential.
  // Keep JABEARRI_TOKEN_B inside jabearri so Bob's token is not exposed to
  // test code, browser drivers, npm lifecycle hooks, or CI logs.
  delete env.JABEARRI_TOKEN_B;

  return {
    ...env,
    HTTP_PROXY:         proxyUrl,
    http_proxy:         proxyUrl,
    JABEARRI_PROXY_URL: proxyUrl,
  };
}

function startCommand(command, args, port) {
  // Resolve Windows .cmd/.bat commands explicitly so we can use shell: false.
  // shell: true produces a Node deprecation warning (DEP0190) about unsanitized
  // args, which is a credibility problem for a security tool's output.
  // On Windows, npm/npx are .cmd files — resolve them so spawn can find them.
  let resolvedCommand = command;
  if (process.platform === 'win32') {
    const lower = command.toLowerCase();
    if (lower === 'npm' || lower === 'npx' || lower === 'yarn') {
      resolvedCommand = command + '.cmd';
    }
  }

  const child = spawn(resolvedCommand, args, {
    env:   proxyEnv(port),
    stdio: 'inherit',
    shell: false,
  });

  const result = new Promise(resolve => {
    child.on('error', err => {
      console.error(`[jabearri] Could not run wrapped command: ${err.message}`);
      resolve({ code: 2, signal: null });
    });

    child.on('exit', (code, signal) => {
      resolve({ code: code === null ? 1 : code, signal });
    });
  });

  return { child, result };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv.slice(2));

  await requireConsent();

  const config = loadConfig();
  const {
    target,
    scope,
    exclude     = [],
    port        = 8877,
    outputFile  = 'jabearri-report.json',
    minObserved = 0,   // exit non-zero if fewer than this many requests observed
  } = config;

  const secondToken = process.env.JABEARRI_TOKEN_B;

  try {
    await verifyTarget(target);
    verifyScope(scope);
  } catch (err) {
    console.error(`\n[jabearri] ${err.message}\n`);
    process.exit(1);
  }

  const store = new SessionStore();
  let proxy;
  let childProcess = null;
  let finalizing = false;

  const triggerFlush = async (preferredExitCode = null) => {
    if (finalizing) return;
    finalizing = true;

    console.log('\n[jabearri] Stopping proxy and running replay...');

    try {
      await proxy.close();
    } catch (err) {
      console.error(`[jabearri] Error closing proxy: ${err.message}`);
    }

    // ── minObserved floor ─────────────────────────────────────────────────────
    // If fewer than minObserved requests were recorded, the proxy may have been
    // bypassed silently. Exit non-zero so CI fails visibly rather than green.
    if (minObserved > 0 && store.size() < minObserved) {
      console.error(`\n[jabearri] PROXY BYPASS DETECTED`);
      console.error(`[jabearri] Expected at least ${minObserved} authenticated requests.`);
      console.error(`[jabearri] Only ${store.size()} were observed.`);
      console.error(`[jabearri] Check that HTTP_PROXY is set and your HTTP client respects it.`);
      console.error(`[jabearri] Note: Node fetch (undici), axios, and Playwright require`);
      console.error(`[jabearri] explicit proxy configuration — see README troubleshooting.\n`);
      process.exit(2); // exit 2 = proxy bypass (distinct from exit 1 = findings)
    }

    if (!secondToken) {
      console.log('[jabearri] JABEARRI_TOKEN_B not set — skipping replay.');
      console.log('[jabearri] Set it to a second user\'s session token to enable checks.');
      process.exit(preferredExitCode === null ? 0 : preferredExitCode);
    }

    let findings = [];
    try {
      findings = await runReplay({ store, targetUrl: target, secondToken });
    } catch (err) {
      console.error(`[jabearri] Replay failed: ${err.message}`);
    }

    printFindings(findings, store);
    if (outputFile) saveReport(findings, store, outputFile, {
      target,
      scope,
      exclude,
      // Store only the command name — never the args.
      // Command arguments may contain secrets (--password=, --token=, env-injected values).
      // Storing the full command string would persist those secrets in the report JSON.
      command:      args.mode === 'run' ? args.command : null,
      commandArgsSuppressed: args.mode === 'run' ? true : null,
      environment:  process.env.NODE_ENV || process.env.ENVIRONMENT || null,
      userALabel:   process.env.JABEARRI_USER_A_LABEL || null,
      userBLabel:   process.env.JABEARRI_USER_B_LABEL || null,
    });

    // Exit-code disambiguation — when the wrapped command also failed, make it
    // explicit in the terminal so CI operators don't miss the auth finding.
    // exit 0 = clean. exit 1 = findings or test failure. exit 2 = proxy/setup.
    const hasFindings = findings.filter(f => f.type === 'broken-access-control' || f.type === 'possible-missing-authentication').length > 0;
    if (hasFindings && preferredExitCode !== null && preferredExitCode !== 0) {
      console.log('\n[jabearri] NOTE: The wrapped command also exited with a non-zero code.');
      console.log('[jabearri] Both the test suite failure AND the authorization findings above');
      console.log('[jabearri] contributed to this exit. Check the report for details:');
      console.log(`[jabearri]   ${outputFile || 'jabearri-report.json'}\n`);
    }

    if (hasFindings) process.exit(1);
    process.exit(preferredExitCode === null ? 0 : preferredExitCode);
  };

  proxy = new ProxyCore({
    target,
    scope,
    exclude,
    store,
    // In wrapper mode the child process exiting is the completion signal.
    // Do not let wrapped test code finalize jabearri early by POSTing /--flush.
    onFlush: args.mode === 'run' ? null : () => triggerFlush(),
  });

  try {
    await proxy.listen(port);
  } catch (err) {
    console.error(`[jabearri] Could not start proxy on port ${port}: ${err.message}`);
    console.error(`[jabearri] Is something already running on port ${port}?`);
    process.exit(1);
  }

  console.log(`\n  jabearri v${VERSION}`);
  console.log(`  ${'─'.repeat(44)}`);
  console.log(`  Proxy       : http://127.0.0.1:${port}`);
  console.log(`  Target      : ${target}`);
  console.log(`  Scope       : ${scope.join(', ')}`);
  console.log(`  Replay      : ${secondToken ? 'enabled' : 'disabled (set JABEARRI_TOKEN_B)'}`);
  console.log(`  Min observed: ${minObserved > 0 ? minObserved : 'not set'}`);
  console.log(`  ${'─'.repeat(44)}`);

  process.on('SIGINT', () => {
    if (childProcess && !childProcess.killed) childProcess.kill('SIGINT');
    triggerFlush(args.mode === 'run' ? 130 : null);
  });
  process.on('SIGTERM', () => {
    if (childProcess && !childProcess.killed) childProcess.kill('SIGTERM');
    triggerFlush(args.mode === 'run' ? 143 : null);
  });

  if (args.mode === 'run') {
    console.log(`[jabearri] Running wrapped command: ${args.command}\n`);
    const wrapped = startCommand(args.command, args.commandArgs, port);
    childProcess = wrapped.child;
    const result = await wrapped.result;
    childProcess = null;
    await triggerFlush(result.code);
    return;
  }

  console.log(`  Set HTTP_PROXY=http://127.0.0.1:${port} and run your tests.`);
  console.log(`  Press Ctrl+C or POST /--flush when done.\n`);
}

main().catch(err => {
  console.error('[jabearri] Fatal:', err.message);
  process.exit(1);
});
