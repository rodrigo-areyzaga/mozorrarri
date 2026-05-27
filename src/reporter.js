'use strict';

const fs = require('fs');

// ── Coverage summary ──────────────────────────────────────────────────────────

function coverageSummary(store) {
  const entries    = store.entries;
  const replayable = store.replayable();

  const patterns = new Set(
    replayable.map(e => {
      let p = e.path;
      e.resourceIds.forEach(r => { p = p.replace(r.value, ':id'); });
      return e.method + ' ' + p;
    })
  );

  const mechanisms = [...new Set(entries.map(e => e.tokenType).filter(Boolean))];

  return {
    observed:   store.size(),
    replayed:   replayable.length,
    patterns:   patterns.size,
    mechanisms: mechanisms.length > 0 ? mechanisms.join(', ') : 'none',
  };
}

// ── Print findings ────────────────────────────────────────────────────────────

function printFindings(findings, store) {
  const divider = '─'.repeat(64);
  const cov     = coverageSummary(store);

  console.log('\n' + divider);
  console.log('  accguard — authorization regression results');
  console.log(divider);
  console.log(`  Requests observed    : ${cov.observed}`);
  console.log(`  Replay candidates    : ${cov.replayed}`);
  console.log(`  Resource patterns    : ${cov.patterns}`);
  console.log(`  Auth mechanisms      : ${cov.mechanisms}`);
  console.log(`  Findings             : ${findings.length}`);
  console.log(divider);

  if (findings.length === 0) {
    console.log('\n  ✓  No authorization regressions detected.');
    console.log(`\n     ${cov.replayed} replay candidates checked across ${cov.patterns} unique`);
    console.log(`     resource patterns. No unauthorized data replays found.\n`);
    return;
  }

  findings.forEach((f, i) => {
    const confidence = f.confidence === 'confirmed'
      ? '✓ confirmed unauthorized data replay'
      : '~ possible unauthorized data replay';

    console.log(`\n  [${i + 1}] ${f.severity.toUpperCase()}`);
    console.log(`      Authorization regression  — broken access control (OWASP A01)`);
    console.log(`      Mechanism                 — ${confidence}`);
    console.log(`      ${f.method} ${f.path}`);
    console.log(`      Resource IDs : ${f.resourceIds.map(r => r.value).join(', ')}`);
    console.log(`      Auth type    : ${f.tokenType}`);
    console.log(`      User A got   : ${f.originalStatus} (${f.originalSize} bytes)`);
    console.log(`      User B got   : ${f.replayStatus}  (${f.replaySize} bytes)`);
    console.log(`\n      Why flagged:`);
    console.log(`        · Same endpoint replayed under a different authenticated user`);
    console.log(`        · Response hashes matched after JSON normalisation`);
    console.log(`        · SHA256(normalised JSON) identical for both principals`);
    console.log(`\n      Reproduce:`);
    console.log(`      ${f.curl}`);
  });

  console.log('\n' + divider);
  console.log(`\n  ${findings.length} authorization regression${findings.length > 1 ? 's' : ''} detected.`);
  console.log(`  Each finding is deterministic — hashes either match or they don't.\n`);
}

// ── Save report — A10 compliant ───────────────────────────────────────────────
// Findings are always printed to terminal first.
// File save failure is surfaced clearly — findings are never silently lost.

function saveReport(findings, store, outputPath) {
  const cov = coverageSummary(store);
  const report = {
    version:     '0.9.1',
    generatedAt: new Date().toISOString(),
    summary: {
      observed:         cov.observed,
      replayCandidates: cov.replayed,
      resourcePatterns: cov.patterns,
      authMechanisms:   cov.mechanisms,
      findings:         findings.length,
    },
    findings,
  };

  try {
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf8');
    console.log(`[accguard] Report saved to ${outputPath}`);
  } catch (err) {
    console.error(`[accguard] Could not save report to ${outputPath}: ${err.message}`);
    console.error(`[accguard] Findings printed above — copy them before closing.`);
  }
}

module.exports = { printFindings, saveReport, coverageSummary };
