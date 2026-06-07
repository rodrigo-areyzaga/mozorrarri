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

  // Separate by type for clear output.
  // needs-review is now its own type (not broken-access-control) so it doesn't
  // inflate the BOLA count or appear in the HIGH severity findings section.
  const bola    = findings.filter(f => f.type === 'broken-access-control');
  const misauth = findings.filter(f => f.type === 'possible-missing-authentication');
  const review  = findings.filter(f => f.type === 'needs-review');

  console.log('\n' + divider);
  console.log('  accguard — authorization regression results');
  console.log(divider);
  console.log(`  Requests observed    : ${cov.observed}`);
  console.log(`  Replay candidates    : ${cov.replayed}`);
  console.log(`  Resource patterns    : ${cov.patterns}`);
  console.log(`  Auth mechanisms      : ${cov.mechanisms}`);
  console.log(`  Findings             : ${bola.length}`);
  if (misauth.length > 0) console.log(`  Missing auth (!)     : ${misauth.length} — see below`);
  if (review.length  > 0) console.log(`  Needs review         : ${review.length} — trivial payload`);
  console.log(divider);

  if (findings.length === 0) {
    console.log('\n  ✓  No authorization regressions detected.');
    console.log(`\n     ${cov.replayed} replay candidates checked across ${cov.patterns} unique`);
    console.log(`     resource patterns. No unauthorized data replays found.\n`);
    return;
  }

  // BOLA findings — confirmed unauthorized data replay
  bola.forEach((f, i) => {
    const confidence = f.confidence === 'confirmed'
      ? '✓ confirmed unauthorized data replay'
      : '~ possible unauthorized data replay';

    console.log(`\n  [${i + 1}] ${f.severity.toUpperCase()} — broken access control (OWASP A01)`);
    console.log(`      Mechanism    — ${confidence}`);
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

  // Missing authentication findings — reclassified from BOLA by anon probe
  if (misauth.length > 0) {
    console.log('\n' + divider);
    console.log('\n  [!] POSSIBLE MISSING AUTHENTICATION\n');
    console.log('      These endpoints returned identical data to an unauthenticated');
    console.log('      request AND to user B. This may indicate:');
    console.log('        · Intentionally public data (verify and add to exclude list)');
    console.log('        · Missing authentication enforcement (critical — fix immediately)\n');

    misauth.forEach((f, i) => {
      console.log(`  [!${i + 1}] CRITICAL — ${f.method} ${f.path}`);
      console.log(`       Resource IDs : ${f.resourceIds.map(r => r.value).join(', ')}`);
      console.log(`       Reproduce    : ${f.curl}\n`);
    });
  }

  // Needs-review findings — trivial payload hash match
  if (review.length > 0) {
    console.log(divider);
    console.log('\n  [~] NEEDS REVIEW — trivial payload\n');
    console.log('      These endpoints returned identical trivial responses ([], {}, null)');
    console.log('      to both users. Hash matched but no per-user data was detected.');
    console.log('      Likely false positive — verify manually.\n');

    review.forEach((f, i) => {
      console.log(`  [~${i + 1}] ${f.method} ${f.path}`);
      console.log(`       Reproduce : ${f.curl}\n`);
    });
  }

  console.log(divider);
  if (bola.length > 0) {
    console.log(`\n  ${bola.length} authorization regression${bola.length !== 1 ? 's' : ''} detected.`);
    console.log(`  Each finding is deterministic — hashes either match or they don't.`);
  }
  console.log('');
}

// ── Save report ───────────────────────────────────────────────────────────────

function saveReport(findings, store, outputPath) {
  const cov = coverageSummary(store);
  const report = {
    version:     '0.9.2',
    generatedAt: new Date().toISOString(),
    summary: {
      observed:         cov.observed,
      replayCandidates: cov.replayed,
      resourcePatterns: cov.patterns,
      authMechanisms:   cov.mechanisms,
      findings:         findings.filter(f => f.type === 'broken-access-control').length,
      missingAuth:      findings.filter(f => f.type === 'possible-missing-authentication').length,
      needsReview:      findings.filter(f => f.confidence === 'needs-review').length,
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
