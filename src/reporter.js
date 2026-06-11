'use strict';

const fs = require('fs');

// ── Why-flagged explanation ───────────────────────────────────────────────────
// Pure function: given a finding, returns the bullet lines explaining why it was
// flagged. Branches on matchType AND the actual evidence hash prefix so the
// wording always matches the proof artifact (e.g. big-int JSON matched via raw
// bytes must not claim "JSON normalisation"). Exported for testing.

function whyFlagged(f) {
  const lines = ['Same endpoint replayed under a different authenticated user'];
  const matchedHash = (f.evidence && f.evidence.matchedHash) || '';
  if (f.matchType === 'raw-hash-fallback') {
    lines.push('Raw response hashes matched byte-for-byte after semantic hash families differed');
    lines.push('SHA256(raw bytes) identical for both principals');
  } else if (f.matchType === 'size-proximity') {
    lines.push('Response sizes within 5% of each other');
    lines.push('Possible unauthorized data replay — verify manually');
  } else if (matchedHash.startsWith('raw:')) {
    lines.push('Response hashes matched using raw-byte hashing');
    lines.push('JSON normalisation bypassed (e.g. big integers); raw-byte SHA256 identical for both principals');
  } else {
    lines.push('Response hashes matched after JSON normalisation');
    lines.push('SHA256(normalised JSON) identical for both principals');
  }
  return lines;
}

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
    if (f.findingId) console.log(`      Finding ID   — ${f.findingId}`);
    console.log(`      Mechanism    — ${confidence}`);
    console.log(`      ${f.method} ${f.path}`);
    console.log(`      Resource IDs : ${f.resourceIds.map(r => r.value).join(', ')}`);
    console.log(`      Auth type    : ${f.tokenType}`);
    console.log(`      User A got   : ${f.originalStatus} (${f.originalSize} bytes)`);
    console.log(`      User B got   : ${f.replayStatus}  (${f.replaySize} bytes)`);
    console.log(`\n      Why flagged:`);
    for (const line of whyFlagged(f)) {
      console.log(`        · ${line}`);
    }

    // Exposure Summary — derived metadata, no raw values
    if (f.exposureSummary) {
      const es = f.exposureSummary;
      if (es.skipped) {
        console.log(`\n      Exposure Summary: skipped (${es.reason})`);
        if (es.reason === 'body-too-large') {
          console.log(`        Response body (${es.bodyBytes} bytes) exceeded analysis limit (${es.bodyByteLimit} bytes)`);
        }
        console.log(`        Raw body stored: no`);
        console.log(`        Raw values     : no`);
        console.log(`        Finding remains valid — only enrichment was skipped`);
      } else {
        console.log(`\n      Exposure Summary:`);
        console.log(`        Fields exposed : ${es.fieldPaths.slice(0, 20).join(', ')}${es.fieldPaths.length > 20 ? ' ...' : ''}`);
        if (es.fieldPathsTruncated) {
          console.log(`        Field list truncated at ${es.fieldPathLimit} paths`);
        }
        if (es.classificationSignals.length > 0) {
          const signalTypes = [...new Set(es.classificationSignals.map(s => s.classification))];
          console.log(`        Signals        : ${signalTypes.join(', ')}`);
          for (const sig of es.classificationSignals) {
            console.log(`          ${sig.field} → ${sig.classification}`);
          }
        }
        if (es.sanitizedFieldPaths) {
          console.log(`        Sanitized keys : ${es.sanitizedKeySegments} segment(s) — ${es.sanitizedKeyTypes.join(', ')}`);
        }
        console.log(`        Raw body stored: no`);
        console.log(`        Raw values     : no`);
        console.log(`        Evidence hash  : ${es.summaryGeneratedFromHash}`);
      }
    }

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
    version:     '0.10.0',
    generatedAt: new Date().toISOString(),
    reportType:  'authorization-regression-evidence',
    privacy: {
      rawTokensStored: false,
      rawBodiesStored: false,
      rawValuesStored: false,
    },
    integrity: {
      reportSchema:        'accguard-report-v1',
      generatedBy:         'accguard 0.10.0',
      detectionPrimitive:  'cross-user replay hash match',
      bodyRetentionPolicy: 'not-stored',
      tokenRetentionPolicy: 'fingerprint-only',
    },
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

module.exports = { printFindings, saveReport, coverageSummary, whyFlagged };
