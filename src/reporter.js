'use strict';

const fs = require('fs');

// ── Why-flagged explanation ───────────────────────────────────────────────────

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

  // Not-replayed entries: observed and in-scope, but filtered out of replay
  // Order matters: check method first, then resource ID, then dedup.
  // A POST with no resource ID should be method_filtered, not no_resource_id.
  const notReplayed = entries
    .filter(e => !replayable.includes(e))
    .map(e => {
      let reason;
      if (!['GET'].includes(e.method)) {
        reason = 'method_filtered';
      } else if (!e.resourceIds || e.resourceIds.length === 0) {
        reason = 'no_resource_id';
      } else {
        reason = 'deduplicated';
      }
      return {
        method:  e.method,
        path:    e.path,
        reason,
      };
    })
    // Deduplicate by method+path+reason
    .filter((e, i, arr) =>
      arr.findIndex(x => x.method === e.method && x.path === e.path && x.reason === e.reason) === i
    );

  return {
    observed:   store.size(),
    replayed:   replayable.length,
    patterns:   patterns.size,
    mechanisms: mechanisms.length > 0 ? mechanisms.join(', ') : 'none',
    notReplayed,
  };
}

// ── Plain-language summary ────────────────────────────────────────────────────
// One paragraph a non-engineer can read and forward. Tells you what was tested,
// what was found, and why some requests were not tested.

function buildPlainSummary(cov, bolaCount, misauthCount) {
  const observed   = cov.observed;
  const replayed   = cov.replayed;
  const notRep     = cov.notReplayed.length;
  const noId       = cov.notReplayed.filter(e => e.reason === 'no_resource_id').length;
  const methodFilt = cov.notReplayed.filter(e => e.reason === 'method_filtered').length;
  const deduped    = cov.notReplayed.filter(e => e.reason === 'deduplicated').length;

  let what;
  if (bolaCount === 0 && misauthCount === 0) {
    what = `No authorization boundary failures were detected in the replayed traffic.`;
  } else {
    const parts = [];
    if (bolaCount > 0) parts.push(`${bolaCount} confirmed authorization boundary failure${bolaCount !== 1 ? 's' : ''}`);
    if (misauthCount > 0) parts.push(`${misauthCount} possible missing-authentication issue${misauthCount !== 1 ? 's' : ''}`);
    what = `${parts.join(' and ')} ${bolaCount + misauthCount === 1 ? 'was' : 'were'} detected.`;
  }

  const notRepParts = [];
  if (noId > 0)       notRepParts.push(`${noId} lacked a URL-level resource identifier`);
  if (methodFilt > 0) notRepParts.push(`${methodFilt} used a non-GET method (out of scope by design)`);
  if (deduped > 0)    notRepParts.push(`${deduped} were deduplicated`);

  const notRepStr = notRep > 0
    ? ` ${notRep} observed request${notRep !== 1 ? 's' : ''} ${notRep === 1 ? 'was' : 'were'} not replayed: ${notRepParts.join('; ')}.`
    : '';

  return `mozorrarri observed ${observed} authenticated request${observed !== 1 ? 's' : ''} and replayed ${replayed} URL-identified resource candidate${replayed !== 1 ? 's' : ''} as a second authenticated user. ${what}${notRepStr} A clean result means this specific failure mode was not observed in the traffic mozorrarri saw — it does not prove the API has no authorization bugs.`;
}

// ── Print findings ────────────────────────────────────────────────────────────

function printFindings(findings, store) {
  const divider = '─'.repeat(64);
  const cov     = coverageSummary(store);

  const bola    = findings.filter(f => f.type === 'broken-access-control');
  const misauth = findings.filter(f => f.type === 'possible-missing-authentication');
  const review  = findings.filter(f => f.type === 'needs-review');

  console.log('\n' + divider);
  console.log('  mozorrarri — authorization regression results');
  console.log(divider);
  console.log(`  Requests observed    : ${cov.observed}`);
  console.log(`  Replay candidates    : ${cov.replayed}`);
  console.log(`  Not replayed         : ${cov.notReplayed.length}`);
  console.log(`  Resource patterns    : ${cov.patterns}`);
  console.log(`  Auth mechanisms      : ${cov.mechanisms}`);
  console.log(`  Findings             : ${bola.length}`);
  if (misauth.length > 0) console.log(`  Missing auth (!)     : ${misauth.length} — see below`);
  if (review.length  > 0) console.log(`  Needs review         : ${review.length} — trivial payload`);
  console.log(divider);

  if (findings.length === 0) {
    console.log('\n  ✓  No authorization regressions detected.');
    console.log(`\n     ${cov.replayed} replay candidates checked across ${cov.patterns} unique`);
    console.log(`     resource patterns. No unauthorized data replays found.`);
    if (cov.notReplayed.length > 0) {
      console.log(`\n     ${cov.notReplayed.length} observed request${cov.notReplayed.length !== 1 ? 's' : ''} not replayed:`);
      const noId  = cov.notReplayed.filter(e => e.reason === 'no_resource_id').length;
      const meth  = cov.notReplayed.filter(e => e.reason === 'method_filtered').length;
      const dedup = cov.notReplayed.filter(e => e.reason === 'deduplicated').length;
      if (noId  > 0) console.log(`       · ${noId} had no URL-level resource identifier`);
      if (meth  > 0) console.log(`       · ${meth} used a non-GET method (out of scope by design)`);
      if (dedup > 0) console.log(`       · ${dedup} were deduplicated`);
    }
    console.log('');
    return;
  }

  // BOLA findings
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

  // Missing authentication findings
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

  // Needs-review findings
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

function saveReport(findings, store, outputPath, runContext = {}) {
  const cov     = coverageSummary(store);
  const bolaCount    = findings.filter(f => f.type === 'broken-access-control').length;
  const misauthCount = findings.filter(f => f.type === 'possible-missing-authentication').length;

  const report = {
    version:     '0.10.1',
    generatedAt: new Date().toISOString(),
    reportType:  'authorization-regression-evidence',

    // Plain-language summary — readable without engineering context
    summary: {
      plain: buildPlainSummary(cov, bolaCount, misauthCount),
      observed:         cov.observed,
      replayCandidates: cov.replayed,
      notReplayed:      cov.notReplayed.length,
      resourcePatterns: cov.patterns,
      authMechanisms:   cov.mechanisms,
      findings:         bolaCount,
      missingAuth:      misauthCount,
      needsReview:      findings.filter(f => f.type === 'needs-review').length,
    },

    // What was tested — answers "what exactly did you test?"
    runContext: {
      target:       runContext.target      || null,
      scope:        runContext.scope       || null,
      exclude:      runContext.exclude     || null,
      command:      runContext.command     || null,
      environment:  runContext.environment || null,
      principalPair: {
        userA: runContext.userALabel || 'primary-test-user',
        userB: runContext.userBLabel || 'secondary-test-user',
      },
      // Note: tokens are never stored — only labels
    },

    privacy: {
      rawTokensStored: false,
      rawBodiesStored: false,
      rawValuesStored: false,
    },

    integrity: {
      reportSchema:         'mozorrarri-report-v1',
      generatedBy:          'mozorrarri 0.10.1',
      detectionPrimitive:   'cross-user replay hash match',
      bodyRetentionPolicy:  'not-stored',
      tokenRetentionPolicy: 'fingerprint-only',
    },

    // Not-replayed breakdown — makes clean runs commercially meaningful
    notReplayed: cov.notReplayed,

    findings,
  };

  try {
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf8');
    console.log(`[mozorrarri] Report saved to ${outputPath}`);
  } catch (err) {
    console.error(`[mozorrarri] Could not save report to ${outputPath}: ${err.message}`);
    console.error(`[mozorrarri] Findings printed above — copy them before closing.`);
  }
}

module.exports = { printFindings, saveReport, coverageSummary, whyFlagged, buildPlainSummary };
