# accguard v0.10.0 — Adversarial Security Assessment

**Build:** v0.10.0 — 536 built-in tests passing
**Assessment:** Twelve adversarial rounds (v0.9.2) plus Exposure Summary verification (v0.10.0). 85+ attack vectors. 13 harnesses. Zero open findings.

---

## Verdict

The tool is clean. Ship it.

---

## Part 1: The One Thing

*Does accguard correctly tell you whether user B can access user A's resources?*

**Yes**, within its documented scope (read-side, HTTP, known ID patterns). Every correctness bug found across twelve adversarial rounds has been fixed and verified.

### Detection engine
Hash comparison with sortKeys normalization, big-integer precision preservation, Unicode NFC normalization, identity-field array reorder absorption, trivial-payload downgrade, and hash-family consistency with rawHash cross-family fallback. Verified against 20+ detection-quality scenarios including adversarial false-positive and false-negative constructions.

### Capture pipeline
Bearer tokens, cookies (13+ framework defaults, ACCGUARD_COOKIE_NAME override, array-header iteration, empty-bearer fallthrough), non-Bearer Authorization schemes (Basic, Digest, Token, ApiKey — recorded as other-auth with scheme reconstruction), X-API-Key (ACCGUARD_API_KEY_HEADER configurable), and scheme-less Authorization headers. All verified end-to-end through proxy→record→replay→finding.

### Scope matching
Case-insensitive, two-pass percent-decoded, traversal-resolved, matrix-parameter-stripped, trailing-slash-boundary-guarded. Eight bypass vectors tested; all blocked. SSRF blocked by design.

### Operational trust
Token-B canary (with original User-Agent), minObserved proxy-bypass floor, CI consent auto-skip, User-Agent preservation in replay and anonymous reclassifier.

### Shell safety
All curl reproduction commands use POSIX single-quote escaping (shellQuote) for URLs and non-variable authFlag components. Eight injection vectors tested (backtick, $(), ${}, single-quote breakout, pipe, redirect, newline, double-quote+semicolon); all neutralized. TOKEN_B is a standard shell variable reference.

### Documented scope boundaries (not bugs)
Shared authenticated resources → confirmed (mitigated by exclude list). Semantic-200 error bodies → confirmed. Volatile fields → hash diverges (awaiting ignoreKeys). Partial leaks → hash diverges. Non-identity-field array reorder → hash diverges. Opaque resource IDs → not replayable. Write-side BOLA → GET-only. HTTPS → not proxied. Post-hoc replay timing → resource deletion between record and replay.

### Exposure Summary (v0.10.0)
Derived metadata enrichment for confirmed BOLA findings. Does not affect detection or pass/fail behavior. Threat model:

- Does not store raw response bodies
- Does not store raw field values
- Does not affect detection logic or pass/fail
- Runs only after confirmed authorization failure (confirmed broken-access-control gate)
- Uses bounded traversal (MAX_DEPTH=12, MAX_FIELD_PATHS=200, MAX_ARRAY_ITEMS=5)
- Uses conservative classification signals (field-name-based only, not value-based)
- Non-JSON responses are not summarized
- Deep objects and large responses may be truncated
- Classification is a signal, not a verdict — field-name match, not value inspection
- Dynamic/sensitive JSON keys (email, UUID, token, long numeric, high-entropy, control-char) are replaced with inert placeholders before storage — sensitive data cannot leak through a field-path segment
- Pre-parse body-size ceiling (1 MB) — oversized responses skip analysis with a `skipped: true` summary; the confirmed finding is never suppressed
- Depth cap is exact: the deepest stored path has exactly MAX_DEPTH (12) segments
- Evidence-hash invariant: `exposureSummary.summaryGeneratedFromHash === evidence.matchedHash` for every finding (normal and skipped); `matchType` and `matchedHash` derive from a single source so they cannot drift
- Sanitization is disclosed honestly: when dynamic keys are replaced, the summary reports how many segments and which placeholder types, so path deduplication cannot make the report look more precise than the underlying data
- Reporter wording matches the proof: `whyFlagged()` branches on the actual evidence-hash prefix, so a big-int JSON match proved by raw bytes is never described as "JSON normalisation"
- URL/path privacy is a documented boundary: `path`, `resourceIds`, and `curl` are preserved verbatim for reproducibility and are NOT sanitized; sensitive data in URLs will appear in reports by design (tests lock this so a silent change is caught)
- Reports explicitly declare privacy model (rawTokensStored, rawBodiesStored, rawValuesStored: false)

---

## Part 2: Everything Else

Proxy survived randomized stress testing (40 fuzz requests: random paths, 10KB URLs, 500-deep traversal, Unicode, empty paths, query abuse). No crashes. SSRF blocked. Report injection neutralized by URL parser. Scope normalization comprehensive.

---

## What was found and fixed (cumulative)

| Round | What broke | Fix |
|---|---|---|
| 1 | Silent clean run (proxy bypass, invalid TOKEN_B, CI consent hang) | minObserved floor, canary, consent auto-skip |
| 1 | 4 false-positive classes on adversarial target | Trivial-payload downgrade, exclude list |
| 2 | Suppression rule destroys severe TP | Adopted as reclassifier (not suppressor) |
| 3 | Big-int hash collision (3 vectors) | Raw-byte fallback for >MAX_SAFE_INTEGER |
| 3 | Unicode NFC/NFD hash divergence | NFC normalization in sortKeys |
| 3 | Identity-field array reorder miss | Order-insensitive hash for identity arrays |
| 3 | 3 red tests passing for wrong reason | Tests corrected to isolate variable |
| 4 | 9 cookie framework defaults missed | Three-tier cookie resolution |
| 4 | Empty-bearer extracts empty string | Guard: raw must be non-empty |
| 5 | Case/encoding scope bypass (4 vectors) | decodeURIComponent + toLowerCase in normalizePath |
| 5 | Trailing-slash exclude gap | Boundary guard in matches() |
| 6 | Hash-family mismatch (json: vs raw:) | rawHash cross-family fallback in assessFinding |
| 8 | Matrix parameter exclude bypass (3 vectors) | Matrix-param stripping in normalizePath |
| 8 | Double-encoding exclude bypass (2 vectors) | Two-pass decode loop |
| 8 | Array Authorization header drops valid token | .find() iteration to first non-empty |
| 9 | Reclassifier cross-family gap | rawHash fallback in reclassifier |
| 10 | User-Agent mismatch (replay vs recording) | Store and replay original UA |
| 10 | 5 auth schemes invisible (Basic, Digest, Token, ApiKey, X-API-Key) | Auth scheme generalization |
| 11 | Shell injection in curl reproduction | shellQuote (POSIX single-quote escaping) |
| 11 | authFlag non-variable parts in double quotes | shellQuote applied to all dynamic authFlag components |
| FINAL | Scheme-less auth misidentifies token as scheme | Empty scheme for space-less Authorization values |
| FINAL | Bare known-scheme headers recorded as auth | KNOWN_SCHEMES guard falls through |
| 0.10.0 | Exposure Summary added | New module: field-path extraction, classification signals, evidence metadata, privacy/integrity report sections. |
| 0.10.0 | Sensitive data leak via JSON keys | Key sanitization — dynamic/sensitive keys replaced with inert placeholders |
| 0.10.0 | Unbounded analysis cost on large bodies | 1 MB pre-parse ceiling; oversized bodies skip enrichment, finding still reported |
| 0.10.0 | Depth-cap off-by-one (13 segments stored for MAX_DEPTH=12) | Guard changed to `depth >= MAX_DEPTH`; deepest path now exactly 12 segments. |
| 0.10.0 | matchType / evidenceHash could diverge on undefined-hash edge | Both now derive from a single pair of booleans; invariant `summaryGeneratedFromHash === evidence.matchedHash` holds by construction |
| 0.10.0 | Sanitization collision hid that multiple dynamic keys existed | Added honest `sanitizedFieldPaths` / `sanitizedKeyTypes` / `sanitizedKeySegments` disclosure. |
| 0.10.0 | Reporter claimed "JSON normalisation" for raw-prefixed (big-int) hashes | `whyFlagged()` now branches on the actual hash prefix; wording matches the proof artifact |
| 0.10.0 | Sensitive data in URLs not addressed | Documented as a conscious reproducibility tradeoff; tests lock the behavior so a future silent change is caught. 536 tests passing. |
