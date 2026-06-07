# accguard v0.9.2-FINAL — Adversarial Security Assessment

**Build:** FINAL — 209 built-in tests passing
**Assessment:** Twelve rounds. 85+ attack vectors. 13 harnesses. Zero open findings.

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
