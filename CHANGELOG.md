# Changelog

All notable changes to jabearri are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.2] — 2026-07-07

### Changed

- **BREAKING CHANGE — renamed `mozorrarri` to `jabearri`** as part of the
  Haritzarri tool family consolidation. All environment variables, config
  file names, and the consent file were renamed accordingly:

  - `MOZORRARRI_CONFIG` → `JABEARRI_CONFIG`
  - `MOZORRARRI_TOKEN_B` → `JABEARRI_TOKEN_B`
  - `MOZORRARRI_PROXY_URL` → `JABEARRI_PROXY_URL`
  - `MOZORRARRI_MAX_ENTRIES` → `JABEARRI_MAX_ENTRIES`
  - `MOZORRARRI_API_KEY_HEADER` → `JABEARRI_API_KEY_HEADER`
  - `MOZORRARRI_COOKIE_NAME` → `JABEARRI_COOKIE_NAME`
  - `MOZORRARRI_TEST_TARGET` → `JABEARRI_TEST_TARGET`
  - `mozorrarri.config.json` → `jabearri.config.json`
  - `.mozorrarri_consent` → `.jabearri_consent`

  If you have CI pipelines or scripts referencing the old names, update them
  before upgrading. The GitHub repository was renamed from `mozorrarri` to
  `jabearri`; the old URL redirects automatically. Functionality is unchanged
  by this rename.

- **BREAKING CHANGE — renamed `accguard` to `mozorrarri`** as an earlier step
  in the same consolidation. All environment variables, config file names, and
  the consent file were renamed accordingly:

  - `ACCGUARD_CONFIG` → `MOZORRARRI_CONFIG`
  - `ACCGUARD_TOKEN_B` → `MOZORRARRI_TOKEN_B`
  - `ACCGUARD_PROXY_URL` → `MOZORRARRI_PROXY_URL`
  - `ACCGUARD_MAX_ENTRIES` → `MOZORRARRI_MAX_ENTRIES`
  - `ACCGUARD_API_KEY_HEADER` → `MOZORRARRI_API_KEY_HEADER`
  - `ACCGUARD_COOKIE_NAME` → `MOZORRARRI_COOKIE_NAME`
  - `ACCGUARD_TEST_TARGET` → `MOZORRARRI_TEST_TARGET`
  - `accguard.config.json` → `mozorrarri.config.json`
  - `.accguard_consent` → `.mozorrarri_consent`

  Functionality was unchanged by this rename. Both renames, and all the naming
  cleanup that followed them, ship together in this release.

### Security

- **Authorization gate could silently exit 0 with no TTY.** In a non-CI
  environment with `stdin` not a TTY (e.g. a closed/redirected stdin), the
  interactive consent prompt's `readline` callback was never invoked, the
  event loop drained, and the process exited `0` — without recording consent
  and without hitting the phrase-mismatch path. `requireConsent()` now checks
  `process.stdin.isTTY` before creating the prompt and exits `2` with a clear
  message if no interactive terminal is available. The CI bypass path is
  unaffected.
- **Public IP misclassification in shorthand IPv4 parsing.** `normalizeIPv4()`
  zero-padded shorthand addresses (`"172.16"`, `"10.1"`, fewer than 4 dotted
  parts) at the *end*, producing the wrong address (`"172.16.0.0"` instead of
  the real `"172.0.0.16"`). Real inet_aton semantics — and what `new URL()`'s
  own host parser already does — have only the *last* part absorb the
  remaining bits. The wrong math meant `"172.16"` classified as private
  (172.16.0.0/12) when the address it actually names, `172.0.0.16`, is not in
  that block. Inert in jabearri's own runtime today (its one call site already
  runs targets through `new URL()` first, which pre-canonicalizes the
  hostname), but a live risk for any future direct caller of the exported
  `isPrivateHost`/`normalizeIPv4` primitives.
- **Misleading error for literal public IP targets.** `verifyTarget()` now
  classifies literal IPv4/IPv6 targets directly instead of attempting DNS
  resolution on them. Previously `http://8.8.8.8` failed with
  `Could not resolve hostname: 8.8.8.8` — still blocked, but for the wrong
  stated reason. Now reports `SAFETY BLOCK: Target "8.8.8.8" is a public IP
  address.`

### Fixed

- **Encoded scope traversal could widen the scope boundary through multiple
  distinct gaps, all now closed.**

  The original check decoded scope entries a fixed 2 passes before looking for
  `..`. Three gaps existed:

  1. **Triple-and-deeper encoding** (`%25252e%25252e`, mixed-depth variants):
     survived 2 decode passes as a residual `%2e%2e` — no literal `..` — but
     the WHATWG URL spec's dot-segment removal collapses `%2e`/`%2E` natively,
     so `normalizePath()` still widened scope at request time. Fixed by
     replacing the fixed 2-pass decode with `decodeUntilStable()`, which loops
     until the string stops changing (capped at `DECODE_MAX_PASSES` passes for
     DoS safety).

  2. **Cap-boundary residual** (encoding depth exactly `DECODE_MAX_PASSES`):
     `decodeUntilStable()` hit its cap and returned `/%2e%2e/` — still no
     literal `..`, still collapsed to `/` by `new URL().pathname`. Fixed by
     `foldEncodedDots()`, which converts residual `%2e`/`%2E` to `.` after the
     decode loop — mirroring what the URL spec does without an explicit decode
     step — before the `..` check runs.

  Both `verifyScope()` (pre-flight validation) and `normalizePath()` (runtime
  scope matching in `ProxyCore`) now apply the same two-step pipeline:
  `foldEncodedDots(decodeUntilStable(input))`. The two functions are provably
  consistent at every encoding depth, including cap-boundary residuals. Deeper
  residuals (`%252e` and beyond) are not folded — the URL spec does not
  collapse them without an explicit decode step — and verified not to widen
  scope via URL normalization.

- **Test-harness integrity: `MAX_ENTRIES` empty-string fallback test passed
  for the wrong reason.** `session-store.js` reads `JABEARRI_MAX_ENTRIES` at
  module-load time, but `test/adversarial-harness.js` set the env var *after*
  already requiring the module — so the assertion never exercised the
  fallback path it claimed to test. Moved to a fresh child process with the
  env var set before `require`.
- **Stale env var name in adversarial harness.** A leftover
  `ACCGUARD_MAX_ENTRIES` reference (from before the accguard→mozorrarri→jabearri
  renames) meant that specific test silently didn't override anything.
  Corrected to `JABEARRI_MAX_ENTRIES`.
- **Naming cleanup completed.** Orphaned `config/mozorrarri.config.json`
  (unreferenced duplicate of `config/jabearri.config.json`) removed. Stale
  old-name traces in `.gitignore`, `.npmignore`, and `docs/architecture.svg`
  updated. `docs/accguard-demo.gif` renamed to `docs/jabearri-demo.gif`.

- **887 total tests** (732 in `test/run.js` + 81 in `test/adversarial-harness.js`
  + 74 in `test/deep-adversarial-harness.js`).

## [0.10.1] — 2026-06-13

### Added

- **`jabearri run -- <command>` wrapper mode.** jabearri can now wrap your test
  command directly — starts the proxy, injects `HTTP_PROXY` into the child
  process environment, waits for the command to exit, then replays automatically.
  No manual coordination or second terminal required. `JABEARRI_TOKEN_B` is
  explicitly removed from the child environment so Bob's token is never exposed
  to test code, browser drivers, or CI logs.
- **Exit-code disambiguation message.** When the wrapped command exits non-zero
  AND jabearri finds confirmed findings, the terminal prints a clear note
  distinguishing both failure causes and the report path.
- **MongoDB ObjectID extraction.** 24-character hex strings containing at least
  one letter (`a–f`) are now recognized as `objectid` resource IDs. Previously
  these fell through `extractResourceIds` entirely, causing MongoDB-backed API
  endpoints (crAPI vehicles, etc.) to be silently skipped from replay.
- **708 automated tests.**

### Fixed

- Version strings unified across all source files, CLI banner, report metadata,
  and documentation.
- Wrapper `shell: true` replaced with `shell: false` and explicit Windows `.cmd`
  resolution for `npm`/`npx`/`yarn`. Eliminates Node.js DEP0190 deprecation
  warning from wrapper output.

### Validation

- Validated `jabearri run -- <command>` against OWASP Juice Shop.
- Confirmed deterministic cross-user replay findings on `/rest/basket/:id`
  endpoints with reproducible evidence.
- Documented boundary: session-scoped endpoints without URL-level resource IDs
  are observed but not replayed as BOLA candidates.
- Added VAmPI boundary validation: Flask/JWT traffic is captured correctly,
  while plain-word path identifiers (`/users/v1/name1`) are intentionally not
  replayed as BOLA candidates. Zero findings on a clean run — correct behavior,
  honestly reported.

[0.10.2]: https://github.com/rodrigo-areyzaga/jabearri/releases/tag/v0.10.2
[0.10.1]: https://github.com/rodrigo-areyzaga/jabearri/releases/tag/v0.10.1

## [0.10.0] — 2026-06-11

v0.10.0 adds a privacy-preserving **Exposure Summary** and audit-ready evidence
metadata for confirmed authorization findings. jabearri still does one thing —
prove cross-user authorization regressions. This release makes the proof
clearer, safer, and harder to misread. Detection behavior is unchanged.

### Added

- **Exposure Summary** for confirmed broken-access-control findings. Inspects
  the replay response body (already in memory) and records sanitized field
  paths, content type, body size, conservative classification signals, and the
  evidence hash. Runs only on confirmed BOLA findings with JSON bodies; never
  affects pass/fail.
- **Classification signals** (field-name-based, conservative): `possible_pii`,
  `possible_location`, `resource_identifier`, `possible_financial`,
  `possible_secret`. Signals are a hint, never a verdict.
- **Evidence metadata** on every finding: `findingId` (stable `AG-<ts>-<seq>`
  reference), `evidence` block (semantic + raw hashes, `matchedHash`,
  `matchType`), `request` metadata, `recordedAt`, and `replayedAt`.
- **Report privacy and integrity sections**: top-level `privacy`
  (`rawTokensStored`/`rawBodiesStored`/`rawValuesStored: false`) and `integrity`
  (schema id, detection primitive, retention policies) so the trust model is
  visible in the artifact itself.
- **Key sanitization**: dynamic or sensitive JSON object keys (email, UUID,
  token, long numeric, high-entropy, control characters) are replaced with inert
  placeholders (`[email-key]`, `[uuid-key]`, `[token-like-key]`, `[numeric-key]`,
  `[dynamic-key]`, `[unsafe-key]`) before being stored as field-path segments.
  Schema field names are kept unchanged.
- **Sanitization disclosure**: `sanitizedFieldPaths`, `sanitizedKeyTypes`, and
  `sanitizedKeySegments` honestly report when and how much sanitization occurred,
  so path deduplication never makes a report look more precise than the data.
- **Pre-parse body-size ceiling** (1 MB). Oversized responses skip exposure
  analysis with a `skipped: true, reason: "body-too-large"` summary; the
  confirmed finding is still reported.
- **`docs/report-schema.md`** documenting the full report structure, both
  Exposure Summary shapes, and the sanitization placeholder table.
- **CHANGELOG.md** (this file).

### Changed

- Reporter "Why flagged" wording now branches on `matchType` and the actual
  evidence-hash prefix. A big-int JSON match proved by raw bytes is described as
  raw-byte hashing rather than incorrectly claiming JSON normalisation.
- `matchType` and the evidence hash now derive from a single pair of booleans,
  so `exposureSummary.summaryGeneratedFromHash === evidence.matchedHash` holds
  by construction.
- Architecture diagram (`docs/architecture.svg`) and README architecture section
  updated to show the Exposure Summary flow and raw-body-discarded annotation.
- `SECURITY.md` documents the Exposure Summary privacy model and adds an explicit
  note that request paths, `resourceIds`, and `curl` are preserved verbatim for
  reproducibility and are **not** sanitized.
- Test suite expanded from 209 to 657 passing tests, including integration
  coverage for Cookie, API key, Token-scheme, and scheme-less authentication
  mechanisms alongside the existing Bearer tests.

### Fixed

- Depth-cap off-by-one: with `MAX_DEPTH = 12`, traversal stored paths 13 segments
  deep. The deepest stored path is now exactly 12 segments.
- **Resource-ID candidate filter** (`extractResourceIds`): version-only path
  segments (`v1`, `v2`, `v10`) were extracted as integer resource IDs, and
  hyphenated route names (`order-history`) were treated as slug resource IDs.
  Both caused false positive findings on shared global endpoints. The function
  now skips API version markers, treats slugs as resource IDs only when they
  embed a digit or appear under a collection parent, and extracts query-string
  IDs only from id-like parameter keys (`id`, `orderId`, `userId`, etc.).

### Security

- Exposure Summary never stores raw response bodies, raw field values, or raw
  tokens. Field-path segments derived from sensitive keys are sanitized.
- URL/path privacy is a documented boundary: sensitive data placed in a URL by
  the target API (email, token, identifier) is preserved verbatim in `path`,
  `resourceIds`, and `curl` for reproduction. Reports are security artifacts.

## [0.9.2] — earlier

- Authorization regression testing from real authenticated traffic.
- Live proxy capture, second-user replay, SHA-256 hash comparison.
- Twelve rounds of adversarial assessment; 85+ attack vectors; zero open findings.

[0.10.0]: https://github.com/rodrigo-areyzaga/jabearri/releases/tag/v0.10.0
[0.9.2]: https://github.com/rodrigo-areyzaga/jabearri/releases/tag/v0.9.2
