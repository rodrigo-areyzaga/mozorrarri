# Changelog

All notable changes to accguard are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] — 2026-06-11

v0.10.0 adds a privacy-preserving **Exposure Summary** and audit-ready evidence
metadata for confirmed authorization findings. accguard still does one thing —
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
- Test suite expanded from 209 to 536 passing tests.

### Fixed

- Depth-cap off-by-one: with `MAX_DEPTH = 12`, traversal stored paths 13 segments
  deep. The deepest stored path is now exactly 12 segments.

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

[0.10.0]: https://github.com/rodrigo-areyzaga/accguard/releases/tag/v0.10.0
[0.9.2]: https://github.com/rodrigo-areyzaga/accguard/releases/tag/v0.9.2
