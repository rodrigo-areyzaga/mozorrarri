# mozorrarri Report Schema — v1

mozorrarri v0.10.1 produces JSON reports with the following structure.

---

## Top-level fields

| Field | Type | Description |
|---|---|---|
| `version` | string | mozorrarri version that generated the report |
| `generatedAt` | ISO-8601 string | When the report was generated |
| `reportType` | string | Always `"authorization-regression-evidence"` |
| `privacy` | object | Trust model — what the report does and does not store |
| `integrity` | object | Report provenance and detection method |
| `summary` | object | Aggregate counts |
| `findings` | array | Individual findings |

## privacy

| Field | Type | Value |
|---|---|---|
| `rawTokensStored` | boolean | `false` — tokens are fingerprinted with SHA-256 |
| `rawBodiesStored` | boolean | `false` — bodies are hashed and discarded |
| `rawValuesStored` | boolean | `false` — field values are never persisted |

## integrity

| Field | Type | Description |
|---|---|---|
| `reportSchema` | string | Schema identifier: `"mozorrarri-report-v1"` |
| `generatedBy` | string | Tool name and version |
| `detectionPrimitive` | string | `"cross-user replay hash match"` |
| `bodyRetentionPolicy` | string | `"not-stored"` |
| `tokenRetentionPolicy` | string | `"fingerprint-only"` |

## summary

| Field | Type | Description |
|---|---|---|
| `observed` | number | Total authenticated requests recorded |
| `replayCandidates` | number | Requests eligible for replay |
| `resourcePatterns` | number | Unique endpoint patterns |
| `authMechanisms` | string | Auth types detected (e.g. `"bearer"`) |
| `findings` | number | Confirmed BOLA findings |
| `missingAuth` | number | Possible missing authentication findings |
| `needsReview` | number | Trivial payload hash matches (likely false positives) |

## findings[]

| Field | Type | Description |
|---|---|---|
| `findingId` | string | Stable reference: `AG-<timestamp>-<seq>` |
| `severity` | string | `"high"`, `"critical"`, or `"info"` |
| `type` | string | `"broken-access-control"`, `"possible-missing-authentication"`, or `"needs-review"` |
| `confidence` | string | `"confirmed"`, `"possible"`, or `"needs-review"` |
| `method` | string | HTTP method |
| `path` | string | Request path including query string |
| `resourceIds` | array | Extracted resource identifiers `[{type, value}]` |
| `tokenType` | string | Auth mechanism: `"bearer"`, `"cookie"`, `"api-key"`, `"other-auth"` |
| `originalStatus` | number | User A's HTTP status code |
| `replayStatus` | number | User B's HTTP status code |
| `originalSize` | number | User A's response size in bytes |
| `replaySize` | number | User B's response size in bytes |
| `matchType` | string | `"semantic-hash"`, `"raw-hash-fallback"`, or `"size-proximity"` |
| `evidence` | object | Hash evidence block |
| `request` | object | Request metadata |
| `recordedAt` | number | Unix epoch ms when original request was recorded |
| `replayedAt` | ISO-8601 string | When the replay was executed |
| `curl` | string | Reproduction command |
| `exposureSummary` | object or absent | Present only on confirmed BOLA findings with JSON responses |

> **Path privacy:** `path`, `request.path`, `resourceIds`, and `curl` preserve URL content verbatim for reproducibility. Unlike Exposure Summary field paths, they are **not** sanitized. If sensitive data appears in a URL (email, token, card number), it will appear in these fields. Treat reports as security artifacts.

## findings[].evidence

| Field | Type | Description |
|---|---|---|
| `originalContentHash` | string | Semantic hash of original response |
| `replayContentHash` | string | Semantic hash of replay response |
| `originalRawHash` | string | Raw-byte hash of original response |
| `replayRawHash` | string | Raw-byte hash of replay response |
| `matchedHash` | string | The specific hash that proved the match |
| `matchType` | string | How the match was established |

## findings[].request

| Field | Type | Description |
|---|---|---|
| `method` | string | HTTP method |
| `path` | string | Request path including query string |
| `queryPresent` | boolean | Whether a query string was present |
| `authMechanism` | string | Auth type used |
| `userAgentPreserved` | boolean | Whether the original User-Agent was available |

## findings[].exposureSummary

Present only on confirmed `broken-access-control` findings with JSON response bodies.

This field has two possible shapes:

### Normal shape (body analyzed)

| Field | Type | Description |
|---|---|---|
| `summaryGeneratedFromHash` | string | The evidence hash this summary was derived from |
| `contentType` | string | Response content type |
| `bodyBytes` | number | Response body size in bytes |
| `fieldPaths` | array of strings | Sanitized JSON field paths found in the response |
| `fieldPathsTruncated` | boolean | Whether the path list was capped at `fieldPathLimit` |
| `fieldPathLimit` | number | Maximum field paths (200) |
| `classificationSignals` | array | Conservative field-name-based classifications |
| `sanitizedFieldPaths` | boolean | Whether any object key was replaced with a placeholder |
| `sanitizedKeyTypes` | array of strings | Deduplicated placeholder types used (e.g. `["email-key", "uuid-key"]`) |
| `sanitizedKeySegments` | number | Count of key occurrences sanitized (before path dedup) |
| `rawBodyStored` | boolean | Always `false` |
| `rawValuesStored` | boolean | Always `false` |

### Skipped shape (body too large)

When the response body exceeds the 1 MB analysis ceiling, exposure analysis is skipped. The confirmed finding is unaffected — only the enrichment is skipped.

| Field | Type | Description |
|---|---|---|
| `skipped` | boolean | `true` |
| `reason` | string | `"body-too-large"` |
| `bodyBytes` | number | Actual body size in bytes |
| `bodyByteLimit` | number | The analysis ceiling (1048576) |
| `summaryGeneratedFromHash` | string | The evidence hash |
| `rawBodyStored` | boolean | Always `false` |
| `rawValuesStored` | boolean | Always `false` |

### Field-path sanitization

Field paths are built from JSON object keys. Keys that look like concrete runtime data are replaced with inert placeholders before storage so sensitive data is never persisted through a key:

| Placeholder | Replaces |
|---|---|
| `[email-key]` | keys matching an email pattern |
| `[uuid-key]` | keys matching a UUID pattern |
| `[token-like-key]` | JWT segments, `sk_`/`pk_`/`ghp_` style secret prefixes |
| `[numeric-key]` | all-digit keys of length ≥ 12 |
| `[dynamic-key]` | high-entropy random-looking keys ≥ 32 chars |
| `[unsafe-key]` | keys containing control characters, newlines, or ANSI escapes |

Schema field names (`email`, `vehicleId`, `latitude`, `accountId`, etc.) are kept unchanged. Placeholders are inert and never produce a classification signal.

When sanitization occurs, the summary discloses it honestly via `sanitizedFieldPaths: true`, `sanitizedKeyTypes` (which placeholder types were used), and `sanitizedKeySegments` (how many key occurrences were replaced, counted before path deduplication). Because path deduplication can collapse several distinct dynamic keys into a single path (e.g. three different emails all become `users.[email-key]`), the segment count preserves the fact that multiple dynamic keys existed without revealing them — so the report never looks more precise than it is.

## findings[].exposureSummary.classificationSignals[]

| Field | Type | Description |
|---|---|---|
| `field` | string | Full field path (e.g. `"author.email"`) |
| `signal` | string | Human-readable signal description |
| `classification` | string | Category: `possible_pii`, `possible_location`, `resource_identifier`, `possible_financial`, `possible_secret` |
| `confidence` | string | Pattern match quality: `"high"` |
