'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// exposure-summary.js — Derived metadata for confirmed BOLA findings
//
// Inspects the replay response body (already in memory) and extracts:
//   · JSON field paths
//   · Conservative classification signals (field-name-based only)
//   · Content type, body size, evidence hash
//
// Does NOT store:
//   · Raw response bodies
//   · Raw field values
//   · Raw tokens
//
// Runs ONLY on confirmed broken-access-control findings.
// Does NOT affect detection or pass/fail behavior.
// ─────────────────────────────────────────────────────────────────────────────

const MAX_FIELD_PATHS  = 200;
const MAX_DEPTH        = 12;
const MAX_ARRAY_ITEMS  = 5;

// Pre-parse body-size ceiling for analysis. The replay body is already in
// memory (received during replay), but JSON.parse + recursive traversal of a
// very large body is a second, avoidable cost. If the body exceeds this limit,
// Exposure Summary is skipped — the confirmed finding is NOT affected.
// 1 MB is conservative: authorization-relevant responses are almost always
// much smaller. A confirmed BOLA on a large export still reports the finding;
// only the enrichment is skipped.
const MAX_EXPOSURE_BODY_BYTES = 1024 * 1024; // 1 MB

// ── Key sanitization ─────────────────────────────────────────────────────────
//
// JSON object keys become field-path segments. When an API keys its objects by
// runtime data (email, UUID, token, numeric ID) rather than by schema field
// name, that data would otherwise be persisted verbatim in the report — a
// privacy leak through the key, not the value.
//
// Sanitization replaces only key segments that clearly look like concrete
// runtime data. Schema field names (email, vehicleId, latitude, accountId) are
// kept unchanged so the exposure shape and classification remain useful.
//
// Precedence is deterministic — the same key always maps to the same placeholder.
// Checked in order; first match wins:
//   1. control chars / newlines / ANSI escapes → [unsafe-key]   (safety first)
//   2. email pattern                           → [email-key]
//   3. UUID pattern                            → [uuid-key]
//   4. token-like (JWT segments, sk_/pk_ etc.) → [token-like-key]
//   5. all-digits, length >= 12                → [numeric-key]
//   6. long high-entropy random-looking string → [dynamic-key]
//   7. otherwise                               → keep as-is (schema field name)
//
// Placeholders are inert: they never match classification rules.

const KEY_EMAIL_RE  = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const KEY_UUID_RE   = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Token-like: JWT (three dot-separated base64url segments), or known secret
// prefixes (sk_, pk_, rk_, ghp_, xox...), or a long opaque base64url blob.
const KEY_JWT_RE    = /^[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}$/;
const KEY_PREFIX_RE = /^(sk|pk|rk|ak|ghp|gho|ghs|xox[b-p])[-_][A-Za-z0-9_-]{8,}$/i;
const KEY_NUMERIC_RE = /^\d{12,}$/;
// Control characters, newlines, tabs, or ANSI escape introducer.
// eslint-disable-next-line no-control-regex
const KEY_UNSAFE_RE = /[\u0000-\u001f\u007f\u009b]/;
// High-entropy heuristic: >= 32 chars, alphanumeric-ish, and contains a mix of
// cases or digits (i.e. doesn't look like a normal lowerCamelCase schema word).
const KEY_LONG_LEN  = 32;

const PLACEHOLDERS = new Set([
  '[unsafe-key]', '[email-key]', '[uuid-key]',
  '[token-like-key]', '[numeric-key]', '[dynamic-key]',
]);

function looksHighEntropy(key) {
  if (key.length < KEY_LONG_LEN) return false;
  // Must be a single contiguous token (no spaces) and contain digits or mixed
  // case — a long lowercase-only word like a sentence fragment is left alone.
  if (/\s/.test(key)) return false;
  const hasDigit = /\d/.test(key);
  const hasUpper = /[A-Z]/.test(key);
  const hasLower = /[a-z]/.test(key);
  return hasDigit || (hasUpper && hasLower);
}

function sanitizeKeySegment(key) {
  if (typeof key !== 'string') return String(key);
  if (KEY_UNSAFE_RE.test(key))   return '[unsafe-key]';
  if (KEY_EMAIL_RE.test(key))    return '[email-key]';
  if (KEY_UUID_RE.test(key))     return '[uuid-key]';
  if (KEY_JWT_RE.test(key) || KEY_PREFIX_RE.test(key)) return '[token-like-key]';
  if (KEY_NUMERIC_RE.test(key))  return '[numeric-key]';
  if (looksHighEntropy(key))     return '[dynamic-key]';
  return key;
}

// ── Classification patterns ─────────────────────────────────────────────────
// Field-name-based signals only. These say "this field path looks like it
// could contain PII / location / financial / secret / identifier data."
// They do NOT say "this value was leaked" — only that the field name matches
// a known sensitive pattern. Confidence is about the pattern match quality,
// not about the severity of the exposure.

const CLASSIFICATION_RULES = [
  {
    classification: 'possible_pii',
    confidence:     'high',
    signal:         'email-like field name',
    test:           /^(e[-_]?mail|user[-_]?name|full[-_]?name|first[-_]?name|last[-_]?name|phone|phone[-_]?number|mobile|ssn|social[-_]?security|date[-_]?of[-_]?birth|dob)$/i,
  },
  {
    classification: 'possible_location',
    confidence:     'high',
    signal:         'location-like field name',
    test:           /^(lat|latitude|lng|long|longitude|gps|geo|location|address|city|state|zip|zip[-_]?code|postal[-_]?code|country|street)$/i,
  },
  {
    classification: 'resource_identifier',
    confidence:     'high',
    signal:         'identifier-like field name',
    test:           /^(id|uuid|_id|user[-_]?id|account[-_]?id|order[-_]?id|transaction[-_]?id|vehicle[-_]?id|customer[-_]?id|payment[-_]?id|document[-_]?id|session[-_]?id|record[-_]?id)$/i,
  },
  {
    classification: 'possible_financial',
    confidence:     'high',
    signal:         'financial-like field name',
    test:           /^(account|balance|card|card[-_]?number|payment|iban|routing[-_]?number|credit|debit|amount|total|price|cost|salary|income)$/i,
  },
  {
    classification: 'possible_secret',
    confidence:     'high',
    signal:         'secret-like field name',
    test:           /^(password|passwd|secret|api[-_]?key|api[-_]?secret|token|access[-_]?token|refresh[-_]?token|private[-_]?key|credential|auth[-_]?token)$/i,
  },
];

// ── Field path extraction ───────────────────────────────────────────────────

function extractFieldPaths(value, prefix, paths, depth, sanitized) {
  // Depth cap: do not inspect deeper than MAX_DEPTH. Keys are pushed at depths
  // 0..MAX_DEPTH-1, so the deepest stored path has exactly MAX_DEPTH segments.
  if (depth >= MAX_DEPTH) return;
  if (paths.length >= MAX_FIELD_PATHS) return;

  if (Array.isArray(value)) {
    // Sample up to MAX_ARRAY_ITEMS elements — union their field paths.
    // This captures the shape of heterogeneous arrays without exploding
    // the path list for large collections.
    const sample = value.slice(0, MAX_ARRAY_ITEMS);
    for (const item of sample) {
      if (paths.length >= MAX_FIELD_PATHS) return;
      extractFieldPaths(item, prefix + '[]', paths, depth + 1, sanitized);
    }
    return;
  }

  if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    for (const key of keys) {
      if (paths.length >= MAX_FIELD_PATHS) return;
      // Sanitize the key segment before it becomes part of a stored field path.
      // Dynamic/sensitive keys (email, UUID, token, long numeric, high-entropy)
      // are replaced with inert placeholders so they are never persisted.
      const safeKey   = sanitizeKeySegment(key);
      // Track sanitization for honest report metadata. A placeholder means the
      // original key was replaced; record the type and count an occurrence.
      if (sanitized && safeKey !== key && PLACEHOLDERS.has(safeKey)) {
        sanitized.count++;
        sanitized.types.add(safeKey.slice(1, -1)); // strip the surrounding [ ]
      }
      const fieldPath = prefix ? prefix + '.' + safeKey : safeKey;
      paths.push(fieldPath);
      extractFieldPaths(value[key], fieldPath, paths, depth + 1, sanitized);
    }
    return;
  }

  // Primitives — the field path was already added by the parent object handler.
  // Nothing to recurse into.
}

// ── Classification ──────────────────────────────────────────────────────────

function classifyFieldPath(fieldPath) {
  // Extract the leaf field name from the full path.
  // "author.email" → "email", "data[].account.balance" → "balance"
  const leaf = fieldPath.split('.').pop().replace(/\[\]$/, '');

  // Sanitization placeholders are inert — they preserve structure, not signal.
  // A key sanitized to [email-key] must not be classified as possible_pii.
  if (PLACEHOLDERS.has(leaf)) return null;

  for (const rule of CLASSIFICATION_RULES) {
    if (rule.test.test(leaf)) {
      return {
        field:          fieldPath,
        signal:         rule.signal,
        classification: rule.classification,
        confidence:     rule.confidence,
      };
    }
  }

  return null;
}

// ── Main entry point ────────────────────────────────────────────────────────

function buildExposureSummary(body, contentType, evidenceHash) {
  // Guard: only JSON responses
  if (!body || body.length === 0) return { skipped: true, reason: 'empty-body', fieldPaths: [], classificationSignals: [] };
  if (!contentType || !/json/i.test(contentType)) return { skipped: true, reason: 'non-json-content-type', fieldPaths: [], classificationSignals: [] };

  // Pre-parse body-size ceiling — analysis protection, not network protection.
  // The body is already in memory from replay; this guards against the second
  // cost of parsing + traversing a very large body. If exceeded, return a
  // minimal skipped summary rather than null — "we looked and chose not to
  // analyze" is more audit-honest than silent absence. The confirmed finding
  // is unaffected.
  if (body.length > MAX_EXPOSURE_BODY_BYTES) {
    return {
      skipped:         true,
      reason:          'body-too-large',
      bodyBytes:       body.length,
      bodyByteLimit:   MAX_EXPOSURE_BODY_BYTES,
      summaryGeneratedFromHash: evidenceHash,
      rawBodyStored:   false,
      rawValuesStored: false,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    return null;
  }

  // Guard: must be a non-trivial object or array-of-objects
  if (parsed === null || typeof parsed !== 'object') return null;
  if (Array.isArray(parsed) && parsed.length === 0) return null;
  if (!Array.isArray(parsed) && Object.keys(parsed).length === 0) return null;

  // Extract field paths, tracking any key sanitization for honest metadata.
  const paths = [];
  const sanitized = { count: 0, types: new Set() };
  extractFieldPaths(parsed, '', paths, 0, sanitized);

  if (paths.length === 0) return null;

  const truncated = paths.length >= MAX_FIELD_PATHS;

  // Deduplicate paths (array sampling can produce duplicates across elements)
  const uniquePaths = [...new Set(paths)];

  // Classify
  const signals = [];
  for (const p of uniquePaths) {
    const signal = classifyFieldPath(p);
    if (signal) signals.push(signal);
  }

  return {
    summaryGeneratedFromHash: evidenceHash,
    contentType:             contentType,
    bodyBytes:               body.length,
    fieldPaths:              uniquePaths,
    fieldPathsTruncated:     truncated,
    fieldPathLimit:          MAX_FIELD_PATHS,
    classificationSignals:   signals,
    // Sanitization metadata — honest disclosure that some key segments were
    // replaced with placeholders. Counts occurrences (before dedup) so the
    // report does not look more precise than it is; deduplication of paths can
    // collapse distinct dynamic keys into one path.
    sanitizedFieldPaths:     sanitized.count > 0,
    sanitizedKeyTypes:       [...sanitized.types],
    sanitizedKeySegments:    sanitized.count,
    rawBodyStored:           false,
    rawValuesStored:         false,
  };
}

module.exports = {
  buildExposureSummary,
  extractFieldPaths,
  classifyFieldPath,
  sanitizeKeySegment,
  // Exported for testing
  MAX_FIELD_PATHS,
  MAX_DEPTH,
  MAX_ARRAY_ITEMS,
  MAX_EXPOSURE_BODY_BYTES,
  CLASSIFICATION_RULES,
};
