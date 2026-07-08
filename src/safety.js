'use strict';

const dns = require('dns').promises;

// Percent-decode a string until it stops changing (fully unwraps any depth of
// nested encoding — %2e, %252e, %25252e, ... all converge to the same value),
// or until a hard cap of passes is hit, whichever comes first.
//
// DECODE_MAX_PASSES caps the loop to bound worst-case CPU cost (decode-bomb
// style DoS protection). After the cap, the result may still contain residual
// percent-escaped sequences that were never fully unwrapped. Callers that need
// to detect path traversal MUST call foldEncodedDots() on the result before
// checking for '..', because the WHATWG URL spec's own dot-segment removal
// algorithm natively recognizes %2e/%2E as encoded dots without an explicit
// decodeURIComponent step. A scope entry that exits the cap as '/%2e%2e/'
// still normalizes to '/' inside new URL(...).pathname, widening the scope
// boundary even though the raw string contains no literal '..'.
const DECODE_MAX_PASSES = 10;

function decodeUntilStable(input, maxPasses = DECODE_MAX_PASSES) {
  let decoded = input;
  for (let i = 0; i < maxPasses; i++) {
    let next;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      break; // malformed escape — stop, use what we have
    }
    if (next === decoded) break; // fixed point reached
    decoded = next;
  }
  return decoded;
}

// Fold any percent-encoded dot sequences that survive the decode cap into
// their literal equivalents before checking for '..'.
//
// The WHATWG URL spec (section 5.1, "URL path segment") treats %2e/%2E as dot
// equivalents during path normalization, even if decodeURIComponent was never
// called on them. At the decode-cap boundary, decodeUntilStable() may return
// a string like '/%2e%2e/' that contains no literal '..' but is still collapsed
// to '/' by 'new URL(...).pathname'. Without this step, a scope entry encoded
// exactly DECODE_MAX_PASSES + 1 layers deep would pass the literal '..' check
// and then be silently widened at request time by normalizePath() in proxy.js.
//
// Only %2e/%2E are folded here — these are the only percent-encodings the URL
// spec treats as dot-segment equivalents. Deeper residual escapes like %252e
// are not folded (the URL spec does not collapse them without an explicit
// decode step), but they also cannot widen scope because normalizePath() uses
// the same decodeUntilStable+foldEncodedDots pipeline and would produce the
// same non-traversal result for any given input.
function foldEncodedDots(s) {
  return s.replace(/%2e/gi, '.');
}

// Private and loopback ranges in dotted-decimal form.
// All IP inputs are normalized to dotted-decimal before matching
// so that non-standard representations (decimal, hex, octal) are caught.
const PRIVATE_RANGES = [
  /^127\./,                          // loopback
  /^0\.0\.0\.0$/,                    // unspecified address
  /^10\./,                           // RFC 1918 class A
  /^172\.(1[6-9]|2\d|3[01])\./,     // RFC 1918 class B
  /^192\.168\./,                     // RFC 1918 class C
  /^169\.254\./,                     // link-local (AWS metadata: 169.254.169.254)
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // CGNAT (RFC 6598)
  /^::1$/,                           // IPv6 loopback
  /^f[cd][0-9a-f]{2}:/i,             // IPv6 unique local (fc00::/7 — covers fc and fd ranges)
  /^fe80:/i,                         // IPv6 link-local
  // IPv4-mapped IPv6 — ::ffff:x.x.x.x and ::ffff:hex:hex forms
  // These are private/loopback if the mapped IPv4 address is private.
  /^::ffff:(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/i,
  /^::ffff:(7f00|0a00|a9fe|ac1[0-9a-f]|ac[2-3][0-9a-f]|c0a8):/i,
];

// Normalize an IPv4 address that may be in decimal, hex, or octal notation
// to standard dotted-decimal. Returns null if not a recognized numeric form.
//
// Covers:
//   http://167772161       → 10.0.0.1  (32-bit decimal)
//   http://0x7f000001      → 127.0.0.1 (hex)
//   http://0177.0.0.1      → 127.0.0.1 (octal first octet)
//   http://10.0.1          → 10.0.0.1  (missing octets)
//
function normalizeIPv4(hostname) {
  // Already dotted-decimal — return as-is
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return hostname;

  // Pure numeric (decimal or hex) — treat as 32-bit IPv4
  if (/^(0x[0-9a-f]+|\d+)$/i.test(hostname)) {
    const n = Number(hostname); // handles 0x... and decimal
    if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return null;
    return [
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>>  8) & 0xff,
       n         & 0xff,
    ].join('.');
  }

  // Mixed octal/hex/decimal dotted notation, including shorthand forms with
  // fewer than 4 parts (e.g. 0177.0.0.1, 0x7f.0.0.1, 172.16, 10.1, 127.1).
  //
  // Shorthand dotted notation follows classic inet_aton semantics, which is
  // also what the WHATWG URL host parser applies to bare hostnames like
  // "172.16" before this code ever sees them (verified: new URL('http://172.16')
  // .hostname === '172.0.0.16', NOT '172.16.0.0'). Only the LAST part absorbs
  // whatever bits remain after the earlier parts — it is not simply appended
  // as another octet with zeros padded after it. Getting this wrong doesn't
  // just misreport an IP, it can misclassify a public address as private:
  // "172.16" naively read as "172.16.0.0" looks private (172.16.0.0/12), but
  // the address it actually names — 172.0.0.16 — is not in that block at all.
  if (/^[0-9a-fx.]+$/i.test(hostname) && hostname.includes('.')) {
    const parts = hostname.split('.');
    if (parts.length > 4) return null;
    try {
      const nums = parts.map(p => {
        let n;
        if (/^0x/i.test(p)) {
          n = parseInt(p, 16);          // hex: 0x7f
        } else if (/^0[0-9]+$/.test(p)) {
          n = parseInt(p, 8);           // octal: 0177
        } else {
          n = parseInt(p, 10);          // decimal
        }
        if (!Number.isFinite(n) || n < 0) throw new Error();
        return n;
      });

      // All parts except the last must fit in a single byte.
      for (let i = 0; i < nums.length - 1; i++) {
        if (nums[i] > 255) throw new Error();
      }

      // The last part absorbs whatever bits remain: 8 bits per already-placed
      // octet, so e.g. 2 parts total ("a.b") leaves 24 bits for b.
      const last          = nums[nums.length - 1];
      const remainingBits = 8 * (4 - (nums.length - 1));
      const maxLast       = remainingBits >= 32 ? 0xffffffff : (2 ** remainingBits) - 1;
      if (last > maxLast) throw new Error();

      const octets = nums.slice(0, -1);
      const remainingOctetCount = 4 - octets.length;
      for (let i = remainingOctetCount - 1; i >= 0; i--) {
        octets.push((last >>> (8 * i)) & 0xff);
      }
      return octets.join('.');
    } catch {
      return null;
    }
  }

  return null; // not a numeric IP — let DNS handle it
}

// Strip brackets from IPv6 addresses as returned by new URL().hostname.
// new URL("http://[::1]:3000").hostname === "[::1]" — brackets included.
// All internal checks expect the bare address without brackets.
function stripIPv6Brackets(hostname) {
  if (hostname && hostname.startsWith('[') && hostname.endsWith(']')) {
    return hostname.slice(1, -1);
  }
  return hostname;
}

function isPrivateAddress(address) {
  const normalized = normalizeIPv4(address) || address;
  return PRIVATE_RANGES.some(r => r.test(normalized));
}

// isPrivateHost is exported for tests and legacy callers.
// It checks both the raw hostname and its normalized form.
// Handles bracketed IPv6 addresses (e.g. "[::1]") from URL parsing.
function isPrivateHost(hostname) {
  if (!hostname) return false;
  if (/^localhost$/i.test(hostname)) return true;
  const bare = stripIPv6Brackets(hostname);
  const normalized = normalizeIPv4(bare);
  const toCheck = normalized || bare;
  return PRIVATE_RANGES.some(r => r.test(toCheck));
}

async function verifyTarget(targetUrl) {
  let url;
  try {
    url = new URL(targetUrl);
  } catch {
    throw new Error(`Invalid target URL: ${targetUrl}`);
  }

  if (url.protocol !== 'http:') {
    if (url.protocol === 'https:') {
      throw new Error(
        `Target is HTTPS — jabearri currently records HTTP traffic only.\n` +
        `Change your target to http://${url.host} to get started.\n` +
        `(Most local test environments work fine over HTTP.)`
      );
    }
    throw new Error(
      `Target protocol "${url.protocol}" is not supported — jabearri only works with http:// targets.\n` +
      `Example: { "target": "http://localhost:3000" }`
    );
  }

  // Strip brackets from IPv6 hostnames — new URL() includes them
  // but isPrivateHost and DNS resolution expect bare addresses.
  const hostname = stripIPv6Brackets(url.hostname);

  // Normalize first — catches decimal, hex, octal IP representations
  // before they reach the DNS resolver.
  if (isPrivateHost(hostname)) return;

  // If the hostname is itself a literal IP address — not a name that needs
  // DNS resolution — classify it directly. By this point new URL() has
  // already canonicalized any decimal/hex/octal/shorthand IPv4 form into
  // dotted-decimal, so a literal here is either dotted-decimal IPv4 or a
  // bare IPv6 address. Without this check, dns.resolve4/6() on a literal
  // IP fails (it isn't a resolvable hostname), which used to produce a
  // misleading "Could not resolve hostname" error for what is actually a
  // deliberate, already-known public IP target.
  const isLiteralIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const isLiteralIPv6 = hostname.includes(':');
  if (isLiteralIPv4 || isLiteralIPv6) {
    throw new Error(
      `SAFETY BLOCK: Target "${hostname}" is a public IP address.\n` +
      `jabearri only works against local or private-network targets.\n` +
      `Pointing this tool at systems you do not own or have written\n` +
      `authorization to test may be a criminal offence under the CFAA,\n` +
      `Computer Misuse Act, or equivalent laws in your jurisdiction.`
    );
  }

  // DNS resolution — confirm every resolved address is private.
  // Catches DNS rebinding: a public hostname that resolves to a private IP
  // is allowed; a private-looking name that resolves to a public IP is blocked.
  let addresses;
  try {
    const v4 = await dns.resolve4(hostname).catch(() => []);
    const v6 = await dns.resolve6(hostname).catch(() => []);
    addresses = [...v4, ...v6];
  } catch {
    throw new Error(`Could not resolve hostname: ${hostname}`);
  }

  if (addresses.length === 0) {
    throw new Error(`Could not resolve hostname: ${hostname}`);
  }

  const publicAddresses = addresses.filter(a => !isPrivateAddress(a));
  if (publicAddresses.length > 0) {
    throw new Error(
      `SAFETY BLOCK: Target "${hostname}" resolves to public IP(s): ${publicAddresses.join(', ')}.\n` +
      `jabearri only works against local or private-network targets.\n` +
      `Pointing this tool at systems you do not own or have written\n` +
      `authorization to test may be a criminal offence under the CFAA,\n` +
      `Computer Misuse Act, or equivalent laws in your jurisdiction.`
    );
  }
}

function verifyScope(scope) {
  if (!scope || !Array.isArray(scope) || scope.length === 0) {
    throw new Error(
      'No scope declared. Add a "scope" array to your jabearri.config.json.\n' +
      'Example: { "scope": ["/api/"] }'
    );
  }
  for (const entry of scope) {
    if (typeof entry !== 'string' || entry.length === 0) {
      throw new Error(
        `Invalid scope entry: ${JSON.stringify(entry)} — each scope entry must be a non-empty string.\n` +
        'Example: { "scope": ["/api/", "/rest/"] }'
      );
    }
    if (!entry.startsWith('/')) {
      throw new Error(
        `Invalid scope entry: ${JSON.stringify(entry)} — scope entries must start with "/".\n` +
        'Example: { "scope": ["/api/"] }'
      );
    }
    // Reject literal and arbitrarily-nested encoded traversal (%2e%2e, %252e%252e,
    // %25252e%25252e, mixed-depth combinations, cap-boundary residuals, etc.).
    //
    // Two-step normalization mirrors what happens at request time:
    //   1. decodeUntilStable — unwraps nested percent-encoding until stable or cap
    //   2. foldEncodedDots  — converts any residual %2e/%2E to '.' so that the
    //      subsequent '..' check catches entries that hit the cap boundary and
    //      exited still containing encoded dot-segments that the WHATWG URL spec
    //      would collapse natively (e.g. '/%2e%2e/' → '/' in new URL().pathname)
    const decoded = foldEncodedDots(decodeUntilStable(entry));
    if (decoded.includes('..')) {
      throw new Error(
        `Invalid scope entry: ${JSON.stringify(entry)} — scope entries must not contain ".." (including encoded forms).\n` +
        'Path traversal in scope entries resolves to unexpected paths after normalization.'
      );
    }
  }
}

module.exports = {
  verifyTarget,
  verifyScope,
  isPrivateHost,
  normalizeIPv4,
  stripIPv6Brackets,
  decodeUntilStable,
  foldEncodedDots,
  DECODE_MAX_PASSES,
};
