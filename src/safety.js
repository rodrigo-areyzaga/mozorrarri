'use strict';

const dns = require('dns').promises;

// Private and loopback ranges in dotted-decimal form.
// All IP inputs are normalized to dotted-decimal before matching
// so that non-standard representations (decimal, hex, octal) are caught.
const PRIVATE_RANGES = [
  /^127\./,                          // loopback
  /^10\./,                           // RFC 1918 class A
  /^172\.(1[6-9]|2\d|3[01])\./,     // RFC 1918 class B
  /^192\.168\./,                     // RFC 1918 class C
  /^::1$/,                           // IPv6 loopback
  /^f[cd][0-9a-f]{2}:/i,             // IPv6 unique local (fc00::/7 — covers fc and fd ranges)
  /^fe80:/i,                         // IPv6 link-local
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

  // Mixed octal/hex/decimal dotted notation (e.g. 0177.0.0.1, 0x7f.0.0.1)
  if (/^[0-9a-fx.]+$/i.test(hostname) && hostname.includes('.')) {
    const parts = hostname.split('.');
    if (parts.length > 4) return null;
    try {
      const octets = parts.map(p => {
        let n;
        if (/^0x/i.test(p)) {
          n = parseInt(p, 16);          // hex: 0x7f
        } else if (/^0[0-9]+$/.test(p)) {
          n = parseInt(p, 8);           // octal: 0177
        } else {
          n = parseInt(p, 10);          // decimal
        }
        if (!Number.isFinite(n) || n < 0 || n > 255) throw new Error();
        return n;
      });
      while (octets.length < 4) octets.push(0);
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

  if (url.protocol === 'https:') {
    throw new Error(
      `Target is HTTPS — mozorrarri currently records HTTP traffic only.\n` +
      `Change your target to http://${url.host} to get started.\n` +
      `(Most local test environments work fine over HTTP.)`
    );
  }

  // Strip brackets from IPv6 hostnames — new URL() includes them
  // but isPrivateHost and DNS resolution expect bare addresses.
  const hostname = stripIPv6Brackets(url.hostname);

  // Normalize first — catches decimal, hex, octal IP representations
  // before they reach the DNS resolver.
  if (isPrivateHost(hostname)) return;

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
      `mozorrarri only works against local or private-network targets.\n` +
      `Pointing this tool at systems you do not own or have written\n` +
      `authorization to test may be a criminal offence under the CFAA,\n` +
      `Computer Misuse Act, or equivalent laws in your jurisdiction.`
    );
  }
}

function verifyScope(scope) {
  if (!scope || !Array.isArray(scope) || scope.length === 0) {
    throw new Error(
      'No scope declared. Add a "scope" array to your mozorrarri.config.json.\n' +
      'Example: { "scope": ["/api/"] }'
    );
  }
}

module.exports = { verifyTarget, verifyScope, isPrivateHost, normalizeIPv4, stripIPv6Brackets };
