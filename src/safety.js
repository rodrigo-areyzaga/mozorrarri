'use strict';

const dns = require('dns').promises;

const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^::1$/,
  /^localhost$/i,
];

function isPrivateHost(hostname) {
  return PRIVATE_RANGES.some(r => r.test(hostname));
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
      `Target is HTTPS — accguard currently records HTTP traffic only.\n` +
      `Change your target to http://${url.host} to get started.\n` +
      `(Most local test environments work fine over HTTP.)`
    );
  }

  const hostname = url.hostname;
  if (isPrivateHost(hostname)) return;

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

  const publicAddresses = addresses.filter(a => !isPrivateHost(a));
  if (publicAddresses.length > 0) {
    throw new Error(
      `SAFETY BLOCK: Target "${hostname}" resolves to public IP(s): ${publicAddresses.join(', ')}.\n` +
      `accguard only works against local or private-network targets.\n` +
      `Pointing this tool at systems you do not own or have written\n` +
      `authorization to test may be a criminal offence under the CFAA,\n` +
      `Computer Misuse Act, or equivalent laws in your jurisdiction.`
    );
  }
}

function verifyScope(scope) {
  if (!scope || !Array.isArray(scope) || scope.length === 0) {
    throw new Error(
      'No scope declared. Add a "scope" array to your accguard.config.json.\n' +
      'Example: { "scope": ["/api/"] }'
    );
  }
}

module.exports = { verifyTarget, verifyScope, isPrivateHost };
