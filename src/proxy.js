'use strict';

const http   = require('http');
const https  = require('https');
const crypto = require('crypto');
const { URL } = require('url');
const { contentHash } = require('./replay');
const { stripIPv6Brackets } = require('./safety');

// Normalize a URL path for scope/exclude matching.
// Applies the same transformations most web servers apply before routing:
//   1. Lowercase
//   2. Two-pass percent-decode — catches double-encoding (%252F → %2F → /)
//      and other double-encoded characters (%2562 → %62 → b)
//   3. Replace residual %2f/%2F with / after decode passes
//   4. Resolve path traversal via URL normalization
//   5. Strip matrix parameters (;param=value) — Java/Tomcat strip these before routing
function normalizePath(p) {
  try {
    // Two-pass decode: first pass handles single encoding, second catches double encoding.
    // decodeURIComponent throws on malformed sequences — catch and use what we have.
    let decoded = p;
    for (let i = 0; i < 2; i++) {
      try { decoded = decodeURIComponent(decoded); } catch { break; }
    }
    decoded = decoded.toLowerCase();
    // Replace any residual encoded slashes that survived decoding
    decoded = decoded.replace(/%2f/gi, '/');
    // Resolve traversal sequences via URL normalization
    const normalized = new URL(decoded, 'http://x').pathname;
    // Strip matrix parameters — ;v=1, ;jsessionid=abc, etc.
    return normalized.replace(/;[^/]*/g, '');
  } catch {
    return p.toLowerCase().replace(/;[^/]*/g, '');
  }
}

// Headers to strip before forwarding.
// accept-encoding  — forces uncompressed JSON for reliable hashing
// transfer-encoding — stale framing from chunked requests; we buffer fully
// connection        — hop-by-hop, must not be forwarded per HTTP spec
const STRIP_HEADERS = new Set(['accept-encoding', 'transfer-encoding', 'connection']);

class ProxyCore {
  constructor({ target, scope, exclude = [], store, logger, onFlush }) {
    this.target   = new URL(target);
    // Normalize scope and exclude at construction time — lowercase and decode
    // unreserved percent-encoding so they match what the target router sees.
    // Prevents case/encoding discrepancies between proxy scope matching and
    // server routing from creating exclude-list bypasses.
    this.scope    = scope.map(normalizePath);
    this.exclude  = exclude.map(normalizePath);
    this.store    = store;
    this.logger   = logger || console;
    this.onFlush  = onFlush || null; // callback for CI /--flush endpoint
    this.server   = null;
  }

  _inScope(pathname) {
    // Normalize the incoming pathname the same way scope/exclude were normalized
    // at construction — lowercase, decode unreserved percent-encoding.
    // Path traversal (/../) is already resolved by new URL() before this runs.
    // This ensures /api/PUBLIC/ and /api/pu%62lic/ match an exclude of /api/public/.
    const normalized = normalizePath(pathname);

    // startsWith check with boundary guard — prevents /api/public matching
    // /api/publications. A prefix p matches only if the next char after p
    // is '/' or the path ends exactly at p.
    // Also handles the trailing-slash gap: an exclude of /api/public/ matches
    // both /api/public/catalog AND the bare /api/public (no trailing slash),
    // since most servers treat those as equivalent.
    const matches = (p) => {
      // Strip trailing slash from p for the comparison so both /api/public/
      // and /api/public are treated as the same pattern boundary.
      const base = p.endsWith('/') ? p.slice(0, -1) : p;
      if (!normalized.startsWith(base)) return false;
      const next = normalized[base.length];
      return next === undefined || next === '/';       // end of path or subpath
    };

    if (this.exclude.some(matches)) return false;
    return this.scope.some(matches);
  }

  _forward(incomingReq, bodyBuffer, inScope) {
    return new Promise((resolve, reject) => {
      // Normalize absolute URLs — HTTP_PROXY clients send full URLs as path:
      // "GET http://127.0.0.1:3100/api/orders/1" instead of "GET /api/orders/1"
      // Many frameworks reject absolute-form request targets.
      let targetPath;
      try {
        const parsed = new URL(incomingReq.url, this.target.href);
        targetPath = parsed.pathname + parsed.search;
      } catch {
        targetPath = incomingReq.url;
      }

      // For in-scope requests, strip accept-encoding so upstream returns
      // uncompressed JSON that can be reliably hashed.
      const headers = { ...incomingReq.headers, host: this.target.host };
      // Always strip hop-by-hop and encoding headers.
      // transfer-encoding and connection must not be forwarded per HTTP/1.1 spec.
      // accept-encoding stripped for in-scope requests to ensure uncompressed JSON.
      for (const h of STRIP_HEADERS) {
        if (h === 'accept-encoding' && !inScope) continue; // only strip for in-scope
        delete headers[h];
      }
      // Recalculate content-length from the actual buffer — original header
      // may not match after chunked reassembly or proxy middleware manipulation.
      if (bodyBuffer && bodyBuffer.length) {
        headers['content-length'] = bodyBuffer.length;
      } else {
        delete headers['content-length'];
      }

      const options = {
        // Strip brackets from IPv6 hostnames — new URL().hostname includes them
        // (e.g. "[::1]") but http.request() expects bare addresses ("::1").
        // The Host header retains brackets as required by RFC 2732.
        hostname: stripIPv6Brackets(this.target.hostname),
        port:     this.target.port || (this.target.protocol === 'https:' ? 443 : 80),
        path:     targetPath,
        method:   incomingReq.method,
        headers,
      };

      const transport = this.target.protocol === 'https:' ? https : http;
      const req = transport.request(options, res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve({
          statusCode:  res.statusCode,
          headers:     res.headers,
          body:        Buffer.concat(chunks),
        }));
      });

      req.on('error', reject);
      req.setTimeout(30000, () => { req.destroy(); reject(new Error('upstream timeout after 30s')); });
      if (bodyBuffer && bodyBuffer.length) req.write(bodyBuffer);
      req.end();
    });
  }

  _readBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end',  () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  async _handleRequest(req, res) {
    // CI flush endpoint — handled entirely here, not forwarded.
    // onFlush callback is set by cli.js so the proxy doesn't need to
    // know about replay logic.
    if (req.url === '/--flush' && req.method === 'POST') {
      res.writeHead(200);
      res.end('flushing');
      if (this.onFlush) setImmediate(this.onFlush); // respond first, then flush
      return;
    }

    const parsed  = new URL(req.url, 'http://localhost');
    const inScope = this._inScope(parsed.pathname);
    const bodyBuffer = await this._readBody(req);

    let upstream;
    try {
      upstream = await this._forward(req, bodyBuffer, inScope);
    } catch (err) {
      this.logger.error(`[mozorrarri] Forward error: ${err.message}`);
      res.writeHead(502);
      res.end('mozorrarri: upstream connection failed');
      return;
    }

    if (inScope) {
      const rawHashVal = 'raw:' + crypto.createHash('sha256').update(upstream.body).digest('hex');
      this.store.record({
        method:        req.method,
        url:           req.url,
        headers:       req.headers,
        statusCode:    upstream.statusCode,
        contentLength: upstream.body.length,
        contentHash:   contentHash(upstream.body, upstream.headers['content-type'] || ''),
        rawHash:       rawHashVal, // always stored — used for hash-family consistency check
      });
    }

    res.writeHead(upstream.statusCode, upstream.headers);
    res.end(upstream.body);
  }

  listen(port) {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this._handleRequest(req, res).catch(err => {
          this.logger.error(`[mozorrarri] Unhandled error: ${err.message}`);
          if (!res.headersSent) { res.writeHead(500); res.end('mozorrarri: internal error'); }
        });
      });

      // Catch HTTPS CONNECT attempts — explain clearly instead of failing silently
      this.server.on('connect', (req, socket) => {
        this.logger.log(
          `[mozorrarri] HTTPS request for "${req.url}" — mozorrarri records HTTP only.\n` +
          `           Update your target to http:// or configure your app to use HTTP in tests.`
        );
        socket.write('HTTP/1.1 501 HTTPS Not Supported\r\n\r\n');
        socket.end();
      });

      // Reject on startup errors — e.g. port already in use
      this.server.once('error', reject);

      // SAFETY: bind only to loopback — cannot be reached from outside this machine
      this.server.listen(port, '127.0.0.1', () => {
        this.server.removeListener('error', reject);
        this.logger.log(`[mozorrarri] Proxy listening on 127.0.0.1:${port} → ${this.target.href}`);
        resolve();
      });
    });
  }

  close() {
    return new Promise(resolve => {
      if (this.server) this.server.close(resolve);
      else resolve();
    });
  }
}

module.exports = { ProxyCore };
