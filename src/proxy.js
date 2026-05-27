'use strict';

const http  = require('http');
const https = require('https');
const { URL } = require('url');
const { contentHash } = require('./replay');

class ProxyCore {
  constructor({ target, scope, exclude = [], store, logger }) {
    this.target  = new URL(target);
    this.scope   = scope;
    this.exclude = exclude;
    this.store   = store;
    this.logger  = logger || console;
    this.server  = null;
  }

  _inScope(pathname) {
    if (this.exclude.some(p => pathname.startsWith(p))) return false;
    return this.scope.some(p => pathname.startsWith(p));
  }

  _forward(incomingReq, bodyBuffer) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: this.target.hostname,
        port:     this.target.port || (this.target.protocol === 'https:' ? 443 : 80),
        path:     incomingReq.url,
        method:   incomingReq.method,
        headers:  { ...incomingReq.headers, host: this.target.host },
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
    const parsed   = new URL(req.url, 'http://localhost');
    const inScope  = this._inScope(parsed.pathname);
    const bodyBuffer = await this._readBody(req);

    let upstream;
    try {
      upstream = await this._forward(req, bodyBuffer);
    } catch (err) {
      this.logger.error(`[accguard] Forward error: ${err.message}`);
      res.writeHead(502);
      res.end('accguard: upstream connection failed');
      return;
    }

    if (inScope) {
      this.store.record({
        method:        req.method,
        url:           req.url,
        headers:       req.headers,
        statusCode:    upstream.statusCode,
        contentLength: upstream.body.length,
        contentHash:   contentHash(upstream.body, upstream.headers['content-type'] || ''),
      });
    }

    res.writeHead(upstream.statusCode, upstream.headers);
    res.end(upstream.body);
  }

  listen(port) {
    return new Promise(resolve => {
      this.server = http.createServer((req, res) => {
        this._handleRequest(req, res).catch(err => {
          this.logger.error(`[accguard] Unhandled error: ${err.message}`);
          if (!res.headersSent) { res.writeHead(500); res.end('accguard: internal error'); }
        });
      });

      // Catch HTTPS CONNECT attempts — explain clearly instead of failing silently
      this.server.on('connect', (req, socket) => {
        this.logger.log(
          `[accguard] HTTPS request for "${req.url}" — accguard records HTTP only.\n` +
          `           Update your target to http:// or configure your app to use HTTP in tests.`
        );
        socket.write('HTTP/1.1 501 HTTPS Not Supported\r\n\r\n');
        socket.end();
      });

      // SAFETY: bind only to loopback — cannot be reached from outside this machine
      this.server.listen(port, '127.0.0.1', () => {
        this.logger.log(`[accguard] Proxy listening on 127.0.0.1:${port} → ${this.target.href}`);
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
