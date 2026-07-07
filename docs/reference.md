# jabearri — configuration, token types, and known limitations

This document covers everything you don't need on day one: full config/env reference, supported auth schemes, and known scope limitations worth knowing before you integrate jabearri into a larger or non-standard test setup.

---

## Configuration

| Field        | Required | Description |
|---|---|---|
| `target`     | yes | URL of your local app |
| `scope`      | yes | Path prefixes to record — e.g. `["/api/"]` |
| `exclude`    | no  | Path prefixes to always skip |
| `port`       | no  | Proxy port — default `8877` |
| `outputFile` | no  | JSON report path — default `jabearri-report.json` |
| `minObserved` | no | Minimum number of recorded requests expected before replay — exits `2` if fewer are observed, to catch proxy bypass. Disabled (`0`) unless set. |

| Environment variable | Description |
|---|---|
| `JABEARRI_TOKEN_B`   | Second user's credential value for replay — token, cookie value, API key, or Basic credential payload depending on the original auth mechanism |
| `JABEARRI_CONFIG`    | Path to config file — default `./jabearri.config.json` |
| `JABEARRI_MAX_ENTRIES` | Max session store entries — default `10000` |
| `JABEARRI_COOKIE_NAME` | Force a specific cookie name for session extraction — use when your framework uses a non-standard name not in the default list |
| `JABEARRI_API_KEY_HEADER` | Header name for API key authentication — default `x-api-key`. Use if your API uses a custom header like `x-client-key` |

Add `minObserved` to your config to catch proxy bypass silently:
```json
{
  "minObserved": 5
}
```
If fewer than `minObserved` requests are recorded, jabearri exits with code `2` and explains the likely cause. This prevents a misconfigured proxy from producing a false green run.

---

## Token type awareness

**Supported auth schemes:** Bearer tokens, session cookies (common framework defaults), HTTP Basic, Token (Django REST Framework), ApiKey, and `X-API-Key` header. For non-Bearer schemes, jabearri records and fingerprints the credential — replay will use `JABEARRI_TOKEN_B` with the original scheme prefix.

For prefix-based `Authorization` schemes such as `Bearer`, `Token`, and `ApiKey`, jabearri preserves the original scheme and replaces only the credential value with `JABEARRI_TOKEN_B`.

For `X-API-Key` or a custom API-key header, `JABEARRI_TOKEN_B` should be the raw API key value.

For HTTP Basic, `JABEARRI_TOKEN_B` should be the replay user's base64-encoded `username:password` credential if jabearri is constructing the `Basic` header.

HTTP Digest is fingerprint-only for most practical purposes. Because Digest is challenge-response, replay generally will not authenticate unless the full precomputed Digest header is supplied and still valid.

**Header fidelity:** replay reconstructs a minimal request (auth, accept, accept-encoding, original User-Agent). Headers like `Accept-Language`, `X-Tenant-ID`, or custom feature-flag headers carried by the original request are not replayed. If your app varies response content based on these headers, hashes may differ even when the underlying data is identical — a real BOLA may be missed. Document those endpoints for manual verification.

jabearri automatically recognizes session cookies from common framework defaults, including Express (`connect.sid`), Laravel (`laravel_session`), PHP (`PHPSESSID`), Java (`JSESSIONID`), NextAuth, ASP.NET, Rails (`_session_id`), and Django (`sessionid`). Set `JABEARRI_COOKIE_NAME` only if your framework uses a non-standard name.

jabearri records how each token was delivered — `Authorization: Bearer` header or session cookie — and replays using the same mechanism. Rails apps using `session=` cookies, Django apps using `sessionid=`, and Bearer token APIs all work correctly without configuration.

---

## Known scope limitations

A few edge cases worth knowing before you integrate:

**axios proxy behavior depends on version and configuration.** Recent axios versions can read conventional `http_proxy` / `https_proxy` environment variables, but custom agents, `NO_PROXY`, or runtime differences can still cause traffic to bypass jabearri. If requests are not being recorded, configure the proxy explicitly:
```javascript
const axios = require('axios');

axios.defaults.proxy = {
  protocol: 'http',
  host: '127.0.0.1',
  port: 8877
};
```
If you use a custom `httpAgent` / `httpsAgent`, make sure it is proxy-aware.

**Playwright should be configured explicitly.** If Playwright traffic is not being recorded, set the proxy in your Playwright config:
```javascript
// playwright.config.js
module.exports = {
  use: {
    proxy: { server: 'http://127.0.0.1:8877' },
  },
};
```
Or per-browser in your test setup:
```javascript
const browser = await chromium.launch();
const context = await browser.newContext({
  proxy: { server: 'http://127.0.0.1:8877' }
});
```

**`204 No Content` responses are not flagged.** Some APIs return `204` with no body on successful resource access. jabearri requires a non-empty response body to confirm a finding — a `204` replay will not be reported even if user B should not have access. These endpoints require manual verification.

**Multi-user test suites.** If your test suite exercises more than two users, jabearri records all of their traffic but replays everything with a single `JABEARRI_TOKEN_B`. Requests made by user C will be replayed as user B, which may not reflect the access boundary you want to test. Document your expected principal pairs explicitly in your test config.

**jabearri models identity through authorization credentials only.** Applications using additional tenant-isolation headers — such as `X-Tenant-ID`, `X-Org-ID`, or custom routing metadata — may not be fully covered by token-swap replay alone. If your app uses secondary isolation mechanisms beyond bearer tokens or session cookies, those endpoints require additional manual verification.

**Responses with volatile fields may not be flagged.** If API responses include fields that change per-request — timestamps, trace IDs, request UUIDs, nonces — the normalized JSON hashes will differ between user A and user B even when the underlying data is identical. This is an intentional tradeoff: determinism over recall. A future configuration option (`ignoreKeys`) is planned for teams whose APIs include volatile metadata fields.

**Windows: `node` not recognized in PowerShell.** If you get `node: command not found` after installing Node.js, close and reopen PowerShell. If that doesn't work, refresh PATH without reopening:
```powershell
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
```
Then run `npm run test:all` again.

**Node.js native `fetch` requires explicit proxy handling.** On current Node versions, `fetch()` can use `HTTP_PROXY` / `HTTPS_PROXY` when Node is started with `NODE_USE_ENV_PROXY=1` or `--use-env-proxy`:
```bash
NODE_USE_ENV_PROXY=1 \
HTTP_PROXY=http://127.0.0.1:8877 \
NO_PROXY="" \
npm test
```
On older Node versions, or if your runtime does not use Node's env-proxy support, native `fetch` may bypass jabearri. In that case, use a proxy-aware client for the test suite or configure Undici explicitly (e.g. `EnvHttpProxyAgent` / `ProxyAgent`).

**Some environments bypass proxies for localhost by default.** If requests are not being recorded, try setting `NO_PROXY` to empty or using `--noproxy` explicitly:
```bash
# curl
curl --noproxy "" --proxy http://127.0.0.1:8877 http://localhost:3000/api/orders

# Node.js / npm test
NO_PROXY="" HTTP_PROXY=http://127.0.0.1:8877 npm test
```

**Repeated endpoint calls are deduplicated.** If your test suite calls `GET /api/orders/1001` fifteen times (setup, assertions, teardown), jabearri records all fifteen but replays once. One finding per unique endpoint — not fifteen.

---

## Exposure Summary — field/signal reference

The Exposure Summary inspects response bodies while they are already in memory during replay. It does not persist response bodies.

Responses larger than 1 MB skip exposure analysis (the body is already in memory from replay, but parsing and walking a very large body is an avoidable second cost). When skipped, the confirmed finding is still reported with an exposure summary marked `skipped: true, reason: "body-too-large"`.

Classification signals are field-name-based only. A signal like `email → possible_pii` means "the field name matches a known PII pattern." It does not mean "a specific email address was leaked." The distinction between fact and signal is load-bearing.

**Signal categories:**

| Category | Matches |
|---|---|
| `possible_pii` | email, username, firstName, lastName, phone, ssn, dob |
| `possible_location` | lat, latitude, lng, longitude, address, city, zip |
| `resource_identifier` | id, uuid, userId, accountId, orderId |
| `possible_financial` | balance, card, payment, iban, amount, total |
| `possible_secret` | password, secret, apiKey, token, privateKey |

Exposure Summary is enabled by default for confirmed findings. It runs only on JSON responses and only after the hash comparison has already confirmed the authorization failure. It does not affect detection or pass/fail behavior.

Schema field names (`email`, `vehicleId`, `latitude`, `accountId`) are kept unchanged and classified normally — only key segments that look like concrete runtime data are sanitized, so the exposure shape stays useful.

**Sample JSON report finding with Exposure Summary:**

```json
{
  "findingId": "AG-20260610T183012Z-001",
  "severity": "high",
  "type": "broken-access-control",
  "confidence": "confirmed",
  "method": "GET",
  "path": "/api/orders/ord-1001",
  "evidence": {
    "originalContentHash": "json:2c913a03...",
    "replayContentHash": "json:2c913a03...",
    "matchedHash": "json:2c913a03...",
    "matchType": "semantic-hash"
  },
  "exposureSummary": {
    "summaryGeneratedFromHash": "json:2c913a03...",
    "contentType": "application/json",
    "bodyBytes": 122,
    "fieldPaths": ["id", "owner", "item", "total", "status"],
    "classificationSignals": [
      { "field": "id", "signal": "identifier-like field name", "classification": "resource_identifier", "confidence": "high" },
      { "field": "total", "signal": "financial-like field name", "classification": "possible_financial", "confidence": "high" }
    ],
    "rawBodyStored": false,
    "rawValuesStored": false
  }
}
```
