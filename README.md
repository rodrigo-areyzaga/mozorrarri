# accguard

![CI](https://github.com/rodrigo-areyzaga/accguard/actions/workflows/ci.yml/badge.svg)

**Authorization regression testing from real authenticated traffic.**

Broken access control remains the most common high-impact API vulnerability. Existing scanners can't reliably catch it — they don't have authenticated context. They've never logged into your app.

Your test suite has that context. accguard uses it.

---

## Try it now

```bash
git clone https://github.com/rodrigo-areyzaga/accguard
cd accguard
node demo.js
```

No install. No config. No accounts. Under 90 seconds from clone to first finding.

---

## What it does

accguard does one thing: it tells you whether user B can access user A's resources, using the traffic your tests already generate.

```
GET /api/orders/ord-1001
Authorization: Bearer alice-token
→ {"orderId":"ord-1001","item":"Keyboard","total":149.99}

Replayed as Bob:
GET /api/orders/ord-1001
Authorization: Bearer bob-token
→ {"orderId":"ord-1001","item":"Keyboard","total":149.99}

HIGH — authorization regression — broken access control (OWASP A01)
       Mechanism: confirmed unauthorized data replay
       GET /api/orders/ord-1001
       curl -H "Authorization: Bearer $TOKEN_B" ".../api/orders/ord-1001"
```

Bob received the same order data as Alice. The endpoint may be missing an ownership check.

This is authorization regression testing: run it on every commit, catch access control failures the moment they're introduced, before they reach production.

---

## How it works

1. accguard starts as a local HTTP proxy on port `8877`
2. Your tests run normally — accguard silently records every authenticated request
3. When tests finish, accguard replays each request using a second user's token
4. Any endpoint that returns the same data to the wrong user is flagged

No changes to your test code. No new testing concepts. One config file.

### How confirmation works — deterministic, not heuristic

accguard doesn't estimate or guess. The detection is a hash comparison:

```
Alice's response:
  SHA256(normalised JSON) = 9af31c2d...

Bob's replay:
  SHA256(normalised JSON) = 9af31c2d...

Match → identical authenticated data exposure
```

For each replayed request accguard:

1. Parses the response as JSON
2. Normalises key order recursively — `{"b":2,"a":1}` and `{"a":1,"b":2}` hash identically
3. Computes `SHA256(JSON.stringify(sortKeys(parsed)))`

The hashes either match or they don't. There is no scoring, no threshold, no grey area. If they match, user B received exactly what user A received. That is a confirmed unauthorized data replay.

For non-JSON responses it falls back to a raw byte hash. Body size is never used as a signal.

**Scope:** accguard detects endpoints that return structurally identical data to a second user. Partial information leaks and structurally different but unauthorized responses require manual review. The tool prioritises precision — one confirmed finding you can trust is worth more than ten warnings you have to triage.

### Token type awareness

accguard records how each token was delivered — `Authorization: Bearer` header or session cookie — and replays using the same mechanism. Rails apps using `session=` cookies, Django apps using `sessionid=`, and Bearer token APIs all work correctly without configuration.

### Clean runs are meaningful

When accguard finds nothing, it tells you what it checked:

```
✓  No authorization regressions detected.

   42 replay candidates checked across 7 unique resource patterns.
   No unauthorized data replays found.
```

That's not silence — it's verification. You know the tool exercised real authenticated flows, not just that it ran quietly.

---

## Works with

**Any backend stack** — Node.js, Rails, Django, Laravel, Spring. If it serves HTTP, accguard watches it.

**Mobile app backends** — The access control lives in the API, not the device. Point your API-level test suite through accguard and it catches authorization regressions in your iOS or Android backend the same way it would for a web app.

**Any test runner** — Cypress, Playwright, Jest, pytest, RSpec, curl scripts. One environment variable: `HTTP_PROXY=http://127.0.0.1:8877`.

---

## Setup

```bash
git clone https://github.com/rodrigo-areyzaga/accguard
cd accguard
node test/run.js   # confirm all tests pass
```

Create `accguard.config.json` in your project root:

```json
{
  "target": "http://localhost:3000",
  "port": 8877,
  "scope": ["/api/"],
  "exclude": ["/api/health", "/api/public/"],
  "outputFile": "accguard-report.json"
}
```

---

## Running with your tests

```bash
# Terminal 1 — start accguard
ACCGUARD_TOKEN_B="second-user-token" node src/cli.js

# Terminal 2 — run your tests through the proxy
HTTP_PROXY=http://127.0.0.1:8877 npm test

# Ctrl+C in Terminal 1 when tests finish
```

---

## CI integration

```yaml
- name: Start app
  run: npm start &

- name: Start accguard
  run: node src/cli.js &
  env:
    ACCGUARD_TOKEN_B: ${{ secrets.TEST_USER_B_TOKEN }}

- name: Run tests
  run: HTTP_PROXY=http://127.0.0.1:8877 npm test

- name: Flush accguard
  run: curl -s -X POST http://127.0.0.1:8877/--flush
```

accguard exits with code `1` if authorization regressions are detected, `0` if clean. The CI step fails automatically when an ownership boundary is violated.

---

## What findings look like

```
────────────────────────────────────────────────────────────────
  accguard — authorization regression results
────────────────────────────────────────────────────────────────
  Requests observed    : 42
  Replay candidates    : 19
  Resource patterns    : 7
  Auth mechanisms      : bearer
  Findings             : 1
────────────────────────────────────────────────────────────────

  [1] HIGH
      Authorization regression  — broken access control (OWASP A01)
      Mechanism                 — ✓ confirmed unauthorized data replay
      GET /api/orders/ord-1001
      Resource IDs : 1001, ord-1001
      Auth type    : bearer
      User A got   : 200 (98 bytes)
      User B got   : 200 (98 bytes)

      Why flagged:
        · Same endpoint replayed under a different authenticated user
        · Response hashes matched after JSON normalisation
        · SHA256(normalised JSON) identical for both principals

      Reproduce:
      curl -s -H "Authorization: Bearer $TOKEN_B" "http://localhost:3000/api/orders/ord-1001"

1 authorization regression detected.
Each finding is deterministic — hashes either match or they don't.
```

---

## What accguard does not do

These are constraints, not missing features. They communicate what the tool is.

- No HTTPS interception — no certificate injection, ever
- No request mutation — requests are forwarded byte-for-byte unchanged
- No browser automation or crawling — only traffic your tests generate
- No port scanning or host discovery
- No cloud telemetry — nothing leaves your machine
- No outbound network calls beyond your declared target
- No persistent background daemon — runs for one session and exits
- No storage of request bodies, response bodies, or raw tokens

---

## Legal notice

You must only use accguard against systems you own or have explicit written permission to test. Unauthorized use may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent laws in your jurisdiction. accguard only operates against localhost and private network addresses. Any attempt to point it at a public IP address will be blocked at startup.

---

## Configuration

| Field        | Required | Description |
|---|---|---|
| `target`     | yes | URL of your local app |
| `scope`      | yes | Path prefixes to record — e.g. `["/api/"]` |
| `exclude`    | no  | Path prefixes to always skip |
| `port`       | no  | Proxy port — default `8877` |
| `outputFile` | no  | JSON report path — default `accguard-report.json` |

| Environment variable | Description |
|---|---|
| `ACCGUARD_TOKEN_B`   | Second user's session token — required for detection |
| `ACCGUARD_CONFIG`    | Path to config file — default `./accguard.config.json` |

---

## Architecture

```
Your tests
    ↓  HTTP_PROXY=127.0.0.1:8877
proxy.js          →  forwards requests unchanged · hashes each response
session-store.js  →  records path · token type · resource IDs · content hash
tests finish
    ↓
replay.js         →  replays as user B · SHA256 hash comparison
reporter.js       →  deterministic findings · coverage summary · curl commands
    ↓
exit 0 (clean) or exit 1 (authorization regression detected)
```

---

*Victor Rodrigo Gutierrez Areyzaga — [LinkedIn](https://www.linkedin.com/in/rodrigo-areyzaga/)*
