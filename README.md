# jabearri

![CI](https://github.com/rodrigo-areyzaga/jabearri/actions/workflows/ci.yml/badge.svg)

**Find confirmed cross-user data exposure using the authenticated traffic your tests already generate.**

Broken access control is one of the highest-impact API failure modes, and generic scanners often miss it because they do not know which user is supposed to own which object. They may know a request is authenticated. They usually do not know whether Alice should be allowed to see Bob's object.

Your test suite has that context. jabearri uses it.

---

## Try it now

```bash
git clone https://github.com/rodrigo-areyzaga/jabearri
cd jabearri
node demo.js
```

Demo only: no install, no config, no accounts. Under 90 seconds from clone to first finding.

---

## What it does

jabearri confirms one high-confidence failure mode: user B receiving the same protected API resource originally observed under user A.

```
GET /api/orders/ord-1001
Authorization: Bearer alice-token
→ {"orderId":"ord-1001","item":"Keyboard","total":149.99}

Replayed as Bob:
GET /api/orders/ord-1001
Authorization: Bearer bob-token
→ {"orderId":"ord-1001","item":"Keyboard","total":149.99}

HIGH — authorization regression — broken access control (OWASP A01)
       Mechanism: confirmed cross-user replay
       GET /api/orders/ord-1001
       curl -s -H "Authorization: Bearer $TOKEN_B" ".../api/orders/ord-1001"
```

Bob received structurally identical authenticated data to Alice. On ownership-scoped endpoints, that is a confirmed authorization failure.

This is confirmed cross-user replay detection: when scoped to user-owned resources, it catches the moment an ownership check breaks before it reaches production.

---

## How it works

1. jabearri starts as a local HTTP proxy on port `8877`
2. Your tests run normally — jabearri silently records every authenticated request
3. When tests finish, jabearri replays each request using a second user's credential
4. Any endpoint that returns structurally identical authenticated data to a different user is flagged

No new testing concepts. In most setups, one config file is enough.

![jabearri architecture](docs/architecture.svg)

### How confirmation works — deterministic, not heuristic

jabearri doesn't estimate or guess. The detection is a hash comparison:

```
Alice's response:
  SHA256(normalized JSON) = 9af31c2d...

Bob's replay:
  SHA256(normalized JSON) = 9af31c2d...

Match → identical authenticated data exposure
```

The hashes either match or they don't. There is no scoring, no threshold, no grey area. If they match, user B received exactly what user A received. On ownership-scoped endpoints, that is a confirmed authorization failure.

**Scope:** jabearri detects endpoints that return structurally identical authenticated data to a different user. Partial information leaks and structurally different but unauthorized responses require manual review. The tool prioritizes precision — one confirmed finding you can trust is worth more than ten warnings you have to triage.

---

## Setup

```bash
git clone https://github.com/rodrigo-areyzaga/jabearri
cd jabearri
npm run test:all   # confirm all tests pass
```

Create `jabearri.config.json` in your project root:

```json
{
  "target": "http://localhost:3000",
  "port": 8877,
  "scope": ["/api/"],
  "exclude": ["/api/health", "/api/public/"],
  "outputFile": "jabearri-report.json"
}
```

---

## Running with your tests

### Option A — wrapper mode (recommended)

jabearri can wrap your test command directly. It starts the proxy, runs your tests with `HTTP_PROXY` injected automatically, then replays when the tests finish. No manual coordination required.

```bash
JABEARRI_TOKEN_B="second-user-token" node src/cli.js run -- npm test
```

With Cypress:

```bash
JABEARRI_TOKEN_B="second-user-token" node src/cli.js run -- npx cypress run
```

With pytest:

```bash
JABEARRI_TOKEN_B="second-user-token" node src/cli.js run -- pytest tests/
```

The syntax is:

```bash
node src/cli.js run -- <your test command>
```

jabearri exits when your tests finish and outputs findings immediately after.

> **Note:** `JABEARRI_TOKEN_B` is used by jabearri for replay only — it is stripped from the environment before your test command runs, so your test code never sees Bob's token.

### Option B — manual mode (two terminals)

```bash
# Terminal 1 — start jabearri
JABEARRI_TOKEN_B="second-user-token" node src/cli.js

# Terminal 2 — run your tests through the proxy
HTTP_PROXY=http://127.0.0.1:8877 npm test

# Ctrl+C in Terminal 1 when tests finish
```

**Works with most backend stacks** — Node.js, Rails, Django, Laravel, Spring. If your test traffic can be routed through an HTTP proxy, jabearri can watch it. **Any test runner** can be used as a traffic source — Cypress, Playwright, Jest, pytest, RSpec, curl scripts — as long as its HTTP traffic is routed through the jabearri proxy. Some runners (axios, Playwright, native `fetch`) need explicit proxy configuration — see [`docs/reference.md`](docs/reference.md) if your traffic isn't being recorded.

---

## CI integration

```yaml
- name: Start app
  run: npm start &

- name: Run tests with jabearri
  run: node src/cli.js run -- npm test
  env:
    JABEARRI_TOKEN_B: ${{ secrets.TEST_USER_B_TOKEN }}
```

jabearri starts the proxy, runs `npm test` with `HTTP_PROXY` injected, replays when tests finish, and exits. One step, no coordination — the exit code (`0` clean, `1` findings, `2` proxy/config guard) is the step's own exit code, so CI fails automatically.

To preserve the report as a downloadable CI artifact — including on failed runs:

```yaml
- name: Save jabearri report
  uses: actions/upload-artifact@v4
  with:
    name: jabearri-report
    path: jabearri-report.json
  if: always()
```

The `if: always()` is important — without it, the artifact is skipped when jabearri exits with code `1`, which is exactly the run you most want to keep.

Wrapper mode is the recommended path for CI. If your setup can't use it (for example, your app and tests are already orchestrated by other tooling), see [`docs/reference.md`](docs/reference.md) for a manual-flush recipe.

---

## What findings look like

```
────────────────────────────────────────────────────────────────
  jabearri — authorization regression results
────────────────────────────────────────────────────────────────
  Requests observed    : 42
  Replay candidates    : 19
  Resource patterns    : 7
  Auth mechanisms      : bearer
  Findings             : 1
────────────────────────────────────────────────────────────────

  [1] HIGH — broken access control (OWASP A01)
      Finding ID   — AG-20260610T183012Z-001
      Mechanism    — ✓ confirmed cross-user replay
      GET /api/orders/ord-1001
      Resource IDs : 1001, ord-1001
      Auth type    : bearer
      User A got   : 200 (98 bytes)
      User B got   : 200 (98 bytes)

      Why flagged:
        · Same endpoint replayed under a different authenticated user
        · Response hashes matched after JSON normalization
        · SHA256(normalized JSON) identical for both principals

      Exposure Summary:
        Fields exposed : id, owner, item, total, status
        Signals        : resource_identifier, possible_financial
          id → resource_identifier
          total → possible_financial
        Raw body stored: no
        Raw values     : no
        Evidence hash  : json:2c913a03...

      Reproduce:
      curl -s -H "Authorization: Bearer $TOKEN_B" "http://localhost:3000/api/orders/ord-1001"

1 authorization regression detected.
Each finding is deterministic — hashes either match or they don't.
```

When jabearri finds nothing, it tells you what it checked, not just that it ran quietly:

```
✓  No authorization regressions detected.

   42 replay candidates checked across 7 unique resource patterns.
   No unauthorized data replays found.
```

---

## Exposure Summary

For confirmed broken-access-control findings, jabearri summarizes which response field paths were exposed to the replay user — field names and classification signals only, never raw values.

**jabearri stores:** sanitized field paths, content type and body size, the evidence hash, conservative field-name-based classification signals.

**jabearri does not store:** raw response bodies, raw field values, raw tokens, or sensitive/dynamic JSON key names (these are replaced with inert placeholders like `[email-key]`, `[uuid-key]`, `[token-like-key]` before storage).

Full field/signal reference and a sample JSON finding are in [`docs/reference.md`](docs/reference.md).

---

## External validation

jabearri has been validated against OWASP Juice Shop using wrapper mode. In that run, jabearri captured authenticated basket traffic and confirmed cross-user replay exposure on `/rest/basket/:id` endpoints with reproducible evidence.

This validates jabearri's core resource-ID replay model against a recognized intentionally vulnerable application. It does not imply full coverage of every Juice Shop endpoint or every authorization flaw class. See [`docs/external-validation/juice-shop.md`](docs/external-validation/juice-shop.md) for the full writeup.

---

## What jabearri does not prove

A clean jabearri run means no identical cross-user response replay was detected in the observed traffic. It does not prove the API has no authorization bugs.

Specifically, jabearri does not detect:

- **Partial leaks** — if user B receives a subset of user A's data, the hashes differ and the finding is missed
- **Volatile-field leaks** — if responses include per-request fields (timestamps, trace IDs, nonces), hashes differ even when the underlying data is identical
- **POST/mutation-side BOLA** — only GET requests are replayed; write-side access control failures are out of scope
- **GraphQL and body-based reads** — resource IDs in request bodies are not extracted or replayed
- **Partial authorization** — an endpoint that returns different data to different users may still have an authorization bug jabearri cannot see
- **Business logic errors** — jabearri does not model ownership intent, role hierarchies, or tenant boundaries

These are intentional scope boundaries, not implementation gaps. The narrower the claim, the more trustworthy the finding.

> jabearri confirms one specific thing: user B received the same protected representation user A received. If the failure mode looks different from that, it is outside scope by design.

Full known-limitations detail (proxy quirks, multi-user suites, tenant headers, etc.) is in [`docs/reference.md`](docs/reference.md).

---

## What jabearri does not do

These are constraints, not missing features. They communicate what the tool is.

- No HTTPS interception — no certificate injection, ever
- No request mutation or fuzzing — jabearri does not alter method, path, query, or body
- No browser automation or crawling — only traffic your tests generate
- No port scanning or host discovery
- No cloud telemetry — nothing leaves your machine
- jabearri does not initiate outbound calls beyond your declared target — your own test suite may still call other services
- No persistent background daemon — runs for one session and exits
- No storage of request bodies, response bodies, or raw tokens — Exposure Summary extracts field paths in memory and discards the body

---

## Legal notice

You must only use jabearri against systems you own or have explicit written permission to test. Unauthorized use may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), or equivalent laws in your jurisdiction. jabearri only operates against localhost and private network addresses. Any attempt to point it at a public IP address will be blocked at startup.

---

## Architecture

```
Your tests
    ↓  HTTP_PROXY=127.0.0.1:8877
proxy.js              →  forwards application requests · hashes each response
session-store.js      →  records path · token type · resource IDs · content hash
tests finish
    ↓
replay.js             →  replays as user B · SHA256 hash comparison
exposure-summary.js   →  confirmed findings only · field paths · classification signals
                         raw body: in memory only → discarded after inspection
reporter.js           →  audit-ready evidence · privacy/integrity metadata · curl commands
    ↓
exit 0 (clean), exit 1 (authorization regression detected), or exit 2 (safety/config/proxy guard)
```

---

## Configuration reference, token types, and known limitations

Full configuration fields, environment variables, supported auth schemes, CI recipes beyond the wrapper-mode default, and known scope limitations (proxy setup for axios/Playwright/native `fetch`, Windows PATH issues, multi-user test suites, tenant-header caveats) are documented in [`docs/reference.md`](docs/reference.md).

---

*Victor Rodrigo Gutierrez Areyzaga — [LinkedIn](https://www.linkedin.com/in/rodrigo-areyzaga/)*
