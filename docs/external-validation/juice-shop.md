# OWASP Juice Shop — external validation

## Purpose

Validate accguard against a recognized intentionally vulnerable application using its core workflow:

existing authenticated traffic → proxy capture → replay as second user → deterministic authorization finding.

## Target

- **Application:** OWASP Juice Shop (Docker: `bkimminich/juice-shop`)
- **Target URL:** `http://localhost:3000`
- **accguard version:** v0.10.1
- **Scope:** `/api/`, `/rest/`
- **Mode:** `accguard run -- node juice-shop-test.js`

## Result

accguard observed 8 authenticated Juice Shop requests and selected 3 URL-identified resource candidates for replay. All 3 produced confirmed cross-user replay findings.

### Confirmed findings

| Endpoint | Resource ID | Alice | Bob replay | Verdict |
|---|---|---|---|---|
| `GET /rest/basket/1` | `1` | 200 (1310 bytes) | 200 (1310 bytes) | confirmed |
| `GET /rest/basket/2` | `2` | 200 (557 bytes) | 200 (557 bytes) | confirmed |
| `GET /rest/basket/3` | `3` | 200 (557 bytes) | 200 (557 bytes) | confirmed |

Each finding was confirmed by matching SHA-256 hashes of normalized JSON responses across two authenticated users. Exposure Summary identified `data.UserId` (resource identifier) and `data.Products[].price` (possible financial) field paths.

### Endpoints observed but not replayed

| Endpoint | Reason |
|---|---|
| `/api/BasketItems/` | No URL-level resource ID |
| `/api/Addresss/` | No URL-level resource ID |
| `/api/Cards/` | No URL-level resource ID |
| `/api/Recycles/` | No URL-level resource ID |
| `/rest/user/whoami` | No URL-level resource ID |

These endpoints return session-scoped data based on the authenticated user, not based on a URL path parameter. accguard's current model focuses on replaying resource-identified requests where the URL contains a candidate resource identifier. Session-scoped endpoints without URL-level resource IDs are observed but not replayed as BOLA candidates.

## What this validates

- Wrapper mode works against a real external target.
- Bearer/JWT replay works against Juice Shop.
- Resource-ID candidate selection correctly identifies basket routes.
- Exposure Summary provides useful field-path evidence on real findings.
- Raw tokens, raw response bodies, and raw values are not stored.
- Curl reproduction commands are generated for each finding.

## What this does not validate

- Full Juice Shop coverage (only 3 of 8 observed endpoints were replayed).
- Session-scoped endpoints without URL resource identifiers.
- GraphQL or request-body-based authorization.
- Production system findings.
- All test runner integrations (Cypress, Playwright, Selenium).

## Reproduction

```bash
# Start Juice Shop
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop

# Register users and get tokens
node juice-shop-setup.js

# Run accguard (replace with Bob's actual token)
ACCGUARD_TOKEN_B="<bob-token>" node src/cli.js run -- node juice-shop-test.js
```
