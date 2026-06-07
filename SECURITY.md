# Security

## What accguard claims

accguard confirms one specific thing: **user B received the same protected resource representation that user A received**, using authenticated traffic your tests already generate.

That claim is deterministic. The hash either matches or it doesn't. There is no scoring, no inference, no confidence threshold.

A clean run means no identical unauthorized response replay was detected in the observed traffic. It does not prove the API has no authorization bugs.

---

## What accguard does not claim

- It does not detect partial leaks (user B receives a subset of user A's data)
- It does not detect volatile-field leaks (timestamps, trace IDs cause hash divergence)
- It does not replay POST, PUT, PATCH, or DELETE requests
- It does not intercept HTTPS
- It does not model roles, ownership intent, or tenant boundaries
- It does not detect business logic errors that produce structurally different responses

These are intentional scope boundaries, not implementation gaps. See the README for the full list.

---

## Security model

**Localhost only.** The proxy binds exclusively to `127.0.0.1`. It cannot be reached from the network.

**No data storage.** accguard records request metadata and response hashes. It does not store response bodies, request bodies, or raw token values. Token fingerprints use one-way SHA-256.

**No outbound connections.** accguard only communicates with the configured target. It does not send telemetry, phone home, or make connections to any external service.

**Consent gate.** First-run interactive consent is required in local environments. CI environments skip the prompt and log an explicit acknowledgment.

**SSRF blocked by design.** The proxy always connects to the configured target hostname. Absolute URLs in requests have their hostname discarded — only the path is forwarded.

**Shell-safe output.** All curl reproduction commands use POSIX single-quote escaping. URLs and header values are wrapped with `shellQuote()` so output is safe to copy-paste even when paths contain backticks, `$()`, or other shell metacharacters.

---

## Adversarial assessment

accguard v0.9.2 underwent twelve rounds of independent adversarial testing across 85+ attack vectors and 13 harnesses. Zero open findings at release.

Areas tested: detection quality, hash soundness, capture pipeline, scope parsing, token handling, operational trust, proxy security, shell safety, fix interactions, and temporal contract.

Twenty-two distinct bugs were found and fixed during assessment. The full findings table — what broke, what was fixed, and what was determined to be a documented scope boundary — is in [`docs/SECURITY-ASSESSMENT.md`](docs/SECURITY-ASSESSMENT.md).

---

## Reporting a vulnerability

If you find a correctness bug or security issue in accguard itself, please open a GitHub issue describing:

- Which component is affected (`proxy.js`, `replay.js`, `session-store.js`, `safety.js`, `reporter.js`, `cli.js`)
- A minimal reproduction case or test vector
- Whether it affects detection accuracy, scope enforcement, or the proxy's own security

accguard is a developer tool intended for use against systems you own or have written authorization to test. Reports about detection limitations or scope boundaries that are already documented are noted but unlikely to result in changes without a concrete real-world case demonstrating impact.

There is no bug bounty program. Issues are reviewed by the maintainer.
