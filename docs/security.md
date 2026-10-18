# Security limitations

Deliberate, documented limitations of this project — not oversights. The
README keeps only the handful most relevant to its PKI/trust design; this
is the complete, deduplicated list.

## Trust model

- **The CA is operated by this project, not a licensed Certifying
  Authority.** The two-tier chain (self-signed Root CA → Issuing CA → user
  certificates, all real X.509 v3) demonstrates genuine PKI mechanics:
  - A certificate from this project verifies with `openssl` or any other
    standard X.509 tooling.
  - There is no real-world chain of trust, OCSP, or third-party
    attestation behind the root.
  - Trusting it at all means trusting this server, by construction — see
    `lib/ca.ts`.
- **Trusted timestamping uses a public, free TSA — not a legally qualified
  one.** The RFC 3161 anchors (`lib/timestamp.ts`) are cryptographically
  genuine:
  - A real third party (DigiCert's public TSA by default) signs a token
    independent of this server's own clock.
  - `verifyAnchor()` checks that signature, its certificate's chain, and
    the anchored entry's integrity for real.
  - That TSA is not an eIDAS-qualified timestamp authority or a
    CCA-licensed one in India — it carries no legal evidentiary status,
    only a genuine cryptographic one.
  - Anchoring is periodic (throttled by `TSA_MIN_INTERVAL_SECONDS`,
    triggered on Registrar decisions and on demand), not per-entry — an
    entry written between two anchors is only covered once a later
    anchor's chain-walk reaches it, not individually.
- **No integration with any government land record database.**
- **The signed CRL's freshness window is 1 hour** (`CRL_VALIDITY_MS` in
  `lib/ca.ts`) — a revocation can take up to that long to be reflected in
  a CRL a client already cached, by design (see the Cache-Control header
  on `GET /api/certificates/crl/signed`).
- **The attack simulation (`scripts/attack-simulation.ts`) is self-designed**,
  not an independent or third-party red-team exercise — it exercises the
  specific attacks this project anticipated, not an exhaustive security
  audit. Current recorded result: 12 of 12 attacks blocked
  (`docs/attack-results.md`).

## Client-side key custody

- **The server serves the frontend's JavaScript.** Client-side signing
  means the private key and the signing logic only ever run in the
  browser — but the browser is running code this server delivered.
  - A compromised server (or a compromised CDN/build pipeline in a real
    deployment) could serve malicious JavaScript that exfiltrates a
    password or a signature before it's ever wrapped/sent.
  - Client-side key custody protects against a server that merely *reads
    its own database*; it does not protect against a server that has been
    fully compromised and can serve arbitrary code.
  - Subresource Integrity, code signing, or a separately-audited static
    host for the signing bundle would close this gap in a real
    deployment — none of that is implemented here.
- **Forgetting your password loses your key, permanently.**
  - No password reset and no key backup/escrow, by design — the server
    cannot decrypt the wrapped key, so it has nothing to reset *to*.
  - The only recovery path is an ADMIN revoking the old certificate and
    the user registering again under a fresh key pair and certificate.
  - A self-service "reissue certificate" flow (generate a new key pair,
    prove possession, get a fresh certificate on the same account) was
    scoped but not built.
- **No session persistence.**
  - The JWT and the wrapped-key blob both live only in React state; a
    page refresh logs the user out and requires re-entering the password
    to re-fetch and hold the wrapped key.
  - There is deliberately no `localStorage` use, so a stolen XSS payload
    can't read a persisted token — but it also means there's no
    "remember me."
- **JWTs are short-lived (1 hour) with no refresh-token flow** — expiry
  just requires logging in again (and re-entering the password to re-fetch
  the wrapped key for signing).
- **No email verification or account recovery flow** beyond the
  certificate-reissue path above.

## Operational

- **No measured production throughput under real concurrent load.** What
  *is* measured, against a remote Neon database from a local dev machine
  (`scripts/test-audit-chain.ts`):
  - A single audit-log write takes roughly 1.2-1.5s (dominated by Neon
    round-trip latency, not CPU).
  - 20 concurrent writes serialized through the audit chain's advisory
    lock take roughly 20-25s total — they queue, by design, since the
    chain cannot allow two writes to compute the next hash concurrently.
  - A full transaction submit (signature verify + business write + audit
    entry, one Prisma transaction) was observed at up to ~5.8s uncontended.
  - These are a sanity floor, not a load-test result — a proper load test
    (e.g. k6 or autocannon hitting a deployed instance) was out of scope.
- **The test-mode tamper endpoint** (`POST /api/dev/tamper/:transactionId`,
  `routes/dev.ts`):
  - Exists purely to make signature/document tampering demonstrable in
    the UI, and is only mounted at all when `ENABLE_DEMO_TAMPER=true`
    (default off — the route 404s otherwise).
  - Bypasses the entire signing flow by writing directly to the database,
    exactly as a real attacker with raw DB access would.
  - Every use is itself logged to the audit chain.
- **No jurisdiction scoping on review queues.** Any Village Officer can
  review any `PENDING_VO` transaction, and any Registrar any
  `PENDING_REGISTRAR` transaction, regardless of which village/district
  the land record belongs to — there is no village/district concept
  modeled at all.
- **Documents are stored on local disk** (`uploads/`), not object
  storage — fine for a single instance, not for a horizontally scaled
  deployment.
- **List endpoints are unpaginated** except `GET /api/users` (caps at 20)
  and `GET /api/audit` (paginated) — fine at the current data volumes,
  not at scale.
