# Testing

`scripts/test-client-signing-e2e.ts` and `scripts/attack-simulation.ts` both require `ADMIN_EMAIL` and `ADMIN_PASSWORD` set in the environment, matching a real ADMIN account — neither has a built-in fallback, and each exits with a clear error if either is missing.

## Commands

```bash
npm test                               # unit tests (node --test)
node scripts/test-certificate-lookup.ts       # HTTP-level: role gating, response
                                               # shape, cache headers (server must
                                               # already be running: npm run dev)
node scripts/test-certificate-verify-client.ts # the actual browser verify helper
                                               # against real signed data (server
                                               # must already be running)
node scripts/export-cert-check.ts      # issues one real certificate and writes
                                        # it (plus the issuing/root certs) as
                                        # plain PEM files, with the exact
                                        # `openssl verify`/`openssl x509 -text`
                                        # commands to check them independently
node scripts/test-timestamp-live.ts    # one real RFC 3161 round trip against
                                        # TSA_URL, verified; skips cleanly
                                        # (not a failure) if the TSA is
                                        # unreachable
node scripts/export-anchor-check.ts    # writes the latest anchor's token as a
                                        # .tsr file plus a bundle of this
                                        # project's own trusted roots, with the
                                        # exact `openssl ts` commands to check
                                        # it independently
node scripts/test-audit-anchor-tamper.ts # anchors, then tampers an anchored
                                        # entry and recomputes every hash
                                        # forward from it, proving verifyAnchor()
                                        # still reports TAMPERED even though
                                        # verifyAuditChain() alone reports valid
                                        # — requires TEST_DATABASE_URL set equal
                                        # to DATABASE_URL, same confirmation as
                                        # attack-sim below (it permanently
                                        # rewrites real AuditLog rows)
npm run attack-sim                     # attack simulation — requires the API
                                        # running separately first, and
                                        # TEST_DATABASE_URL set equal to
                                        # DATABASE_URL as an explicit
                                        # confirmation; prints a pass/fail
                                        # table and writes it to
                                        # docs/attack-results.md; exits non-zero
                                        # if any attack that should have been
                                        # blocked instead succeeded
```

## Counts

Counts (re-run the commands above to reproduce):

- **`npm test`** — 35 `node --test` cases across `test/canonicalize.test.ts`
  (7), `test/signing.test.ts` (5), `test/certificate.test.ts` (8),
  `test/x509Keys.test.ts` (8), `test/timestamp.test.ts` (7): canonicalization
  determinism and the shared backend/frontend test vector, signature
  verify true/false paths, certificate
  valid/expired/revoked/tampered/issued-by-an-unknown-CA, the real signed
  X.509 CRL, RSA key PEM round trips (file path, `*_BASE64` env path, CRLF,
  no trailing newline), and RFC 3161 anchor verification (genuine token,
  wrong messageImprint, tampered CMS signature, wrong nonce, a certificate
  missing the `timeStamping` EKU, and an untrusted root — each checked
  against the specific one of `verifyAnchor()`'s steps it's expected to fail).
- **`scripts/test-certificate-lookup.ts`** — 13 HTTP-level checks: role
  gating on certificate search, response shape (no private fields, no
  server-computed verdict), cache headers, and the `/api/users`
  enumeration fix.
- **`scripts/test-certificate-verify-client.ts`** — 22 checks exercising
  `frontend/src/lib/certificateVerify.ts` itself (not a reimplementation)
  against a genuine, a tampered, a backdated/expired, and a revoked
  certificate, plus a certificate chained to a forged intermediate CA, a
  CRL signed by the wrong key, and a stale CRL — each checked against the
  specific one of the five verify steps it's expected to fail.
- **`scripts/test-timestamp-live.ts`** — one real TSA round trip, 6 checks
  (the same live-reachable steps `verifyAnchor()` runs).
- **`scripts/test-audit-anchor-tamper.ts`** — anchors, tampers an anchored
  entry, and recomputes every hash forward from it: `verifyAuditChain()`
  reports valid on its own, `verifyAnchor()` still correctly reports
  `TAMPERED`.
- **`scripts/attack-simulation.ts`** — writes its results to
  `docs/attack-results.md` on every run; the result recorded there is
  **12 of 12 attacks blocked**.
