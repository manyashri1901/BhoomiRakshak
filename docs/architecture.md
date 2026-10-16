# Architecture

## Client-side signing

Every Landowner / Village Officer / Registrar generates their own RSA-2048
key pair in the browser at registration. The private key is wrapped with
AES-256-GCM (key derived via PBKDF2-SHA256, 600,000 iterations, a random
salt) before it ever leaves memory, and only that wrapped blob — never the
key itself — is sent to and stored by the server. At login, the server
returns the wrapped blob back to the browser; it is useless without the
user's password, which the server never has.

Every signature (transaction creation, VO review, registrar review) follows
a **prepare → sign → submit** sequence:

1. `POST .../prepare` — the server validates everything it can up front,
   builds the exact canonical string to be signed (embedding the chain's
   prior signatures and the signer's certificate fingerprint), and freezes
   it under a short-lived, single-use nonce (`SigningNonce`, 5-minute
   expiry).
2. The browser prompts for the user's password, unwraps the private key
   into a **non-extractable** `CryptoKey`, signs the exact bytes the server
   returned, and discards the key.
3. `POST .../submit` sends back only `{nonce, signatureValue}` — never the
   payload. The server looks up the frozen payload by nonce (it never
   trusts a client-echoed payload), re-checks certificate validity and
   business preconditions, verifies the signature, and only then commits
   the signature, the business write, and an audit log entry together in
   one transaction.

A rejected review never involves a signature, so reject stays a plain
authenticated endpoint with no nonce/signing step.

## Technical design

The public site (Home, How it works, About) deliberately keeps this detail
out of view — this section holds what it leaves out, for anyone reading the
code or grading it.

**Certificate model** (`lib/ca.ts`) — real X.509 v3, built with
`@peculiar/x509` (no hand-rolled ASN.1 anywhere in this codebase). A
two-tier chain: a self-signed **Root CA** (`CA:true, pathLen:1`), generated
once and kept offline — its private key is written only to
`keys/root-offline/root-ca-private.pem` by `scripts/first-run.ts` and is
never loaded by the running server again — and an **Issuing CA**
(`CA:true, pathLen:0`, signed by the root) that the server actually holds
and signs user certificates with day to day. Every registered user gets a
leaf certificate (`CA:false`, `KeyUsage: digitalSignature`, a
`CRLDistributionPoints` extension pointing at this server's signed-CRL
endpoint) with a genuine random 128-bit serial number, subject
`CN=<name>,OU=<role>`. The stored `Certificate` row
(`prisma/schema.prisma`) holds the real `certificatePem`, the X.509
`serialNumber`, a `fingerprint` (SHA-256 of the certificate's DER bytes),
and the revocation fields (`revoked`, `revokedAt`, `revokedReason`). The
actor's public key for every signature check (`routes/transactions.ts`) is
parsed out of their certificate (`publicKeyPemFromCertificatePem()`), not
read from a separate stored column.

**Client-side key generation and private-key storage** — covered above
under "Client-side signing"
(`frontend/src/lib/clientCrypto.ts`): RSASSA-PKCS1-v1_5 2048-bit keys
generated in the browser; the private key is wrapped with AES-256-GCM
(key derived via PBKDF2-SHA256, 600,000 iterations) before it ever leaves
memory. Only the wrapped blob (`User.wrappedPrivateKey/wrapSalt/wrapIv` in
`prisma/schema.prisma`) is stored server-side.

**Prepare → sign → submit with a single-use nonce** — also covered above
(`lib/signingNonce.ts`'s `SigningNonce` model, `createSigningNonce`/
`consumeSigningNonce`; `routes/transactions.ts`'s `/prepare` and `/submit`
endpoints per review stage).

**Chained signatures** — each review stage's signed payload embeds the
fingerprint of the reviewer's own certificate plus the prior signature(s)
in the chain (`routes/transactions.ts`'s `buildReviewPayload`/
`rebuildCreationPayload`). `routes/transactions.ts`'s
`verifySignatureChain()` re-verifies every signature in a transaction's
chain live, against each actor's *current* public key — never a cached
"was valid when signed" flag.

**Hash-chained audit log** (`lib/audit.ts`) — a system-wide `AuditLog`
table, separate from the per-transaction signature chain, where each row's
hash commits to every field plus the previous row's hash
(`computeEntryHash`). Writes are serialized through a Postgres advisory
lock (`pg_advisory_xact_lock`, `AUDIT_CHAIN_LOCK_KEY`) so concurrent
writers can never fork the chain. `verifyAuditChain()` recomputes and
checks the whole chain on demand, reporting the first broken sequence
number rather than trusting a cached flag.

**RFC 3161 trusted timestamping** (`lib/timestamp.ts`) — periodically
anchors the audit chain's head hash with a public Time-Stamp Authority
(default: DigiCert's, `TSA_URL`), built entirely with `pkijs`/`asn1js` (no
hand-rolled ASN.1). The messageImprint submitted is SHA-256 of the head
hash's own bytes, with `certReq=true` and a random nonce; the returned
token (a real CMS `SignedData`/`TSTInfo`) is stored as `AuditAnchor` rows —
a side table, never written into the `AuditLog` chain itself or its
advisory lock. Anchoring happens automatically, best-effort and
non-blocking, after a transaction's final Registrar approval or rejection
(`anchorAuditChainBestEffort()` in `routes/transactions.ts`; a TSA failure
only ever logs a short warning, never affects the request), or manually via
`POST /api/audit/anchor` (ADMIN-only) — both paths share one
`TSA_MIN_INTERVAL_SECONDS` throttle so neither one hammers the TSA.
`verifyAnchor()` checks, independently and never short-circuited: the token
parses; its messageImprint matches this anchor's own stored head hash; the
CMS signature verifies; the TSA certificate carries the `timeStamping` EKU
and its chain validates to a trusted root (Node's `tls.rootCertificates`,
plus `TSA_CA_CERT_BASE64` if set) as of the token's own `genTime`; the
nonce matches; `genTime` isn't implausibly in the future — **and, the
property a timestamp alone can't give you**, that the `AuditLog` row this
anchor points at still exists with the exact hash that was anchored, and
that `verifyAuditChain()`'s own walk reports no break at or before that
row. That last pair is what makes an anchor prove something a plain
hash-chain check alone cannot: even an attacker who edits an old entry and
recomputes every hash forward from it (so the chain's own links look
internally consistent again) cannot also retroactively obtain a new,
independently-signed TSA token for the hash that existed before — see
`scripts/test-audit-anchor-tamper.ts`, which performs exactly that attack
and confirms `verifyAnchor()` still reports `TAMPERED` while
`verifyAuditChain()` alone reports valid. `scripts/export-anchor-check.ts`
writes an anchor's token out so it can also be checked with `openssl ts`,
independent of this project's own code.

**Double-sale prevention** — a `LandRecord` only accepts a new transaction
while `status = ACTIVE` (checked in `routes/transactions.ts`), backed by a
database-level partial unique index
(`prisma/migrations/20261012110626_add_pending_transaction_unique_index`)
on `transactions(landRecordId)` for rows with
`status IN ('PENDING_VO', 'PENDING_REGISTRAR')` — the actual race-condition
backstop behind the application-level check, surfaced as a 409 on conflict.

**Upload validation** (`lib/fileType.ts`, `routes/documents.ts`) — uploads
are held in memory, their magic bytes checked against the PDF/PNG/JPEG
signatures in `lib/fileType.ts` *before* anything touches disk, and stored
under a random UUID filename with an extension derived from the detected
type, not the client-supplied one.

**Signed CRL and client-side certificate verification** — `lib/ca.ts`'s
`getSignedCRL()` publishes a real, CA-signed X.509 CRL (`X509CrlGenerator`)
with `thisUpdate`/`nextUpdate` timestamps, cached in memory for 3 minutes
and explicitly invalidated on every revocation.
`frontend/src/lib/certificateVerify.ts` independently verifies, entirely
in the browser via WebCrypto (`@peculiar/x509`, the same library the
backend issues with): the certificate chain's issuer-name linkage, both
signatures in the chain (user→issuing, issuing→root), the validity window
of all three certificates, the CRL's own signature and freshness, and
whether either the certificate's or the Issuing CA's own serial appears on
the CRL — five checks, never short-circuited and never a verdict computed
only by the server (the lookup endpoints return raw PEMs, nothing
server-judged). `scripts/export-cert-check.ts` issues one certificate and
writes it, plus the issuing and root certificates, out as plain PEM files
so the chain can also be checked with `openssl verify` — independent of
this project's own code entirely.

**Rate limiting and headers** (`middleware/rateLimit.ts`, `server.ts`) —
`loginRateLimiter` (IP+email-keyed, skips successful attempts),
`registerRateLimiter`, `directoryLookupRateLimiter` (IP+user-keyed,
shared by `/api/users`, `/api/certificates/search`, and
`/api/certificates/serial/:id`), and `anchorRateLimiter` (IP+user-keyed,
`POST /api/audit/anchor` — on top of, not instead of,
`TSA_MIN_INTERVAL_SECONDS`). `server.ts` applies `helmet()` globally.

## Project structure

```
lib/                 CA (ca.ts), signature verification (signing.ts),
                     prepare/submit nonces (signingNonce.ts), canonical
                     JSON (canonicalize.ts), audit hash chain (audit.ts),
                     RFC 3161 trusted timestamping (timestamp.ts), upload
                     magic-byte detection (fileType.ts), Prisma client
middleware/          auth.ts (requireAuth/requireRole), rateLimit.ts
routes/              One file per resource — auth, documents, land-records,
                     transactions, certificates, users, audit, dev (test-mode only)
prisma/schema.prisma Data model; prisma/migrations/ — migration history
keys/                Issuing CA key pair + both CA certs (generated on first
                     run; gitignored). keys/root-offline/ holds the Root CA
                     private key only — never loaded by the running server
uploads/             Uploaded transaction documents (gitignored)
scripts/             CA walkthrough, admin bootstrap, first-run, attack simulation,
                     certificate-lookup/verify-client HTTP tests,
                     export-cert-check / export-anchor-check (openssl-checkable
                     PEM/token export), test-timestamp-live, and
                     audit/crypto/signing test scripts
test/                node --test unit tests (canonicalize, signing,
                     certificate, x509Keys, timestamp)
frontend/            Vite React app — src/pages, src/components, src/api;
                     src/lib/clientCrypto.ts (Web Crypto key handling),
                     src/lib/signAndSubmit.ts (prepare -> sign -> submit)
Dockerfile           Multi-stage build for the API (see "Deploying" below)
.env.example         Full list of environment variables with descriptions
docs/security.md     Full, deduplicated list of security/trust limitations
docs/ui.md           Design system — color tokens, routes, principles
```
