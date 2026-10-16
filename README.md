# BhoomiRakshak

A PKI-based secure land record and ownership management system. Every user
holds an RSA-2048 key pair and a CA-issued certificate; every registration,
transfer, and update to a land record is signed by the acting party and
chained through a Landowner → Village Officer → Registrar approval
workflow, where each stage's signature embeds the actual signature bytes of
every prior signer. The result is a tamper-evident audit trail: a
database-level tamper of a transaction's stored data is independently
detectable by re-verifying signatures and re-hashing the referenced
document on demand, without trusting any cached "this was valid when it
was created" flag.

Every key pair is generated **in the browser** (Web Crypto, RSASSA-PKCS1-v1_5
/ SHA-256) and the private key never reaches the server in usable form — see
"Client-side signing" below. A separate, append-only audit log
(`AuditLog`/`lib/audit.ts`) hash-chains every sensitive action system-wide,
independently of the per-transaction signature chain.

## Tech stack

**Backend** — Node.js (22+) + Express 5, written in TypeScript and run
directly via Node's native type stripping (no build/compile step). Prisma 7
ORM against PostgreSQL (developed against Neon), with the `@prisma/adapter-pg`
driver adapter Prisma 7 requires at runtime. Auth is JWT-based (`jsonwebtoken`)
with `bcrypt` password hashing; file uploads via `multer`. All PKI
cryptography (key generation, signing, verification) uses Node's built-in
`crypto` module — no external crypto library.

**Frontend** — Vite + React 19 + TypeScript, Tailwind CSS v4, React Router
v7, axios. Auth state is held in React state only (no `localStorage`) — see
Known Limits below. Key generation, wrapping, and signing all use the
browser's native Web Crypto API (`frontend/src/lib/clientCrypto.ts`); the
exact same canonical-JSON module as the backend
(`frontend/src/lib/canonicalize.ts`, kept byte-identical and tested by
`scripts/test-client-crypto.ts`) builds the registration proof.

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

## Limitations

- **This CA is operated by this system, not a licensed Certifying
  Authority.** The two-tier chain (self-signed Root CA → Issuing CA →
  user certificates, all real X.509 v3) demonstrates genuine PKI
  mechanics — a certificate from this project will verify with `openssl`
  or any other standard X.509 tooling — but there is no real-world chain
  of trust, OCSP, or third-party attestation behind the root. Trusting it
  at all means trusting this server, by construction; see `lib/ca.ts`.
- **Trusted timestamping uses a public, free TSA — not a legally qualified
  one.** The RFC 3161 anchors (`lib/timestamp.ts`) are cryptographically
  genuine: a real third party (DigiCert's public TSA by default) signs a
  token independent of this server's own clock, and `verifyAnchor()`
  checks that signature, its certificate's chain, and the anchored entry's
  integrity for real. But that TSA is not an eIDAS-qualified timestamp
  authority or a CCA-licensed one in India — it carries no legal
  evidentiary status, only a genuine cryptographic one. Anchoring is also
  periodic (throttled by `TSA_MIN_INTERVAL_SECONDS`, triggered on
  Registrar decisions and on demand), not per-entry — an entry written
  between two anchors is only covered once a later anchor's chain-walk
  reaches it, not individually.
- **No integration with any government land record database.**
- **The signed CRL's freshness window is 1 hour** (`CRL_VALIDITY_MS` in
  `lib/ca.ts`) — a revocation can take up to that long to be reflected in
  a CRL a client already cached, by design (see the Cache-Control header
  on `GET /api/certificates/crl/signed`).
- **The attack simulation (`scripts/attack-simulation.ts`) is self-designed**,
  not an independent or third-party red-team exercise — it exercises the
  specific attacks this project anticipated, not an exhaustive security audit.

## Project structure

```
lib/                 CA (ca.ts), signature verification (signing.ts),
                     prepare/submit nonces (signingNonce.ts), canonical
                     JSON (canonicalize.ts), audit hash chain (audit.ts),
                     RFC 3161 trusted timestamping (timestamp.ts), upload
                     magic-byte detection (fileType.ts), Prisma client
middleware/          auth.ts (requireAuth/requireRole), rateLimit.ts
routes/              One file per resource — auth, documents, land-records,
                     transactions, certificates, users, audit, dev (demo-only)
prisma/schema.prisma Data model; prisma/migrations/ — migration history
keys/                Issuing CA key pair + both CA certs (generated on first
                     run; gitignored). keys/root-offline/ holds the Root CA
                     private key only — never loaded by the running server
uploads/             Uploaded transaction documents (gitignored)
scripts/             CA demo, admin bootstrap, first-run, attack simulation,
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
```

## UI design

The frontend is a minimalist flat design, trust-first (government/fintech
feel) rather than decorative — no glassmorphism, neumorphism, or gradients
on data. Light `backdrop-blur` is used only on the sticky navbar and modal
overlays.

**Principles**: large clear hierarchy (one type scale, Inter), generous
white space, few colors, consistent 8px spacing, solid white cards with a
thin `slate-200` border and a subtle shadow instead of heavier elevation
effects. Interactive elements always show a visible focus ring. Animation
is subtle and one-shot (sections fade/slide up once on entering the
viewport, a thin scroll-progress bar, a brief fade on route change) and
is skipped entirely under `prefers-reduced-motion`.

**Color tokens** (`frontend/src/index.css`, defined once as Tailwind
`@theme` variables so no component hard-codes a hex value):

| Token | Value | Use |
|---|---|---|
| `--color-navy` | `#0F2A4A` | Primary — headings, primary buttons, active nav state |
| `--color-teal` | `#0D9488` | Accent, used sparingly — links in illustrative/technical spots, scroll-progress bar |

Everything else (neutrals, status colors, white surfaces) uses Tailwind's
built-in `slate`/`green`/`amber`/`red`/`white` palette directly, since
that palette is itself already a defined token set rather than ad hoc hex
values.

**Routes**:

| Path | Page | Auth |
|---|---|---|
| `/` | Home (hero, features, CTA band) | Public |
| `/how-it-works` | Interactive stepper, tamper-detection demo, PKI strip | Public |
| `/login`, `/register` | Auth | Public |
| `/verify` | Independent transaction verification | Logged in (unchanged) |
| `/landowner`, `/village-officer`, `/registrar`, `/admin` | Role dashboards | Logged in, role-gated (unchanged) |
| `/land-records`, `/land-records/:id`, `/certificates`, `/certificates/:userId` | Registry & certificate lookup | Logged in (unchanged) |

Logged-in users keep the existing role sidebar + simple footer; the richer
public navbar (Home / How it works / Verify a record / Login / Get
started) and footer (links + "Demo prototype" note) only render when
signed out.

## Setup

### Prerequisites

- Node.js 22 or later
- A PostgreSQL database (developed against [Neon](https://neon.tech))

### Backend

```bash
npm install
```

Copy `.env.example` to `.env` and fill in at least `DATABASE_URL` and
`JWT_SECRET` (see `.env.example` for how to generate a `JWT_SECRET`, and
for what every other variable does).

Apply migrations, generate the CA root key pair, and create the first
ADMIN account in one step (set `ADMIN_NAME`/`ADMIN_EMAIL`/`ADMIN_PASSWORD`
in `.env` first if you want the admin account created now — it's safe to
run this again later without them set, or a second time at all):

```bash
npm run first-run
```

(Equivalently, run `npx prisma migrate dev` and
`npm run bootstrap-admin` separately — `first-run` just wraps both plus the
CA key step into one idempotent command.)

Start the API (port 4000 by default; override with `PORT`):

```bash
npm run dev
```

### Frontend

```bash
cd frontend
npm install
```

`frontend/.env` already points at the default backend URL:

```bash
VITE_API_URL=http://localhost:4000/api
```

Start the dev server (port 5173):

```bash
npm run dev
```

Open `http://localhost:5173`. Register a Landowner, a Village Officer, and
a Registrar to exercise the full approval workflow; a Registrar can create
land records, and the `/verify` and `/certificates` pages work independently
of the approval flow for any authenticated role.

## Testing

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

Current counts (as of this writing — re-run the commands above for the
latest):

- **`npm test`** — 35 `node --test` cases across `test/canonicalize.test.ts`
  (7), `test/signing.test.ts` (5), `test/certificate.test.ts` (8),
  `test/x509Keys.test.ts` (8), `test/timestamp.test.ts` (7):
  canonicalization determinism and the shared backend/frontend test
  vector, signature verify true/false paths, certificate
  valid/expired/revoked/tampered/issued-by-an-unknown-CA, the real signed
  X.509 CRL, RSA key PEM round trips (file path, `*_BASE64` env path, CRLF,
  no trailing newline, the exact pool-allocation condition that once broke
  this — see report), and RFC 3161 anchor verification (genuine token,
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
- **`scripts/test-audit-anchor-tamper.ts`** — not yet run against the real
  database (needs the `add_audit_anchor` migration applied first — see
  report); written and sanity-checked for import/logic correctness only.
- **`scripts/attack-simulation.ts`** — writes its results to
  `docs/attack-results.md` on every run; the most recent recorded result
  in that file is **12 of 12 attacks blocked** (dated in the file itself) —
  not yet re-run since the X.509 rework (see report).

## Deploying

This is a two-service deployment: the API (this repo's root, as a Docker
container) and the frontend (`frontend/`, a static Vite build). They are
deployed independently and talk to each other only over HTTPS via
`FRONTEND_ORIGIN` / `VITE_API_URL`.

### 1. Database — Neon

Create a **new, separate Neon project/database for production** — do not
point production at the same database used for local development. Copy its
pooled connection string into `DATABASE_URL`.

### 2. API — Render (Docker)

1. Push this repo (with the root `Dockerfile`) to GitHub, then create a new
   Render **Web Service** from it, environment "Docker". Set the **Health
   Check Path** to `/health` — a pure liveness check (no DB call, always
   200 `{"status":"ok","uptime":<seconds>}`), so a cold/sleeping Neon
   branch never makes Render think the process itself is down and restart
   it. There's a separate `GET /health/db` for the post-deploy smoke test
   and manual checks — it runs an 8-second-capped `SELECT 1` against the
   database and returns 200 `{"status":"ok","db":"up"}` or 503
   `{"status":"degraded","db":"down"}`. Both are unauthenticated and return
   nothing else (no version info, env values, or error detail). Note: the
   first call to `/health/db` after the database has been idle can take a
   few seconds while Neon wakes the branch back up — that's expected, not
   a fault.
2. Set the environment variables below (Render's dashboard → Environment).
   Mark `JWT_SECRET`, `ADMIN_PASSWORD`, and the two `CA_*_BASE64` vars as
   **Secrets**, not plain env vars.
3. First deploy only: run `npm run first-run` once against the production
   environment (Render's "Shell" tab on the service, or a one-off Job) to
   apply migrations, bootstrap the two-tier CA hierarchy, and create the
   first ADMIN account. It's safe to run again on later deploys — every
   step is a no-op if already done, **except** that if it had to
   *generate* the CA hierarchy for the first time, it prints
   `ROOT_CA_CERT_BASE64` plus the Issuing CA's `ISSUING_CA_PRIVATE_KEY_BASE64`
   / `ISSUING_CA_CERT_BASE64` once; copy all three into Render's env vars
   immediately. The Root CA's *private* key is never printed — it's written
   only to `keys/root-offline/root-ca-private.pem` on whatever machine ran
   `first-run`, deliberately off of Render's ephemeral filesystem; move
   that one file to real cold storage and keep it off any server. Without
   saving the three printed values, the Issuing CA (and every certificate
   it's issued) is lost on the next redeploy — but note that losing it
   does *not* let you silently regenerate a replacement Issuing CA from the
   same root, since the root private key is deliberately not on this
   server either.
4. Subsequent deploys: just redeploy the image. `node server.ts` (the
   container's `CMD`) does not run migrations itself by design — rerun
   `npm run first-run` (or at least `npx prisma migrate deploy`) after any
   deploy that adds a new migration.

| Variable | Notes |
|---|---|
| `DATABASE_URL` | Neon production connection string |
| `JWT_SECRET` | long random string; **secret** |
| `ROOT_CA_CERT_BASE64` | from first `first-run` (public cert only — no root private key var exists) |
| `ISSUING_CA_PRIVATE_KEY_BASE64` / `ISSUING_CA_CERT_BASE64` | from first `first-run`; the private key var is a **secret** |
| `TSA_URL` | leave unset for the default (DigiCert's public TSA) |
| `TSA_TIMEOUT_MS` / `TSA_MIN_INTERVAL_SECONDS` | defaults `8000` / `600` |
| `TSA_CA_CERT_BASE64` | only needed if `TSA_URL` points at a TSA whose root isn't already trusted; not a secret (a public certificate) |
| `API_PUBLIC_URL` | this API's own public URL, e.g. `https://bhoomirakshak-api.onrender.com` — embedded as the CRL Distribution Point in every issued certificate |
| `TRUST_PROXY` | leave unset (defaults to `1` when `NODE_ENV=production`) |
| `ENABLE_DEMO_TAMPER` | `false` — keep off outside grading/demo |
| `RATE_LIMIT_LOGIN_MAX` / `RATE_LIMIT_LOGIN_WINDOW_MS` | defaults `10` / `900000` (15 min) |
| `RATE_LIMIT_REGISTER_MAX` / `RATE_LIMIT_REGISTER_WINDOW_MS` | defaults `20` / `3600000` (1 hr) |
| `RATE_LIMIT_ANCHOR_MAX` / `RATE_LIMIT_ANCHOR_WINDOW_MS` | defaults `5` / `60000` (1 min) |
| `PG_POOL_MAX` | default `10` |
| `ADMIN_NAME` / `ADMIN_EMAIL` / `ADMIN_PASSWORD` | consumed once by `first-run`; `ADMIN_PASSWORD` **secret**, 10+ chars |
| `FRONTEND_ORIGIN` | the deployed frontend's exact origin, e.g. `https://bhoomirakshak.vercel.app` |
| `NODE_ENV` | `production` |
| `PORT` | Render sets this itself — no action needed |

See `.env.example` for the full list with descriptions.

### 3. Frontend — Vercel

1. Import `frontend/` as the project root in Vercel (Framework preset:
   Vite).
2. Set `VITE_API_URL` to the deployed API's URL plus `/api`, e.g.
   `https://bhoomirakshak-api.onrender.com/api`.
3. Deploy. Update the API's `FRONTEND_ORIGIN` to match the resulting
   Vercel URL (CORS will reject requests from any other origin).

### Known Limits (deployment-specific)

- **No measured production throughput under real concurrent load.** What
  *is* measured, against a remote Neon database from a local dev machine
  (`scripts/test-audit-chain.ts`): a single audit-log write takes roughly
  1.2–1.5s (dominated by Neon round-trip latency, not CPU), and 20
  concurrent writes serialized through the audit chain's advisory lock take
  roughly 20–25s total (i.e. they queue, by design — the chain cannot allow
  two writes to compute the next hash concurrently). A full transaction
  submit (signature verify + business write + audit entry, one Prisma
  transaction) was observed at up to ~5.8s uncontended. These are useful as
  a sanity floor, not a load-test result — a proper load test (e.g. k6 or
  autocannon hitting a deployed instance) was out of scope for this pass.
- **This is a prototype CA, not a legally recognized one.** Certificates
  are real X.509 v3, issued through a genuine two-tier chain (root →
  issuing), but that chain is entirely self-issued by this application —
  there is no real-world chain of trust, OCSP, or third-party attestation.
  It demonstrates the mechanics of PKI-based trust (issuance, expiry,
  revocation, signature verification, chain validation), not a production CA.
- See also the application-level Known Limits below (server-served JS,
  no password recovery, etc.) — those apply in any environment, not just
  this deployment.

## Known Limits

These are deliberate, documented limitations rather than oversights:

- **The server serves the frontend's JavaScript.** Client-side signing
  means the private key and the signing logic only ever run in the
  browser — but the browser is running code this server delivered. A
  compromised server (or a compromised CDN/build pipeline in a real
  deployment) could serve malicious JavaScript that exfiltrates a
  password or a signature before it's ever wrapped/sent. Client-side key
  custody protects against a server that merely *reads its own database*;
  it does not protect against a server that has been fully compromised
  and can serve arbitrary code. Subresource Integrity, code signing, or a
  separately-audited static host for the signing bundle would close this
  gap in a real deployment — none of that is implemented here.
- **Forgetting your password loses your key, permanently.** There is no
  password reset and no key backup/escrow (by design — the server cannot
  decrypt the wrapped key, so it has nothing to reset *to*). The only
  recovery path is an ADMIN revoking the old certificate and the user
  registering again under a fresh key pair and certificate. A self-service
  "reissue certificate" flow (generate a new key pair, prove possession,
  get a fresh certificate on the same account) was scoped as
  time-permitting and was not built in this pass — see Day 3-4 report.
- **No session persistence.** The JWT and the wrapped-key blob both live
  only in React state; a page refresh logs the user out and requires
  re-entering the password again to re-fetch and hold the wrapped key.
  There is deliberately no `localStorage` use, so a stolen XSS payload
  can't read a persisted token — but it also means there's no "remember me."
- **The tamper-evidence demo endpoint** (`POST /api/dev/tamper/:transactionId`,
  `routes/dev.ts`) exists purely to make signature/document tampering
  demonstrable in the UI, and is only mounted at all when
  `ENABLE_DEMO_TAMPER=true` (default off — the route 404s otherwise). It
  bypasses the entire signing flow by writing directly to the database,
  exactly as a real attacker with raw DB access would, and every use is
  itself logged to the audit chain.
- **No jurisdiction scoping on review queues.** Any Village Officer can
  review any `PENDING_VO` transaction, and any Registrar any
  `PENDING_REGISTRAR` transaction, regardless of which village/district the
  land record belongs to (there is no village/district concept modeled at
  all).
- **Documents are stored on local disk** (`uploads/`), not object storage —
  fine for a single-instance MVP, not for a horizontally scaled deployment.
- **No email verification or account recovery flow** beyond the
  certificate-reissue path above.
- **JWTs are short-lived (1 hour) with no refresh-token flow** — expiry
  just requires logging in again (and re-entering the password to re-fetch
  the wrapped key for signing).
- **List endpoints are unpaginated** except `GET /api/users` (caps at 20)
  and `GET /api/audit` (paginated); fine at demo data volumes, not at scale.
