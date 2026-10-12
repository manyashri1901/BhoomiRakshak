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

## Project structure

```
lib/                 CA (ca.ts), signature verification (signing.ts),
                     prepare/submit nonces (signingNonce.ts), canonical
                     JSON (canonicalize.ts), audit hash chain (audit.ts),
                     upload magic-byte detection (fileType.ts), Prisma client
middleware/          auth.ts (requireAuth/requireRole), rateLimit.ts
routes/              One file per resource — auth, documents, land-records,
                     transactions, certificates, users, audit, dev (demo-only)
prisma/schema.prisma Data model; prisma/migrations/ — migration history
keys/                CA root key pair (generated on first run; gitignored)
uploads/             Uploaded transaction documents (gitignored)
scripts/             CA demo, admin bootstrap, and crypto/signing test scripts
frontend/            Vite React app — src/pages, src/components, src/api;
                     src/lib/clientCrypto.ts (Web Crypto key handling),
                     src/lib/signAndSubmit.ts (prepare -> sign -> submit)
```

## Setup

### Prerequisites

- Node.js 22 or later
- A PostgreSQL database (developed against [Neon](https://neon.tech))

### Backend

```bash
npm install
```

Create `.env` in the project root:

```bash
DATABASE_URL="postgresql://user:password@host/db?sslmode=require"
JWT_SECRET="<a long random string>"   # e.g. `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
```

Run the migration to create all tables:

```bash
npx prisma migrate dev
```

Start the API (port 4000 by default; override with `PORT`):

```bash
npm run dev
```

On first request that touches the CA, `keys/ca-private.pem` and
`keys/ca-public.pem` are generated automatically if they don't already
exist.

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
