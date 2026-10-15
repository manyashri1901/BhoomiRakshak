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
scripts/             CA demo, admin bootstrap, first-run, attack simulation,
                     and crypto/signing test scripts
test/                node --test unit tests (canonicalize, signing, certificate)
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

## Running the tests

```bash
npm test                      # unit tests (node --test): canonicalization,
                               # signature verify, certificate valid/expired/revoked
npm run attack-sim            # attack simulation — requires the API running
                               # separately first (npm run dev), and prints a
                               # pass/fail table; exits non-zero if any attack
                               # that should have been blocked instead succeeded
```

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
   apply migrations, create/load the CA key pair, and create the first
   ADMIN account. It's safe to run again on later deploys — every step is a
   no-op if already done, **except** that if it had to *generate* a CA key
   pair, it prints the `CA_PRIVATE_KEY_BASE64` / `CA_PUBLIC_KEY_BASE64`
   values once; copy those into Render's env vars immediately; Render's
   filesystem is ephemeral, so without this the CA key (and every
   certificate ever issued) is lost on the next redeploy.
4. Subsequent deploys: just redeploy the image. `node server.ts` (the
   container's `CMD`) does not run migrations itself by design — rerun
   `npm run first-run` (or at least `npx prisma migrate deploy`) after any
   deploy that adds a new migration.

| Variable | Notes |
|---|---|
| `DATABASE_URL` | Neon production connection string |
| `JWT_SECRET` | long random string; **secret** |
| `CA_PRIVATE_KEY_BASE64` / `CA_PUBLIC_KEY_BASE64` | from first `first-run`; **secrets** |
| `TRUST_PROXY` | leave unset (defaults to `1` when `NODE_ENV=production`) |
| `ENABLE_DEMO_TAMPER` | `false` — keep off outside grading/demo |
| `RATE_LIMIT_LOGIN_MAX` / `RATE_LIMIT_LOGIN_WINDOW_MS` | defaults `10` / `900000` (15 min) |
| `RATE_LIMIT_REGISTER_MAX` / `RATE_LIMIT_REGISTER_WINDOW_MS` | defaults `20` / `3600000` (1 hr) |
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
  are self-issued by this application's own root key — there is no
  real-world chain of trust, OCSP, or third-party attestation. It
  demonstrates the mechanics of PKI-based trust (issuance, expiry,
  revocation, signature verification), not a production CA.
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
