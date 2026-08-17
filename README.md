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
Known MVP Simplifications below.

## Project structure

```
lib/                CA (lib/ca.ts), signing engine (lib/signing.ts),
                     canonical JSON (lib/canonicalize.ts), Prisma client
middleware/auth.ts   requireAuth / requireRole (JWT verification, RBAC)
routes/              One file per resource — auth, documents, land-records,
                     transactions, certificates, users, dev (demo-only)
prisma/schema.prisma Data model; prisma/migrations/ — migration history
keys/                CA root key pair (generated on first run; gitignored)
uploads/             Uploaded transaction documents (gitignored)
frontend/            Vite React app — src/pages, src/components, src/api
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

## Known MVP Simplifications

These are deliberate shortcuts for this stage of the project, called out
here rather than left silent:

- **Private keys are stored server-side, in plaintext, in the database**
  (`User.privateKeyRef`). A production system would generate and hold each
  user's private key client-side (browser/mobile secure storage) or in an
  HSM/KMS — the server would only ever see public keys. This is the single
  biggest simplification in the MVP and is called out in `routes/auth.ts`
  where the key is written.
- **No session persistence.** The JWT lives only in React state; a page
  refresh logs the user out. There is deliberately no `localStorage` use,
  so a stolen XSS payload can't read a persisted token — but it also means
  there's no "remember me."
- **The tamper-evidence demo endpoint** (`POST /api/dev/tamper/:transactionId`,
  `routes/dev.ts`) exists purely to make signature/document tampering
  demonstrable in the UI. It bypasses the entire signing flow by writing
  directly to the database, exactly as a real attacker with raw DB access
  would. It is Registrar-gated and clearly marked DEMO-ONLY in code — no
  production deployment would ship this route.
- **No jurisdiction scoping on review queues.** Any Village Officer can
  review any `PENDING_VO` transaction, and any Registrar any
  `PENDING_REGISTRAR` transaction, regardless of which village/district the
  land record belongs to (there is no village/district concept modeled at
  all).
- **Documents are stored on local disk** (`uploads/`), not object storage —
  fine for a single-instance MVP, not for a horizontally scaled deployment.
- **No email verification, password reset, or account recovery flow.**
- **No rate limiting** on login or registration.
- **JWTs are short-lived (1 hour) with no refresh-token flow** — expiry
  just requires logging in again.
- **List endpoints are unpaginated** except `GET /api/users`, which caps at
  20 results; fine at demo data volumes, not at scale.
