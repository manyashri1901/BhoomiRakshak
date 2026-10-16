# Deploying

This is a two-service deployment: the API (this repo's root, as a Docker
container) and the frontend (`frontend/`, a static Vite build). They are
deployed independently and talk to each other only over HTTPS via
`FRONTEND_ORIGIN` / `VITE_API_URL`.

## 1. Database — Neon

Create a **new, separate Neon project/database for production** — do not
point production at the same database used for local development. Copy its
pooled connection string into `DATABASE_URL`.

## 2. API — Render (Docker)

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

See [`configuration.md`](configuration.md) for the full environment
variable table.

## 3. Frontend — Vercel

1. Import `frontend/` as the project root in Vercel (Framework preset:
   Vite).
2. Set `VITE_API_URL` to the deployed API's URL plus `/api`, e.g.
   `https://bhoomirakshak-api.onrender.com/api`.
3. Deploy. Update the API's `FRONTEND_ORIGIN` to match the resulting
   Vercel URL (CORS will reject requests from any other origin).

## Known limits

No measured production throughput under real concurrent load, client-side
key custody's own trust boundary, password/key recovery, and the rest —
see the full, deduplicated list in [`security.md`](security.md).
