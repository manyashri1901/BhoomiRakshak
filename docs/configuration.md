# Configuration

Environment variables for a production deployment (see `.env.example` in
the repo root for local-development defaults and full inline documentation
of every variable).

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
| `ENABLE_DEMO_TAMPER` | `false` — keep off outside grading/test mode |
| `RATE_LIMIT_LOGIN_MAX` / `RATE_LIMIT_LOGIN_WINDOW_MS` | defaults `10` / `900000` (15 min) |
| `RATE_LIMIT_REGISTER_MAX` / `RATE_LIMIT_REGISTER_WINDOW_MS` | defaults `20` / `3600000` (1 hr) |
| `RATE_LIMIT_ANCHOR_MAX` / `RATE_LIMIT_ANCHOR_WINDOW_MS` | defaults `5` / `60000` (1 min) |
| `PG_POOL_MAX` | default `10` |
| `ADMIN_NAME` / `ADMIN_EMAIL` / `ADMIN_PASSWORD` | consumed once by `first-run`; `ADMIN_PASSWORD` **secret**, 10+ chars |
| `FRONTEND_ORIGIN` | the deployed frontend's exact origin, e.g. `https://bhoomirakshak.vercel.app` |
| `NODE_ENV` | `production` |
| `PORT` | Render sets this itself — no action needed |

See `.env.example` for the full list with descriptions.
