# Dockerfile for the BhoomiRakshak API (backend only — the frontend is a
# static Vite build meant to be deployed separately, e.g. to Vercel).
#
# The backend has no build step of its own: it runs .ts files directly via
# Node 22's native TypeScript stripping (see server.ts, package.json
# "dev" script). The only thing that needs to happen before the server can
# start is `prisma generate`, which writes the typed client to
# generated/prisma (see prisma/schema.prisma's custom `output`) — that
# happens once in the builder stage below and the result is copied into
# the runtime image.
#
# devDependencies (specifically the `prisma` CLI package) are kept in the
# final image on purpose, not pruned with --omit=dev: scripts/first-run.ts
# shells out to `npx prisma migrate deploy` as a one-off deployment step
# (see README's Deploy section), and that needs the CLI binary, not just
# the generated @prisma/client runtime. This makes the image a bit larger
# than a typical pruned Node image — an acceptable trade-off for a
# single-service student project rather than adding a separate migration
# image/stage.

FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY prisma ./prisma
COPY prisma.config.ts ./
RUN npx prisma generate

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/generated ./generated
COPY package.json package-lock.json prisma.config.ts ./
COPY prisma ./prisma
COPY lib ./lib
COPY middleware ./middleware
COPY routes ./routes
COPY scripts ./scripts
COPY server.ts ./server.ts

# node:22-alpine already ships an unprivileged "node" user (uid/gid 1000).
# uploads/ is where routes/documents.ts writes received files
# (fs.mkdirSync in that file is also safe to run again under this user —
# it's a no-op if the directory already exists and is owned correctly).
RUN mkdir -p uploads && chown -R node:node /app
USER node

EXPOSE 4000
CMD ["node", "server.ts"]
