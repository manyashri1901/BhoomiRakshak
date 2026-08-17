// routes/documents.ts
//
// POST /api/documents/upload  — accepts one file, saves it under /uploads,
//                                and returns its SHA-256 hash. This is a
//                                standalone step: transaction creation
//                                (routes/transactions.ts) calls this first,
//                                then references the returned
//                                {documentPath, documentHash} when signing.
// GET  /api/documents/:filename — authenticated download of a previously
//                                uploaded file, so a reviewer can inspect
//                                the document a transaction references.

import express from "express";
import multer from "multer";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { requireAuth } from "../middleware/auth.ts";

const router = express.Router();

const UPLOAD_DIR = path.join(process.cwd(), "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    // path.basename + character allowlist: file.originalname is
    // client-controlled, so strip any directory components and anything
    // that isn't a safe filename character before it's used to build a
    // path on disk (prevents path traversal via a crafted filename).
    const safeName = path
      .basename(file.originalname)
      .replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, `${randomUUID()}-${safeName}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB — sane cap for land-record documents
});

router.post("/upload", requireAuth, upload.single("file"), async (req, res) => {
  if (!req.file) {
    res.status(400).json({ error: "file is required (multipart field name: file)" });
    return;
  }

  // Hash the actual bytes written to disk — not the filename or any
  // multer metadata — since this hash is what later gets embedded in a
  // signed transaction payload and must reflect exactly what's on disk.
  const fileBuffer = await fs.promises.readFile(req.file.path);
  const documentHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");

  // Relative path (not an absolute filesystem path) so it's portable
  // across environments and safe to store/return.
  const documentPath = path
    .relative(process.cwd(), req.file.path)
    .split(path.sep)
    .join("/");

  res.status(201).json({ documentPath, documentHash });
});

router.get("/:filename", requireAuth, (req, res) => {
  // filename comes straight from the URL — it's already just a bare
  // filename (no slashes reach a route param), but resolve + confirm it's
  // still inside UPLOAD_DIR before touching the filesystem, matching the
  // same defense used when transactions re-read a client-supplied path.
  const resolvedPath = path.resolve(UPLOAD_DIR, req.params.filename);
  if (resolvedPath !== UPLOAD_DIR && !resolvedPath.startsWith(UPLOAD_DIR + path.sep)) {
    res.status(400).json({ error: "Invalid filename" });
    return;
  }

  res.sendFile(resolvedPath, (err) => {
    if (err) {
      res.status(404).json({ error: "File not found" });
    }
  });
});

export default router;
