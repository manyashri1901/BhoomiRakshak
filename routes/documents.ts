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
import { appendAuditEntry } from "../lib/audit.ts";
import { detectDocumentType, DOCUMENT_TYPE_EXTENSIONS } from "../lib/fileType.ts";

const router = express.Router();

const UPLOAD_DIR = path.join(process.cwd(), "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const MAX_UPLOAD_BYTES = 20 * 1024 * 1024; // 20MB — sane cap for land-record documents

// memoryStorage, not diskStorage: the upload must be inspected (magic
// bytes) BEFORE anything is written to disk — a file that fails the check
// should never touch the filesystem at all, not get written then deleted.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_BYTES },
});

function uploadSingleFile(req: express.Request, res: express.Response, next: express.NextFunction) {
  upload.single("file")(req, res, (err: unknown) => {
    if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
      res.status(413).json({ error: `File exceeds the ${MAX_UPLOAD_BYTES / (1024 * 1024)}MB limit` });
      return;
    }
    if (err) {
      next(err);
      return;
    }
    next();
  });
}

router.post("/upload", requireAuth, uploadSingleFile, async (req, res) => {
  if (!req.file) {
    res.status(400).json({ error: "file is required (multipart field name: file)" });
    return;
  }

  // The client-declared mimetype/filename are not trusted — only the
  // actual file header bytes decide what this file is. Anything that
  // doesn't match the PDF/PNG/JPEG allowlist is rejected before it's ever
  // written to uploads/.
  const documentType = detectDocumentType(req.file.buffer);
  if (!documentType) {
    res.status(415).json({
      error: "Unsupported file type. Only PDF, PNG, and JPEG documents are accepted.",
    });
    return;
  }

  const documentHash = crypto.createHash("sha256").update(req.file.buffer).digest("hex");

  // Fully random stored filename (not derived from the client-supplied
  // originalname at all) with an extension derived from the DETECTED type,
  // not the claimed one.
  const storedFilename = `${randomUUID()}.${DOCUMENT_TYPE_EXTENSIONS[documentType]}`;
  const storedPath = path.join(UPLOAD_DIR, storedFilename);
  await fs.promises.writeFile(storedPath, req.file.buffer);

  // Relative path (not an absolute filesystem path) so it's portable
  // across environments and safe to store/return.
  const documentPath = path.relative(process.cwd(), storedPath).split(path.sep).join("/");

  await appendAuditEntry({
    action: "DOCUMENT_UPLOADED",
    actorUserId: req.user!.userId,
    entityType: "DOCUMENT",
    entityId: documentPath,
    details: { documentHash, documentType, sizeBytes: req.file.buffer.length },
  });

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
