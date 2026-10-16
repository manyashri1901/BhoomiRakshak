// lib/fileType.ts
//
// Detects a file's real type from its magic bytes (the actual file
// header), not from its claimed Content-Type or its extension — both of
// which the uploader fully controls and can spoof (e.g. renaming an .exe
// to document.pdf). This is the check that catches that: the allowlist
// below is checked against bytes read from the buffer itself.

export type AllowedDocumentType = "pdf" | "png" | "jpeg";

const SIGNATURES: { type: AllowedDocumentType; magic: number[] }[] = [
  { type: "pdf", magic: [0x25, 0x50, 0x44, 0x46, 0x2d] }, // "%PDF-"
  { type: "png", magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: "jpeg", magic: [0xff, 0xd8, 0xff] },
];

export function detectDocumentType(buffer: Buffer): AllowedDocumentType | null {
  for (const { type, magic } of SIGNATURES) {
    if (buffer.length >= magic.length && magic.every((byte, i) => buffer[i] === byte)) {
      return type;
    }
  }
  return null;
}

export const DOCUMENT_TYPE_EXTENSIONS: Record<AllowedDocumentType, string> = {
  pdf: "pdf",
  png: "png",
  jpeg: "jpg",
};
