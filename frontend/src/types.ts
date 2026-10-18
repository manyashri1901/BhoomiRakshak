export type Role = "LANDOWNER" | "VILLAGE_OFFICER" | "REGISTRAR" | "ADMIN";

export interface AuthUser {
  userId: string;
  role: Role;
  name: string;
}

export type LandRecordStatus = "ACTIVE" | "PENDING" | "DISPUTED" | "TRANSFERRED";
export type TransactionType = "REGISTRATION" | "TRANSFER" | "UPDATE" | "SUCCESSION";
export type TransactionStatus = "PENDING_VO" | "PENDING_REGISTRAR" | "APPROVED" | "REJECTED";
export type AreaUnit = "HECTARE" | "ACRE";
export type UserStatus = "ACTIVE" | "DECEASED";

export interface LandRecord {
  id: string;
  surveyNumber: string;
  location: string;
  area: number; // denominated in areaUnit — always read/display them together
  areaUnit: AreaUnit;
  status: LandRecordStatus;
  createdAt: string;
  currentOwnerId: string;
  currentOwnerName?: string;
}

export interface LandRecordListItem extends LandRecord {
  currentOwnerName: string;
}

export interface UserSummary {
  id: string;
  name: string;
  role: Role;
}

// The actor embedded in a signature is deliberately narrowed server-side —
// never passwordHash or wrapped key material, only what verification/display need.
// `certificate` was already present in the JSON returned by GET /pending-vo
// and GET /pending-registrar (see routes/transactions.ts's
// transactionWithChain) — just not previously declared here.
export interface ActorSummary {
  id: string;
  name: string;
  publicKey: string;
  certificate: { fingerprint: string } | null;
}

export interface SignatureWithActor {
  id: string;
  transactionId: string;
  actorId: string;
  role: Role;
  signedAt: string;
  signatureValue: string;
  dataHash: string;
  valid: boolean;
  actor: ActorSummary;
}

export interface TransactionWithChain {
  id: string;
  type: TransactionType;
  landRecordId: string;
  fromOwnerId: string | null;
  toOwnerId: string;
  documentPath: string;
  documentHash: string;
  secondaryDocumentPath: string | null;
  secondaryDocumentHash: string | null;
  status: TransactionStatus;
  rejectReason: string | null;
  createdAt: string;
  landRecord: LandRecord;
  signatures: SignatureWithActor[];
}

export interface RawSignature {
  id: string;
  transactionId: string;
  actorId: string;
  role: Role;
  signedAt: string;
  signatureValue: string;
  dataHash: string;
  valid: boolean;
}

export interface TransactionActionResult {
  id: string;
  type: TransactionType;
  landRecordId: string;
  fromOwnerId: string | null;
  toOwnerId: string;
  documentPath: string;
  documentHash: string;
  status: TransactionStatus;
  rejectReason: string | null;
  createdAt: string;
  signature?: RawSignature;
  landRecord?: LandRecord;
}

export interface AutoRejectResult {
  transaction: TransactionActionResult;
  autoRejected: true;
  reason: string;
}

export interface HistorySignature {
  actorName: string;
  role: Role;
  signedAt: string;
  valid: boolean;
  // certificateValid is "valid AT SIGNING TIME" — see routes/transactions.ts's
  // GET /:id/verify for the full rationale. currentlyRevoked distinguishes
  // "signed while valid, certificate later revoked" (e.g. a deceased
  // SUCCESSION owner's earlier signatures) from a signature that was
  // never good. signingTimeTrusted false means no matching audit log
  // entry was found — certificateValid is then always false regardless.
  certificateValid: boolean;
  certificateReason: string | null;
  currentlyRevoked: boolean;
  currentlyRevokedReason: string | null;
  signingTimeTrusted: boolean;
}

export interface DocumentIntegrityResult {
  match: boolean;
  error?: string;
}

export interface HistoryTransaction {
  id: string;
  type: TransactionType;
  landRecordId: string;
  fromOwnerId: string | null;
  fromOwnerName: string | null;
  toOwnerId: string;
  toOwnerName: string;
  documentPath: string;
  documentHash: string;
  secondaryDocumentPath: string | null;
  secondaryDocumentHash: string | null;
  status: TransactionStatus;
  rejectReason: string | null;
  createdAt: string;
  signatures: HistorySignature[];
  documentIntegrity: DocumentIntegrityResult;
}

export interface LandRecordHistory {
  landRecord: LandRecord;
  transactions: HistoryTransaction[];
}

// GET /api/transactions/mine — every transaction where the caller is the
// buyer or the seller, regardless of who currently owns the land record
// (backs transfer-status visibility on both the buyer's and seller's
// dashboards; see routes/transactions.ts).
export interface MyTransaction {
  id: string;
  type: TransactionType;
  landRecordId: string;
  surveyNumber: string;
  location: string;
  fromOwnerId: string | null;
  fromOwnerName: string | null;
  toOwnerId: string;
  toOwnerName: string;
  status: TransactionStatus;
  rejectReason: string | null;
  createdAt: string;
  isBuyer: boolean;
  isSeller: boolean;
}

export interface Certificate {
  id: string;
  subjectUserId: string;
  subjectName: string;
  role: Role;
  publicKey: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
  fingerprint: string;
  revoked: boolean;
  revokedAt: string | null;
  revokedReason: string | null;
  valid: boolean;
  reason: string | null;
}

export interface RevokedCertificateSummary {
  certificateId: string;
  subjectUserId: string;
  subjectName: string;
  role: Role;
  fingerprint: string;
  revokedAt: string;
  revokedReason: string | null;
  revokedByUserId: string | null;
}

export interface TransactionVerifyResult {
  transactionId: string;
  status: TransactionStatus;
  signerIdentity: {
    actorId: string;
    actorName: string;
    role: Role;
    certificateValid: boolean;
    certificateReason: string | null;
    currentlyRevoked: boolean;
    currentlyRevokedReason: string | null;
    signingTimeTrusted: boolean;
  }[];
  signatureValidity: {
    actorName: string;
    role: Role;
    signedAt: string;
    valid: boolean;
  }[];
  documentIntegrity: DocumentIntegrityResult;
}
