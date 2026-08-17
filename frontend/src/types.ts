export type Role = "LANDOWNER" | "VILLAGE_OFFICER" | "REGISTRAR";

export interface AuthUser {
  userId: string;
  role: Role;
  name: string;
}

export type LandRecordStatus = "ACTIVE" | "PENDING" | "DISPUTED" | "TRANSFERRED";
export type TransactionType = "REGISTRATION" | "TRANSFER" | "UPDATE";
export type TransactionStatus = "PENDING_VO" | "PENDING_REGISTRAR" | "APPROVED" | "REJECTED";
export type AreaUnit = "HECTARE" | "ACRE";

export interface LandRecord {
  id: string;
  surveyNumber: string;
  location: string;
  area: number; // denominated in areaUnit — always read/display them together
  areaUnit: AreaUnit;
  status: LandRecordStatus;
  createdAt: string;
  currentOwnerId: string;
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
// never passwordHash/privateKeyRef, only what verification/display need.
export interface ActorSummary {
  id: string;
  name: string;
  publicKey: string;
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
  toOwnerId: string;
  documentPath: string;
  documentHash: string;
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

export interface Certificate {
  id: string;
  subjectUserId: string;
  subjectName: string;
  role: Role;
  publicKey: string;
  issuer: string;
  issuedAt: string;
  fingerprint: string;
  valid: boolean;
}

export interface TransactionVerifyResult {
  transactionId: string;
  status: TransactionStatus;
  signerIdentity: {
    actorId: string;
    actorName: string;
    role: Role;
    certificateValid: boolean;
  }[];
  signatureValidity: {
    actorName: string;
    role: Role;
    signedAt: string;
    valid: boolean;
  }[];
  documentIntegrity: DocumentIntegrityResult;
}
