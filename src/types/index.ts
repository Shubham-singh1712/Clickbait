// =============================================================================
// CLICKBAIT - Type Definitions & Domain Contracts
// =============================================================================

export type InstitutionStatus = 'PENDING' | 'ACTIVE' | 'SUSPENDED';
export type KeyStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED';
export type NoticeStatus = 'ACTIVE' | 'REVOKED' | 'EXPIRED';
export type VerificationResultStatus =
  | 'VERIFIED'
  | 'TAMPERED'
  | 'EXPIRED'
  | 'REVOKED'
  | 'UNVERIFIED'
  | 'SUSPICIOUS';
export type RiskLevel = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// -----------------------------------------------------------------------------
// Standard API Response Envelope
// -----------------------------------------------------------------------------
export interface ApiResponse<T = unknown> {
  success: boolean;
  message?: string;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  timestamp: string;
}

// -----------------------------------------------------------------------------
// Notice Canonical Payload & Signing Contracts
// -----------------------------------------------------------------------------
export interface NoticeCanonicalPayload {
  noticeId?: string;
  institutionId: string;
  title: string;
  content: string;
  issuedAt: string; // ISO 8601 UTC
  expiresAt: string; // ISO 8601 UTC
  metadata?: Record<string, unknown>;
}

export interface NoticeCreateDto {
  noticeId?: string;
  institutionId: string;
  title: string;
  content: string;
  issuedAt?: string | Date; // ISO 8601 format or Date, defaults to current time
  expiresAt: string | Date; // ISO 8601 format or Date
  metadata?: Record<string, unknown>;
}

export interface SignedNoticeResponseDto {
  id: string;
  noticeId?: string;
  institutionId: string;
  title: string;
  content: string;
  issuedAt: string;
  expiresAt: string;
  metadata?: Record<string, unknown>;
  contentHash: string;
  signature: string;
  signatureAlgorithm: string;
  status: NoticeStatus;
}

export interface NoticeRevokeDto {
  reason: string;
}

export interface NoticeVerificationRequestDto {
  noticeId?: string;
  institutionId?: string;
  canonicalPayload?: NoticeCanonicalPayload;
  payload?: NoticeCanonicalPayload; // Alias for canonicalPayload
  contentHash?: string;
  signature?: string;
  publicKey?: string; // Optional: verified only if validated against trusted registry
}

export interface ScreenshotVerificationRequestDto {
  imageDataBase64?: string;
  imageUrl?: string;
  claimedDomain?: string;
  claimedInstitutionId?: string;
}

export interface VerificationResult {
  isAuthentic: boolean;
  resultStatus: VerificationResultStatus;
  riskLevel: RiskLevel;
  institution?: {
    id: string;
    name: string;
    verifiedDomain: string;
  };
  notice?: {
    id: string;
    title: string;
    contentHash: string;
    issuedAt: string;
    expiresAt: string;
    status: NoticeStatus;
  };
  checks: {
    signatureValid: boolean;
    integrityVerified: boolean;
    notExpired: boolean;
    notRevoked: boolean;
    trustedIssuerKey: boolean;
    blockchainProvenanceConfirmed?: boolean;
  };
  securityAnalysis?: {
    indicators?: Record<string, unknown>;
    aiAssessment?: Record<string, unknown>;
  };
  timestamp: string;
}

// -----------------------------------------------------------------------------
// Blockchain Provenance Contract (STRICT ZERO-PII GUARANTEE)
// -----------------------------------------------------------------------------
export interface BlockchainNoticeProvenance {
  institutionId: string;
  publicKeyRef: string;
  noticeId: string;
  contentHash: string;
  issuanceTimestamp: number;
  expiryTimestamp: number;
  isRevoked: boolean;
  blockNumber?: number;
  transactionHash?: string;
}

// -----------------------------------------------------------------------------
// Institution & Issuer Key Domain Models
// -----------------------------------------------------------------------------
export interface InstitutionRecord {
  id: string;
  name: string;
  verifiedDomain: string;
  status: InstitutionStatus;
  createdAt: Date;
  updatedAt: Date;
}

export interface InstitutionCreateDto {
  name: string;
  verifiedDomain: string;
  status?: InstitutionStatus;
}

export interface RegisterTrustedKeyDto {
  publicKey: string;
  expiresAt: string | Date;
}

export interface IssuerKeyRecord {
  id: string;
  institutionId: string;
  publicKey: string;
  keyStatus: KeyStatus;
  createdAt: Date;
  expiresAt: Date;
  revokedAt?: Date | null;
}

