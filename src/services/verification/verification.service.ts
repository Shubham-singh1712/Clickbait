import { PrismaClient } from '@prisma/client';
import {
  NoticeVerificationRequestDto,
  VerificationResult,
  NoticeCanonicalPayload,
  NoticeStatus,
  VerificationResultStatus,
  RiskLevel,
} from '../../types';
import { prisma as defaultPrisma } from '../../config/database';
import {
  canonicalizationService as defaultCanonicalizer,
  ICanonicalizationService,
} from '../crypto/canonicalization.service';
import {
  hashingService as defaultHasher,
  IHashingService,
} from '../crypto/hashing.service';
import {
  ed25519Service as defaultEd25519,
  IEd25519Service,
} from '../crypto/ed25519.service';
import {
  issuerRegistryService as defaultRegistry,
  IIssuerRegistryService,
} from '../registry/issuer-registry.service';
import { logger } from '../../utils/logger';

export interface IVerificationService {
  verifyNotice(request: NoticeVerificationRequestDto): Promise<VerificationResult>;
}

export class VerificationService implements IVerificationService {
  private db: PrismaClient;
  private registry: IIssuerRegistryService;
  private canonicalizer: ICanonicalizationService;
  private hasher: IHashingService;
  private ed25519: IEd25519Service;

  constructor(
    customPrisma?: PrismaClient,
    customRegistry?: IIssuerRegistryService,
    customCanonicalizer?: ICanonicalizationService,
    customHasher?: IHashingService,
    customEd25519?: IEd25519Service
  ) {
    this.db = customPrisma || defaultPrisma;
    this.registry = customRegistry || defaultRegistry;
    this.canonicalizer = customCanonicalizer || defaultCanonicalizer;
    this.hasher = customHasher || defaultHasher;
    this.ed25519 = customEd25519 || defaultEd25519;
  }

  /**
   * Orchestrates full end-to-end cryptographic verification of a digital notice.
   *
   * Verification Pipeline:
   * 1. Validate request structure and payload parameters.
   * 2. Identify institution and resolve active public key from Phase 4 Trusted Issuer Registry.
   * 3. Construct and deterministically canonicalize the NoticeCanonicalPayload (Phase 2).
   * 4. Compute SHA-256 content hash and verify payload integrity (Phase 2).
   * 5. Verify Ed25519 digital signature against registered public key (Phase 3).
   * 6. Check notice expiration and revocation lifecycle status.
   * 7. Formulate and return standardized VerificationResult.
   */
  public async verifyNotice(request: NoticeVerificationRequestDto): Promise<VerificationResult> {
    const timestamp = new Date().toISOString();

    if (!request || typeof request !== 'object') {
      throw new Error('Verification request payload must be a non-null object');
    }

    // 1. Extract canonical payload (supports `canonicalPayload`, `payload`, or fallback noticeId query)
    let payload: NoticeCanonicalPayload | undefined =
      request.canonicalPayload || request.payload;
    const signature = request.signature?.trim();

    // If noticeId is supplied without inline payload, attempt database lookup
    let dbNotice: any = null;
    if (request.noticeId && typeof request.noticeId === 'string' && request.noticeId.trim().length > 0) {
      try {
        dbNotice = await this.db.notice.findUnique({
          where: { id: request.noticeId.trim() },
        });
      } catch (err) {
        logger.error(`Database error looking up notice ${request.noticeId}`, err, 'VerificationService');
      }
    }

    // If payload is not explicitly provided, extract from DB notice record if available
    if (!payload && dbNotice) {
      payload = {
        noticeId: dbNotice.id,
        institutionId: dbNotice.institutionId,
        title: dbNotice.title,
        content: '', // Notice content hash will be verified
        issuedAt: dbNotice.issuedAt.toISOString(),
        expiresAt: dbNotice.expiresAt.toISOString(),
      };
    }

    // If still no payload provided, validate required input
    if (!payload) {
      throw new Error(
        'Must provide "payload" (or "canonicalPayload") with signature for cryptographic verification'
      );
    }

    // 2. Validate input fields
    if (!payload.institutionId || typeof payload.institutionId !== 'string' || payload.institutionId.trim().length === 0) {
      throw new Error('Notice payload requires a valid non-empty "institutionId"');
    }

    if (!payload.title || typeof payload.title !== 'string' || payload.title.trim().length === 0) {
      throw new Error('Notice payload requires a valid non-empty "title"');
    }

    if (typeof payload.content !== 'string') {
      throw new Error('Notice payload requires a "content" string');
    }

    if (!payload.issuedAt) {
      throw new Error('Notice payload requires an "issuedAt" timestamp');
    }

    if (!payload.expiresAt) {
      throw new Error('Notice payload requires an "expiresAt" timestamp');
    }

    // Validate timestamps with canonicalizer
    let normalizedIssuedAt: string;
    let normalizedExpiresAt: string;
    try {
      normalizedIssuedAt = this.canonicalizer.normalizeTimestamp(payload.issuedAt);
      normalizedExpiresAt = this.canonicalizer.normalizeTimestamp(payload.expiresAt);
    } catch {
      throw new Error('Invalid timestamp format provided in notice payload');
    }

    if (new Date(normalizedExpiresAt).getTime() <= new Date(normalizedIssuedAt).getTime()) {
      throw new Error('Notice "expiresAt" timestamp must be strictly later than "issuedAt"');
    }

    if (!signature || typeof signature !== 'string' || signature.length === 0) {
      throw new Error('Verification requires a valid non-empty "signature" string');
    }

    const institutionId = payload.institutionId.trim();

    // 3. Construct normalized NoticeCanonicalPayload
    const normalizedPayload: NoticeCanonicalPayload = {
      institutionId,
      title: payload.title.trim(),
      content: payload.content,
      issuedAt: normalizedIssuedAt,
      expiresAt: normalizedExpiresAt,
    };

    if (payload.noticeId && typeof payload.noticeId === 'string' && payload.noticeId.trim().length > 0) {
      normalizedPayload.noticeId = payload.noticeId.trim();
    }

    if (payload.metadata && typeof payload.metadata === 'object' && !Array.isArray(payload.metadata)) {
      normalizedPayload.metadata = payload.metadata;
    }

    // 4. Compute deterministic canonical string and SHA-256 hash (Phase 2)
    const canonicalString = this.canonicalizer.canonicalizeNoticePayload(normalizedPayload);
    const computedContentHash = this.hasher.sha256(canonicalString);

    // Verify content hash integrity if expected hash was provided in request
    let integrityVerified = true;
    if (request.contentHash && typeof request.contentHash === 'string') {
      integrityVerified = this.hasher.verifyHash(computedContentHash, request.contentHash);
    }

    // 5. Query Phase 4 Trusted Issuer Registry
    const institution = await this.registry.getInstitutionById(institutionId);
    const activeKeyRecord = await this.registry.getActiveKeyByInstitution(institutionId);

    const institutionExists = !!institution && institution.status === 'ACTIVE';
    const trustedIssuerKey = institutionExists && !!activeKeyRecord;

    // 6. Cryptographic Ed25519 Signature Verification (Phase 3)
    let signatureValid = false;
    if (trustedIssuerKey && activeKeyRecord) {
      // Validate signature format (64 bytes Base64)
      if (this.ed25519.validateSignature(signature)) {
        try {
          signatureValid = this.ed25519.verify(
            canonicalString,
            signature,
            activeKeyRecord.publicKey
          );
        } catch (err) {
          logger.warn(`Signature verification exception for institution ${institutionId}`, 'VerificationService');
          signatureValid = false;
        }
      }
    }

    // 7. Expiry & Revocation Checks
    const now = Date.now();
    const noticeExpiryTime = new Date(normalizedExpiresAt).getTime();
    const notExpired = noticeExpiryTime > now;

    let notRevoked = true;
    if (dbNotice && (dbNotice.status === 'REVOKED' || dbNotice.revokedAt !== null)) {
      notRevoked = false;
    }

    // 8. Overall Authenticity & Result Status Determination
    const isAuthentic =
      signatureValid &&
      integrityVerified &&
      notExpired &&
      notRevoked &&
      trustedIssuerKey;

    let resultStatus: VerificationResultStatus;
    let riskLevel: RiskLevel;

    if (isAuthentic) {
      resultStatus = 'VERIFIED';
      riskLevel = 'NONE';
    } else if (!trustedIssuerKey) {
      resultStatus = 'UNVERIFIED';
      riskLevel = 'HIGH';
    } else if (!signatureValid || !integrityVerified) {
      resultStatus = 'TAMPERED';
      riskLevel = 'CRITICAL';
    } else if (!notRevoked) {
      resultStatus = 'REVOKED';
      riskLevel = 'HIGH';
    } else if (!notExpired) {
      resultStatus = 'EXPIRED';
      riskLevel = 'LOW';
    } else {
      resultStatus = 'SUSPICIOUS';
      riskLevel = 'HIGH';
    }

    // Format final response
    const result: VerificationResult = {
      isAuthentic,
      resultStatus,
      riskLevel,
      ...(institution
        ? {
            institution: {
              id: institution.id,
              name: institution.name,
              verifiedDomain: institution.verifiedDomain,
            },
          }
        : undefined),
      notice: {
        id: normalizedPayload.noticeId || dbNotice?.id || 'unregistered-notice',
        title: normalizedPayload.title,
        contentHash: computedContentHash,
        issuedAt: normalizedIssuedAt,
        expiresAt: normalizedExpiresAt,
        status: (dbNotice?.status as NoticeStatus) || (notExpired ? 'ACTIVE' : 'EXPIRED'),
      },
      checks: {
        signatureValid,
        integrityVerified,
        notExpired,
        notRevoked,
        trustedIssuerKey,
      },
      timestamp,
    };

    return result;
  }
}

export const verificationService = new VerificationService();
