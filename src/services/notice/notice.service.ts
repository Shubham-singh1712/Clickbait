import { PrismaClient } from '@prisma/client';
import {
  NoticeCreateDto,
  NoticeRevokeDto,
  NoticeStatus,
  NoticeCanonicalPayload,
  SignedNoticeResponseDto,
} from '../../types';
import { prisma as defaultPrisma } from '../../config/database';
import { canonicalizationService } from '../crypto/canonicalization.service';
import { hashingService } from '../crypto/hashing.service';
import { ed25519Service } from '../crypto/ed25519.service';
import {
  issuerRegistryService as defaultRegistry,
  IIssuerRegistryService,
} from '../registry/issuer-registry.service';
import { logger } from '../../utils/logger';
import { env } from '../../config/env';

export interface NoticeRecord {
  id: string;
  institutionId: string;
  title: string;
  contentHash: string;
  signature: string;
  issuedAt: Date;
  expiresAt: Date;
  status: NoticeStatus;
  revocationReason?: string | null;
  revokedAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface INoticeService {
  createAndSignNotice(
    dto: NoticeCreateDto,
    signingKeyOverride?: string
  ): Promise<SignedNoticeResponseDto>;
  revokeNotice(noticeId: string, dto: NoticeRevokeDto): Promise<NoticeRecord>;
  getNoticeById(id: string): Promise<NoticeRecord | null>;
  setInstitutionSigningKey(institutionId: string, privateKeyBase64: string): void;
}

export class NoticeService implements INoticeService {
  private db: PrismaClient;
  private registry: IIssuerRegistryService;
  // Secure server-side in-memory keystore for institutional signing keys (HSM/vault mock)
  private secureKeyStore: Map<string, string> = new Map();

  constructor(customPrisma?: PrismaClient, customRegistry?: IIssuerRegistryService) {
    this.db = customPrisma || defaultPrisma;
    this.registry = customRegistry || defaultRegistry;
  }

  /**
   * Securely maps an institution ID to its private signing key within the server-side vault.
   * NOTE: This is an internal configuration / vault interface; private keys are NEVER accepted over HTTP.
   */
  public setInstitutionSigningKey(institutionId: string, privateKeyBase64: string): void {
    if (!institutionId || !privateKeyBase64) {
      throw new Error('institutionId and privateKeyBase64 are required to configure signing key');
    }
    this.secureKeyStore.set(institutionId.trim(), privateKeyBase64.trim());
  }

  /**
   * Validates notice creation inputs before canonicalization and signing.
   */
  private validateNoticeInput(dto: NoticeCreateDto): {
    normalizedTitle: string;
    normalizedIssuedAt: string;
    normalizedExpiresAt: string;
  } {
    if (!dto || typeof dto !== 'object') {
      throw new Error('Notice creation payload must be a non-null object');
    }

    // 1. Institution ID validation
    if (!dto.institutionId || typeof dto.institutionId !== 'string' || dto.institutionId.trim().length === 0) {
      throw new Error('Valid "institutionId" is required');
    }

    // 2. Title validation
    if (!dto.title || typeof dto.title !== 'string' || dto.title.trim().length === 0) {
      throw new Error('Notice "title" is required and cannot be empty');
    }

    const trimmedTitle = dto.title.trim();
    if (trimmedTitle.length > 500) {
      throw new Error('Notice "title" exceeds maximum length of 500 characters');
    }

    // 3. Content validation
    if (!dto.content || typeof dto.content !== 'string' || dto.content.trim().length === 0) {
      throw new Error('Notice "content" is required and cannot be empty');
    }

    // 4. IssuedAt timestamp validation
    let normalizedIssuedAt: string;
    try {
      normalizedIssuedAt = canonicalizationService.normalizeTimestamp(dto.issuedAt || new Date());
    } catch {
      throw new Error('Invalid "issuedAt" timestamp provided');
    }

    // 5. ExpiresAt timestamp validation
    if (!dto.expiresAt) {
      throw new Error('Notice "expiresAt" timestamp is required');
    }

    let normalizedExpiresAt: string;
    try {
      normalizedExpiresAt = canonicalizationService.normalizeTimestamp(dto.expiresAt);
    } catch {
      throw new Error('Invalid "expiresAt" timestamp provided');
    }

    // 6. Temporal relationship check: expiresAt must be strictly later than issuedAt
    const issuedTime = new Date(normalizedIssuedAt).getTime();
    const expiryTime = new Date(normalizedExpiresAt).getTime();

    if (expiryTime <= issuedTime) {
      throw new Error('Notice "expiresAt" timestamp must be strictly later than "issuedAt"');
    }

    // 7. Metadata validation if provided
    if (dto.metadata !== undefined && dto.metadata !== null) {
      if (typeof dto.metadata !== 'object' || Array.isArray(dto.metadata)) {
        throw new Error('Notice "metadata" must be a valid JSON object');
      }
    }

    return {
      normalizedTitle: trimmedTitle,
      normalizedIssuedAt,
      normalizedExpiresAt,
    };
  }

  /**
   * Retrieves the authorized private signing key for an institution from server-side vault or environment.
   */
  private resolveSigningKey(institutionId: string, signingKeyOverride?: string): string {
    if (signingKeyOverride && typeof signingKeyOverride === 'string') {
      return signingKeyOverride.trim();
    }

    const storedKey = this.secureKeyStore.get(institutionId);
    if (storedKey) {
      return storedKey;
    }

    // Fallback to environment fixture if configured (for local dev/testing)
    if (process.env.INSTITUTION_PRIVATE_KEY_TEST_FIXTURE) {
      return process.env.INSTITUTION_PRIVATE_KEY_TEST_FIXTURE.trim();
    }

    throw new Error(
      `Signing authorization failed: No secure private signing key configured on server for institution '${institutionId}'`
    );
  }

  /**
   * Orchestrates the complete Notice Creation and Cryptographic Signing workflow.
   *
   * Workflow:
   * 1. Validate notice input parameters (title, content, timestamps, metadata).
   * 2. Validate institution existence and active status in registry.
   * 3. Resolve active trusted Ed25519 public key for the institution.
   * 4. Retrieve institution private signing key from secure server-side vault.
   * 5. Construct NoticeCanonicalPayload and canonicalize using Phase 2 rules.
   * 6. Generate SHA-256 content hash using Phase 2 hashing engine.
   * 7. Sign canonical UTF-8 payload using Phase 3 Ed25519 engine.
   * 8. Verify signature matches active public key before persistence.
   * 9. Persist signed notice in database.
   * 10. Return safe SignedNoticeResponseDto (Zero private keys, Zero PII).
   */
  public async createAndSignNotice(
    dto: NoticeCreateDto,
    signingKeyOverride?: string
  ): Promise<SignedNoticeResponseDto> {
    // 1. Validate inputs
    const { normalizedTitle, normalizedIssuedAt, normalizedExpiresAt } = this.validateNoticeInput(dto);
    const targetInstId = dto.institutionId.trim();

    // 2. Validate institution authorization
    const institution = await this.registry.getInstitutionById(targetInstId);
    if (!institution) {
      throw new Error(`Cannot create notice: Institution with ID '${targetInstId}' does not exist`);
    }

    if (institution.status === 'SUSPENDED') {
      throw new Error(`Cannot create notice: Institution '${targetInstId}' is suspended`);
    }

    if (institution.status !== 'ACTIVE') {
      throw new Error(
        `Cannot create notice: Institution '${targetInstId}' status is '${institution.status}'. Only ACTIVE institutions may issue notices.`
      );
    }

    // 3. Resolve active trusted public key from Phase 4 registry
    const trustedKeyRecord = await this.registry.getActiveKeyByInstitution(targetInstId);
    if (!trustedKeyRecord) {
      throw new Error(
        `Cannot create notice: No active trusted Ed25519 public key found in registry for institution '${targetInstId}'`
      );
    }

    // 4. Resolve private signing key securely from server context
    const privateSigningKey = this.resolveSigningKey(targetInstId, signingKeyOverride);

    // 5. Construct canonical payload (Phase 2 standard)
    const canonicalPayload: NoticeCanonicalPayload = {
      institutionId: targetInstId,
      title: normalizedTitle,
      content: dto.content,
      issuedAt: normalizedIssuedAt,
      expiresAt: normalizedExpiresAt,
    };

    if (dto.noticeId && typeof dto.noticeId === 'string' && dto.noticeId.trim().length > 0) {
      canonicalPayload.noticeId = dto.noticeId.trim();
    }

    if (dto.metadata && typeof dto.metadata === 'object' && !Array.isArray(dto.metadata)) {
      canonicalPayload.metadata = dto.metadata;
    }

    // 6. Deterministically canonicalize and compute SHA-256 content hash (Phase 2)
    const canonicalString = canonicalizationService.canonicalizeNoticePayload(canonicalPayload);
    const contentHash = hashingService.sha256(canonicalString);

    // 7. Sign canonical payload using Ed25519 (Phase 3)
    let signature: string;
    try {
      signature = ed25519Service.sign(canonicalString, privateSigningKey);
    } catch {
      throw new Error('Cryptographic signing failed: Invalid private key material');
    }

    // 8. Cryptographic verification sanity check: Ensure signature verifies against registered public key
    const isSelfVerified = ed25519Service.verify(
      canonicalString,
      signature,
      trustedKeyRecord.publicKey
    );

    if (!isSelfVerified) {
      throw new Error(
        'Cryptographic integrity error: Generated signature does not verify against the institution’s registered public key'
      );
    }

    // 9. Persist signed notice in database
    const createdRecord = await this.db.notice.create({
      data: {
        ...(canonicalPayload.noticeId ? { id: canonicalPayload.noticeId } : {}),
        institutionId: targetInstId,
        title: normalizedTitle,
        contentHash,
        signature,
        issuedAt: new Date(normalizedIssuedAt),
        expiresAt: new Date(normalizedExpiresAt),
        status: 'ACTIVE',
      },
    });

    logger.info(
      `Notice created and signed: ${createdRecord.id} for institution ${targetInstId} (Content Hash: ${contentHash})`,
      'NoticeService'
    );

    // 10. Return safe response DTO (Strictly excluding private keys and PII)
    const response: SignedNoticeResponseDto = {
      id: createdRecord.id,
      noticeId: canonicalPayload.noticeId,
      institutionId: targetInstId,
      title: normalizedTitle,
      content: dto.content,
      issuedAt: normalizedIssuedAt,
      expiresAt: normalizedExpiresAt,
      metadata: canonicalPayload.metadata,
      contentHash,
      signature,
      signatureAlgorithm: 'Ed25519',
      status: createdRecord.status as NoticeStatus,
    };

    return response;
  }

  /**
   * Revokes an existing notice.
   */
  public async revokeNotice(noticeId: string, dto: NoticeRevokeDto): Promise<NoticeRecord> {
    if (!noticeId || typeof noticeId !== 'string') {
      throw new Error('Notice ID is required for revocation');
    }

    if (!dto || !dto.reason || typeof dto.reason !== 'string' || dto.reason.trim().length === 0) {
      throw new Error('Revocation reason is required');
    }

    const existing = await this.db.notice.findUnique({
      where: { id: noticeId.trim() },
    });

    if (!existing) {
      throw new Error(`Cannot revoke notice: Notice with ID '${noticeId}' not found`);
    }

    logger.info(`Revoking notice ${noticeId}, reason: ${dto.reason.trim()}`, 'NoticeService');

    const updated = await this.db.notice.update({
      where: { id: noticeId.trim() },
      data: {
        status: 'REVOKED',
        revocationReason: dto.reason.trim(),
        revokedAt: new Date(),
      },
    });

    return updated as unknown as NoticeRecord;
  }

  /**
   * Retrieves a notice by ID.
   */
  public async getNoticeById(id: string): Promise<NoticeRecord | null> {
    if (!id || typeof id !== 'string') {
      return null;
    }

    try {
      const record = await this.db.notice.findUnique({
        where: { id: id.trim() },
      });
      return record as unknown as NoticeRecord | null;
    } catch (error) {
      logger.error(`Error querying notice by ID: ${id}`, error, 'NoticeService');
      return null;
    }
  }
}

export const noticeService = new NoticeService();
