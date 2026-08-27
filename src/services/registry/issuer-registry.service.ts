import { PrismaClient } from '@prisma/client';
import {
  IssuerKeyRecord,
  InstitutionRecord,
  InstitutionCreateDto,
  InstitutionStatus,
} from '../../types';
import { prisma as defaultPrisma } from '../../config/database';
import { ed25519Service, ED25519_PUBLIC_KEY_BYTE_LENGTH } from '../crypto/ed25519.service';
import { logger } from '../../utils/logger';

/**
 * Service interface for the Trusted Issuer Public-Key Registry.
 *
 * CORE SECURITY MANDATE:
 * - Public keys registered must be strictly valid 32-byte Ed25519 raw public keys in Base64 format.
 * - Private keys are NEVER stored, accepted, or returned.
 * - Keys must be associated with valid, active authorized institutions.
 * - Revoked, expired, inactive, or unassociated keys must NEVER be returned as trusted verification sources.
 */
export interface IIssuerRegistryService {
  registerInstitution(dto: InstitutionCreateDto): Promise<InstitutionRecord>;
  getInstitutionById(institutionId: string): Promise<InstitutionRecord | null>;
  getInstitutionByDomain(domain: string): Promise<InstitutionRecord | null>;
  registerKey(institutionId: string, publicKeyBase64: string, expiresAt: Date | string): Promise<IssuerKeyRecord>;
  registerTrustedKey(institutionId: string, publicKeyBase64: string, expiresAt: Date | string): Promise<IssuerKeyRecord>;
  getActiveKeyByInstitution(institutionId: string): Promise<IssuerKeyRecord | null>;
  getTrustedPublicKey(institutionId: string): Promise<IssuerKeyRecord | null>;
  getKeyByPublicKey(publicKeyBase64: string): Promise<IssuerKeyRecord | null>;
  isKeyTrusted(institutionId: string, publicKeyBase64: string): Promise<boolean>;
  revokeKey(keyId: string, reason?: string): Promise<IssuerKeyRecord>;
  revokeKeyByPublicKey(institutionId: string, publicKeyBase64: string, reason?: string): Promise<IssuerKeyRecord>;
}

export class IssuerRegistryService implements IIssuerRegistryService {
  private db: PrismaClient;

  constructor(customPrisma?: PrismaClient) {
    this.db = customPrisma || defaultPrisma;
  }

  /**
   * Registers a new authorized institution in the registry.
   */
  public async registerInstitution(dto: InstitutionCreateDto): Promise<InstitutionRecord> {
    if (!dto.name || typeof dto.name !== 'string' || dto.name.trim().length === 0) {
      throw new Error('Institution name is required');
    }

    if (!dto.verifiedDomain || typeof dto.verifiedDomain !== 'string' || dto.verifiedDomain.trim().length === 0) {
      throw new Error('Institution verifiedDomain is required');
    }

    const domain = dto.verifiedDomain.trim().toLowerCase();

    // Check if institution with same domain already exists
    const existing = await this.db.institution.findUnique({
      where: { verifiedDomain: domain },
    });

    if (existing) {
      throw new Error(`Institution with domain '${domain}' is already registered`);
    }

    const institution = await this.db.institution.create({
      data: {
        name: dto.name.trim(),
        verifiedDomain: domain,
        status: (dto.status as InstitutionStatus) || 'PENDING',
      },
    });

    logger.info(`Institution registered: ${institution.id} (${institution.name})`, 'IssuerRegistry');
    return institution;
  }

  /**
   * Retrieves an institution by unique ID.
   */
  public async getInstitutionById(institutionId: string): Promise<InstitutionRecord | null> {
    if (!institutionId || typeof institutionId !== 'string') {
      return null;
    }

    try {
      return await this.db.institution.findUnique({
        where: { id: institutionId.trim() },
      });
    } catch (error) {
      logger.error(`Error querying institution by ID: ${institutionId}`, error, 'IssuerRegistry');
      return null;
    }
  }

  /**
   * Retrieves an institution by verified domain.
   */
  public async getInstitutionByDomain(domain: string): Promise<InstitutionRecord | null> {
    if (!domain || typeof domain !== 'string') {
      return null;
    }

    try {
      return await this.db.institution.findUnique({
        where: { verifiedDomain: domain.trim().toLowerCase() },
      });
    } catch (error) {
      logger.error(`Error querying institution by domain: ${domain}`, error, 'IssuerRegistry');
      return null;
    }
  }

  /**
   * Normalizes and validates an Ed25519 Base64 public key.
   * Throws detailed error if format, encoding, or length is invalid.
   */
  private validateAndStandardizePublicKey(publicKeyBase64: string): string {
    if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
      throw new Error('Public key must be a non-empty Base64-encoded string');
    }

    const standardized = publicKeyBase64.trim();

    // Guard against private key material injection (SPKI / PKCS#8 / PEM / raw 64-byte private keys)
    if (
      standardized.includes('PRIVATE KEY') ||
      standardized.includes('BEGIN ED25519 PRIVATE KEY') ||
      standardized.includes('BEGIN EC PRIVATE KEY')
    ) {
      throw new Error('Invalid public key: private key material must never be submitted to the registry');
    }

    // Format validation using Phase 3 Ed25519 standard
    if (!ed25519Service.validatePublicKey(standardized)) {
      // Check specific failure conditions for precise diagnostics
      const buffer = Buffer.from(standardized, 'base64');
      if (buffer.length !== ED25519_PUBLIC_KEY_BYTE_LENGTH) {
        throw new Error(
          `Invalid Ed25519 public key length: expected exactly ${ED25519_PUBLIC_KEY_BYTE_LENGTH} decoded bytes, received ${buffer.length} bytes`
        );
      }
      throw new Error('Invalid Ed25519 public key: malformed Base64 representation or invalid curve encoding');
    }

    return standardized;
  }

  /**
   * Registers a trusted Ed25519 public key for an institution.
   *
   * Validates:
   * 1. Target institution exists and is not suspended.
   * 2. Public key conforms strictly to raw 32-byte Ed25519 Base64 format.
   * 3. Expiration date is a valid future timestamp.
   * 4. Safe duplicate / conflict handling.
   */
  public async registerKey(
    institutionId: string,
    publicKeyBase64: string,
    expiresAt: Date | string
  ): Promise<IssuerKeyRecord> {
    if (!institutionId || typeof institutionId !== 'string' || institutionId.trim().length === 0) {
      throw new Error('Valid institutionId is required for key registration');
    }

    const targetInstId = institutionId.trim();

    // 1. Validate & standardize public key first (fails fast on malformed inputs)
    const standardizedKey = this.validateAndStandardizePublicKey(publicKeyBase64);

    // 2. Validate expiration date
    const expiryDate = expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
    if (isNaN(expiryDate.getTime())) {
      throw new Error('Invalid expiration date provided');
    }

    if (expiryDate.getTime() <= Date.now()) {
      throw new Error('Key expiration date must be in the future');
    }

    // 3. Verify institution exists
    const institution = await this.db.institution.findUnique({
      where: { id: targetInstId },
    });

    if (!institution) {
      throw new Error(`Cannot register key: Institution with ID '${targetInstId}' does not exist`);
    }

    if (institution.status === 'SUSPENDED') {
      throw new Error(`Cannot register key: Institution '${targetInstId}' is currently suspended`);
    }

    // 4. Duplicate & Conflict Detection
    const existingKey = await this.db.issuerKey.findUnique({
      where: { publicKey: standardizedKey },
    });

    if (existingKey) {
      if (existingKey.institutionId !== targetInstId) {
        throw new Error(
          `Conflicting registration: Public key is already associated with another institution (${existingKey.institutionId})`
        );
      }

      if (existingKey.keyStatus === 'ACTIVE' && existingKey.expiresAt.getTime() > Date.now()) {
        throw new Error('Duplicate registration: Public key is already active for this institution');
      }

      if (existingKey.keyStatus === 'REVOKED') {
        throw new Error('Security policy violation: A revoked public key cannot be re-registered');
      }

      // If expired, update/renew key record with new expiration date
      if (existingKey.keyStatus === 'EXPIRED' || existingKey.expiresAt.getTime() <= Date.now()) {
        return await this.db.issuerKey.update({
          where: { id: existingKey.id },
          data: {
            keyStatus: 'ACTIVE',
            expiresAt: expiryDate,
            revokedAt: null,
          },
        });
      }
    }

    // 5. Persist trusted public key record
    const createdKey = await this.db.issuerKey.create({
      data: {
        institutionId: targetInstId,
        publicKey: standardizedKey,
        expiresAt: expiryDate,
        keyStatus: 'ACTIVE',
      },
    });

    logger.info(
      `Trusted Ed25519 public key registered for institution ${targetInstId} (Key ID: ${createdKey.id})`,
      'IssuerRegistry'
    );

    return createdKey;
  }

  /**
   * Alias for registerKey to provide explicit semantic naming.
   */
  public async registerTrustedKey(
    institutionId: string,
    publicKeyBase64: string,
    expiresAt: Date | string
  ): Promise<IssuerKeyRecord> {
    return this.registerKey(institutionId, publicKeyBase64, expiresAt);
  }

  /**
   * Retrieves the currently active, unexpired, unrevoked public key for an authorized institution.
   *
   * SECURITY CHECKS:
   * - Institution must exist and have ACTIVE status.
   * - Key must have ACTIVE keyStatus.
   * - Key must not be revoked (revokedAt must be null).
   * - Key must not be expired (expiresAt > now).
   * - Key format must pass Ed25519 32-byte cryptographic validation.
   */
  public async getActiveKeyByInstitution(institutionId: string): Promise<IssuerKeyRecord | null> {
    if (!institutionId || typeof institutionId !== 'string') {
      return null;
    }

    const targetInstId = institutionId.trim();

    try {
      // 1. Verify institution status
      const institution = await this.db.institution.findUnique({
        where: { id: targetInstId },
      });

      if (!institution || institution.status !== 'ACTIVE') {
        return null;
      }

      const now = new Date();

      // 2. Query for active, unexpired key for this institution
      const record = await this.db.issuerKey.findFirst({
        where: {
          institutionId: targetInstId,
          keyStatus: 'ACTIVE',
          expiresAt: { gt: now },
          revokedAt: null,
        },
        orderBy: { createdAt: 'desc' },
      });

      if (!record) {
        return null;
      }

      // 3. Verify cryptographic integrity of the retrieved key format
      if (!ed25519Service.validatePublicKey(record.publicKey)) {
        logger.error(
          `Corrupted public key format encountered in database for key ${record.id}`,
          undefined,
          'IssuerRegistry'
        );
        return null;
      }

      return record;
    } catch (error) {
      logger.error(`Error querying active key for institution ${targetInstId}`, error, 'IssuerRegistry');
      return null;
    }
  }

  /**
   * Semantic alias for getActiveKeyByInstitution.
   */
  public async getTrustedPublicKey(institutionId: string): Promise<IssuerKeyRecord | null> {
    return this.getActiveKeyByInstitution(institutionId);
  }

  /**
   * Looks up a registered public key record by its Base64 value.
   */
  public async getKeyByPublicKey(publicKeyBase64: string): Promise<IssuerKeyRecord | null> {
    if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
      return null;
    }

    const standardized = publicKeyBase64.trim();

    try {
      return await this.db.issuerKey.findUnique({
        where: { publicKey: standardized },
      });
    } catch (error) {
      logger.error('Error querying issuer key by public key string', error, 'IssuerRegistry');
      return null;
    }
  }

  /**
   * Validates whether a given public key is currently trusted and active for a specific institution.
   *
   * Rejection criteria:
   * - Institution does not exist or is not ACTIVE
   * - Key does not exist in registry
   * - Key does not belong to the specified institution (Association Protection)
   * - Key status is REVOKED
   * - Key status is EXPIRED or current time >= expiresAt
   * - Key format is malformed or invalid Ed25519
   */
  public async isKeyTrusted(institutionId: string, publicKeyBase64: string): Promise<boolean> {
    if (
      !institutionId ||
      typeof institutionId !== 'string' ||
      !publicKeyBase64 ||
      typeof publicKeyBase64 !== 'string'
    ) {
      return false;
    }

    const targetInstId = institutionId.trim();
    const standardizedKey = publicKeyBase64.trim();

    // 1. Validate public key format first
    if (!ed25519Service.validatePublicKey(standardizedKey)) {
      return false;
    }

    try {
      // 2. Check institution status
      const institution = await this.db.institution.findUnique({
        where: { id: targetInstId },
      });

      if (!institution || institution.status !== 'ACTIVE') {
        return false;
      }

      // 3. Find key record
      const keyRecord = await this.db.issuerKey.findUnique({
        where: { publicKey: standardizedKey },
      });

      if (!keyRecord) {
        return false;
      }

      // 4. Strict Association Check: Key must belong to target institution
      if (keyRecord.institutionId !== targetInstId) {
        logger.warn(
          `Security violation: Key ${keyRecord.id} belongs to institution ${keyRecord.institutionId}, not ${targetInstId}`,
          'IssuerRegistry'
        );
        return false;
      }

      // 5. Key Status Check (Must be ACTIVE, not REVOKED)
      if (keyRecord.keyStatus !== 'ACTIVE' || keyRecord.revokedAt !== null) {
        return false;
      }

      // 6. Expiration Check
      if (keyRecord.expiresAt.getTime() <= Date.now()) {
        return false;
      }

      return true;
    } catch (error) {
      logger.error(`Error during isKeyTrusted check for ${targetInstId}`, error, 'IssuerRegistry');
      return false;
    }
  }

  /**
   * Revokes an existing issuer key by its primary key ID.
   */
  public async revokeKey(keyId: string, reason?: string): Promise<IssuerKeyRecord> {
    if (!keyId || typeof keyId !== 'string') {
      throw new Error('Key ID is required for revocation');
    }

    const existing = await this.db.issuerKey.findUnique({
      where: { id: keyId.trim() },
    });

    if (!existing) {
      throw new Error(`Cannot revoke key: Key with ID '${keyId}' not found`);
    }

    const updated = await this.db.issuerKey.update({
      where: { id: keyId.trim() },
      data: {
        keyStatus: 'REVOKED',
        revokedAt: new Date(),
      },
    });

    logger.info(
      `Issuer key ${keyId} revoked for institution ${existing.institutionId}. Reason: ${reason || 'Not specified'}`,
      'IssuerRegistry'
    );

    return updated;
  }

  /**
   * Revokes an existing issuer key by its public key string and institution association.
   */
  public async revokeKeyByPublicKey(
    institutionId: string,
    publicKeyBase64: string,
    reason?: string
  ): Promise<IssuerKeyRecord> {
    if (!institutionId || !publicKeyBase64) {
      throw new Error('institutionId and publicKeyBase64 are required for revocation');
    }

    const targetInstId = institutionId.trim();
    const standardizedKey = publicKeyBase64.trim();

    const existing = await this.db.issuerKey.findUnique({
      where: { publicKey: standardizedKey },
    });

    if (!existing) {
      throw new Error('Cannot revoke key: Public key not found in registry');
    }

    if (existing.institutionId !== targetInstId) {
      throw new Error('Cannot revoke key: Public key is not associated with the specified institution');
    }

    return this.revokeKey(existing.id, reason);
  }
}

export const issuerRegistryService = new IssuerRegistryService();
