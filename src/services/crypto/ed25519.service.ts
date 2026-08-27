import crypto from 'crypto';
import { canonicalizationService } from './canonicalization.service';
import { NoticeCanonicalPayload } from '../../types';

// Standard ASN.1 DER Header Constants for Ed25519 (RFC 8410 / RFC 8411)
// SPKI Header: 30 2a 30 05 06 03 2b 65 70 03 21 00 (12 bytes) + 32 raw bytes = 44 bytes
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// PKCS#8 Header: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 (16 bytes) + 32 raw seed bytes = 48 bytes
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export const ED25519_PUBLIC_KEY_BYTE_LENGTH = 32;
export const ED25519_SIGNATURE_BYTE_LENGTH = 64;

/**
 * Service interface for Ed25519 Cryptographic Signatures & Verification.
 */
export interface IEd25519Service {
  generateKeyPair(): { publicKeyBase64: string; privateKeyBase64: string };
  signNoticePayload(payload: NoticeCanonicalPayload, privateKey: string | Buffer | crypto.KeyObject): string;
  sign(data: string | Buffer, privateKey: string | Buffer | crypto.KeyObject): string;
  verifyNoticePayload(payload: NoticeCanonicalPayload, signatureBase64: string, publicKeyBase64: string): boolean;
  verify(data: string | Buffer, signatureBase64: string, publicKeyBase64: string): boolean;
  validatePublicKey(publicKeyBase64: string): boolean;
  validateSignature(signatureBase64: string): boolean;
}

export class Ed25519Service implements IEd25519Service {
  /**
   * Generates a fresh Ed25519 keypair for development, testing, or institutional onboarding fixtures.
   * Returns Base64-encoded raw 32-byte public key and Base64-encoded raw 32-byte private seed.
   */
  public generateKeyPair(): { publicKeyBase64: string; privateKeyBase64: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

    // Extract raw 32-byte public key from SPKI DER (strip 12-byte prefix)
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const rawPublicKey = spkiDer.subarray(12);

    // Extract raw 32-byte private seed from PKCS#8 DER (strip 16-byte prefix)
    const pkcs8Der = privateKey.export({ type: 'pkcs8', format: 'der' });
    const rawPrivateKey = pkcs8Der.subarray(16);

    return {
      publicKeyBase64: rawPublicKey.toString('base64'),
      privateKeyBase64: rawPrivateKey.toString('base64'),
    };
  }

  /**
   * Validates whether a given string is a valid Base64-encoded raw 32-byte Ed25519 public key.
   */
  public validatePublicKey(publicKeyBase64: string): boolean {
    if (!publicKeyBase64 || typeof publicKeyBase64 !== 'string') {
      return false;
    }

    const trimmed = publicKeyBase64.trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
      return false;
    }

    try {
      const buffer = Buffer.from(trimmed, 'base64');
      // Verify round-trip encoding to catch invalid padding or corrupted base64
      if (buffer.toString('base64') !== trimmed && buffer.toString('base64') !== trimmed.replace(/=+$/, '')) {
        // Base64 padding check
        if (buffer.toString('base64').replace(/=+$/, '') !== trimmed.replace(/=+$/, '')) {
          return false;
        }
      }
      return buffer.length === ED25519_PUBLIC_KEY_BYTE_LENGTH;
    } catch {
      return false;
    }
  }

  /**
   * Validates whether a given string is a valid Base64-encoded raw 64-byte Ed25519 signature.
   */
  public validateSignature(signatureBase64: string): boolean {
    if (!signatureBase64 || typeof signatureBase64 !== 'string') {
      return false;
    }

    const trimmed = signatureBase64.trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
      return false;
    }

    try {
      const buffer = Buffer.from(trimmed, 'base64');
      if (buffer.toString('base64').replace(/=+$/, '') !== trimmed.replace(/=+$/, '')) {
        return false;
      }
      return buffer.length === ED25519_SIGNATURE_BYTE_LENGTH;
    } catch {
      return false;
    }
  }

  /**
   * Imports a raw 32-byte (Base64/Buffer) or SPKI PEM/DER public key into a Node.js KeyObject.
   */
  private importPublicKey(publicKey: string | Buffer | crypto.KeyObject): crypto.KeyObject {
    if (typeof publicKey === 'object' && 'type' in publicKey && publicKey.type === 'public') {
      return publicKey as crypto.KeyObject;
    }

    if (Buffer.isBuffer(publicKey)) {
      if (publicKey.length === ED25519_PUBLIC_KEY_BYTE_LENGTH) {
        return crypto.createPublicKey({
          key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
          format: 'der',
          type: 'spki',
        });
      }
      return crypto.createPublicKey(publicKey);
    }

    if (typeof publicKey === 'string') {
      const trimmed = publicKey.trim();

      // Check if PEM format
      if (trimmed.includes('-----BEGIN PUBLIC KEY-----')) {
        return crypto.createPublicKey(trimmed);
      }

      // Treat as Base64 raw public key
      const decoded = Buffer.from(trimmed, 'base64');
      if (decoded.length === ED25519_PUBLIC_KEY_BYTE_LENGTH) {
        return crypto.createPublicKey({
          key: Buffer.concat([ED25519_SPKI_PREFIX, decoded]),
          format: 'der',
          type: 'spki',
        });
      }

      // If already SPKI DER in base64 (44 bytes)
      if (decoded.length === 44 && decoded.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) {
        return crypto.createPublicKey({
          key: decoded,
          format: 'der',
          type: 'spki',
        });
      }
    }

    throw new Error('Invalid Ed25519 public key format (expected raw 32-byte Base64 or SPKI PEM/DER)');
  }

  /**
   * Imports a raw 32-byte seed (Base64/Buffer) or PKCS#8 PEM/DER private key into a Node.js KeyObject.
   * NOTE: Error messages intentionally omit key material for security.
   */
  private importPrivateKey(privateKey: string | Buffer | crypto.KeyObject): crypto.KeyObject {
    if (typeof privateKey === 'object' && 'type' in privateKey && privateKey.type === 'private') {
      return privateKey as crypto.KeyObject;
    }

    if (Buffer.isBuffer(privateKey)) {
      if (privateKey.length === 32) {
        return crypto.createPrivateKey({
          key: Buffer.concat([ED25519_PKCS8_PREFIX, privateKey]),
          format: 'der',
          type: 'pkcs8',
        });
      }
      return crypto.createPrivateKey(privateKey);
    }

    if (typeof privateKey === 'string') {
      const trimmed = privateKey.trim();

      // Check if PEM format
      if (trimmed.includes('-----BEGIN PRIVATE KEY-----') || trimmed.includes('-----BEGIN ED25519 PRIVATE KEY-----')) {
        return crypto.createPrivateKey(trimmed);
      }

      // Treat as Base64 raw private key seed (32 bytes)
      const decoded = Buffer.from(trimmed, 'base64');
      if (decoded.length === 32) {
        return crypto.createPrivateKey({
          key: Buffer.concat([ED25519_PKCS8_PREFIX, decoded]),
          format: 'der',
          type: 'pkcs8',
        });
      }

      // If already PKCS#8 DER in base64 (48 bytes)
      if (decoded.length === 48 && decoded.subarray(0, 16).equals(ED25519_PKCS8_PREFIX)) {
        return crypto.createPrivateKey({
          key: decoded,
          format: 'der',
          type: 'pkcs8',
        });
      }
    }

    throw new Error('Invalid Ed25519 private key format (expected raw 32-byte Base64 or PKCS#8 PEM/DER)');
  }

  /**
   * Canonicalizes a notice payload using Phase 2 rules and signs the UTF-8 buffer.
   * Returns a Base64-encoded 64-byte Ed25519 signature.
   */
  public signNoticePayload(
    payload: NoticeCanonicalPayload,
    privateKey: string | Buffer | crypto.KeyObject
  ): string {
    const canonicalString = canonicalizationService.canonicalizeNoticePayload(payload);
    return this.sign(canonicalString, privateKey);
  }

  /**
   * Signs raw data (string or Buffer) using an Ed25519 private key.
   * Returns Base64-encoded 64-byte signature.
   */
  public sign(
    data: string | Buffer,
    privateKey: string | Buffer | crypto.KeyObject
  ): string {
    try {
      const keyObject = this.importPrivateKey(privateKey);
      const bufferData = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf-8');
      const signature = crypto.sign(null, bufferData, keyObject);
      return signature.toString('base64');
    } catch (error) {
      if (error instanceof Error && error.message.includes('Invalid Ed25519 private key')) {
        throw error;
      }
      throw new Error('Failed to generate Ed25519 digital signature: invalid signing key or payload');
    }
  }

  /**
   * Verifies an Ed25519 signature against a canonical notice payload.
   * Canonicalizes the payload using Phase 2 rules before verification.
   */
  public verifyNoticePayload(
    payload: NoticeCanonicalPayload,
    signatureBase64: string,
    publicKeyBase64: string
  ): boolean {
    try {
      const canonicalString = canonicalizationService.canonicalizeNoticePayload(payload);
      return this.verify(canonicalString, signatureBase64, publicKeyBase64);
    } catch {
      return false;
    }
  }

  /**
   * Verifies an Ed25519 signature against raw data using a Base64-encoded raw 32-byte public key.
   * Safely returns false on any formatting or cryptographic error.
   */
  public verify(
    data: string | Buffer,
    signatureBase64: string,
    publicKeyBase64: string
  ): boolean {
    try {
      if (!this.validatePublicKey(publicKeyBase64)) {
        return false;
      }

      if (!this.validateSignature(signatureBase64)) {
        return false;
      }

      const keyObject = this.importPublicKey(publicKeyBase64);
      const signatureBuffer = Buffer.from(signatureBase64.trim(), 'base64');
      const bufferData = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf-8');

      return crypto.verify(null, bufferData, keyObject, signatureBuffer);
    } catch {
      return false;
    }
  }
}

export const ed25519Service = new Ed25519Service();
