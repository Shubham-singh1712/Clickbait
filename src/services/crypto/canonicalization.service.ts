import { NoticeCanonicalPayload } from '../../types';

/**
 * Service interface for Deterministic JSON Canonicalization.
 *
 * SPECIFICATION & RULES:
 * 1. Deterministic Key Ordering: Object properties are recursively sorted lexicographically by UTF-16 code units (ASCII/Unicode).
 * 2. Array Order Preservation: Array element positions are strictly preserved (never sorted or altered).
 * 3. Minimal Whitespace: No whitespace characters (spaces, tabs, newlines) are introduced outside string literals.
 * 4. Primitive Value Encoding:
 *    - Strings: Valid UTF-8 strings formatted with standard JSON escaping.
 *    - Numbers: Standard IEEE 754 decimal representation; -0 normalized to 0; non-finite numbers (NaN/Infinity) are rejected.
 *    - Booleans: 'true' or 'false'.
 *    - Null: 'null'.
 *    - Undefined: Excluded from object serialization.
 * 5. Timestamp Normalization: Date objects and timestamp strings are normalized to ISO 8601 UTC (YYYY-MM-DDTHH:mm:ss.sssZ).
 * 6. Scope Exclusion: Volatile fields (signatures, hashes, database internal audit timestamps, AI risk metrics, PII) are strictly excluded.
 */
export interface ICanonicalizationService {
  canonicalize(value: unknown): string;
  canonicalizeNoticePayload(payload: NoticeCanonicalPayload): string;
  normalizeTimestamp(timestamp: string | Date | number): string;
  buildCanonicalNoticePayload(input: NoticeCanonicalPayload): NoticeCanonicalPayload;
}

export class CanonicalizationService implements ICanonicalizationService {
  /**
   * Normalizes any valid timestamp input into a strict, canonical ISO 8601 UTC string.
   * e.g., "2026-03-31T23:59:59.000Z"
   */
  public normalizeTimestamp(timestamp: string | Date | number): string {
    if (timestamp instanceof Date) {
      if (isNaN(timestamp.getTime())) {
        throw new Error('Invalid Date object provided for timestamp normalization');
      }
      return timestamp.toISOString();
    }

    if (typeof timestamp === 'number') {
      const date = new Date(timestamp);
      if (isNaN(date.getTime())) {
        throw new Error(`Invalid numeric timestamp: ${timestamp}`);
      }
      return date.toISOString();
    }

    if (typeof timestamp === 'string') {
      const parsed = new Date(timestamp);
      if (isNaN(parsed.getTime())) {
        throw new Error(`Invalid date string provided for timestamp normalization: "${timestamp}"`);
      }
      return parsed.toISOString();
    }

    throw new Error(`Unsupported timestamp type: ${typeof timestamp}`);
  }

  /**
   * Constructs a cleaned, normalized NoticeCanonicalPayload containing only authenticatable notice fields.
   * Explicitly drops any accidental volatile properties, client PII, or internal tokens.
   */
  public buildCanonicalNoticePayload(input: NoticeCanonicalPayload): NoticeCanonicalPayload {
    if (!input || typeof input !== 'object') {
      throw new Error('Notice canonical payload must be a non-null object');
    }

    if (!input.institutionId || typeof input.institutionId !== 'string') {
      throw new Error('Canonical payload requires a non-empty "institutionId" string');
    }

    if (!input.title || typeof input.title !== 'string') {
      throw new Error('Canonical payload requires a non-empty "title" string');
    }

    if (typeof input.content !== 'string') {
      throw new Error('Canonical payload requires a "content" string');
    }

    if (!input.issuedAt) {
      throw new Error('Canonical payload requires an "issuedAt" timestamp');
    }

    if (!input.expiresAt) {
      throw new Error('Canonical payload requires an "expiresAt" timestamp');
    }

    const payload: NoticeCanonicalPayload = {
      institutionId: input.institutionId.trim(),
      title: input.title.trim(),
      content: input.content,
      issuedAt: this.normalizeTimestamp(input.issuedAt),
      expiresAt: this.normalizeTimestamp(input.expiresAt),
    };

    if (input.noticeId && typeof input.noticeId === 'string' && input.noticeId.trim().length > 0) {
      payload.noticeId = input.noticeId.trim();
    }

    if (input.metadata && typeof input.metadata === 'object' && !Array.isArray(input.metadata)) {
      payload.metadata = input.metadata;
    }

    return payload;
  }

  /**
   * Deterministically serializes a NoticeCanonicalPayload after normalizing timestamps and fields.
   */
  public canonicalizeNoticePayload(payload: NoticeCanonicalPayload): string {
    const normalized = this.buildCanonicalNoticePayload(payload);
    return this.canonicalize(normalized);
  }

  /**
   * Deterministically canonicalizes any JSON-compatible value.
   * Recursively sorts object keys lexicographically, preserves array order, and outputs zero-whitespace JSON.
   */
  public canonicalize(value: unknown): string {
    return this.serializeValue(value);
  }

  private serializeValue(value: unknown): string {
    if (value === null) {
      return 'null';
    }

    if (value === undefined) {
      return '';
    }

    const type = typeof value;

    if (type === 'boolean') {
      return value ? 'true' : 'false';
    }

    if (type === 'number') {
      if (!Number.isFinite(value)) {
        throw new Error(`Cannot canonicalize non-finite number: ${value}`);
      }
      // Normalize -0 to 0
      return Object.is(value, -0) ? '0' : JSON.stringify(value);
    }

    if (type === 'string') {
      return JSON.stringify(value);
    }

    if (value instanceof Date) {
      return JSON.stringify(this.normalizeTimestamp(value));
    }

    if (Array.isArray(value)) {
      const elements: string[] = [];
      for (let i = 0; i < value.length; i++) {
        const item = value[i];
        if (item === undefined || typeof item === 'function' || typeof item === 'symbol') {
          elements.push('null');
        } else {
          elements.push(this.serializeValue(item));
        }
      }
      return `[${elements.join(',')}]`;
    }

    if (type === 'object') {
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort(); // Lexicographical sort by UTF-16 code units
      const entries: string[] = [];

      for (const key of keys) {
        const val = obj[key];
        // Skip undefined values, functions, and symbols from serialized object output
        if (val !== undefined && typeof val !== 'function' && typeof val !== 'symbol') {
          const serializedKey = JSON.stringify(key);
          const serializedVal = this.serializeValue(val);
          entries.push(`${serializedKey}:${serializedVal}`);
        }
      }

      return `{${entries.join(',')}}`;
    }

    throw new Error(`Unsupported value type encountered during canonicalization: ${type}`);
  }
}

export const canonicalizationService = new CanonicalizationService();
