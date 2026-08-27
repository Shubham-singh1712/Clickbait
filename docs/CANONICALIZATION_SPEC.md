# CLICKBAIT — Cryptographic Canonicalization & SHA-256 Specification (Phase 2)

> **Document Version**: 1.0.0  
> **Status**: Production Ready  
> **Module**: `src/services/crypto/` (`canonicalization.service.ts`, `hashing.service.ts`)

---

## 1. Executive Summary

In **CLICKBAIT**, digital notices issued by authorized institutions are cryptographically signed using Ed25519. To ensure that digital signatures remain verifiable across disparate platforms (Node.js backend, mobile apps, student verification portals), the notice payload must undergo **deterministic canonicalization** before hashing with **SHA-256**.

```
[Raw Notice Data]
       │
       ▼
[Field Validation & Timestamp Normalization]
       │
       ▼
[Recursive Lexicographical Key Sorting] ──> [Minimal Whitespace UTF-8 String]
                                                     │
                                                     ▼
                                            [SHA-256 Content Hash]
                                            (64-character lowercase hex)
                                                     │
                                                     ▼
                                            [Phase 3: Ed25519 Signing]
```

---

## 2. Canonical Notice Payload Definition

The canonical notice payload contains only the authenticable, immutable content of an official circular.

### Included Fields (`NoticeCanonicalPayload`)

| Field | Type | Description | Required | Example |
|---|---|---|---|---|
| `noticeId` | `string` | Unique notice UUID (if pre-allocated) | Optional | `"9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"` |
| `institutionId` | `string` | Authorized issuing institution identifier | **Required** | `"inst-univ-delhi-01"` |
| `title` | `string` | Official circular/notice title | **Required** | `"End Semester Examination Schedule 2026"` |
| `content` | `string` | Full textual notice body | **Required** | `"Examinations commence on May 15, 2026..."` |
| `issuedAt` | `string` | Normalized ISO 8601 UTC issuance timestamp | **Required** | `"2026-04-01T10:00:00.000Z"` |
| `expiresAt` | `string` | Normalized ISO 8601 UTC expiration timestamp | **Required** | `"2026-06-30T23:59:59.000Z"` |
| `metadata` | `object` | Optional structured circular metadata | Optional | `{"department":"Exams","semester":6}` |

### Strictly Excluded Fields

The following fields are **never** included in the canonical payload:
- **Cryptographic Outputs**: `signature`, `contentHash`.
- **Database Lifecycle Audit Fields**: `createdAt`, `updatedAt`, `revocationReason`, `revokedAt`.
- **Student Data & PII**: Student names, roll numbers, query sessions, IP addresses, screenshots.
- **Security & AI Scores**: Anomaly flags, OCR outputs, secondary AI confidence scores.
- **Sensitive Credentials**: Private keys, JWT tokens, database passwords.

---

## 3. Canonicalization Rules & Algorithm

The canonicalizer follows RFC 8785 (JSON Canonicalization Scheme - JCS) deterministic serialization principles:

1. **Object Key Sorting**:  
   Object keys are recursively sorted lexicographically by **UTF-16 code units** (standard JavaScript sorting order `Array.prototype.sort()`).
2. **Array Order Preservation**:  
   Arrays are treated as ordered data sequences. Array element positions are strictly preserved and recursively canonicalized without sorting.
3. **Whitespace Elimination**:  
   Zero whitespace characters (spaces, tabs, newlines) are output outside string literals. Objects serialize as `{"key":val}` and arrays as `[elem1,elem2]`.
4. **Primitive Types**:
   - **Strings**: Encoded using standard JSON escaping rules (`"`, `\`, control chars `\u0000` to `\u001f`) over UTF-8.
   - **Numbers**: Standard IEEE 754 decimal format without exponents for integers. `-0` is normalized to `0`. Non-finite numbers (`NaN`, `Infinity`, `-Infinity`) throw an error.
   - **Booleans**: Literal `true` or `false`.
   - **Null**: Literal `null`.
   - **Undefined**: Omitted from object serialization; converted to `null` inside array elements.
5. **Timestamp Normalization**:  
   Date objects, numeric milliseconds, or timestamp strings are parsed and formatted into standard ISO 8601 UTC (`YYYY-MM-DDTHH:mm:ss.sssZ`).
6. **UTF-8 Encoding**:  
   All characters are encoded in UTF-8 before passing to the SHA-256 digest engine.

---

## 4. SHA-256 Content Hash Specification

- **Algorithm**: SHA-256 (`crypto.createHash('sha256')`).
- **Input**: UTF-8 encoded canonical JSON string.
- **Output Format**: **64-character lowercase hexadecimal string** matching `/^[a-f0-9]{64}$/`.
- **Timing-Safe Verification**: Hash comparison utilizes `crypto.timingSafeEqual()` on 32-byte buffers to eliminate side-channel timing vulnerabilities.

### Known Test Vectors

- `SHA-256("")` = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `SHA-256("The quick brown fox jumps over the lazy dog")` = `d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592`

---

## 5. Phase 3 Interface Readiness

In **Phase 3 (Ed25519 Signing and Verification)**:
1. An institution signs the UTF-8 buffer of the canonical string (or raw SHA-256 digest) using their institutional Ed25519 private key.
2. The resulting signature and `contentHash` are stored alongside the notice.
3. Students and client verifiers reconstruct the canonical payload from the claimed notice, recompute the SHA-256 content hash, and verify the Ed25519 signature against the institution's public key from the trusted registry.
