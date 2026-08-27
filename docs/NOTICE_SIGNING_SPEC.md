# CLICKBAIT — Notice Creation & Cryptographic Signing Specification (Phase 5)

> **Document Version**: 1.0.0  
> **Status**: Production Ready  
> **Module**: `src/services/notice/notice.service.ts`  
> **Audience**: Backend Engineers (Member 3), Cryptography & Security Architects, Institution Signing Portal (Member 5), Verification Engine (Member 4)

---

## 1. Executive Summary & Purpose

In **CLICKBAIT**, official circulars and digital notices must be provably authentic and immune to unauthorized forgery or tampering.

**Phase 5** implements the end-to-end **Notice Creation & Cryptographic Signing Workflow**. When an authorized institution issues a notice, the system validates the institution's authorization against the Phase 4 Trusted Issuer Registry, constructs a deterministic canonical payload (Phase 2), computes a SHA-256 content hash (Phase 2), signs the payload using the institution's Ed25519 private signing key (Phase 3), and persists the signed notice with its cryptographic verification metadata.

---

## 2. Core Signing Architecture & Pipeline

```
=============================================================================
                     NOTICE CREATION & SIGNING PIPELINE
=============================================================================

                  [ Authorized Institution Request ]
            (institutionId, title, content, expiresAt, metadata)
                                  │
                                  ▼
                     [ Input Validation Layer ]
         (Non-empty fields, max lengths, timestamp validity,
                       expiresAt > issuedAt)
                                  │
                                  ▼
                 [ Institution Authorization Check ]
         (Query Phase 4 Registry: Institution exists & ACTIVE)
                                  │
                                  ▼
                [ Active Trusted Public Key Lookup ]
       (Phase 4: getActiveKeyByInstitution -> Valid, Unrevoked)
                                  │
                                  ▼
               [ Secure Private Key Resolution (Vault) ]
         (Server-side secure key store / HSM fixture context)
                                  │
                                  ▼
              [ Construct NoticeCanonicalPayload (Phase 2) ]
              - institutionId: String
              - title: String (Trimmed)
              - content: String
              - issuedAt: ISO 8601 UTC Normalized
              - expiresAt: ISO 8601 UTC Normalized
              - metadata: Object (Optional)
                                  │
                                  ▼
               [ Deterministic JSON Canonicalization ]
                 canonicalizeNoticePayload(payload)
                                  │
                                  ▼
                 [ SHA-256 Content Hash Generation ]
                      hashingService.sha256(str)
                                  │
                                  ▼
                     [ Ed25519 Digital Signing ]
                   ed25519Service.sign(str, privKey)
                                  │
                                  ▼
              [ Self-Verification Integrity Check ]
       verifyNoticePayload(payload, signature, trustedPubKey)
                                  │
                                  ▼
                   [ Database Persistence Layer ]
                   (Notice Record + Content Hash + Sig)
                                  │
                                  ▼
               [ Safe SignedNoticeResponseDto Return ]
               (Zero Private Keys, Zero Student PII)
```

---

## 3. Canonical Payload & Signing Specification

The signed data is strictly defined by the **`NoticeCanonicalPayload`** domain contract:

```typescript
export interface NoticeCanonicalPayload {
  noticeId?: string;       // Optional unique notice identifier
  institutionId: string;   // Unique authorized institution UUID
  title: string;           // Official notice headline (trimmed)
  content: string;         // Full notice circular text
  issuedAt: string;        // Strict ISO 8601 UTC timestamp
  expiresAt: string;       // Strict ISO 8601 UTC timestamp
  metadata?: Record<string, unknown>; // Optional structured context
}
```

### Data Exclusions:
To prevent signature invalidation during storage or verification, the signing payload **strictly excludes**:
- Database internal audit timestamps (`createdAt`, `updatedAt`).
- Mutable server-only fields or verification results.
- Authentication tokens and session secrets.
- Private keys or cryptographic seeds.
- Client search queries or student PII.

---

## 4. Input Validation & Error Handling Rules

| Parameter | Validation Constraint | Error Response |
|---|---|---|
| `institutionId` | Required, non-empty string | `400 VALIDATION_ERROR` |
| `title` | Required, non-empty, max 500 characters | `400 VALIDATION_ERROR` |
| `content` | Required, non-empty string | `400 VALIDATION_ERROR` |
| `issuedAt` | ISO 8601 UTC normalized (defaults to now) | `400 VALIDATION_ERROR` |
| `expiresAt` | Required, ISO 8601 UTC normalized | `400 VALIDATION_ERROR` |
| `expiresAt > issuedAt` | Expiry must be strictly later than issuance | `400 VALIDATION_ERROR` |
| `metadata` | Optional JSON object (cannot be array) | `400 VALIDATION_ERROR` |
| Institution Status | Must exist and have `status: ACTIVE` | `400 VALIDATION_ERROR` |
| Trusted Key Status | Must have active, unrevoked, unexpired key | `400 VALIDATION_ERROR` |

---

## 5. Private Key Security & Zero-PII Guarantees

### 1. Zero Private Key Ingestion & Leakage:
- **No Client Secrets**: The HTTP request body never accepts, processes, or relies on client-provided private keys.
- **Server-Side Key Vault**: Institutional signing keys are resolved strictly through server-side secure keystores, HSM configurations, or KMS interfaces.
- **No Private Key Persistence**: The `Notice` table schema and response DTOs contain zero private key columns.
- **Zero Logging**: Private key material is never logged or formatted.

### 2. Zero-PII Blockchain Boundary:
- The signing workflow operates strictly on public circular announcements and institutional cryptographic metadata.
- No student names, roll numbers, emails, queries, or screenshots are involved in notice issuance.

---

## 6. Integration Contract for Phase 6 (Verification Engine)

When an end-user verifies a notice in Phase 6:
1. Reconstruct the `NoticeCanonicalPayload` from the circular content.
2. Canonicalize the payload using `canonicalizationService.canonicalizeNoticePayload`.
3. Compute SHA-256 hash with `hashingService.sha256` and verify against stored `contentHash`.
4. Query Phase 4 registry for the institution's active public key (`getActiveKeyByInstitution(institutionId)`).
5. Verify signature using `ed25519Service.verify(canonicalString, signature, trustedPublicKey)`.
