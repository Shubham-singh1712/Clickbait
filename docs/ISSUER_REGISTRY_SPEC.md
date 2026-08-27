# CLICKBAIT — Trusted Issuer Public-Key Registry Specification (Phase 4)

> **Document Version**: 1.0.0  
> **Status**: Production Ready  
> **Module**: `src/services/registry/issuer-registry.service.ts`  
> **Audience**: Backend Engineers (Member 3), Cryptography & Security Architects, Institution Portal (Member 5), Verification Engine (Member 4)

---

## 1. Executive Summary & Purpose

In **CLICKBAIT**, circular and notice authenticity relies on **deterministic digital signatures**. However, digital signatures are cryptographically meaningless if the verifier does not know with absolute certainty **which public key belongs to which authorized issuing institution**.

The **Trusted Issuer Public-Key Registry** establishes the definitive, authoritative source of truth for all authorized institutions and their active Ed25519 public keys. 

### Fundamental Security Axiom:
> **The backend and verification client must NEVER blindly trust an arbitrary public key provided by an untrusted client or notice request.**  
> Notice verification MUST always resolve the public key through the Trusted Issuer Registry using the claimed institution identifier.

---

## 2. Core Security Architecture & Trust Flow

```
=============================================================================
                      TRUSTED VERIFICATION TRUST FLOW
=============================================================================

                 [ Incoming Verification Request ]
                 (Notice Payload + Signature + institutionId)
                                 │
                                 ▼
                     [ Issuer Registry Lookup ]
                     getActiveKeyByInstitution(institutionId)
                                 │
                  ┌──────────────┴──────────────┐
                  │                             │
          [ Institution Found ]       [ Unknown Institution ]
                  │                             │
                  ▼                             ▼
       [ Active Key Retrieved ]              [ REJECT ]
                  │                     (isAuthentic: false,
                  │                      trustedIssuerKey: false)
                  │
        ┌─────────┴─────────────────────────────┐
        │ Key Status Evaluation                 │
        │ - Status: ACTIVE                      │
        │ - revokedAt == null                   │
        │ - expiresAt > now                     │
        │ - Valid 32-Byte Ed25519 format        │
        └─────────┬─────────────────────────────┘
                  │
       ┌──────────┴──────────┐
       │                     │
    [ PASS ]             [ FAIL ] (REVOKED / EXPIRED / CORRUPTED)
       │                     │
       ▼                     ▼
[ Ed25519 Verification ]  [ REJECT ]
(Phase 3 Engine)         (isAuthentic: false, trustedIssuerKey: false)
```

---

## 3. Institution-to-Key Association & Database Model

The relational database model (PostgreSQL managed via Prisma ORM) models authorized institutions and their cryptographic key lifecycle.

```
┌──────────────────────────────────────┐       1 : N       ┌──────────────────────────────────────┐
│             institutions             │ ────────────────< │             issuer_keys              │
├──────────────────────────────────────┤                   ├──────────────────────────────────────┤
│ id: String (UUID, PK)                │                   │ id: String (UUID, PK)                │
│ name: String                         │                   │ institutionId: String (FK)           │
│ verifiedDomain: String (Unique)      │                   │ publicKey: String (Unique, Base64)   │
│ status: InstitutionStatus            │                   │ keyStatus: KeyStatus (ACTIVE, ...)   │
│ createdAt: DateTime                  │                   │ createdAt: DateTime                  │
│ updatedAt: DateTime                  │                   │ expiresAt: DateTime                  │
│                                      │                   │ revokedAt: DateTime?                 │
└──────────────────────────────────────┘                   └──────────────────────────────────────┘
```

### Key Association Rules:
1. **Uniqueness**: Each public key is globally unique (`@unique`). A single cryptographic public key cannot belong to multiple institutions.
2. **Cascading Relations**: Keys are strictly scoped to an `institutionId`.
3. **Association Integrity Protection**: Institution A can never resolve, claim, or validate against Institution B's registered public key (`isKeyTrusted("inst-A", keyB)` strictly evaluates to `false`).

---

## 4. Ed25519 Public-Key Format & Strict Validation

Phase 4 enforces the standard established in Phase 3 (RFC 8032 / RFC 8410):

| Property | Requirement | Enforcement Rule |
|---|---|---|
| **Algorithm** | Ed25519 | Edwards-curve Digital Signature over Curve25519 |
| **Encoding** | Base64 | Standard Base64 regex `^[A-Za-z0-9+/]+={0,2}$` |
| **Binary Length** | Exactly 32 bytes | Decoded buffer length must equal `32` (`ED25519_PUBLIC_KEY_BYTE_LENGTH`) |
| **Encoded String Length** | Exactly 44 characters | Includes standard Base64 padding (`==`) |
| **Private Key Separation** | Strictly Prohibited | Reject any payload containing private key headers or >32 byte payloads |

### Validation Pipeline:
```typescript
// 1. Non-empty string check
// 2. Base64 regex validation
// 3. Round-trip padding integrity check
// 4. Decoded buffer byte count === 32
// 5. Curve point / SPKI prefix validation
```

---

## 5. Key Lifecycle & Status State Machine

Keys transition through strict lifecycle states:

```
  [ Key Registration ]
           │
           ▼
     ┌───────────┐
     │  ACTIVE   │ ──( Expiry Timestamp Reached )──> ┌───────────┐
     └─────┬─────┘                                  │  EXPIRED  │
           │                                        └───────────┘
           │ ( Security Audit / Compromise )
           ▼
     ┌───────────┐
     │  REVOKED  │ ──( Re-registration Forbidden )──> [ PERMANENT TERMINATION ]
     └───────────┘
```

### Status Rules:
1. **`ACTIVE`**: Key is currently authorized. Can be used for signature verification if and only if `expiresAt > now` and `revokedAt === null`.
2. **`REVOKED`**: Key was revoked (e.g. key compromise, administrative revocation). **A revoked key is NEVER returned as trusted** and cannot be re-registered.
3. **`EXPIRED`**: Key lifetime has elapsed (`expiresAt <= now`). An expired key is NEVER returned as active.
4. **`SUSPENDED` Institution**: If an institution itself is marked `SUSPENDED`, all key registration and trusted verification lookups immediately fail.

---

## 6. Service API & Method Contracts

The `IssuerRegistryService` (`src/services/registry/issuer-registry.service.ts`) exposes the following interface:

```typescript
export interface IIssuerRegistryService {
  /** Registers a new institution record in the registry */
  registerInstitution(dto: InstitutionCreateDto): Promise<InstitutionRecord>;

  /** Retrieves institution by unique ID */
  getInstitutionById(institutionId: string): Promise<InstitutionRecord | null>;

  /** Retrieves institution by verified domain */
  getInstitutionByDomain(domain: string): Promise<InstitutionRecord | null>;

  /** Registers a validated 32-byte Ed25519 public key */
  registerKey(institutionId: string, publicKeyBase64: string, expiresAt: Date | string): Promise<IssuerKeyRecord>;

  /** Retrieves the currently active, unrevoked, unexpired public key for an institution */
  getActiveKeyByInstitution(institutionId: string): Promise<IssuerKeyRecord | null>;

  /** Semantic alias for getActiveKeyByInstitution */
  getTrustedPublicKey(institutionId: string): Promise<IssuerKeyRecord | null>;

  /** Looks up a public key record by its Base64 string */
  getKeyByPublicKey(publicKeyBase64: string): Promise<IssuerKeyRecord | null>;

  /** Deterministically checks if a public key is active and trusted for a specific institution */
  isKeyTrusted(institutionId: string, publicKeyBase64: string): Promise<boolean>;

  /** Revokes a key by primary key ID */
  revokeKey(keyId: string, reason?: string): Promise<IssuerKeyRecord>;

  /** Revokes a key by public key string and institution association */
  revokeKeyByPublicKey(institutionId: string, publicKeyBase64: string, reason?: string): Promise<IssuerKeyRecord>;
}
```

---

## 7. Security Boundaries & Zero-PII Guarantees

### 1. Private Key Security
- **No Private Keys in Registry**: The database schema and domain models do NOT contain private key columns or fields.
- **Input Sanitization**: Key registration rejects private key inputs (PEM blocks, PKCS#8 seeds, 64-byte secret arrays).
- **Zero Key Logging**: Logger calls NEVER format or log private cryptographic material.

### 2. Zero-PII Blockchain Boundary
- The registry stores institutional identity (`name`, `verifiedDomain`) and cryptographic public keys.
- **Zero Student PII**: No student names, emails, roll numbers, query histories, or search inputs are ever accepted, stored, or sent to the blockchain layer.
- Blockchain provenance interfaces receive only public identifiers (`institutionId`, `publicKeyRef`, `contentHash`).

---

## 8. Integration Contract for Future Phases

### For Phase 5 (Notice Creation & Signing):
- Authorized issuers authenticate and look up their active registered public key.
- Notices are signed using the corresponding private key (held in the institution's secure client/HSM, never sent to the backend).

### For Phase 6 (Notice Verification Engine):
- When verifying notice authenticity:
  1. Extract `institutionId` and `signature` from notice.
  2. Query `issuerRegistryService.getActiveKeyByInstitution(institutionId)`.
  3. If null, verify result status is `UNVERIFIED` / `SUSPICIOUS` with `trustedIssuerKey: false`.
  4. If active key is returned, pass trusted key to `ed25519Service.verifyNoticePayload(...)`.

---

## 9. Known Limitations & Phase Scope

- **Phase 4 Scope**: Registry establishment, key validation, duplicate handling, association enforcement, and revocation marking.
- **Out of Scope for Phase 4** (Deferred to Future Phases):
  - Notice issuance API (Phase 5)
  - Public verification API orchestration (Phase 6)
  - Live Web3 smart contract deployment on mainnet/testnet (Future)
  - AI risk engine & screenshot OCR pipeline (Phase 7+)
