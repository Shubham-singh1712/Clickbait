# CLICKBAIT — Public Notice Verification Specification (Phase 6)

> **Document Version**: 1.0.0  
> **Status**: Production Ready  
> **Module**: `src/services/verification/verification.service.ts`  
> **Audience**: Backend Engineers (Member 3), Cryptography & Security Architects, Public Client Portal (Member 4), Institution Portal (Member 5)

---

## 1. Executive Summary & Purpose

In **CLICKBAIT**, digital notice authenticity requires an absolute, trust-anchored verification pipeline. 

**Phase 6** establishes the **Public Notice Verification API Orchestration**. The verification engine connects all preceding cryptographic and registry services into a unified, publicly accessible verification pipeline:
1. Validates notice payload structure and normalized ISO 8601 UTC timestamps.
2. Queries the **Phase 4 Trusted Issuer Public-Key Registry** to retrieve the authentic active Ed25519 public key.
3. Reconstructs and deterministically canonicalizes the **`NoticeCanonicalPayload`** using **Phase 2 Canonicalization**.
4. Computes and checks the **SHA-256 Content Hash** (Phase 2).
5. Cryptographically verifies the **Ed25519 Digital Signature** using the registered public key (Phase 3).
6. Evaluates notice lifecycle expiration and revocation statuses.
7. Formulates and returns a standardized, transparent **`VerificationResult`**.

---

## 2. Core Verification Architecture & Pipeline

```
=============================================================================
                  PUBLIC NOTICE VERIFICATION PIPELINE
=============================================================================

                   [ Public Client Verification Request ]
                         (POST /api/verify)
                                  │
                                  ▼
                     [ Request Validation Layer ]
         (Structure check, required fields, timestamp parsing,
                       expiresAt > issuedAt)
                                  │
                                  ▼
                [ Issuer Registry Resolution (Phase 4) ]
       (Query getActiveKeyByInstitution -> Status: ACTIVE,
                     revokedAt == null, expiresAt > now)
                                  │
                   ┌──────────────┴──────────────┐
                   │                             │
         [ Trusted Key Found ]         [ Unknown / Revoked / Inactive ]
                   │                             │
                   │                             ▼
                   │                     [ REJECT: UNVERIFIED / REVOKED ]
                   │                     (trustedIssuerKey: false,
                   │                      isAuthentic: false)
                   ▼
       [ Construct & Canonicalize Payload (Phase 2) ]
              canonicalizeNoticePayload(payload)
                                  │
                                  ▼
             [ Compute SHA-256 Content Hash (Phase 2) ]
                      hashingService.sha256(str)
                                  │
                                  ▼
           [ Ed25519 Cryptographic Verification (Phase 3) ]
           ed25519Service.verify(str, signature, pubKey)
                                  │
                   ┌──────────────┴──────────────┐
                   │                             │
           [ Signature Valid ]           [ Signature Invalid ]
                   │                             │
                   │                             ▼
                   │                     [ REJECT: TAMPERED ]
                   │                     (signatureValid: false,
                   │                      riskLevel: CRITICAL)
                   ▼
        [ Expiration & Revocation Status Evaluation ]
            - notExpired: expiresAt > now
            - notRevoked: dbRecord.status !== REVOKED
                                  │
                                  ▼
             [ Standardized Verification Result Return ]
             (Zero Private Keys, Zero Student PII)
```

---

## 3. API Endpoint Specification

### `POST /api/verify`

Publicly accessible verification endpoint that validates notice authenticity.

#### Request Body Schema:
```json
{
  "payload": {
    "noticeId": "notice-uuid-optional",
    "institutionId": "inst-delhi-university-01",
    "title": "Official Holiday Announcement",
    "content": "The campus will remain closed on Friday for University Day.",
    "issuedAt": "2026-07-01T00:00:00.000Z",
    "expiresAt": "2026-12-31T23:59:59.000Z",
    "metadata": { "department": "General Administration" }
  },
  "signature": "88-character-base64-ed25519-signature",
  "contentHash": "optional-64-character-sha256-hex-hash"
}
```

#### Successful Authentic Response (`HTTP 200 OK`):
```json
{
  "success": true,
  "message": "Notice signature verified successfully",
  "data": {
    "isAuthentic": true,
    "resultStatus": "VERIFIED",
    "riskLevel": "NONE",
    "institution": {
      "id": "inst-delhi-university-01",
      "name": "University of Delhi",
      "verifiedDomain": "du.ac.in"
    },
    "notice": {
      "id": "notice-uuid-optional",
      "title": "Official Holiday Announcement",
      "contentHash": "67bd86c8b9ab433f31528bb7e1ffb0cda90d7b110581cb417bb91331f603542e",
      "issuedAt": "2026-07-01T00:00:00.000Z",
      "expiresAt": "2026-12-31T23:59:59.000Z",
      "status": "ACTIVE"
    },
    "checks": {
      "signatureValid": true,
      "integrityVerified": true,
      "notExpired": true,
      "notRevoked": true,
      "trustedIssuerKey": true
    },
    "timestamp": "2026-08-27T13:46:31.643Z"
  }
}
```

#### Tampered Notice Response (`HTTP 200 OK`):
```json
{
  "success": true,
  "message": "Notice verification failed",
  "data": {
    "isAuthentic": false,
    "resultStatus": "TAMPERED",
    "riskLevel": "CRITICAL",
    "checks": {
      "signatureValid": false,
      "integrityVerified": false,
      "notExpired": true,
      "notRevoked": true,
      "trustedIssuerKey": true
    },
    "timestamp": "2026-08-27T13:46:31.643Z"
  }
}
```

---

## 4. Verification Check Flags & Status Codes

| Check Flag | Description | Failure Consequence |
|---|---|---|
| `trustedIssuerKey` | Institution is registered, ACTIVE, with active Ed25519 public key | `isAuthentic = false`, `resultStatus = 'UNVERIFIED'` |
| `signatureValid` | Ed25519 digital signature verified against registered public key | `isAuthentic = false`, `resultStatus = 'TAMPERED'` |
| `integrityVerified` | SHA-256 computed hash matches provided content hash | `isAuthentic = false`, `resultStatus = 'TAMPERED'` |
| `notExpired` | Notice expiration timestamp is in the future (`expiresAt > now`) | `isAuthentic = false`, `resultStatus = 'EXPIRED'` |
| `notRevoked` | Notice is not marked as revoked in database | `isAuthentic = false`, `resultStatus = 'REVOKED'` |

---

## 5. Security Guarantees & Privacy Boundaries

1. **Zero Private Key Ingestion**: The verification service neither accepts nor utilizes private keys.
2. **Authoritative Key Resolution**: Arbitrary client-supplied public keys are strictly ignored; the verifier resolves public keys exclusively through the Trusted Issuer Registry.
3. **Deterministic Canonicalization**: Protects against JSON key reordering, spacing variations, and Unicode encoding exploits.
4. **Zero-PII Preservation**: Verification operates solely over public notice content and institutional metadata; no student identities, search queries, or session identifiers are stored or shared.

---

## 6. Integration Contract & Next Steps

Phase 6 provides the complete public verification backend required for:
- Web verification clients (Member 4 verification portal).
- Mobile and browser extension verification widgets.
- Future screenshot OCR extraction pipelines (Phase 7+).
