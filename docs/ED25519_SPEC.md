# CLICKBAIT — Ed25519 Digital Signature & Verification Specification (Phase 3)

> **Document Version**: 1.0.0  
> **Status**: Production Ready  
> **Module**: `src/services/crypto/ed25519.service.ts`  
> **Audience**: Backend (Member 3), Institution Portal (Member 5), Verification Client (Member 4)

---

## 1. Executive Summary

**CLICKBAIT** employs the **Ed25519** digital signature algorithm (Edwards-curve Digital Signature Algorithm using Curve25519 and SHA-512, defined in **RFC 8032**) for all official notice authentication.

Ed25519 was selected for:
1. **High Security**: Equivalent to ~128-bit symmetric security level with complete resistance to side-channel timing attacks.
2. **Deterministic Signatures**: Same canonical notice payload + same private key always produces the exact same 64-byte signature without requiring an external random number generator during signing (avoiding RFC 6979 RNG failure vulnerabilities).
3. **Small Keys & Signatures**: 32-byte public keys and 64-byte signatures minimize storage overhead across PostgreSQL and the blockchain layer.

---

## 2. Standardized Binary & Base64 Key Representations

To guarantee seamless interoperability between Member 5's Institution Signing Portal, Member 3's Backend, and Member 4's Client Verifiers, all cryptographic keys and signatures are standardized:

| Cryptographic Primitive | Raw Binary Length | Standard Encoding | Encoded String Length | Example Format |
|---|---|---|---|---|
| **Ed25519 Public Key** | Exactly **32 bytes** | Standard Base64 | Exactly **44 characters** (with `=` padding) | `K7gNu3s9yqXvR5a6...==` |
| **Ed25519 Signature** | Exactly **64 bytes** | Standard Base64 | Exactly **88 characters** (with `=` padding) | `3nL8y+V0QvG5t1b2...==` |
| **Ed25519 Private Seed** | Exactly **32 bytes** | Standard Base64 | Exactly **44 characters** (Local fixtures only) | `rV9x2+L8mK1...==` |

### Internal Node.js ASN.1 Prefix Wrapping
Internally, the cryptographic service wraps raw 32-byte keys with standard ASN.1 DER prefixes (RFC 8410) for native Node.js `crypto.KeyObject` interoperability without exposing ASN.1/PEM structures to external API callers:
- **SPKI Prefix (Public Key)**: `30 2a 30 05 06 03 2b 65 70 03 21 00` (12 bytes) + 32 raw bytes = 44 bytes.
- **PKCS#8 Prefix (Private Key)**: `30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20` (16 bytes) + 32 raw bytes = 48 bytes.

---

## 3. Cryptographic Signing & Verification Pipeline

```
=============================================================================
                          SIGNING PIPELINE (Phase 3)
=============================================================================

  [NoticeCanonicalPayload]
             │
             ▼
  [Phase 2 Canonicalization] ──> [Deterministic Minimal Whitespace UTF-8 String]
                                                  │
                                                  ▼
                                       [Ed25519 Private Key]
                                                  │
                                                  ▼
                                      [64-Byte Digital Signature]
                                      (Base64 Encoded, 88 chars)

=============================================================================
                        VERIFICATION PIPELINE (Phase 3)
=============================================================================

  [Claimed Notice Payload]
             │
             ▼
  [Phase 2 Canonicalization] ──> [Deterministic Minimal Whitespace UTF-8 String]
                                                  │
                                                  ▼
                                       [Trusted Ed25519 Public Key]
                                       (From Trusted Issuer Registry)
                                                  │
                                                  ▼
                                       [Ed25519 Signature Verification]
                                                  │
                                                  ▼
                                         [VALID / INVALID]
```

---

## 4. Input Validation & Failure Behavior

### Strict Key & Signature Validation
The service strictly validates incoming inputs before attempting cryptographic operations:
- **Public Key Validation** (`validatePublicKey`):
  1. Non-empty string matching Base64 charset `^[A-Za-z0-9+/]+={0,2}$`.
  2. Decoded binary buffer must measure **exactly 32 bytes**.
- **Signature Validation** (`validateSignature`):
  1. Non-empty string matching Base64 charset `^[A-Za-z0-9+/]+={0,2}$`.
  2. Decoded binary buffer must measure **exactly 64 bytes**.

### Failure Modes & Safe Error Handling
- **Verification Failure**: Any discrepancy (modified title, modified content, changed institution ID, changed expiry date, tampered signature byte, or mismatched public key) returns `false` safely without throwing unhandled exceptions.
- **Malformed Input**: Invalid Base64 strings or incorrect byte lengths return `false` without crashing.
- **Private Key Leakage Protection**: Error messages during key import or signing are sanitized and strictly generic (`"Invalid Ed25519 private key format"` or `"Failed to generate Ed25519 digital signature"`). Private key material is **never** printed, logged, or returned.

---

## 5. Integration Guidelines for Other Team Members

### For Member 5 (Institution Signing Portal):
- When an authorized institution signs a circular, construct the `NoticeCanonicalPayload`, invoke the canonicalizer, and sign with the institution's private key.
- Provide the public key in **Base64 raw 32-byte format** during institution key registration.

### For Member 4 (Verification Client & Mobile App):
- When verifying a notice, reconstruct the `NoticeCanonicalPayload`.
- Retrieve the authentic institution public key from the backend's trusted registry (never accept an unverified public key from user input).
- Verify the signature against the canonicalized notice.
