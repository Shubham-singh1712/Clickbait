# CLICKBAIT Backend — SIH 2026

> **"Don't Guess. Verify."**  
> Tamper-Proof Notice Verification, Ed25519 Cryptographic Signatures, Trusted Public-Key Registry & Blockchain Provenance.

---

## 🏛️ Project Purpose & Architecture

**CLICKBAIT** provides authorized institutions (universities, examination boards, government bodies) with a cryptographic signing pipeline for digital notices and circulars. Students and public users can verify notices deterministically.

### Verification Hierarchy
1. **Primary Mechanism (Deterministic)**: Ed25519 cryptographic signature + SHA-256 canonical hash verification against the institution's active public key stored in the trusted registry.
2. **Provenance Layer (Tamper-evident)**: Blockchain registry stores immutable cryptographic notice fingerprints.
3. **Secondary Layer (Advisory)**: AI Risk Engine and OCR for unverified forwards, cropped screenshots, or anomalies. AI **never** overrides valid cryptographic proofs.
4. **Privacy First (Zero-PII)**: Student data, queries, and personal records are **never** stored on or sent to the blockchain layer.

---

## 📁 Project Structure

```
Backend SIH/
├── src/
│   ├── config/
│   │   ├── env.ts                         # Validated environment configuration (Zod)
│   │   └── database.ts                    # Singleton Prisma PostgreSQL Client
│   ├── controllers/
│   │   ├── auth.controller.ts             # POST /api/auth/login
│   │   ├── institution.controller.ts      # POST /api/institutions
│   │   ├── notice.controller.ts           # POST /api/notices, POST /api/notices/:id/revoke
│   │   └── verification.controller.ts     # POST /api/verify, POST /api/verify/screenshot
│   ├── routes/
│   │   ├── index.ts                       # API root & Health check (/api/health)
│   │   ├── auth.routes.ts                 # Auth routes
│   │   ├── institution.routes.ts          # Institution routes
│   │   ├── notice.routes.ts               # Notice creation & revocation routes
│   │   └── verification.routes.ts         # Deterministic & screenshot verification routes
│   ├── services/
│   │   ├── crypto/
│   │   │   ├── canonicalization.service.ts # Deterministic JSON serialization
│   │   │   ├── hashing.service.ts          # SHA-256 & timing-safe hash comparison
│   │   │   └── ed25519.service.ts          # Ed25519 key signing & verification
│   │   ├── notice/
│   │   │   └── notice.service.ts           # Notice lifecycle management
│   │   ├── registry/
│   │   │   └── issuer-registry.service.ts  # Trusted Public Key Registry
│   │   └── blockchain/
│   │       ├── blockchain-registry.interface.ts # Zero-PII blockchain contract
│   │       └── blockchain-registry.mock.ts      # In-memory mock adapter
│   ├── middleware/
│   │   ├── error.middleware.ts            # Centralized error handler
│   │   ├── not-found.middleware.ts        # 404 handler
│   │   └── request-logger.middleware.ts   # Safe structured logger
│   ├── utils/
│   │   ├── api-response.ts                # Standardized JSON response envelope
│   │   └── logger.ts                      # Secret-redacted logging utility
│   ├── types/
│   │   └── index.ts                       # TypeScript domain types & DTOs
│   ├── app.ts                             # Express application configuration
│   └── server.ts                          # Server bootstrap & graceful shutdown
├── prisma/
│   └── schema.prisma                      # PostgreSQL Schema (Institutions, Keys, Notices, Verifications)
├── tests/
│   ├── unit/
│   │   └── sanity.test.ts                 # Sanity & service interface contract tests
│   └── integration/
│       └── api-skeleton.test.ts           # API endpoint integration tests
├── .env.example                           # Safe environment variable template
├── .gitignore                             # Secret and build ignore rules
├── jest.config.ts                         # Jest + ts-jest configuration
├── package.json                           # Dependencies & scripts
├── tsconfig.json                          # Strict TypeScript configuration
└── README.md                              # Documentation
```

---

## 🔒 Security Principles
- **No Hardcoded Keys**: Private keys are never hardcoded or committed.
- **Zero Secret Logging**: The logging layer automatically redacts private keys, authorization headers, and credentials.
- **No Student PII on Blockchain**: Blockchain payload contains only `institutionId`, `publicKeyRef`, `noticeId`, `contentHash`, timestamps, and revocation status.
- **Strict Public Key Origin**: Public keys are strictly queried from the trusted issuer registry, rejecting arbitrary user-provided public keys.

---

## 🛠️ Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 3. Generate Prisma Client
```bash
npx prisma generate
```

### 4. Run Development Server
```bash
npm run dev
```
Server runs at `http://localhost:5000` (Health check: `http://localhost:5000/api/health`).

### 5. Run Tests
```bash
npm test
```

---

## 📋 API Contracts (Phase 1 Skeleton)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status |
| `POST` | `/api/auth/login` | Institution authentication |
| `POST` | `/api/institutions` | Register authorized institution |
| `POST` | `/api/notices` | Create and sign official notice |
| `POST` | `/api/notices/:id/revoke` | Revoke an existing notice |
| `POST` | `/api/verify` | Deterministic cryptographic notice verification |
| `POST` | `/api/verify/screenshot` | Secondary OCR & AI risk assessment |

---

## 🗓️ Roadmap
- **Phase 1 (Completed)**: Backend Foundation, Prisma Schema, API Skeleton, Security & Jest Setup
- **Phase 2 (Completed)**: Deterministic Canonicalization Engine & SHA-256 Content Hashing (RFC 8785 principles)
- **Phase 3 (Completed)**: Ed25519 Digital Signature & Verification Engine (Base64 raw 32/64-byte standards)
- **Phase 4**: Trusted Issuer Public-Key Registry
- **Phase 5**: Notice Creation & Signing API
- **Phase 6**: Notice Cryptographic Verification API
- **Phase 7**: Notice Expiry & Revocation Life-cycle
- **Phase 8 (Completed)**: Blockchain Provenance Registry Adapter
- **Phase 9 (Completed)**: Integration with Member 2 AI Risk Engine
- **Phase 10 (Completed)**: Master Unified Orchestration & Security Audit

