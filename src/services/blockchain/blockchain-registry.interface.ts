import { BlockchainNoticeProvenance } from '../../types';

/**
 * Interface for Blockchain Provenance Registry.
 *
 * CRITICAL SECURITY & PRIVACY MANDATE:
 * Student PII (names, emails, phones, roll numbers, query histories, screenshots)
 * MUST NEVER be transmitted to or stored on the blockchain layer.
 *
 * Only cryptographic fingerprints, institutional identifiers, and lifecycle status are permitted.
 */
export interface IBlockchainRegistry {
  /**
   * Records notice provenance immutably on the ledger.
   */
  registerNoticeProvenance(provenance: BlockchainNoticeProvenance): Promise<{
    success: boolean;
    transactionHash: string;
    blockNumber?: number;
  }>;

  /**
   * Retrieves notice provenance details from the blockchain registry.
   */
  getNoticeProvenance(noticeId: string): Promise<BlockchainNoticeProvenance | null>;

  /**
   * Updates revocation status of a notice on the ledger.
   */
  revokeNoticeProvenance(noticeId: string): Promise<{
    success: boolean;
    transactionHash: string;
  }>;

  /**
   * Verifies if notice content hash matches the recorded blockchain hash.
   */
  verifyContentHash(noticeId: string, contentHash: string): Promise<boolean>;
}
