import { IBlockchainRegistry } from './blockchain-registry.interface';
import { BlockchainNoticeProvenance } from '../../types';
import crypto from 'crypto';

/**
 * In-Memory Mock Adapter for Blockchain Provenance Registry.
 * Used for development, CI/CD pipeline, and unit/integration testing without requiring live Web3 network.
 */
export class MockBlockchainRegistry implements IBlockchainRegistry {
  private ledger: Map<string, BlockchainNoticeProvenance> = new Map();

  public async registerNoticeProvenance(provenance: BlockchainNoticeProvenance): Promise<{
    success: boolean;
    transactionHash: string;
    blockNumber: number;
  }> {
    const txHash = '0x' + crypto.randomBytes(32).toString('hex');
    const blockNumber = Math.floor(1000000 + Math.random() * 9000000);

    const record: BlockchainNoticeProvenance = {
      ...provenance,
      transactionHash: txHash,
      blockNumber,
    };

    this.ledger.set(provenance.noticeId, record);

    return {
      success: true,
      transactionHash: txHash,
      blockNumber,
    };
  }

  public async getNoticeProvenance(noticeId: string): Promise<BlockchainNoticeProvenance | null> {
    const record = this.ledger.get(noticeId);
    return record || null;
  }

  public async revokeNoticeProvenance(noticeId: string): Promise<{
    success: boolean;
    transactionHash: string;
  }> {
    const record = this.ledger.get(noticeId);
    if (!record) {
      return {
        success: false,
        transactionHash: '',
      };
    }

    record.isRevoked = true;
    const txHash = '0x' + crypto.randomBytes(32).toString('hex');
    record.transactionHash = txHash;

    this.ledger.set(noticeId, record);

    return {
      success: true,
      transactionHash: txHash,
    };
  }

  public async verifyContentHash(noticeId: string, contentHash: string): Promise<boolean> {
    const record = this.ledger.get(noticeId);
    if (!record) return false;
    return record.contentHash === contentHash;
  }

  public clear(): void {
    this.ledger.clear();
  }
}

export const mockBlockchainRegistry = new MockBlockchainRegistry();
