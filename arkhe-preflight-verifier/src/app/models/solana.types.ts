export type SolanaCluster = 'devnet' | 'mainnet-beta' | 'testnet' | 'localnet' | 'custom';

export interface SolanaClusterConfig {
  id: SolanaCluster;
  name: string;
  rpcUrl: string;
  wsUrl?: string;
  explorerUrl: string;
  isTestnet: boolean;
  faucetSupported: boolean;
}

export const SOLANA_CLUSTERS: Record<SolanaCluster, SolanaClusterConfig> = {
  devnet: {
    id: 'devnet',
    name: 'Solana Devnet',
    rpcUrl: 'https://api.devnet.solana.com',
    explorerUrl: 'https://explorer.solana.com/tx/{sig}?cluster=devnet',
    isTestnet: true,
    faucetSupported: true
  },
  'mainnet-beta': {
    id: 'mainnet-beta',
    name: 'Solana Mainnet Beta',
    rpcUrl: 'https://api.mainnet-beta.solana.com',
    explorerUrl: 'https://explorer.solana.com/tx/{sig}',
    isTestnet: false,
    faucetSupported: false
  },
  testnet: {
    id: 'testnet',
    name: 'Solana Testnet',
    rpcUrl: 'https://api.testnet.solana.com',
    explorerUrl: 'https://explorer.solana.com/tx/{sig}?cluster=testnet',
    isTestnet: true,
    faucetSupported: true
  },
  localnet: {
    id: 'localnet',
    name: 'Solana Localnet (127.0.0.1:8899)',
    rpcUrl: 'http://127.0.0.1:8899',
    explorerUrl: 'https://explorer.solana.com/tx/{sig}?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899',
    isTestnet: true,
    faucetSupported: true
  },
  custom: {
    id: 'custom',
    name: 'Custom RPC Endpoint',
    rpcUrl: 'https://api.devnet.solana.com',
    explorerUrl: 'https://explorer.solana.com/tx/{sig}?cluster=custom',
    isTestnet: true,
    faucetSupported: false
  }
};

export const ARKHE_MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
export const ARKHE_MEMO_PREFIX = 'ARKHE:v1:';
export const ARKHE_COMMITMENT_DOMAIN = 'ARKHE:v1';

export type WalletProviderType = 'injected' | 'ephemeral' | 'simulated';

export interface SolanaWalletState {
  connected: boolean;
  connecting: boolean;
  publicKey: string | null;
  balanceLamports: number;
  balanceSol: number;
  providerType: WalletProviderType;
  walletName: string;
  cluster: SolanaCluster;
  lastUpdated: string | null;
  error: string | null;
}

export interface SolanaParsedInstruction {
  programId: string;
  program: string;
  parsedType?: string;
  memoText?: string;
  rawParsed?: unknown;
}

export interface SolanaTxInspection {
  signature: string;
  cluster: SolanaCluster;
  found: boolean;
  fetching: boolean;
  error: string | null;
  slot: number | null;
  blockTime: number | null;
  blockTimeIso: string | null;
  confirmationStatus: string | null;
  feeLamports: number | null;
  feeSol: number | null;
  err: unknown | null;
  extractedMemos: string[];
  matchedArkheMemo: string | null;
  extractedCommitment: string | null;
  expectedCommitment: string | null;
  commitmentMatches: boolean;
  blockTimeCompliesWithGeneratedAt: boolean;
  driftSeconds: number | null;
  driftFormatted: string;
  programLogs: string[];
  rawResult: unknown;
}

export interface OnChainAnchorProgress {
  active: boolean;
  step: 'idle' | 'preparing' | 'fetching_blockhash' | 'signing' | 'broadcasting' | 'confirming' | 'completed' | 'error';
  stepMessage: string;
  txSignature: string | null;
  commitmentBase58: string | null;
  memoPayload: string | null;
  slot: number | null;
  blockTime: number | null;
  error: string | null;
}
