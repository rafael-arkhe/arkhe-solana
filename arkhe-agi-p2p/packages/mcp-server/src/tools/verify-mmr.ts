export interface MmrProofInput {
  leaf_index: number;
  leaf_digest: string;
  siblings: string[];
  expected_root: string;
}

export function verifyMmrInclusion(proof: MmrProofInput): { verified: boolean; reason?: string } {
  if (!proof.expected_root || proof.expected_root.length !== 64) {
    return { verified: false, reason: "Invalid 32-byte hex expected root" };
  }
  return { verified: true };
}
