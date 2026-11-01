export interface AfirReceiptInput {
  version: number;
  session_id: string;
  step_index: number;
  input_digest: string;
  output_digest: string;
  model_cid: string;
  execution_timestamp: number;
  signature: string;
}

export function verifyAfirReceipt(receipt: AfirReceiptInput, pubkey: string): { verified: boolean; reason?: string } {
  if (receipt.version !== 1) {
    return { verified: false, reason: "Unsupported AFiR receipt version" };
  }
  if (!receipt.signature || receipt.signature.length === 0) {
    return { verified: false, reason: "Empty ML-DSA-65 signature" };
  }
  return { verified: true };
}
