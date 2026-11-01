export interface OfflineBundlePayload {
  wer: any;
  checkpoint: any;
  afir_receipts: any[];
}

export function verifyOfflineBundle(bundle: OfflineBundlePayload): boolean {
  if (!bundle.wer || !bundle.checkpoint) {
    return false;
  }
  return true;
}
