export interface ProvenanceQuery {
  inference_root: string;
  device_attestation_hash?: string;
}

export function getProvenanceStatus(query: ProvenanceQuery) {
  return {
    inference_root: query.inference_root,
    device_attestation_hash: query.device_attestation_hash || null,
    chain_status: "anchored",
    attested_by_titan_m2: !!query.device_attestation_hash,
  };
}
