export type CheckResultStatus = 'PASS' | 'FAIL' | 'WARN' | 'NOT_CHECKED';
export type CheckSeverity = 'hard' | 'external' | 'heuristic';
export type VerificationMode = 'sanity' | 'release';
export type TrustPolicy = 'integrity_only' | 'signer_trusted';

export interface PreflightCheck {
  id: string;
  name: string;
  result: CheckResultStatus;
  detail: string;
  severity: CheckSeverity;
  category?: 'audio' | 'hash' | 'solana' | 'mmr' | 'did' | 'c2pa' | 'trust' | 'calibration' | 'leakage' | 'system';
}

export interface MMRPeak {
  height: number;
  hash: string;
}

export interface MMRPathStep {
  direction: 'L' | 'R';
  sibling_hash: string;
}

export interface ValidationItem {
  label: 'positive' | 'negative';
  score: number;
  pair_id: string;
  sha256_a: string;
  sha256_b: string;
  name?: string;
}

export interface TargetModel {
  title: string;
  artist: string;
  year: number;
  mbid: string;
  isrcs?: string[];
  iswcs?: string[];
  composers?: string[];
  sha256: string;
  acoustid_gate?: boolean;
  creator_did?: string;
}

export interface AnchorModel {
  tx_signature: string;
  chain?: string;
  mmr_root: string;
  mmr_version?: string;
  mmr_algorithm?: string;
  leaf_index: number;
  leaf_count: number;
  peak_index: number;
  peaks: MMRPeak[];
  path: MMRPathStep[];
  timestamp?: string;
  anchor_commitment?: string;
}

export interface C2PACertificate {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  fingerprintSha256: string;
  status: 'trusted' | 'untrusted_self_signed' | 'revoked';
}

export interface C2PAAssertion {
  label: string;
  data: Record<string, unknown>;
}

export interface C2PAManifestDetail {
  claimGenerator: string;
  title: string;
  format: string;
  hardBindingSha256: string;
  certificate: C2PACertificate;
  assertions: C2PAAssertion[];
}

export interface C2PAEntry {
  integrity: string;
  signature: string;
  hard_binding: string;
  trust?: string;
  manifestDetail?: C2PAManifestDetail;
}

export interface C2PAModel {
  a: C2PAEntry;
  b: C2PAEntry;
}

export interface TrustContext {
  verifier: string;
  verifier_version: string;
  trust_basis: string;
  trust_snapshot?: string | null;
}

export interface CalibrationModel {
  threshold: number;
  confidence_alpha: number;
  max_fpr: number;
  tau: number;
  val_scores: ValidationItem[];
  n_negatives: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  calibration_valid?: boolean;
  alpha_guaranteed?: boolean;
  decision?: string;
}

export interface MelodicModel {
  status: string;
  similarity?: Record<string, unknown>;
  calibration?: CalibrationModel;
}

export interface SimilarityModel {
  clap_cosine?: number;
  melodic?: MelodicModel;
}

export interface ArkheLedger {
  schema_version: '1.1';
  generated_at: string;
  target_a: TargetModel;
  target_b: TargetModel;
  similarity: SimilarityModel;
  anchor?: AnchorModel;
  c2pa?: C2PAModel;
  manifest: Record<string, unknown>;
  script_sha256: string;
  content_hash?: string;
  envelope_hash?: string;
  trust_policy: TrustPolicy;
  trust_context: TrustContext;
}

export interface PreflightVerificationReport {
  timestamp: string;
  mode: VerificationMode;
  trustPolicy: TrustPolicy;
  requireTrustPolicy?: TrustPolicy | null;
  isReleaseGrade: boolean;
  overallStatus: 'PASS' | 'FAIL';
  checks: PreflightCheck[];
  hardFailures: PreflightCheck[];
  contentHash?: string;
  txSignature?: string;
  blockTime?: number;
  releaseIssues: string[];
  selftestPassed: boolean;
  executionTimeMs: number;
}

export interface GoldenVectorResult {
  name: string;
  status: 'PASS' | 'FAIL';
  detail: string;
  expected?: string;
  actual?: string;
}
