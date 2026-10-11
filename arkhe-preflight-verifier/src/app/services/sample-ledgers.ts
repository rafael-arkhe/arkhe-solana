import {ArkheLedger, C2PAManifestDetail, ValidationItem} from '../models/arkhe.types';
import {
  base58Encode,
  canonicalSha256,
  hexToBytes,
  sha256AsciiSync,
  sha256Sync
} from './crypto-utils';
import {generateMusicalWav} from './audio-synth';

export interface SampleScenario {
  id: string;
  name: string;
  description: string;
  expectedStatus: 'PASS' | 'FAIL';
  expectedIssue?: string;
  ledger: ArkheLedger;
  audioABytes: Uint8Array;
  audioBBytes: Uint8Array;
  audioAName: string;
  audioBName: string;
  c2paAVerified: {integrity: string; signature: string; hard_binding: string; trust: string; manifestDetail?: C2PAManifestDetail};
  c2paBVerified: {integrity: string; signature: string; hard_binding: string; trust: string; manifestDetail?: C2PAManifestDetail};
}

// Generate genuine 44.1kHz 16-bit PCM WAV audio waveforms
const AUDIO_A_WAV = generateMusicalWav('vivaldi');
const AUDIO_B_WAV = generateMusicalWav('richter');

const SHA_A = sha256Sync(AUDIO_A_WAV);
const SHA_B = sha256Sync(AUDIO_B_WAV);

// Deterministic DIDs (Ed25519 prefix 0xed 0x01 + 32 bytes)
const DID_A = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3dJDX3mDooWp';
const DID_B = 'did:key:z6MkjTBC3eL42mJ5Fq8zYkXzVv7T8g6wU9rQ1pL2mN4kP5sR';

const L1_VAL = sha256AsciiSync('ARKHE_MMR_LEAF_1_PREVIOUS_CATALOG_BLOCK');
const L2_VAL = sha256AsciiSync('ARKHE_MMR_LEAF_2_ORCHESTRAL_ARCHIVE');
const L3_VAL = sha256AsciiSync('ARKHE_MMR_LEAF_3_SYNTHESIS_INDEX');

const CD_VAL = sha256AsciiSync(L2_VAL + L3_VAL);

// Detailed C2PA Manifest Assertions & Certificates
const C2PA_MANIFEST_A: C2PAManifestDetail = {
  claimGenerator: 'Arkhe C2PA Audio Toolkit v23.0.1 (Rust C2PA SDK 0.38)',
  title: 'Concerto No. 4 in F minor, Op. 8, RV 297 "L\'inverno" Master Recording',
  format: 'audio/vnd.wave; codec=1',
  hardBindingSha256: SHA_A,
  certificate: {
    subject: 'CN=Arkhe Music Provenance Vault, O=Classical Heritage Archive, C=IT',
    issuer: 'CN=DigiCert Global Root CA, O=DigiCert Inc, C=US',
    serialNumber: '4A:8B:12:F3:99:C2:55:01',
    validFrom: '2026-01-01T00:00:00Z',
    validTo: '2028-12-31T23:59:59Z',
    fingerprintSha256: '9f23a1098efc451290bbce881249fa98231017ba541098ecbf3489102489c190',
    status: 'trusted'
  },
  assertions: [
    {
      label: 'c2pa.actions',
      data: {
        actions: [
          {action: 'c2pa.created', parameters: {format: 'audio/wav', sampleRate: 44100, bitDepth: 16}},
          {action: 'c2pa.recorded', softwareAgent: 'Arkhe High-Res Master Recorder v2.4'}
        ]
      }
    },
    {
      label: 'stds.schema-org.CreativeWork',
      data: {
        '@context': 'https://schema.org',
        '@type': 'MusicRecording',
        name: 'Concerto No. 4 in F minor, Op. 8, RV 297 "L\'inverno"',
        composer: 'Antonio Vivaldi',
        isrcCode: 'IT-A01-26-00101',
        iswcCode: 'T-034.524.980-1'
      }
    },
    {
      label: 'c2pa.hash.data',
      data: {
        alg: 'sha256',
        pad: 0,
        hash: SHA_A
      }
    }
  ]
};

const C2PA_MANIFEST_B: C2PAManifestDetail = {
  claimGenerator: 'Arkhe C2PA Audio Toolkit v23.0.1 (Rust C2PA SDK 0.38)',
  title: 'Recomposed by Max Richter: Vivaldi - The Four Seasons: Winter 1',
  format: 'audio/vnd.wave; codec=1',
  hardBindingSha256: SHA_B,
  certificate: {
    subject: 'CN=Deutsche Grammophon Digital Master CA, O=Universal Music Group, C=DE',
    issuer: 'CN=DigiCert Global Root CA, O=DigiCert Inc, C=US',
    serialNumber: '7C:1E:44:A2:81:99:00:BF',
    validFrom: '2026-02-15T00:00:00Z',
    validTo: '2029-02-14T23:59:59Z',
    fingerprintSha256: '3819fa00bc19283746552910ab38475619283746501928374650192837465192',
    status: 'trusted'
  },
  assertions: [
    {
      label: 'c2pa.actions',
      data: {
        actions: [
          {action: 'c2pa.created', parameters: {format: 'audio/wav', sampleRate: 44100, bitDepth: 16}},
          {action: 'c2pa.placed', description: 'Recomposed melodic motif from RV 297'}
        ]
      }
    },
    {
      label: 'stds.schema-org.CreativeWork',
      data: {
        '@context': 'https://schema.org',
        '@type': 'MusicRecording',
        name: 'Recomposed by Max Richter: Vivaldi - The Four Seasons: Winter 1',
        byArtist: 'Max Richter, Daniel Hope',
        isrcCode: 'GB-UM7-12-05432',
        iswcCode: 'T-909.123.456-7'
      }
    },
    {
      label: 'c2pa.hash.data',
      data: {
        alg: 'sha256',
        pad: 0,
        hash: SHA_B
      }
    }
  ]
};

function makeCalibrationItems(): {val_scores: ValidationItem[]; tp: number; fp: number; tn: number; fn: number} {
  const scores: ValidationItem[] = [];
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const threshold = 0.72;

  // 100 negatives: 1 false positive above threshold
  for (let i = 0; i < 100; i++) {
    const sha1 = sha256AsciiSync(`CALIBRATION_NEG_AUDIO_X_${i}`);
    const sha2 = sha256AsciiSync(`CALIBRATION_NEG_AUDIO_Y_${i}`);
    const [x, y] = sha1 <= sha2 ? [sha1, sha2] : [sha2, sha1];
    const pairId = sha256AsciiSync(x + y);
    const score = i === 0 ? 0.74 : (0.10 + (i % 50) * 0.01);
    scores.push({
      label: 'negative',
      score: Number(score.toFixed(3)),
      pair_id: pairId,
      sha256_a: sha1,
      sha256_b: sha2,
      name: `neg_benchmark_${i}`
    });
    if (score >= threshold) fp++;
    else tn++;
  }

  // 50 positives: 48 true positives, 2 false negatives
  for (let i = 0; i < 50; i++) {
    const sha1 = sha256AsciiSync(`CALIBRATION_POS_AUDIO_A_${i}`);
    const sha2 = sha256AsciiSync(`CALIBRATION_POS_AUDIO_B_${i}`);
    const [x, y] = sha1 <= sha2 ? [sha1, sha2] : [sha2, sha1];
    const pairId = sha256AsciiSync(x + y);
    const score = i < 2 ? 0.65 : (0.75 + (i % 20) * 0.01);
    scores.push({
      label: 'positive',
      score: Number(score.toFixed(3)),
      pair_id: pairId,
      sha256_a: sha1,
      sha256_b: sha2,
      name: `pos_benchmark_${i}`
    });
    if (score >= threshold) tp++;
    else fn++;
  }

  return {val_scores: scores, tp, fp, tn, fn};
}

export function buildSampleScenarios(): SampleScenario[] {
  const calData = makeCalibrationItems();

  // Create valid base ledger (Schema 1.1 with trust_context)
  const baseLedger: ArkheLedger = {
    schema_version: '1.1',
    generated_at: '2026-10-11T06:00:00Z',
    target_a: {
      title: 'Concerto No. 4 in F minor, Op. 8, RV 297 "L\'inverno"',
      artist: 'Antonio Vivaldi',
      year: 1725,
      mbid: '89a44b15-9937-4d7a-b68a-a8ef9f123456',
      isrcs: ['IT-A01-26-00101'],
      iswcs: ['T-034.524.980-1'],
      composers: ['Antonio Vivaldi'],
      sha256: SHA_A,
      acoustid_gate: true,
      creator_did: DID_A
    },
    target_b: {
      title: 'Recomposed by Max Richter: Vivaldi - The Four Seasons: Winter 1',
      artist: 'Max Richter, Daniel Hope',
      year: 2012,
      mbid: 'e4b37812-78d1-4122-bc50-13f28490a1bc',
      isrcs: ['GB-UM7-12-05432'],
      iswcs: ['T-909.123.456-7'],
      composers: ['Max Richter', 'Antonio Vivaldi'],
      sha256: SHA_B,
      acoustid_gate: true,
      creator_did: DID_B
    },
    similarity: {
      clap_cosine: 0.8872,
      melodic: {
        status: 'calibrated_match',
        similarity: {
          pitch_contour_dtw: 0.942,
          harmonic_chroma_correlation: 0.891,
          rhythm_onset_iou: 0.835
        },
        calibration: {
          threshold: 0.72,
          confidence_alpha: 0.05,
          max_fpr: 0.05,
          tau: 0.85,
          val_scores: calData.val_scores,
          n_negatives: 100,
          tp: calData.tp,
          fp: calData.fp,
          tn: calData.tn,
          fn: calData.fn,
          calibration_valid: true,
          alpha_guaranteed: true,
          decision: 'provenance_linked'
        }
      }
    },
    c2pa: {
      a: {
        integrity: 'valid',
        signature: 'valid',
        hard_binding: 'match',
        trust: 'trusted',
        manifestDetail: C2PA_MANIFEST_A
      },
      b: {
        integrity: 'valid',
        signature: 'valid',
        hard_binding: 'match',
        trust: 'trusted',
        manifestDetail: C2PA_MANIFEST_B
      }
    },
    manifest: {
      engine: 'Arkhe Core Audio Kernel v23.0',
      audio_sample_rate: 44100,
      fft_window_size: 2048,
      chroma_bins: 12,
      spectrogram_type: 'cqt'
    },
    script_sha256: '9f83c6b12a84b5e28a7e0892c909671d182093a890b0d3674bb9f3458a2d4821',
    trust_policy: 'signer_trusted',
    trust_context: {
      verifier: 'encypher-c2pa',
      verifier_version: '1.0.0',
      trust_basis: 'bundled_static_material',
      trust_snapshot: null
    }
  };

  // Compute canonical content hash covering ALL 9 fields of schema 1.1
  const covered: Record<string, unknown> = {
    schema_version: baseLedger.schema_version,
    generated_at: baseLedger.generated_at,
    target_a: baseLedger.target_a,
    target_b: baseLedger.target_b,
    similarity: baseLedger.similarity,
    manifest: baseLedger.manifest,
    script_sha256: baseLedger.script_sha256,
    trust_policy: baseLedger.trust_policy,
    trust_context: baseLedger.trust_context
  };
  const validContentHash = canonicalSha256(covered);
  baseLedger.content_hash = validContentHash;

  // MMR for Leaf 0 of 4 leaves:
  const AB_VAL = sha256AsciiSync(validContentHash + L1_VAL);
  const ABCD_VAL = sha256AsciiSync(AB_VAL + CD_VAL);
  const mmrRoot = sha256AsciiSync(ABCD_VAL);

  // Anchor commitment
  const commitmentDomain = new TextEncoder().encode('ARKHE:v1');
  const cBytes = hexToBytes(validContentHash);
  const rBytes = hexToBytes(mmrRoot);
  const combined = new Uint8Array(commitmentDomain.length + cBytes.length + rBytes.length);
  combined.set(commitmentDomain, 0);
  combined.set(cBytes, commitmentDomain.length);
  combined.set(rBytes, commitmentDomain.length + cBytes.length);
  const commitmentBytes = hexToBytes(sha256Sync(combined));
  const anchorCommitment = base58Encode(commitmentBytes);

  // Solana tx signature
  const txBytes = new Uint8Array(64);
  for (let i = 0; i < 64; i++) txBytes[i] = (i * 17 + 43) & 0xff;
  const validTxSig = base58Encode(txBytes);

  baseLedger.anchor = {
    tx_signature: validTxSig,
    mmr_root: mmrRoot,
    mmr_version: 'aegis-mmr-inclusion-v1',
    mmr_algorithm: 'sha256-asciihex',
    leaf_index: 0,
    leaf_count: 4,
    peak_index: 0,
    peaks: [
      {height: 2, hash: ABCD_VAL}
    ],
    path: [
      {direction: 'R', sibling_hash: L1_VAL},
      {direction: 'R', sibling_hash: CD_VAL}
    ],
    timestamp: '2026-10-11T06:05:00Z',
    anchor_commitment: anchorCommitment
  };

  // Envelope hash covering content_hash, anchor, c2pa, trust_policy, trust_context
  baseLedger.envelope_hash = canonicalSha256({
    content_hash: validContentHash,
    anchor: baseLedger.anchor,
    c2pa: baseLedger.c2pa,
    trust_policy: baseLedger.trust_policy,
    trust_context: baseLedger.trust_context
  });

  const clone = <T>(obj: T): T => JSON.parse(JSON.stringify(obj));

  // Scenario 1: 100% Valid Release Grade
  const scn1: SampleScenario = {
    id: 'valid-release',
    name: '1. Arkhe Release-Grade Certification (100% PASS)',
    description: 'Cryptographic provenance ledger with authentic synthesized 44.1kHz PCM WAV audio waveforms, strictly satisfying all Verification Gates I1 to I15 and P0.',
    expectedStatus: 'PASS',
    ledger: clone(baseLedger),
    audioABytes: new Uint8Array(AUDIO_A_WAV),
    audioBBytes: new Uint8Array(AUDIO_B_WAV),
    audioAName: 'vivaldi_winter_rv297.wav',
    audioBName: 'richter_winter_1_recomposed.wav',
    c2paAVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_A
    },
    c2paBVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_B
    }
  };

  // Scenario 2: Audio Tamper (Audio bytes modified)
  const scn2Ledger = clone(baseLedger);
  const tamperedWavA = new Uint8Array(AUDIO_A_WAV.length);
  tamperedWavA.set(AUDIO_A_WAV, 0);
  // Flip bytes in data chunk
  tamperedWavA[120] = tamperedWavA[120] ^ 0xff;
  tamperedWavA[121] = tamperedWavA[121] ^ 0xaa;

  const scn2: SampleScenario = {
    id: 'audio-tamper',
    name: '2. Integrity Breach: Target Audio A Tampered (FAIL I1a)',
    description: 'The WAV audio file for Work A suffered sample bit corruption. The calculated SHA-256 hash diverges from the value declared in the ledger.',
    expectedStatus: 'FAIL',
    expectedIssue: 'Audio A SHA-256 mismatch (I1a)',
    ledger: scn2Ledger,
    audioABytes: tamperedWavA,
    audioBBytes: new Uint8Array(AUDIO_B_WAV),
    audioAName: 'vivaldi_winter_rv297_tampered.wav',
    audioBName: 'richter_winter_1_recomposed.wav',
    c2paAVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_A
    },
    c2paBVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_B
    }
  };

  // Scenario 3: MMR Proof Forged (FAIL I8b)
  const scn3Ledger = clone(baseLedger);
  if (scn3Ledger.anchor && scn3Ledger.anchor.path[0]) {
    scn3Ledger.anchor.path[0].sibling_hash = sha256AsciiSync('FORGED_SIBLING_HASH_ATTACK');
  }
  const scn3: SampleScenario = {
    id: 'mmr-forgery',
    name: '3. MMR Inclusion Attack: Forged Sibling Hash (FAIL I8b)',
    description: 'The cryptographic Merkle Mountain Range inclusion proof was corrupted. The leaf-to-peak path folding computation fails.',
    expectedStatus: 'FAIL',
    expectedIssue: 'MMR leaf→peak divergence (I8b)',
    ledger: scn3Ledger,
    audioABytes: new Uint8Array(AUDIO_A_WAV),
    audioBBytes: new Uint8Array(AUDIO_B_WAV),
    audioAName: 'vivaldi_winter_rv297.wav',
    audioBName: 'richter_winter_1_recomposed.wav',
    c2paAVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_A
    },
    c2paBVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_B
    }
  };

  // Scenario 4: C2PA Untrusted Signer (FAIL I10vB / I10c)
  const scn4Ledger = clone(baseLedger);
  const untrustedManifestB: C2PAManifestDetail = {
    ...C2PA_MANIFEST_B,
    certificate: {
      ...C2PA_MANIFEST_B.certificate,
      issuer: 'CN=Unknown Self-Signed Authority, C=XX',
      status: 'untrusted_self_signed'
    }
  };
  const scn4: SampleScenario = {
    id: 'c2pa-untrusted',
    name: '4. C2PA Trust Failure: Untrusted Certificate Signer (FAIL I10)',
    description: 'Under the signer_trusted policy, the Target B certificate issuer is self-signed or unverified (untrusted_self_signed).',
    expectedStatus: 'FAIL',
    expectedIssue: 'C2PA trust status not in ACCEPTED_TRUST_STATUSES (I10vB / I10c)',
    ledger: scn4Ledger,
    audioABytes: new Uint8Array(AUDIO_A_WAV),
    audioBBytes: new Uint8Array(AUDIO_B_WAV),
    audioAName: 'vivaldi_winter_rv297.wav',
    audioBName: 'richter_winter_1_recomposed.wav',
    c2paAVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_A
    },
    c2paBVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'untrusted_self_signed',
      manifestDetail: untrustedManifestB
    }
  };

  // Scenario 5: Trust Context Basis Invalid (FAIL I10ctx.basis)
  const scn5Ledger = clone(baseLedger);
  scn5Ledger.trust_context.trust_basis = 'custom_unsupported_bundle';
  const cov5: Record<string, unknown> = {
    schema_version: scn5Ledger.schema_version,
    generated_at: scn5Ledger.generated_at,
    target_a: scn5Ledger.target_a,
    target_b: scn5Ledger.target_b,
    similarity: scn5Ledger.similarity,
    manifest: scn5Ledger.manifest,
    script_sha256: scn5Ledger.script_sha256,
    trust_policy: scn5Ledger.trust_policy,
    trust_context: scn5Ledger.trust_context
  };
  scn5Ledger.content_hash = canonicalSha256(cov5);
  const scn5: SampleScenario = {
    id: 'trust-basis-invalid',
    name: '5. Context Binding Violation: Invalid trust_basis (FAIL I10ctx)',
    description: 'Per v23 P0-2 specification, trust_basis is strictly constrained to "bundled_static_material". Any other basis triggers fail-closed rejection.',
    expectedStatus: 'FAIL',
    expectedIssue: 'trust_basis != bundled_static_material (I10ctx.basis)',
    ledger: scn5Ledger,
    audioABytes: new Uint8Array(AUDIO_A_WAV),
    audioBBytes: new Uint8Array(AUDIO_B_WAV),
    audioAName: 'vivaldi_winter_rv297.wav',
    audioBName: 'richter_winter_1_recomposed.wav',
    c2paAVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_A
    },
    c2paBVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_B
    }
  };

  // Scenario 6: Dataset Contamination / Leakage (FAIL I12)
  const scn6Ledger = clone(baseLedger);
  if (scn6Ledger.similarity.melodic?.calibration) {
    const leakedItem = scn6Ledger.similarity.melodic.calibration.val_scores[10];
    if (leakedItem) {
      leakedItem.sha256_a = SHA_A;
      const [x, y] = SHA_A <= leakedItem.sha256_b ? [SHA_A, leakedItem.sha256_b] : [leakedItem.sha256_b, SHA_A];
      leakedItem.pair_id = sha256AsciiSync(x + y);
    }
  }
  const scn6: SampleScenario = {
    id: 'data-leakage',
    name: '6. Statistical Contamination: Target Audio in Benchmark (FAIL I12)',
    description: 'Cross-contamination gate violation (I12): Target A audio SHA-256 hash was discovered inside the validation dataset benchmark pairs.',
    expectedStatus: 'FAIL',
    expectedIssue: 'Target presence in calibration pairs (I12)',
    ledger: scn6Ledger,
    audioABytes: new Uint8Array(AUDIO_A_WAV),
    audioBBytes: new Uint8Array(AUDIO_B_WAV),
    audioAName: 'vivaldi_winter_rv297.wav',
    audioBName: 'richter_winter_1_recomposed.wav',
    c2paAVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_A
    },
    c2paBVerified: {
      integrity: 'valid',
      signature: 'valid',
      hard_binding: 'match',
      trust: 'trusted',
      manifestDetail: C2PA_MANIFEST_B
    }
  };

  return [scn1, scn2, scn3, scn4, scn5, scn6];
}
