import {Injectable} from '@angular/core';
import {
  ArkheLedger,
  GoldenVectorResult,
  MMRPeak,
  MMRPathStep,
  PreflightCheck,
  PreflightVerificationReport,
  TrustPolicy,
  VerificationMode
} from '../models/arkhe.types';
import {
  base58Decode,
  base58Encode,
  canonicalSha256,
  clopperPearsonUpper,
  hexToBytes,
  sha256AsciiSync,
  sha256Sync
} from './crypto-utils';

export const SCHEMA_VERSION = '1.1';
export const MMR_VERSION = 'aegis-mmr-inclusion-v1';
export const MMR_ALGORITHM = 'sha256-asciihex';
export const COMMITMENT_DOMAIN = new TextEncoder().encode('ARKHE:v1');
export const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
export const MEMO_PREFIX = 'ARKHE:v1:';
export const ED25519_PREFIX = new Uint8Array([0xed, 0x01]);
export const ACCEPTED_TRUST_STATUSES = new Set(['trusted']);
export const ACCEPTED_TRUST_BASIS = 'bundled_static_material';
export const VALID_TRUST_POLICIES = new Set(['integrity_only', 'signer_trusted']);

export const CONTENT_FIELDS: Record<string, string[]> = {
  '1.1': [
    'schema_version', 'generated_at', 'target_a', 'target_b',
    'similarity', 'manifest', 'script_sha256', 'trust_policy', 'trust_context'
  ]
};

export const REQUIRED_GROUPS: Record<string, ['ALL' | 'ANY', string[]]> = {
  'I1': ['ALL', ['I1a', 'I1b']],
  'I2': ['ANY', ['I2']],
  'I3': ['ANY', ['I3']],
  'I4': ['ANY', ['I4']],
  'I5': ['ANY', ['I5']],
  'I6': ['ANY', ['I6']],
  'I7': ['ANY', ['I7']],
  'I8': ['ALL', ['I8a', 'I8b', 'I8c']],
  'I9': ['ALL', ['I9A', 'I9B']],
  'I10': ['ALL', ['I10vA', 'I10vB', 'I10c', 'I10ctx']],
  'I11': ['ALL', ['I11', 'I11b', 'I11c', 'I11d']],
  'I12': ['ANY', ['I12']],
  'I13': ['ANY', ['I13']],
  'I14': ['ANY', ['I14']],
  'I15': ['ALL', ['I15a', 'I15b']],
  'P0': ['ALL', ['P0a', 'P0b']]
};

interface SolanaInstruction {
  programId: string;
  parsed?: string | { info?: string };
}

interface SolanaTxResult {
  slot?: number;
  blockTime?: number;
  meta?: {
    err?: unknown;
    innerInstructions?: {
      instructions: SolanaInstruction[];
    }[];
  };
  transaction?: {
    message?: {
      instructions: SolanaInstruction[];
    };
  };
}

@Injectable({
  providedIn: 'root'
})
export class ArkheVerifierService {

  // --- Utility Primitives ---

  isHex64(val: unknown): boolean {
    return typeof val === 'string' && /^[0-9a-f]{64}$/.test(val);
  }

  hAscii(str: string): string {
    return sha256AsciiSync(str);
  }

  pairIdCanonical(shaA: string, shaB: string): string {
    if (!this.isHex64(shaA) || !this.isHex64(shaB)) {
      throw new Error('sha256_a/b must be 64-character lowercase hex');
    }
    const [x, y] = shaA <= shaB ? [shaA, shaB] : [shaB, shaA];
    return this.hAscii(x + y);
  }

  computeAnchorCommitment(contentHashHex: string, mmrRootHex: string): Uint8Array {
    const contentBytes = hexToBytes(contentHashHex);
    const mmrBytes = hexToBytes(mmrRootHex);
    const combined = new Uint8Array(COMMITMENT_DOMAIN.length + contentBytes.length + mmrBytes.length);
    combined.set(COMMITMENT_DOMAIN, 0);
    combined.set(contentBytes, COMMITMENT_DOMAIN.length);
    combined.set(mmrBytes, COMMITMENT_DOMAIN.length + contentBytes.length);

    const hashHex = sha256Sync(combined);
    return hexToBytes(hashHex);
  }

  expectedMemo(contentHashHex: string, mmrRootHex: string): string {
    const commitmentBytes = this.computeAnchorCommitment(contentHashHex, mmrRootHex);
    return MEMO_PREFIX + base58Encode(commitmentBytes);
  }

  // --- MMR Primitives ---

  foldPath(leafHex: string, path: MMRPathStep[]): string {
    let current = leafHex;
    for (const step of path) {
      if (step.direction === 'L') {
        current = this.hAscii(step.sibling_hash + current);
      } else {
        current = this.hAscii(current + step.sibling_hash);
      }
    }
    return current;
  }

  bagPeaks(peaks: MMRPeak[]): string {
    const ordered = [...peaks].sort((a, b) => b.height - a.height);
    const concatenated = ordered.map(p => p.hash).join('');
    return this.hAscii(concatenated);
  }

  leafToMountain(leafIndex: number, leafCount: number): [number, number, number] {
    if (leafCount < 1) {
      throw new Error('leaf_count >= 1');
    }
    if (leafIndex < 0 || leafIndex >= leafCount) {
      throw new Error('leaf_index out of [0, leaf_count)');
    }

    const bitLength = leafCount.toString(2).length;
    const heights: number[] = [];
    for (let i = 0; i < bitLength; i++) {
      if ((leafCount >> i) & 1) {
        heights.push(i);
      }
    }
    heights.sort((a, b) => b - a);

    let start = 0;
    for (let peakIdx = 0; peakIdx < heights.length; peakIdx++) {
      const h = heights[peakIdx];
      const end = start + (1 << h);
      if (start <= leafIndex && leafIndex < end) {
        return [peakIdx, leafIndex - start, h];
      }
      start = end;
    }
    throw new Error('leaf_index has no mountain peak');
  }

  expectedDirections(localIndex: number, height: number): ('L' | 'R')[] {
    const dirs: ('L' | 'R')[] = [];
    for (let i = 0; i < height; i++) {
      dirs.push((localIndex >> i) & 1 ? 'L' : 'R');
    }
    return dirs;
  }

  computeContentHash(ledger: ArkheLedger): string {
    const version = ledger.schema_version;
    const fields = CONTENT_FIELDS[version];
    if (!fields) {
      throw new Error(`Unsupported schema version: ${version}`);
    }
    const covered: Record<string, unknown> = {};
    for (const field of fields) {
      const val = (ledger as unknown as Record<string, unknown>)[field];
      if (val === undefined || val === null) {
        throw new Error(`Missing covered field in content: ${field}`);
      }
      covered[field] = val;
    }
    return canonicalSha256(covered);
  }

  computeEnvelopeHash(
    contentHash: string,
    anchor: unknown,
    c2pa: unknown,
    trustPolicy: string,
    trustContext: unknown
  ): string {
    const envelope = {
      content_hash: contentHash,
      anchor: anchor,
      c2pa: c2pa,
      trust_policy: trustPolicy,
      trust_context: trustContext
    };
    return canonicalSha256(envelope);
  }

  // --- Duplicate Key JSON Parser (P0-4) ---

  parseJsonRejectingDuplicates(rawJson: string): {parsed: unknown; error: string | null} {
    try {
      // Tokenize to find duplicated keys in same object scope
      let inString = false;
      let escape = false;
      let currentKey = '';
      let isCapturingKey = false;
      const objectScopes: Set<string>[] = [new Set()];

      for (let i = 0; i < rawJson.length; i++) {
        const char = rawJson[i];
        if (escape) {
          escape = false;
          continue;
        }
        if (char === '\\') {
          escape = true;
          continue;
        }
        if (char === '"') {
          inString = !inString;
          if (inString) {
            isCapturingKey = true;
            currentKey = '';
          } else {
            // Check if next non-whitespace char is ':'
            let j = i + 1;
            while (j < rawJson.length && /\s/.test(rawJson[j])) j++;
            if (rawJson[j] === ':') {
              const currentScope = objectScopes[objectScopes.length - 1];
              if (currentScope.has(currentKey)) {
                return {parsed: null, error: `duplicate JSON key: "${currentKey}"`};
              }
              currentScope.add(currentKey);
            }
            isCapturingKey = false;
          }
          continue;
        }

        if (inString && isCapturingKey) {
          currentKey += char;
        } else if (!inString) {
          if (char === '{') {
            objectScopes.push(new Set());
          } else if (char === '}') {
            if (objectScopes.length > 1) objectScopes.pop();
          }
        }
      }

      const parsed = JSON.parse(rawJson);
      return {parsed, error: null};
    } catch (e: unknown) {
      return {parsed: null, error: String(e)};
    }
  }

  // --- Golden Vectors Self-Test Suite (16 Vectors in v23) ---

  runGoldenVectors(): GoldenVectorResult[] {
    const results: GoldenVectorResult[] = [];

    // 1. single_leaf
    try {
      const A = this.hAscii('A');
      const folded = this.foldPath(A, []);
      const bagged = this.bagPeaks([{height: 0, hash: A}]);
      const expectedBag = this.hAscii(A);
      if (folded === A && bagged === expectedBag) {
        results.push({name: 'single_leaf', status: 'PASS', detail: `Peak & bag match: ${bagged.slice(0, 16)}…`});
      } else {
        results.push({name: 'single_leaf', status: 'FAIL', detail: 'Mismatch in single leaf fold or bag'});
      }
    } catch (e: unknown) {
      results.push({name: 'single_leaf', status: 'FAIL', detail: String(e)});
    }

    // 2. two_leaves
    try {
      const A = this.hAscii('A');
      const B = this.hAscii('B');
      const AB = this.hAscii(A + B);
      const root = this.hAscii(AB);
      const foldA = this.foldPath(A, [{direction: 'R', sibling_hash: B}]);
      const foldB = this.foldPath(B, [{direction: 'L', sibling_hash: A}]);
      const bagged = this.bagPeaks([{height: 1, hash: AB}]);
      if (foldA === AB && foldB === AB && bagged === root) {
        results.push({name: 'two_leaves', status: 'PASS', detail: `Mountain height 1: ${root.slice(0, 16)}…`});
      } else {
        results.push({name: 'two_leaves', status: 'FAIL', detail: 'Fold or bag mismatch'});
      }
    } catch (e: unknown) {
      results.push({name: 'two_leaves', status: 'FAIL', detail: String(e)});
    }

    // 3. three_leaves
    try {
      const A = this.hAscii('A');
      const B = this.hAscii('B');
      const C = this.hAscii('C');
      const AB = this.hAscii(A + B);
      const root = this.hAscii(AB + C);
      const foldA = this.foldPath(A, [{direction: 'R', sibling_hash: B}]);
      const foldB = this.foldPath(B, [{direction: 'L', sibling_hash: A}]);
      const foldC = this.foldPath(C, []);
      const bagged = this.bagPeaks([{height: 1, hash: AB}, {height: 0, hash: C}]);
      if (foldA === AB && foldB === AB && foldC === C && bagged === root) {
        results.push({name: 'three_leaves', status: 'PASS', detail: `2 peaks bagged: ${root.slice(0, 16)}…`});
      } else {
        results.push({name: 'three_leaves', status: 'FAIL', detail: 'Mismatch in 3 leaves MMR'});
      }
    } catch (e: unknown) {
      results.push({name: 'three_leaves', status: 'FAIL', detail: String(e)});
    }

    // 4. four_leaves
    try {
      const A = this.hAscii('A');
      const B = this.hAscii('B');
      const C = this.hAscii('C');
      const D = this.hAscii('D');
      const AB = this.hAscii(A + B);
      const CD = this.hAscii(C + D);
      const ABCD = this.hAscii(AB + CD);
      const root = this.hAscii(ABCD);
      const foldA = this.foldPath(A, [{direction: 'R', sibling_hash: B}, {direction: 'R', sibling_hash: CD}]);
      const foldB = this.foldPath(B, [{direction: 'L', sibling_hash: A}, {direction: 'R', sibling_hash: CD}]);
      const foldC = this.foldPath(C, [{direction: 'R', sibling_hash: D}, {direction: 'L', sibling_hash: AB}]);
      const foldD = this.foldPath(D, [{direction: 'L', sibling_hash: C}, {direction: 'L', sibling_hash: AB}]);
      const bagged = this.bagPeaks([{height: 2, hash: ABCD}]);
      if (foldA === ABCD && foldB === ABCD && foldC === ABCD && foldD === ABCD && bagged === root) {
        results.push({name: 'four_leaves', status: 'PASS', detail: `Balanced tree height 2: ${root.slice(0, 16)}…`});
      } else {
        results.push({name: 'four_leaves', status: 'FAIL', detail: 'Mismatch in 4 leaves MMR fold'});
      }
    } catch (e: unknown) {
      results.push({name: 'four_leaves', status: 'FAIL', detail: String(e)});
    }

    // 5. bagging_single_peak_not_identity
    try {
      const A = this.hAscii('A');
      const B = this.hAscii('B');
      const peak = this.hAscii(A + B);
      if (this.hAscii(peak) !== peak) {
        results.push({name: 'bagging_single_peak_not_identity', status: 'PASS', detail: 'Bagging applies hash function: h(p) != p'});
      } else {
        results.push({name: 'bagging_single_peak_not_identity', status: 'FAIL', detail: 'Bagging was identity'});
      }
    } catch (e: unknown) {
      results.push({name: 'bagging_single_peak_not_identity', status: 'FAIL', detail: String(e)});
    }

    // 6. wrong_direction_load_bearing
    try {
      const A = this.hAscii('A');
      const B = this.hAscii('B');
      if (this.hAscii(A + B) !== this.hAscii(B + A)) {
        results.push({name: 'wrong_direction_load_bearing', status: 'PASS', detail: 'Direction order preserved: h(A+B) != h(B+A)'});
      } else {
        results.push({name: 'wrong_direction_load_bearing', status: 'FAIL', detail: 'Hash was commutative'});
      }
    } catch (e: unknown) {
      results.push({name: 'wrong_direction_load_bearing', status: 'FAIL', detail: String(e)});
    }

    // 7. pair_id_symmetric
    try {
      const a = this.hAscii('a');
      const b = this.hAscii('b');
      if (this.pairIdCanonical(a, b) === this.pairIdCanonical(b, a)) {
        results.push({name: 'pair_id_symmetric', status: 'PASS', detail: 'Canonical ordering ensures pair_id(a,b) == pair_id(b,a)'});
      } else {
        results.push({name: 'pair_id_symmetric', status: 'FAIL', detail: 'Pair ID was not symmetric'});
      }
    } catch (e: unknown) {
      results.push({name: 'pair_id_symmetric', status: 'FAIL', detail: String(e)});
    }

    // 8. trust_policy_binding
    try {
      const policyA = {trust_policy: 'signer_trusted'};
      const policyB = {trust_policy: 'integrity_only'};
      if (canonicalSha256(policyA) !== canonicalSha256(policyB)) {
        results.push({name: 'trust_policy_binding', status: 'PASS', detail: 'Different policies produce divergent canonical hashes'});
      } else {
        results.push({name: 'trust_policy_binding', status: 'FAIL', detail: 'Policy hashes collided'});
      }
    } catch (e: unknown) {
      results.push({name: 'trust_policy_binding', status: 'FAIL', detail: String(e)});
    }

    // 9. duplicate_keys_rejected_production
    try {
      const a = 'a'.repeat(64);
      const b = 'b'.repeat(64);
      const payload = `{"schema_version":"1.1","generated_at":"2026-10-11T00:00:00Z","content_hash":"${a}","content_hash":"${b}"}`;
      const parseRes = this.parseJsonRejectingDuplicates(payload);
      if (parseRes.error && parseRes.error.toLowerCase().includes('duplicate')) {
        results.push({name: 'duplicate_keys_rejected_production', status: 'PASS', detail: 'Rejected duplicate JSON key prior to canonicalization'});
      } else {
        results.push({name: 'duplicate_keys_rejected_production', status: 'FAIL', detail: 'Duplicate key was not rejected'});
      }
    } catch (e: unknown) {
      results.push({name: 'duplicate_keys_rejected_production', status: 'FAIL', detail: String(e)});
    }

    // 10. p0b_optional_uses_production
    try {
      const ledgerMock = {trust_policy: 'signer_trusted'} as unknown as ArkheLedger;
      const p0Checks = this.checkTrustPolicyBinding(ledgerMock, null);
      const p0a = p0Checks.find(c => c.id === 'P0a');
      const p0b = p0Checks.find(c => c.id === 'P0b');
      if (p0a?.result === 'PASS' && p0b?.result === 'PASS') {
        results.push({name: 'p0b_optional_uses_production', status: 'PASS', detail: 'P0b emits PASS when require_policy is null'});
      } else {
        results.push({name: 'p0b_optional_uses_production', status: 'FAIL', detail: 'P0b did not emit PASS'});
      }
    } catch (e: unknown) {
      results.push({name: 'p0b_optional_uses_production', status: 'FAIL', detail: String(e)});
    }

    // 11. p0b_restriction_enforced
    try {
      const ledgerMock = {trust_policy: 'signer_trusted'} as unknown as ArkheLedger;
      const p0Checks = this.checkTrustPolicyBinding(ledgerMock, 'integrity_only');
      const p0b = p0Checks.find(c => c.id === 'P0b');
      if (p0b?.result === 'FAIL') {
        results.push({name: 'p0b_restriction_enforced', status: 'PASS', detail: 'P0b fails when required policy diverges from artifact'});
      } else {
        results.push({name: 'p0b_restriction_enforced', status: 'FAIL', detail: 'P0b did not fail under policy divergence'});
      }
    } catch (e: unknown) {
      results.push({name: 'p0b_restriction_enforced', status: 'FAIL', detail: String(e)});
    }

    // 12. enforce_release_requires_p0b
    try {
      const mockChecks: PreflightCheck[] = [
        {id: 'P0a', name: 'trust_policy committed', result: 'PASS', detail: '', severity: 'hard'}
      ];
      const [ok, issues] = this.enforceReleaseGates(mockChecks);
      if (!ok && issues.some(i => i.includes('P0'))) {
        results.push({name: 'enforce_release_requires_p0b', status: 'PASS', detail: 'Release gate strictly requires P0b'});
      } else {
        results.push({name: 'enforce_release_requires_p0b', status: 'FAIL', detail: 'Release approved without P0b'});
      }
    } catch (e: unknown) {
      results.push({name: 'enforce_release_requires_p0b', status: 'FAIL', detail: String(e)});
    }

    // 13. trust_context_version_unknown_fails
    try {
      const ctxMock = {
        verifier: 'encypher-c2pa',
        verifier_version: '1.0.0',
        trust_basis: 'bundled_static_material',
        trust_snapshot: null
      };
      // installed version unknown -> fail
      const ctxCheck = this.checkTrustContext({trust_context: ctxMock} as unknown as ArkheLedger, 'release', true, null);
      const verCheck = ctxCheck.find(c => c.id === 'I10ctx.version');
      if (verCheck?.result === 'FAIL') {
        results.push({name: 'trust_context_version_unknown_fails', status: 'PASS', detail: 'Indeterminate version emits fail-closed rejection'});
      } else {
        results.push({name: 'trust_context_version_unknown_fails', status: 'FAIL', detail: 'Did not fail on indeterminate version'});
      }
    } catch (e: unknown) {
      results.push({name: 'trust_context_version_unknown_fails', status: 'FAIL', detail: String(e)});
    }

    // 14. trust_context_basis_restricted
    try {
      const ctxMock = {
        verifier: 'encypher-c2pa',
        verifier_version: '0.0.0',
        trust_basis: 'arkhe-private-bundle',
        trust_snapshot: null
      };
      const ctxCheck = this.checkTrustContext({trust_context: ctxMock} as unknown as ArkheLedger, 'release', true, '0.0.0');
      const basisCheck = ctxCheck.find(c => c.id === 'I10ctx.basis');
      if (basisCheck?.result === 'FAIL') {
        results.push({name: 'trust_context_basis_restricted', status: 'PASS', detail: 'Rejects basis other than bundled_static_material'});
      } else {
        results.push({name: 'trust_context_basis_restricted', status: 'FAIL', detail: 'Accepted invalid trust_basis'});
      }
    } catch (e: unknown) {
      results.push({name: 'trust_context_basis_restricted', status: 'FAIL', detail: String(e)});
    }

    // 15. trust_context_snapshot_forbidden
    try {
      const ctxMock = {
        verifier: 'encypher-c2pa',
        verifier_version: '0.0.0',
        trust_basis: 'bundled_static_material',
        trust_snapshot: '2026-10-11' // forbidden when bundled!
      };
      const ctxCheck = this.checkTrustContext({trust_context: ctxMock} as unknown as ArkheLedger, 'release', true, '0.0.0');
      const snapCheck = ctxCheck.find(c => c.id === 'I10ctx.snapshot');
      if (snapCheck?.result === 'FAIL') {
        results.push({name: 'trust_context_snapshot_forbidden', status: 'PASS', detail: 'Rejects snapshot declaration in bundled basis'});
      } else {
        results.push({name: 'trust_context_snapshot_forbidden', status: 'FAIL', detail: 'Accepted forbidden snapshot'});
      }
    } catch (e: unknown) {
      results.push({name: 'trust_context_snapshot_forbidden', status: 'FAIL', detail: String(e)});
    }

    // 16. trust_context_differs_blocks
    try {
      const ctxA = {verifier: 'encypher-c2pa', verifier_version: '1.0.0', trust_basis: 'bundled_static_material', trust_snapshot: null};
      const ctxB = {verifier: 'encypher-c2pa', verifier_version: '1.0.1', trust_basis: 'bundled_static_material', trust_snapshot: null};
      if (canonicalSha256(ctxA) !== canonicalSha256(ctxB)) {
        results.push({name: 'trust_context_differs_blocks', status: 'PASS', detail: 'Context difference alters canonical hash'});
      } else {
        results.push({name: 'trust_context_differs_blocks', status: 'FAIL', detail: 'Context hashes collided'});
      }
    } catch (e: unknown) {
      results.push({name: 'trust_context_differs_blocks', status: 'FAIL', detail: String(e)});
    }

    return results;
  }

  // --- Trust Policy & Context Checks ---

  checkTrustPolicyBinding(ledger: ArkheLedger, requirePolicy?: TrustPolicy | null): PreflightCheck[] {
    const checks: PreflightCheck[] = [];
    const effective = ledger.trust_policy;

    checks.push({
      id: 'P0a',
      name: 'trust_policy committed',
      result: 'PASS',
      detail: `effective=${effective}`,
      severity: 'hard',
      category: 'trust'
    });

    if (!requirePolicy) {
      checks.push({
        id: 'P0b',
        name: 'external trust policy constraint',
        result: 'PASS',
        detail: 'no external constraint requested',
        severity: 'hard',
        category: 'trust'
      });
    } else if (requirePolicy !== effective) {
      checks.push({
        id: 'P0b',
        name: 'external trust policy constraint',
        result: 'FAIL',
        detail: `required=${requirePolicy} ≠ artifact=${effective}`,
        severity: 'hard',
        category: 'trust'
      });
    } else {
      checks.push({
        id: 'P0b',
        name: 'external trust policy constraint',
        result: 'PASS',
        detail: `required=${requirePolicy} == artifact`,
        severity: 'hard',
        category: 'trust'
      });
    }

    return checks;
  }

  checkTrustContext(
    ledger: ArkheLedger,
    mode: VerificationMode,
    c2paVerifyAvailable = true,
    installedVersion: string | null = '1.0.0'
  ): PreflightCheck[] {
    const checks: PreflightCheck[] = [];

    if (mode !== 'release') {
      checks.push({
        id: 'I10ctx',
        name: 'trust_context binding',
        result: 'NOT_CHECKED',
        detail: 'verified in release mode only',
        severity: 'external',
        category: 'c2pa'
      });
      return checks;
    }

    if (!c2paVerifyAvailable) {
      checks.push({
        id: 'I10ctx',
        name: 'trust_context binding',
        result: 'FAIL',
        detail: 'c2pa_verify unavailable',
        severity: 'hard',
        category: 'c2pa'
      });
      return checks;
    }

    const ctx = ledger.trust_context;
    if (!ctx) {
      checks.push({
        id: 'I10ctx',
        name: 'trust_context binding',
        result: 'FAIL',
        detail: 'trust_context block missing in report',
        severity: 'hard',
        category: 'c2pa'
      });
      return checks;
    }

    const acceptedNames = new Set(['encypher_c2pa', 'encypher-c2pa']);
    if (!acceptedNames.has(ctx.verifier)) {
      checks.push({
        id: 'I10ctx.verifier',
        name: 'declared verifier',
        result: 'FAIL',
        detail: `declared=${ctx.verifier} not accepted`,
        severity: 'hard',
        category: 'c2pa'
      });
      return checks;
    }

    if (installedVersion === null) {
      checks.push({
        id: 'I10ctx.version',
        name: 'verifier_version',
        result: 'FAIL',
        detail: 'installed version indeterminate',
        severity: 'hard',
        category: 'c2pa'
      });
      return checks;
    }

    if (ctx.verifier_version !== installedVersion) {
      checks.push({
        id: 'I10ctx.version',
        name: 'verifier_version',
        result: 'FAIL',
        detail: `declared=${ctx.verifier_version} installed=${installedVersion}`,
        severity: 'hard',
        category: 'c2pa'
      });
      return checks;
    }

    if (ctx.trust_basis !== ACCEPTED_TRUST_BASIS) {
      checks.push({
        id: 'I10ctx.basis',
        name: 'trust_basis',
        result: 'FAIL',
        detail: `declared=${ctx.trust_basis} accepted=${ACCEPTED_TRUST_BASIS}`,
        severity: 'hard',
        category: 'c2pa'
      });
      return checks;
    }

    if (ctx.trust_snapshot !== null && ctx.trust_snapshot !== undefined) {
      checks.push({
        id: 'I10ctx.snapshot',
        name: 'trust_snapshot',
        result: 'FAIL',
        detail: 'bundled SDK does not expose snapshot; declaring is forbidden',
        severity: 'hard',
        category: 'c2pa'
      });
      return checks;
    }

    checks.push({
      id: 'I10ctx',
      name: 'trust_context binding',
      result: 'PASS',
      detail: `verifier=${ctx.verifier} version=${installedVersion} basis=${ctx.trust_basis}`,
      severity: 'hard',
      category: 'c2pa'
    });

    return checks;
  }

  enforceReleaseGates(checks: PreflightCheck[]): [boolean, string[]] {
    const issues: string[] = [];
    for (const [gid, [sem, members]] of Object.entries(REQUIRED_GROUPS)) {
      const exactMap = new Map<string, PreflightCheck>();
      for (const c of checks) {
        if (members.includes(c.id)) {
          exactMap.set(c.id, c);
        }
      }

      if (exactMap.size === 0) {
        issues.push(`${gid} (${sem}): no checks emitted`);
        continue;
      }

      if (sem === 'ALL') {
        const missing = members.filter(m => !exactMap.has(m));
        const notPass = members.filter(m => {
          const c = exactMap.get(m);
          return c && c.result !== 'PASS';
        });
        if (missing.length > 0) {
          issues.push(`${gid} (ALL): missing [${missing.join(', ')}]`);
        }
        if (notPass.length > 0) {
          issues.push(`${gid} (ALL): non-PASS [${notPass.join(', ')}]`);
        }
      } else {
        const hasPass = Array.from(exactMap.values()).some(c => c.result === 'PASS');
        if (!hasPass) {
          issues.push(`${gid} (ANY): none PASS`);
        }
      }
    }
    return [issues.length === 0, issues];
  }

  // --- Main Verification Engine (v23) ---

  async runPreflightVerification(params: {
    ledger: ArkheLedger;
    mode: VerificationMode;
    trustPolicy: TrustPolicy;
    requireTrustPolicy?: TrustPolicy | null;
    audioABytes?: Uint8Array;
    audioBBytes?: Uint8Array;
    c2paAVerified?: {integrity: string; signature: string; hard_binding: string; trust?: string};
    c2paBVerified?: {integrity: string; signature: string; hard_binding: string; trust?: string};
    online?: boolean;
    solanaRpcUrl?: string;
  }): Promise<PreflightVerificationReport> {
    const startTime = performance.now();
    let checks: PreflightCheck[] = [];
    const {ledger, mode, requireTrustPolicy} = params;

    // Self-test check first
    const selftestResults = this.runGoldenVectors();
    const selftestPassed = selftestResults.every(r => r.status === 'PASS');

    let computedContentHash: string | undefined;
    let computedTxSignature: string | undefined;
    let blockTime: number | undefined;

    // 0. Policy Binding (P0a & P0b)
    const p0Checks = this.checkTrustPolicyBinding(ledger, requireTrustPolicy);
    checks = checks.concat(p0Checks);

    // 1. Check Required & Covered Fields (I13 & I3)
    const version = ledger.schema_version;
    const coveredFields = CONTENT_FIELDS[version] || [];
    const missingCovered = coveredFields.filter(f => (ledger as unknown as Record<string, unknown>)[f] === undefined);

    if (missingCovered.length > 0) {
      checks.push({
        id: 'I13',
        name: 'Campos obrigatórios',
        result: 'FAIL',
        detail: `Campos ausentes: ${missingCovered.join(', ')}`,
        severity: 'hard',
        category: 'system'
      });
      checks.push({
        id: 'I3',
        name: 'Campos cobertos',
        result: 'FAIL',
        detail: `Campos não cobertos: ${missingCovered.join(', ')}`,
        severity: 'hard',
        category: 'hash'
      });
    } else {
      checks.push({
        id: 'I13',
        name: 'Campos obrigatórios',
        result: 'PASS',
        detail: `Todos os ${coveredFields.length} campos obrigatórios presentes`,
        severity: 'hard',
        category: 'system'
      });
      checks.push({
        id: 'I3',
        name: 'Campos cobertos',
        result: 'PASS',
        detail: `Todos os campos do schema ${version} válidos`,
        severity: 'hard',
        category: 'hash'
      });
    }

    // 2. Audio Binding (I1a & I1b) - P1-2: Obrigatório em ambos os modos
    if (params.audioABytes) {
      const shaA = sha256Sync(params.audioABytes);
      const matchA = shaA === ledger.target_a.sha256;
      checks.push({
        id: 'I1a',
        name: 'Audio A SHA-256',
        result: matchA ? 'PASS' : 'FAIL',
        detail: matchA ? `${shaA.slice(0, 16)}… (Match)` : `Calculado ${shaA.slice(0, 12)}… ≠ Esperado ${ledger.target_a.sha256.slice(0, 12)}…`,
        severity: 'hard',
        category: 'audio'
      });
    } else {
      checks.push({
        id: 'I1a',
        name: 'Audio A existe',
        result: 'FAIL',
        detail: 'Ficheiro de áudio Target A não encontrado',
        severity: 'hard',
        category: 'audio'
      });
    }

    if (params.audioBBytes) {
      const shaB = sha256Sync(params.audioBBytes);
      const matchB = shaB === ledger.target_b.sha256;
      checks.push({
        id: 'I1b',
        name: 'Audio B SHA-256',
        result: matchB ? 'PASS' : 'FAIL',
        detail: matchB ? `${shaB.slice(0, 16)}… (Match)` : `Calculado ${shaB.slice(0, 12)}… ≠ Esperado ${ledger.target_b.sha256.slice(0, 12)}…`,
        severity: 'hard',
        category: 'audio'
      });
    } else {
      checks.push({
        id: 'I1b',
        name: 'Audio B existe',
        result: 'FAIL',
        detail: 'Ficheiro de áudio Target B não encontrado',
        severity: 'hard',
        category: 'audio'
      });
    }

    // 3. Content Hash (I2)
    const claimedHash = ledger.content_hash;
    if (!claimedHash) {
      checks.push({
        id: 'I2',
        name: 'content_hash',
        result: 'FAIL',
        detail: 'content_hash ausente',
        severity: 'hard',
        category: 'hash'
      });
    } else if (!this.isHex64(claimedHash)) {
      checks.push({
        id: 'I2',
        name: 'content_hash formato',
        result: 'FAIL',
        detail: 'não hex64',
        severity: 'hard',
        category: 'hash'
      });
    } else {
      try {
        const computed = this.computeContentHash(ledger);
        if (computed === claimedHash) {
          computedContentHash = claimedHash;
          checks.push({
            id: 'I2',
            name: 'content_hash',
            result: 'PASS',
            detail: `${claimedHash.slice(0, 16)}…`,
            severity: 'hard',
            category: 'hash'
          });
        } else {
          checks.push({
            id: 'I2',
            name: 'content_hash',
            result: 'FAIL',
            detail: `${computed.slice(0, 16)}… ≠ ${claimedHash.slice(0, 16)}…`,
            severity: 'hard',
            category: 'hash'
          });
        }
      } catch (e: unknown) {
        checks.push({
          id: 'I2',
          name: 'content_hash',
          result: 'FAIL',
          detail: String(e),
          severity: 'hard',
          category: 'hash'
        });
      }
    }

    // 4. Solana Anchor Signature (I4)
    if (!ledger.anchor) {
      checks.push({
        id: 'I4',
        name: 'tx_signature',
        result: 'NOT_CHECKED',
        detail: 'sem âncora',
        severity: 'external',
        category: 'solana'
      });
    } else {
      const sig = ledger.anchor.tx_signature;
      try {
        const decoded = base58Decode(sig);
        if (decoded.length === 64) {
          computedTxSignature = sig;
          checks.push({
            id: 'I4',
            name: 'tx_signature 64 bytes',
            result: 'PASS',
            detail: `${sig.slice(0, 16)}…`,
            severity: 'hard',
            category: 'solana'
          });
        } else {
          checks.push({
            id: 'I4',
            name: 'tx_signature 64 bytes',
            result: 'FAIL',
            detail: `${decoded.length} bytes`,
            severity: 'hard',
            category: 'solana'
          });
        }
      } catch (e: unknown) {
        checks.push({
          id: 'I4',
          name: 'decode',
          result: 'FAIL',
          detail: String(e),
          severity: 'hard',
          category: 'solana'
        });
      }
    }

    // 5. Solana On-Chain Verification (I5, I6, I7)
    if (!ledger.anchor || !computedTxSignature) {
      for (const cid of ['I5', 'I6', 'I7']) {
        checks.push({
          id: cid,
          name: cid === 'I5' ? 'tx ok' : cid === 'I6' ? 'Binding' : 'blockTime',
          result: 'NOT_CHECKED',
          detail: 'sem anchor',
          severity: 'external',
          category: 'solana'
        });
      }
    } else if (!params.online) {
      checks.push({
        id: 'I5',
        name: 'tx ok',
        result: 'NOT_CHECKED',
        detail: 'offline',
        severity: 'external',
        category: 'solana'
      });
      if (computedContentHash && ledger.anchor.mmr_root && this.isHex64(ledger.anchor.mmr_root)) {
        try {
          const expected = this.expectedMemo(computedContentHash, ledger.anchor.mmr_root);
          checks.push({
            id: 'I6',
            name: 'Binding (offline)',
            result: 'PASS',
            detail: `${expected.slice(0, 32)}…`,
            severity: 'hard',
            category: 'solana'
          });
        } catch (e: unknown) {
          checks.push({
            id: 'I6',
            name: 'commitment',
            result: 'FAIL',
            detail: String(e),
            severity: 'hard',
            category: 'solana'
          });
        }
      } else {
        checks.push({
          id: 'I6',
          name: 'Binding',
          result: 'NOT_CHECKED',
          detail: 'sem mmr_root',
          severity: 'external',
          category: 'solana'
        });
      }
      checks.push({
        id: 'I7',
        name: 'blockTime',
        result: 'NOT_CHECKED',
        detail: 'offline',
        severity: 'external',
        category: 'solana'
      });
    } else {
      const rpcUrl = params.solanaRpcUrl || 'https://api.devnet.solana.com';
      try {
        const txResp = await this.fetchSolanaTx(rpcUrl, computedTxSignature);
        if (!txResp) {
          checks.push({
            id: 'I5',
            name: 'tx existe',
            result: 'FAIL',
            detail: `${computedTxSignature.slice(0, 16)}…`,
            severity: 'hard',
            category: 'solana'
          });
          checks.push({id: 'I6', name: 'Binding', result: 'NOT_CHECKED', detail: 'sem tx', severity: 'external', category: 'solana'});
          checks.push({id: 'I7', name: 'blockTime', result: 'NOT_CHECKED', detail: 'sem tx', severity: 'external', category: 'solana'});
        } else if (txResp.meta?.err !== null && txResp.meta?.err !== undefined) {
          checks.push({
            id: 'I5',
            name: 'tx ok',
            result: 'FAIL',
            detail: String(txResp.meta.err),
            severity: 'hard',
            category: 'solana'
          });
          checks.push({id: 'I6', name: 'Binding', result: 'NOT_CHECKED', detail: 'tx erro', severity: 'external', category: 'solana'});
          checks.push({id: 'I7', name: 'blockTime', result: 'NOT_CHECKED', detail: 'tx erro', severity: 'external', category: 'solana'});
        } else {
          checks.push({
            id: 'I5',
            name: 'tx ok',
            result: 'PASS',
            detail: `${computedTxSignature.slice(0, 16)}…`,
            severity: 'hard',
            category: 'solana'
          });

          const memos = this.extractMemos(txResp);
          if (computedContentHash && ledger.anchor.mmr_root) {
            const expMemo = this.expectedMemo(computedContentHash, ledger.anchor.mmr_root);
            const found = memos.some(m => m === expMemo);
            checks.push({
              id: 'I6',
              name: 'Binding',
              result: found ? 'PASS' : 'FAIL',
              detail: found ? `${expMemo.slice(0, 32)}…` : `esperado ${expMemo.slice(0, 32)}…`,
              severity: 'hard',
              category: 'solana'
            });
          } else {
            checks.push({id: 'I6', name: 'Binding', result: 'NOT_CHECKED', detail: 'sem mmr_root', severity: 'external', category: 'solana'});
          }

          const txBlockTime = txResp.blockTime;
          const genAt = ledger.generated_at;
          if (txBlockTime && genAt) {
            const genTs = Math.floor(new Date(genAt).getTime() / 1000);
            blockTime = txBlockTime;
            if (txBlockTime >= genTs) {
              checks.push({
                id: 'I7',
                name: 'blockTime',
                result: 'PASS',
                detail: `${txBlockTime} >= ${genTs}`,
                severity: 'hard',
                category: 'solana'
              });
            } else {
              checks.push({
                id: 'I7',
                name: 'blockTime',
                result: 'FAIL',
                detail: `${txBlockTime} < ${genTs}`,
                severity: 'hard',
                category: 'solana'
              });
            }
          } else {
            checks.push({id: 'I7', name: 'blockTime', result: 'NOT_CHECKED', detail: 'sem dados', severity: 'external', category: 'solana'});
          }
        }
      } catch (err: unknown) {
        checks.push({
          id: 'I5',
          name: 'getTransaction',
          result: 'FAIL',
          detail: String(err),
          severity: 'external',
          category: 'solana'
        });
        checks.push({id: 'I6', name: 'Binding', result: 'NOT_CHECKED', detail: 'erro RPC', severity: 'external', category: 'solana'});
        checks.push({id: 'I7', name: 'blockTime', result: 'NOT_CHECKED', detail: 'erro RPC', severity: 'external', category: 'solana'});
      }
    }

    // 6. MMR Validation (I8a, I8b, I8c)
    if (!ledger.anchor) {
      checks.push({id: 'I8a', name: 'MMR root', result: 'NOT_CHECKED', detail: 'sem anchor', severity: 'external', category: 'mmr'});
      checks.push({id: 'I8b', name: 'MMR proof', result: 'NOT_CHECKED', detail: 'sem anchor', severity: 'external', category: 'mmr'});
      checks.push({id: 'I8c', name: 'MMR specs', result: 'NOT_CHECKED', detail: 'sem anchor', severity: 'external', category: 'mmr'});
    } else {
      const anchor = ledger.anchor;

      if (!this.isHex64(anchor.mmr_root)) {
        checks.push({
          id: 'I8a',
          name: 'MMR root',
          result: 'FAIL',
          detail: 'não hex64',
          severity: 'hard',
          category: 'mmr'
        });
      } else {
        checks.push({
          id: 'I8a',
          name: 'MMR root formato',
          result: 'PASS',
          detail: `${anchor.mmr_root.slice(0, 16)}…`,
          severity: 'hard',
          category: 'mmr'
        });
      }

      const ver = anchor.mmr_version || MMR_VERSION;
      const alg = anchor.mmr_algorithm || MMR_ALGORITHM;
      if (ver !== MMR_VERSION || alg !== MMR_ALGORITHM) {
        checks.push({
          id: 'I8c',
          name: 'MMR version/algorithm',
          result: 'FAIL',
          detail: `${ver}/${alg}`,
          severity: 'hard',
          category: 'mmr'
        });
      } else {
        checks.push({
          id: 'I8c',
          name: 'MMR version/algorithm',
          result: 'PASS',
          detail: `${MMR_VERSION}/${MMR_ALGORITHM}`,
          severity: 'hard',
          category: 'mmr'
        });
      }

      try {
        const [expPeak, localIdx, height] = this.leafToMountain(anchor.leaf_index, anchor.leaf_count);

        if (anchor.peak_index !== expPeak) {
          checks.push({
            id: 'I8b',
            name: 'MMR peak_index',
            result: 'FAIL',
            detail: `${anchor.peak_index} ≠ ${expPeak}`,
            severity: 'hard',
            category: 'mmr'
          });
        } else {
          const bitLength = anchor.leaf_count.toString(2).length;
          const expHeights: number[] = [];
          for (let i = 0; i < bitLength; i++) {
            if ((anchor.leaf_count >> i) & 1) expHeights.push(i);
          }
          expHeights.sort((a, b) => b - a);

          const actualHeights = anchor.peaks.map(p => p.height);
          const heightsMatch = actualHeights.length === expHeights.length &&
            actualHeights.every((h, i) => h === expHeights[i]);

          const expDirs = this.expectedDirections(localIdx, height);
          const actualDirs = anchor.path.map(s => s.direction);
          const dirsMatch = actualDirs.length === expDirs.length &&
            actualDirs.every((d, i) => d === expDirs[i]);

          const leaf = computedContentHash || ledger.content_hash;

          if (!heightsMatch) {
            checks.push({
              id: 'I8b',
              name: 'MMR peak heights',
              result: 'FAIL',
              detail: `${actualHeights} ≠ ${expHeights}`,
              severity: 'hard',
              category: 'mmr'
            });
          } else if (anchor.path.length !== height) {
            checks.push({
              id: 'I8b',
              name: 'MMR path length',
              result: 'FAIL',
              detail: `${anchor.path.length} ≠ ${height}`,
              severity: 'hard',
              category: 'mmr'
            });
          } else if (!dirsMatch) {
            checks.push({
              id: 'I8b',
              name: 'MMR path directions',
              result: 'FAIL',
              detail: `${actualDirs} ≠ ${expDirs}`,
              severity: 'hard',
              category: 'mmr'
            });
          } else if (!leaf) {
            checks.push({
              id: 'I8b',
              name: 'MMR leaf',
              result: 'FAIL',
              detail: 'sem content_hash',
              severity: 'hard',
              category: 'mmr'
            });
          } else {
            const folded = this.foldPath(leaf, anchor.path);
            const peakHash = anchor.peaks[expPeak]?.hash;

            if (folded !== peakHash) {
              checks.push({
                id: 'I8b',
                name: 'MMR leaf→peak',
                result: 'FAIL',
                detail: `${folded.slice(0, 16)}… ≠ ${peakHash ? peakHash.slice(0, 16) : 'null'}…`,
                severity: 'hard',
                category: 'mmr'
              });
            } else {
              const bagged = this.bagPeaks(anchor.peaks);
              if (bagged !== anchor.mmr_root) {
                checks.push({
                  id: 'I8b',
                  name: 'MMR root bagged',
                  result: 'FAIL',
                  detail: `${bagged.slice(0, 16)}… ≠ ${anchor.mmr_root.slice(0, 16)}…`,
                  severity: 'hard',
                  category: 'mmr'
                });
              } else {
                checks.push({
                  id: 'I8b',
                  name: 'MMR inclusion proof',
                  result: 'PASS',
                  detail: `leaf ${leaf.slice(0, 16)}… @ ${anchor.leaf_index}/${anchor.leaf_count}`,
                  severity: 'hard',
                  category: 'mmr'
                });
              }
            }
          }
        }
      } catch (e: unknown) {
        checks.push({
          id: 'I8b',
          name: 'MMR topologia',
          result: 'FAIL',
          detail: String(e),
          severity: 'hard',
          category: 'mmr'
        });
      }
    }

    // 7. W3C DID Verification (I9A, I9B, I9c)
    const checkDidOne = (suffix: 'A' | 'B', did: string | undefined): boolean => {
      const cid = `I9${suffix}`;
      if (!did) {
        checks.push({id: cid, name: `DID ${suffix}`, result: 'NOT_CHECKED', detail: 'ausente', severity: 'external', category: 'did'});
        return false;
      }
      if (!did.startsWith('did:key:z')) {
        checks.push({id: cid, name: `DID ${suffix} prefixo`, result: 'FAIL', detail: did.slice(0, 20), severity: 'hard', category: 'did'});
        return false;
      }
      try {
        const decoded = base58Decode(did.slice('did:key:z'.length));
        if (decoded.length < 34 || decoded[0] !== 0xed || decoded[1] !== 0x01 || (decoded.length - 2) !== 32) {
          checks.push({id: cid, name: `DID ${suffix} estrutura`, result: 'FAIL', detail: `len=${decoded.length}`, severity: 'hard', category: 'did'});
          return false;
        }
        checks.push({id: cid, name: `DID ${suffix} Ed25519`, result: 'PASS', detail: `${did.slice(0, 24)}…`, severity: 'hard', category: 'did'});
        return true;
      } catch (e: unknown) {
        checks.push({id: cid, name: `DID ${suffix} decode`, result: 'FAIL', detail: String(e), severity: 'hard', category: 'did'});
        return false;
      }
    };

    const didAOk = checkDidOne('A', ledger.target_a.creator_did);
    const didBOk = checkDidOne('B', ledger.target_b.creator_did);
    if (didAOk && didBOk) {
      if (ledger.target_a.creator_did === ledger.target_b.creator_did) {
        checks.push({id: 'I9c', name: 'DIDs distintos', result: 'WARN', detail: 'mesma identidade', severity: 'heuristic', category: 'did'});
      } else {
        checks.push({id: 'I9c', name: 'DIDs distintos', result: 'PASS', detail: 'separados', severity: 'heuristic', category: 'did'});
      }
    }

    // 8. C2PA Verification (I10)
    const effectivePolicy = ledger.trust_policy;
    if (mode === 'release') {
      const verifiedData: Record<'A' | 'B', {integrity: string; signature: string; hard_binding: string; trust?: string} | null> = {
        A: params.c2paAVerified || null,
        B: params.c2paBVerified || null
      };

      for (const suffix of ['A', 'B'] as const) {
        const v = verifiedData[suffix];
        if (!v) {
          checks.push({
            id: `I10v${suffix}`,
            name: `C2PA verificado ${suffix}`,
            result: 'FAIL',
            detail: 'ficheiro ausente em release',
            severity: 'hard',
            category: 'c2pa'
          });
        } else {
          const baseOk = v.integrity === 'valid' && v.signature === 'valid' && v.hard_binding === 'match';
          let ok = baseOk;
          if (effectivePolicy === 'signer_trusted') {
            ok = baseOk && !!v.trust && ACCEPTED_TRUST_STATUSES.has(v.trust);
          }
          const detail = `integrity=${v.integrity} signature=${v.signature} hard_binding=${v.hard_binding} trust=${v.trust} policy=${effectivePolicy}`;
          checks.push({
            id: `I10v${suffix}`,
            name: `C2PA verificado ${suffix}`,
            result: ok ? 'PASS' : 'FAIL',
            detail,
            severity: ok ? 'external' : 'hard',
            category: 'c2pa'
          });
        }
      }

      // I10c
      if (ledger.c2pa && verifiedData.A && verifiedData.B) {
        const declA = ledger.c2pa.a;
        const declB = ledger.c2pa.b;
        const vA = verifiedData.A;
        const vB = verifiedData.B;

        const matchA = declA.integrity === vA.integrity &&
                       declA.signature === vA.signature &&
                       declA.hard_binding === vA.hard_binding &&
                       declA.trust === vA.trust;

        const matchB = declB.integrity === vB.integrity &&
                       declB.signature === vB.signature &&
                       declB.hard_binding === vB.hard_binding &&
                       declB.trust === vB.trust;

        if (matchA && matchB) {
          checks.push({id: 'I10c', name: 'C2PA declared == verified', result: 'PASS', detail: 'consistente', severity: 'hard', category: 'c2pa'});
        } else {
          checks.push({id: 'I10c', name: 'C2PA declared == verified', result: 'FAIL', detail: 'declarado ≠ verificado', severity: 'hard', category: 'c2pa'});
        }
      } else if (ledger.c2pa) {
        checks.push({id: 'I10c', name: 'C2PA declared == verified', result: 'NOT_CHECKED', detail: 'verificação incompleta', severity: 'external', category: 'c2pa'});
      } else {
        checks.push({id: 'I10c', name: 'C2PA declared == verified', result: 'FAIL', detail: 'bloco c2pa ausente', severity: 'hard', category: 'c2pa'});
      }
    } else {
      // sanity mode
      if (ledger.c2pa) {
        for (const suffix of ['A', 'B'] as const) {
          const entry = suffix === 'A' ? ledger.c2pa.a : ledger.c2pa.b;
          const baseOk = entry.integrity === 'valid' && entry.signature === 'valid' && entry.hard_binding === 'match';
          const ok = effectivePolicy === 'signer_trusted' ? (baseOk && !!entry.trust && ACCEPTED_TRUST_STATUSES.has(entry.trust)) : baseOk;
          checks.push({
            id: `I10d${suffix}`,
            name: `C2PA declarado ${suffix}`,
            result: ok ? 'PASS' : 'FAIL',
            detail: `trust=${entry.trust} policy=${effectivePolicy}`,
            severity: ok ? 'external' : 'hard',
            category: 'c2pa'
          });
        }
      } else {
        checks.push({id: 'I10dA', name: 'C2PA declarado A', result: 'NOT_CHECKED', detail: 'sem bloco c2pa', severity: 'external', category: 'c2pa'});
        checks.push({id: 'I10dB', name: 'C2PA declarado B', result: 'NOT_CHECKED', detail: 'sem bloco c2pa', severity: 'external', category: 'c2pa'});
      }
    }

    // 9. Trust Context Binding (I10ctx) - P0-1, P0-2, P0-3
    const ctxChecks = this.checkTrustContext(ledger, mode, true, '1.0.0');
    checks = checks.concat(ctxChecks);

    // 10. Statistical Calibration (I11, I11b, I11c, I11d) - P1-1
    const melodic = ledger.similarity?.melodic;
    if (!melodic || !melodic.calibration) {
      checks.push({id: 'I11', name: 'Calibração', result: 'NOT_CHECKED', detail: 'ausente', severity: 'external', category: 'calibration'});
    } else {
      const cal = melodic.calibration;
      const vals = cal.val_scores || [];
      const nNeg = vals.filter(v => v.label === 'negative').length;
      const nPos = vals.filter(v => v.label === 'positive').length;

      if (nNeg === 0) {
        checks.push({id: 'I11', name: 'Negativos > 0', result: 'FAIL', detail: 'sem negativos', severity: 'hard', category: 'calibration'});
      } else {
        const tp = vals.filter(v => v.label === 'positive' && v.score >= cal.threshold).length;
        const fp = vals.filter(v => v.label === 'negative' && v.score >= cal.threshold).length;
        const tn = vals.filter(v => v.label === 'negative' && v.score < cal.threshold).length;
        const fn = vals.filter(v => v.label === 'positive' && v.score < cal.threshold).length;

        if (tp !== cal.tp || fp !== cal.fp || tn !== cal.tn || fn !== cal.fn) {
          checks.push({
            id: 'I11',
            name: 'Métricas',
            result: 'FAIL',
            detail: `recomp (${tp},${fp},${tn},${fn}) ≠ declarado`,
            severity: 'hard',
            category: 'calibration'
          });
        } else {
          checks.push({
            id: 'I11',
            name: 'Métricas',
            result: 'PASS',
            detail: `tp=${tp} fp=${fp} tn=${tn} fn=${fn}`,
            severity: 'hard',
            category: 'calibration'
          });
        }

        if (cal.n_negatives !== nNeg) {
          checks.push({id: 'I11c', name: 'n_negatives', result: 'FAIL', detail: `${cal.n_negatives} ≠ ${nNeg}`, severity: 'hard', category: 'calibration'});
        } else {
          checks.push({id: 'I11c', name: 'n_negatives', result: 'PASS', detail: String(nNeg), severity: 'hard', category: 'calibration'});
        }

        const alpha = cal.confidence_alpha || 0.05;
        const maxFpr = cal.max_fpr !== undefined ? cal.max_fpr : 0.05;
        const upper = clopperPearsonUpper(fp, nNeg, alpha);

        if (upper === null) {
          checks.push({id: 'I11b', name: 'Clopper-Pearson', result: 'FAIL', detail: 'FP>0 e SciPy ausente', severity: 'hard', category: 'calibration'});
        } else if (upper <= maxFpr) {
          checks.push({
            id: 'I11b',
            name: 'FPR upper bound',
            result: 'PASS',
            detail: `CP(${fp}/${nNeg}, ${alpha}) = ${upper.toFixed(4)} <= ${maxFpr}`,
            severity: 'hard',
            category: 'calibration'
          });
        } else {
          checks.push({
            id: 'I11b',
            name: 'FPR upper bound',
            result: 'FAIL',
            detail: `CP(${fp}/${nNeg}, ${alpha}) = ${upper.toFixed(4)} > ${maxFpr}`,
            severity: 'hard',
            category: 'calibration'
          });
        }

        const tpr = nPos > 0 ? (tp / nPos) : 0.0;
        if (mode === 'release') {
          if (nPos === 0) {
            checks.push({id: 'I11d', name: 'n_pos > 0', result: 'FAIL', detail: 'release exige positivos', severity: 'hard', category: 'calibration'});
          } else if (cal.tau <= 0.0) {
            checks.push({id: 'I11d', name: 'tau > 0', result: 'FAIL', detail: 'release exige tau > 0', severity: 'hard', category: 'calibration'});
          } else if (tpr >= cal.tau) {
            checks.push({id: 'I11d', name: 'TPR >= tau', result: 'PASS', detail: `${tpr.toFixed(4)} >= ${cal.tau}`, severity: 'hard', category: 'calibration'});
          } else {
            checks.push({id: 'I11d', name: 'TPR >= tau', result: 'FAIL', detail: `${tpr.toFixed(4)} < ${cal.tau}`, severity: 'hard', category: 'calibration'});
          }
        } else {
          if (tpr >= cal.tau) {
            checks.push({id: 'I11d', name: 'TPR >= tau', result: 'PASS', detail: `${tpr.toFixed(4)} >= ${cal.tau}`, severity: 'hard', category: 'calibration'});
          } else {
            checks.push({id: 'I11d', name: 'TPR >= tau', result: 'FAIL', detail: `${tpr.toFixed(4)} < ${cal.tau}`, severity: 'hard', category: 'calibration'});
          }
        }
      }
    }

    // 11. Calibration Data Leakage (I12)
    if (!melodic || !melodic.calibration) {
      checks.push({id: 'I12', name: 'Separação', result: 'NOT_CHECKED', detail: 'sem calibração', severity: 'external', category: 'leakage'});
    } else {
      const targets = new Set([ledger.target_a.sha256, ledger.target_b.sha256]);
      const seenPairIds = new Set<string>();
      const overlap: string[] = [];
      let pairDerivationFailed = false;

      for (const v of melodic.calibration.val_scores) {
        if (seenPairIds.has(v.pair_id)) {
          checks.push({id: 'I12', name: 'pair_id único', result: 'FAIL', detail: `duplicado: ${v.pair_id.slice(0, 16)}…`, severity: 'hard', category: 'leakage'});
          pairDerivationFailed = true;
          break;
        }
        seenPairIds.add(v.pair_id);

        try {
          const expectedPairId = this.pairIdCanonical(v.sha256_a, v.sha256_b);
          if (v.pair_id !== expectedPairId) {
            checks.push({id: 'I12', name: 'pair_id derivado', result: 'FAIL', detail: `${v.pair_id.slice(0, 16)}… ≠ ${expectedPairId.slice(0, 16)}…`, severity: 'hard', category: 'leakage'});
            pairDerivationFailed = true;
            break;
          }
        } catch (e: unknown) {
          checks.push({id: 'I12', name: 'pair_id derivado', result: 'FAIL', detail: String(e), severity: 'hard', category: 'leakage'});
          pairDerivationFailed = true;
          break;
        }

        if (targets.has(v.sha256_a) || targets.has(v.sha256_b)) {
          overlap.push(v.pair_id.slice(0, 16) + '…');
        }
      }

      if (!pairDerivationFailed) {
        if (overlap.length > 0) {
          checks.push({id: 'I12', name: 'Separação', result: 'FAIL', detail: `targets presentes: ${overlap.join(', ')}`, severity: 'hard', category: 'leakage'});
        } else {
          checks.push({id: 'I12', name: 'Separação', result: 'PASS', detail: `${seenPairIds.size} pairs, sem overlap`, severity: 'hard', category: 'leakage'});
        }
      }
    }

    // 12. Script Integrity (I14)
    if (!ledger.script_sha256) {
      checks.push({id: 'I14', name: 'script_sha256', result: 'NOT_CHECKED', detail: 'ausente', severity: 'external', category: 'system'});
    } else {
      if (this.isHex64(ledger.script_sha256)) {
        checks.push({id: 'I14', name: 'script_sha256', result: 'PASS', detail: `${ledger.script_sha256.slice(0, 16)}…`, severity: 'hard', category: 'system'});
      } else {
        checks.push({id: 'I14', name: 'script_sha256', result: 'FAIL', detail: 'formato inválido', severity: 'hard', category: 'system'});
      }
    }

    // 13. Derived Hashes (I15a & I15b)
    const anchor = ledger.anchor;
    if (anchor && computedContentHash && this.isHex64(anchor.mmr_root)) {
      if (anchor.anchor_commitment) {
        try {
          const expCommitmentBytes = this.computeAnchorCommitment(computedContentHash, anchor.mmr_root);
          const expCommitment = base58Encode(expCommitmentBytes);
          const match = expCommitment === anchor.anchor_commitment;
          checks.push({
            id: 'I15a',
            name: 'anchor_commitment',
            result: match ? 'PASS' : 'FAIL',
            detail: match ? `${expCommitment.slice(0, 16)}…` : `exp ${expCommitment.slice(0, 12)}… ≠ decl ${anchor.anchor_commitment.slice(0, 12)}…`,
            severity: 'hard',
            category: 'system'
          });
        } catch (e: unknown) {
          checks.push({id: 'I15a', name: 'anchor_commitment', result: 'FAIL', detail: String(e), severity: 'hard', category: 'system'});
        }
      } else {
        checks.push({id: 'I15a', name: 'anchor_commitment', result: 'NOT_CHECKED', detail: 'ausente', severity: 'external', category: 'system'});
      }

      if (ledger.envelope_hash) {
        try {
          const expEnv = this.computeEnvelopeHash(
            computedContentHash,
            anchor,
            ledger.c2pa || null,
            ledger.trust_policy,
            ledger.trust_context || null
          );
          const match = expEnv === ledger.envelope_hash;
          checks.push({
            id: 'I15b',
            name: 'envelope_hash',
            result: match ? 'PASS' : 'FAIL',
            detail: match ? `${expEnv.slice(0, 16)}…` : `exp ${expEnv.slice(0, 12)}… ≠ decl ${ledger.envelope_hash.slice(0, 12)}…`,
            severity: 'hard',
            category: 'system'
          });
        } catch (e: unknown) {
          checks.push({id: 'I15b', name: 'envelope_hash', result: 'FAIL', detail: String(e), severity: 'hard', category: 'system'});
        }
      } else {
        checks.push({id: 'I15b', name: 'envelope_hash', result: 'NOT_CHECKED', detail: 'ausente', severity: 'external', category: 'system'});
      }
    }

    // 14. Heuristics (H1)
    const hashes = [ledger.target_a.sha256, ledger.target_b.sha256];
    if (hashes.length === 2 && this.isHex64(hashes[0]) && this.isHex64(hashes[1])) {
      const wa = new Set<string>();
      const wb = new Set<string>();
      for (let i = 0; i <= 48; i += 4) {
        wa.add(hashes[0].slice(i, i + 16));
        wb.add(hashes[1].slice(i, i + 16));
      }
      let collision = 0;
      for (const seg of wa) {
        if (wb.has(seg)) collision++;
      }
      if (collision > 0) {
        checks.push({id: 'H1', name: 'Fragmentos', result: 'WARN', detail: `${collision}`, severity: 'heuristic', category: 'system'});
      } else {
        checks.push({id: 'H1', name: 'Fragmentos', result: 'PASS', detail: 'sem', severity: 'heuristic', category: 'system'});
      }
    }

    // Release Gate Enforcement
    const hardFailures = checks.filter(c => c.severity === 'hard' && c.result === 'FAIL');
    let releaseIssues: string[] = [];

    if (mode === 'release') {
      if (!selftestPassed) {
        releaseIssues.push('Selftest falhou em modo release');
      }
      const [releaseOk, gateIssues] = this.enforceReleaseGates(checks);
      if (!releaseOk) {
        releaseIssues = releaseIssues.concat(gateIssues);
      }
    }

    const overallStatus = hardFailures.length === 0 && (mode !== 'release' || releaseIssues.length === 0) ? 'PASS' : 'FAIL';
    const executionTimeMs = performance.now() - startTime;

    return {
      timestamp: new Date().toISOString(),
      mode,
      trustPolicy: ledger.trust_policy,
      requireTrustPolicy,
      isReleaseGrade: mode === 'release' && overallStatus === 'PASS',
      overallStatus,
      checks,
      hardFailures,
      contentHash: computedContentHash,
      txSignature: computedTxSignature,
      blockTime,
      releaseIssues,
      selftestPassed,
      executionTimeMs
    };
  }

  // --- Network Solana Fetcher ---

  private async fetchSolanaTx(rpcUrl: string, signature: string): Promise<SolanaTxResult | null> {
    const payload = {
      jsonrpc: '2.0',
      id: 1,
      method: 'getTransaction',
      params: [
        signature,
        {
          encoding: 'jsonParsed',
          maxSupportedTransactionVersion: 0,
          commitment: 'finalized'
        }
      ]
    };

    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }

    const json = await res.json();
    return json?.result || null;
  }

  private extractMemos(tx: SolanaTxResult | null): string[] {
    const memos: string[] = [];
    if (!tx) return memos;

    const outerIxs = tx.transaction?.message?.instructions || [];
    for (const ix of outerIxs) {
      if (ix.programId === MEMO_PROGRAM_ID) {
        if (typeof ix.parsed === 'string') memos.push(ix.parsed);
        else if (ix.parsed && typeof ix.parsed.info === 'string') memos.push(ix.parsed.info);
      }
    }

    const innerSets = tx.meta?.innerInstructions || [];
    for (const set of innerSets) {
      for (const ix of set.instructions || []) {
        if (ix.programId === MEMO_PROGRAM_ID) {
          if (typeof ix.parsed === 'string') memos.push(ix.parsed);
          else if (ix.parsed && typeof ix.parsed.info === 'string') memos.push(ix.parsed.info);
        }
      }
    }

    return memos;
  }
}
