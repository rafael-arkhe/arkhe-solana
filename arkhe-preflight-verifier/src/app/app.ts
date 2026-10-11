import {ChangeDetectionStrategy, Component, computed, inject, signal} from '@angular/core';
import {CommonModule} from '@angular/common';
import {MatIconModule} from '@angular/material/icon';
import {
  ArkheLedger,
  GoldenVectorResult,
  PreflightCheck,
  PreflightVerificationReport,
  TrustPolicy,
  VerificationMode
} from './models/arkhe.types';
import {ArkheVerifierService} from './services/arkhe-verifier.service';
import {SolanaWeb3Service} from './services/solana-web3.service';
import {SOLANA_CLUSTERS, SolanaCluster} from './models/solana.types';
import {buildSampleScenarios, SampleScenario} from './services/sample-ledgers';
import {clopperPearsonUpper, sha256Sync, base58Encode} from './services/crypto-utils';

export type NavTab =
  | 'cockpit'
  | 'audio'
  | 'matrix'
  | 'mmr'
  | 'c2pa'
  | 'solana'
  | 'calibration'
  | 'selftest'
  | 'editor';

export interface MmrNodeVisual {
  id: string;
  label: string;
  x: number;
  y: number;
  height: number;
  isPeak: boolean;
  isInPath: boolean;
  isTargetLeaf: boolean;
}

export interface MmrEdgeVisual {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'app-root',
  imports: [CommonModule, MatIconModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  private verifier = inject(ArkheVerifierService);
  readonly solanaService = inject(SolanaWeb3Service);

  // Web3 & Solana signals
  readonly solanaCluster = this.solanaService.selectedCluster;
  readonly solanaWallet = this.solanaService.walletState;
  readonly anchorProgress = this.solanaService.anchorProgress;
  readonly inspectedTx = this.solanaService.inspectedTx;
  readonly isInspectingTx = this.solanaService.isInspecting;
  readonly rpcLatencyMs = this.solanaService.rpcLatencyMs;
  readonly inspectSearchSignature = signal<string>('');
  readonly availableClusters = Object.values(SOLANA_CLUSTERS);

  // Scenarios repository
  readonly scenarios = signal<SampleScenario[]>(buildSampleScenarios());
  readonly selectedScenarioId = signal<string>('valid-release');

  // Active configurations
  readonly activeTab = signal<NavTab>('cockpit');
  readonly mode = signal<VerificationMode>('release');
  readonly requireTrustPolicy = signal<'none' | TrustPolicy>('none');
  readonly online = signal<boolean>(false);
  readonly solanaRpcUrl = signal<string>('https://api.devnet.solana.com');

  // Ledger state
  readonly currentLedger = signal<ArkheLedger>(this.scenarios()[0].ledger);
  readonly rawJsonString = signal<string>(JSON.stringify(this.scenarios()[0].ledger, null, 2));
  readonly jsonError = signal<string | null>(null);

  // Audio payloads
  readonly audioAName = signal<string>(this.scenarios()[0].audioAName);
  readonly audioBName = signal<string>(this.scenarios()[0].audioBName);
  readonly audioABytes = signal<Uint8Array | null>(this.scenarios()[0].audioABytes);
  readonly audioBBytes = signal<Uint8Array | null>(this.scenarios()[0].audioBBytes);

  // Audio playback state
  private audioContext: AudioContext | null = null;
  private currentAudioSource: AudioBufferSourceNode | null = null;
  readonly currentlyPlaying = signal<'A' | 'B' | null>(null);
  readonly audioPlayProgress = signal<number>(0);
  private playbackTimer: ReturnType<typeof setInterval> | null = null;

  // C2PA verified objects
  readonly c2paAVerified = signal<{integrity: string; signature: string; hard_binding: string; trust: string}>(
    this.scenarios()[0].c2paAVerified
  );
  readonly c2paBVerified = signal<{integrity: string; signature: string; hard_binding: string; trust: string}>(
    this.scenarios()[0].c2paBVerified
  );

  // Verification results
  readonly verificationReport = signal<PreflightVerificationReport | null>(null);
  readonly isVerifying = signal<boolean>(false);
  readonly goldenVectors = signal<GoldenVectorResult[]>(this.verifier.runGoldenVectors());
  readonly copyNotification = signal<string | null>(null);

  // Detail Modal / Inspector for Check
  readonly selectedCheck = signal<PreflightCheck | null>(null);

  // MMR Interactive Playground
  readonly calcLeafIndex = signal<number>(0);
  readonly calcLeafCount = signal<number>(7);

  // Clopper-Pearson Sandbox
  readonly cpTrials = signal<number>(100);
  readonly cpFailures = signal<number>(1);
  readonly cpAlpha = signal<number>(0.05);

  // Filter for Matrix checks
  readonly matrixFilter = signal<string>('all');
  readonly matrixSearchQuery = signal<string>('');

  // Computed Metrics
  readonly filteredChecks = computed(() => {
    const report = this.verificationReport();
    if (!report) return [];
    let list = report.checks;
    const f = this.matrixFilter();
    if (f === 'fail') list = list.filter(c => c.result === 'FAIL');
    else if (f === 'pass') list = list.filter(c => c.result === 'PASS');
    else if (f === 'warn') list = list.filter(c => c.result === 'WARN');
    else if (f !== 'all') list = list.filter(c => c.category === f);

    const q = this.matrixSearchQuery().toLowerCase().trim();
    if (q) {
      list = list.filter(c =>
        c.id.toLowerCase().includes(q) ||
        c.name.toLowerCase().includes(q) ||
        c.detail.toLowerCase().includes(q)
      );
    }
    return list;
  });

  readonly passCount = computed(() => {
    const r = this.verificationReport();
    return r ? r.checks.filter(c => c.result === 'PASS').length : 0;
  });

  readonly failCount = computed(() => {
    const r = this.verificationReport();
    return r ? r.checks.filter(c => c.result === 'FAIL').length : 0;
  });

  readonly warnCount = computed(() => {
    const r = this.verificationReport();
    return r ? r.checks.filter(c => c.result === 'WARN').length : 0;
  });

  readonly notCheckedCount = computed(() => {
    const r = this.verificationReport();
    return r ? r.checks.filter(c => c.result === 'NOT_CHECKED').length : 0;
  });

  // Clopper-Pearson live calculation
  readonly cpUpperComputed = computed(() => {
    const k = this.cpFailures();
    const n = this.cpTrials();
    const alpha = this.cpAlpha();
    if (n <= 0 || k < 0 || k > n) return {upper: 0, percentage: '0.000', passesGate: false};
    const upper = clopperPearsonUpper(k, n, alpha);
    if (upper === null) {
      return {upper: 0, percentage: '0.000', passesGate: false};
    }
    return {
      upper,
      percentage: (upper * 100).toFixed(3),
      passesGate: upper <= 0.05
    };
  });

  treeLeavesForHeight(height: number | undefined): number {
    return height !== undefined && height >= 0 ? 1 << height : 0;
  }

  // MMR Mountain Calculation & Visual Tree
  readonly calcMountainResult = computed(() => {
    const idx = this.calcLeafIndex();
    const count = this.calcLeafCount();
    try {
      const [peakIndex, localIdx, height] = this.verifier.leafToMountain(idx, count);
      const directions = this.verifier.expectedDirections(localIdx, height);
      const bitLength = count.toString(2).length;
      const expHeights: number[] = [];
      for (let i = 0; i < bitLength; i++) {
        if ((count >> i) & 1) expHeights.push(i);
      }
      expHeights.sort((a, b) => b - a);

      return {
        valid: true,
        peakIndex,
        localIdx,
        height,
        directions,
        expHeights,
        error: null
      };
    } catch (e: unknown) {
      return {
        valid: false,
        peakIndex: 0,
        localIdx: 0,
        height: 0,
        directions: [],
        expHeights: [],
        error: String(e)
      };
    }
  });

  // Visual SVG Tree Nodes for MMR
  readonly mmrSvgVisual = computed(() => {
    const count = this.calcLeafCount();
    const targetLeaf = this.calcLeafIndex();
    const nodes: MmrNodeVisual[] = [];
    const edges: MmrEdgeVisual[] = [];

    // Binary decomposition of count
    let remaining = count;
    let leafOffset = 0;
    let peakIndex = 0;
    let currentX = 40;
    const baseY = 240;

    while (remaining > 0) {
      const bitLen = Math.floor(Math.log2(remaining));
      const treeLeaves = 1 << bitLen;
      const height = bitLen;

      // Build balanced binary tree of height
      // Bottom leaves
      const leafXs: number[] = [];
      for (let i = 0; i < treeLeaves; i++) {
        const globalLeaf = leafOffset + i;
        const x = currentX + i * 44;
        leafXs.push(x);
        nodes.push({
          id: `leaf-${globalLeaf}`,
          label: `L${globalLeaf}`,
          x,
          y: baseY,
          height: 0,
          isPeak: height === 0,
          isInPath: globalLeaf === targetLeaf,
          isTargetLeaf: globalLeaf === targetLeaf
        });
      }

      // Internal nodes up to peak
      let prevLevelXs = leafXs;
      let prevLevelY = baseY;
      for (let h = 1; h <= height; h++) {
        const currentLevelXs: number[] = [];
        const levelY = baseY - h * 50;
        for (let j = 0; j < prevLevelXs.length; j += 2) {
          const parentX = (prevLevelXs[j] + prevLevelXs[j + 1]) / 2;
          currentLevelXs.push(parentX);
          const isPeak = h === height;
          nodes.push({
            id: `node-h${h}-p${peakIndex}-${j / 2}`,
            label: isPeak ? `Peak ${peakIndex} (H${h})` : `H${h}`,
            x: parentX,
            y: levelY,
            height: h,
            isPeak,
            isInPath: false,
            isTargetLeaf: false
          });
          edges.push({x1: prevLevelXs[j], y1: prevLevelY - 14, x2: parentX, y2: levelY + 14});
          edges.push({x1: prevLevelXs[j + 1], y1: prevLevelY - 14, x2: parentX, y2: levelY + 14});
        }
        prevLevelXs = currentLevelXs;
        prevLevelY = levelY;
      }

      currentX += treeLeaves * 44 + 30;
      leafOffset += treeLeaves;
      remaining -= treeLeaves;
      peakIndex++;
    }

    return {nodes, edges, width: Math.max(760, currentX + 60), height: 320};
  });

  // Audio waveforms computed points
  readonly audioAWaveformPoints = computed(() => {
    return this.generateWaveformPoints(this.audioABytes());
  });

  readonly audioBWaveformPoints = computed(() => {
    return this.generateWaveformPoints(this.audioBBytes());
  });

  readonly audioAComputedSha = computed(() => {
    const bytes = this.audioABytes();
    return bytes ? sha256Sync(bytes) : '—';
  });

  readonly audioBComputedSha = computed(() => {
    const bytes = this.audioBBytes();
    return bytes ? sha256Sync(bytes) : '—';
  });

  readonly audioASizeKb = computed(() => {
    const bytes = this.audioABytes();
    return bytes ? (bytes.length / 1024).toFixed(1) : '0';
  });

  readonly audioBSizeKb = computed(() => {
    const bytes = this.audioBBytes();
    return bytes ? (bytes.length / 1024).toFixed(1) : '0';
  });

  constructor() {
    this.executeVerification();
  }

  // --- Navigation & Mode Actions ---

  setTab(tab: NavTab) {
    this.activeTab.set(tab);
  }

  setMode(m: VerificationMode) {
    this.mode.set(m);
    this.executeVerification();
  }

  setRequireTrustPolicy(p: 'none' | TrustPolicy) {
    this.requireTrustPolicy.set(p);
    this.executeVerification();
  }

  toggleArtifactTrustPolicy() {
    const current = this.currentLedger();
    const nextPolicy: TrustPolicy = current.trust_policy === 'signer_trusted' ? 'integrity_only' : 'signer_trusted';
    const cloned = JSON.parse(JSON.stringify(current));
    cloned.trust_policy = nextPolicy;
    cloned.content_hash = this.verifier.computeContentHash(cloned);
    this.currentLedger.set(cloned);
    this.rawJsonString.set(JSON.stringify(cloned, null, 2));
    this.executeVerification();
    this.showToast(`Política do artefato alterada para: ${nextPolicy}`);
  }

  toggleOnline() {
    this.online.update(v => !v);
    this.executeVerification();
  }

  selectScenario(id: string) {
    const found = this.scenarios().find(s => s.id === id);
    if (!found) return;
    this.stopAudio();
    this.selectedScenarioId.set(id);
    this.currentLedger.set(found.ledger);
    this.rawJsonString.set(JSON.stringify(found.ledger, null, 2));
    this.jsonError.set(null);
    this.audioABytes.set(found.audioABytes);
    this.audioBBytes.set(found.audioBBytes);
    this.audioAName.set(found.audioAName);
    this.audioBName.set(found.audioBName);
    this.c2paAVerified.set(found.c2paAVerified);
    this.c2paBVerified.set(found.c2paBVerified);
    this.executeVerification();
  }

  async executeVerification() {
    this.isVerifying.set(true);
    try {
      const selectedReq = this.requireTrustPolicy();
      const reqPolicy: TrustPolicy | null = selectedReq === 'none' ? null : selectedReq;
      const rep = await this.verifier.runPreflightVerification({
        ledger: this.currentLedger(),
        mode: this.mode(),
        trustPolicy: this.currentLedger().trust_policy,
        requireTrustPolicy: reqPolicy,
        audioABytes: this.audioABytes() || undefined,
        audioBBytes: this.audioBBytes() || undefined,
        c2paAVerified: this.c2paAVerified(),
        c2paBVerified: this.c2paBVerified(),
        online: this.online(),
        solanaRpcUrl: this.solanaRpcUrl()
      });
      this.verificationReport.set(rep);
    } catch (e: unknown) {
      console.error('Verification failure:', e);
    } finally {
      this.isVerifying.set(false);
    }
  }

  // --- Audio Player & Sound Synthesis ---

  async playAudio(target: 'A' | 'B') {
    if (this.currentlyPlaying() === target) {
      this.stopAudio();
      return;
    }

    this.stopAudio();

    const bytes = target === 'A' ? this.audioABytes() : this.audioBBytes();
    if (!bytes) {
      this.showToast('Nenhum dado de áudio carregado.');
      return;
    }

    try {
      if (typeof window === 'undefined') return;
      const AudioCtx = window.AudioContext || (window as unknown as {webkitAudioContext: typeof AudioContext}).webkitAudioContext;
      if (!AudioCtx) {
        this.showToast('Web Audio API não suportada neste navegador.');
        return;
      }

      if (!this.audioContext || this.audioContext.state === 'closed') {
        this.audioContext = new AudioCtx();
      }

      if (this.audioContext.state === 'suspended') {
        await this.audioContext.resume();
      }

      // Clone array buffer for decoding
      const arrayBuffer = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(arrayBuffer).set(bytes);
      const audioBuffer = await this.audioContext.decodeAudioData(arrayBuffer);

      const source = this.audioContext.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(this.audioContext.destination);

      this.currentAudioSource = source;
      this.currentlyPlaying.set(target);
      this.audioPlayProgress.set(0);

      const duration = audioBuffer.duration;
      const startTime = this.audioContext.currentTime;

      this.playbackTimer = setInterval(() => {
        if (!this.audioContext) return;
        const elapsed = this.audioContext.currentTime - startTime;
        const progress = Math.min(100, (elapsed / duration) * 100);
        this.audioPlayProgress.set(progress);
        if (elapsed >= duration) {
          this.stopAudio();
        }
      }, 50);

      source.onended = () => {
        this.stopAudio();
      };

      source.start(0);
    } catch (e: unknown) {
      console.error('Playback error:', e);
      this.showToast('Falha na reprodução do áudio WAV.');
      this.stopAudio();
    }
  }

  stopAudio() {
    if (this.playbackTimer) {
      clearInterval(this.playbackTimer);
      this.playbackTimer = null;
    }
    if (this.currentAudioSource) {
      try {
        this.currentAudioSource.stop();
      } catch {
        // Ignored
      }
      this.currentAudioSource = null;
    }
    this.currentlyPlaying.set(null);
    this.audioPlayProgress.set(0);
  }

  downloadWav(target: 'A' | 'B') {
    const bytes = target === 'A' ? this.audioABytes() : this.audioBBytes();
    const name = target === 'A' ? this.audioAName() : this.audioBName();
    if (!bytes) return;

    const arrayBuffer = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(arrayBuffer).set(bytes);
    const blob = new Blob([arrayBuffer], {type: 'audio/wav'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    this.showToast(`Download iniciado: ${name}`);
  }

  async handleAudioFileUpload(target: 'A' | 'B', event: Event) {
    const input = event.target as HTMLInputElement;
    if (!input.files || input.files.length === 0) return;
    const file = input.files[0];
    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);

    if (target === 'A') {
      this.audioABytes.set(bytes);
      this.audioAName.set(file.name);
    } else {
      this.audioBBytes.set(bytes);
      this.audioBName.set(file.name);
    }
    this.executeVerification();
    this.showToast(`Áudio ${target} importado: ${file.name} (${bytes.length} bytes)`);
  }

  setAudioToMatchTarget(target: 'A' | 'B') {
    const scn = this.scenarios().find(s => s.id === this.selectedScenarioId());
    if (scn) {
      const bytes = target === 'A' ? scn.audioABytes : scn.audioBBytes;
      if (target === 'A') this.audioABytes.set(bytes);
      else this.audioBBytes.set(bytes);
      this.executeVerification();
      this.showToast(`Áudio ${target} restaurado para o padrão do cenário.`);
    }
  }

  tamperAudio(target: 'A' | 'B') {
    const existing = target === 'A' ? this.audioABytes() : this.audioBBytes();
    if (!existing) return;
    const tampered = new Uint8Array(existing.length + 4);
    tampered.set(existing, 0);
    tampered.set([0xde, 0xad, 0xbe, 0xef], existing.length);

    if (target === 'A') this.audioABytes.set(tampered);
    else this.audioBBytes.set(tampered);

    this.executeVerification();
    this.showToast(`Áudio ${target} corrompido com bytes de injeção (dispara falha em I1${target.toLowerCase()}).`);
  }

  // --- C2PA State Manipulations ---

  toggleC2paIntegrity(target: 'A' | 'B') {
    if (target === 'A') {
      this.c2paAVerified.update(c => ({
        ...c,
        integrity: c.integrity === 'valid' ? 'invalid' : 'valid'
      }));
    } else {
      this.c2paBVerified.update(c => ({
        ...c,
        integrity: c.integrity === 'valid' ? 'invalid' : 'valid'
      }));
    }
    this.executeVerification();
    this.showToast(`Integridade de C2PA ${target} alternada.`);
  }

  toggleC2paTrust(target: 'A' | 'B') {
    if (target === 'A') {
      this.c2paAVerified.update(c => ({
        ...c,
        trust: c.trust === 'trusted' ? 'untrusted_self_signed' : 'trusted'
      }));
    } else {
      this.c2paBVerified.update(c => ({
        ...c,
        trust: c.trust === 'trusted' ? 'untrusted_self_signed' : 'trusted'
      }));
    }
    this.executeVerification();
    this.showToast(`Status de confiança de C2PA ${target} alternado.`);
  }

  // --- JSON Ledger Studio & Recalculation ---

  onJsonEditorChange(val: string) {
    this.rawJsonString.set(val);
    try {
      const parsed = JSON.parse(val);
      this.currentLedger.set(parsed);
      this.jsonError.set(null);
      this.executeVerification();
    } catch (e: unknown) {
      this.jsonError.set((e as Error)?.message || 'JSON inválido');
    }
  }

  formatJson() {
    try {
      const parsed = JSON.parse(this.rawJsonString());
      this.rawJsonString.set(JSON.stringify(parsed, null, 2));
      this.jsonError.set(null);
    } catch (e: unknown) {
      this.jsonError.set((e as Error)?.message || 'JSON inválido');
    }
  }

  recalculateContentHash() {
    try {
      const cloned = JSON.parse(this.rawJsonString());
      const updatedHash = this.verifier.computeContentHash(cloned);
      cloned.content_hash = updatedHash;

      if (cloned.anchor) {
        cloned.envelope_hash = this.verifier.computeEnvelopeHash(
          updatedHash,
          cloned.anchor,
          cloned.c2pa || null,
          cloned.trust_policy,
          cloned.trust_context
        );
        if (cloned.anchor.mmr_root && this.verifier.isHex64(cloned.anchor.mmr_root)) {
          const commitmentBytes = this.verifier.computeAnchorCommitment(updatedHash, cloned.anchor.mmr_root);
          cloned.anchor.anchor_commitment = base58Encode(commitmentBytes);
        }
      }

      this.currentLedger.set(cloned);
      this.rawJsonString.set(JSON.stringify(cloned, null, 2));
      this.jsonError.set(null);
      this.executeVerification();
      this.showToast(`Hashes canônicos RFC 8785 recalculados com sucesso!`);
    } catch (e: unknown) {
      this.jsonError.set((e as Error)?.message || 'Falha ao recalcular hashes');
    }
  }

  // --- Terminal Output Generation ---

  generateCliOutput(): string {
    const rep = this.verificationReport();
    if (!rep) return 'Nenhum relatório de verificação gerado.';

    const lines: string[] = [];
    lines.push('═'.repeat(74));
    lines.push(`ARKHE PREFLIGHT v21 — MODO ${rep.mode.toUpperCase()} (11 out 2026)`);
    lines.push('═'.repeat(74));
    lines.push(`Online: ${this.online()} | RPC: ${this.solanaRpcUrl()}`);
    if (rep.requireTrustPolicy) {
      lines.push(`--require-trust-policy: ${rep.requireTrustPolicy}`);
    }
    lines.push(`trust_policy (artefacto): ${this.currentLedger().trust_policy}`);
    lines.push(`Tempo de execução: ${rep.executionTimeMs.toFixed(2)} ms`);
    lines.push('');
    lines.push('DIAGNÓSTICOS:');

    for (const c of rep.checks) {
      const icon = c.result === 'PASS' ? '✓' : c.result === 'FAIL' ? '✗' : c.result === 'WARN' ? '⚠' : '○';
      lines.push(`  ${icon} [${c.severity.padEnd(9)}] ${c.id.padEnd(5)}: ${c.name.padEnd(20)} — ${c.result}`);
      if (c.detail) {
        lines.push(`      └─ ${c.detail}`);
      }
    }

    lines.push('');
    if (rep.overallStatus === 'FAIL') {
      lines.push('═'.repeat(74));
      lines.push(`RESULTADO GERAL: ✗ FAIL (${rep.hardFailures.length} falhas duras)`);
      lines.push('═'.repeat(74));
      for (const hf of rep.hardFailures) {
        lines.push(`  ✗ ${hf.id}: ${hf.name}`);
        if (hf.detail) lines.push(`      └─ ${hf.detail}`);
      }
      if (rep.mode === 'release' && rep.releaseIssues.length > 0) {
        lines.push('─'.repeat(74));
        lines.push(`PORTÕES DE RELEASE BLOQUEADOS (${rep.releaseIssues.length}):`);
        for (const issue of rep.releaseIssues) {
          lines.push(`  ✗ ${issue}`);
        }
      }
    } else {
      lines.push('═'.repeat(74));
      lines.push(`RESULTADO GERAL: ✓ PASS (${rep.mode.toUpperCase()}) — Aprovado para Release`);
      lines.push('═'.repeat(74));
      if (rep.contentHash) lines.push(`  content_hash: ${rep.contentHash}`);
      if (rep.txSignature) lines.push(`  tx_signature: ${rep.txSignature}`);
      if (rep.blockTime) lines.push(`  block_time:   ${rep.blockTime}`);
    }

    return lines.join('\n');
  }

  copyCliText() {
    const text = this.generateCliOutput();
    navigator.clipboard.writeText(text);
    this.showToast('Saída do terminal CLI copiada!');
  }

  copyText(text: string, label: string) {
    navigator.clipboard.writeText(text);
    this.showToast(`${label} copiado!`);
  }

  downloadPythonScript() {
    window.location.href = '/api/script/download';
  }

  downloadLedgerJson() {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(this.rawJsonString());
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `arkhe_ledger_${this.currentLedger().target_a.title.slice(0, 10).toLowerCase().replace(/[^a-z0-9]/g, '_')}_v21.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  updateMmrCalcLeaf(val: string) {
    const n = parseInt(val, 10);
    if (!isNaN(n) && n >= 0) {
      this.calcLeafIndex.set(n);
    }
  }

  updateMmrCalcCount(val: string) {
    const n = parseInt(val, 10);
    if (!isNaN(n) && n >= 1) {
      this.calcLeafCount.set(n);
    }
  }

  updateCpTrials(val: string) {
    const n = parseInt(val, 10);
    if (!isNaN(n) && n > 0) this.cpTrials.set(n);
  }

  updateCpFailures(val: string) {
    const k = parseInt(val, 10);
    if (!isNaN(k) && k >= 0) this.cpFailures.set(k);
  }

  // --- Web3 & Solana Actions ---

  switchSolanaCluster(c: SolanaCluster) {
    this.solanaService.setCluster(c);
    this.solanaRpcUrl.set(this.solanaService.getRpcUrl());
    this.showToast(`Cluster alterado para ${SOLANA_CLUSTERS[c]?.name || c}`);
  }

  async connectPhantomOrSolflare() {
    try {
      await this.solanaService.connectInjectedWallet();
      this.showToast('Carteira Web3 conectada com sucesso!');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Erro ao conectar carteira';
      this.showToast(msg);
    }
  }

  generateEphemeralWallet() {
    this.solanaService.generateNewEphemeralWallet();
    this.showToast('Nova Carteira Efêmera Devnet gerada!');
  }

  disconnectSolanaWallet() {
    this.solanaService.disconnectWallet();
    this.showToast('Carteira desconectada.');
  }

  async requestSolAirdrop() {
    try {
      this.showToast('Solicitando 1 SOL de airdrop na Devnet...');
      await this.solanaService.requestAirdrop();
      this.showToast('Airdrop de 1 SOL creditado com sucesso!');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Falha no airdrop';
      this.showToast(msg);
    }
  }

  async executeAnchorToSolana() {
    const ledger = this.currentLedger();
    if (!ledger.anchor?.mmr_root) {
      this.showToast('Erro: mmr_root ausente no ledger.');
      return;
    }

    try {
      // Recompute content_hash first to ensure consistency
      const contentHash = this.verifier.computeContentHash(ledger);
      const res = await this.solanaService.anchorToSolana(contentHash, ledger.anchor.mmr_root);

      // Update current ledger with on-chain anchor data
      const updated = JSON.parse(JSON.stringify(ledger)) as ArkheLedger;
      if (updated.anchor) {
        updated.anchor.tx_signature = res.signature;
        updated.anchor.chain = `solana:${this.solanaCluster()}`;
        updated.anchor.timestamp = new Date(res.blockTime * 1000).toISOString();
        updated.anchor.anchor_commitment = res.commitment;
        updated.envelope_hash = this.verifier.computeEnvelopeHash(
          contentHash,
          updated.anchor,
          updated.c2pa || null,
          updated.trust_policy,
          updated.trust_context || null
        );
      }

      this.currentLedger.set(updated);
      this.rawJsonString.set(JSON.stringify(updated, null, 2));
      this.inspectSearchSignature.set(res.signature);

      // Automatically inspect transaction
      await this.solanaService.inspectTransaction(res.signature, res.commitment, updated.generated_at);

      this.executeVerification();
      this.showToast(`Ancoragem concluída! Assinatura: ${res.signature.slice(0, 12)}…`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Falha ao ancorar na Solana';
      this.showToast(msg);
    }
  }

  async runInspectTransaction(sig?: string) {
    const targetSig = (sig || this.inspectSearchSignature() || this.currentLedger().anchor?.tx_signature || '').trim();
    if (!targetSig) {
      this.showToast('Informe uma assinatura de transação válida.');
      return;
    }
    this.inspectSearchSignature.set(targetSig);
    const expCommitment = this.currentLedger().anchor?.anchor_commitment;
    const genAt = this.currentLedger().generated_at;
    await this.solanaService.inspectTransaction(targetSig, expCommitment, genAt);
  }

  prefillInspector(sig: string) {
    this.inspectSearchSignature.set(sig);
    this.runInspectTransaction(sig);
  }

  // --- Private Helpers ---

  private generateWaveformPoints(bytes: Uint8Array | null): number[] {
    if (!bytes || bytes.length <= 44) {
      return Array(64).fill(10);
    }
    const points: number[] = [];
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const numSamples = Math.floor((bytes.length - 44) / 2);
    const step = Math.max(1, Math.floor(numSamples / 64));

    for (let i = 0; i < 64; i++) {
      let maxAmp = 0;
      const start = 44 + i * step * 2;
      for (let s = 0; s < step && start + s * 2 + 1 < bytes.length; s += 4) {
        const val = Math.abs(view.getInt16(start + s * 2, true));
        if (val > maxAmp) maxAmp = val;
      }
      const normalizedHeight = Math.max(4, Math.min(48, Math.round((maxAmp / 32768) * 48)));
      points.push(normalizedHeight);
    }
    return points;
  }

  private showToast(msg: string) {
    this.copyNotification.set(msg);
    setTimeout(() => {
      this.copyNotification.set(null);
    }, 3000);
  }
}
