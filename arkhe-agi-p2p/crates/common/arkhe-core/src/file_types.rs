//! Normative Arkhe File Extensions and Validation Logic.
//!
//! Categorized across the 9 architectural layers, with strict fail-closed enforcement
//! for prohibited and restricted file formats.

use std::path::Path;

/// Status level of a file extension or format in Arkhe
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtensionStatus {
    Mandatory,
    Optional,
    Recommended,
    Restricted,
    Prohibited,
}

/// Architectural layer governing the file format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArkheLayer {
    IdentityAndContent = 1,
    ManifestsAndModels = 2,
    ReceiptsAndEvidence = 3,
    NetworkAndDiscovery = 4,
    InferenceAndExecution = 5,
    VerificationAndFrauds = 6,
    EconomyAndGovernance = 7,
    ChainIntegration = 8,
    BuildAndSupplyChain = 9,
}

/// Normative Arkhe file types categorized by functional layer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArkheFileType {
    // 1. Identity and Content
    Cid,
    Multihash,
    Pubkey,
    Signature,
    Certificate,
    Crl,
    Keystore,
    Seed,

    // 2. Manifests and Models
    ArkManifest,
    ArkManifestSig,
    Gguf,
    GgufPart,
    GgufIndex,
    QuantProfile,
    Lineage,
    Eval,
    Dataset,
    Tokenizer,
    Vocab,

    // 3. Receipts and Evidence
    Afir,
    AfirJson,
    AfirTree,
    MobileWer,
    Mmr,
    MmrProof,
    ConsistencyProof,
    Checkpoint,
    Attestation,
    ArkBundle,
    Wasm,

    // 4. Network and Discovery
    Peers,
    PeerLedger,
    Seeds,
    DhtCache,
    Announce,
    Gossip,
    NetPolicy,
    Pcap,

    // 5. Inference and Execution
    Policy,
    PolicySig,
    Request,
    Response,
    Session,
    Router,
    ExpertMap,
    KvCache,
    GpuProfile,
    Onnx,
    Safetensors,

    // 6. Verification and Frauds
    FraudProof,
    Reexecution,
    ZkProof,
    TeeQuote,
    Verdict,
    Slash,
    Golden,

    // 7. Economy and Governance
    Constitution,
    ConstitutionSig,
    Proposal,
    Vote,
    Canon,
    Emission,
    Reward,
    Stake,
    Epoch,
    Gini,

    // 8. Chain Integration
    Anchor,
    Ibc,
    Ccip,
    LayerZero,
    Abi,
    Sol,
    Move,
    Tx,
    ReceiptRoot,

    // 9. Build, Test and Supply Chain
    Toml,
    RustSource,
    TypeScriptSource,
    CSharpSource,
    CSharpProject,
    WasmText,
    Json,
    Lock,
    Sbom,
    Provenance,
    Sha256,
    Sigstore,
    Log,
    Trace,
}

impl ArkheFileType {
    pub fn layer(&self) -> ArkheLayer {
        match self {
            Self::Cid
            | Self::Multihash
            | Self::Pubkey
            | Self::Signature
            | Self::Certificate
            | Self::Crl
            | Self::Keystore
            | Self::Seed => ArkheLayer::IdentityAndContent,

            Self::ArkManifest
            | Self::ArkManifestSig
            | Self::Gguf
            | Self::GgufPart
            | Self::GgufIndex
            | Self::QuantProfile
            | Self::Lineage
            | Self::Eval
            | Self::Dataset
            | Self::Tokenizer
            | Self::Vocab => ArkheLayer::ManifestsAndModels,

            Self::Afir
            | Self::AfirJson
            | Self::AfirTree
            | Self::MobileWer
            | Self::Mmr
            | Self::MmrProof
            | Self::ConsistencyProof
            | Self::Checkpoint
            | Self::Attestation
            | Self::ArkBundle
            | Self::Wasm => ArkheLayer::ReceiptsAndEvidence,

            Self::Peers
            | Self::PeerLedger
            | Self::Seeds
            | Self::DhtCache
            | Self::Announce
            | Self::Gossip
            | Self::NetPolicy
            | Self::Pcap => ArkheLayer::NetworkAndDiscovery,

            Self::Policy
            | Self::PolicySig
            | Self::Request
            | Self::Response
            | Self::Session
            | Self::Router
            | Self::ExpertMap
            | Self::KvCache
            | Self::GpuProfile
            | Self::Onnx
            | Self::Safetensors => ArkheLayer::InferenceAndExecution,

            Self::FraudProof
            | Self::Reexecution
            | Self::ZkProof
            | Self::TeeQuote
            | Self::Verdict
            | Self::Slash
            | Self::Golden => ArkheLayer::VerificationAndFrauds,

            Self::Constitution
            | Self::ConstitutionSig
            | Self::Proposal
            | Self::Vote
            | Self::Canon
            | Self::Emission
            | Self::Reward
            | Self::Stake
            | Self::Epoch
            | Self::Gini => ArkheLayer::EconomyAndGovernance,

            Self::Anchor
            | Self::Ibc
            | Self::Ccip
            | Self::LayerZero
            | Self::Abi
            | Self::Sol
            | Self::Move
            | Self::Tx
            | Self::ReceiptRoot => ArkheLayer::ChainIntegration,

            Self::Toml
            | Self::RustSource
            | Self::TypeScriptSource
            | Self::CSharpSource
            | Self::CSharpProject
            | Self::WasmText
            | Self::Json
            | Self::Lock
            | Self::Sbom
            | Self::Provenance
            | Self::Sha256
            | Self::Sigstore
            | Self::Log
            | Self::Trace => ArkheLayer::BuildAndSupplyChain,
        }
    }

    pub fn status(&self) -> ExtensionStatus {
        match self {
            Self::Cid
            | Self::Pubkey
            | Self::Signature
            | Self::Keystore
            | Self::ArkManifest
            | Self::ArkManifestSig
            | Self::Gguf
            | Self::GgufPart
            | Self::QuantProfile
            | Self::Lineage
            | Self::Eval
            | Self::Dataset
            | Self::Tokenizer
            | Self::Afir
            | Self::AfirTree
            | Self::MobileWer
            | Self::Mmr
            | Self::MmrProof
            | Self::ConsistencyProof
            | Self::Checkpoint
            | Self::Attestation
            | Self::ArkBundle
            | Self::Wasm
            | Self::Peers
            | Self::PeerLedger
            | Self::Seeds
            | Self::Gossip
            | Self::NetPolicy
            | Self::Policy
            | Self::PolicySig
            | Self::Request
            | Self::Response
            | Self::Session
            | Self::Router
            | Self::ExpertMap
            | Self::GpuProfile
            | Self::FraudProof
            | Self::Reexecution
            | Self::Verdict
            | Self::Slash
            | Self::Golden
            | Self::Constitution
            | Self::ConstitutionSig
            | Self::Proposal
            | Self::Vote
            | Self::Canon
            | Self::Emission
            | Self::Reward
            | Self::Stake
            | Self::Epoch
            | Self::Abi
            | Self::ReceiptRoot
            | Self::Toml
            | Self::RustSource
            | Self::TypeScriptSource
            | Self::Json
            | Self::Lock
            | Self::Sbom
            | Self::Provenance
            | Self::Sha256
            | Self::Trace => ExtensionStatus::Mandatory,

            Self::Crl | Self::GgufIndex | Self::Gini | Self::Sigstore => {
                ExtensionStatus::Recommended
            }

            Self::Multihash
            | Self::Certificate
            | Self::Seed
            | Self::Vocab
            | Self::AfirJson
            | Self::DhtCache
            | Self::Announce
            | Self::Pcap
            | Self::KvCache
            | Self::Onnx
            | Self::Safetensors
            | Self::ZkProof
            | Self::TeeQuote
            | Self::Anchor
            | Self::Ibc
            | Self::Ccip
            | Self::LayerZero
            | Self::Sol
            | Self::Move
            | Self::Tx
            | Self::CSharpSource
            | Self::CSharpProject
            | Self::WasmText
            | Self::Log => ExtensionStatus::Optional,
        }
    }

    pub fn primary_extension(&self) -> &'static str {
        match self {
            Self::Cid => "cid",
            Self::Multihash => "multihash",
            Self::Pubkey => "pub",
            Self::Signature => "sig",
            Self::Certificate => "cert",
            Self::Crl => "crl",
            Self::Keystore => "keystore",
            Self::Seed => "seed",
            Self::ArkManifest => "arkmanifest",
            Self::ArkManifestSig => "arkmanifest.sig",
            Self::Gguf => "gguf",
            Self::GgufPart => "gguf.part",
            Self::GgufIndex => "gguf.index",
            Self::QuantProfile => "quant",
            Self::Lineage => "lineage",
            Self::Eval => "eval",
            Self::Dataset => "dataset",
            Self::Tokenizer => "tokenizer",
            Self::Vocab => "vocab",
            Self::Afir => "afir",
            Self::AfirJson => "afir.json",
            Self::AfirTree => "afirtree",
            Self::MobileWer => "wer",
            Self::Mmr => "mmr",
            Self::MmrProof => "mmrproof",
            Self::ConsistencyProof => "consistency",
            Self::Checkpoint => "checkpoint",
            Self::Attestation => "attest",
            Self::ArkBundle => "arkbundle",
            Self::Wasm => "wasm",
            Self::Peers => "peers",
            Self::PeerLedger => "peerledger",
            Self::Seeds => "seeds",
            Self::DhtCache => "dhtcache",
            Self::Announce => "announce",
            Self::Gossip => "gossip",
            Self::NetPolicy => "netpolicy",
            Self::Pcap => "pcap",
            Self::Policy => "policy",
            Self::PolicySig => "policy.sig",
            Self::Request => "request",
            Self::Response => "response",
            Self::Session => "session",
            Self::Router => "router",
            Self::ExpertMap => "expertmap",
            Self::KvCache => "kv",
            Self::GpuProfile => "gpu",
            Self::Onnx => "onnx",
            Self::Safetensors => "safetensors",
            Self::FraudProof => "fraudproof",
            Self::Reexecution => "reexec",
            Self::ZkProof => "zkproof",
            Self::TeeQuote => "teequote",
            Self::Verdict => "verdict",
            Self::Slash => "slash",
            Self::Golden => "golden",
            Self::Constitution => "constitution",
            Self::ConstitutionSig => "constitution.sig",
            Self::Proposal => "proposal",
            Self::Vote => "vote",
            Self::Canon => "canon",
            Self::Emission => "emission",
            Self::Reward => "reward",
            Self::Stake => "stake",
            Self::Epoch => "epoch",
            Self::Gini => "gini",
            Self::Anchor => "anchor",
            Self::Ibc => "ibc",
            Self::Ccip => "ccip",
            Self::LayerZero => "layerzero",
            Self::Abi => "abi",
            Self::Sol => "sol",
            Self::Move => "move",
            Self::Tx => "tx",
            Self::ReceiptRoot => "receiptroot",
            Self::Toml => "toml",
            Self::RustSource => "rs",
            Self::TypeScriptSource => "ts",
            Self::CSharpSource => "cs",
            Self::CSharpProject => "csproj",
            Self::WasmText => "wat",
            Self::Json => "json",
            Self::Lock => "lock",
            Self::Sbom => "sbom",
            Self::Provenance => "provenance",
            Self::Sha256 => "sha256",
            Self::Sigstore => "sigstore",
            Self::Log => "log",
            Self::Trace => "trace",
        }
    }
}

/// Classifies a path or filename into a recognized `ArkheFileType` if valid.
pub fn classify_file(filename: &str) -> Option<ArkheFileType> {
    let lower = filename.to_ascii_lowercase();

    // Check multi-segment extensions first
    if lower.ends_with(".arkmanifest.sig") {
        return Some(ArkheFileType::ArkManifestSig);
    }
    if lower.ends_with(".policy.sig") {
        return Some(ArkheFileType::PolicySig);
    }
    if lower.ends_with(".constitution.sig") {
        return Some(ArkheFileType::ConstitutionSig);
    }
    if lower.ends_with(".afir.json") {
        return Some(ArkheFileType::AfirJson);
    }
    if lower.ends_with(".gguf.index") {
        return Some(ArkheFileType::GgufIndex);
    }
    if lower.contains(".gguf.part") {
        return Some(ArkheFileType::GgufPart);
    }

    // Single-segment extensions
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "cid" => Some(ArkheFileType::Cid),
        "multihash" => Some(ArkheFileType::Multihash),
        "pub" => Some(ArkheFileType::Pubkey),
        "sig" => Some(ArkheFileType::Signature),
        "cert" => Some(ArkheFileType::Certificate),
        "crl" => Some(ArkheFileType::Crl),
        "keystore" => Some(ArkheFileType::Keystore),
        "seed" => Some(ArkheFileType::Seed),
        "arkmanifest" => Some(ArkheFileType::ArkManifest),
        "gguf" => Some(ArkheFileType::Gguf),
        "quant" => Some(ArkheFileType::QuantProfile),
        "lineage" => Some(ArkheFileType::Lineage),
        "eval" => Some(ArkheFileType::Eval),
        "dataset" => Some(ArkheFileType::Dataset),
        "tokenizer" => Some(ArkheFileType::Tokenizer),
        "vocab" => Some(ArkheFileType::Vocab),
        "afir" => Some(ArkheFileType::Afir),
        "afirtree" => Some(ArkheFileType::AfirTree),
        "wer" => Some(ArkheFileType::MobileWer),
        "mmr" => Some(ArkheFileType::Mmr),
        "mmrproof" => Some(ArkheFileType::MmrProof),
        "consistency" => Some(ArkheFileType::ConsistencyProof),
        "checkpoint" => Some(ArkheFileType::Checkpoint),
        "attest" => Some(ArkheFileType::Attestation),
        "arkbundle" => Some(ArkheFileType::ArkBundle),
        "wasm" => Some(ArkheFileType::Wasm),
        "peers" => Some(ArkheFileType::Peers),
        "peerledger" => Some(ArkheFileType::PeerLedger),
        "seeds" => Some(ArkheFileType::Seeds),
        "dhtcache" => Some(ArkheFileType::DhtCache),
        "announce" => Some(ArkheFileType::Announce),
        "gossip" => Some(ArkheFileType::Gossip),
        "netpolicy" => Some(ArkheFileType::NetPolicy),
        "pcap" => Some(ArkheFileType::Pcap),
        "policy" => Some(ArkheFileType::Policy),
        "request" => Some(ArkheFileType::Request),
        "response" => Some(ArkheFileType::Response),
        "session" => Some(ArkheFileType::Session),
        "router" => Some(ArkheFileType::Router),
        "expertmap" => Some(ArkheFileType::ExpertMap),
        "kv" => Some(ArkheFileType::KvCache),
        "gpu" => Some(ArkheFileType::GpuProfile),
        "onnx" => Some(ArkheFileType::Onnx),
        "safetensors" => Some(ArkheFileType::Safetensors),
        "fraudproof" => Some(ArkheFileType::FraudProof),
        "reexec" => Some(ArkheFileType::Reexecution),
        "zkproof" => Some(ArkheFileType::ZkProof),
        "teequote" => Some(ArkheFileType::TeeQuote),
        "verdict" => Some(ArkheFileType::Verdict),
        "slash" => Some(ArkheFileType::Slash),
        "golden" => Some(ArkheFileType::Golden),
        "constitution" => Some(ArkheFileType::Constitution),
        "proposal" => Some(ArkheFileType::Proposal),
        "vote" => Some(ArkheFileType::Vote),
        "canon" => Some(ArkheFileType::Canon),
        "emission" => Some(ArkheFileType::Emission),
        "reward" => Some(ArkheFileType::Reward),
        "stake" => Some(ArkheFileType::Stake),
        "epoch" => Some(ArkheFileType::Epoch),
        "gini" => Some(ArkheFileType::Gini),
        "anchor" => Some(ArkheFileType::Anchor),
        "ibc" => Some(ArkheFileType::Ibc),
        "ccip" => Some(ArkheFileType::Ccip),
        "layerzero" => Some(ArkheFileType::LayerZero),
        "abi" => Some(ArkheFileType::Abi),
        "sol" => Some(ArkheFileType::Sol),
        "move" => Some(ArkheFileType::Move),
        "tx" => Some(ArkheFileType::Tx),
        "receiptroot" => Some(ArkheFileType::ReceiptRoot),
        "toml" => Some(ArkheFileType::Toml),
        "rs" => Some(ArkheFileType::RustSource),
        "ts" => Some(ArkheFileType::TypeScriptSource),
        "cs" => Some(ArkheFileType::CSharpSource),
        "csproj" => Some(ArkheFileType::CSharpProject),
        "wat" => Some(ArkheFileType::WasmText),
        "json" => Some(ArkheFileType::Json),
        "lock" => Some(ArkheFileType::Lock),
        "sbom" => Some(ArkheFileType::Sbom),
        "provenance" => Some(ArkheFileType::Provenance),
        "sha256" => Some(ArkheFileType::Sha256),
        "sigstore" => Some(ArkheFileType::Sigstore),
        "log" => Some(ArkheFileType::Log),
        "trace" => Some(ArkheFileType::Trace),
        _ => None,
    }
}

/// Checks if an extension is strictly prohibited in Arkhe.
///
/// Prohibited extensions violate protocol integrity, leak secrets, or break append-only invariants:
/// - Unencrypted `.pem` private keys.
/// - Production `.env` secret files.
/// - `.bak` backups of append-only structures like MMR or checkpoints.
/// - Payload `.dump` files leaking prompts or model activations.
pub fn is_extension_prohibited(path: &Path, is_production: bool) -> Result<(), &'static str> {
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if filename.ends_with(".pem") {
        return Err("Prohibited: Plaintext .pem unencrypted keys are strictly forbidden");
    }
    if filename.ends_with(".bak") {
        return Err("Prohibited: .bak backup files break append-only history and consistency");
    }
    if filename.ends_with(".dump") {
        return Err("Prohibited: Raw payload .dump files may leak prompt or token data");
    }
    if is_production && (filename == ".env" || filename.ends_with(".env")) {
        return Err("Prohibited: Production .env configuration files are strictly forbidden");
    }

    Ok(())
}

/// Checks if a file extension is restricted.
///
/// Restricted extensions require attestation, SLSA provenance, or atomic handling:
/// - `.dll`, `.exe`, `.so`, `.dylib`: Native distribution binaries (must have provenance and signatures).
/// - `.tmp`: Ephemeral receipt/state files (must be atomically committed or deleted).
pub fn is_extension_restricted(path: &Path) -> bool {
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    filename.ends_with(".dll")
        || filename.ends_with(".exe")
        || filename.ends_with(".so")
        || filename.ends_with(".dylib")
        || filename.ends_with(".tmp")
}

/// Comprehensive validator ensuring a file follows the Arkhe specification.
pub fn validate_arkhe_file(path: &Path, is_production: bool) -> Result<(), String> {
    // 1. Fail-closed on prohibited formats
    is_extension_prohibited(path, is_production).map_err(|e| e.to_string())?;

    // 2. Classify file
    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if filename.is_empty() {
        return Err("Invalid file path: missing file name".into());
    }

    // Note: Diagnostics like .pcap are prohibited in production
    if is_production && filename.to_ascii_lowercase().ends_with(".pcap") {
        return Err("Prohibited: .pcap packet capture files are forbidden in production".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_layer_and_status() {
        assert_eq!(ArkheFileType::Cid.layer(), ArkheLayer::IdentityAndContent);
        assert_eq!(ArkheFileType::Cid.status(), ExtensionStatus::Mandatory);
        assert_eq!(ArkheFileType::Cid.primary_extension(), "cid");

        assert_eq!(ArkheFileType::ArkManifest.layer(), ArkheLayer::ManifestsAndModels);
        assert_eq!(ArkheFileType::ArkManifest.status(), ExtensionStatus::Mandatory);

        assert_eq!(ArkheFileType::Afir.layer(), ArkheLayer::ReceiptsAndEvidence);
        assert_eq!(ArkheFileType::Afir.status(), ExtensionStatus::Mandatory);

        assert_eq!(ArkheFileType::Peers.layer(), ArkheLayer::NetworkAndDiscovery);
        assert_eq!(ArkheFileType::Peers.status(), ExtensionStatus::Mandatory);

        assert_eq!(ArkheFileType::Policy.layer(), ArkheLayer::InferenceAndExecution);
        assert_eq!(ArkheFileType::Policy.status(), ExtensionStatus::Mandatory);

        assert_eq!(ArkheFileType::FraudProof.layer(), ArkheLayer::VerificationAndFrauds);
        assert_eq!(ArkheFileType::FraudProof.status(), ExtensionStatus::Mandatory);

        assert_eq!(ArkheFileType::Constitution.layer(), ArkheLayer::EconomyAndGovernance);
        assert_eq!(ArkheFileType::Constitution.status(), ExtensionStatus::Mandatory);

        assert_eq!(ArkheFileType::ReceiptRoot.layer(), ArkheLayer::ChainIntegration);
        assert_eq!(ArkheFileType::ReceiptRoot.status(), ExtensionStatus::Mandatory);

        assert_eq!(ArkheFileType::RustSource.layer(), ArkheLayer::BuildAndSupplyChain);
        assert_eq!(ArkheFileType::RustSource.status(), ExtensionStatus::Mandatory);

        assert_eq!(ArkheFileType::Gini.status(), ExtensionStatus::Recommended);
        assert_eq!(ArkheFileType::ZkProof.status(), ExtensionStatus::Optional);
    }

    #[test]
    fn test_classification_of_spec_examples() {
        // Multi-segment extensions
        assert_eq!(classify_file("model.arkmanifest.sig"), Some(ArkheFileType::ArkManifestSig));
        assert_eq!(classify_file("inference.policy.sig"), Some(ArkheFileType::PolicySig));
        assert_eq!(classify_file("arkhe.constitution.sig"), Some(ArkheFileType::ConstitutionSig));
        assert_eq!(classify_file("fragment.afir.json"), Some(ArkheFileType::AfirJson));
        assert_eq!(classify_file("model.gguf.index"), Some(ArkheFileType::GgufIndex));
        assert_eq!(classify_file("model.gguf.part0001"), Some(ArkheFileType::GgufPart));

        // Single extensions
        assert_eq!(classify_file("model.cid"), Some(ArkheFileType::Cid));
        assert_eq!(classify_file("digest.multihash"), Some(ArkheFileType::Multihash));
        assert_eq!(classify_file("publisher.pub"), Some(ArkheFileType::Pubkey));
        assert_eq!(classify_file("manifest.sig"), Some(ArkheFileType::Signature));
        assert_eq!(classify_file("device.cert"), Some(ArkheFileType::Certificate));
        assert_eq!(classify_file("revocation.crl"), Some(ArkheFileType::Crl));
        assert_eq!(classify_file("node.keystore"), Some(ArkheFileType::Keystore));
        assert_eq!(classify_file("node.seed"), Some(ArkheFileType::Seed));
        assert_eq!(classify_file("model.arkmanifest"), Some(ArkheFileType::ArkManifest));
        assert_eq!(classify_file("model.gguf"), Some(ArkheFileType::Gguf));
        assert_eq!(classify_file("nvfp4.quant"), Some(ArkheFileType::QuantProfile));
        assert_eq!(classify_file("training.lineage"), Some(ArkheFileType::Lineage));
        assert_eq!(classify_file("evaluation.eval"), Some(ArkheFileType::Eval));
        assert_eq!(classify_file("cohort.dataset"), Some(ArkheFileType::Dataset));
        assert_eq!(classify_file("tokenizer.json"), Some(ArkheFileType::Json));
        assert_eq!(classify_file("model.tokenizer"), Some(ArkheFileType::Tokenizer));
        assert_eq!(classify_file("vocab.txt"), None);
        assert_eq!(classify_file("legacy.vocab"), Some(ArkheFileType::Vocab));
        assert_eq!(classify_file("fragment.afir"), Some(ArkheFileType::Afir));
        assert_eq!(classify_file("session.afirtree"), Some(ArkheFileType::AfirTree));
        assert_eq!(classify_file("session.wer"), Some(ArkheFileType::MobileWer));
        assert_eq!(classify_file("device.mmr"), Some(ArkheFileType::Mmr));
        assert_eq!(classify_file("inclusion.mmrproof"), Some(ArkheFileType::MmrProof));
        assert_eq!(classify_file("history.consistency"), Some(ArkheFileType::ConsistencyProof));
        assert_eq!(classify_file("device.checkpoint"), Some(ArkheFileType::Checkpoint));
        assert_eq!(classify_file("boot.attest"), Some(ArkheFileType::Attestation));
        assert_eq!(classify_file("audit.arkbundle"), Some(ArkheFileType::ArkBundle));
        assert_eq!(classify_file("arkverify.wasm"), Some(ArkheFileType::Wasm));
        assert_eq!(classify_file("peers.dat"), None);
        assert_eq!(classify_file("book.peers"), Some(ArkheFileType::Peers));
        assert_eq!(classify_file("service.peerledger"), Some(ArkheFileType::PeerLedger));
        assert_eq!(classify_file("seeds.toml"), Some(ArkheFileType::Toml));
        assert_eq!(classify_file("fallback.seeds"), Some(ArkheFileType::Seeds));
        assert_eq!(classify_file("dht.dhtcache"), Some(ArkheFileType::DhtCache));
        assert_eq!(classify_file("chunk.announce"), Some(ArkheFileType::Announce));
        assert_eq!(classify_file("topic.gossip"), Some(ArkheFileType::Gossip));
        assert_eq!(classify_file("network.netpolicy"), Some(ArkheFileType::NetPolicy));
        assert_eq!(classify_file("debug.pcap"), Some(ArkheFileType::Pcap));
        assert_eq!(classify_file("inference.policy"), Some(ArkheFileType::Policy));
        assert_eq!(classify_file("inference.request"), Some(ArkheFileType::Request));
        assert_eq!(classify_file("inference.response"), Some(ArkheFileType::Response));
        assert_eq!(classify_file("inference.session"), Some(ArkheFileType::Session));
        assert_eq!(classify_file("moe.router"), Some(ArkheFileType::Router));
        assert_eq!(classify_file("moe.expertmap"), Some(ArkheFileType::ExpertMap));
        assert_eq!(classify_file("cache.kv"), Some(ArkheFileType::KvCache));
        assert_eq!(classify_file("gpu.profile"), None);
        assert_eq!(classify_file("worker.gpu"), Some(ArkheFileType::GpuProfile));
        assert_eq!(classify_file("model.onnx"), Some(ArkheFileType::Onnx));
        assert_eq!(classify_file("model.safetensors"), Some(ArkheFileType::Safetensors));
        assert_eq!(classify_file("receipt.fraudproof"), Some(ArkheFileType::FraudProof));
        assert_eq!(classify_file("reexecution.reexec"), Some(ArkheFileType::Reexecution));
        assert_eq!(classify_file("fragment.zkproof"), Some(ArkheFileType::ZkProof));
        assert_eq!(classify_file("attestation.teequote"), Some(ArkheFileType::TeeQuote));
        assert_eq!(classify_file("adjudication.verdict"), Some(ArkheFileType::Verdict));
        assert_eq!(classify_file("slashing.slash"), Some(ArkheFileType::Slash));
        assert_eq!(classify_file("vectors.golden"), Some(ArkheFileType::Golden));
        assert_eq!(classify_file("arkhe.constitution"), Some(ArkheFileType::Constitution));
        assert_eq!(classify_file("upgrade.proposal"), Some(ArkheFileType::Proposal));
        assert_eq!(classify_file("quorum.vote"), Some(ArkheFileType::Vote));
        assert_eq!(classify_file("canonification.canon"), Some(ArkheFileType::Canon));
        assert_eq!(classify_file("emission.schedule"), None);
        assert_eq!(classify_file("token.emission"), Some(ArkheFileType::Emission));
        assert_eq!(classify_file("poi.reward"), Some(ArkheFileType::Reward));
        assert_eq!(classify_file("validator.stake"), Some(ArkheFileType::Stake));
        assert_eq!(classify_file("roles.epoch"), Some(ArkheFileType::Epoch));
        assert_eq!(classify_file("emission.gini"), Some(ArkheFileType::Gini));
        assert_eq!(classify_file("checkpoint.anchor"), Some(ArkheFileType::Anchor));
        assert_eq!(classify_file("cal.ibc"), Some(ArkheFileType::Ibc));
        assert_eq!(classify_file("cal.ccip"), Some(ArkheFileType::Ccip));
        assert_eq!(classify_file("cal.layerzero"), Some(ArkheFileType::LayerZero));
        assert_eq!(classify_file("ISettlement.abi"), Some(ArkheFileType::Abi));
        assert_eq!(classify_file("ArkheSettlement.sol"), Some(ArkheFileType::Sol));
        assert_eq!(classify_file("arkhe.move"), Some(ArkheFileType::Move));
        assert_eq!(classify_file("anchor.tx"), Some(ArkheFileType::Tx));
        assert_eq!(classify_file("settlement.receiptroot"), Some(ArkheFileType::ReceiptRoot));
        assert_eq!(classify_file("release.sbom"), Some(ArkheFileType::Sbom));
        assert_eq!(classify_file("build.provenance"), Some(ArkheFileType::Provenance));
        assert_eq!(classify_file("artifact.sha256"), Some(ArkheFileType::Sha256));
        assert_eq!(classify_file("artifact.sigstore"), Some(ArkheFileType::Sigstore));
        assert_eq!(classify_file("consensus.trace"), Some(ArkheFileType::Trace));
    }

    #[test]
    fn test_falsifier_prohibited_extensions() {
        let pem_res = is_extension_prohibited(Path::new("private_key.pem"), false);
        assert!(pem_res.is_err(), "Plaintext .pem should be prohibited");

        let bak_res = is_extension_prohibited(Path::new("device.mmr.bak"), false);
        assert!(bak_res.is_err(), ".bak of MMR/checkpoint breaks append-only history and must be prohibited");

        let dump_res = is_extension_prohibited(Path::new("raw_activations.dump"), false);
        assert!(dump_res.is_err(), ".dump leaks payloads and must be prohibited");

        let env_prod_res = is_extension_prohibited(Path::new(".env"), true);
        assert!(env_prod_res.is_err(), ".env in production must be prohibited");

        let env_dev_res = is_extension_prohibited(Path::new(".env"), false);
        assert!(env_dev_res.is_ok(), ".env in dev should not be prohibited");
    }

    #[test]
    fn test_falsifier_restricted_and_pcap_in_production() {
        assert!(is_extension_restricted(Path::new("plugin.dll")));
        assert!(is_extension_restricted(Path::new("installer.exe")));
        assert!(is_extension_restricted(Path::new("libengine.so")));
        assert!(is_extension_restricted(Path::new("libengine.dylib")));
        assert!(is_extension_restricted(Path::new("receipt_atomic.tmp")));

        assert!(!is_extension_restricted(Path::new("audit.arkbundle")));

        let pcap_prod = validate_arkhe_file(Path::new("debug.pcap"), true);
        assert!(pcap_prod.is_err(), ".pcap is forbidden in production");

        let pcap_dev = validate_arkhe_file(Path::new("debug.pcap"), false);
        assert!(pcap_dev.is_ok(), ".pcap allowed for dev diagnostics");

        let bundle_valid = validate_arkhe_file(Path::new("evidence.arkbundle"), true);
        assert!(bundle_valid.is_ok());
    }
}
