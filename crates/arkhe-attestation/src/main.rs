use anyhow::{Context, Result};
use arkhe_attestation::graph::build_graph;
use arkhe_attestation::hash::{compute_source_hashes, per_file_hashes};
use arkhe_attestation::junit::parse_junit;
use arkhe_attestation::types::{Claim, Diff, Freshness};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "arkhe-attest",
    version,
    about = "Attestation graph + freshness gate"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Constrói o grafo de atestação a partir de um ledger JSON.
    Graph {
        #[arg(long, default_value = "arkhe/ledger.json")]
        ledger: PathBuf,
        #[arg(long, default_value = "arkhe/attestation_graph.json")]
        out: PathBuf,
        #[arg(long)]
        strict: bool,
    },
    /// Verifica freshness do código vs. report.json.
    Freshness {
        #[arg(long, default_value = "arkhe/report.json")]
        report: PathBuf,
        #[arg(long, default_value = "arkhe/freshness.json")]
        out: PathBuf,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        allow_missing_hash: bool,
    },
    /// Calcula o hash agregado dos ficheiros-fonte.
    Hash,
    /// Parse de JUnit XML (cargo-nextest) para um ledger JSON.
    Junit {
        #[arg(long)]
        xml: PathBuf,
        #[arg(long, default_value = "arkhe/junit_claims.json")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Graph {
            ledger,
            out,
            strict,
        } => {
            let raw = std::fs::read_to_string(&ledger)
                .with_context(|| format!("ledger não encontrado: {}", ledger.display()))?;
            let claims: BTreeMap<String, Claim> =
                serde_json::from_str(&raw).context("ledger JSON inválido")?;

            let graph = build_graph(&claims);
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&out, serde_json::to_string_pretty(&graph)?)?;

            println!(
                "✓ grafo: {} nós, {} arestas",
                graph.nodes.len(),
                graph.edges.len()
            );
            if !graph.cycles.is_empty() {
                println!("  ⚠ {} ciclo(s):", graph.cycles.len());
                for c in &graph.cycles {
                    println!("    {}", c.join(" → "));
                }
            }
            if !graph.propagated_compromised.is_empty() {
                println!(
                    "  {} claim(s) compromised propagado(s), max depth={}",
                    graph.propagated_compromised.len(),
                    graph.max_depth
                );
                for p in &graph.propagated_compromised {
                    println!(
                        "    {} ← {} (depth={}, {:?})",
                        p.id, p.upstream, p.depth, p.severity
                    );
                }
            }
            if !graph.cycles.is_empty() && strict {
                std::process::exit(1);
            }
        }
        Command::Freshness {
            report,
            out,
            strict,
            allow_missing_hash,
        } => {
            let code = run_freshness(&report, &out, strict, allow_missing_hash)?;
            std::process::exit(code);
        }
        Command::Hash => {
            let root = std::env::current_dir()?;
            let agg = compute_source_hashes(&root)?;
            let files = per_file_hashes(&root)?;
            println!("files: {}", files.len());
            println!("sha256: {}", agg.sha256);
            if let Some(b3) = &agg.blake3 {
                println!("blake3: {}", b3);
            }
        }
        Command::Junit { xml, out } => {
            let results = parse_junit(&xml)?;
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(&out, serde_json::to_string_pretty(&results)?)?;
            println!("✓ {} testcase(s) parseado(s)", results.len());
        }
    }
    Ok(())
}

fn run_freshness(
    report: &PathBuf,
    out: &PathBuf,
    strict: bool,
    allow_missing_hash: bool,
) -> Result<i32> {
    let root = std::env::current_dir()?;

    if !report.exists() {
        eprintln!("ERRO: report não encontrado: {}", report.display());
        return Ok(1);
    }
    let raw = std::fs::read_to_string(report)?;
    let report_json: serde_json::Value = serde_json::from_str(&raw)?;

    // Fail-closed se code_hash ausente
    let code_hash = report_json.get("code_hash");
    if code_hash.is_none() {
        if !allow_missing_hash {
            let current = compute_source_hashes(&root)?;
            let freshness = Freshness {
                checked_at: chrono::Utc::now().to_rfc3339(),
                match_: false,
                reason: "report_without_code_hash".into(),
                sha_match: false,
                blake3_match: false,
                report_hash: None,
                current_hash: current.sha256,
                report_blake3: None,
                current_blake3: current.blake3,
                diff: Diff::default(),
            };
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(out, serde_json::to_string_pretty(&freshness)?)?;
            eprintln!("✗ report sem code_hash — freshness falha por omissão");
            return Ok(1);
        }
        return Ok(0);
    }

    let report_agg = code_hash.unwrap();
    let report_sha = report_agg.get("sha256").and_then(|v| v.as_str());
    let report_b3 = report_agg.get("blake3").and_then(|v| v.as_str());

    let current = compute_source_hashes(&root)?;
    let current_files: BTreeMap<String, String> = per_file_hashes(&root)?
        .into_iter()
        .map(|(p, h)| (p, h.sha256))
        .collect();

    // diff per-file
    let report_files: BTreeMap<String, String> = report_json
        .get("source_hashes")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mut diff = Diff::default();
    for (path, h) in &report_files {
        match current_files.get(path) {
            None => diff.missing.push(path.clone()),
            Some(cur) if cur != h => diff.changed.push(path.clone()),
            _ => {}
        }
    }
    for path in current_files.keys() {
        if !report_files.contains_key(path) {
            diff.added.push(path.clone());
        }
    }

    let sha_match = report_sha.map(|s| s == current.sha256).unwrap_or(false);
    let b3_match = match (report_b3, current.blake3.as_deref()) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };

    // Dual-hash simétrico
    if sha_match != b3_match {
        eprintln!(
            "AVISO: SHA-256 e BLAKE3 discordam entre si. \
             sha_match={}, blake3_match={}. Possível colisão ou corrupção.",
            sha_match, b3_match
        );
    }

    let match_ = sha_match && b3_match;
    let reason = if match_ {
        "match".to_string()
    } else if !diff.missing.is_empty() {
        "source_missing".to_string()
    } else if diff.changed.iter().any(|p| {
        p.ends_with("Cargo.toml") || p.ends_with("Anchor.toml") || p.ends_with("package.json")
    }) {
        "config_changed".to_string()
    } else if !diff.changed.is_empty() {
        "source_changed".to_string()
    } else if !diff.added.is_empty() {
        "source_added".to_string()
    } else {
        "unknown".to_string()
    };

    let freshness = Freshness {
        checked_at: chrono::Utc::now().to_rfc3339(),
        match_,
        reason,
        sha_match,
        blake3_match: b3_match,
        report_hash: report_sha.map(String::from),
        current_hash: current.sha256,
        report_blake3: report_b3.map(String::from),
        current_blake3: current.blake3,
        diff,
    };

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(out, serde_json::to_string_pretty(&freshness)?)?;

    if match_ {
        println!("✓ freshness ok");
        Ok(0)
    } else {
        println!("✗ freshness mismatch ({})", freshness.reason);
        println!("  sha_match={}, blake3_match={}", sha_match, b3_match);
        Ok(if strict { 1 } else { 0 })
    }
}
