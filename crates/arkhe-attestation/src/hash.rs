use crate::types::DualHash;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Config files que afectam comportamento sem serem código.
pub const CONFIG_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "Anchor.toml",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
];

/// Descobre os ficheiros-fonte a hashear.
///
/// Inclui .rs em `crates/*/src` e `programs/*/src`, mais config files.
pub fn collect_source_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for base in ["crates", "programs"] {
        let base_path = root.join(base);
        if !base_path.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&base_path)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                name != "target" && name != "__pycache__"
            })
            .filter_map(Result::ok)
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.extension().and_then(|e| e.to_str()) == Some("rs") && !name.starts_with("test_")
            {
                files.push(path.to_path_buf());
            }
        }
    }

    for cfg in CONFIG_FILES {
        let p = root.join(cfg);
        if p.exists() {
            files.push(p);
        }
    }

    files.sort();
    files
}

/// Calcula o hash de um único ficheiro.
fn hash_file(path: &Path) -> Result<DualHash> {
    let bytes = fs::read(path).with_context(|| format!("falha ao ler {}", path.display()))?;

    let sha256 = {
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    };

    let blake3 = blake3::hash(&bytes).to_hex().to_string();

    Ok(DualHash {
        sha256,
        blake3: Some(blake3),
    })
}

/// Agrega hashes de um conjunto de ficheiros num único DualHash.
///
/// O hash agregado é o SHA-256 (e BLAKE3) do conteúdo concatenado
/// `path:hash\npath:hash\n...` ordenado por path.
pub fn aggregate_hash(files: &[PathBuf]) -> Result<DualHash> {
    let mut hashes = Vec::new();
    for f in files {
        let h = hash_file(f)?;
        hashes.push((f.clone(), h));
    }
    Ok(aggregate_from_hashes(&hashes))
}

/// Versão que aceita um mapa path→DualHash já calculado.
pub fn aggregate_from_hashes(hashes: &[(PathBuf, DualHash)]) -> DualHash {
    let mut hasher_sha = Sha256::new();
    let mut hasher_b3 = blake3::Hasher::new();

    for (path, h) in hashes {
        let line = format!("{}:{}\n", path.display(), h.sha256);
        hasher_sha.update(line.as_bytes());
        hasher_b3.update(line.as_bytes());
        if let Some(b3) = &h.blake3 {
            let line_b3 = format!("{}:{}\n", path.display(), b3);
            hasher_sha.update(line_b3.as_bytes());
            hasher_b3.update(line_b3.as_bytes());
        }
    }

    DualHash {
        sha256: hex::encode(hasher_sha.finalize()),
        blake3: Some(hasher_b3.finalize().to_hex().to_string()),
    }
}

/// Atalho: descobre + agrega.
pub fn compute_source_hashes(root: &Path) -> Result<DualHash> {
    let files = collect_source_files(root);
    aggregate_hash(&files)
}

/// Mapa path→DualHash para comparação per-file.
pub fn per_file_hashes(root: &Path) -> Result<Vec<(String, DualHash)>> {
    let files = collect_source_files(root);
    let mut out = Vec::new();
    for f in files {
        let h = hash_file(&f)?;
        let rel = f.strip_prefix(root).unwrap_or(&f).display().to_string();
        out.push((rel, h));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn aggregate_empty_is_deterministic() {
        let a = aggregate_hash(&[]).unwrap();
        let b = aggregate_hash(&[]).unwrap();
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(a.blake3, b.blake3);
    }

    #[test]
    fn aggregate_changes_with_content() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("a.rs");
        fs::write(&f, "fn main() {}").unwrap();
        let h1 = aggregate_hash(&[f.clone()]).unwrap();

        fs::write(&f, "fn main() { println!(); }").unwrap();
        let h2 = aggregate_hash(&[f.clone()]).unwrap();

        assert_ne!(h1.sha256, h2.sha256);
        assert_ne!(h1.blake3, h2.blake3);
    }
}
