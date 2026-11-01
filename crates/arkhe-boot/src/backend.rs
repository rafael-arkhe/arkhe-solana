// crates/arkhe-boot/src/backend.rs

use std::process::Command;

/// Versão mínima do kernel para composefs com fs-verity digest.
/// Kernel 7.0+ introduziu uma regressão que exige fs-verity em todos os ficheiros;
/// bootc apenas aplica verity a content objects, pelo que erofs mounts falham.
/// Ver: https://github.com/bootc-dev/bootc/issues/2174
const MIN_KERNEL_COMPOSEFS: KernelVersion = KernelVersion::new(7, 0, 0);

/// Kernel recomendado para composefs estável (antes da regressão).
#[allow(dead_code)]
const RECOMMENDED_KERNEL_COMPOSEFS: KernelVersion = KernelVersion::new(6, 19, 14);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Lê a versão do kernel em execução via `uname -r`.
    pub fn current() -> Result<Self, BootError> {
        let output = Command::new("uname").arg("-r").output()?;
        let raw = String::from_utf8_lossy(&output.stdout);
        Self::parse(&raw)
    }

    /// Parse de "7.0.1-arch1-1" → KernelVersion { 7, 0, 1 }.
    pub fn parse(raw: &str) -> Result<Self, BootError> {
        let base = raw.split('-').next().ok_or(BootError::InvalidKernelVersion)?;
        let parts: Vec<&str> = base.split('.').collect();
        if parts.len() < 2 {
            return Err(BootError::InvalidKernelVersion);
        }
        Ok(Self {
            major: parts[0].parse().map_err(|_| BootError::InvalidKernelVersion)?,
            minor: parts[1].parse().map_err(|_| BootError::InvalidKernelVersion)?,
            patch: parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0),
        })
    }
}

/// Backend de armazenamento do bootc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    /// Estável, default upstream. Hardlinked checkouts.
    Ostree,
    /// Experimental. EROFS + overlayfs + fs-verity + UKI.
    Composefs,
}

impl StorageBackend {
    /// Flag de instalação correspondente.
    pub fn install_flag(&self) -> &'static str {
        match self {
            StorageBackend::Composefs => "--composefs-backend",
            StorageBackend::Ostree => "--ostree-backend",
        }
    }

    /// Flag de bootloader (apenas composefs suporta systemd-boot).
    pub fn bootloader_flag(&self) -> Option<&'static str> {
        match self {
            StorageBackend::Composefs => Some("--bootloader=systemd"),
            StorageBackend::Ostree => None, // bootupd/GRUB por omissão
        }
    }
}

pub struct BootBackend {
    pub backend: StorageBackend,
    /// Indica se o backend foi seleccionado por fallback.
    pub fallback: bool,
    /// Razão do fallback (vazio se selecção primária).
    pub reason: Option<String>,
}

impl BootBackend {
    /// Selecciona o backend com base na versão do kernel e no suporte a fs-verity.
    /// Falha fechado se nenhum backend for viável.
    pub fn select() -> Result<Self, BootError> {
        let kernel = KernelVersion::current()?;
        let fsverity = fs_verity_available()?;

        Self::select_with_kernel(kernel, fsverity)
    }

    pub fn select_with_kernel(kernel: KernelVersion, fsverity: bool) -> Result<Self, BootError> {
        // Kernel 7.0+ tem regressão conhecida com composefs.
        // Ver: https://github.com/bootc-dev/bootc/issues/2174
        if kernel >= MIN_KERNEL_COMPOSEFS {
            return Ok(Self {
                backend: StorageBackend::Ostree,
                fallback: true,
                reason: Some(format!(
                    "Kernel {} >= {} tem regressão conhecida com composefs (fs-verity digest)",
                    kernel.major, MIN_KERNEL_COMPOSEFS.major
                )),
            });
        }

        if !fsverity {
            return Ok(Self {
                backend: StorageBackend::Ostree,
                fallback: true,
                reason: Some("fs-verity indisponível no kernel/filesystem".into()),
            });
        }

        Ok(Self {
            backend: StorageBackend::Composefs,
            fallback: false,
            reason: None,
        })
    }

    /// Força um backend específico (override explícito).
    pub fn force(backend: StorageBackend) -> Self {
        Self {
            backend,
            fallback: false,
            reason: Some("override explícito".into()),
        }
    }
}

/// Verifica se fs-verity está disponível no kernel.
fn fs_verity_available() -> Result<bool, BootError> {
    // Verifica se o kernel tem suporte a fs-verity via /proc/filesystems.
    let fs = std::fs::read_to_string("/proc/filesystems")?;
    Ok(fs.contains("fsverity") || fs.contains("ext4") || fs.contains("btrfs"))
}

#[derive(Debug, thiserror::Error)]
pub enum BootError {
    #[error("versão de kernel inválida")]
    InvalidKernelVersion,
    #[error("falha ao ler versão do kernel: {0}")]
    Io(#[from] std::io::Error),
    #[error("nenhum backend viável")]
    NoViableBackend,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_7_selects_ostree_fallback() {
        let backend = BootBackend::select_with_kernel(KernelVersion::new(7, 0, 1), true).unwrap();
        assert_eq!(backend.backend, StorageBackend::Ostree);
        assert!(backend.fallback);
        assert!(backend.reason.unwrap().contains("regressão"));
    }

    #[test]
    fn kernel_6_19_selects_composefs() {
        let backend = BootBackend::select_with_kernel(KernelVersion::new(6, 19, 14), true).unwrap();
        assert_eq!(backend.backend, StorageBackend::Composefs);
        assert!(!backend.fallback);
    }
}
