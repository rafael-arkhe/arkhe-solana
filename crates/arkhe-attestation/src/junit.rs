use crate::types::ClaimStatus;
use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::BTreeMap;
use std::path::Path;
use serde::{Deserialize, Serialize};

/// Resultado de um testcase parseado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub status: ClaimStatus,
    pub last_run: String,
}

/// Parse de JUnit XML (formato cargo-nextest / JUnit padrão).
///
/// Estrutura esperada:
///   <testsuites>
///     <testsuite ...>
///       <testcase name="..." classname="...">
///         <failure .../> | <error .../> | <skipped/>  (opcional)
///       </testcase>
///     </testsuite>
///   </testsuites>
pub fn parse_junit(path: &Path) -> Result<BTreeMap<String, TestResult>> {
    if !path.exists() {
        eprintln!("[aviso] XML ausente: {}", path.display());
        return Ok(BTreeMap::new());
    }

    let xml = std::fs::read_to_string(path)
        .with_context(|| format!("falha ao ler {}", path.display()))?;

    let mut reader = Reader::from_str(&xml);
    reader.config_mut().trim_text(true);

    let mut results = BTreeMap::new();
    let now = chrono::Utc::now().to_rfc3339();
    let mut buf = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_status = ClaimStatus::Verified;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"testcase" => {
                    current_name = None;
                    current_status = ClaimStatus::Verified;
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"name" {
                            current_name = Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }
                b"failure" | b"error" => {
                    current_status = ClaimStatus::Falsified;
                }
                b"skipped" => {
                    current_status = ClaimStatus::Partial;
                }
                _ => {}
            },
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"testcase" {
                    if let Some(name) = current_name.take() {
                        results.insert(
                            name.clone(),
                            TestResult {
                                name,
                                status: current_status,
                                last_run: now.clone(),
                            },
                        );
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                anyhow::bail!("erro a parsear XML {}: {}", path.display(), e);
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(results)
}
