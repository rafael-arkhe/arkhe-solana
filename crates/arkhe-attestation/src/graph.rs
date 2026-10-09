use crate::types::{AttestationGraph, Claim, ClaimStatus, Edge, Node, Propagated, Severity};
use chrono::Utc;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Detecta ciclos no grafo de dependências.
pub fn detect_cycles(claims: &BTreeMap<String, Claim>) -> Vec<Vec<String>> {
    let mut cycles = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();

    fn dfs(
        node: &str,
        claims: &BTreeMap<String, Claim>,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        if path.iter().any(|p| p == node) {
            let idx = path.iter().position(|p| p == node).unwrap();
            let mut cycle = path[idx..].to_vec();
            cycle.push(node.to_string());
            cycles.push(cycle);
            return;
        }
        if visited.contains(node) {
            return;
        }
        visited.insert(node.to_string());
        path.push(node.to_string());

        if let Some(c) = claims.get(node) {
            for dep in &c.depends_on {
                if claims.contains_key(dep) {
                    dfs(dep, claims, visited, path, cycles);
                }
            }
        }
        path.pop();
    }

    for cid in claims.keys() {
        let mut path = Vec::new();
        dfs(cid, claims, &mut visited, &mut path, &mut cycles);
    }
    cycles
}

/// Propaga `compromised` por BFS com profundidade correcta.
///
/// A fila guarda `(node_id, depth)`. A origem é depth=0. Cada
/// salto incrementa o depth. Visita cada nó uma vez (shortest path).
pub fn propagate_compromised(nodes: &[Node], edges: &[Edge]) -> Vec<Propagated> {
    // Adjacência reversa: quem depende de X?
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in edges {
        dependents
            .entry(e.to.as_str())
            .or_default()
            .push(e.from.as_str());
    }

    // Origens: nós compromised de base
    let origins: Vec<&str> = nodes
        .iter()
        .filter(|n| n.status == ClaimStatus::Compromised)
        .map(|n| n.id.as_str())
        .collect();

    let mut propagated = Vec::new();
    let mut visited: HashSet<&str> = origins.iter().copied().collect();

    let mut queue: VecDeque<(&str, u32)> = origins.iter().map(|id| (*id, 0u32)).collect();

    while let Some((current, depth)) = queue.pop_front() {
        if let Some(deps) = dependents.get(current) {
            for &dependent in deps {
                if visited.contains(dependent) {
                    continue;
                }
                visited.insert(dependent);

                let new_depth = depth + 1;
                let severity = match new_depth {
                    1 => Severity::High,
                    2..=3 => Severity::Medium,
                    _ => Severity::Low,
                };

                propagated.push(Propagated {
                    id: dependent.to_string(),
                    upstream: current.to_string(),
                    depth: new_depth,
                    severity,
                });

                queue.push_back((dependent, new_depth));
            }
        }
    }

    propagated
}

/// Constrói o grafo de atestação a partir de um ledger.
pub fn build_graph(claims: &BTreeMap<String, Claim>) -> AttestationGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for (cid, c) in claims {
        nodes.push(Node {
            id: cid.clone(),
            status: c.status,
            verification_source: c.verification_source.clone(),
            falsifier: c.falsifier.clone(),
            source_files: c.source_files.clone(),
        });
        for dep in &c.depends_on {
            edges.push(Edge {
                from: cid.clone(),
                to: dep.clone(),
            });
        }
    }

    let cycles = detect_cycles(claims);
    let propagated = propagate_compromised(&nodes, &edges);
    let max_depth = propagated.iter().map(|p| p.depth).max().unwrap_or(0);

    AttestationGraph {
        generated_at: Utc::now().to_rfc3339(),
        nodes,
        edges,
        cycles,
        propagated_compromised: propagated,
        max_depth,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(id: &str, status: ClaimStatus, deps: &[&str]) -> (String, Claim) {
        (
            id.to_string(),
            Claim {
                claim_id: id.to_string(),
                status,
                verification_source: "cargo-test".to_string(),
                falsifier: None,
                source_files: vec![],
                depends_on: deps.iter().map(|s| s.to_string()).collect(),
                last_run: None,
            },
        )
    }

    #[test]
    fn bfs_depth_is_real_distance() {
        // A (compromised) <- B <- C <- D
        let mut claims = BTreeMap::new();
        claims.insert("A".into(), claim("A", ClaimStatus::Compromised, &[]).1);
        claims.insert("B".into(), claim("B", ClaimStatus::Conjecture, &["A"]).1);
        claims.insert("C".into(), claim("C", ClaimStatus::Conjecture, &["B"]).1);
        claims.insert("D".into(), claim("D", ClaimStatus::Conjecture, &["C"]).1);

        let graph = build_graph(&claims);
        let depths: HashMap<_, _> = graph
            .propagated_compromised
            .iter()
            .map(|p| (p.id.as_str(), p.depth))
            .collect();

        assert_eq!(depths.get("B"), Some(&1));
        assert_eq!(depths.get("C"), Some(&2));
        assert_eq!(depths.get("D"), Some(&3));
        assert_eq!(graph.max_depth, 3);
    }

    #[test]
    fn severity_by_depth() {
        let mut claims = BTreeMap::new();
        claims.insert("A".into(), claim("A", ClaimStatus::Compromised, &[]).1);
        claims.insert("B".into(), claim("B", ClaimStatus::Conjecture, &["A"]).1);
        claims.insert("C".into(), claim("C", ClaimStatus::Conjecture, &["B"]).1);
        claims.insert("D".into(), claim("D", ClaimStatus::Conjecture, &["C"]).1);
        claims.insert("E".into(), claim("E", ClaimStatus::Conjecture, &["D"]).1);

        let graph = build_graph(&claims);
        let sev: HashMap<_, _> = graph
            .propagated_compromised
            .iter()
            .map(|p| (p.id.as_str(), p.severity))
            .collect();

        assert_eq!(sev.get("B"), Some(&Severity::High));
        assert_eq!(sev.get("C"), Some(&Severity::Medium));
        assert_eq!(sev.get("D"), Some(&Severity::Medium));
        assert_eq!(sev.get("E"), Some(&Severity::Low));
    }

    #[test]
    fn cycles_detected() {
        let mut claims = BTreeMap::new();
        claims.insert("A".into(), claim("A", ClaimStatus::Conjecture, &["B"]).1);
        claims.insert("B".into(), claim("B", ClaimStatus::Conjecture, &["A"]).1);
        let graph = build_graph(&claims);
        assert!(!graph.cycles.is_empty());
    }
}
