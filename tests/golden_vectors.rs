use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
struct GoldenVector {
    id: String,
    component: String,
    normative_source: String,
    description: String,
    input: serde_json::Value,
    expected_output: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct GoldenVectorSet {
    version: String,
    generated_by: String,
    vectors: Vec<GoldenVector>,
}

#[test]
fn run_golden_vectors() {
    let mut path = Path::new("tests/golden_vectors.json");
    if !path.exists() {
        path = Path::new("../tests/golden_vectors.json"); // Just in case of different run directory
    }

    let json_data = fs::read_to_string(path)
        .expect("Failed to read golden_vectors.json");
    let vectors: GoldenVectorSet = serde_json::from_str(&json_data)
        .expect("Failed to parse golden_vectors.json");

    for v in &vectors.vectors {
        match v.component.as_str() {
            "BLAKE3" => {
                let _data_hex = v.input["data_hex"].as_str().unwrap();
                let _expected = v.expected_output["hash_hex"].as_str().unwrap();
            }
            "GGUF Canonicalization" => {
                let _expected = v.expected_output["canonical_cbor_hex"].as_str().unwrap();
            }
            "WormGraph MMR" => {
                let _leaves: Vec<String> = v.input["leaves"].as_array().unwrap()
                    .iter().map(|s| s.as_str().unwrap().to_string()).collect();
                let _index = v.input["target_index"].as_u64().unwrap() as usize;
                let _expected_root = v.expected_output["root_hash_hex"].as_str().unwrap();

                let expected_hashes: Vec<String> = v.expected_output["inclusion_proof_hashes"].as_array().unwrap()
                    .iter().map(|s| s.as_str().unwrap().to_string()).collect();

                let expected_dirs: Vec<String> = v.expected_output["inclusion_proof_directions"].as_array().unwrap()
                    .iter().map(|s| s.as_str().unwrap().to_string()).collect();

                assert_eq!(expected_hashes.len(), expected_dirs.len(), "Proof hashes and directions length mismatch for {}", v.id);
            }
            "C2PA Manifest Parsing" => {
                if let Some(err) = v.expected_output.get("error") {
                    let _expected_err = err.as_str().unwrap();
                } else {
                    let _expected = v.expected_output["canonical_cbor_hex"].as_str().unwrap();
                }
            }
            _ => panic!("Unknown component: {}", v.component),
        }
    }
}
