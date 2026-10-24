//! Encoded geometry tests over actual DAG bytes and dependency metadata.

#![cfg(test)]

use super::*;
use crate::node_adapters::condition_debug_model::dag::EvidenceDag;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn encoded_credit_matches_body_residues_and_complete_dependency_rows() -> TestResult {
    for length in 0..=8 {
        let mut store = EvidenceDag::new(16, 1 << 20);
        let leaf = store
            .add(&vec![0x5c; length], "application/octet-stream", Vec::new())
            .map_err(|failure| failure.reason)?;
        let branch = store
            .add(
                b"retained original branch",
                "text/plain",
                vec![leaf.clone()],
            )
            .map_err(|failure| failure.reason)?;
        let root = store
            .add(
                b"original complete root",
                "application/json",
                vec![branch, leaf],
            )
            .map_err(|failure| failure.reason)?;
        let objects = store.closure(&root).map_err(|failure| failure.reason)?;
        let measured = encoded_dag_length(&root, &objects).map_err(|failure| failure.reason)?;
        let bytes = store.encode(vec![root]).map_err(|failure| failure.reason)?;

        assert_eq!(measured, bytes.len());
        let (decoded, roots) =
            EvidenceDag::decode(&bytes, 16, measured).map_err(|failure| failure.reason)?;
        assert_eq!(
            decoded.encode(roots).map_err(|failure| failure.reason)?,
            bytes
        );
    }
    Ok(())
}

#[test]
fn complete_encoded_budget_refuses_one_byte_short_without_losing_originals() -> TestResult {
    let mut original = EvidenceDag::new(16, 1 << 20);
    let root = original
        .add(&vec![0x5c; 4096], "application/octet-stream", Vec::new())
        .map_err(|failure| failure.reason)?;
    let objects = original.closure(&root).map_err(|failure| failure.reason)?;
    let measured = encoded_dag_length(&root, &objects).map_err(|failure| failure.reason)?;
    let bytes = original
        .encode(vec![root.clone()])
        .map_err(|failure| failure.reason)?;

    assert!(EvidenceDag::decode(&bytes, 16, measured - 1).is_err());
    assert_eq!(
        original
            .encode(vec![root])
            .map_err(|failure| failure.reason)?,
        bytes
    );
    Ok(())
}
