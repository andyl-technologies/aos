//! Checks complete Stage receipt rows independently of native source eligibility.

use super::*;
use crucible_node_contract::canonical;

fn evidence() -> Result<OriginalInputEvidence, crucible_node_contract::ContractError> {
    let leaf = InputPayload {
        reference: canonical::content_ref(b"original inventory", "application/octet-stream")?,
        bytes: b"original inventory".to_vec(),
    };
    let root_bytes = canonical::canonical_json(&serde_json::json!({"inventory": leaf.reference}))?;
    let root = InputPayload {
        reference: canonical::content_ref(&root_bytes, "application/json")?,
        bytes: root_bytes,
    };
    let mut objects = vec![root.clone(), leaf.clone()];
    objects.sort_by(|a, b| a.reference.cmp(&b.reference));
    let rows = objects
        .iter()
        .map(|object| OriginalLineageRow {
            object: object.reference.clone(),
            dependencies: if object.reference == root.reference {
                vec![leaf.reference.clone()]
            } else {
                vec![]
            },
        })
        .collect();
    Ok(OriginalInputEvidence {
        root: root.reference,
        objects,
        rows,
    })
}

#[test]
fn original_input_evidence_geometry_requires_every_body_and_edge()
-> Result<(), crucible_node_contract::ContractError> {
    let mut original = evidence()?;
    assert!(valid_geometry(&original, OriginalInputLineageLimits::default()).is_ok());
    let root = original
        .rows
        .iter_mut()
        .find(|row| row.object == original.root);
    if let Some(root) = root {
        root.dependencies.clear();
    }
    assert!(valid_geometry(&original, OriginalInputLineageLimits::default()).is_err());
    let mut original = evidence()?;
    original.objects[0].bytes.push(0);
    assert!(valid_geometry(&original, OriginalInputLineageLimits::default()).is_err());
    Ok(())
}

#[test]
fn original_input_evidence_geometry_counts_bodies_before_graph_storage()
-> Result<(), crucible_node_contract::ContractError> {
    let original = evidence()?;
    let bytes = original
        .objects
        .iter()
        .map(|object| object.bytes.len())
        .sum();
    let limits = OriginalInputLineageLimits {
        maximum_bytes: bytes,
        ..OriginalInputLineageLimits::default()
    };
    assert!(valid_geometry(&original, limits).is_ok());
    assert!(
        valid_geometry(
            &original,
            OriginalInputLineageLimits {
                maximum_bytes: bytes - 1,
                ..limits
            }
        )
        .is_err()
    );
    assert!(
        valid_geometry(
            &original,
            OriginalInputLineageLimits {
                maximum_edges: 0,
                ..limits
            }
        )
        .is_err()
    );
    Ok(())
}
