//! Tests extracted from the adjacent production module.

use super::*;

fn sample(index: u64, node: &str) -> VerifyFingerprintSample {
    VerifyFingerprintSample {
        index,
        instruction: index + 10,
        node: node.to_string(),
        digest: format!("blake3:{index:064x}"),
    }
}

#[test]
fn terminal_fingerprint_capture_selects_one_reindexed_sample_per_node()
-> Result<(), Box<dyn std::error::Error>> {
    let scenario = crucible::happy_path_scenario()?.scenario;
    let nodes = scenario.world().vm_nodes();
    let first = nodes
        .first()
        .ok_or_else(|| std::io::Error::other("fixture has no first node"))?;
    let second = nodes
        .get(1)
        .ok_or_else(|| std::io::Error::other("fixture has no second node"))?;
    let selected = select_live_qemu_artifact_fingerprints(
        nodes,
        vec![
            sample(0, &first.id.name),
            sample(1, &second.id.name),
            sample(2, &first.id.name),
            sample(3, &second.id.name),
        ],
        LiveQemuFingerprintScope::TerminalAllNodes,
    )?;
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].index, 0);
    assert_eq!(selected[0].node, first.id.name);
    assert_eq!(selected[1].index, 1);
    assert_eq!(selected[1].node, second.id.name);
    Ok(())
}

#[test]
fn terminal_fingerprint_capture_rejects_duplicate_node_suffix()
-> Result<(), Box<dyn std::error::Error>> {
    let scenario = crucible::happy_path_scenario()?.scenario;
    let nodes = scenario.world().vm_nodes();
    let first = nodes
        .first()
        .ok_or_else(|| std::io::Error::other("fixture has no first node"))?;
    let error = match select_live_qemu_artifact_fingerprints(
        nodes,
        vec![sample(0, &first.id.name), sample(1, &first.id.name)],
        LiveQemuFingerprintScope::TerminalAllNodes,
    ) {
        Err(error) => error,
        Ok(_) => panic!("duplicate terminal node samples must fail closed"),
    };
    assert!(error.to_string().contains("scenario VM nodes"));
    Ok(())
}

#[test]
fn signal_artifact_bundle_restores_without_source_store() -> Result<(), Box<dyn std::error::Error>>
{
    let object = b"normalized signal object".to_vec();
    let identity = crucible::ContentHash::from_bytes(&object);
    let bundle = encode_signal_artifact_bundle(&BTreeMap::from([(identity, object.clone())]))?;

    let restored = decode_signal_artifact_bundle(&bundle)?;
    assert_eq!(restored.get(&identity)?, object);
    Ok(())
}

#[test]
fn signal_artifact_bundle_rejects_tampered_objects() -> Result<(), Box<dyn std::error::Error>> {
    let object = b"normalized signal object".to_vec();
    let identity = crucible::ContentHash::from_bytes(&object);
    let mut bundle = encode_signal_artifact_bundle(&BTreeMap::from([(identity, object)]))?;
    let last = bundle
        .last_mut()
        .ok_or_else(|| std::io::Error::other("bundle fixture is empty"))?;
    *last ^= 1;

    let error = decode_signal_artifact_bundle(&bundle)
        .err()
        .ok_or_else(|| std::io::Error::other("tampered bundle must fail"))?;
    assert!(error.to_string().contains("failed authentication"));
    Ok(())
}
