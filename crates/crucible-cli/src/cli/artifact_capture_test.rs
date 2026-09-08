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
fn lifecycle_artifact_bundle_restores_without_source_store()
-> Result<(), Box<dyn std::error::Error>> {
    let object = b"normalized signal object".to_vec();
    let identity = crucible::ContentHash::from_bytes(&object);
    let bundle = encode_lifecycle_artifact_bundle(
        &BTreeMap::from([(identity, object.clone())]),
        object.len() as u64,
    )?;

    let restored = decode_lifecycle_artifact_bundle(&bundle, object.len() as u64)?;
    assert_eq!(restored.get(&identity)?, object);
    Ok(())
}

#[test]
fn lifecycle_artifact_bundle_rejects_tampered_world_object()
-> Result<(), Box<dyn std::error::Error>> {
    let object = b"immutable world block base".to_vec();
    let identity = crucible::ContentHash::from_bytes(&object);
    let mut bundle = encode_lifecycle_artifact_bundle(
        &BTreeMap::from([(identity, object.clone())]),
        object.len() as u64,
    )?;
    let last = bundle
        .last_mut()
        .ok_or_else(|| std::io::Error::other("bundle fixture is empty"))?;
    *last ^= 1;

    let error = decode_lifecycle_artifact_bundle(&bundle, object.len() as u64)
        .err()
        .ok_or_else(|| std::io::Error::other("tampered bundle must fail"))?;
    assert!(
        error.to_string().contains("failed authentication"),
        "{error}"
    );
    Ok(())
}

#[test]
fn lifecycle_artifact_bundle_enforces_aggregate_payload_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let object = b"world object exceeds configured aggregate".to_vec();
    let identity = crucible::ContentHash::from_bytes(&object);
    let error = encode_lifecycle_artifact_bundle(
        &BTreeMap::from([(identity, object.clone())]),
        (object.len() - 1) as u64,
    )
    .err()
    .ok_or_else(|| std::io::Error::other("oversized lifecycle bundle must fail"))?;

    assert!(error.to_string().contains("aggregate limit"));

    let bundle = encode_lifecycle_artifact_bundle(
        &BTreeMap::from([(identity, object.clone())]),
        object.len() as u64,
    )?;
    let decode_error = decode_lifecycle_artifact_bundle(&bundle, (object.len() - 1) as u64)
        .err()
        .ok_or_else(|| std::io::Error::other("oversized decoded bundle must fail"))?;
    assert!(decode_error.to_string().contains("aggregate limit"));
    Ok(())
}

#[test]
fn lifecycle_artifact_bundle_carries_block_and_ninep_bases()
-> Result<(), Box<dyn std::error::Error>> {
    let source = crucible::happy_path_scenario()?.scenario;
    let owner = source
        .world()
        .vm_nodes()
        .first()
        .ok_or_else(|| std::io::Error::other("fixture has no VM node"))?
        .clone();
    let store = crucible::MemoryDagStore::new();
    let base = vec![0x5a_u8; 4096];
    let identity = store.put(&base)?;
    let tree = crucible_device::FsTree::try_new(crucible_device::Node::Directory {
        children: [(
            String::from("fixture"),
            crucible_device::Node::File {
                content: b"representative ninep object".to_vec(),
            },
        )]
        .into_iter()
        .collect(),
    })?;
    let tree_bytes = tree.canonical_bytes();
    let tree_identity = store.put(&tree_bytes)?;
    let block = crucible::WorldIoNode::block(
        crucible::NodeId {
            name: String::from("artifact-block"),
        },
        owner.id.clone(),
        crucible::WorldIoCoreConfig::new(0),
        crucible::ContentAddressedBlobRef::from_hash(identity),
        base.len() as u64,
        crucible::WorldBlockLatency::new(100, 100, 100, 100, 1),
    );
    let ninep = crucible::WorldIoNode::ninep(
        crucible::NodeId {
            name: String::from("artifact-ninep"),
        },
        owner.id.clone(),
        crucible::WorldIoCoreConfig::new(0),
        crucible::ContentAddressedBlobRef::from_hash(tree_identity),
        crucible::WorldNinePLatency::new(100, 100, 1),
    );
    let world = crucible::World::from_node_defs_and_links(
        vec![
            crucible::WorldNodeDef::Vm(owner),
            crucible::WorldNodeDef::Io(block),
            crucible::WorldNodeDef::Io(ninep),
        ],
        Vec::new(),
    )?;

    let payloads = lifecycle_artifact_payloads(
        &world,
        crucible::Plan::empty().fault_signals(),
        &store,
        None,
    )?;
    let bundle = payloads
        .iter()
        .find(|payload| payload.media_type == LIFECYCLE_ARTIFACT_BUNDLE_MEDIA_TYPE)
        .ok_or_else(|| std::io::Error::other("lifecycle artifact bundle is absent"))?;
    let restored = decode_lifecycle_artifact_bundle(
        &bundle.bytes,
        crucible::FaultResourceLimits::default().fat_checkpoint_bytes,
    )?;

    assert_eq!(restored.get(&identity)?, base);
    assert_eq!(restored.get(&tree_identity)?, tree_bytes);
    Ok(())
}

#[test]
fn lifecycle_artifact_capture_rejects_missing_world_object()
-> Result<(), Box<dyn std::error::Error>> {
    let source = crucible::happy_path_scenario()?.scenario;
    let owner = source
        .world()
        .vm_nodes()
        .first()
        .ok_or_else(|| std::io::Error::other("fixture has no VM node"))?
        .clone();
    let missing = crucible::ContentHash::from_bytes(b"absent block base");
    let block = crucible::WorldIoNode::block(
        crucible::NodeId {
            name: String::from("missing-block"),
        },
        owner.id.clone(),
        crucible::WorldIoCoreConfig::new(0),
        crucible::ContentAddressedBlobRef::from_hash(missing),
        4096,
        crucible::WorldBlockLatency::new(100, 100, 100, 100, 1),
    );
    let world = crucible::World::from_node_defs_and_links(
        vec![
            crucible::WorldNodeDef::Vm(owner),
            crucible::WorldNodeDef::Io(block),
        ],
        Vec::new(),
    )?;
    let store = crucible::MemoryDagStore::new();

    let error = lifecycle_artifact_payloads(
        &world,
        crucible::Plan::empty().fault_signals(),
        &store,
        None,
    )
    .err()
    .ok_or_else(|| std::io::Error::other("missing world artifact must fail"))?;

    assert!(error.to_string().contains("collect world I/O artifact"));
    Ok(())
}
