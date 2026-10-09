//! Native storage construction, immutable enrollment and sibling independence.

// These native fixtures panic when an asserted construction invariant fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_device::{BlockRequest, ninep::tree::Node};
use crucible_node_contract::{Id, canonical};

fn selected() -> InstalledNodeSelection {
    InstalledNodeSelection {
        node: Id::new("storage").unwrap(),
        owner: Id::new("owner/storage").unwrap(),
        kind: super::super::InstalledNodeKind::HostClock,
    }
}

fn block(reference: ContentRef) -> InstalledHostIoProfile {
    InstalledHostIoProfile::Block {
        base_image: reference,
        source_node: 7,
        read_ns: 1.into(),
        write_ns: 1.into(),
        flush_ns: 1.into(),
        get_length_ns: 1.into(),
        per_byte_ns: 1.into(),
    }
}

fn enroll(path: &std::path::Path, bytes: &[u8]) -> InstalledIoArtifact {
    std::fs::write(path, bytes).unwrap();
    InstalledIoArtifact::path(
        path.to_owned(),
        canonical::content_ref(bytes, "application/octet-stream").unwrap(),
    )
}

#[test]
fn block_models_own_independent_overlay_and_pending_response_state() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = enroll(&directory.path().join("base"), &vec![0xab; 4096]);
    let profile = block(artifact.expected.clone());
    let registry = BTreeMap::from([(artifact.expected.hash.digest.clone(), artifact.clone())]);
    let HostModel::Io(mut left) = build_model(&selected(), &profile, &registry).unwrap() else {
        panic!("expected actual storage model");
    };
    let HostModel::Io(right) = build_model(&selected(), &profile, &registry).unwrap() else {
        panic!("expected actual storage model");
    };
    let initial = right.checkpoint().canonical_bytes().unwrap();

    left.submit_fifo(10, &BlockRequest::write(1, 0, vec![7, 8, 9]))
        .unwrap();

    assert_ne!(left.checkpoint().canonical_bytes().unwrap(), initial);
    assert_eq!(right.checkpoint().canonical_bytes().unwrap(), initial);
    assert!(left.pending_completion_keys().next().is_some());
    assert!(right.pending_completion_keys().next().is_none());
    assert_eq!(read_artifact(&artifact).unwrap(), vec![0xab; 4096]);
}

#[test]
fn portable_selection_cannot_enroll_a_host_path_or_skip_native_timing() {
    let reference = canonical::content_ref(&[1], "application/octet-stream").unwrap();
    let profile = block(reference.clone());
    let mut value = serde_json::to_value(&profile).unwrap();
    value["path"] = serde_json::json!("/arbitrary/client/path");
    assert!(serde_json::from_value::<InstalledHostIoProfile>(value).is_err());
    assert!(build_model(&selected(), &profile, &BTreeMap::new()).is_err());

    let mut value = serde_json::to_value(profile).unwrap();
    value["read_ns"] = serde_json::json!("0");
    let zero: InstalledHostIoProfile = serde_json::from_value(value).unwrap();
    assert!(zero.validate().is_err());
}

#[test]
fn installed_artifact_is_verified_on_actual_open_before_native_construction() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = enroll(&directory.path().join("base"), &[1, 2, 3]);
    let profile = block(artifact.expected.clone());
    let registry = BTreeMap::from([(artifact.expected.hash.digest.clone(), artifact.clone())]);
    let InstalledIoArtifactSource::Path(path) = &artifact.source else {
        panic!("fixture must enroll an actual file")
    };
    std::fs::write(path, [3, 2, 1]).unwrap();

    assert!(build_model(&selected(), &profile, &registry).is_err());
    let symlink = directory.path().join("symlink");
    std::os::unix::fs::symlink(path, &symlink).unwrap();
    assert!(read_artifact(&InstalledIoArtifact::path(symlink, artifact.expected)).is_err());
}

#[test]
fn archive_only_enrollment_cannot_supply_bytes_for_fresh_native_models() {
    let expected = canonical::content_ref(&[1, 2, 3], "application/octet-stream").unwrap();
    let artifact = InstalledIoArtifact::archive_only(expected.clone());
    let registry = BTreeMap::from([(expected.hash.digest.clone(), artifact.clone())]);

    assert!(read_artifact(&artifact).is_err());
    assert!(build_model(&selected(), &block(expected), &registry).is_err());

    let mut excess = artifact;
    excess.expected.length = (MAXIMUM_IO_ARTIFACT_BYTES as u64 + 1).into();
    assert!(read_artifact(&excess).is_err());
}

#[test]
fn missing_path_never_implicitly_becomes_archive_only() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = enroll(&directory.path().join("base"), &[1, 2, 3]);
    let InstalledIoArtifactSource::Path(path) = &artifact.source else {
        panic!("fixture must enroll an actual file")
    };
    std::fs::remove_file(path).unwrap();

    assert!(read_artifact(&artifact).is_err());
    assert!(matches!(
        artifact.source,
        InstalledIoArtifactSource::Path(_)
    ));
}

#[test]
fn ninep_model_requires_actual_canonical_served_tree_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let tree = FsTree::try_new(Node::Directory {
        children: BTreeMap::new(),
    })
    .unwrap();
    let artifact = enroll(&directory.path().join("tree"), &tree.canonical_bytes());
    let profile = InstalledHostIoProfile::Ninep {
        tree: artifact.expected.clone(),
        source_node: 9,
        control_ns: 1.into(),
        data_ns: 1.into(),
        per_byte_ns: 1.into(),
    };
    let registry = BTreeMap::from([(artifact.expected.hash.digest.clone(), artifact)]);
    let model = build_model(&selected(), &profile, &registry).unwrap();
    assert!(matches!(&model,HostModel::Io(io) if io.ninep_device().is_some()));

    let bad = enroll(&directory.path().join("bad-tree"), &[1, 2, 3]);
    let invalid = InstalledHostIoProfile::Ninep {
        tree: bad.expected.clone(),
        source_node: 9,
        control_ns: 1.into(),
        data_ns: 1.into(),
        per_byte_ns: 1.into(),
    };
    assert!(
        build_model(
            &selected(),
            &invalid,
            &BTreeMap::from([(bad.expected.hash.digest.clone(), bad)])
        )
        .is_err()
    );
}

#[test]
fn archive_storage_validator_preserves_mutation_but_rejects_reconfigured_native_state() {
    let artifact_bytes = vec![0xab; 4096];
    let reference = canonical::content_ref(&artifact_bytes, "application/octet-stream").unwrap();
    let profile = block(reference);
    let HostModel::Io(mut actual) =
        build_model_from_bytes(&selected(), &profile, artifact_bytes.clone()).unwrap()
    else {
        panic!("expected native block storage");
    };
    actual
        .submit_fifo(10, &BlockRequest::write(1, 0, vec![7, 8, 9]))
        .unwrap();
    let original = actual.checkpoint().canonical_bytes().unwrap();

    validate_native_storage(&selected(), &profile, artifact_bytes.clone(), &original).unwrap();
    assert!(actual.pending_completion_keys().next().is_some());

    let mut alternate_latency = profile.clone();
    let InstalledHostIoProfile::Block { write_ns, .. } = &mut alternate_latency else {
        unreachable!()
    };
    *write_ns = 2.into();
    let mut alternate_source = profile.clone();
    let InstalledHostIoProfile::Block { source_node, .. } = &mut alternate_source else {
        unreachable!()
    };
    *source_node = 8;

    for alternate in [alternate_latency, alternate_source] {
        let HostModel::Io(changed) =
            build_model_from_bytes(&selected(), &alternate, artifact_bytes.clone()).unwrap()
        else {
            panic!("expected native block storage");
        };
        let changed_codec = changed.checkpoint().canonical_bytes().unwrap();
        assert!(
            validate_native_storage(
                &selected(),
                &profile,
                artifact_bytes.clone(),
                &changed_codec
            )
            .is_err(),
            "signed native bytes cannot replace independently installed timing or source identity"
        );
    }
    assert_eq!(actual.checkpoint().canonical_bytes().unwrap(), original);
}
