//! Independently enrolled script bytes and exact request-lane profile coherence.

// These native fixtures panic when an asserted construction invariant fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible::node_adapters::{ScriptedRequest, ScriptedRequestKind};
use crucible_device::BlockRequest;
use crucible_node_contract::canonical;

fn selected(profile: &InstalledScriptedSourceProfile) -> InstalledNodeSelection {
    InstalledNodeSelection {
        node: Id::new("source").unwrap(),
        owner: Id::new("source-owner").unwrap(),
        kind: super::super::InstalledNodeKind::HostScripted {
            profile: profile.clone(),
        },
    }
}

fn script() -> Vec<u8> {
    ScriptedSource::new(
        ScriptedRequestKind::Block,
        vec![ScriptedRequest {
            time_ps: 10,
            payload: BlockRequest::get_length(71).encode().unwrap(),
        }],
    )
    .unwrap()
    .script_bytes()
    .unwrap()
}

fn enroll(path: &std::path::Path, bytes: &[u8]) -> InstalledIoArtifact {
    std::fs::write(path, bytes).unwrap();
    InstalledIoArtifact::path(
        path.to_owned(),
        canonical::content_ref(bytes, "application/octet-stream").unwrap(),
    )
}

#[test]
fn source_requires_independent_enrollment_and_rechecks_actual_script_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let original = script();
    let artifact = enroll(&directory.path().join("script"), &original);
    let profile = InstalledScriptedSourceProfile {
        script: artifact.expected.clone(),
        consumer: Id::new("disk").unwrap(),
    };
    assert!(build_model(&selected(&profile), &profile, &BTreeMap::new()).is_err());
    let registry = BTreeMap::from([(artifact.expected.hash.digest.clone(), artifact.clone())]);
    let HostModel::ScriptedSource(source) =
        build_model(&selected(&profile), &profile, &registry).unwrap()
    else {
        panic!("source factory returned another model")
    };
    assert_eq!(source.script_bytes().unwrap(), original);
    assert_eq!(source.cursor(), 0);
    assert_eq!(source.time_ps(), 0);
    for (request, identity) in source.requests().iter().zip(source.payload_refs()) {
        identity.verify(&request.payload).unwrap();
    }
    let mut changed = original;
    let last = changed.len() - 1;
    changed[last] ^= 1;
    let super::super::io::InstalledIoArtifactSource::Path(path) = &artifact.source else {
        panic!("fixture must enroll an actual file")
    };
    std::fs::write(path, changed).unwrap();
    assert!(build_model(&selected(&profile), &profile, &registry).is_err());
}

#[test]
fn archive_only_script_cannot_start_a_fresh_request_source() {
    let expected = canonical::content_ref(&script(), "application/octet-stream").unwrap();
    let artifact = InstalledIoArtifact::archive_only(expected.clone());
    let profile = InstalledScriptedSourceProfile {
        script: expected.clone(),
        consumer: Id::new("disk").unwrap(),
    };
    let registry = BTreeMap::from([(expected.hash.digest, artifact)]);

    assert!(build_model(&selected(&profile), &profile, &registry).is_err());
}

#[test]
fn source_portable_profile_cannot_install_paths_or_accept_invalid_native_content() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = enroll(
        &directory.path().join("invalid-script"),
        b"syntactically measured, unsupported native script",
    );
    let profile = InstalledScriptedSourceProfile {
        script: artifact.expected.clone(),
        consumer: Id::new("disk").unwrap(),
    };
    let mut wire = serde_json::to_value(&profile).unwrap();
    wire["path"] = serde_json::json!("/client/chosen/path");
    assert!(serde_json::from_value::<InstalledScriptedSourceProfile>(wire).is_err());
    let registry = BTreeMap::from([(artifact.expected.hash.digest.clone(), artifact)]);
    assert!(build_model(&selected(&profile), &profile, &registry).is_err());
}

#[test]
fn installed_source_profile_matches_real_storage_request_schema_and_connection() {
    use super::super::{InstalledHostIoProfile, InstalledNodeKind};
    let directory = tempfile::tempdir().unwrap();
    let source = enroll(&directory.path().join("script"), &script());
    let base = enroll(&directory.path().join("base"), &[1, 2, 3]);
    let profile = InstalledScriptedSourceProfile {
        script: source.expected.clone(),
        consumer: Id::new("disk").unwrap(),
    };
    let io = InstalledNodeSelection {
        node: Id::new("disk").unwrap(),
        owner: Id::new("disk-owner").unwrap(),
        kind: InstalledNodeKind::HostIo {
            profile: InstalledHostIoProfile::Block {
                base_image: base.expected.clone(),
                source_node: 7,
                read_ns: 1.into(),
                write_ns: 1.into(),
                flush_ns: 1.into(),
                get_length_ns: 1.into(),
                per_byte_ns: 1.into(),
            },
        },
    };
    let registry = BTreeMap::from([
        (source.expected.hash.digest.clone(), source),
        (base.expected.hash.digest.clone(), base),
    ]);
    let host = canonical::content_ref(
        b"profile test executable identity",
        "application/octet-stream",
    )
    .unwrap();
    let world =
        super::super::profile::build_world(&[io, selected(&profile)], &host, &host, &registry)
            .unwrap()
            .scenario;
    let input = &world.descriptors[0].ports[0].lanes[0];
    let output = &world.descriptors[1].ports[0].lanes[0];
    assert_eq!(input.payload_schema, output.payload_schema);
    assert_eq!(
        world.descriptors[0].ports[0].interface_id,
        world.descriptors[1].ports[0].interface_id
    );
    assert_eq!(world.descriptors[1].ports[0].lanes.len(), 1);
    assert_eq!(output.direction, crucible_node_contract::Direction::Output);
    assert_eq!(world.world.connections.len(), 1);
    assert_eq!(
        world.world.connections[0].producer.node_id,
        Id::new("source").unwrap()
    );
    assert_eq!(
        world.world.connections[0].consumer.node_id,
        Id::new("disk").unwrap()
    );
}
