//! Private format negatives and exact qualification identity, without native proof.

// crucible-lint: allow rust-allow -- closed private data fixture assertions deliberately panic.
#![allow(clippy::unwrap_used)]

use super::*;

fn fixture() -> (
    ReferenceProfile,
    ReferenceServiceBootstrap,
    InstalledContent,
) {
    let artifact = canonical::content_ref(
        b"unexecuted codec fixture artifact",
        "application/octet-stream",
    )
    .unwrap();
    let profile = ReferenceProfile::build_public_linked(
        Id::new("node").unwrap(),
        Id::new("owner").unwrap(),
        artifact.clone(),
        artifact,
        U64::new(1000),
        U64::new(1_000_000_000),
        true,
    )
    .unwrap();
    let authority = LiveAuthority {
        schema_version: 1,
        session_id: Id::new("session").unwrap(),
        incarnation_id: Id::new("incarnation").unwrap(),
        realization_id: Id::new("realization").unwrap(),
        activation_id: None,
        world_generation: U64::new(0),
        owner_generation: U64::new(1),
        input_epoch: Id::new("input-epoch").unwrap(),
        host_receipt: canonical::content_ref(b"constructed below", "text/plain").unwrap(),
        extensions: Extensions::new(),
    };
    let bootstrap = ReferenceServiceBootstrap::fixture(
        &profile,
        authority,
        Bytes::new(vec![7; 32]),
        U64::new(1000),
        crate::handshake::Limits {
            frame_bytes: U64::new(1_048_576),
            nesting: U64::new(64),
            requests: U64::new(16),
            journal_entries: U64::new(256),
            blob_chunk_bytes: U64::new(16384),
        },
        ResourceLimits {
            cpu_budget_ns: U64::new(4_000_000_000),
            memory_bytes: U64::new(512 * 1024 * 1024),
            writable_bytes: U64::new(0),
            processes: U64::new(2),
            descriptors: U64::new(32),
            pending_events: U64::new(16),
            content_bytes: U64::new(16 * 1024 * 1024),
            maximum_operations: U64::new(8),
            extensions: Extensions::new(),
        },
        canonical::hash(
            "cnp.world-binding.v1",
            b"codec fixture without qualification acceptance",
        )
        .unwrap(),
    )
    .unwrap();
    let bytes = b"caller-supplied evidence; not an accepted native certificate".to_vec();
    let content = InstalledContent {
        reference: canonical::content_ref(&bytes, "text/plain").unwrap(),
        bytes: Bytes::new(bytes),
    };
    (profile, bootstrap, content)
}

#[test]
fn installed_launch_commits_exact_supplied_evidence_and_preserves_legacy_binding() {
    let (profile, bootstrap, qualification) = fixture();
    let legacy = profile.bind(bootstrap.authority.clone()).unwrap();
    assert_eq!(
        legacy,
        profile
            .bind_qualified(bootstrap.authority.clone(), &[])
            .unwrap()
    );
    let launch = bootstrap
        .install_qualifications(&profile, vec![qualification.clone()])
        .unwrap();
    let installed = profile
        .bind_qualified(
            launch.bootstrap.authority.clone(),
            &launch.qualification_refs,
        )
        .unwrap();
    assert_ne!(
        legacy.0.identity().unwrap(),
        installed.0.identity().unwrap()
    );
    assert_ne!(
        legacy.1.identity().unwrap(),
        installed.1.identity().unwrap()
    );
    assert_eq!(
        installed.0.compatibility.qualification_refs,
        vec![qualification.reference.clone()]
    );
    let receipt_bytes = launch
        .bootstrap
        .installed_content
        .iter()
        .find(|content| content.reference == launch.bootstrap.admission_receipt)
        .unwrap();
    let receipt: ControlReceipt = canonical::decode(receipt_bytes.bytes.as_slice(), 65536).unwrap();
    let record_bytes = launch
        .bootstrap
        .installed_content
        .iter()
        .find(|content| content.reference == receipt.record_ref)
        .unwrap();
    let admission: AdmissionRecord =
        canonical::decode(record_bytes.bytes.as_slice(), 65536).unwrap();
    assert_eq!(
        admission.binding_hashes,
        vec![installed.0.identity().unwrap()]
    );
    assert_eq!(admission.qualification_refs, vec![qualification.reference]);
    assert_eq!(receipt.issuer, ReceiptIssuer::Host);
    launch.validate().unwrap();
}

#[test]
fn installed_launch_refuses_missing_changed_duplicate_and_foreign_edition_evidence() {
    let (profile, bootstrap, qualification) = fixture();
    assert!(
        bootstrap
            .clone()
            .install_qualifications(&profile, Vec::new())
            .is_err()
    );
    assert!(
        bootstrap
            .clone()
            .install_qualifications(&profile, vec![qualification.clone(), qualification.clone()])
            .is_err()
    );
    let mut changed = qualification.clone();
    changed.bytes = Bytes::new(b"changed original bytes".to_vec());
    assert!(
        bootstrap
            .clone()
            .install_qualifications(&profile, vec![changed])
            .is_err()
    );
    let launch = bootstrap
        .install_qualifications(&profile, vec![qualification.clone()])
        .unwrap();
    let mut value = serde_json::to_value(&launch).unwrap();
    value["schema_version"] = serde_json::json!(2);
    assert!(
        canonical::decode::<ReferenceServiceInstalledLaunchBootstrap>(
            &canonical::canonical_json(&value).unwrap(),
            16 * 1024 * 1024
        )
        .is_err()
    );
    value = serde_json::to_value(&launch).unwrap();
    value.as_object_mut().unwrap().remove("qualification_refs");
    assert!(serde_json::from_value::<ReferenceServiceInstalledLaunchBootstrap>(value).is_err());
    let mut missing = launch.clone();
    missing
        .bootstrap
        .installed_content
        .retain(|content| content.reference != qualification.reference);
    assert!(missing.validate().is_err());
    let mut foreign = launch;
    foreign.profile = PublicReferenceProfile::ChecksumJsonV1;
    assert!(foreign.validate().is_err());
}
