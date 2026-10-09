//! Identity and complete immutable-content checks for the reference profile.

#![allow(clippy::unwrap_used)]

use super::*;

fn profile(quantum: u64) -> ReferenceProfile {
    ReferenceProfile::build(
        id("checksum").unwrap(),
        id("owner/checksum").unwrap(),
        canonical::content_ref(b"fixture-provider", "application/octet-stream").unwrap(),
        canonical::content_ref(b"fixture-device", "application/octet-stream").unwrap(),
        quantum.into(),
        1_000_000_000.into(),
    )
    .unwrap()
}

fn authority(incarnation: &str) -> LiveAuthority {
    LiveAuthority {
        schema_version: 1,
        session_id: id("test-session").unwrap(),
        incarnation_id: id(incarnation).unwrap(),
        realization_id: id("test-realization").unwrap(),
        activation_id: None,
        world_generation: 0.into(),
        owner_generation: 1.into(),
        input_epoch: id("test-input").unwrap(),
        host_receipt: canonical::content_ref(b"synthetic identity-only test", "text/plain")
            .unwrap(),
        extensions: Extensions::new(),
    }
}

#[test]
fn immutable_objects_resolve_exact_bytes_and_reject_alias_metadata() {
    let profile = profile(100);
    for entry in profile.content_objects() {
        assert_eq!(profile.content(&entry.reference).unwrap(), entry.bytes);
        assert_eq!(
            canonical::content_ref(&entry.bytes, &entry.reference.media_type).unwrap(),
            entry.reference
        );
    }

    let mut alias = profile.configuration_ref.clone();
    alias.length = alias.length.checked_add(1.into()).unwrap();
    assert!(profile.content(&alias).is_err());
    alias = profile.configuration_ref.clone();
    alias.media_type = "application/octet-stream".into();
    assert!(profile.content(&alias).is_err());
}

#[test]
fn incarnation_does_not_change_durable_binding_but_quantum_does() {
    let original = profile(100);
    let (first, first_owner) = original.bind(authority("first")).unwrap();
    let (second, second_owner) = original.bind(authority("second")).unwrap();
    assert_eq!(first.identity().unwrap(), second.identity().unwrap());
    assert_eq!(
        first_owner.identity().unwrap(),
        second_owner.identity().unwrap()
    );

    let (changed, _) = profile(101).bind(authority("first")).unwrap();
    assert_ne!(first.identity().unwrap(), changed.identity().unwrap());
    assert_ne!(
        first.compatibility.descriptor_hash,
        changed.compatibility.descriptor_hash
    );
}

#[test]
fn profile_claims_only_quantized_application_capabilities() {
    let profile = profile(100);
    assert_eq!(
        profile.guarantees.repeatability,
        Repeatability::Nondeterministic
    );
    assert_eq!(profile.guarantees.capture_scope, CaptureScope::None);
    assert_eq!(profile.guarantees.continuation, Continuation::Unsupported);
    assert!(!profile.guarantees.durable_restart);
    assert!(!profile.guarantees.isolated_fork);
    assert!(!profile.guarantees.conditional_replay);
    assert!(profile.node_manifest.state_formats.is_empty());
    assert!(profile.provider_manifest.qualification_refs.is_empty());
    assert_eq!(profile.capabilities.facets.len(), 1);
    assert_eq!(profile.operating_contract.mode, OperatingMode::Quantized);
    assert_eq!(profile.owner.participant_ids, vec![id("checksum").unwrap()]);
    assert_eq!(
        profile.owner.state_domain_ids,
        vec![id("owner/checksum/state").unwrap()]
    );
}

#[test]
fn zero_budgets_are_refused_before_profile_creation() {
    let artifact = canonical::content_ref(b"fixture", "application/octet-stream").unwrap();
    for (quantum, budget) in [(0, 1), (1, 0)] {
        assert!(
            ReferenceProfile::build(
                id("n").unwrap(),
                id("o").unwrap(),
                artifact.clone(),
                artifact.clone(),
                quantum.into(),
                budget.into()
            )
            .is_err()
        );
    }
}
