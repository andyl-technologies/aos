//! Version-three codec and protected historical-provenance regressions.
//!
//! Synthetic observation fields here are audit-format fixtures, never live
//! `CurrentRuntimeScope` values. Only the kernel/Host path can qualify issuance.

#![allow(
    clippy::unwrap_used,
    reason = "Audit fixtures and regression assertions intentionally panic."
)]

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use aos_sandbox_core::{OperationId, PrincipalId};
use sha2::{Digest as _, Sha256};

use super::super::{
    MAXIMUM_RECORD_BYTES, PublisherAuthorityLimits, PublisherCapabilityRegistry, RECORD_KEY_BYTES,
    capability_key, decode_record, encode_record_complete,
};
use super::*;
use crate::publication::{
    AuthorityPublicationStore,
    tests::{activation_claim, runtime_scope_activation_fixture},
};
use crate::runtime_authority::{
    RuntimeAuthorityIntentV1, RuntimeAuthorityLimits, RuntimeAuthorityStore,
};
use crate::{
    EffectFailure, EffectObservation, EffectPlan, EffectReceipt, IdempotencyKey, JournalLimits,
    JournalRecord, JournalTransaction, OperationPlan, Reconciler, RecordNamespace,
    SingleNodeEffectExecutor,
};

struct NoEffects;
impl SingleNodeEffectExecutor for NoEffects {
    fn observe(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        panic!("audit fixture must not dispatch effects");
    }
    fn apply(
        &mut self,
        _: OperationId,
        _: u32,
        _: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        panic!("audit fixture must not dispatch effects");
    }
}

fn open(path: &std::path::Path) -> Journal {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    Journal::open_protected_at_uid(
        path,
        "runtime-issuance.journal",
        JournalLimits::default(),
        std::fs::metadata(path).unwrap().uid(),
    )
    .unwrap()
    .0
}

fn activate(
    reconciler: &mut Reconciler<NoEffects>,
    generation: u8,
    revoked: bool,
) -> RuntimeAuthorityBindingV1 {
    let (draft, prepared) = runtime_scope_activation_fixture(u64::from(generation));
    let sandbox = draft.manifest().manifest().sandbox();
    let effect = draft.bind_effect(draft.templates()[0].digest()).unwrap();
    let revision = (generation > 1).then_some(u64::from(generation) - 1);
    let intent = if revoked {
        RuntimeAuthorityIntentV1::revoke(revision).unwrap()
    } else {
        RuntimeAuthorityIntentV1::bind_holder(PrincipalId::from_bytes([0x91; 16]), revision)
            .unwrap()
    };
    let operation = OperationId::from_bytes([generation; 16]);
    let plan = OperationPlan::ownership_gated(
        operation,
        IdempotencyKey::new(vec![generation]).unwrap(),
        [generation; 32],
        vec![generation],
        vec![generation],
        vec![effect],
        activation_claim(&draft, u64::from(generation)),
        draft.clone(),
    )
    .unwrap()
    .with_runtime_authority(intent)
    .unwrap();
    reconciler.accept(&plan).unwrap();
    let activation = AuthorityPublicationStore::new(reconciler.journal_mut())
        .prepare_gate_activation(&draft, &prepared)
        .unwrap();
    reconciler
        .activate_ownership_gate(operation, activation)
        .unwrap();
    RuntimeAuthorityStore::load(reconciler.journal_mut(), RuntimeAuthorityLimits::default())
        .unwrap()
        .current(sandbox)
        .unwrap()
        .unwrap()
}

fn evidence(
    binding: &RuntimeAuthorityBindingV1,
) -> (
    CapabilityRecord,
    IssuanceDecisionMetadataV1,
    RuntimeIssuanceEvidenceV1,
) {
    let mut draft = super::super::issuance_tests::capability_draft(30, 3);
    let manifest = binding.manifest().manifest();
    draft.holder = binding.holder().unwrap();
    draft.root_subject = draft.holder;
    draft.project = manifest.project();
    draft.sandbox = Some(manifest.sandbox());
    draft.incarnation = Some(manifest.incarnation());
    draft.assignment_epoch = Some(manifest.epoch());
    let capability = CapabilityRecord::issue(draft).unwrap();
    let metadata = super::super::issuance_tests::metadata(30, 3);
    let runtime = RuntimeIssuanceEvidenceV1 {
        binding_revision: binding.revision(),
        binding_digest: binding.digest(),
        publication_digest: binding.publication_digest(),
        assignment_digest: binding.assignment_digest(),
        lease_generation: binding.lease_generation(),
        lease_digest: binding.lease_digest(),
        payload_scope_handle: [33; 32],
        boot_id: metadata.boot_id(),
        clock_provenance: metadata.clock_provenance(),
        observed_wall_seconds: 150,
        observed_boottime_nanoseconds: 1_000,
        expires_wall_seconds: 180,
        deadline_boottime_nanoseconds: 30_000_001_000,
    };
    (capability, metadata, runtime)
}

fn encoded(
    capability: &CapabilityRecord,
    metadata: &IssuanceDecisionMetadataV1,
    runtime: &RuntimeIssuanceEvidenceV1,
) -> Vec<u8> {
    encode_record_v3(
        DurableCapabilityStateV1::Active,
        capability,
        &(metadata.clone(), metadata.validate_for(capability).unwrap()),
        runtime,
        MAXIMUM_RECORD_BYTES,
    )
    .unwrap()
}

fn install_audit_fixture(journal: &mut Journal, capability: &CapabilityRecord, bytes: Vec<u8>) {
    journal
        .commit(
            &JournalTransaction::new(
                [70; 16],
                vec![JournalRecord::put(
                    RecordNamespace::PublisherAuthority,
                    capability_key(capability.id()).to_vec(),
                    bytes,
                )],
            )
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn version_three_retains_historical_origin_after_renewal_revocation_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let binding = activate(&mut reconciler, 1, false);
    let (capability, metadata, runtime) = evidence(&binding);
    let bytes = encoded(&capability, &metadata, &runtime);
    let limits =
        PublisherAuthorityLimits::new(1, bytes.len(), RECORD_KEY_BYTES + bytes.len()).unwrap();
    install_audit_fixture(reconciler.journal_mut(), &capability, bytes.clone());
    let too_small =
        limits.with_runtime_limits(RuntimeAuthorityLimits::new(1, 1_000_000, 10_000_000).unwrap());
    assert!(matches!(
        PublisherCapabilityRegistry::load(reconciler.journal_mut(), too_small),
        Err(PublisherAuthorityError::RuntimeAuthority(_))
    ));
    let registry = PublisherCapabilityRegistry::load(reconciler.journal_mut(), limits).unwrap();
    assert_eq!(
        registry.resolve_current(capability.id()).unwrap(),
        capability
    );
    assert_eq!(
        registry
            .resolve_issuance(capability.id())
            .unwrap()
            .unwrap()
            .runtime(),
        Some(&runtime)
    );

    activate(&mut reconciler, 2, false);
    activate(&mut reconciler, 3, true);
    let mut registry = PublisherCapabilityRegistry::load(reconciler.journal_mut(), limits).unwrap();
    assert_eq!(
        registry
            .resolve_issuance(capability.id())
            .unwrap()
            .unwrap()
            .runtime(),
        Some(&runtime)
    );
    registry
        .revoke_from_trusted_controller([71; 16], capability.id())
        .unwrap();
    let revoked = registry.resolve_issuance(capability.id()).unwrap().unwrap();
    assert!(revoked.is_revoked());
    assert_eq!(revoked.runtime(), Some(&runtime));
    assert_eq!(
        reconciler
            .journal_mut()
            .get(
                RecordNamespace::PublisherAuthority,
                &capability_key(capability.id())
            )
            .unwrap()
            .len(),
        bytes.len()
    );
    reconciler.journal_mut().compact().unwrap();
    drop(reconciler);

    let mut journal = open(directory.path());
    let registry = PublisherCapabilityRegistry::load(&mut journal, limits).unwrap();
    assert!(matches!(
        registry.resolve_current(capability.id()),
        Err(PublisherAuthorityError::Revoked)
    ));
    assert_eq!(
        registry.resolve_issuance(capability.id()).unwrap().unwrap(),
        revoked
    );
}

#[test]
fn canonical_version_three_has_a_fixed_golden_and_closed_bounded_shape() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let binding = activate(&mut reconciler, 1, false);
    let (capability, metadata, runtime) = evidence(&binding);
    let bytes = encoded(&capability, &metadata, &runtime);
    // Pins field order and complete audit facts; update only with an intentional format change.
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        "a1f2b079f95582b4ba79d5cc37f1a548e10588a08ea95d21c941904bdec5e4f3"
    );
    let decoded = decode_record(&capability_key(capability.id()), &bytes, bytes.len()).unwrap();
    assert_eq!(decoded.runtime, Some(runtime.clone()));
    assert!(decode_record(&capability_key(capability.id()), &bytes, bytes.len() - 1).is_err());
    assert!(
        encode_record_v3(
            DurableCapabilityStateV1::Active,
            &capability,
            &(
                metadata.clone(),
                metadata.validate_for(&capability).unwrap()
            ),
            &runtime,
            bytes.len() - 1
        )
        .is_err()
    );
    for field in ["issuance", "claims_digest", "runtime"] {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            decode_record(
                &capability_key(capability.id()),
                &serde_json::to_vec(&value).unwrap(),
                MAXIMUM_RECORD_BYTES
            )
            .is_err()
        );
    }
    let mut unknown = bytes.clone();
    unknown.pop();
    unknown.extend_from_slice(b",\"extra\":0}");
    assert!(
        decode_record(
            &capability_key(capability.id()),
            &unknown,
            MAXIMUM_RECORD_BYTES
        )
        .is_err()
    );
    let mut downgraded = bytes.clone();
    downgraded[b"{\"version\":".len()] = b'2';
    assert!(
        decode_record(
            &capability_key(capability.id()),
            &downgraded,
            MAXIMUM_RECORD_BYTES
        )
        .is_err()
    );
    let old = encode_record_complete(
        DurableCapabilityStateV1::Active,
        &capability,
        Some(&(
            metadata.clone(),
            metadata.validate_for(&capability).unwrap(),
        )),
        None,
        MAXIMUM_RECORD_BYTES,
    )
    .unwrap();
    assert!(
        decode_record(&capability_key(capability.id()), &old, MAXIMUM_RECORD_BYTES)
            .unwrap()
            .runtime
            .is_none()
    );
}

#[test]
fn runtime_provenance_substitution_is_rejected_by_protected_replay() {
    for field in 0..6 {
        let directory = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
        let binding = activate(&mut reconciler, 1, false);
        let (capability, metadata, mut runtime) = evidence(&binding);
        match field {
            0 => runtime.binding_revision += 1,
            1 => runtime.binding_digest = ObjectDigest::from_bytes([99; 32]),
            2 => runtime.publication_digest = ObjectDigest::from_bytes([99; 32]),
            3 => runtime.assignment_digest = ObjectDigest::from_bytes([99; 32]),
            4 => runtime.lease_generation += 1,
            5 => runtime.lease_digest = ObjectDigest::from_bytes([99; 32]),
            _ => unreachable!(),
        }
        let bytes = encoded(&capability, &metadata, &runtime);
        decode_record(
            &capability_key(capability.id()),
            &bytes,
            MAXIMUM_RECORD_BYTES,
        )
        .unwrap();
        install_audit_fixture(reconciler.journal_mut(), &capability, bytes);
        assert!(
            PublisherCapabilityRegistry::load(
                reconciler.journal_mut(),
                PublisherAuthorityLimits::default()
            )
            .is_err(),
            "accepted field {field}"
        );
    }
}

#[test]
fn timing_identity_and_zero_field_substitution_are_rejected_by_the_codec() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let binding = activate(&mut reconciler, 1, false);
    let (capability, metadata, runtime) = evidence(&binding);
    for field in 0..10 {
        let mut changed = runtime.clone();
        match field {
            0 => changed.binding_revision = 0,
            1 => changed.binding_digest = ObjectDigest::from_bytes([0; 32]),
            2 => changed.payload_scope_handle = [0; 32],
            3 => changed.boot_id = [99; 16],
            4 => changed.clock_provenance = [99; 16],
            5 => changed.observed_wall_seconds = 151,
            6 => {
                changed.observed_boottime_nanoseconds = metadata.observed_boottime_nanoseconds() + 1
            }
            7 => changed.expires_wall_seconds = 150,
            8 => changed.deadline_boottime_nanoseconds += 1,
            9 => {
                changed.expires_wall_seconds = 181;
                changed.deadline_boottime_nanoseconds += 1_000_000_000;
            }
            _ => unreachable!(),
        }
        let bytes = encoded(&capability, &metadata, &changed);
        assert!(
            decode_record(
                &capability_key(capability.id()),
                &bytes,
                MAXIMUM_RECORD_BYTES
            )
            .is_err(),
            "accepted field {field}"
        );
    }
}

#[test]
fn missing_runtime_history_cannot_be_replaced_by_issuance_claims() {
    let directory = tempfile::tempdir().unwrap();
    let mut reconciler = Reconciler::new(open(directory.path()), NoEffects);
    let binding = activate(&mut reconciler, 1, false);
    let (capability, metadata, runtime) = evidence(&binding);
    install_audit_fixture(
        reconciler.journal_mut(),
        &capability,
        encoded(&capability, &metadata, &runtime),
    );
    let keys: Vec<_> = reconciler
        .journal_mut()
        .records(RecordNamespace::RuntimeAuthority)
        .map(|(key, _)| key.to_vec())
        .collect();
    reconciler
        .journal_mut()
        .commit(
            &JournalTransaction::new(
                [72; 16],
                keys.into_iter()
                    .map(|key| JournalRecord::delete(RecordNamespace::RuntimeAuthority, key))
                    .collect(),
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        PublisherCapabilityRegistry::load(
            reconciler.journal_mut(),
            PublisherAuthorityLimits::default()
        )
        .is_err()
    );
}
