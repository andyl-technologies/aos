//! Independent reviewer signatures, exact audiences and provider class isolation.

use super::super::NativeDirectUploadRuntime;
use super::*;
use aos_hub_core::storage_authority::{
    control::StorageAuthorityPublication, lease::*, ApproveStorageAuthorityAlias,
    AssociateStorageAuthorityBinding, AttestStorageAuthorityExclusivity,
    CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId, SetStorageAuthorityAdmission,
    StorageAuthorityAdmissionState, StorageAuthorityAliasSpec, StorageAuthorityCredentialMember,
    StorageAuthorityHost,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest as _;

const EXECUTOR: &str = "qualified-executor";

fn integer(value: i64) -> LeaseInteger {
    LeaseInteger::new(value).unwrap()
}

fn publication_for_binding(
    binding: Option<&aos_hub_core::db::BindingRecord>,
) -> StorageAuthorityPublication {
    let authority_id =
        PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    let authority = CreatePhysicalStorageAuthority {
        authority_id: authority_id.clone(),
        guard_namespace_id: "permanent-guard-namespace".into(),
        physical_resource_evidence_digest: "1".repeat(64),
        qualification_digest: "2".repeat(64),
        qualified_managed_prefix: "managed".into(),
    };
    let alias = ApproveStorageAuthorityAlias {
        alias_id: "alias-one".into(),
        authority_id: authority_id.clone(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("s3.fleet.test".into()),
            port: 443,
            bucket: "qualified-bucket".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority_id.clone(),
        alias_id: alias.alias_id.clone(),
        binding_id: binding.map_or(9_007_199_254_740_993, |binding| binding.id),
        binding_stable_id: binding
            .map_or_else(|| "binding-one".into(), |binding| binding.stable_id.clone()),
        binding_resource_version: binding
            .map_or(9_007_199_254_740_995, |binding| binding.resource_version),
        binding_write_revision: if binding.is_some() {
            1
        } else {
            9_007_199_254_740_997
        },
        binding_prefix: "managed/binding".into(),
    };
    let credentials = ["delete", "list", "presign", "read", "write"]
        .into_iter()
        .map(|purpose| StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: purpose.into(),
            generation: if binding.is_some() {
                1
            } else {
                9_007_199_254_741_001
            },
            secret_version_ref: format!("secret://fixture/{purpose}/v1"),
            credential_fingerprint: "4".repeat(64),
        })
        .collect();
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "attestation-one".into(),
        authority_id: authority_id.clone(),
        managed_prefix: "managed".into(),
        qualification_digest: authority.qualification_digest.clone(),
        provider_policy_evidence_digest: "5".repeat(64),
        executor_identity: EXECUTOR.into(),
        credentials,
        valid_until: if binding.is_some() { i64::MAX } else { 1000 },
    };
    let admission = SetStorageAuthorityAdmission {
        authority_id,
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: authority.guard_namespace_id.clone(),
        state: StorageAuthorityAdmissionState::Admitted,
        attestation_id: Some(attestation.attestation_id.clone()),
        association_ids: vec![association.association_id.clone()],
    };
    let digest = hex::encode(sha2::Sha256::digest(
        serde_json::to_vec(&admission).unwrap(),
    ));
    let publication = StorageAuthorityPublication {
        authority,
        aliases: vec![alias],
        associations: vec![association],
        attestation: Some(attestation),
        admission,
        generation: 1,
        digest,
    };
    publication
        .validate(&publication.authority.guard_namespace_id, EXECUTOR)
        .unwrap();
    publication
}

pub(crate) fn profile() -> DirectExternalStorageCapabilities {
    profile_from_publication(publication_for_binding(None))
}

fn profile_from_publication(
    publication: StorageAuthorityPublication,
) -> DirectExternalStorageCapabilities {
    let write = LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Write,
        "managed/binding",
        vec![
            LeaseEffect::Put,
            LeaseEffect::MultipartCreate,
            LeaseEffect::MultipartPart,
            LeaseEffect::MultipartComplete,
            LeaseEffect::MultipartAbort,
        ],
    )
    .unwrap();
    let read = LeaseCohort::from_publication(
        &publication,
        EXECUTOR,
        "association-one",
        LeasePurpose::Read,
        "managed/binding",
        vec![LeaseEffect::Head, LeaseEffect::Read],
    )
    .unwrap();
    let credential = |purpose: &str| DirectCredentialRevision {
        purpose: purpose.into(),
        credential_id: format!("protected-{purpose}"),
        generation: WireInteger::new(write.credential.generation.get() as u64),
        secret_version_ref: format!("secret://fixture/{purpose}/v1"),
        credential_fingerprint: "4".repeat(64),
    };
    DirectExternalStorageCapabilities {
        selector: DirectExternalProfileSelector {
            physical_authority_id: write.authority.authority_id.clone(),
            association: write.association.clone(),
            write_credential: credential("write"),
            read_credential: credential("read"),
            presign_credential: credential("presign"),
        },
        issuer_installation: aos_hub_core::storage_authority::lease::control::IssuerInstallation {
            format_version: 1,
            authority: write.authority.clone(),
            issuer_resource_id: "retained-independent-volume".into(),
            runtime_identity: "dedicated-issuer".into(),
            executor_identity: EXECUTOR.into(),
        },
        issuer_key_id: "independent-public-verifier".into(),
        issuer_public_key: "ab".repeat(32),
        write_cohort: write,
        read_cohort: read,
        private_stage_policy: DirectPrivateStagePolicyRef {
            policy_id: "fixture-provider-evidence".into(),
            policy_digest: "6".repeat(64),
            namespace: "qualified-bucket".into(),
        },
        staging_prefix: "managed/binding/.aos-direct-upload".into(),
        checksum_algorithm: DirectChecksumAlgorithm::Sha256,
        maximum_grant_lifetime: WireInteger::new(60),
        provider_contract_id: "emulated-test-closure".into(),
        provider_contract_evidence_digest: "7".repeat(64),
        // These are pure fixture inputs, never qualified deployment defaults.
        timing_profile: LeaseTimingProfile {
            profile_id: "fixture-reviewed-clock".into(),
            review_digest: "8".repeat(64),
            maximum_lifetime: integer(30),
            maximum_clock_uncertainty: integer(2),
        },
        clock_uncertainty: integer(2),
    }
}

pub(crate) fn runtime_reference() -> DirectRuntimeQualification {
    DirectRuntimeQualification {
        version: 1,
        qualification_digest: "f".repeat(64),
        maximum_object_bytes: WireInteger::new(1024 * 1024),
        maximum_verification_seconds: WireInteger::new(10),
        settlement_reserve_seconds: WireInteger::new(8),
        maximum_parallel_objects: WireInteger::new(4),
        maximum_parallel_provider_requests: WireInteger::new(8),
        cache_destination_policy: DirectCacheDestinationPolicy::RetainedOriginalBaseline,
    }
}

#[path = "../../../../../aos-hub-core/src/direct_upload/worker_qualification/fixtures.rs"]
mod measured_fixture;

fn artifact() -> DirectWorkerQualificationArtifact {
    let (mut item, _) = measured_fixture::direct_worker_qualification_fixture();
    item.execution_kind = DirectWorkerExecutionKind::EmulatedExternal;
    item.script_version = direct_worker_emulated_script_id(&item.source_digest).unwrap();
    item.evidence.bulk_queue.script_version = item.script_version.clone();
    item.evidence.metadata_queue.script_version = item.script_version.clone();
    item.evidence
        .bulk_queue
        .delivery_policy
        .maximum_concurrent_invocations = None;
    item.evidence
        .metadata_queue
        .delivery_policy
        .maximum_concurrent_invocations = None;
    // Independent installed-byte observations are explicit test inputs only.
    item.evidence.installation = Some(DirectWorkerInstallationMeasurement {
        observation_sha256: "91".repeat(32),
        report: DirectWorkerInstallationReport {
            version: 1,
            execution_kind: item.execution_kind,
            deployment_id: item.deployment_id.clone(),
            public_origin: item.public_origin.clone(),
            source_digest: item.source_digest.clone(),
            script_version: item.script_version.clone(),
            source_nar_sha256: "92".repeat(32),
            distribution_nar_sha256: "93".repeat(32),
            wasm_sha256: "94".repeat(32),
            wasm_byte_size: WireInteger::new(1024),
            shim_sha256: "95".repeat(32),
            shim_byte_size: WireInteger::new(256),
            runtime_bindings_sha256: "96".repeat(32),
            runner_sha256: Some("97".repeat(32)),
            runtime_executable_sha256: Some("98".repeat(32)),
            observed_process_executable_sha256: Some("98".repeat(32)),
        },
    });
    item.evidence.clock_policy.uncertainty_seconds = WireInteger::new(2);
    item.evidence.clock.uncertainty_seconds = WireInteger::new(2);
    item.evidence.managed_profile = None;
    item.evidence.private_stage_policy = None;
    item.evidence.sdk_probe = None;
    item.evidence.privacy = None;
    item.evidence.external_profiles =
        vec![
            DirectProtectedExternalProfile::new(profile(), item.evidence.runtime.clone()).unwrap(),
        ];
    item.evidence.issued_at = WireInteger::new(100);
    item.evidence.valid_until = WireInteger::new(200);
    resign(&mut item);
    item
}

fn resign(item: &mut DirectWorkerQualificationArtifact) {
    item.evidence_sha256 = direct_qualification_digest(&item.evidence).unwrap();
    let key = SigningKey::from_bytes(&[0x19; 32]);
    item.signature = hex::encode(key.sign(&item.signing_bytes().unwrap()).to_bytes());
}

fn encoded(item: &DirectWorkerQualificationArtifact) -> (Vec<u8>, Vec<u8>) {
    let key = SigningKey::from_bytes(&[0x19; 32]);
    let keys = BTreeMap::from([(
        item.reviewer_key_id.clone(),
        hex::encode(key.verifying_key().to_bytes()),
    )]);
    (
        serde_json::to_vec(item).unwrap(),
        serde_json::to_vec(&keys).unwrap(),
    )
}

#[test]
fn cold_expired_acceptance_retains_guard_facts_and_refuses_new_producer_permission() {
    let item = artifact();
    let (bytes, keys) = encoded(&item);
    let expiry = item.evidence.valid_until.get();
    let history = NativeDirectUploadAcceptances::load_bytes(
        &bytes,
        &keys,
        expiry,
        AcceptanceLoad::PositiveMetadataRecovery,
    )
    .unwrap();
    assert!(history
        .profiles(&item.deployment_id, &item.public_origin, expiry)
        .is_err());
    assert!(NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, expiry).is_err());
    assert!(NativeDirectUploadRuntime::new(
        &item.public_origin,
        &item.deployment_id,
        &[11; 32],
        &[12; 32],
        history.clone()
    )
    .is_err());
    NativeDirectUploadRuntime::new_for_positive_recovery(
        &item.public_origin,
        &item.deployment_id,
        &[11; 32],
        &[12; 32],
        history,
    )
    .unwrap();
    let mut invalid = item.clone();
    invalid.signature.replace_range(..2, "00");
    let (invalid, _) = encoded(&invalid);
    assert!(NativeDirectUploadAcceptances::load_bytes(
        &invalid,
        &keys,
        expiry,
        AcceptanceLoad::PositiveMetadataRecovery
    )
    .is_err());
    assert!(NativeDirectUploadAcceptances::load_bytes(
        &bytes,
        b"{}",
        expiry,
        AcceptanceLoad::PositiveMetadataRecovery
    )
    .is_err());
    let mut future = item.clone();
    future.evidence.issued_at = WireInteger::new(expiry + 10);
    resign(&mut future);
    let (future, _) = encoded(&future);
    assert!(NativeDirectUploadAcceptances::load_bytes(
        &future,
        &keys,
        expiry,
        AcceptanceLoad::PositiveMetadataRecovery
    )
    .is_err());
    assert!(NativeDirectUploadAcceptances::load_bytes(
        b"",
        &keys,
        expiry,
        AcceptanceLoad::PositiveMetadataRecovery
    )
    .is_err());
}

pub(in crate::direct_upload::authority) fn managed_fixture(
    origin: &str,
    now: u64,
    expiry: u64,
) -> (NativeDirectUploadAcceptances, DirectProtectedProfile) {
    let (mut item, _) = measured_fixture::direct_worker_qualification_fixture();
    item.public_origin = origin.into();
    item.evidence.issued_at = WireInteger::new(now.saturating_sub(1));
    item.evidence.valid_until = WireInteger::new(expiry);
    resign(&mut item);
    let (bytes, keys) = encoded(&item);
    let accepted = NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, now).unwrap();
    let profile = accepted
        .profiles("deployment-1", origin, now)
        .unwrap()
        .remove(0);
    (accepted, profile)
}

pub(in crate::direct_upload::authority) fn managed_expired_fixture(
    origin: &str,
    now: u64,
) -> NativeDirectUploadAcceptances {
    let (mut item, _) = measured_fixture::direct_worker_qualification_fixture();
    item.public_origin = origin.into();
    item.evidence.issued_at = WireInteger::new(now - 60);
    item.evidence.valid_until = WireInteger::new(now - 30);
    resign(&mut item);
    let (bytes, keys) = encoded(&item);
    NativeDirectUploadAcceptances::load_bytes(
        &bytes,
        &keys,
        now,
        AcceptanceLoad::PositiveMetadataRecovery,
    )
    .unwrap()
}

pub(in crate::direct_upload::authority) fn external_fixture(
    origin: &str,
    now: u64,
    expiry: u64,
    binding: &aos_hub_core::db::BindingRecord,
) -> (NativeDirectUploadAcceptances, DirectProtectedProfile) {
    let mut item = artifact();
    let profile = profile_from_publication(publication_for_binding(Some(binding)));
    item.public_origin = origin.into();
    item.evidence
        .installation
        .as_mut()
        .unwrap()
        .report
        .public_origin = origin.into();
    item.evidence.issued_at = WireInteger::new(now.saturating_sub(1));
    item.evidence.valid_until = WireInteger::new(expiry);
    item.evidence.external_profiles =
        vec![DirectProtectedExternalProfile::new(profile, item.evidence.runtime.clone()).unwrap()];
    resign(&mut item);
    let (bytes, keys) = encoded(&item);
    let accepted = NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, now).unwrap();
    let profile = accepted
        .profiles("deployment-1", origin, now)
        .unwrap()
        .remove(0);
    (accepted, profile)
}

#[test]
fn reviewed_emulator_requires_exact_current_audience_and_window() {
    let item = artifact();
    let (bytes, keys) = encoded(&item);
    let accepted = NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, 100).unwrap();
    assert_eq!(
        accepted
            .profiles("deployment-1", "https://hub.example.test", 100)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        accepted
            .valid_until("deployment-1", "https://hub.example.test", 150)
            .unwrap(),
        200
    );
    assert!(accepted
        .profiles("other", "https://hub.example.test", 150)
        .is_err());
    assert!(accepted
        .profiles("deployment-1", "https://other.example", 150)
        .is_err());
    assert!(accepted
        .profiles("deployment-1", "https://hub.example.test", 99)
        .is_err());
    assert!(accepted
        .profiles("deployment-1", "https://hub.example.test", 200)
        .is_err());
    assert!(NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, 200).is_err());
}

#[test]
fn altered_signature_profile_and_unknown_reviewer_are_rejected() {
    let original = artifact();
    let (_, keys) = encoded(&original);
    let mut changed = original.clone();
    changed.signature = "00".repeat(64);
    assert!(NativeDirectUploadAcceptances::from_bytes(
        &serde_json::to_vec(&changed).unwrap(),
        &keys,
        100
    )
    .is_err());
    let mut changed = original.clone();
    changed.evidence.runtime.maximum_object_bytes = WireInteger::new(100);
    assert!(NativeDirectUploadAcceptances::from_bytes(
        &serde_json::to_vec(&changed).unwrap(),
        &keys,
        100
    )
    .is_err());
    let unknown_keys =
        serde_json::to_vec(&BTreeMap::from([("another-reviewer", "01".repeat(32))])).unwrap();
    assert!(NativeDirectUploadAcceptances::from_bytes(
        &serde_json::to_vec(&original).unwrap(),
        &unknown_keys,
        100
    )
    .is_err());
}

#[test]
fn emulation_cannot_qualify_production_or_managed_profiles() {
    let mut changed = artifact();
    changed.execution_kind = DirectWorkerExecutionKind::Hosted;
    resign(&mut changed);
    let (bytes, keys) = encoded(&changed);
    assert!(NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, 100).is_err());
    let mut changed = artifact();
    changed.evidence.external_profiles[0]
        .profile
        .write_cohort
        .alias
        .spec
        .host = StorageAuthorityHost::Dns("s3.provider.example".into());
    resign(&mut changed);
    let (bytes, keys) = encoded(&changed);
    assert!(NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, 100).is_err());
    let (mut changed, _) = measured_fixture::direct_worker_qualification_fixture();
    changed.execution_kind = DirectWorkerExecutionKind::EmulatedExternal;
    resign(&mut changed);
    let (bytes, keys) = encoded(&changed);
    assert!(NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, 100).is_err());
}

#[test]
fn independently_signed_inconsistent_measurements_and_origin_are_rejected() {
    let mut changed = artifact();
    changed.evidence.clock.expired_mutation_dispatches = WireInteger::new(1);
    resign(&mut changed);
    let (bytes, keys) = encoded(&changed);
    assert!(NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, 100).is_err());
    let mut changed = artifact();
    changed.public_origin = "https://hub.example.test/path".into();
    resign(&mut changed);
    let (bytes, keys) = encoded(&changed);
    assert!(NativeDirectUploadAcceptances::from_bytes(&bytes, &keys, 100).is_err());
}
