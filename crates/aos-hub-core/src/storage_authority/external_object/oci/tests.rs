//! Focused immutable OCI original, ordered manifest and control refusal tests.

use super::control::{ExternalOciRequest, OciControl};
use super::*;
use crate::storage_authority::{
    control::StorageAuthorityObjectScope, GuardIncarnation, PhysicalStorageAuthorityId,
};
use crate::storage_work::{StorageBindingSnapshot, StorageWorkKey};

pub(super) fn original() -> ExternalOciOriginal {
    ExternalOciOriginal {
        version: 1,
        deployment_id: "oci-test-deployment".into(),
        upload: OciUploadOriginal {
            upload_id: "a".repeat(32),
            resource_version: LeaseInteger::new(2).unwrap(),
            registry_id: LeaseInteger::new(1).unwrap(),
            repository_id: LeaseInteger::new(2).unwrap(),
            writer_id: "actual-writer-slot".into(),
            token_id: "actual-upload-owner".into(),
            quota_reservation_id: "retained-quota".into(),
            publication_id: None,
            created_at: LeaseInteger::new(100).unwrap(),
            expires_at: LeaseInteger::new(200).unwrap(),
            maximum_size: 16 * 1024 * 1024 * 1024,
        },
        actor: OciActorOriginal::from_authenticated(
            crate::direct_upload::DirectActorSlot {
                kind: crate::direct_upload::DirectActorKind::User,
                numeric_id: crate::direct_upload::WireInteger::new(1),
                incarnation: "00000000-0000-4000-8000-000000000001".into(),
            },
            "actual-current-iam-token".into(),
            300,
        )
        .unwrap(),
        writer: OciWriterOriginal {
            placement_id: LeaseInteger::new(3).unwrap(),
            placement_resource_version: LeaseInteger::new(4).unwrap(),
            write_spec_version: LeaseInteger::new(5).unwrap(),
            placement_prefix: "registry".into(),
            binding_prefix: "private".into(),
            binding_id: LeaseInteger::new(6).unwrap(),
            binding_stable_id: "existing-binding-lifetime".into(),
            binding_resource_version: LeaseInteger::new(7).unwrap(),
            binding_write_revision: LeaseInteger::new(8).unwrap(),
            authority_id: LeaseInteger::new(9).unwrap(),
            authority_incarnation: "existing-authority-lifetime".into(),
            authority_resource_version: LeaseInteger::new(10).unwrap(),
            authority_generation: LeaseInteger::new(11).unwrap(),
        },
        binding_spec_revision: "b".repeat(64),
        profile_digest: "c".repeat(64),
        scope: StorageAuthorityObjectScope {
            guard_namespace_id: "permanent-oci-guard".into(),
            physical_authority_id: PhysicalStorageAuthorityId::parse(
                "00000000-0000-4000-8000-000000000001",
            )
            .unwrap(),
            full_key: format!(
                "private/registry/oci/uploads/{}/chunks/0-{}",
                "a".repeat(32),
                "d".repeat(32)
            ),
        },
        object: OciObjectOriginal::Chunk {
            ordinal: 0,
            offset: 0,
            maximum_bytes: MAX_EXTERNAL_OCI_CHUNK_BYTES,
            prior_sha256: OciSha256State::initial(),
            expected: None,
        },
    }
}

fn source(ordinal: usize) -> OciSourceOriginal {
    OciSourceOriginal {
        key: format!(
            "private/registry/oci/uploads/{}/chunks/{ordinal}-{}",
            "a".repeat(32),
            "d".repeat(32)
        ),
        bytes: OciBytes {
            sha256: format!("{ordinal:064x}"),
            size: 1,
        },
        receipt_digest: "e".repeat(64),
        etag: format!("\"source-{ordinal}\""),
        incarnation: OciProviderIncarnation::Versioned {
            provider_version: format!("actual-version-{ordinal}"),
            guard_stamp: StorageGuardStamp {
                physical_authority_id: PhysicalStorageAuthorityId::parse(
                    "00000000-0000-4000-8000-000000000001",
                )
                .unwrap(),
                incarnation: GuardIncarnation::parse("1").unwrap(),
            },
        },
    }
}

#[test]
fn original_freezes_complete_writer_prefix_and_contiguous_chunk_state() {
    let expected = original();
    expected.validate().unwrap();
    let fingerprint = expected.fingerprint().unwrap();

    let mut changed = expected.clone();
    changed.writer.binding_stable_id = "recreated-binding".into();
    assert_ne!(changed.fingerprint().unwrap(), fingerprint);

    for key in [
        format!(
            "another/private/registry/oci/uploads/{}/chunks/0-x",
            "a".repeat(32)
        ),
        format!(
            "private/registry/unrelated/oci/uploads/{}/chunks/0-x",
            "a".repeat(32)
        ),
        format!("private/registry/oci/uploads/{}/chunks/1-x", "a".repeat(32)),
    ] {
        changed = expected.clone();
        changed.scope.full_key = key;
        assert!(changed.validate().is_err());
    }

    changed = expected;
    if let OciObjectOriginal::Chunk { offset, .. } = &mut changed.object {
        *offset = 1;
    }
    assert!(changed.validate().is_err());
}

#[test]
fn full_ordered_source_commitment_supports_4096_without_an_unbounded_original() {
    let sources: Vec<_> = (0..MAX_EXTERNAL_OCI_SOURCE_CHUNKS).map(source).collect();
    let manifest = OciSourceManifest::from_sources(&sources).unwrap();
    assert_eq!(manifest.count, 4096);
    assert_eq!(manifest.bytes, 4096);

    let mut expected = original();
    expected.scope.full_key = format!("private/registry/oci/blobs/sha256/{}", "f".repeat(64));
    expected.object = OciObjectOriginal::Compose {
        expected: OciBytes {
            sha256: "f".repeat(64),
            size: 4096,
        },
        sources: manifest.clone(),
    };
    expected.validate().unwrap();
    assert!(serde_json::to_vec(&expected).unwrap().len() < 4096);

    let mut reordered = sources.clone();
    reordered.swap(0, 1);
    assert_ne!(
        OciSourceManifest::from_sources(&reordered).unwrap(),
        manifest
    );

    let mut substituted = sources;
    substituted[0].incarnation = OciProviderIncarnation::Guarded {
        guard_stamp: StorageGuardStamp {
            physical_authority_id: PhysicalStorageAuthorityId::parse(
                "00000000-0000-4000-8000-000000000001",
            )
            .unwrap(),
            incarnation: GuardIncarnation::parse("2").unwrap(),
        },
    };
    assert_ne!(
        OciSourceManifest::from_sources(&substituted).unwrap(),
        manifest
    );
    substituted.push(source(4096));
    assert!(OciSourceManifest::from_sources(&substituted).is_err());
}

#[test]
fn source_pages_are_ordered_bounded_and_tied_to_the_whole_original() {
    let sources = [source(0), source(1)];
    let mut expected = original();
    expected.scope.full_key = format!("private/registry/oci/blobs/sha256/{}", "f".repeat(64));
    expected.object = OciObjectOriginal::Compose {
        expected: OciBytes {
            sha256: "f".repeat(64),
            size: 2,
        },
        sources: OciSourceManifest::from_sources(&sources).unwrap(),
    };
    let good = ExternalOciRequest::new(
        expected,
        "b".repeat(64),
        original().actor,
        110,
        130,
        "e".repeat(64),
        OciControl::InstallSources {
            first: 0,
            sources: sources.to_vec(),
        },
    )
    .unwrap();

    let mut invalid = good.clone();
    if let OciControl::InstallSources { first, .. } = &mut invalid.operation {
        *first = 1;
    }
    assert!(invalid.validate("oci-test-deployment", 110).is_err());

    invalid = good;
    if let OciControl::InstallSources { sources, .. } = &mut invalid.operation {
        sources[0].key = format!("private/other/oci/uploads/{}/chunks/0-x", "a".repeat(32));
    }
    assert!(invalid.validate("oci-test-deployment", 110).is_err());
}

#[test]
fn short_application_control_cannot_relabel_original_actor_or_upload() {
    let key = StorageWorkKey::new("fixture-application-key-32-bytes-abcdef").unwrap();
    let request = ExternalOciRequest::new(
        original(),
        "b".repeat(64),
        original().actor,
        110,
        130,
        "e".repeat(64),
        OciControl::Stage,
    )
    .unwrap();
    let (body, signature) = request.sign(&key, "oci-test-deployment", 110).unwrap();
    let observed =
        ExternalOciRequest::authenticate(&key, &signature, &body, "oci-test-deployment", 129)
            .unwrap();
    assert_eq!(observed, request);
    assert!(
        ExternalOciRequest::authenticate(&key, &signature, &body, "oci-test-deployment", 130)
            .is_err()
    );
    assert!(
        ExternalOciRequest::authenticate(&key, &signature, &body, "foreign-deployment", 110)
            .is_err()
    );
    assert!(request.validate("oci-test-deployment", 109).is_err());

    let mut relabelled = request.clone();
    relabelled.original.writer.binding_stable_id = "recreated-binding".into();
    assert!(ExternalOciRequest::authenticate(
        &key,
        &signature,
        &serde_json::to_vec(&relabelled).unwrap(),
        "oci-test-deployment",
        110
    )
    .is_err());

    let mut renewed = request;
    renewed.actor.token_id = "another-token".into();
    assert!(renewed.validate("oci-test-deployment", 110).is_err());
    renewed.actor = original().actor;
    renewed.expires_at = 141;
    assert!(renewed.validate("oci-test-deployment", 110).is_err());
}

#[test]
fn provider_version_and_guard_incarnation_remain_distinct_exact_identities() {
    let authority = "00000000-0000-4000-8000-000000000001";
    let mut identity = source(0).incarnation;
    identity.validate(authority).unwrap();
    if let OciProviderIncarnation::Versioned {
        provider_version, ..
    } = &mut identity
    {
        *provider_version = "null".into();
    }
    assert!(identity.validate(authority).is_err());
    assert!(source(0)
        .incarnation
        .validate("00000000-0000-4000-8000-000000000002")
        .is_err());
}

// Structural test material exercises the same publication/cohort constructors
// as the runtime. It is not independently accepted provider evidence.
fn snapshot_profile(
    snapshot: &StorageBindingSnapshot,
    original: &ExternalOciOriginal,
) -> qualification::ExternalOciProfile {
    use crate::storage_authority::{
        canonical_digest,
        control::StorageAuthorityPublication,
        lease::{control::IssuerInstallation, LeaseCohort, LeaseEffect, LeasePurpose},
        ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding,
        AttestStorageAuthorityExclusivity, CreatePhysicalStorageAuthority,
        SetStorageAuthorityAdmission, StorageAuthorityAdmissionState, StorageAuthorityAliasSpec,
        StorageAuthorityCredentialMember, StorageAuthorityHost,
    };

    let executor = "oci-test-executor";
    let authority = CreatePhysicalStorageAuthority {
        authority_id: original.scope.physical_authority_id.clone(),
        guard_namespace_id: original.scope.guard_namespace_id.clone(),
        physical_resource_evidence_digest: "1".repeat(64),
        qualification_digest: "2".repeat(64),
        qualified_managed_prefix: snapshot.object_prefix.clone(),
    };
    let alias = ApproveStorageAuthorityAlias {
        alias_id: "oci-test-alias".into(),
        authority_id: authority.authority_id.clone(),
        spec: StorageAuthorityAliasSpec {
            host: StorageAuthorityHost::Dns("oci-test.example".into()),
            port: 443,
            bucket: snapshot.object_bucket.clone(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    let association = AssociateStorageAuthorityBinding {
        association_id: "oci-test-association".into(),
        authority_id: authority.authority_id.clone(),
        alias_id: alias.alias_id.clone(),
        binding_id: snapshot.binding_id,
        binding_stable_id: snapshot.binding_stable_id.clone(),
        binding_resource_version: snapshot.binding_resource_version,
        binding_write_revision: original.writer.binding_write_revision.get(),
        binding_prefix: snapshot.object_prefix.clone(),
    };
    let attestation = AttestStorageAuthorityExclusivity {
        attestation_id: "oci-test-attestation".into(),
        authority_id: authority.authority_id.clone(),
        managed_prefix: snapshot.object_prefix.clone(),
        qualification_digest: authority.qualification_digest.clone(),
        provider_policy_evidence_digest: "4".repeat(64),
        executor_identity: executor.into(),
        credentials: snapshot
            .credentials
            .iter()
            .map(|reference| StorageAuthorityCredentialMember {
                association_id: association.association_id.clone(),
                purpose: reference.purpose.clone(),
                generation: reference.generation,
                secret_version_ref: reference.secret_version_ref.clone(),
                credential_fingerprint: reference.fingerprint.clone(),
            })
            .collect(),
        valid_until: 1000,
    };
    let admission = SetStorageAuthorityAdmission {
        authority_id: authority.authority_id.clone(),
        expected_generation: 0,
        expected_digest: None,
        guard_namespace_id: authority.guard_namespace_id.clone(),
        state: StorageAuthorityAdmissionState::Admitted,
        attestation_id: Some(attestation.attestation_id.clone()),
        association_ids: vec![association.association_id.clone()],
    };
    let publication = StorageAuthorityPublication {
        authority: authority.clone(),
        aliases: vec![alias],
        associations: vec![association.clone()],
        attestation: Some(attestation),
        digest: canonical_digest(&admission).unwrap(),
        admission,
        generation: 1,
    };
    let admitted_prefix =
        crate::keymap::r2_key(&snapshot.object_prefix, &original.writer.placement_prefix);
    let cohort = |purpose, effects| {
        LeaseCohort::from_publication(
            &publication,
            executor,
            &association.association_id,
            purpose,
            &admitted_prefix,
            effects,
        )
        .unwrap()
    };
    let profile = qualification::ExternalOciProfile {
        issuer_installation: IssuerInstallation {
            format_version: 1,
            authority,
            issuer_resource_id: "oci-test-issuer-resource".into(),
            runtime_identity: "oci-test-issuer-runtime".into(),
            executor_identity: executor.into(),
        },
        read_cohort: cohort(
            LeasePurpose::Read,
            vec![LeaseEffect::Head, LeaseEffect::Read],
        ),
        write_cohort: cohort(
            LeasePurpose::Write,
            vec![
                LeaseEffect::Put,
                LeaseEffect::MultipartCreate,
                LeaseEffect::MultipartPart,
                LeaseEffect::MultipartComplete,
                LeaseEffect::MultipartAbort,
            ],
        ),
        binding_spec_revision: snapshot.binding_spec_revision().unwrap(),
        private_policy: crate::direct_upload::DirectPrivateStagePolicyRef {
            policy_id: "oci-test-private-policy".into(),
            policy_digest: "5".repeat(64),
            namespace: original.scope.guard_namespace_id.clone(),
        },
        maximum_blob_bytes: original.upload.maximum_size,
        maximum_chunk_bytes: MAX_EXTERNAL_OCI_CHUNK_BYTES,
        part_bytes: EXTERNAL_OCI_PART_BYTES,
        versionless_conditional_reads: false,
    };
    profile.validate().unwrap();
    profile
}

#[test]
fn current_protected_snapshot_cannot_change_binding_lifetime_or_prefix() {
    let mut expected = original();
    let mut snapshot = StorageBindingSnapshot {
        version: 1,
        deployment_id: expected.deployment_id.clone(),
        binding_id: 6,
        binding_resource_version: 7,
        binding_stable_id: expected.writer.binding_stable_id.clone(),
        binding_kind: "s3".into(),
        object_bucket: "oci-test-bucket".into(),
        object_prefix: "private".into(),
        endpoint_scheme: "https".into(),
        endpoint_host_kind: "dns".into(),
        endpoint_host_bytes: b"oci-test.example".to_vec(),
        endpoint_port: Some(443),
        signing_region: "test-region".into(),
        access_mode: "private".into(),
        credentials: vec![
            crate::storage_work::StorageCredentialReference {
                purpose: "read".into(),
                generation: 1,
                secret_version_ref: "secret://oci-test/read/v1".into(),
                fingerprint: "e".repeat(64),
            },
            crate::storage_work::StorageCredentialReference {
                purpose: "write".into(),
                generation: 1,
                secret_version_ref: "secret://oci-test/write/v1".into(),
                fingerprint: "f".repeat(64),
            },
        ],
        issued_at: 100,
        expires_at: 200,
    };
    snapshot.validate("oci-test-deployment", 110).unwrap();
    expected.binding_spec_revision = snapshot.binding_spec_revision().unwrap();
    let profile = snapshot_profile(&snapshot, &expected);
    expected.profile_digest = profile.digest().unwrap();
    profile.validate_snapshot(&snapshot, 110).unwrap();
    let request = ExternalOciRequest::new(
        expected,
        snapshot.revision().unwrap(),
        original().actor,
        110,
        130,
        "e".repeat(64),
        OciControl::Stage,
    )
    .unwrap();
    request.validate_snapshot(&snapshot, 110).unwrap();
    let original_digest = request.original.fingerprint().unwrap();
    snapshot.issued_at = 105;
    snapshot.expires_at = 205;
    assert!(request.validate_snapshot(&snapshot, 110).is_err());
    let refreshed = ExternalOciRequest::new(
        request.original.clone(), snapshot.revision().unwrap(),
        original().actor, 110, 130, "f".repeat(64), OciControl::Stage,
    ).unwrap();
    refreshed.validate_snapshot(&snapshot, 110).unwrap();
    assert_eq!(refreshed.original.fingerprint().unwrap(), original_digest);
    profile.validate_snapshot(&snapshot, 110).unwrap();

    // A phase pins the full current snapshot, while the retained profile pins
    // exact reviewed credentials. Refreshing the phase cannot refresh that profile.
    snapshot.credentials[0].generation += 1;
    assert!(refreshed.validate_snapshot(&snapshot, 110).is_err());
    let changed = ExternalOciRequest::new(
        request.original.clone(),
        snapshot.revision().unwrap(),
        original().actor,
        110,
        130,
        "f".repeat(64),
        OciControl::Stage,
    )
    .unwrap();
    changed.validate_snapshot(&snapshot, 110).unwrap();
    assert_eq!(changed.original.fingerprint().unwrap(), original_digest);
    assert_eq!(
        snapshot.binding_spec_revision().unwrap(),
        changed.original.binding_spec_revision
    );
    assert!(profile.validate_snapshot(&snapshot, 110).is_err());

    // Match each new phase revision so physical-identity refusals cannot be
    // accidentally supplied by the earlier time or credential revision change.
    let current = snapshot.clone();
    for change in ["stable_id", "resource_version", "prefix"] {
        let mut altered = current.clone();
        match change {
            "stable_id" => altered.binding_stable_id = "recreated-binding".into(),
            "resource_version" => altered.binding_resource_version += 1,
            "prefix" => altered.object_prefix = "another".into(),
            _ => unreachable!(),
        }
        altered.validate(&request.original.deployment_id, 110).unwrap();
        let phase = ExternalOciRequest::new(
            request.original.clone(),
            altered.revision().unwrap(),
            original().actor,
            110,
            130,
            "f".repeat(64),
            OciControl::Stage,
        )
        .unwrap();
        assert!(phase.validate_snapshot(&altered, 110).is_err(), "{change}");
    }
}

#[test]
fn current_phase_grant_refresh_preserves_original_and_unknown_effect_identity() {
    let mut original = original();
    original.actor.expires_at = LeaseInteger::new(140).unwrap();
    let fingerprint = original.fingerprint().unwrap();
    let mut current_actor = original.actor.clone();
    current_actor.expires_at = LeaseInteger::new(190).unwrap();
    let request = ExternalOciRequest::new(
        original, "b".repeat(64), current_actor, 150, 170,
        "f".repeat(64), OciControl::Stage,
    ).unwrap();
    assert_eq!(request.original.fingerprint().unwrap(), fingerprint);
    assert_eq!(request.original.actor.expires_at.get(), 140);
    request.validate("oci-test-deployment", 160).unwrap();

    let mut changed = request.clone();
    changed.actor.account.incarnation = "00000000-0000-4000-8000-000000000002".into();
    assert!(changed.validate("oci-test-deployment", 160).is_err());
    changed = request.clone();
    changed.actor.token_id = "new-token-record".into();
    assert!(changed.validate("oci-test-deployment", 160).is_err());
    changed = request;
    changed.issued_at = 190;
    changed.expires_at = 205;
    changed.actor.expires_at = LeaseInteger::new(210).unwrap();
    assert!(changed.validate("oci-test-deployment", 190).is_err());
}
