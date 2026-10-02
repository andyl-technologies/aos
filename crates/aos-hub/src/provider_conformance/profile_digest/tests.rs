//! Structural-only fixture checks of shared commitment and closed input bounds.
//!
//! The public test profile below mirrors the Core capability contract fixture;
//! it supplies no authenticated observation, credential material or acceptance.

use super::*;
use aos_hub_core::direct_upload::*;
use aos_hub_core::storage_authority::{
    control::StorageAuthorityPublication, lease::*,
    ApproveStorageAuthorityAlias, AssociateStorageAuthorityBinding,
    AttestStorageAuthorityExclusivity, CreatePhysicalStorageAuthority,
    PhysicalStorageAuthorityId, SetStorageAuthorityAdmission,
    StorageAuthorityAdmissionState, StorageAuthorityAliasSpec,
    StorageAuthorityCredentialMember, StorageAuthorityHost,
};

const EXECUTOR: &str = "qualified-executor";

fn integer(value: i64) -> LeaseInteger {
    LeaseInteger::new(value).unwrap()
}

fn publication() -> StorageAuthorityPublication {
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
            host: StorageAuthorityHost::Dns("objects.example.invalid".into()),
            port: 443,
            bucket: "qualified-bucket".into(),
        },
        equivalence_evidence_digest: "3".repeat(64),
    };
    let association = AssociateStorageAuthorityBinding {
        association_id: "association-one".into(),
        authority_id: authority_id.clone(),
        alias_id: alias.alias_id.clone(),
        binding_id: 9_007_199_254_740_993,
        binding_stable_id: "binding-one".into(),
        binding_resource_version: 9_007_199_254_740_995,
        binding_write_revision: 9_007_199_254_740_997,
        binding_prefix: "managed/binding".into(),
    };
    let credentials = ["delete", "list", "presign", "read", "write"]
        .into_iter()
        .map(|purpose| StorageAuthorityCredentialMember {
            association_id: association.association_id.clone(),
            purpose: purpose.into(),
            generation: 9_007_199_254_741_001,
            secret_version_ref: format!("secret://fixture/{purpose}/immutable-v1"),
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
        valid_until: 1000,
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
    let digest = journal::digest(&serde_json::to_vec(&admission).unwrap());
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

fn profile() -> DirectExternalStorageCapabilities {
    let publication = publication();
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
        generation: WireInteger::new(9_007_199_254_741_001),
        secret_version_ref: format!("secret://fixture/{purpose}/immutable-v1"),
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
        provider_contract_id: "fixture-positive-closure".into(),
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

fn runtime_reference() -> DirectRuntimeQualification {
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


#[test]
fn structural_projection_matches_shared_digest_and_refuses_unknown_bounds() {
    let selected = DirectProtectedExternalProfile::new(profile(), runtime_reference()).unwrap();
    let bytes = serde_json::to_vec(&selected).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.json");
    std::fs::write(&path, &bytes).unwrap();

    let result: serde_json::Value = serde_json::from_str(&project(&path).unwrap()).unwrap();

    assert_eq!(result["version"], 1);
    assert_eq!(result["profile_sha256"], journal::digest(&bytes));
    assert_eq!(result["protected_profile_digest"], selected.digest().unwrap());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);

    let mut unknown = serde_json::to_value(&selected).unwrap();
    unknown["permission"] = true.into();
    std::fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert!(project(&path).is_err());

    std::fs::write(&path, [bytes.as_slice(), b"\n"].concat()).unwrap();
    assert!(project(&path).is_err());

    std::fs::write(&path, vec![b' '; MAX_PROFILE_BYTES as usize + 1]).unwrap();
    assert!(project(&path).is_err());
}
