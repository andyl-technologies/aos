//! Pure fresh-profile authentication, exact selection and capability budget tests.

use super::*;
use crate::storage_authority::{
    canonical_digest, control::StorageAuthorityPublication, lease::*, ApproveStorageAuthorityAlias,
    AssociateStorageAuthorityBinding, AttestStorageAuthorityExclusivity,
    CreatePhysicalStorageAuthority, PhysicalStorageAuthorityId, SetStorageAuthorityAdmission,
    StorageAuthorityAdmissionState, StorageAuthorityAliasSpec, StorageAuthorityCredentialMember,
    StorageAuthorityHost,
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
    let digest = canonical_digest(&admission).unwrap();
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
        issuer_installation: crate::storage_authority::lease::control::IssuerInstallation {
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

fn request(profile: &DirectExternalStorageCapabilities) -> DirectStorageCapabilitiesRequest {
    DirectStorageCapabilitiesRequest {
        version: 2,
        deployment_id: "deployment".into(),
        executor_public_origin: "https://executor.example".into(),
        request_nonce: "9".repeat(64),
        issued_at: WireInteger::new(100),
        expires_at: WireInteger::new(130),
        managed: false,
        external_selectors: vec![profile.selector.clone()],
    }
}

fn reply(profile: DirectExternalStorageCapabilities) -> DirectStorageCapabilitiesReply {
    DirectStorageCapabilitiesReply {
        request: request(&profile),
        capabilities: DirectStorageCapabilities {
            version: 2,
            capability: DIRECT_UPLOAD_CAPABILITY.into(),
            profile: None,
            private_stage_policy: None,
            runtime_qualification: None,
            external_profiles: vec![DirectProtectedExternalProfile::new(
                profile,
                runtime_reference(),
            )
            .unwrap()],
        },
    }
}

#[test]
fn external_profiles_bind_actual_selected_purpose_and_immutable_issuer_domain() {
    let original = profile();
    original.validate().unwrap();
    let commitment = original.fingerprint().unwrap();
    for index in 0..6 {
        let mut changed = original.clone();
        match index {
            0 => changed.selector.write_credential.generation = WireInteger::new(1),
            1 => changed.read_cohort.credential.purpose = LeasePurpose::Write,
            2 => changed.issuer_installation.executor_identity = "another-executor".into(),
            3 => changed.selector.association.binding_resource_version = integer(1),
            4 => changed.staging_prefix = "outside/.aos-direct-upload".into(),
            _ => changed.issuer_public_key = "invalid-public-key".into(),
        }
        assert!(changed.validate().is_err());
    }
    let mut changed = original.clone();
    changed.timing_profile.review_digest = "a".repeat(64);
    assert_ne!(changed.fingerprint().unwrap(), commitment);
    changed = original;
    changed.provider_contract_evidence_digest = "b".repeat(64);
    assert_ne!(changed.fingerprint().unwrap(), commitment);
}

#[test]
fn fresh_capability_reply_checks_domains_entire_selector_and_exclusive_clock_bound() {
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let reply = reply(profile());
    let signed_request = sign_direct_storage_capabilities_request(&key, &reply.request).unwrap();
    assert_eq!(
        verify_direct_storage_capabilities_request(
            &key,
            &signed_request.signature,
            &signed_request.body,
            "deployment",
            "https://executor.example",
            129
        )
        .unwrap(),
        reply.request
    );
    assert!(verify_direct_storage_capabilities_request(
        &key,
        &signed_request.signature,
        &signed_request.body,
        "deployment",
        "https://executor.example",
        130
    )
    .is_err());
    let signed = sign_direct_storage_capabilities_reply(&key, &reply).unwrap();
    assert_eq!(
        verify_direct_storage_capabilities_reply(
            &key,
            &signed.signature,
            &signed.body,
            &reply.request,
            129
        )
        .unwrap(),
        reply
    );
    assert!(verify_direct_storage_capabilities_reply(
        &key,
        &signed.signature,
        &signed.body,
        &reply.request,
        130
    )
    .is_err());
    let mut changed = reply.request.clone();
    changed.request_nonce = "c".repeat(64);
    assert!(verify_direct_storage_capabilities_reply(
        &key,
        &signed.signature,
        &signed.body,
        &changed,
        100
    )
    .is_err());
    changed = reply.request.clone();
    changed.external_selectors[0]
        .presign_credential
        .secret_version_ref = "changed-protected-locator".into();
    assert!(verify_direct_storage_capabilities_reply(
        &key,
        &signed.signature,
        &signed.body,
        &changed,
        100
    )
    .is_err());
    assert!(verify_direct_storage_capabilities_reply(
        &key,
        &signed_request.signature,
        &signed_request.body,
        &reply.request,
        100
    )
    .is_err());
    let wrong_domain = key.sign_body(&signed.body).unwrap();
    assert!(verify_direct_storage_capabilities_reply(
        &key,
        &wrong_domain,
        &signed.body,
        &reply.request,
        100
    )
    .is_err());
}

#[test]
fn capability_wire_refuses_duplicates_unknown_fields_budgets_and_unsolicited_profiles() {
    let key = StorageWorkKey::new([7; 32]).unwrap();
    let reply = reply(profile());
    let body = encode_capability(&reply.request).unwrap();
    for text in [
        String::from_utf8(body.clone())
            .unwrap()
            .replacen("{", "{\"unknown\":true,", 1),
        String::from_utf8(body)
            .unwrap()
            .replacen("{", "{\"version\":2,", 1),
    ] {
        let signed = key
            .sign_body(&domain_bytes(REQUEST_DOMAIN, text.as_bytes()))
            .unwrap();
        assert!(verify_direct_storage_capabilities_request(
            &key,
            &signed,
            text.as_bytes(),
            "deployment",
            "https://executor.example",
            100
        )
        .is_err());
    }
    let bytes = vec![b' '; MAX_DIRECT_CAPABILITY_BYTES + 1];
    assert!(verify_direct_storage_capabilities_request(
        &key,
        "invalid",
        &bytes,
        "deployment",
        "https://executor.example",
        100
    )
    .is_err());
    assert!(encode_capability(&"x".repeat(MAX_DIRECT_CAPABILITY_BYTES)).is_err());
    let mut changed = reply.clone();
    changed.capabilities.external_profiles.clear();
    assert!(sign_direct_storage_capabilities_reply(&key, &changed).is_err());
    changed = reply.clone();
    changed.request.managed = true;
    assert!(sign_direct_storage_capabilities_reply(&key, &changed).is_err());
    changed = reply;
    changed
        .request
        .external_selectors
        .push(changed.request.external_selectors[0].clone());
    assert!(sign_direct_storage_capabilities_request(&key, &changed.request).is_err());
}
