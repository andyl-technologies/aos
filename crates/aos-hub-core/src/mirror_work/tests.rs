//! Structural External mirror original, physical identity and cutoff regressions.
//!
//! These pure fixtures prove validation behavior only, not provider settlement
//! or independently reviewed mirror execution.

use super::*;
use crate::{
    storage_authority::{
        GuardIncarnation, StorageGuardStamp, control::StorageAuthorityObjectScope,
    },
    storage_work::{StorageCredentialSelector, StorageWorkOperation},
};

pub(crate) fn external_original() -> MirrorOriginal {
    let (profile, list_cohort) = crate::direct_upload::mirror_test_prerequisite();
    let association = &profile.profile.selector.association;
    let mut original = MirrorOriginal {
        version: 1,
        job_id: String::new(),
        copy_operation_id: Some("ab".repeat(16)),
        registry_id: 1,
        registry_resource_version: 2,
        mirror_resource_version: 3,
        upstream_base: "https://upstream.example.org/git/".into(),
        path: "objects/info/packs".into(),
        placement_id: 4,
        placement_resource_version: 5,
        write_spec_version: 6,
        binding_id: association.binding_id.get(),
        binding_resource_version: association.binding_resource_version.get(),
        placement_prefix: "registry".into(),
        protected_profile_digest: profile.digest().unwrap(),
        verification: MirrorVerification::Sha256 {
            sha256: "cd".repeat(32),
            size: 8,
        },
        external_destination: Some(MirrorExternalDestination {
            binding_kind: "s3".into(),
            binding_spec_revision: "ee".repeat(32),
            protected_profile: profile,
            list_cohort,
            issued_at: 100,
            expires_at: 200,
            acceptance_digest: "ff".repeat(32),
        }),
    };
    original.job_id = original.identity().unwrap();
    original.validate().unwrap();
    original
}

fn plan(original: &MirrorOriginal) -> StorageWorkPlan {
    let selector = &original
        .external_destination
        .as_ref()
        .unwrap()
        .protected_profile
        .profile
        .selector;
    StorageWorkPlan {
        version: 1,
        plan_id: "11".repeat(16),
        deployment_id: "deployment".into(),
        issued_at: 150,
        expires_at: 180,
        placement_id: original.placement_id,
        placement_resource_version: original.placement_resource_version,
        binding_id: original.binding_id,
        binding_resource_version: original.binding_resource_version,
        binding_kind: "s3".into(),
        binding_snapshot_revision: Some("22".repeat(32)),
        credential_references: vec![
            StorageCredentialSelector {
                purpose: "read".into(),
                generation: i64::try_from(selector.read_credential.generation.get()).unwrap(),
            },
            StorageCredentialSelector {
                purpose: "write".into(),
                generation: i64::try_from(selector.write_credential.generation.get()).unwrap(),
            },
        ],
        placement_prefix: original.placement_prefix.clone(),
        operation: StorageWorkOperation::MirrorTransfer {
            original: original.clone(),
            step: MirrorStep::Begin,
        },
    }
}

#[test]
fn external_mirror_controls_pin_current_material_and_original_cutoff() {
    let original = external_original();
    let admitted = plan(&original);
    original.validate_plan(&admitted).unwrap();
    admitted.validate("deployment", 150).unwrap();

    for mutation in 0..5 {
        let mut changed = admitted.clone();
        match mutation {
            0 => changed.binding_snapshot_revision = None,
            1 => changed.credential_references[1].generation += 1,
            2 => changed.expires_at = 200,
            3 => changed.binding_resource_version += 1,
            _ => changed.binding_kind = "deployment_r2".into(),
        }
        assert!(original.validate_plan(&changed).is_err());
    }
}

#[test]
fn external_mirror_original_commits_each_independent_publication_pin() {
    let original = external_original();
    assert!(original
        .destination_key()
        .starts_with("managed/binding/registry/"));
    assert!(original
        .stage_key()
        .starts_with("managed/binding/.aos-direct-upload/mirror/"));

    for mutation in 0..4 {
        let mut changed = original.clone();
        let destination = changed.external_destination.as_mut().unwrap();
        match mutation {
            0 => destination.list_cohort.association.binding_stable_id = "another-binding".into(),
            1 => destination.list_cohort.publication_digest = "33".repeat(32),
            2 => {
                destination
                    .protected_profile
                    .profile
                    .selector
                    .read_credential
                    .generation = crate::direct_upload::WireInteger::new(1)
            }
            _ => destination.binding_spec_revision = "not-a-revision".into(),
        }
        changed.job_id = changed.identity().unwrap();
        assert!(changed.validate().is_err());
    }
}

#[test]
fn external_mirror_closure_preserves_optional_provider_version_and_physical_key() {
    let original = external_original();
    let authority = &original
        .external_destination
        .as_ref()
        .unwrap()
        .protected_profile
        .profile
        .write_cohort
        .authority;
    let closure = MirrorExternalClosure {
        scope: StorageAuthorityObjectScope {
            guard_namespace_id: authority.guard_namespace_id.clone(),
            physical_authority_id: authority.authority_id.clone(),
            full_key: original.destination_key(),
        },
        guard_stamp: StorageGuardStamp {
            physical_authority_id: authority.authority_id.clone(),
            incarnation: GuardIncarnation::parse("1").unwrap(),
        },
        receipt_digest: "44".repeat(32),
        object: StorageObjectIdentity {
            key: original.destination_key(),
            size: 8,
            etag: "\"positive-tag\"".into(),
            provider_version: None,
        },
    };
    closure.validate_for(&original, true).unwrap();
    assert!(closure.object.provider_version.is_none());

    let mut versioned = closure.clone();
    versioned.object.provider_version = Some("actual-provider-version".into());
    versioned.validate_for(&original, true).unwrap();
    assert!(GuardIncarnation::parse("0").is_err());
    for mutation in 0..4 {
        let mut changed = closure.clone();
        match mutation {
            0 => changed.scope.full_key = original.stage_key(),
            1 => {
                changed.guard_stamp.physical_authority_id =
                    crate::storage_authority::PhysicalStorageAuthorityId::parse(
                        "00000000-0000-4000-8000-000000000002",
                    )
                    .unwrap()
            }
            2 => changed.object.size += 1,
            _ => changed.object.provider_version = Some("null".into()),
        }
        assert!(changed.validate_for(&original, true).is_err());
    }
}
