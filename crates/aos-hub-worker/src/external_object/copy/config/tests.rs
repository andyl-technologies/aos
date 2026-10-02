//! Copy profile refusal and exact independently installed cohort regression tests.

use aos_hub_core::storage_authority::external_object::copy::{
    CopyOperationKind, CopyPlacementPin, CopySourceObject, CopyTarget, CopyTopologyOriginal,
};

use super::*;

fn integer(value: i64) -> LeaseInteger {
    LeaseInteger::new(value).unwrap()
}

pub(in crate::external_object::copy) fn fixture() -> (ObjectConfig, Config, ExternalCopyOriginal) {
    let mut object = crate::external_object::tests::config();
    let publication = &object.publications[0];
    let cohort = |purpose, effects| {
        LeaseCohort::from_publication(
            publication,
            &object.executor_identity,
            "association-one",
            purpose,
            "managed/binding/objects",
            effects,
        )
        .unwrap()
    };
    let read = cohort(
        LeasePurpose::Read,
        vec![LeaseEffect::Head, LeaseEffect::Read],
    );
    let list = cohort(LeasePurpose::List, vec![LeaseEffect::List]);
    let write = cohort(
        LeasePurpose::Write,
        vec![
            LeaseEffect::Put,
            LeaseEffect::MultipartCreate,
            LeaseEffect::MultipartPart,
            LeaseEffect::MultipartComplete,
            LeaseEffect::MultipartAbort,
        ],
    );
    object.cohorts = vec![read.clone(), list.clone(), write.clone()];
    object.validate().unwrap();
    let domain = Domain {
        issuer_installation: IssuerInstallation {
            format_version: 1,
            authority: write.authority.clone(),
            issuer_resource_id: "fixture-copy-issuer-resource".into(),
            runtime_identity: "fixture-copy-issuer-runtime".into(),
            executor_identity: object.executor_identity.clone(),
        },
        producer_profile_digest: "c".repeat(64),
        provider_contract: ProviderContract {
            contract_id: "controlled-copy-provider".into(),
            evidence_digest: "d".repeat(64),
            versioned_conditional_range_read: true,
            versioned_multipart_complete: true,
            private_incomplete_upload: true,
            completed_upload_rejects_late_parts: true,
            abort_closes_upload_id: true,
            upload_part_checksum_enforced: true,
            versioned_empty_put: false,
            protected_versionless: None,
        },
        read_cohort: read,
        list_cohort: list,
        write_cohort: write,
        part_bytes: integer(MIN_DIRECT_PART_BYTES as i64),
        provider_concurrency: 3,
        maximum_list_page_objects: 256,
        maximum_list_pages: 256,
    };
    let association = &domain.write_cohort.association;
    let target = |stable_id: &str, generation| CopyTarget {
        stable_id: stable_id.into(),
        authorization_scope_key: "org:1/registry:2".into(),
        control_permission: "placement.manage".into(),
        generation_key: integer(generation),
        configuration_digest: String::new(),
    };
    let pin = |id, generation, prefix: &str| CopyPlacementPin {
        placement_id: integer(id),
        binding_id: association.binding_id,
        resource_version: integer(generation),
        write_spec_version: integer(1),
        registry_id: Some(integer(2)),
        cache_id: None,
        prefix: prefix.into(),
    };
    let original = ExternalCopyOriginal {
        version: 1,
        deployment_id: "fixture-deployment".into(),
        topology: CopyTopologyOriginal {
            operation_id: "actual-retained-operation".into(),
            operation_kind: CopyOperationKind::ReplicatePlacement,
            authorization_scope_key: "org:1/registry:2".into(),
            control_permission: "placement.manage".into(),
            created_at: integer(100),
            source: target("source-placement", 1),
            destination: target("destination-placement", 2),
        },
        binding_id: association.binding_id,
        binding_stable_id: association.binding_stable_id.clone(),
        binding_resource_version: association.binding_resource_version,
        binding_write_revision: association.binding_write_revision,
        snapshot_revision: "a".repeat(64),
        source: pin(1, 1, "objects/source/"),
        destination: pin(2, 2, "objects/destination/"),
        path: "nar/blob.nar".into(),
        source_object: CopySourceObject {
            provider_version: Some("actual-immutable-version".into()),
            etag: "\"actual-source-tag\"".into(),
            bytes: integer(11),
            guard_stamp: None,
        },
        read_generation: domain.read_cohort.credential.generation,
        write_generation: domain.write_cohort.credential.generation,
        profile_digest: domain.commitment().unwrap(),
        part_bytes: domain.part_bytes,
        expected_sha256: None,
        source_receipt_digest: None,
    };
    (
        object,
        Config {
            version: 1,
            domains: vec![domain],
        },
        original,
    )
}

#[test]
fn exact_installed_domain_roundtrips_with_lossless_purpose_pins() {
    let (object, config, original) = fixture();
    let encoded = serde_json::to_string(&config).unwrap();
    let restored = Config::parse(&encoded, &object).unwrap();
    assert!(restored.domain(&object, &original).is_ok());
    assert_eq!(
        restored.domains[0].commitment().unwrap(),
        original.profile_digest
    );
    assert!(encoded.contains("9007199254740993"));
}

#[test]
fn staging_qualification_cannot_substitute_for_versioned_copy_requirements() {
    let (object, config, original) = fixture();
    for property in 0..6 {
        let mut changed = config.clone();
        let contract = &mut changed.domains[0].provider_contract;
        match property {
            0 => contract.versioned_conditional_range_read = false,
            1 => contract.versioned_multipart_complete = false,
            2 => contract.private_incomplete_upload = false,
            3 => contract.completed_upload_rejects_late_parts = false,
            4 => contract.abort_closes_upload_id = false,
            _ => contract.upload_part_checksum_enforced = false,
        }
        assert!(changed.domain(&object, &original).is_err());
    }
}

#[test]
fn uninstalled_list_and_read_cohorts_refuse_without_derived_authority() {
    let (object, config, original) = fixture();
    for purpose in [LeasePurpose::Read, LeasePurpose::List] {
        let mut changed = object.clone();
        changed
            .cohorts
            .retain(|cohort| cohort.credential.purpose != purpose);
        assert!(config.domain(&changed, &original).is_err());
    }
    let mut changed = config.clone();
    changed.domains[0].read_cohort.credential.generation = integer(1);
    assert!(changed.domain(&object, &original).is_err());
}

#[test]
fn old_profile_cannot_select_changed_limits_evidence_or_source_prefix() {
    let (object, config, original) = fixture();
    let mut changed = config.clone();
    changed.domains[0].provider_contract.evidence_digest = "e".repeat(64);
    assert!(changed.domain(&object, &original).is_err());
    changed = config.clone();
    changed.domains[0].maximum_list_pages = 1;
    assert!(changed.domain(&object, &original).is_err());

    let mut owner = original.clone();
    owner.source.prefix = "outside/source".into();
    assert!(config.domain(&object, &owner).is_err());
    owner = original;
    owner.binding_stable_id = "same-numeric-binding-replacement".into();
    assert!(config.domain(&object, &owner).is_err());
}

#[test]
fn empty_copy_requires_explicit_put_property_and_installed_put_cohort() {
    let (object, mut config, mut original) = fixture();
    original.source_object.bytes = integer(0);
    assert!(config.domain(&object, &original).is_err());

    config.domains[0].provider_contract.versioned_empty_put = true;
    original.profile_digest = config.domains[0].commitment().unwrap();
    assert!(config.domain(&object, &original).is_ok());
    config.domains[0].write_cohort.allowed_effects.remove(0);
    original.profile_digest = config.domains[0].commitment().unwrap();
    assert!(config.domain(&object, &original).is_err());
}

#[test]
fn parser_and_execution_budgets_refuse_ambiguity_and_capacity_exhaustion() {
    let (object, config, original) = fixture();
    let mut changed = config.clone();
    changed.domains.push(changed.domains[0].clone());
    assert!(changed.domain(&object, &original).is_err());
    changed = config.clone();
    changed.domains[0].provider_concurrency = 2;
    assert!(changed.domain(&object, &original).is_err());
    changed = config.clone();
    changed.domains[0].maximum_list_page_objects = 257;
    assert!(changed.domain(&object, &original).is_err());
    assert!(Config::parse(&" ".repeat(MAX_CONFIG_BYTES + 1), &object).is_err());
    let mut value = serde_json::to_value(config).unwrap();
    value["unreviewed"] = serde_json::json!(true);
    assert!(Config::parse(&serde_json::to_string(&value).unwrap(), &object).is_err());
}

pub(in crate::external_object::copy) fn protected_fixture(
) -> (ObjectConfig, Config, ExternalCopyOriginal) {
    let (object, mut config, mut original) = fixture();
    let contract = &mut config.domains[0].provider_contract;
    contract.versioned_conditional_range_read = false;
    contract.versioned_multipart_complete = false;
    contract.protected_versionless = Some(VersionlessProviderContract {
        strong_conditional_range_read: true,
        positive_multipart_complete: true,
    });
    original.version = 2;
    original.source_object.provider_version = None;
    original.source_object.guard_stamp = Some(aos_hub_core::storage_authority::StorageGuardStamp {
        physical_authority_id: config.domains[0].read_cohort.authority.authority_id.clone(),
        incarnation: aos_hub_core::storage_authority::GuardIncarnation::parse("11").unwrap(),
    });
    original.expected_sha256 = Some("e".repeat(64));
    original.source_receipt_digest = Some("f".repeat(64));
    original.profile_digest = config.domains[0].commitment().unwrap();
    (object, config, original)
}

#[test]
fn protected_copy_requires_its_exact_independently_installed_contract() {
    let (object, config, original) = protected_fixture();
    assert!(config.domain(&object, &original).is_ok());
    let (_, versioned, _) = fixture();
    assert_ne!(
        config.domains[0].commitment().unwrap(),
        versioned.domains[0].commitment().unwrap()
    );
    assert!(versioned.domain(&object, &original).is_err());
    let encoded = serde_json::to_string(&versioned).unwrap();
    assert!(!encoded.contains("protected_versionless"));

    for requirement in 0..8 {
        let mut changed = config.clone();
        let contract = &mut changed.domains[0].provider_contract;
        match requirement {
            0 => {
                contract
                    .protected_versionless
                    .as_mut()
                    .unwrap()
                    .strong_conditional_range_read = false
            }
            1 => {
                contract
                    .protected_versionless
                    .as_mut()
                    .unwrap()
                    .positive_multipart_complete = false
            }
            2 => contract.versioned_conditional_range_read = true,
            3 => contract.versioned_multipart_complete = true,
            4 => contract.private_incomplete_upload = false,
            5 => contract.completed_upload_rejects_late_parts = false,
            6 => contract.abort_closes_upload_id = false,
            _ => contract.upload_part_checksum_enforced = false,
        }
        assert!(Config::parse(&serde_json::to_string(&changed).unwrap(), &object).is_err());
    }
}
