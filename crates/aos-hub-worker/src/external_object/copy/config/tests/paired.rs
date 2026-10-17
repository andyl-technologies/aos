//! Independently installed source Read and destination Write selector regressions.
//!
//! These local publication fixtures exercise structural installation checks;
//! they do not attest a provider or qualify the source's declared range bound.

use super::*;
use aos_hub_core::storage_authority::{PhysicalStorageAuthorityId, external_object::copy::{CopyIncarnationMode, CopySourceBindingPin, CopyTransferPins}};

fn paired() -> (ObjectConfig, Config, ExternalCopyOriginal) {
    let (mut object, mut config, mut original) = fixture();
    let mut publication = object.publications[0].clone();
    let authority = PhysicalStorageAuthorityId::parse("00000000-0000-4000-8000-000000000002").unwrap();
    publication.authority.authority_id = authority.clone();
    for alias in &mut publication.aliases {
        alias.authority_id = authority.clone();
        alias.spec.bucket = "independent-source-bucket".into();
    }
    for association in &mut publication.associations {
        association.authority_id = authority.clone();
        association.binding_id += 20;
        association.binding_stable_id = "independent-source-binding".into();
    }
    publication.attestation.as_mut().unwrap().authority_id = authority.clone();
    publication.admission.authority_id = authority;
    publication.digest = crate::external_object::protocol::digest(&publication.admission).unwrap();
    publication.validate(&object.guard_namespace_id, &object.executor_identity).unwrap();

    let destination = &config.domains[0];
    let mut source = destination.clone();
    let project = |cohort: &LeaseCohort| LeaseCohort::from_publication(
        &publication, &object.executor_identity, &cohort.association.association_id,
        cohort.credential.purpose, &cohort.admitted_prefix, cohort.allowed_effects.clone(),
    ).unwrap();
    source.read_cohort = project(&destination.read_cohort);
    source.list_cohort = project(&destination.list_cohort);
    source.write_cohort = project(&destination.write_cohort);
    source.issuer_installation.authority = source.write_cohort.authority.clone();
    source.provider_concurrency = 5;
    // Its writer can use a larger part; only this separately admitted Read bound matters.
    source.part_bytes = integer(MAX_DIRECT_PART_BYTES as i64);
    source.provider_contract.maximum_copy_read_range_bytes = Some(original.part_bytes);
    object.aliases.extend(publication.aliases.clone());
    object.cohorts.extend([source.read_cohort.clone(), source.list_cohort.clone(), source.write_cohort.clone()]);
    object.publications.push(publication);
    object.validate().unwrap();

    original.version = 3;
    original.source.binding_id = source.read_cohort.association.binding_id;
    original.source.prefix = original.destination.prefix.clone();
    original.expected_sha256 = Some("a".repeat(64));
    original.transfer = Some(CopyTransferPins {
        source_binding: CopySourceBindingPin {
            binding_id: original.source.binding_id,
            binding_stable_id: source.read_cohort.association.binding_stable_id.clone(),
            binding_resource_version: source.read_cohort.association.binding_resource_version,
            snapshot_revision: "e".repeat(64),
            profile_digest: source.commitment().unwrap(),
            binding_read_revision: source.read_cohort.association.binding_write_revision,
            read_generation: source.read_cohort.credential.generation,
            physical_authority_id: source.read_cohort.authority.authority_id.clone(),
        },
        source_incarnation: CopyIncarnationMode::ProviderVersion,
        destination_incarnation: CopyIncarnationMode::ProviderVersion,
        destination_physical_authority_id: destination.write_cohort.authority.authority_id.clone(),
        maximum_source_range_bytes: original.part_bytes,
    });
    config.version = 2;
    config.domains.push(source);
    config.validate(&object).unwrap();
    (object, config, original)
}

#[test]
fn paired_original_resolves_independent_domains_and_real_physical_keys() {
    let (object, config, original) = paired();
    config.validate_pair(&object, &original).unwrap();
    let source = config.source_domain(&object, &original).unwrap();
    let destination = config.domain(&object, &original).unwrap();
    assert_ne!(source.commitment().unwrap(), destination.commitment().unwrap());
    assert_ne!(source.read_cohort.alias.spec.bucket, destination.write_cohort.alias.spec.bucket);
    assert_ne!(source.part_bytes, original.part_bytes);
    assert_eq!(source.scope(&object, &original, false).unwrap().full_key,
        destination.scope(&object, &original, true).unwrap().full_key);
}

#[test]
fn paired_source_profile_read_generation_and_range_cannot_be_substituted() {
    let (object, config, original) = paired();
    for change in 0..4 {
        let mut altered = original.clone();
        let pins = altered.transfer.as_mut().unwrap();
        match change {
            0 => pins.source_binding.profile_digest = altered.profile_digest.clone(),
            1 => { pins.source_binding.read_generation = integer(7); altered.read_generation = integer(7); }
            2 => pins.maximum_source_range_bytes = integer(pins.maximum_source_range_bytes.get() + 1),
            _ => pins.source_binding.physical_authority_id = pins.destination_physical_authority_id.clone(),
        }
        assert!(config.validate_pair(&object, &altered).is_err());
    }
}
