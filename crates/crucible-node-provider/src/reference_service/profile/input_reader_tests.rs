//! Checks distinct reader identities and durable declarations without source authority.

use crucible_node_contract::{ContentRef, Id, U64, canonical};

use super::*;

fn object(bytes: &[u8]) -> ContentRef {
    canonical::content_ref(bytes, "application/octet-stream").unwrap()
}

fn definition() -> InputLineageDefinition {
    InputLineageDefinition::build(
        object(b"namespace"),
        object(b"handler"),
        object(b"Event"),
        object(b"InputBatch"),
        object(b"Stop"),
    )
    .unwrap()
}

fn lineage() -> ReferenceProfile {
    ReferenceProfile::build_public_lineage(
        Id::new("node/a").unwrap(),
        Id::new("owner/a").unwrap(),
        object(b"provider"),
        object(b"device"),
        10.into(),
        U64::new(1_000_000_000),
        false,
    )
    .unwrap()
}

#[test]
fn reader_profile_has_distinct_configuration_facet_and_source_identity() {
    let old = lineage();
    let selected = ReferenceProfile::build_public_lineage_reader(
        old.descriptor.id.clone(),
        old.owner.id.clone(),
        object(b"provider"),
        object(b"device"),
        10.into(),
        U64::new(1_000_000_000),
        InputLineageProfileSelection {
            closed_ingress: false,
            definition: definition(),
        },
    )
    .unwrap();
    assert_ne!(
        old.descriptor.identity().unwrap(),
        selected.descriptor.identity().unwrap()
    );
    assert_ne!(old.configuration_ref, selected.configuration_ref);
    assert_ne!(
        old.implementation.implementation_id,
        selected.implementation.implementation_id
    );
    assert_ne!(
        old.node_manifest.profile_id,
        selected.node_manifest.profile_id
    );
    assert!(old.operating_contract.facets[0].extensions.is_empty());
    assert_eq!(
        selected.operating_contract.facets[0].extensions,
        definition().durable_extensions().unwrap()
    );
    assert_eq!(
        selected.input_lineage_definition().unwrap().selection(),
        definition().selection()
    );
    let after = lineage();
    assert_eq!(
        canonical::canonical_json(&serde_json::to_value(&old.descriptor).unwrap()).unwrap(),
        canonical::canonical_json(&serde_json::to_value(&after.descriptor).unwrap()).unwrap()
    );
    assert!(after.input_lineage_definition().is_none());
}

#[test]
fn reader_configuration_binds_exact_roles_and_two_validation_passes() {
    let profile = ReferenceProfile::build_public_lineage_reader(
        Id::new("node/a").unwrap(),
        Id::new("owner/a").unwrap(),
        object(b"provider"),
        object(b"device"),
        10.into(),
        U64::new(1_000_000_000),
        InputLineageProfileSelection {
            closed_ingress: false,
            definition: definition(),
        },
    )
    .unwrap();
    let configuration =
        canonical::parse_json(profile.content(&profile.configuration_ref).unwrap(), 65_536)
            .unwrap();
    assert_eq!(configuration["maximum_lineage_callbacks"], "8704");
    assert_eq!(
        configuration["input_reader_handler"],
        serde_json::to_value(definition().handler()).unwrap()
    );
    assert!(
        profile
            .provider_manifest
            .extensions_supported
            .iter()
            .any(|feature| feature.as_str() == crate::reference_lineage::INPUT_LINEAGE_FEATURE)
    );
    for (reference, body) in definition().objects() {
        assert_eq!(profile.content(reference).unwrap(), body);
    }
}

#[test]
fn reader_selected_facets_are_exactly_advertised_by_regenerated_capability_body() {
    let legacy = lineage();
    for closed_ingress in [false, true] {
        let profile = ReferenceProfile::build_public_lineage_reader(
            legacy.descriptor.id.clone(),
            legacy.owner.id.clone(),
            object(b"provider"),
            object(b"device"),
            10.into(),
            U64::new(1_000_000_000),
            InputLineageProfileSelection {
                closed_ingress,
                definition: definition(),
            },
        )
        .unwrap();
        let body = profile.content(&profile.capabilities_ref).unwrap();
        profile.capabilities_ref.verify(body).unwrap();
        let advertised: crucible_node_contract::CapabilityProfile =
            canonical::decode(body, 65_536).unwrap();

        assert_eq!(advertised, profile.capabilities);
        assert_eq!(advertised.facets, profile.operating_contract.facets);
        assert!(
            profile
                .operating_contract
                .facets
                .iter()
                .all(|facet| advertised.facets.contains(facet))
        );
        assert_ne!(profile.capabilities_ref, legacy.capabilities_ref);
        assert_eq!(
            advertised.facets[0].configuration_ref,
            profile.configuration_ref
        );
        assert_eq!(
            advertised.facets[0].extensions,
            definition().durable_extensions().unwrap()
        );
    }
    let after = lineage();
    assert_eq!(legacy.capabilities_ref, after.capabilities_ref);
    assert_eq!(legacy.capabilities, after.capabilities);
}
