//! Exercises real admitted, superseded and contained empty-registry owners.

use super::*;
use crate::retained_metadata::MetadataObserver;

fn empty_pair(
    resume: bool,
    request_id: &str,
) -> (crate::envelope::Envelope, crate::envelope::Envelope) {
    let (mut request, mut response) = pair(resume, request_id);
    request.extensions.insert(
        EXTENSION_NEGOTIATION_V1.into(),
        serde_json::to_value(ExtensionOfferV1 {
            format: U64::new(1),
            required: Vec::new(),
            optional: Vec::new(),
        })
        .unwrap(),
    );
    response.extensions.insert(
        EXTENSION_NEGOTIATION_V1.into(),
        serde_json::to_value(ExtensionSelectionV1 {
            format: U64::new(1),
            selected: Vec::new(),
        })
        .unwrap(),
    );
    (request, response)
}

fn wrapper() -> (ExtensionHandshake, Rc<Empty>) {
    let registry = Rc::new(Empty);
    let mut original = Some(configured_with_schema_spare_capacity(17).0);
    let wrapper =
        ExtensionHandshake::from_original_empty_retained(&mut original, &registry).unwrap();
    assert!(original.is_none());
    (wrapper, registry)
}

fn admitted() -> (ExtensionHandshake, Rc<Empty>, ConnectionAuthority) {
    let (mut wrapper, registry) = wrapper();
    let (request, response) = empty_pair(false, "original-hello/1");
    let mut connection = String::with_capacity(4096);
    connection.push_str("original-connection/1");
    let authority = wrapper
        .admit_envelopes(
            &request,
            &response,
            Id::new(connection).unwrap(),
            &mut Verifier::default(),
        )
        .unwrap();
    (wrapper, registry, authority)
}

#[test]
fn unselected_and_refused_states_preserve_the_original_census() {
    for deny_contract in [false, true] {
        let (mut wrapper, registry) = wrapper();
        let before = wrapper
            .original_empty_retained_metadata_facts_data(&registry)
            .unwrap();
        assert_eq!(
            wrapper
                .original_empty_state_metadata_facts_data(&registry, None)
                .unwrap(),
            before
        );
        let (request, response) = empty_pair(false, "refused-hello/1");
        let mut verifier = Verifier {
            deny_auth: !deny_contract,
            deny_contract,
            ..Verifier::default()
        };

        assert!(
            wrapper
                .admit_envelopes(&request, &response, id("refused/1"), &mut verifier)
                .is_err()
        );

        assert_eq!(
            wrapper
                .original_empty_state_metadata_facts_data(&registry, None)
                .unwrap(),
            before
        );
        assert_eq!(
            wrapper
                .original_empty_retained_metadata_facts_data(&registry)
                .unwrap(),
            before
        );
    }
}

#[test]
fn selected_pair_counts_all_owned_capacities_and_only_proven_shared_roots_once() {
    let (wrapper, registry, authority) = admitted();
    let wrapper_facts = wrapper
        .original_empty_state_metadata_facts_data(&registry, None)
        .unwrap();
    let mut separate = MetadataObserver::new();
    authority.observe_retained_metadata(&mut separate).unwrap();
    let authority_facts = separate.finish();

    let pair = wrapper
        .original_empty_state_metadata_facts_data(&registry, Some(&authority))
        .unwrap();

    assert!(authority.ensure_live().is_ok());
    assert!(wrapper.verify_authority(&authority).is_ok());
    assert!(
        wrapper
            .original_empty_retained_metadata_facts_data(&registry)
            .is_err()
    );
    assert_eq!(wrapper_facts.shared_backing_views, 4);
    assert_eq!(authority_facts.shared_backing_views, 3);
    assert_eq!(pair.shared_backing_views, 4);
    assert_eq!(pair.shared_value_bytes, wrapper_facts.shared_value_bytes);
    assert_eq!(
        pair.string_capacity_bytes,
        wrapper_facts.string_capacity_bytes + authority_facts.string_capacity_bytes
    );
    assert!(pair.string_capacity_bytes - wrapper_facts.string_capacity_bytes >= 4096);
    assert_eq!(
        pair.vector_capacity_bytes,
        wrapper_facts.vector_capacity_bytes + authority_facts.vector_capacity_bytes
    );
    assert_eq!(
        pair.tree_containers,
        wrapper_facts.tree_containers + authority_facts.tree_containers
    );
    assert_eq!(
        pair.tree_entries,
        wrapper_facts.tree_entries + authority_facts.tree_entries
    );
}

#[test]
fn containment_revokes_authority_without_discarding_retained_allocations() {
    let (mut wrapper, registry, authority) = admitted();
    let before = wrapper
        .original_empty_state_metadata_facts_data(&registry, Some(&authority))
        .unwrap();

    wrapper.contain();

    assert!(authority.ensure_live().is_err());
    assert!(wrapper.verify_authority(&authority).is_err());
    assert_eq!(
        wrapper
            .original_empty_state_metadata_facts_data(&registry, Some(&authority))
            .unwrap(),
        before
    );
    assert!(
        wrapper
            .original_empty_retained_metadata_facts_data(&registry)
            .is_err()
    );
    assert!(authority.ensure_live().is_err());
}

#[test]
fn superseded_lease_keeps_its_distinct_empty_selection_allocation() {
    let (mut wrapper, registry, old) = admitted();
    let (request, response) = empty_pair(true, "resumed-hello/2");
    let current = wrapper
        .admit_envelopes(
            &request,
            &response,
            id("connection/2"),
            &mut Verifier::default(),
        )
        .unwrap();

    assert!(old.ensure_live().is_err());
    assert!(current.ensure_live().is_ok());
    assert!(!Arc::ptr_eq(
        old.extensions.as_ref().unwrap(),
        current.extensions.as_ref().unwrap()
    ));
    let retired = wrapper
        .original_empty_state_metadata_facts_data(&registry, Some(&old))
        .unwrap();
    let live = wrapper
        .original_empty_state_metadata_facts_data(&registry, Some(&current))
        .unwrap();
    assert_eq!(retired.shared_backing_views, 5);
    assert_eq!(live.shared_backing_views, 4);
    assert_eq!(retired.shared_value_bytes, live.shared_value_bytes);
    assert!(wrapper.verify_authority(&old).is_err());
}

#[test]
fn equal_wire_claims_and_shared_selection_cannot_replace_original_registrar_backing() {
    let (wrapper, registry, original) = admitted();
    let (_foreign_wrapper, foreign_registry, mut foreign) = admitted();
    assert_eq!(original.connection_id(), foreign.connection_id());
    assert_eq!(original.session_id(), foreign.session_id());
    assert_eq!(original.incarnation_id(), foreign.incarnation_id());
    assert_eq!(original.epoch(), foreign.epoch());
    assert!(!original.same_registration(&foreign));
    foreign.extensions = original.extensions.clone();

    assert!(
        wrapper
            .original_empty_state_metadata_facts_data(&registry, Some(&foreign))
            .is_err()
    );
    assert!(
        wrapper
            .original_empty_state_metadata_facts_data(&foreign_registry, Some(&original))
            .is_err()
    );
    assert!(
        wrapper
            .original_empty_state_metadata_facts_data(&registry, Some(&original))
            .is_ok()
    );
    assert!(original.ensure_live().is_ok());
}

#[test]
fn missing_or_nonempty_lease_selection_cannot_use_empty_registry_census() {
    let (wrapper, registry, mut authority) = admitted();
    let original = authority.extensions.take().unwrap();

    assert!(
        wrapper
            .original_empty_state_metadata_facts_data(&registry, Some(&authority))
            .is_err()
    );
    authority.extensions = Some(vec![selection()].into());
    assert!(
        wrapper
            .original_empty_state_metadata_facts_data(&registry, Some(&authority))
            .is_err()
    );
    authority.extensions = Some(original);
    assert!(
        wrapper
            .original_empty_state_metadata_facts_data(&registry, Some(&authority))
            .is_ok()
    );

    let (unselected, unselected_registry) = self::wrapper();
    assert!(
        unselected
            .original_empty_state_metadata_facts_data(&unselected_registry, Some(&authority))
            .is_err()
    );
}

#[test]
fn historical_registry_owner_variant_still_requires_its_own_census() {
    let mut original = Some(configured());
    let wrapper = ExtensionHandshake::from_original_empty_registry_retained(&mut original).unwrap();

    assert!(
        wrapper
            .original_empty_state_metadata_facts_data(&Rc::new(Empty), None)
            .is_err()
    );
    assert!(wrapper.retain_original_registry_metadata_owner().is_ok());
}
