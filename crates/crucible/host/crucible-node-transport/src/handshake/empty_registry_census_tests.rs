//! Checks exact empty-registry allocation custody without issuing a lease.

use super::*;
use crate::retained_metadata::requested_metadata_backing_storage_data;

struct Empty;

impl OriginalEmptyExtensionRegistry for Empty {}

impl InstalledExtensionNegotiationVerifier for Empty {
    fn supported(&self) -> &[ExtensionSelection] {
        &[]
    }

    fn required(&self) -> &[ExtensionSelection] {
        &[]
    }

    fn verify_selection(
        &self,
        selected: &[ExtensionSelection],
        _: &IdSet,
    ) -> Result<(), ProviderError> {
        if selected.is_empty() {
            Ok(())
        } else {
            Err(ProviderError::Correlation(
                "fixture empty selection differs",
            ))
        }
    }
}

#[test]
fn census_requires_the_same_rc_even_for_equal_zero_field_registries() {
    let (handshake, _) = configured_with_schema_spare_capacity(9);
    let plain = handshake.retained_metadata_facts_data().unwrap();
    let registry = Rc::new(Empty);
    let mut plain_owner = Some(handshake);

    let wrapper =
        ExtensionHandshake::from_original_empty_retained(&mut plain_owner, &registry).unwrap();
    assert!(plain_owner.is_none());
    let facts = wrapper
        .original_empty_retained_metadata_facts_data(&registry)
        .unwrap();

    assert_eq!(facts.shared_backing_views, plain.shared_backing_views + 1);
    assert_eq!(facts.shared_value_bytes, plain.shared_value_bytes);
    assert_eq!(facts.vector_capacity_bytes, plain.vector_capacity_bytes);
    assert_eq!(facts.string_capacity_bytes, plain.string_capacity_bytes);
    assert!(
        requested_metadata_backing_storage_data(&facts).unwrap()
            > requested_metadata_backing_storage_data(&plain).unwrap()
    );

    let equal_but_foreign = Rc::new(Empty);
    assert!(!Rc::ptr_eq(&registry, &equal_but_foreign));
    assert!(
        wrapper
            .original_empty_retained_metadata_facts_data(&equal_but_foreign)
            .is_err()
    );
    assert!(wrapper.retain_original_registry_metadata_owner().is_err());
    assert!(
        wrapper
            .original_empty_retained_metadata_facts_data(&registry)
            .is_ok()
    );
}

#[test]
fn empty_registry_constructor_refuses_owning_marker_without_consuming_handshake() {
    struct Owning(usize);

    impl OriginalEmptyExtensionRegistry for Owning {}

    impl InstalledExtensionNegotiationVerifier for Owning {
        fn supported(&self) -> &[ExtensionSelection] {
            &[]
        }

        fn required(&self) -> &[ExtensionSelection] {
            &[]
        }

        fn verify_selection(
            &self,
            _: &[ExtensionSelection],
            _: &IdSet,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    let registry = Rc::new(Owning(17));
    let mut original = Some(configured());

    assert!(ExtensionHandshake::from_original_empty_retained(&mut original, &registry).is_err());
    assert_eq!(registry.0, 17);
    assert!(original.is_some());
    let exact = Rc::new(Empty);
    assert!(ExtensionHandshake::from_original_empty_retained(&mut original, &exact).is_ok());
    assert!(original.is_none());
}

#[test]
fn historical_registry_owner_variant_cannot_use_empty_wrapper_census() {
    let mut original = Some(configured());
    let wrapper = ExtensionHandshake::from_original_empty_registry_retained(&mut original).unwrap();
    let foreign = Rc::new(Empty);

    assert!(wrapper.retain_original_registry_metadata_owner().is_ok());
    assert!(
        wrapper
            .original_empty_retained_metadata_facts_data(&foreign)
            .is_err()
    );
}
