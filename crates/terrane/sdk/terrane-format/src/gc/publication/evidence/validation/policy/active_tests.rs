//! Checks registered execution profiles without claiming any native authority.

#![allow(
    clippy::expect_used,
    reason = "unregistered revision fixtures must fail their assertions"
)]

use super::*;
use alloc::borrow::ToOwned;

fn registered(property: u64, attribute: u64) -> ConfiguredRegistryInputs {
    ConfiguredRegistryInputs {
        property_revision: property,
        behavioral_properties: revision_properties(property)
            .unwrap_or_else(|error| panic!("registered test revision: {error:?}"))
            .into_iter()
            .map(str::to_owned)
            .collect(),
        attribute_revision: attribute,
        selector_revision: 1,
        tree_revision: 1,
        chunk_revision: 1,
        identity_profile: "terrane-v1".into(),
        later_properties: Vec::new(),
    }
}

#[test]
fn active_registry_supports_exact_three_two_one_without_relabeling_legacy() {
    for property in 1..=3 {
        for attribute in [1, 2] {
            let registries = registered(property, attribute);
            assert_eq!(registries.validate(), Ok(()));
            assert_eq!(
                ConfiguredRegistryInputs::property_revision_for(&registries.behavioral_properties),
                Ok(property)
            );
            let bytes = registries.encode().expect("registered ordinary scalars");
            assert_eq!(ConfiguredRegistryInputs::decode(&bytes), Ok(registries));
        }
    }

    for property in [0, 4, u64::MAX] {
        let mut unknown = registered(3, 2);
        unknown.property_revision = property;
        assert_eq!(unknown.validate(), Err(EvidenceError::UnsupportedRevision));
    }
    for attribute in [0, 3, u64::MAX] {
        assert_eq!(
            registered(3, attribute).validate(),
            Err(EvidenceError::UnsupportedRevision)
        );
    }

    // Registered ordinary scalars do not enable an executable carrier tuple.
    use crate::indexing::carrier::SemanticContext;
    assert!(SemanticContext::new(3, 2, 1).is_ok());
    for (property, attribute, tree) in [
        (1, 1, 1),
        (1, 2, 1),
        (2, 2, 1),
        (3, 1, 1),
        (3, 3, 1),
        (3, 2, 2),
    ] {
        assert!(SemanticContext::new(property, attribute, tree).is_err());
    }
}

#[test]
fn active_registry_requires_complete_names_and_unchanged_other_profiles() {
    let active = registered(3, 2);
    let mut missing = active.clone();
    missing
        .behavioral_properties
        .retain(|name| name != "index-gaps");
    assert_eq!(missing.validate(), Err(EvidenceError::Contradiction));
    let mut overlap = active.clone();
    overlap.later_properties.push("index-roots".into());
    assert_eq!(overlap.validate(), Err(EvidenceError::Contradiction));
    let mut tree = active.clone();
    tree.tree_revision = 2;
    assert_eq!(tree.validate(), Err(EvidenceError::UnsupportedRevision));
    let mut unknown = active;
    unknown.identity_profile = "unknown".into();
    assert_eq!(unknown.validate(), Err(EvidenceError::UnsupportedRevision));
}
