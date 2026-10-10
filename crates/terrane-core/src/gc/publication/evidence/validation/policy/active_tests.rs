//! Checks registered execution profiles without claiming any native authority.

use alloc::borrow::ToOwned;

use super::*;

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
    assert_eq!(registered(1, 1).validate(), Ok(()));
    assert_eq!(registered(2, 1).validate(), Ok(()));
    assert_eq!(registered(3, 2).validate(), Ok(()));
    for (property, attribute) in [(1, 2), (2, 2), (3, 1), (3, 3)] {
        assert_eq!(
            registered(property, attribute).validate(),
            Err(EvidenceError::UnsupportedRevision)
        );
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
