//! Borrows selected facet descriptions without constructing operation authority.

use crate::node_contract::FacetDescription;
use crucible_node_format::{FacetSelection, Id};

impl FacetDescription for FacetSelection {
    fn profile(&self) -> &Id {
        &self.id
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use crate::node_contract::{ExactBoundaryPolicy, NodeFacet, OperationFailure, Refusal};
    use crucible_node_format::Position;
    use std::mem::size_of;

    size_of::<&[FacetSelection]>()
        + size_of::<std::slice::Iter<'static, FacetSelection>>()
        + size_of::<&FacetSelection>()
        + size_of::<Option<&FacetSelection>>()
        + size_of::<&Id>()
        + size_of::<NodeFacet<'static>>()
        + size_of::<Result<NodeFacet<'static>, Refusal>>()
        + size_of::<Refusal>()
        + size_of::<String>()
        + size_of::<(Position, Position, ExactBoundaryPolicy)>()
        + size_of::<Result<(Position, Position, ExactBoundaryPolicy), OperationFailure>>()
}

pub(super) fn preservation(selected: &[FacetSelection]) -> Option<&FacetSelection> {
    selected.iter().find(|facet| {
        facet.id.as_str() == "source-owned.packet-complete-original-lineage/5" && facet.version == 5
    })
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- Invalid inert fixtures or failed refusal assertions stop these controls.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_node_format::{Extensions, canonical};

    fn facet(profile: &str, version: u16) -> FacetSelection {
        let reference = canonical::content_ref(b"{}", "application/json").unwrap();
        FacetSelection {
            id: Id::new(profile).unwrap(),
            version,
            configuration_ref: reference.clone(),
            guarantees_ref: reference,
            extensions: Extensions::new(),
        }
    }

    #[test]
    fn complete_preservation_description_borrows_its_selected_profile() {
        let selected = [
            facet("source-owned.packet-complete-original-lineage/5", 5),
            facet("source-owned.packet-exact/5", 5),
        ];
        let description = preservation(&selected).unwrap();

        assert!(std::ptr::eq(description, &selected[0]));
        assert_eq!(description.profile(), &selected[0].id);
        assert_ne!(description.profile(), &selected[1].id);
    }

    #[test]
    fn exact_only_or_another_edition_cannot_supply_preservation() {
        let exact = [facet("source-owned.packet-exact/5", 5)];
        assert!(preservation(&exact).is_none());

        let other_edition = [facet("source-owned.packet-complete-original-lineage/5", 6)];
        assert!(preservation(&other_edition).is_none());
    }
}
