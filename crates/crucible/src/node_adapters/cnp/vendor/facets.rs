//! Closed facet-to-profile mapping without allocating a second roster.

use super::{VendorCnpFacet, refused};
use crate::node_contract::{FacetKind, OperationFailure};
use crucible_node_contract::{OperatingContract, OperatingMode};

pub(super) fn validate_mapping(
    contract: &OperatingContract,
    facets: &[VendorCnpFacet],
) -> Result<(), OperationFailure> {
    if facets.len() > 10 || facets.len() != contract.facets.len() {
        return Err(refused(
            "vendor facet roster differs from selected profiles",
        ));
    }
    for (index, facet) in facets.iter().enumerate() {
        if !contract
            .facets
            .iter()
            .any(|selected| selected.id == facet.profile)
            || facets[..index]
                .iter()
                .any(|prior| prior.kind == facet.kind || prior.profile == facet.profile)
        {
            return Err(refused("vendor facet mapping is not an exact bijection"));
        }
        if matches!(
            (contract.mode, facet.kind),
            (OperatingMode::Exact, FacetKind::QuantizedExecution)
                | (OperatingMode::Quantized, FacetKind::ExactExecution)
        ) {
            return Err(refused(
                "vendor facet timing mode differs from its selection",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::{Extensions, FacetSelection, Id, canonical};
    use crucible_node_provider::reference_service::ReferenceProfile;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap_or_else(|error| panic!("malformed inert fixture ID: {error}"))
    }

    fn contract() -> OperatingContract {
        let body = canonical::content_ref(b"[]", "application/json")
            .unwrap_or_else(|error| panic!("malformed inert facet fixture: {error}"));
        let mut contract = ReferenceProfile::build(
            id("node"),
            id("owner"),
            body.clone(),
            body,
            crucible_node_contract::U64::new(1000),
            crucible_node_contract::U64::new(1000000),
        )
        .unwrap_or_else(|error| panic!("malformed inert facet fixture: {error}"))
        .operating_contract;
        contract.facets = ["execution", "pause"]
            .map(|name| FacetSelection {
                id: id(name),
                version: 1,
                configuration_ref: canonical::content_ref(b"[]", "application/json")
                    .unwrap_or_else(|error| panic!("malformed inert facet fixture: {error}")),
                guarantees_ref: canonical::content_ref(b"[]", "application/json")
                    .unwrap_or_else(|error| panic!("malformed inert facet fixture: {error}")),
                extensions: Extensions::new(),
            })
            .to_vec();
        contract.mode = OperatingMode::Quantized;
        contract
    }

    fn facets() -> Vec<VendorCnpFacet> {
        vec![
            VendorCnpFacet {
                kind: FacetKind::QuantizedExecution,
                profile: id("execution"),
            },
            VendorCnpFacet {
                kind: FacetKind::PhysicalPause,
                profile: id("pause"),
            },
        ]
    }

    #[test]
    fn duplicate_profile_cannot_omit_another_selected_facet() {
        let selected = contract();
        let mut mapped = facets();
        assert!(validate_mapping(&selected, &mapped).is_ok());

        mapped[1].profile = id("execution");
        assert!(validate_mapping(&selected, &mapped).is_err());
    }

    #[test]
    fn changed_kind_cannot_widen_the_selected_timing_mode() {
        let mut selected = contract();
        let mapped = facets();
        assert!(validate_mapping(&selected, &mapped).is_ok());

        selected.mode = OperatingMode::Exact;
        assert!(validate_mapping(&selected, &mapped).is_err());
    }

    #[test]
    fn foreign_profile_or_duplicate_kind_refuses() {
        let selected = contract();
        let mut mapped = facets();
        mapped[1].profile = id("foreign");
        assert!(validate_mapping(&selected, &mapped).is_err());

        mapped[1].profile = id("pause");
        mapped[1].kind = mapped[0].kind;
        assert!(validate_mapping(&selected, &mapped).is_err());
    }
}
