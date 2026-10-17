//! Retains actual installed semantic axes without consulting later registry defaults.

use std::collections::BTreeSet;

use crucible_node_contract::{ContentRef, ExtensionSelection, Id, OperatingMode};
use serde::{Serialize, Serializer};

use super::{ExtensionImpact, ExtensionRecordKind, ExtensionSemanticContract};

#[cfg(test)]
#[path = "frozen_tests.rs"]
mod tests;

/// Retains one selected installed definition and its exact qualified interpretation.
///
/// Prerequisites have their own records even when no containing graph object
/// directly selects them. Their handlers and semantic axes must not be inferred
/// from the direct application's code or a registry installed after capture.
#[derive(Clone, Debug, Serialize)]
pub struct AdmittedExtensionDefinition {
    selection: ExtensionSelection,
    handler_identity: ContentRef,
    #[serde(serialize_with = "serialize_semantics")]
    semantic_contract: ExtensionSemanticContract,
}

impl AdmittedExtensionDefinition {
    /// Borrows the exact authenticated declaration, version and schema identity.
    pub fn selection(&self) -> &ExtensionSelection {
        &self.selection
    }

    /// Borrows actual independently authenticated handler code identity.
    pub fn handler_identity(&self) -> &ContentRef {
        &self.handler_identity
    }

    /// Borrows all frozen semantic axes and supported actual-context selectors.
    pub fn semantic_contract(&self) -> &ExtensionSemanticContract {
        &self.semantic_contract
    }

    pub(super) fn new(
        selection: ExtensionSelection,
        handler_identity: ContentRef,
        semantic_contract: ExtensionSemanticContract,
    ) -> Self {
        Self {
            selection,
            handler_identity,
            semantic_contract,
        }
    }
}

/// Borrows the complete typed contract for bounded canonical serialization.
#[derive(Serialize)]
pub(super) struct SemanticContractView<'a> {
    class_contract: &'a ContentRef,
    facet_contract: &'a ContentRef,
    mode_contract: &'a ContentRef,
    port_contract: &'a ContentRef,
    timing_contract: &'a ContentRef,
    state_contract: &'a ContentRef,
    error_contract: &'a ContentRef,
    qualification_contract: &'a ContentRef,
    locations: &'a BTreeSet<ExtensionRecordKind>,
    roles: &'a BTreeSet<Id>,
    facets: &'a BTreeSet<Id>,
    modes: &'a [OperatingMode],
    interfaces: &'a BTreeSet<Id>,
    impact: &'static str,
}

impl<'a> From<&'a ExtensionSemanticContract> for SemanticContractView<'a> {
    fn from(contract: &'a ExtensionSemanticContract) -> Self {
        Self {
            class_contract: &contract.class_contract,
            facet_contract: &contract.facet_contract,
            mode_contract: &contract.mode_contract,
            port_contract: &contract.port_contract,
            timing_contract: &contract.timing_contract,
            state_contract: &contract.state_contract,
            error_contract: &contract.error_contract,
            qualification_contract: &contract.qualification_contract,
            locations: &contract.locations,
            roles: &contract.roles,
            facets: &contract.facets,
            modes: &contract.modes,
            interfaces: &contract.interfaces,
            impact: match contract.impact {
                ExtensionImpact::Metadata => "metadata",
                ExtensionImpact::Behavior => "behavior",
            },
        }
    }
}

pub(super) fn serialize_semantics<S: Serializer>(
    contract: &ExtensionSemanticContract,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    SemanticContractView::from(contract).serialize(serializer)
}

/// Measures the same definition shape without cloning bounded installed values.
#[derive(Serialize)]
pub(super) struct DefinitionView<'a> {
    pub selection: &'a ExtensionSelection,
    pub handler_identity: &'a ContentRef,
    pub semantic_contract: SemanticContractView<'a>,
}
