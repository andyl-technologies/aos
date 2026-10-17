//! Distinct private selection for the ordered native-consumption source candidate.
//!
//! ```json
//! {"schema_version":4,"closed_ingress":true,"bootstrap":{},"qualification_refs":[]}
//! ```
//!
//! The abbreviated bootstrap denotes the complete original private authority.
//! Edition four is accepted only by the separate lineage provider entry point.

use crucible_node_contract::{ContentRef, ContractError, Validate};
use serde::{Deserialize, Serialize};

use super::ReferenceServiceBootstrap;

/// Retains original private authority under a distinct source-model selection.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceLineageLaunchBootstrap {
    /// Selects only the closed edition-four private launch grammar.
    pub schema_version: u16,
    /// Permanently removes the input lane for the upstream source.
    pub closed_ingress: bool,
    /// Retains original private host authority and complete resource allowance.
    pub bootstrap: ReferenceServiceBootstrap,
    /// Binds independently host-installed source qualification; empty is unqualified.
    pub qualification_refs: Vec<ContentRef>,
}

impl Validate for ReferenceLineageLaunchBootstrap {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 4 {
            return Err(crate::bodies::invalid(
                "schema_version",
                "lineage source launch edition differs",
            ));
        }
        self.bootstrap.validate()?;
        super::profile::validate_qualifications(&self.qualification_refs).map_err(|_| {
            crate::bodies::invalid(
                "qualification_refs",
                "lineage source qualification geometry differs",
            )
        })
    }
}
