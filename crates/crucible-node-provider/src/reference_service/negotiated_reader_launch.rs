//! Selects distinct launch7 original-input lineage semantics before native effects.
//!
//! ```json
//! {"schema_version":7,"closed_ingress":true,"bootstrap":{},"qualification_refs":[],
//!  "definition_sources":{"namespace_publication":{},"handler":{},"event":{},"input":{},"stop":{}}}
//! ```
//! Abbreviated objects denote complete original records. The source regenerates
//! its exact definition from retained bodies; references alone grant no authority.

use crucible_node_contract::{ContentRef, ContractError, Validate};
use serde::{Deserialize, Serialize};

use super::{LineageReaderDefinitionSources, ReferenceServiceBootstrap};

/// Selects only the independently measured original-input reader source dialect.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceNegotiatedLineageReaderLaunchBootstrap {
    /// Selects closed edition seven with mandatory exact typed peer negotiation.
    pub schema_version: u16,
    /// Permanently removes the upstream source ingress when true.
    pub closed_ingress: bool,
    /// Retains actual original private host authority and finite allowances.
    pub bootstrap: ReferenceServiceBootstrap,
    /// Retains independently installed qualification; empty remains unqualified.
    pub qualification_refs: Vec<ContentRef>,
    /// Pins original role bodies from the actual installed source closure.
    pub definition_sources: LineageReaderDefinitionSources,
}

impl Validate for ReferenceNegotiatedLineageReaderLaunchBootstrap {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 7 {
            return Err(crate::bodies::invalid(
                "schema_version",
                "typed lineage reader launch edition differs",
            ));
        }
        self.bootstrap.validate()?;
        super::profile::validate_qualifications(&self.qualification_refs).map_err(|_| {
            crate::bodies::invalid(
                "qualification_refs",
                "lineage reader qualification geometry differs",
            )
        })?;
        for reference in [
            &self.definition_sources.namespace_publication,
            &self.definition_sources.handler,
            &self.definition_sources.event,
            &self.definition_sources.input,
            &self.definition_sources.stop,
        ] {
            reference.validate()?;
            let original = self
                .bootstrap
                .installed_content
                .iter()
                .find(|content| content.reference == *reference)
                .ok_or_else(|| {
                    crate::bodies::invalid(
                        "definition_sources",
                        "original installed role body is absent",
                    )
                })?;
            reference.verify(original.bytes.as_slice())?;
        }
        Ok(())
    }
}
