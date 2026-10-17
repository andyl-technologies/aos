//! Selects distinct launch6 original-input lineage semantics before native effects.
//!
//! ```json
//! {"schema_version":6,"closed_ingress":true,"bootstrap":{},"qualification_refs":[],
//!  "definition_sources":{"namespace_publication":{},"handler":{},"event":{},"input":{},"stop":{}}}
//! ```
//! Abbreviated objects denote complete original records. The source regenerates
//! its exact definition from retained bodies; references alone grant no authority.

use crucible_node_contract::{ContentRef, ContractError, Validate};
use serde::{Deserialize, Serialize};

use super::ReferenceServiceBootstrap;
use crate::reference_lineage::InputLineageDefinition;

/// Retains exact original independently installed source definition roles.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageReaderDefinitionSources {
    /// Retains the independently qualified namespace-origin publication body.
    pub namespace_publication: ContentRef,
    /// Pins the separately measured source handler/build closure body.
    pub handler: ContentRef,
    /// Retains the exact installed core Event definition.
    pub event: ContentRef,
    /// Retains the exact installed core InputBatch definition.
    pub input: ContentRef,
    /// Retains the exact installed core StopReceipt definition.
    pub stop: ContentRef,
}

impl LineageReaderDefinitionSources {
    pub(super) fn build(&self) -> Result<InputLineageDefinition, crate::ProviderError> {
        InputLineageDefinition::build(
            self.namespace_publication.clone(),
            self.handler.clone(),
            self.event.clone(),
            self.input.clone(),
            self.stop.clone(),
        )
    }
}

/// Selects only the independently measured original-input reader source dialect.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceLineageReaderLaunchBootstrap {
    /// Selects closed edition six; prior launch grammars cannot enable this reader.
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

impl Validate for ReferenceLineageReaderLaunchBootstrap {
    fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 6 {
            return Err(crate::bodies::invalid(
                "schema_version",
                "lineage reader launch edition differs",
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
