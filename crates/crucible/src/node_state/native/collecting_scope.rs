//! Retains signed collecting provenance without treating decoded facts as authority.
//!
//! The original Refused plan/audit and source roots are mandatory dependencies.
//! Fresh adoption additionally requires the genuine installed native factory and
//! new opaque collecting plan; this metadata can never issue ordinary acceptance.

use super::*;
use crucible_node_contract::{ContentRef, HashRef, Validate};
use serde::{Deserialize, Serialize};

/// Describes the exact signed collecting scope as inert archive facts.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectingCompleteCaptureProvenance {
    /// Selects the closed collecting archive subrecord, edition one.
    pub schema: String,
    /// Retains the complete original collection plan.
    pub plan: ContentRef,
    /// Retains the complete original Refused acceptance audit.
    pub refused: ContentRef,
    /// Retains every independently installed source/fixture prerequisite.
    pub sources: Vec<ContentRef>,
    /// Retains complete original durable world identity.
    pub world: HashRef,
    /// Remains false; this archive does not issue ordinary acceptance.
    pub ordinary_acceptance: bool,
}

impl NativeArchiveRecord {
    /// Reads signed collecting archive facts without issuing adoption permission.
    ///
    /// # Errors
    /// Refuses malformed scope, accepted markers, missing/reordered prerequisites,
    /// foreign world identity or dependency roles omitted from the signed index.
    pub fn collecting_complete_capture_provenance(
        &self,
    ) -> Result<Option<CollectingCompleteCaptureProvenance>, StateError> {
        let reference = &self.manifest().provenance_ref;
        let bytes = self.object(reference, self.limits.state.maximum_record_bytes)?;
        let value = crucible_node_contract::canonical::parse_json(
            &bytes,
            self.limits.state.maximum_record_bytes,
        )
        .map_err(super::super::schema)?;
        let Some(scope) = value.get("collecting_capture") else {
            return Ok(None);
        };
        let scope: CollectingCompleteCaptureProvenance =
            serde_json::from_value(scope.clone()).map_err(super::super::schema)?;
        if scope.schema != "source-owned.collecting-complete-capture/1"
            || scope.ordinary_acceptance
            || scope.world != self.manifest().world_binding_hash
            || scope.sources.len() > 32
            || scope.sources.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(refused("unsupported collecting capture provenance"));
        }
        scope.world.validate().map_err(super::super::schema)?;
        let object = self
            .index
            .objects
            .iter()
            .find(|object| &object.reference == reference)
            .ok_or_else(|| refused("collecting provenance role is absent"))?;
        for dependency in std::iter::once(&scope.plan)
            .chain(std::iter::once(&scope.refused))
            .chain(&scope.sources)
        {
            dependency.validate().map_err(super::super::schema)?;
            if !object.dependencies.contains(dependency)
                || !self
                    .index
                    .objects
                    .iter()
                    .any(|object| &object.reference == dependency)
            {
                return Err(refused("collecting provenance dependency is absent"));
            }
        }
        Ok(Some(scope))
    }
}
