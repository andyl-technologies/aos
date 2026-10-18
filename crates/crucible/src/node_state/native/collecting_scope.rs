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
        if self.complete_load_is_selected() {
            self.authenticate_complete_load_admission()
                .map_err(super::super::schema)?;
            return self.collecting_complete_capture_provenance_admitted(
                0,
                self.limits.state.maximum_total_content_bytes,
            );
        }
        self.collecting_provenance_inner(0, None)
    }

    /// Reads actual signed collecting facts while preserving the caller's census.
    ///
    /// This is only a bounded DATA loan. The selected-load receipt, actual code
    /// graph, immutable plan equality and factory callback remain independent.
    pub(crate) fn complete_collecting_provenance_with_retained_data(
        &self,
        additional_retained_bytes: usize,
    ) -> Result<Option<CollectingCompleteCaptureProvenance>, StateError> {
        self.authenticate_complete_load_admission()
            .map_err(super::super::schema)?;
        self.collecting_complete_capture_provenance_admitted(
            additional_retained_bytes,
            self.limits.state.maximum_total_content_bytes,
        )
    }

    pub(super) fn collecting_complete_capture_provenance_admitted(
        &self,
        extra_retained: usize,
        maximum_total: usize,
    ) -> Result<Option<CollectingCompleteCaptureProvenance>, StateError> {
        self.collecting_provenance_inner(extra_retained, Some(maximum_total))
    }

    fn collecting_provenance_inner(
        &self,
        extra_retained: usize,
        admitted: Option<usize>,
    ) -> Result<Option<CollectingCompleteCaptureProvenance>, StateError> {
        let reference = &self.manifest().provenance_ref;
        let bytes = match admitted {
            Some(maximum) => {
                self.read_complete_object_admitted(reference, extra_retained, maximum)?
            }
            None => self.object(reference, self.limits.state.maximum_record_bytes)?,
        };
        if let Some(maximum) = admitted {
            let retained = self
                .capture_owned_storage()
                .map_err(super::super::schema)?
                .checked_add(extra_retained)
                .ok_or_else(|| refused("collecting retained overflow"))?;
            super::storage::admit_decode(&bytes, retained, maximum)?;
        }
        let mut value = crucible_node_contract::canonical::parse_json(
            &bytes,
            self.limits.state.maximum_record_bytes,
        )
        .map_err(super::super::schema)?;
        let scope: CollectingCompleteCaptureProvenance = if admitted.is_some() {
            let Some(scope) = value
                .as_object_mut()
                .and_then(|body| body.remove("collecting_capture"))
            else {
                return Ok(None);
            };
            // Move the selected subtree once; no second DOM is created.
            serde_json::from_value(scope).map_err(super::super::schema)?
        } else {
            let Some(scope) = value.get("collecting_capture") else {
                return Ok(None);
            };
            serde_json::from_value(scope.clone()).map_err(super::super::schema)?
        };
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
