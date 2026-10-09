//! Resolves only prepared original selected bodies alongside immutable base evidence.

use crucible_node_contract::{CaptureManifest, CapturedOwner, ContentRef};

use crate::node_admission::AdmittedGraph;
use crate::node_state::{
    CaptureEvidence, NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateError,
    StateErrorCode, StateRequirements, VerifiedStateContent,
};

use super::PreparedExtensionClosure;

/// Borrows typed prepared bytes; unknown references remain with the base resolver.
pub(in crate::node_state::native) struct SelectionEvidence<'a> {
    pub base: &'a dyn CaptureEvidence,
    pub selected: Option<&'a PreparedExtensionClosure>,
}

impl CaptureEvidence for SelectionEvidence<'_> {
    fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
        if let Some(selected) = self.selected {
            let object = selected
                .objects
                .iter()
                .chain(std::iter::once(&selected.record))
                .find(|object| &object.reference == reference);
            if let Some(object) = object {
                if object.bytes.len() > maximum {
                    return Err(limit("selected immutable body read"));
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(object.bytes.len())
                    .map_err(|_| limit("selected immutable body read"))?;
                bytes.extend_from_slice(&object.bytes);
                return Ok(bytes);
            }
        }
        self.base.content(reference, maximum)
    }

    fn dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<Vec<ContentRef>, StateError> {
        if let Some(selected) = self.selected {
            if reference == &selected.record.reference {
                if bytes != selected.record.bytes.as_slice() || selected.objects.len() > maximum {
                    return Err(limit("selected complete inventory dependencies"));
                }
                let mut row = Vec::new();
                row.try_reserve_exact(selected.objects.len())
                    .map_err(|_| limit("selected complete inventory dependencies"))?;
                row.extend(
                    selected
                        .objects
                        .iter()
                        .map(|object| object.reference.clone()),
                );
                return Ok(row);
            }
            if let Some(row) = selected
                .inventory
                .dependencies
                .iter()
                .find(|row| &row.reference == reference)
            {
                reference.verify(bytes).map_err(crate::node_state::schema)?;
                if row.dependencies.len() > maximum {
                    return Err(limit("selected dependency row"));
                }
                let mut dependencies = Vec::new();
                dependencies
                    .try_reserve_exact(row.dependencies.len())
                    .map_err(|_| limit("selected dependency row"))?;
                dependencies.extend(row.dependencies.iter().cloned());
                return Ok(dependencies);
            }
        }
        self.base.dependencies(reference, bytes, maximum)
    }

    fn verify_owner_capture(
        &self,
        graph: &AdmittedGraph,
        manifest: &CaptureManifest,
        owner: &CapturedOwner,
        requirements: &StateRequirements,
        content: &VerifiedStateContent,
    ) -> Result<NativeOwnerCaptureProof, StateError> {
        self.base
            .verify_owner_capture(graph, manifest, owner, requirements, content)
    }

    fn verify_coordinator_capture(
        &self,
        graph: &AdmittedGraph,
        manifest: &CaptureManifest,
        content: &VerifiedStateContent,
    ) -> Result<NativeCoordinatorCaptureProof, StateError> {
        self.base
            .verify_coordinator_capture(graph, manifest, content)
    }
}

fn limit(subject: &'static str) -> StateError {
    StateError::new(
        StateErrorCode::ResourceLimit,
        subject,
        "selected closure read exceeded reserved credit",
    )
}
