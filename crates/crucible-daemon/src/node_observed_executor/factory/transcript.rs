//! Installed native recording and authenticated conditional replay policy.
//!
//! Recording starts only after the ordinary catalog authenticates real native
//! resources and seals their complete graph. Recorded context retains the full
//! selected world and run policy; it never turns a physical source into an exact
//! native continuation or removes its original nondeterminism.

pub(super) mod original_lineage;

pub use original_lineage::{
    InstalledOriginalLineageAuthority, InstalledOriginalLineagePlan,
    InstalledOriginalLineagePreparation, InstalledOriginalLineageSourcePolicy,
};

mod context;
mod context_fragments;
mod recording;
mod replay_recipe;
pub(super) mod replay_stepper;

#[cfg(test)]
mod preparation_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod production_tests;

mod source_enrollment;

mod replay_profile;

mod cursor_allocation;

mod cursor_evidence;

mod cursor_policy;

pub use recording::{InstalledRecordedWorld, InstalledReferenceRecording};
pub use replay_recipe::{InstalledConditionalReplay, InstalledReplayRecipe};

use crucible::{
    node_adapters::transcript::{RecordingHandle, RecordingNode, TranscriptLimits},
    node_contract::{ActivationRecord, SimulationNode},
    node_scheduling::InputPayload,
};

use super::*;

/// Retains recording configuration until the actual sealed nodes are wrapped.
pub(super) struct ReferenceRecorder<'a> {
    selections: &'a [InstalledNodeSelection],
    scenario: &'a NodeScenario,
    configuration: &'a NodeRunConfiguration,
    attempt: Id,
    limits: TranscriptLimits,
    handles: BTreeMap<Id, RecordingHandle>,
    #[cfg(test)]
    preparation_fault: Option<RecordingPreparationFault>,
}

#[cfg(test)]
struct RecordingPreparationFault {
    node: Id,
    original_activation: Option<ActivationRecord>,
}

/// Keeps an allocated original handle available for its whole-world guard.
pub(super) struct RecorderPreparationFailure {
    pub(super) error: NodeObservedError,
    pub(super) node: Box<dyn SimulationNode>,
}

impl ReferenceRecorder<'_> {
    pub(super) fn wrap(
        &mut self,
        graph: &AdmittedGraph,
        activation: &ActivationRecord,
        node: Box<dyn SimulationNode>,
        evidence: &trust::InstalledEvidence,
    ) -> Result<Box<dyn SimulationNode>, RecorderPreparationFailure> {
        let logical = node.route().node.clone();
        #[cfg(test)]
        if let Some(fault) = self.preparation_fault.as_mut()
            && fault.node == logical
        {
            fault.original_activation = Some(activation.clone());
            return Err(RecorderPreparationFailure {
                error: refused("injected recording preparation custody fault"),
                node,
            });
        }

        let context = (|| {
            let selection = self
                .selections
                .iter()
                .find(|selection| selection.node == logical)
                .ok_or_else(|| refused("recorded node has no installed selection"))?;
            if !matches!(
                selection.kind,
                InstalledNodeKind::ReferenceDevice { .. }
                    | InstalledNodeKind::ReferenceNativeLinked { .. }
            ) {
                return Ok(None);
            }
            if self.handles.contains_key(&logical) {
                return Err(refused("recorded source node was prepared twice"));
            }
            context::source_context(
                graph,
                self.selections,
                self.scenario,
                self.configuration,
                evidence,
            )
            .map(Some)
        })();
        let context = match context {
            Ok(Some(context)) => context,
            Ok(None) => return Ok(node),
            Err(error) => return Err(RecorderPreparationFailure { error, node }),
        };
        let (node, handle) = match RecordingNode::new(
            graph,
            node,
            self.attempt.clone(),
            activation,
            context,
            self.limits.clone(),
        ) {
            Ok(prepared) => prepared,
            Err(failure) => {
                let (error, node) = failure.into_parts();
                return Err(RecorderPreparationFailure {
                    error: native(error),
                    node,
                });
            }
        };
        self.handles.insert(logical, handle);
        Ok(Box::new(node))
    }
}

#[cfg(test)]
mod replay_execution;

#[cfg(test)]
mod continuation_factory;

#[cfg(test)]
mod continuation_restore;

#[cfg(test)]
mod continuation_publication;

/// Names the existing lossless source context codec for test-only native callers.
#[cfg(test)]
pub(super) const ORIGINAL_CONTEXT_FRAGMENT_MEDIA_TYPE: &str =
    context_fragments::FRAGMENT_MEDIA_TYPE;

/// Fragments original fixture context through the same installed source codec.
///
/// # Errors
/// Refuses changed original bytes, unsupported extents or allocation failure.
#[cfg(test)]
pub(super) fn fragment_fixture_context(
    original: InputPayload,
) -> Result<Vec<InputPayload>, NodeObservedError> {
    context_fragments::fragment_source_object(original)
}

/// Reconstructs original fixture context using the installed bounded reader.
///
/// # Errors
/// Refuses missing, changed, reordered or oversized original source fragments.
#[cfg(test)]
pub(super) fn reconstruct_fixture_context(
    manifest: &InputPayload,
    objects: &[InputPayload],
    maximum_bytes: usize,
) -> Result<InputPayload, NodeObservedError> {
    context_fragments::reconstruct_source_object(manifest, objects, maximum_bytes)
}
