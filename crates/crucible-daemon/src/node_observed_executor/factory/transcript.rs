//! Installed native recording and authenticated conditional replay policy.
//!
//! Recording starts only after the ordinary catalog authenticates real native
//! resources and seals their complete graph. Recorded context retains the full
//! selected world and run policy; it never turns a physical source into an exact
//! native continuation or removes its original nondeterminism.

mod context;
mod context_fragments;
mod recording;

#[cfg(test)]
mod preparation_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod source_enrollment;

#[cfg(test)]
mod replay_profile;

#[cfg(test)]
mod cursor_allocation;

#[cfg(test)]
mod cursor_evidence;

#[cfg(test)]
mod cursor_policy;

pub use recording::{InstalledRecordedWorld, InstalledReferenceRecording};

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
