//! Installed native recording and authenticated conditional replay policy.
//!
//! Recording starts only after the ordinary catalog authenticates real native
//! resources and seals their complete graph. Recorded context retains the full
//! selected world and run policy; it never turns a physical source into an exact
//! native continuation or removes its original nondeterminism.

mod recording;

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
    ) -> Result<Box<dyn SimulationNode>, RecorderPreparationFailure> {
        let logical = node.route().node.clone();
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
            recording::source_context(graph, self.selections, self.scenario, self.configuration)
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
