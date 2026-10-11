//! Recorded debugger graph boundaries without native process authority.

use std::collections::BTreeMap;

use crucible::{
    ContentHash, DebugRuntimeRepositionRequest, EventLogOffset, FingerprintSample, Icount, NodeId,
    RuntimeState, SchedulerError, SchedulerState, VirtualTime,
};

/// Original live-execution evidence sampled at one scheduler boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordedDebugBoundary {
    pub(crate) configuration: ContentHash,
    pub(crate) event_log: EventLogOffset,
    pub(crate) scheduler: SchedulerState,
    pub(crate) node_icounts: BTreeMap<NodeId, Icount>,
    pub(crate) node_times: BTreeMap<NodeId, VirtualTime>,
    pub(crate) fingerprints: BTreeMap<NodeId, FingerprintSample>,
    pub(crate) graph_runtimes: Vec<RuntimeState>,
    pub(crate) runtime: Option<RuntimeState>,
}

impl RecordedDebugBoundary {
    /// Returns the earliest recorded node time, or the graph-only fallback.
    pub(crate) fn scheduler_frontier(&self, graph_fallback: VirtualTime) -> VirtualTime {
        self.node_times
            .values()
            .copied()
            .min()
            .unwrap_or(graph_fallback)
    }

    /// Matches graph identity while ignoring boundary-owned runtime evidence.
    ///
    /// A repositioned runtime carries the event-log offset and node counters
    /// from its landed boundary. Those fields must not prevent a subsequent
    /// reverse operation from resolving an earlier sample of the same reduced
    /// graph state.
    pub(crate) fn matches_graph_runtime(&self, runtime: &RuntimeState) -> bool {
        self.validate_graph_runtime(runtime.configuration, runtime.id, runtime)
            .is_ok()
    }

    pub(crate) fn same_sample(&self, other: &Self) -> bool {
        self.configuration == other.configuration
            && self.event_log == other.event_log
            && self.scheduler == other.scheduler
            && self.node_icounts == other.node_icounts
            && self.node_times == other.node_times
            && self.fingerprints == other.fingerprints
    }

    pub(crate) fn bind_graph_runtime(&self, runtime: &RuntimeState) -> RuntimeState {
        let mut bound = runtime.clone();
        bound.configuration = self.configuration;
        bound.event_log = self.event_log;
        bound.scheduler = self.scheduler.clone();
        bound.node_icounts = self.node_icounts.clone();
        bound
    }

    pub(crate) fn validate_graph_runtime(
        &self,
        configuration: ContentHash,
        reduced_state: ContentHash,
        runtime: &RuntimeState,
    ) -> Result<(), SchedulerError> {
        let graph_nodes = runtime
            .node_icounts
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let evidence_nodes = self
            .node_icounts
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let blob_nodes = runtime
            .node_blobs
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let graph_nodes_valid = (graph_nodes.is_empty() && blob_nodes.is_empty())
            || (graph_nodes == evidence_nodes && blob_nodes == evidence_nodes);
        if self.configuration == configuration
            && runtime.configuration == configuration
            && runtime.id == reduced_state
            && graph_nodes_valid
        {
            return Ok(());
        }
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "graph runtime identity does not match the latest production debugger boundary: boundary_configuration_match={} runtime_configuration_match={} reduced_state_match={} node_sets_match={}",
                self.configuration == configuration,
                runtime.configuration == configuration,
                runtime.id == reduced_state,
                graph_nodes_valid,
            ),
        })
    }

    pub(crate) fn matches_target(&self, request: &DebugRuntimeRepositionRequest) -> bool {
        self.configuration == request.target.id()
            && self.event_log == request.target_runtime.event_log
            && self.scheduler == request.target_runtime.scheduler
            && self.node_icounts == request.target_runtime.node_icounts
            && self.runtime.as_ref() == Some(&request.target_runtime)
    }
}
