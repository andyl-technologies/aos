//! Typed node and host-I/O boundaries captured for a world hot fork.

use super::*;

/// Modeled service state of one node in a hot-fork world continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionVmHotForkNodeServiceState {
    /// The node has one paused source QEMU that must participate in the fork.
    Running,
    /// The node is powered off but retains a paused source for a later Boot.
    PoweredOff,
    /// The node is permanently failed and cannot acquire a child process.
    PermanentlyFailed,
}

impl From<ProductionNodeServiceState> for ProductionVmHotForkNodeServiceState {
    fn from(state: ProductionNodeServiceState) -> Self {
        match state {
            ProductionNodeServiceState::Running => Self::Running,
            ProductionNodeServiceState::PoweredOff => Self::PoweredOff,
            ProductionNodeServiceState::PermanentlyFailed => Self::PermanentlyFailed,
        }
    }
}

/// Exact process and scheduler boundary for one World node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionVmHotForkNodeBoundary {
    pub(super) node: NodeId,
    pub(super) generation: u64,
    pub(super) service_state: ProductionVmHotForkNodeServiceState,
    pub(super) scheduler_time: VirtualTime,
    pub(super) physical_time: Option<VirtualTime>,
    pub(super) process: Option<QemuProcessIdentity>,
}

impl ProductionVmHotForkNodeBoundary {
    /// Returns the canonical World node identity.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the positive source process generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the modeled node service state.
    #[must_use]
    pub const fn service_state(&self) -> ProductionVmHotForkNodeServiceState {
        self.service_state
    }

    /// Returns the scheduler time paired with the paused source boundary.
    #[must_use]
    pub const fn scheduler_time(&self) -> VirtualTime {
        self.scheduler_time
    }

    /// Returns the physical QEMU time for a running or powered-off source node.
    #[must_use]
    pub const fn physical_time(&self) -> Option<VirtualTime> {
        self.physical_time
    }

    /// Returns the exact Linux incarnation of a retained source process.
    #[must_use]
    pub const fn process(&self) -> Option<&QemuProcessIdentity> {
        self.process.as_ref()
    }
}

/// Device family of one explicit host-I/O continuation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductionVmHotForkIoNodeKind {
    /// A block device whose immutable base image remains shared.
    Block,
    /// A 9p device whose immutable filesystem tree remains shared.
    NineP,
}

/// Exact host continuation identity for one first-class World I/O node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionVmHotForkIoNodeBoundary {
    pub(super) node: NodeId,
    pub(super) owner: NodeId,
    pub(super) kind: ProductionVmHotForkIoNodeKind,
    pub(super) immutable_artifact: ContentHash,
    pub(super) owner_service_state: ProductionVmHotForkNodeServiceState,
    pub(super) owner_checkpoint_binding: ContentHash,
    pub(super) owner_checkpoint_identity: ContentHash,
}

impl ProductionVmHotForkIoNodeBoundary {
    /// Returns the canonical World I/O node identity.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the VM node that owns this I/O continuation.
    #[must_use]
    pub const fn owner(&self) -> &NodeId {
        &self.owner
    }

    /// Returns the declared I/O device family.
    #[must_use]
    pub const fn kind(&self) -> ProductionVmHotForkIoNodeKind {
        self.kind
    }

    /// Returns the immutable base-image or filesystem-tree identity.
    #[must_use]
    pub const fn immutable_artifact(&self) -> ContentHash {
        self.immutable_artifact
    }

    /// Returns the owner VM's service state at the captured world boundary.
    #[must_use]
    pub const fn owner_service_state(&self) -> ProductionVmHotForkNodeServiceState {
        self.owner_service_state
    }

    /// Returns the original execution binding carried by the owner checkpoint.
    #[must_use]
    pub const fn owner_checkpoint_binding(&self) -> ContentHash {
        self.owner_checkpoint_binding
    }

    /// Returns the canonical identity of the complete owner host checkpoint.
    #[must_use]
    pub const fn owner_checkpoint_identity(&self) -> ContentHash {
        self.owner_checkpoint_identity
    }
}

/// Authenticated scheduler and device boundary of one exact-checkpoint source.
///
/// This opaque value is derived directly from a completely authenticated
/// native exact closure. It lets source admission prove that preparing a live
/// QEMU world preserved the restored scheduler, event-log, node, fault, and
/// host-device cursors.
pub struct ProductionVmExactHotForkSourceBoundary {
    pub(super) configuration: Configuration,
    pub(super) scheduler: SingleSchedulerCheckpoint,
    pub(super) event_log_objects: Arc<BTreeMap<ContentHash, Vec<u8>>>,
    pub(super) signal_artifact_objects: Arc<BTreeMap<ContentHash, Vec<u8>>>,
    pub(super) node_generations: BTreeMap<NodeId, u64>,
    pub(super) node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
    pub(super) host_io: BTreeMap<NodeId, QemuHostIoCheckpoint>,
    pub(super) fault_checkpoint: ContentHash,
}

impl ProductionVmExactHotForkSourceBoundary {
    pub(in crate::vm_lifecycle) fn from_exact_checkpoint(
        checkpoint: &ProductionVmExactCheckpointSet,
    ) -> Result<Self, SchedulerError> {
        let mut host_io = BTreeMap::new();
        for (node, target) in &checkpoint.targets {
            if host_io
                .insert(node.clone(), target.snapshot.host_io().clone())
                .is_some()
            {
                return Err(hot_fork_boundary_error(
                    "exact hot-fork boundary repeats a live host-I/O owner",
                ));
            }
        }
        for (node, failed) in &checkpoint.failed_host_io {
            if host_io
                .insert(node.clone(), failed.host_io.clone())
                .is_some()
            {
                return Err(hot_fork_boundary_error(
                    "exact hot-fork boundary repeats a failed host-I/O owner",
                ));
            }
        }
        if host_io.keys().ne(checkpoint.node_service_states.keys()) {
            return Err(hot_fork_boundary_error(
                "exact hot-fork boundary has an incomplete host-I/O owner set",
            ));
        }
        let fault_checkpoint = checkpoint
            .fault_checkpoint
            .as_ref()
            .ok_or_else(|| hot_fork_boundary_error("exact hot-fork boundary lost fault state"))?
            .id();

        Ok(Self {
            configuration: checkpoint.configuration.clone(),
            scheduler: checkpoint.scheduler.clone(),
            event_log_objects: Arc::clone(&checkpoint.event_log_objects),
            signal_artifact_objects: Arc::clone(&checkpoint.signal_artifact_objects),
            node_generations: checkpoint.node_generations.clone(),
            node_service_states: checkpoint.node_service_states.clone(),
            host_io,
            fault_checkpoint,
        })
    }

    /// Reports whether a prepared source preserves this authenticated boundary.
    #[must_use]
    pub fn matches(&self, continuation: &ProductionVmHotForkWorldContinuation) -> bool {
        let expected_active_host_io = self
            .node_service_states
            .values()
            .filter(|state| {
                matches!(
                    state,
                    ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff
                )
            })
            .count();
        let expected_failed_host_io = self.node_service_states.len() - expected_active_host_io;

        if self.configuration != continuation.configuration
            || self.scheduler != continuation.scheduler
            || self.event_log_objects != continuation.event_log_objects
            || self.signal_artifact_objects != continuation.signal_artifact_objects
            || self.node_generations != continuation.node_generations
            || self.node_service_states != continuation.node_service_states
            || self.fault_checkpoint != continuation.fault_checkpoint.id()
            || self.host_io.len() != continuation.node_service_states.len()
            || continuation.active_host_io.len() != expected_active_host_io
            || continuation.failed_host_io.len() != expected_failed_host_io
            || continuation.nodes.len() != self.node_generations.len()
        {
            return false;
        }

        let mut matched_nodes = BTreeSet::new();
        for boundary in &continuation.nodes {
            if !matched_nodes.insert(boundary.node.clone())
                || !self.node_generations.contains_key(&boundary.node)
            {
                return false;
            }
        }
        if matched_nodes.iter().ne(self.node_generations.keys()) {
            return false;
        }

        self.host_io.iter().all(|(node, expected)| {
            let Some(service_state) = self.node_service_states.get(node) else {
                return false;
            };
            let actual = match service_state {
                ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff => {
                    continuation.active_host_io.get(node)
                }
                ProductionNodeServiceState::PermanentlyFailed => continuation
                    .failed_host_io
                    .get(node)
                    .map(|failed| &failed.host_io),
            };
            actual.is_some_and(|actual| expected.same_device_continuation(actual))
        })
    }
}
