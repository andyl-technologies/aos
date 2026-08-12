//! Terminal conditions, quiescence, World-link runtime, and scheduler-owned state.

use super::*;
/// The terminal scheduler condition reached by a liveness run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerTerminal {
    /// No node can advance and no scheduler event remains pending.
    Quiescent,
    /// The run reached its virtual-time or quantum budget.
    TimeLimitReached,
}

/// Evidence produced by a successful scheduler liveness run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerLivenessReport {
    /// The terminal condition reached by the scheduler.
    pub terminal: SchedulerTerminal,
    /// The number of scheduler quanta driven.
    pub quanta: u64,
    /// The shared-timeline frontier after the last quantum.
    pub frontier: VirtualTime,
    /// The nodes advanced, in scheduler order.
    pub advanced_nodes: Vec<SchedulerNodeId>,
    /// The number of events resolved by the scheduler.
    pub resolved_events: usize,
    /// The number of event-log entries emitted by the scheduler.
    pub event_log_entries: usize,
    /// The final event-log offset reached by the scheduler.
    pub event_log_offset: EventLogOffset,
    /// Content hashes of emitted entries in append order.
    pub event_log_entry_hashes: Vec<ContentHash>,
    /// Whether every node advance happened after yielding the scheduler lock.
    pub yielded_between_quanta: bool,
    /// The final configuration with scheduler decisions appended.
    pub final_configuration: Configuration,
}

/// A liveness failure reported by the scheduler gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerLivenessError {
    /// A scenario with no nodes cannot exercise scheduler progress.
    EmptyScenario,
    /// The scheduler reached a non-quiescent state with no advanceable node.
    Deadlock {
        /// The shared-timeline frontier at the deadlock.
        frontier: VirtualTime,
        /// The number of events still waiting for delivery.
        pending_events: usize,
    },
    /// A runnable node remained non-quiescent but no quantum could advance it.
    Livelock {
        /// The zero-based quantum index that failed to make progress.
        quantum: u64,
        /// The stalled scheduler node.
        node: SchedulerNodeId,
        /// The counter at which the node stalled.
        counter: NodeCounter,
    },
    /// A scheduler implementation held its internal lock across node advance.
    LockHeldAcrossAdvance {
        /// The zero-based quantum index that violated the yield contract.
        quantum: u64,
        /// The node advanced while the scheduler lock was still held.
        node: SchedulerNodeId,
    },
    /// The scheduler boundary returned an operational error.
    Scheduler(SchedulerError),
}

impl fmt::Display for SchedulerLivenessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScenario => f.write_str("scheduler liveness scenario has no nodes"),
            Self::Deadlock {
                frontier,
                pending_events,
            } => write!(
                f,
                "scheduler deadlocked at virtual time {} with {pending_events} pending events",
                frontier.ticks
            ),
            Self::Livelock {
                quantum,
                node,
                counter,
            } => write!(
                f,
                "scheduler livelock at quantum {quantum} on {}:{:?} counter {}",
                node.node.name, node.kind, counter.ticks
            ),
            Self::LockHeldAcrossAdvance { quantum, node } => write!(
                f,
                "scheduler held its lock across node advance at quantum {quantum} on {}:{:?}",
                node.node.name, node.kind
            ),
            Self::Scheduler(error) => write!(f, "scheduler liveness check failed: {error}"),
        }
    }
}

impl Error for SchedulerLivenessError {}

impl From<SchedulerError> for SchedulerLivenessError {
    fn from(error: SchedulerError) -> Self {
        Self::Scheduler(error)
    }
}

/// Deterministic quiescence evidence computed from scheduler-owned state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SchedulerQuiescence {
    /// Authoritative scheduler-state reasons the system is not quiescent.
    pub blockers: Vec<SchedulerQuiescenceBlocker>,
}

impl SchedulerQuiescence {
    /// Returns whether no scheduler-state blocker remains.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// One scheduler-owned state component that prevents quiescence.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SchedulerQuiescenceBlocker {
    /// A node is still runnable and may be selected by PICK.
    RunnableNode {
        /// The runnable scheduler graph node.
        node: SchedulerNodeId,
    },
    /// A scheduler-resolved delivery, I/O completion, fault, or control event is queued.
    PendingEvent {
        /// The canonical key of the queued event.
        key: ScheduledEventKey,
    },
    /// A control operation is waiting for the next quantum boundary.
    PendingControl {
        /// The queued control operation.
        operation: ControlOperation,
    },
    /// An explorer-supplied preemption is waiting for its node RUN.
    PendingPreemption {
        /// The queued preemption decision.
        decision: PreemptionDecision,
    },
    /// A vCPU inside an N-vCPU node is still running.
    ActiveVcpu {
        /// The owning scheduler VM node.
        node: SchedulerNodeId,
        /// The vCPU that is not halted.
        vcpu: VcpuId,
    },
    /// A vCPU inside an N-vCPU node has an armed timer.
    PendingVcpuTimer {
        /// The owning scheduler VM node.
        node: SchedulerNodeId,
        /// The vCPU whose timer is armed.
        vcpu: VcpuId,
        /// The exact virtual-time timer deadline.
        deadline: SimInstant,
    },
    /// A vCPU inside an N-vCPU node has pending input.
    PendingVcpuInput {
        /// The owning scheduler VM node.
        node: SchedulerNodeId,
        /// The vCPU with pending input.
        vcpu: VcpuId,
    },
    /// A topology change is waiting for the next boundary recompute.
    PendingTopologyChange {
        /// Session-local sequence number of the queued topology change.
        sequence: u64,
        /// The reason this change requires a lookahead recompute.
        trigger: SchedulerTopologyChangeTrigger,
        /// Exact activation rendezvous time, when the change is fault-timed.
        activation_time: Option<SimInstant>,
    },
    /// A scheduler node still has an exact local wakeup.
    PendingExactLocalEvent {
        /// The scheduler graph node with the exact wakeup.
        node: SchedulerNodeId,
        /// The exact local event that prevents terminal quiescence.
        event: ExactLocalEvent,
    },
    /// A device sub-node still holds an undelivered I/O completion.
    ///
    /// A completion not yet delivered to its requester is a future happening, so
    /// the system is not quiescent while any is in flight even if every node is
    /// parked `Idle` ([SCHED-22], [SCHED-29]).
    DeviceCompletionInFlight {
        /// The VM node that still owes the completion.
        target: NodeId,
    },
}

/// Error returned while instantiating a production scheduler from a [`World`].
#[derive(Debug, thiserror::Error)]
pub enum SchedulerWorldInstantiationError {
    /// The runtime VM scheduler nodes do not match the logical World participants.
    #[error("scheduler VM nodes do not match the World VM topology")]
    VmTopologyMismatch {
        /// Canonical VM scheduler nodes required by the World.
        expected: Vec<SchedulerNodeId>,
        /// Canonical scheduler nodes supplied by the runtime scenario.
        actual: Vec<SchedulerNodeId>,
    },
    /// Resolving or binding concrete block/9p artifacts failed.
    #[error("cannot instantiate World I/O sub-nodes: {0}")]
    Io(#[from] WorldIoInstantiationError),
    /// A logical World link could not be instantiated as a concrete directed link.
    #[error("cannot instantiate World network link {link:?} ({direction:?}): {source}")]
    Network {
        /// Canonical logical-link identifier.
        link: LinkId,
        /// Directed orientation that failed to instantiate.
        direction: NetworkLinkDirection,
        /// Concrete link-construction error.
        #[source]
        source: crucible_device::DeviceError,
    },
    /// The canonical World contains more directed links than `u32` source ids.
    #[error("World has too many directed network links for physical source ids: {count}")]
    TooManyNetworkLinks {
        /// First directed-link index that did not fit in `u32`.
        count: usize,
    },
    /// A materialized directed-link cursor is missing or does not belong to this World.
    #[error("materialized World network-link state is incompatible: {reason}")]
    NetworkStateMismatch {
        /// Stable explanation of the incompatible cursor set.
        reason: String,
    },
    /// A content-addressed in-flight link payload could not be loaded.
    #[error("cannot restore a materialized World network-link payload: {0}")]
    NetworkPayload(#[from] crate::DagStoreError),
    /// Scheduler state could not absorb the resolved World projection.
    #[error("cannot install World topology in scheduler: {0}")]
    Scheduler(#[from] SchedulerError),
}

/// One concrete directed network link owned by the production scheduler.
#[derive(Clone, Debug)]
pub struct WorldNetworkLinkRuntime {
    pub(super) canonical_id: LinkId,
    pub(super) endpoint_a: NodeId,
    pub(super) endpoint_b: NodeId,
    pub(super) direction: NetworkLinkDirection,
    pub(super) scheduler_node: SchedulerNodeId,
    pub(super) rng_stream: RngStreamId,
    pub(super) fault_id: crate::DeviceId,
    pub(super) link: crucible_device::NetLink,
}

/// Complete scheduler-owned continuation for every modeled network link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerNetworkCheckpoint {
    /// Directed link snapshots in canonical link/direction order.
    pub links: Vec<SchedulerNetworkLinkCheckpoint>,
    /// Shared RNG positions in canonical link order.
    pub rng_positions: BTreeMap<LinkId, u64>,
    /// Exact signal-driven wakeup armed at capture time.
    pub signal_fault_wakeup_nanos: Option<u64>,
}

impl SchedulerNetworkCheckpoint {
    /// Encodes every scheduler-owned directed link and shared RNG cursor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerNetworkCheckpointCodecError`] when link identities are
    /// duplicated or out of order, a collection exceeds its hard bound, or one
    /// of the complete device-owned link snapshots is invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SchedulerNetworkCheckpointCodecError> {
        validate_scheduler_network_checkpoint(self)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SCHEDULER_NETWORK_CHECKPOINT_MAGIC);
        write_scheduler_network_count(&mut bytes, self.links.len(), "directed links")?;
        for link in &self.links {
            write_scheduler_network_string(&mut bytes, &link.link.name)?;
            bytes.push(match link.direction {
                NetworkLinkDirection::EndpointAToEndpointB => 1,
                NetworkLinkDirection::EndpointBToEndpointA => 2,
            });
            write_scheduler_network_blob(&mut bytes, &link.state.canonical_bytes()?)?;
        }
        write_scheduler_network_count(&mut bytes, self.rng_positions.len(), "RNG positions")?;
        for (link, position) in &self.rng_positions {
            write_scheduler_network_string(&mut bytes, &link.name)?;
            bytes.extend_from_slice(&position.to_le_bytes());
        }
        match self.signal_fault_wakeup_nanos {
            Some(wakeup) => {
                bytes.push(1);
                bytes.extend_from_slice(&wakeup.to_le_bytes());
            }
            None => bytes.push(0),
        }
        Ok(bytes)
    }

    /// Decodes and validates every scheduler-owned network continuation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerNetworkCheckpointCodecError`] for unsupported,
    /// malformed, over-limit, duplicated, out-of-order, invalid nested, or
    /// trailing state.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, SchedulerNetworkCheckpointCodecError> {
        let mut reader = SchedulerNetworkCheckpointReader::new(bytes)?;
        let link_count = reader.count("directed links")?;
        let mut links = Vec::with_capacity(link_count);
        for _ in 0..link_count {
            let link = LinkId::from_name(reader.string("link identity")?);
            let direction = match reader.byte("link direction")? {
                1 => NetworkLinkDirection::EndpointAToEndpointB,
                2 => NetworkLinkDirection::EndpointBToEndpointA,
                _ => {
                    return Err(SchedulerNetworkCheckpointCodecError::Malformed(
                        "link direction",
                    ));
                }
            };
            let state =
                crucible_device::LinkSnapshot::from_canonical_bytes(reader.blob("link snapshot")?)?;
            links.push(SchedulerNetworkLinkCheckpoint {
                link,
                direction,
                state,
            });
        }
        let rng_count = reader.count("RNG positions")?;
        let mut rng_positions = BTreeMap::new();
        for _ in 0..rng_count {
            let link = LinkId::from_name(reader.string("RNG link identity")?);
            let position = reader.u64("RNG position")?;
            if rng_positions.insert(link, position).is_some() {
                return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
            }
        }
        let signal_fault_wakeup_nanos = match reader.byte("fault wakeup tag")? {
            0 => None,
            1 => Some(reader.u64("fault wakeup")?),
            _ => {
                return Err(SchedulerNetworkCheckpointCodecError::Malformed(
                    "fault wakeup tag",
                ));
            }
        };
        reader.finish()?;
        let checkpoint = Self {
            links,
            rng_positions,
            signal_fault_wakeup_nanos,
        };
        validate_scheduler_network_checkpoint(&checkpoint)?;
        if checkpoint.canonical_bytes()?.as_slice() != bytes {
            return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
        }
        Ok(checkpoint)
    }
}

const SCHEDULER_NETWORK_CHECKPOINT_MAGIC: &[u8] = b"crucible.scheduler-network.v1\0";
const HARD_SCHEDULER_NETWORK_LINKS: usize = 65_536;
const HARD_SCHEDULER_NETWORK_BLOB_BYTES: usize = 1 << 30;
const HARD_SCHEDULER_NETWORK_NAME_BYTES: usize = 4_096;

/// Failure to encode or decode scheduler-owned network continuation state.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SchedulerNetworkCheckpointCodecError {
    /// The stored format version is unsupported.
    #[error("unsupported scheduler network checkpoint version")]
    Version,
    /// A field is truncated, invalid UTF-8, or has an unknown tag.
    #[error("malformed scheduler network checkpoint field `{0}`")]
    Malformed(&'static str),
    /// A bounded collection or blob exceeds its hard ceiling.
    #[error("scheduler network checkpoint `{field}` exceeds hard limit {hard}")]
    Limit {
        /// Field whose hard bound was exceeded.
        field: &'static str,
        /// Compiled hard ceiling.
        hard: usize,
    },
    /// Link identities are duplicated, out of order, or have noncanonical bytes.
    #[error("noncanonical scheduler network checkpoint")]
    Noncanonical,
    /// A device-owned directed-link checkpoint is invalid.
    #[error(transparent)]
    Link(#[from] crucible_device::LinkSnapshotCodecError),
}

fn validate_scheduler_network_checkpoint(
    checkpoint: &SchedulerNetworkCheckpoint,
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    if checkpoint.links.len() > HARD_SCHEDULER_NETWORK_LINKS
        || checkpoint.rng_positions.len() > HARD_SCHEDULER_NETWORK_LINKS
    {
        return Err(SchedulerNetworkCheckpointCodecError::Limit {
            field: "link count",
            hard: HARD_SCHEDULER_NETWORK_LINKS,
        });
    }
    let mut previous: Option<(&LinkId, NetworkLinkDirection)> = None;
    for link in &checkpoint.links {
        if link.link.name.is_empty()
            || link.link.name.len() > HARD_SCHEDULER_NETWORK_NAME_BYTES
            || previous
                .as_ref()
                .is_some_and(|prior| prior >= &(&link.link, link.direction))
        {
            return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
        }
        let _ = link.state.canonical_bytes()?;
        previous = Some((&link.link, link.direction));
    }
    if checkpoint
        .rng_positions
        .keys()
        .any(|link| link.name.is_empty() || link.name.len() > HARD_SCHEDULER_NETWORK_NAME_BYTES)
    {
        return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
    }
    let directed = checkpoint
        .links
        .iter()
        .map(|link| &link.link)
        .collect::<BTreeSet<_>>();
    if directed != checkpoint.rng_positions.keys().collect::<BTreeSet<_>>() {
        return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
    }
    Ok(())
}

fn write_scheduler_network_count(
    bytes: &mut Vec<u8>,
    count: usize,
    field: &'static str,
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    if count > HARD_SCHEDULER_NETWORK_LINKS {
        return Err(SchedulerNetworkCheckpointCodecError::Limit {
            field,
            hard: HARD_SCHEDULER_NETWORK_LINKS,
        });
    }
    bytes.extend_from_slice(
        &u32::try_from(count)
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Limit {
                field,
                hard: HARD_SCHEDULER_NETWORK_LINKS,
            })?
            .to_le_bytes(),
    );
    Ok(())
}

fn write_scheduler_network_string(
    bytes: &mut Vec<u8>,
    value: &str,
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    if value.is_empty() || value.len() > HARD_SCHEDULER_NETWORK_NAME_BYTES {
        return Err(SchedulerNetworkCheckpointCodecError::Noncanonical);
    }
    write_scheduler_network_blob(bytes, value.as_bytes())
}

fn write_scheduler_network_blob(
    bytes: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), SchedulerNetworkCheckpointCodecError> {
    if value.len() > HARD_SCHEDULER_NETWORK_BLOB_BYTES {
        return Err(SchedulerNetworkCheckpointCodecError::Limit {
            field: "blob",
            hard: HARD_SCHEDULER_NETWORK_BLOB_BYTES,
        });
    }
    bytes.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Limit {
                field: "blob",
                hard: HARD_SCHEDULER_NETWORK_BLOB_BYTES,
            })?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(value);
    Ok(())
}

struct SchedulerNetworkCheckpointReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SchedulerNetworkCheckpointReader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, SchedulerNetworkCheckpointCodecError> {
        let bytes = bytes
            .strip_prefix(SCHEDULER_NETWORK_CHECKPOINT_MAGIC)
            .ok_or(SchedulerNetworkCheckpointCodecError::Version)?;
        Ok(Self { bytes, offset: 0 })
    }

    fn take<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], SchedulerNetworkCheckpointCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SchedulerNetworkCheckpointCodecError::Malformed(field))?
            .try_into()
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, SchedulerNetworkCheckpointCodecError> {
        Ok(self.take::<1>(field)?[0])
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, SchedulerNetworkCheckpointCodecError> {
        Ok(u32::from_le_bytes(self.take(field)?))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, SchedulerNetworkCheckpointCodecError> {
        Ok(u64::from_le_bytes(self.take(field)?))
    }

    fn count(
        &mut self,
        field: &'static str,
    ) -> Result<usize, SchedulerNetworkCheckpointCodecError> {
        let count = usize::try_from(self.u32(field)?)
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        if count > HARD_SCHEDULER_NETWORK_LINKS {
            return Err(SchedulerNetworkCheckpointCodecError::Limit {
                field,
                hard: HARD_SCHEDULER_NETWORK_LINKS,
            });
        }
        Ok(count)
    }

    fn blob(
        &mut self,
        field: &'static str,
    ) -> Result<&'a [u8], SchedulerNetworkCheckpointCodecError> {
        let length = usize::try_from(self.u32(field)?)
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        if length > HARD_SCHEDULER_NETWORK_BLOB_BYTES {
            return Err(SchedulerNetworkCheckpointCodecError::Limit {
                field,
                hard: HARD_SCHEDULER_NETWORK_BLOB_BYTES,
            });
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SchedulerNetworkCheckpointCodecError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    fn string(
        &mut self,
        field: &'static str,
    ) -> Result<String, SchedulerNetworkCheckpointCodecError> {
        let bytes = self.blob(field)?;
        if bytes.is_empty() || bytes.len() > HARD_SCHEDULER_NETWORK_NAME_BYTES {
            return Err(SchedulerNetworkCheckpointCodecError::Malformed(field));
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| SchedulerNetworkCheckpointCodecError::Malformed(field))
    }

    fn finish(self) -> Result<(), SchedulerNetworkCheckpointCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SchedulerNetworkCheckpointCodecError::Noncanonical)
        }
    }
}

/// One directed scheduler link and its complete device continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerNetworkLinkCheckpoint {
    /// Canonical symmetric World-link identity.
    pub link: LinkId,
    /// Directed orientation within the symmetric link.
    pub direction: NetworkLinkDirection,
    /// Clock, fault, RNG, sequence, and in-flight frame state.
    pub state: crucible_device::LinkSnapshot,
}

/// Authenticated result of removing frames during a directed link transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkInFlightDropEvidence {
    /// Canonical scheduler link identity.
    pub link: LinkId,
    /// Directed runtime edge whose frames were removed.
    pub direction: NetworkLinkDirection,
    /// Number of removed frames.
    pub frame_count: u64,
    /// Complete removed-frame records in deterministic delivery order.
    pub frames: Vec<NetworkDroppedFrameEvidence>,
    /// Digest of every removed delivery key, frame identity, and payload.
    pub evidence: ContentHash,
}

/// One recoverable frame record removed by an availability transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkDroppedFrameEvidence {
    /// Consumer icount at which the frame would have become visible.
    pub delivery_icount: u64,
    /// Producer slot in the deterministic transport ABI.
    pub source_slot: u32,
    /// Per-producer delivery sequence.
    pub delivery_sequence: u32,
    /// Correlation identity assigned at guest transmission.
    pub frame_id: u32,
    /// Exact modeled payload at the instant it was removed.
    pub payload: Vec<u8>,
}

impl WorldNetworkLinkRuntime {
    pub(super) fn matches(&self, link: &LinkId, direction: NetworkLinkDirection) -> bool {
        self.direction == direction && &self.canonical_id == link
    }

    /// Returns the canonical collision-free logical link identifier.
    #[must_use]
    pub fn canonical_id(&self) -> &LinkId {
        &self.canonical_id
    }

    /// Returns this runtime's directed orientation.
    #[must_use]
    pub fn direction(&self) -> NetworkLinkDirection {
        self.direction
    }

    pub(super) fn source(&self) -> &NodeId {
        match self.direction {
            NetworkLinkDirection::EndpointAToEndpointB => &self.endpoint_a,
            NetworkLinkDirection::EndpointBToEndpointA => &self.endpoint_b,
        }
    }

    pub(super) fn target(&self) -> &NodeId {
        match self.direction {
            NetworkLinkDirection::EndpointAToEndpointB => &self.endpoint_b,
            NetworkLinkDirection::EndpointBToEndpointA => &self.endpoint_a,
        }
    }

    /// Returns the concrete directed link owned by the scheduler.
    #[must_use]
    pub fn link(&self) -> &crucible_device::NetLink {
        &self.link
    }

    /// Emits a frame using the canonical World-declared link RNG stream.
    ///
    /// # Errors
    ///
    /// Returns [`crucible_device::DeviceError`] when the link rejects the frame,
    /// including clock overflow or a fail-loud delivery into the past.
    pub fn emit(
        &mut self,
        seed: Seed,
        frame: &crucible_device::Frame,
        policy: crucible_device::PastDeliveryPolicy,
    ) -> Result<crate::LinkEmitDecisionRecord, crucible_device::DeviceError> {
        self.emit_from_position(seed, self.link.rng_position(), frame, policy)
    }

    pub(super) fn emit_from_position(
        &mut self,
        seed: Seed,
        rng_position: u64,
        frame: &crucible_device::Frame,
        policy: crucible_device::PastDeliveryPolicy,
    ) -> Result<crate::LinkEmitDecisionRecord, crucible_device::DeviceError> {
        crate::device::emit_link_frame_with_recorded_stream_at_position(
            seed,
            &self.rng_stream,
            &self.fault_id,
            rng_position,
            &mut self.link,
            frame,
            policy,
        )
    }

    pub(super) fn emit_injected_from_position(
        &mut self,
        rng_position: u64,
        frame: &crucible_device::Frame,
        draws: crucible_device::FrameDraws,
        policy: crucible_device::PastDeliveryPolicy,
    ) -> Result<crate::LinkEmitDecisionRecord, crucible_device::DeviceError> {
        crate::device::emit_link_frame_with_injected_draws_at_position(
            &self.rng_stream,
            &self.fault_id,
            rng_position,
            &mut self.link,
            frame,
            draws,
            policy,
        )
    }
}

/// The single authoritative scheduler used by the liveness gate.
#[derive(Clone, Debug)]
pub struct SingleScheduler {
    pub(super) configuration: Configuration,
    pub(super) timeline: SharedTimeline,
    pub(super) quantum_budget: u64,
    pub(super) time_limit: SimInstant,
    /// Runtime-only common-time cap for an exact production branch boundary.
    pub(super) branch_frontier_cap: Option<SimInstant>,
    pub(super) rendezvous: SchedulerRendezvous,
    pub(super) effective_topology: SchedulerLookaheadGraph,
    pub(super) nodes: Vec<RuntimeSchedulerNode>,
    pub(super) topology_changes: Vec<SchedulerTopologyChange>,
    pub(super) run_subdivision_policies: Vec<SchedulerRunSubdivisionPolicy>,
    pub(super) run_subdivision_records: Vec<SchedulerRunSubdivisionRecord>,
    pub(super) preemption_requests: Vec<PreemptionDecision>,
    pub(super) preemption_applications: Vec<SchedulerPreemptionApplication>,
    pub(super) control_admissions: Vec<SchedulerControlAdmission>,
    pub(super) control_applications: Vec<SchedulerControlApplication>,
    pub(super) pending_events: Vec<ScheduledEvent>,
    pub(super) event_sequences: EventSequenceState,
    /// Exact-completion I/O scheduling sub-nodes (disk/9p) keyed by target VM.
    ///
    /// Each [`DeviceSchedulingSubNode`](crate::device_subnode::DeviceSchedulingSubNode)
    /// holds an L1 `crucible-device` whose in-flight completions become the owning
    /// node's exact I/O-completion horizon term and are delivered at their exact
    /// icount through [`SingleScheduler::resolve_device_completions`] ([IO-1],
    /// [IO-3], [SCHED-29]).
    pub(super) device_sub_nodes:
        BTreeMap<NodeId, Vec<crate::device_subnode::DeviceSchedulingSubNode>>,
    /// Concrete directed network links derived from the logical World.
    ///
    /// Each symmetric [`LinkDef`] produces two scheduler-owned [`crucible_device::NetLink`]
    /// values. Trigger/control network faults update these live tables directly;
    /// callers may only borrow the links through the World-aware accessors.
    pub(super) world_network_links:
        BTreeMap<(LinkId, NetworkLinkDirection), WorldNetworkLinkRuntime>,
    /// Shared logical RNG cursor per symmetric World link.
    ///
    /// Both directed runtime edges consume this one stream in scheduler emission
    /// order; their concrete queues and clocks remain direction-local.
    pub(super) world_network_rng_positions: BTreeMap<LinkId, u64>,
    /// Link-fault decisions awaiting the next authoritative EMIT/STEP boundary.
    pub(super) world_network_decisions: Vec<Decision>,
    /// The earliest undelivered device-completion virtual time per target node,
    /// recomputed each quantum by
    /// [`refresh_device_horizons`](SingleScheduler::refresh_device_horizons).
    ///
    /// This is the separate exact I/O-completion horizon TERM the scheduler folds
    /// into a node's effective exact local event ([IO-3], [SCHED-10]) — it bounds
    /// the requester's horizon without injecting a deliverable event, so delivery
    /// happens solely on the RESOLVE path through
    /// [`resolve_device_completions`](SingleScheduler::resolve_device_completions)
    /// and is never double-counted.
    pub(super) device_horizons: BTreeMap<NodeId, SimInstant>,
    /// Earliest exact global evaluation boundary requested by the signal fault runtime.
    ///
    /// This runtime-only term is folded into every live VM's horizon so the
    /// shared frontier reaches cadence and residence deadlines without polling.
    pub(super) signal_fault_wakeup: Option<SimInstant>,
    /// Test-only fault injection: when `true`,
    /// [`resolve_device_completions`](SingleScheduler::resolve_device_completions)
    /// stamps each I/O completion's key with the consumer's *frontier* icount
    /// instead of the completion's exact `delivery_icount`, modeling the
    /// freeze-time / transport-timing bug RFC-0010 forbids ([IO-2], [DET-19]).
    /// Used by `gate:layer1-injection` falsifiability tests to prove the gates go
    /// red when delivery is not icount-exact. It is never set in production.
    #[cfg(test)]
    pub(super) broken_device_delivery_stamp: bool,
    pub(super) control_inbox: Vec<ControlOperation>,
    /// Seed that owns future scheduler/device decision streams.
    ///
    /// It normally equals the immutable scenario seed. A fork may replace it
    /// at the exact branch boundary without rewriting the recorded prefix.
    pub(super) decision_seed: Seed,
    pub(super) decision_rng_cursor: DecisionRngState,
    /// Explorer-selected live World-network outcomes awaiting exact emissions.
    pub(super) branch_network_choices: Vec<OverrideDecision>,
    /// Live World-network frontiers captured in execution order.
    pub(super) search_frontiers: Vec<SearchRuntimeFrontier>,
    pub(super) event_log: EventLog,
    pub(super) trigger_actions: TriggerActionState,
    pub(super) trigger_static_topology: Option<WorldStaticTopology>,
    /// Canonical VM, device, and network-link scheduler identities consumed from
    /// the World projection at instantiation.
    pub(super) world_scheduling_nodes: BTreeSet<SchedulerNodeId>,
    pub(super) frontier: VirtualTime,
    pub(super) quanta: u64,
    pub(super) topology_epoch: u64,
    pub(super) topology_change_applications: Vec<SchedulerTopologyChangeApplication>,
    pub(super) rendezvous_records: Vec<SchedulerRendezvousRecord>,
    pub(super) boundary_yields: u64,
    pub(super) ceiling_publications: Vec<SchedulerRunCeilingPublication>,
    pub(super) lock_held: bool,
    pub(super) last_advance: Option<NodeAdvance>,
    pub(super) last_topology_recompute: bool,
}
