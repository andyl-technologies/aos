//! In-process deterministic backend and QEMU plugin-side test double.

use std::collections::BTreeMap;

use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, ControlLifecycle, ControlLifecycleError, ControlLifecycleEvent,
    FrameDecodeError, HandshakeError, HostMsg, PluginHandshakeConfig, PluginMsg,
    SETUP_ACK_STATUS_READY, control_decode_host_msg, control_encode_plugin_msg,
    plugin_validate_handshake_ack,
};
use crucible_shmem::{
    ABI_VERSION, AdvanceCeiling, DEFAULT_QUEUE_CAPACITY, FrameDeliveryKey, FrameEntry,
    FrameEntryError, NodeSlotError, RegionAllocation, RegionAllocationAccessError, RegionConfig,
    RegionHeaderSnapshot, RegionLayout, RegionLayoutError, RegionSetupValidationError,
    authorize_advance_ceiling, validate_setup_region_header,
};
use crucible_sim::StableHasher;
use thiserror::Error;

use crate::{
    AdvanceOutcome, Backend, BackendEffect, BackendError, BackendInput, BackendSnapshot,
    Checkpoint, CheckpointKind, ContentHash, ExecutionFingerprint, ExecutionHorizon,
    FingerprintSample, GdbAttachInfo, GdbListen, Icount, NodeBlobRef, NodeId, SchedulerError,
    SchedulerNodeId, SchedulerSendAuthorizer, SchedulingNodeKind, SimulationBackend,
    StepObservation, VirtualTime,
};

/// A deterministic in-process backend implementing [`Backend`].
///
/// `SimBackend` models the minimum backend behavior needed by engine tests: it
/// advances an instruction counter, records delivered inputs, produces stable
/// fingerprints, snapshots its small state, restores snapshots captured by the
/// same backend instance, and shuts down deterministically.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimBackend {
    state: SimBackendState,
    snapshots: BTreeMap<ContentHash, SimBackendState>,
}

impl SimBackend {
    /// Builds a backend at instruction count zero with no delivered inputs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a backend from an explicit state.
    #[must_use]
    pub fn from_state(state: SimBackendState) -> Self {
        Self {
            state,
            snapshots: BTreeMap::new(),
        }
    }

    /// Builds a backend that can restore `checkpoint` as a known snapshot.
    ///
    /// The resulting backend mirrors the checkpoint's highest recorded node
    /// instruction count as its deterministic state. This is intended for
    /// model-backed realization paths that need to replay from an existing
    /// checkpoint without depending on a concrete VM process.
    #[must_use]
    pub fn from_restorable_checkpoint(checkpoint: &Checkpoint) -> Self {
        Self::from_restorable_checkpoints(std::slice::from_ref(checkpoint))
    }

    /// Builds a backend that can restore each checkpoint in `checkpoints`.
    ///
    /// Unknown checkpoints still fail through [`Backend::restore`]. This
    /// constructor only declares the supplied checkpoints as known deterministic
    /// model snapshots.
    #[must_use]
    pub fn from_restorable_checkpoints(checkpoints: &[Checkpoint]) -> Self {
        let mut snapshots = BTreeMap::new();
        for checkpoint in checkpoints {
            snapshots.insert(checkpoint.id, SimBackendState::from_checkpoint(checkpoint));
        }
        let state = checkpoints
            .last()
            .map(SimBackendState::from_checkpoint)
            .unwrap_or_default();
        Self { state, snapshots }
    }

    /// Returns the current deterministic backend state.
    #[must_use]
    pub fn state(&self) -> &SimBackendState {
        &self.state
    }

    /// Consumes the backend and returns the current deterministic state.
    #[must_use]
    pub fn into_state(self) -> SimBackendState {
        self.state
    }

    fn reject_if_shutdown(&self, operation: &'static str) -> Result<(), BackendError> {
        if self.state.shutdown {
            Err(BackendError::Rejected {
                message: format!("sim backend is shut down; cannot {operation}"),
            })
        } else {
            Ok(())
        }
    }
}

impl Backend for SimBackend {
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        self.reject_if_shutdown("advance")?;
        if horizon.icount < self.state.icount {
            return Err(BackendError::Rejected {
                message: format!(
                    "sim backend cannot advance backwards from {} to {} retired instructions",
                    self.state.icount.retired, horizon.icount.retired
                ),
            });
        }

        self.state.icount = horizon.icount;
        Ok(AdvanceOutcome::ReachedHorizon)
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        Ok(ExecutionFingerprint {
            hash: self.state.fingerprint(),
        })
    }

    fn deliver_input(&mut self, input: BackendInput) -> Result<(), BackendError> {
        self.reject_if_shutdown("deliver input")?;
        self.state.delivered_inputs.push(input);
        Ok(())
    }

    fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
        let mut checkpoint = Checkpoint::with_node_blobs(
            self.state.checkpoint_id(),
            self.state.fingerprint(),
            CheckpointKind::Fat,
            self.state.node_blobs(),
        );
        checkpoint.virtual_time = VirtualTime {
            ticks: self.state.icount.retired,
        };
        checkpoint.node_icounts.insert(
            NodeId {
                name: String::from("sim"),
            },
            self.state.icount,
        );
        self.snapshots.insert(checkpoint.id, self.state.clone());
        Ok(checkpoint)
    }

    fn restore(&mut self, checkpoint: &Checkpoint) -> Result<(), BackendError> {
        let Some(state) = self.snapshots.get(&checkpoint.id) else {
            return Err(BackendError::Rejected {
                message: String::from("sim backend cannot restore unknown checkpoint"),
            });
        };
        self.state = state.clone();
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.state.shutdown = true;
        Ok(())
    }
}

impl SimulationBackend for SimBackend {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        let outcome = self.advance_to_horizon(ExecutionHorizon {
            icount: Icount {
                retired: ceiling.ticks,
            },
        })?;
        Ok(StepObservation::from_advance_outcome(ceiling, outcome))
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        let now = self.now();
        if at != now {
            return Err(BackendError::Rejected {
                message: format!(
                    "sim backend effect at {} does not match scheduler time {}",
                    at.ticks, now.ticks
                ),
            });
        }
        match effect {
            BackendEffect::Noop => Ok(()),
            BackendEffect::DeliverInput(input) => self.deliver_input(input.clone()),
            BackendEffect::Shutdown => Backend::shutdown(self),
        }
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        Backend::snapshot(self).map(BackendSnapshot::new)
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        Backend::restore(self, &snapshot.checkpoint)
    }

    fn now(&self) -> VirtualTime {
        VirtualTime {
            ticks: self.state.icount.retired,
        }
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        Ok(FingerprintSample {
            node,
            at: self.now(),
            fingerprint: Backend::fingerprint(self)?,
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Backend::shutdown(self)
    }
}

/// The small deterministic state tracked by [`SimBackend`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimBackendState {
    /// The current retired-instruction count.
    pub icount: Icount,
    /// Deterministic inputs delivered to the backend.
    pub delivered_inputs: Vec<BackendInput>,
    /// Whether the backend has been shut down.
    pub shutdown: bool,
}

impl SimBackendState {
    fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        let icount = checkpoint
            .node_icounts
            .values()
            .copied()
            .max()
            .unwrap_or(Icount {
                retired: checkpoint.virtual_time.ticks,
            });
        Self {
            icount,
            delivered_inputs: Vec::new(),
            shutdown: false,
        }
    }

    /// Computes a deterministic fingerprint for this state.
    #[must_use]
    pub fn fingerprint(&self) -> ContentHash {
        let mut hasher = StableHasher::new();
        hasher.write_tag("crucible.sim-backend.state");
        hasher.write_u64(self.icount.retired);
        hasher.write_bool(self.shutdown);
        hasher.write_u64(self.delivered_inputs.len() as u64);
        for input in &self.delivered_inputs {
            hasher.write_tag("input");
            hasher.write_bytes(input.node.name.as_bytes());
            hasher.write_bytes(&input.payload);
        }
        ContentHash {
            bytes: hasher.finish().bytes,
        }
    }

    fn checkpoint_id(&self) -> ContentHash {
        let fingerprint = self.fingerprint();
        let mut hasher = StableHasher::new();
        hasher.write_tag("crucible.sim-backend.checkpoint");
        hasher.write_bytes(&fingerprint.bytes);
        ContentHash {
            bytes: hasher.finish().bytes,
        }
    }

    fn node_blobs(&self) -> BTreeMap<NodeId, NodeBlobRef> {
        let parent = ContentHash::from_canonical_material("crucible.sim-backend.node-blob", "root");
        let resolved = self.fingerprint();
        let delta = ContentHash::from_canonical_material(
            "crucible.sim-backend.node-blob.delta",
            &format!(
                "icount={}\ninputs={}\nshutdown={}",
                self.icount.retired,
                self.delivered_inputs.len(),
                self.shutdown
            ),
        );
        BTreeMap::from([(
            NodeId {
                name: String::from("sim"),
            },
            NodeBlobRef::cow_delta(parent, delta, resolved),
        )])
    }
}

/// Configuration for an in-process QEMU plugin-side test double.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimDoubleConfig {
    /// Zero-based VM slot represented by the double.
    pub slot_index: u32,
    /// Number of logical VM slots in the shared-memory region.
    pub vm_node_count: u32,
    /// Capacity of every directed SPSC frame ring.
    pub queue_capacity: u32,
    /// Fixed icount shift used by the shared-memory clock cells.
    pub icount_shift: u8,
    /// Deterministic instruction-budget script.
    pub script: SimInstructionScript,
}

impl Default for SimDoubleConfig {
    fn default() -> Self {
        Self {
            slot_index: 0,
            vm_node_count: 1,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            icount_shift: 0,
            script: SimInstructionScript::default(),
        }
    }
}

/// A deterministic instruction-budget program for [`SimDouble`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimInstructionScript {
    steps: Vec<SimInstructionStep>,
    next_step: usize,
}

impl SimInstructionScript {
    /// Builds a script from ordered steps.
    #[must_use]
    pub fn new(steps: Vec<SimInstructionStep>) -> Self {
        Self {
            steps,
            next_step: 0,
        }
    }

    /// Returns the ordered script steps.
    #[must_use]
    pub fn steps(&self) -> &[SimInstructionStep] {
        &self.steps
    }

    fn candidate(&self, current_icount: u64, horizon_icount: u64) -> SimInstructionStep {
        if self.steps.is_empty() {
            return SimInstructionStep {
                instruction_budget: horizon_icount.saturating_sub(current_icount),
                outbound_frames: Vec::new(),
            };
        }

        let step_index = self.next_step.min(self.steps.len().saturating_sub(1));
        self.steps[step_index].clone()
    }

    fn consume_candidate(&mut self) {
        if self.steps.is_empty() {
            return;
        }

        self.next_step = self.next_step.saturating_add(1);
    }
}

/// One deterministic instruction-budget step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimInstructionStep {
    /// Maximum retired instructions this step may consume.
    pub instruction_budget: u64,
    /// Frames the double posts after reaching this step's target icount.
    pub outbound_frames: Vec<SimOutboundFrame>,
}

impl SimInstructionStep {
    /// Builds one instruction-budget step with no outbound frames.
    #[must_use]
    pub fn budget(instruction_budget: u64) -> Self {
        Self {
            instruction_budget,
            outbound_frames: Vec::new(),
        }
    }
}

/// A scripted frame emitted by [`SimDouble`] after one instruction step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimOutboundFrame {
    /// Physical destination slot in the shared-memory region.
    pub dst_slot: u32,
    /// Consumer icount at which the frame is deliverable.
    pub delivery_icount: u64,
    /// Payload bytes carried by the real shared-memory [`FrameEntry`].
    pub payload: Vec<u8>,
}

/// A control protocol event observed by [`SimDouble`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimDoubleControlEvent {
    /// The host accepted the plugin hello.
    HelloAck {
        /// Negotiated control-protocol version.
        proto_version: u32,
        /// Negotiated shared-memory ABI version.
        abi_version: u32,
        /// Slot assigned by the host.
        slot_index: u32,
        /// Host-advertised node count.
        node_count: u32,
    },
    /// The host sent setup with a region length.
    Setup {
        /// Shared-memory byte length sent in the setup frame.
        region_len: u64,
    },
    /// The host sent a graceful quit request.
    Quit,
}

/// A frame delivered into [`SimDouble`] through the shared SPSC ring API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimDeliveredFrame {
    /// Source physical slot.
    pub src_slot: u32,
    /// Producer sequence number.
    pub sequence: u32,
    /// Consumer icount at which the frame became visible.
    pub delivery_icount: u64,
    /// Payload bytes copied from the shared-memory frame.
    pub payload: Vec<u8>,
}

/// A canonical host-side ordering event observed while driving [`SimDouble`].
///
/// The event vocabulary deliberately excludes the synthetic guest fingerprint
/// and other double-only state. It records only ordering visible to the host
/// scheduler or shared-memory transport so tests can compare it with the real
/// plugin path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimDoubleHostScheduleEvent {
    /// The host-authorized quantum advanced or paused at an earlier delivery.
    HorizonAdvance {
        /// Icount before the advance request.
        from_icount: u64,
        /// Icount requested by the host for this quantum.
        requested_icount: u64,
        /// Icount reached by the backend before returning control.
        reached_icount: u64,
        /// Backend result reported to the host.
        outcome: AdvanceOutcome,
    },
    /// An inbound frame became visible to the guest through a shared SPSC ring.
    FrameDelivery {
        /// Source physical slot.
        src_slot: u32,
        /// Producer sequence number.
        sequence: u32,
        /// Consumer icount at which the frame became visible.
        delivery_icount: u64,
        /// Delivered payload bytes.
        payload: Vec<u8>,
    },
    /// A guest-emitted frame was posted to an outbound shared SPSC ring.
    FrameEmission {
        /// Physical destination slot.
        dst_slot: u32,
        /// Producer sequence number stamped on the outbound frame.
        sequence: u32,
        /// Consumer icount at which the frame is deliverable.
        delivery_icount: u64,
        /// Emitted payload bytes.
        payload: Vec<u8>,
    },
    /// A deterministic device callback completed host-side I/O.
    IoCompletion {
        /// Stable device or executor label.
        device: String,
        /// Completion sequence within the device stream.
        sequence: u64,
        /// Icount at which the completion became host-observable.
        completion_icount: u64,
        /// Completion payload or status bytes.
        payload: Vec<u8>,
    },
    /// A host-visible snapshot was captured.
    Snapshot {
        /// Content-addressed checkpoint identifier.
        checkpoint_id: ContentHash,
        /// Execution fingerprint recorded in the checkpoint.
        fingerprint: ContentHash,
        /// Captured checkpoint representation.
        kind: CheckpointKind,
    },
}

/// An in-process QEMU plugin-side test double.
///
/// `SimDouble` is the Phase-1 stand-in for one real QEMU plugin endpoint. It
/// uses the real shared-memory layout types, SPSC queue implementation, and
/// control protocol codec; only the guest behavior generator is synthetic.
pub struct SimDouble {
    backend: SimBackend,
    shmem: SimDoubleShmem,
    script: SimInstructionScript,
    control_lifecycle: ControlLifecycle,
    slot_index: u32,
    icount_shift: u8,
    next_outbound_sequence: u32,
    next_inbound_sequence_by_source: BTreeMap<u32, u32>,
    delivered_frames: Vec<SimDeliveredFrame>,
    control_events: Vec<SimDoubleControlEvent>,
    host_observable_schedule: Vec<SimDoubleHostScheduleEvent>,
    snapshots: BTreeMap<ContentHash, SimDoubleSnapshotState>,
}

#[derive(Clone)]
struct SimDoubleSnapshotState {
    backend: SimBackend,
    shmem: SimDoubleShmem,
    script: SimInstructionScript,
    control_lifecycle: ControlLifecycle,
    next_outbound_sequence: u32,
    next_inbound_sequence_by_source: BTreeMap<u32, u32>,
    delivered_frames: Vec<SimDeliveredFrame>,
    control_events: Vec<SimDoubleControlEvent>,
    host_observable_schedule: Vec<SimDoubleHostScheduleEvent>,
}

impl SimDouble {
    /// Builds a new in-process test double.
    ///
    /// # Errors
    ///
    /// Returns [`SimDoubleError`] when the requested shared-memory geometry is
    /// invalid or the requested slot is outside the VM node range.
    pub fn new(config: SimDoubleConfig) -> Result<Self, SimDoubleError> {
        if config.slot_index >= config.vm_node_count {
            return Err(SimDoubleError::SlotOutOfRange {
                slot_index: config.slot_index,
                vm_node_count: config.vm_node_count,
            });
        }
        let shmem = SimDoubleShmem::new(RegionConfig::new(
            config.vm_node_count,
            config.queue_capacity,
            u32::from(config.icount_shift),
        ))?;
        let mut control_lifecycle = ControlLifecycle::new();
        control_lifecycle.observe(ControlLifecycleEvent::ConnectUnixStreamSocketPair)?;
        control_lifecycle.observe(ControlLifecycleEvent::PluginHello)?;
        Ok(Self {
            backend: SimBackend::new(),
            shmem,
            script: config.script,
            control_lifecycle,
            slot_index: config.slot_index,
            icount_shift: config.icount_shift,
            next_outbound_sequence: 0,
            next_inbound_sequence_by_source: BTreeMap::new(),
            delivered_frames: Vec::new(),
            control_events: Vec::new(),
            host_observable_schedule: Vec::new(),
            snapshots: BTreeMap::new(),
        })
    }

    /// Returns the backend state owned by the test double.
    #[must_use]
    pub fn backend_state(&self) -> &SimBackendState {
        self.backend.state()
    }

    /// Returns the shared-memory layout used by the double.
    #[must_use]
    pub fn shmem_layout(&self) -> RegionLayout {
        self.shmem.layout()
    }

    /// Returns the shared-memory region header snapshot.
    #[must_use]
    pub fn shmem_header_snapshot(&self) -> RegionHeaderSnapshot {
        self.shmem.header_snapshot()
    }

    /// Returns ordered control protocol events observed by the double.
    #[must_use]
    pub fn control_events(&self) -> &[SimDoubleControlEvent] {
        &self.control_events
    }

    /// Returns ordered frames delivered through the double's inbound rings.
    #[must_use]
    pub fn delivered_frames(&self) -> &[SimDeliveredFrame] {
        &self.delivered_frames
    }

    /// Returns the canonical host-observable schedule recorded by the double.
    #[must_use]
    pub fn host_observable_schedule(&self) -> &[SimDoubleHostScheduleEvent] {
        &self.host_observable_schedule
    }

    /// Encodes the plugin-side `Hello` frame with the real protocol codec.
    #[must_use]
    pub fn plugin_hello_frame(&self) -> Vec<u8> {
        control_encode_plugin_msg(&PluginMsg::Hello {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
        })
    }

    /// Decodes and handles one host-to-plugin control frame.
    ///
    /// # Errors
    ///
    /// Returns [`SimDoubleError`] when the frame is malformed, carries
    /// incompatible versions or geometry, or requests an invalid slot.
    pub fn accept_host_control_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<Vec<u8>>, SimDoubleError> {
        let message = control_decode_host_msg(frame)?;
        match message {
            message @ HostMsg::HelloAck { .. } => {
                let negotiated = plugin_validate_handshake_ack(
                    message,
                    PluginHandshakeConfig {
                        proto_version: CONTROL_PROTOCOL_VERSION,
                        abi_version: ABI_VERSION,
                    },
                )?;
                if negotiated.slot_index != self.slot_index {
                    return Err(SimDoubleError::SlotMismatch {
                        expected: self.slot_index,
                        actual: negotiated.slot_index,
                    });
                }
                if negotiated.node_count != self.shmem.layout().node_count {
                    return Err(SimDoubleError::NodeCountMismatch {
                        expected: self.shmem.layout().node_count,
                        actual: negotiated.node_count,
                    });
                }
                self.control_lifecycle
                    .observe(ControlLifecycleEvent::HostHelloAck)?;
                self.control_events.push(SimDoubleControlEvent::HelloAck {
                    proto_version: negotiated.proto_version,
                    abi_version: negotiated.abi_version,
                    slot_index: negotiated.slot_index,
                    node_count: negotiated.node_count,
                });
                Ok(None)
            }
            HostMsg::Setup { region_len } => {
                self.control_lifecycle
                    .observe(ControlLifecycleEvent::HostSetup)?;
                validate_setup_region_header(self.shmem.header_snapshot(), region_len)?;
                self.control_events
                    .push(SimDoubleControlEvent::Setup { region_len });
                self.control_lifecycle
                    .observe(ControlLifecycleEvent::PluginSetupAck {
                        status: SETUP_ACK_STATUS_READY,
                    })?;
                self.control_lifecycle
                    .observe(ControlLifecycleEvent::RunViaSharedMemory)?;
                Ok(Some(control_encode_plugin_msg(&PluginMsg::SetupAck {
                    status: SETUP_ACK_STATUS_READY,
                })))
            }
            HostMsg::Quit => {
                self.control_lifecycle
                    .observe(ControlLifecycleEvent::HostQuit)?;
                Backend::shutdown(&mut self.backend)?;
                self.control_events.push(SimDoubleControlEvent::Quit);
                Ok(None)
            }
        }
    }

    /// Enqueues an inbound frame into the real shared-memory SPSC ring model.
    ///
    /// # Errors
    ///
    /// Returns [`SimDoubleError`] when no directed ring exists from `src_slot`
    /// to the double's slot, the payload is too large, or the ring is full.
    pub fn enqueue_inbound_frame(
        &mut self,
        src_slot: u32,
        delivery_icount: u64,
        payload: &[u8],
    ) -> Result<(), SimDoubleError> {
        let sequence = self
            .next_inbound_sequence_by_source
            .entry(src_slot)
            .or_insert(0);
        let frame_sequence = *sequence;
        *sequence = sequence.wrapping_add(1);
        self.enqueue_inbound_frame_with_sequence(src_slot, frame_sequence, delivery_icount, payload)
    }

    /// Enqueues an inbound frame with an explicit producer sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`SimDoubleError`] when no directed ring exists from `src_slot`
    /// to the double's slot, the payload is too large, or the ring is full.
    pub fn enqueue_inbound_frame_with_sequence(
        &mut self,
        src_slot: u32,
        sequence: u32,
        delivery_icount: u64,
        payload: &[u8],
    ) -> Result<(), SimDoubleError> {
        let frame = FrameEntry::new(delivery_icount, src_slot, sequence, payload)?;
        self.shmem
            .enqueue_directed_frame(src_slot, self.slot_index, &frame)
    }

    /// Advances the scripted backend toward `horizon`.
    ///
    /// The method consumes one deterministic script step, publishes the same
    /// shared-memory clock/ceiling fields a plugin would touch, drains
    /// deliverable inbound frames through the real SPSC dequeue path, and emits
    /// any scripted outbound frames through the real SPSC enqueue path after
    /// scheduler topology authorization.
    ///
    /// # Errors
    ///
    /// Returns [`SimDoubleError`] when backend advancement, shared-memory clock
    /// publication, frame delivery, scheduler send authorization, or scripted
    /// frame enqueue fails.
    pub fn advance_scripted_quantum(
        &mut self,
        horizon: ExecutionHorizon,
        send_authorizer: &dyn SchedulerSendAuthorizer,
    ) -> Result<AdvanceOutcome, SimDoubleError> {
        self.advance_scripted_quantum_inner(horizon, send_authorizer)
    }

    fn advance_scripted_quantum_inner(
        &mut self,
        horizon: ExecutionHorizon,
        send_authorizer: &dyn SchedulerSendAuthorizer,
    ) -> Result<AdvanceOutcome, SimDoubleError> {
        self.control_lifecycle
            .observe(ControlLifecycleEvent::RunViaSharedMemory)?;
        let current_icount = self.backend.state().icount.retired;
        self.drain_deliverable_inbound_frames(current_icount)?;

        let step = self
            .script
            .candidate(current_icount, horizon.icount.retired);
        let script_target_icount = current_icount
            .saturating_add(step.instruction_budget)
            .min(horizon.icount.retired);
        let earliest_inbound = self
            .shmem
            .earliest_inbound_delivery_key(self.slot_index)?
            .map(|key| key.delivery_icount);
        let target_icount = match earliest_inbound {
            Some(delivery_icount) if delivery_icount <= script_target_icount => delivery_icount,
            _ => script_target_icount,
        };
        let ceiling =
            authorize_sim_double_delivery_ceiling(current_icount, target_icount, earliest_inbound)?;
        self.publish_ceiling_and_reached_icount(ceiling, target_icount)?;
        self.backend.advance_to_horizon(ExecutionHorizon {
            icount: Icount {
                retired: target_icount,
            },
        })?;
        let outcome = if target_icount == horizon.icount.retired {
            AdvanceOutcome::ReachedHorizon
        } else {
            AdvanceOutcome::Paused {
                at: Icount {
                    retired: target_icount,
                },
            }
        };
        self.host_observable_schedule
            .push(SimDoubleHostScheduleEvent::HorizonAdvance {
                from_icount: current_icount,
                requested_icount: horizon.icount.retired,
                reached_icount: target_icount,
                outcome,
            });
        self.drain_deliverable_inbound_frames(target_icount)?;
        let reached_script_target = target_icount == script_target_icount;
        if reached_script_target {
            self.script.consume_candidate();
            for outbound in step.outbound_frames {
                self.enqueue_outbound_frame(outbound, send_authorizer)?;
            }
        }
        Ok(outcome)
    }

    /// Computes the deterministic synthetic execution fingerprint.
    ///
    /// The hash covers the scripted backend state, the ordered control events,
    /// delivered frames, synthetic registers, synthetic memory, and the current
    /// shared-memory slot snapshot.
    pub fn synthetic_fingerprint(&self) -> ExecutionFingerprint {
        let mut hasher = StableHasher::new();
        let backend_hash = self.backend.state().fingerprint();
        hasher.write_tag("crucible.sim-double.synthetic-fingerprint.v1");
        hasher.write_bytes(&backend_hash.bytes);
        hasher.write_u64(u64::from(self.slot_index));
        hasher.write_u64(self.backend.state().icount.retired);
        hasher.write_u64(self.control_events.len() as u64);
        for event in &self.control_events {
            match event {
                SimDoubleControlEvent::HelloAck {
                    proto_version,
                    abi_version,
                    slot_index,
                    node_count,
                } => {
                    hasher.write_tag("hello-ack");
                    hasher.write_u64(u64::from(*proto_version));
                    hasher.write_u64(u64::from(*abi_version));
                    hasher.write_u64(u64::from(*slot_index));
                    hasher.write_u64(u64::from(*node_count));
                }
                SimDoubleControlEvent::Setup { region_len } => {
                    hasher.write_tag("setup");
                    hasher.write_u64(*region_len);
                }
                SimDoubleControlEvent::Quit => hasher.write_tag("quit"),
            }
        }
        hasher.write_u64(self.delivered_frames.len() as u64);
        for frame in &self.delivered_frames {
            hasher.write_tag("delivered-frame");
            hasher.write_u64(u64::from(frame.src_slot));
            hasher.write_u64(u64::from(frame.sequence));
            hasher.write_u64(frame.delivery_icount);
            hasher.write_bytes(&frame.payload);
        }
        for register in self.synthetic_register_file() {
            hasher.write_tag("register");
            hasher.write_u64(register);
        }
        hasher.write_bytes(&self.synthetic_memory_region());
        let slot = self.shmem.slot(self.slot_index);
        hasher.write_u64(slot.current_icount);
        hasher.write_u64(slot.current_ns);
        hasher.write_u64(slot.max_advance_icount);
        hasher.write_u64(u64::from(slot.status));
        hasher.write_u64(u64::from(slot.kind));
        ExecutionFingerprint {
            hash: ContentHash {
                bytes: hasher.finish().bytes,
            },
        }
    }

    /// Returns the synthetic register file used by [`Self::synthetic_fingerprint`].
    #[must_use]
    pub fn synthetic_register_file(&self) -> [u64; 4] {
        let icount = self.backend.state().icount.retired;
        [
            icount,
            self.delivered_frames.len() as u64,
            self.control_events.len() as u64,
            u64::from(self.next_outbound_sequence),
        ]
    }

    /// Returns the synthetic memory region used by [`Self::synthetic_fingerprint`].
    #[must_use]
    pub fn synthetic_memory_region(&self) -> [u8; 32] {
        let fingerprint = self.backend.state().fingerprint();
        let mut memory = fingerprint.bytes;
        for (index, byte) in memory.iter_mut().enumerate() {
            *byte ^= self
                .delivered_frames
                .get(index % self.delivered_frames.len().max(1))
                .and_then(|frame| frame.payload.get(index % frame.payload.len().max(1)))
                .copied()
                .unwrap_or(0);
        }
        memory
    }

    fn snapshot_state(&self) -> SimDoubleSnapshotState {
        SimDoubleSnapshotState {
            backend: self.backend.clone(),
            shmem: self.shmem.clone(),
            script: self.script.clone(),
            control_lifecycle: self.control_lifecycle.clone(),
            next_outbound_sequence: self.next_outbound_sequence,
            next_inbound_sequence_by_source: self.next_inbound_sequence_by_source.clone(),
            delivered_frames: self.delivered_frames.clone(),
            control_events: self.control_events.clone(),
            host_observable_schedule: self.host_observable_schedule.clone(),
        }
    }

    fn restore_snapshot_state(&mut self, state: &SimDoubleSnapshotState) {
        self.backend = state.backend.clone();
        self.shmem = state.shmem.clone();
        self.script = state.script.clone();
        self.control_lifecycle = state.control_lifecycle.clone();
        self.next_outbound_sequence = state.next_outbound_sequence;
        self.next_inbound_sequence_by_source = state.next_inbound_sequence_by_source.clone();
        self.delivered_frames = state.delivered_frames.clone();
        self.control_events = state.control_events.clone();
        self.host_observable_schedule = state.host_observable_schedule.clone();
    }

    fn simulation_checkpoint(&self) -> Checkpoint {
        let mut hasher = StableHasher::new();
        let fingerprint = self.synthetic_fingerprint();
        hasher.write_tag("crucible.sim-double.checkpoint.v1");
        hasher.write_bytes(&fingerprint.hash.bytes);
        hasher.write_u64(self.backend.state().icount.retired);
        hasher.write_u64(self.script.next_step as u64);
        hasher.write_u64(u64::from(self.next_outbound_sequence));
        hasher.write_u64(self.next_inbound_sequence_by_source.len() as u64);
        for (source, sequence) in &self.next_inbound_sequence_by_source {
            hasher.write_u64(u64::from(*source));
            hasher.write_u64(u64::from(*sequence));
        }
        hasher.write_u64(self.delivered_frames.len() as u64);
        hasher.write_u64(self.control_events.len() as u64);
        hasher.write_u64(self.host_observable_schedule.len() as u64);
        let id = ContentHash {
            bytes: hasher.finish().bytes,
        };
        let mut checkpoint = Checkpoint::new(id, fingerprint.hash, CheckpointKind::Fat);
        checkpoint.virtual_time = VirtualTime {
            ticks: self.backend.state().icount.retired,
        };
        checkpoint.node_icounts.insert(
            NodeId {
                name: format!("slot-{}", self.slot_index),
            },
            self.backend.state().icount,
        );
        checkpoint
    }

    fn publish_ceiling_and_reached_icount(
        &self,
        ceiling: AdvanceCeiling,
        reached_icount: u64,
    ) -> Result<(), SimDoubleError> {
        let slot = self.shmem.node_slot(self.slot_index)?;
        slot.publish_scheduler_ceiling(ceiling)?;
        slot.publish_reached_icount(reached_icount, self.icount_shift)?;
        Ok(())
    }

    fn drain_deliverable_inbound_frames(
        &mut self,
        current_icount: u64,
    ) -> Result<(), SimDoubleError> {
        while let Some(src_slot) = self.next_deliverable_source(current_icount)? {
            let Some(frame) = self
                .shmem
                .dequeue_directed_frame(src_slot, self.slot_index)?
            else {
                break;
            };
            let payload = frame.payload()?.to_vec();
            let delivered = SimDeliveredFrame {
                src_slot: frame.src_node,
                sequence: frame.seq,
                delivery_icount: frame.delivery_icount,
                payload: payload.clone(),
            };
            self.backend.deliver_input(BackendInput {
                node: NodeId {
                    name: format!("slot-{}", self.slot_index),
                },
                payload,
            })?;
            self.host_observable_schedule
                .push(SimDoubleHostScheduleEvent::FrameDelivery {
                    src_slot: delivered.src_slot,
                    sequence: delivered.sequence,
                    delivery_icount: delivered.delivery_icount,
                    payload: delivered.payload.clone(),
                });
            self.delivered_frames.push(delivered);
        }
        Ok(())
    }

    fn next_deliverable_source(&self, current_icount: u64) -> Result<Option<u32>, SimDoubleError> {
        let mut next = None;
        for src_slot in self.shmem.inbound_sources(self.slot_index) {
            let Some(frame) = self.shmem.peek_directed_frame(src_slot, self.slot_index)? else {
                continue;
            };
            if !frame.is_deliverable_at(current_icount) {
                continue;
            }
            let key = frame.delivery_key();
            if next
                .map(|(_src_slot, next_key): (u32, FrameDeliveryKey)| key < next_key)
                .unwrap_or(true)
            {
                next = Some((src_slot, key));
            }
        }
        Ok(next.map(|(src_slot, _key)| src_slot))
    }

    fn enqueue_outbound_frame(
        &mut self,
        outbound: SimOutboundFrame,
        send_authorizer: &dyn SchedulerSendAuthorizer,
    ) -> Result<(), SimDoubleError> {
        let SimOutboundFrame {
            dst_slot,
            delivery_icount,
            payload,
        } = outbound;
        let producer = sim_scheduler_node_for_slot(self.slot_index);
        let consumer = sim_scheduler_node_for_slot(dst_slot);
        send_authorizer.authorize_cross_node_send(&producer, &consumer)?;

        let sequence = self.next_outbound_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(SimDoubleError::OutboundSequenceOverflow { sequence })?;
        let frame = FrameEntry::new(delivery_icount, self.slot_index, sequence, &payload)?;
        self.shmem
            .enqueue_directed_frame(self.slot_index, dst_slot, &frame)?;
        self.next_outbound_sequence = next_sequence;
        self.host_observable_schedule
            .push(SimDoubleHostScheduleEvent::FrameEmission {
                dst_slot,
                sequence,
                delivery_icount,
                payload,
            });
        Ok(())
    }
}

impl SimulationBackend for SimDouble {
    fn step_to(&mut self, ceiling: VirtualTime) -> Result<StepObservation, BackendError> {
        let outcome = self
            .advance_scripted_quantum(
                ExecutionHorizon {
                    icount: Icount {
                        retired: ceiling.ticks,
                    },
                },
                &RejectingSimulationBackendSends,
            )
            .map_err(|source| BackendError::Rejected {
                message: source.to_string(),
            })?;
        Ok(StepObservation::from_advance_outcome(ceiling, outcome))
    }

    fn apply(&mut self, effect: &BackendEffect, at: VirtualTime) -> Result<(), BackendError> {
        let now = self.now();
        if at != now {
            return Err(BackendError::Rejected {
                message: format!(
                    "sim double backend effect at {} does not match scheduler time {}",
                    at.ticks, now.ticks
                ),
            });
        }
        match effect {
            BackendEffect::Noop => Ok(()),
            BackendEffect::DeliverInput(input) => self.backend.deliver_input(input.clone()),
            BackendEffect::Shutdown => Backend::shutdown(&mut self.backend),
        }
    }

    fn snapshot(&mut self) -> Result<BackendSnapshot, BackendError> {
        let checkpoint = self.simulation_checkpoint();
        self.snapshots.insert(checkpoint.id, self.snapshot_state());
        Ok(BackendSnapshot::new(checkpoint))
    }

    fn restore(&mut self, snapshot: &BackendSnapshot) -> Result<(), BackendError> {
        let Some(state) = self.snapshots.get(&snapshot.checkpoint.id).cloned() else {
            return Err(BackendError::Rejected {
                message: String::from("sim double cannot restore unknown snapshot"),
            });
        };
        self.restore_snapshot_state(&state);
        Ok(())
    }

    fn now(&self) -> VirtualTime {
        VirtualTime {
            ticks: self.backend.state().icount.retired,
        }
    }

    fn fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, BackendError> {
        Ok(FingerprintSample {
            node,
            at: self.now(),
            fingerprint: self.synthetic_fingerprint(),
        })
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, BackendError> {
        let _ = node;
        let _ = listen;
        Err(BackendError::Unsupported {
            capability: "open_gdbstub",
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Backend::shutdown(&mut self.backend)
    }
}

struct RejectingSimulationBackendSends;

impl SchedulerSendAuthorizer for RejectingSimulationBackendSends {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<crate::SchedulerSendAuthorization, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "simulation backend trait step lacks scheduler send authorization for {} -> {}",
                producer.node.name, consumer.node.name
            ),
        })
    }
}

/// Error returned by [`SimDouble`] operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SimDoubleError {
    /// Requested shared-memory slot is outside the configured VM node range.
    #[error("sim double slot {slot_index} is outside VM node range 0..{vm_node_count}")]
    SlotOutOfRange {
        /// Requested slot.
        slot_index: u32,
        /// Configured VM node count.
        vm_node_count: u32,
    },
    /// Shared-memory region geometry is invalid.
    #[error("sim double shared-memory region is invalid")]
    RegionLayout {
        /// Underlying layout error.
        #[from]
        source: RegionLayoutError,
    },
    /// A host control frame could not be decoded.
    #[error("sim double control frame decode failed")]
    ControlFrame {
        /// Underlying protocol frame decode error.
        #[from]
        source: FrameDecodeError,
    },
    /// The host/plugin handshake failed shared protocol validation.
    #[error("sim double control handshake failed")]
    Handshake {
        /// Underlying handshake validation error.
        #[from]
        source: HandshakeError,
    },
    /// A control frame violated the shared lifecycle state machine.
    #[error("sim double control lifecycle violation")]
    ControlLifecycle {
        /// Underlying lifecycle validation error.
        #[from]
        source: ControlLifecycleError,
    },
    /// Host assigned a slot that does not match this double.
    #[error("sim double expected slot {expected}, got {actual}")]
    SlotMismatch {
        /// Expected slot.
        expected: u32,
        /// Actual slot.
        actual: u32,
    },
    /// Host advertised a different node count than the shmem region.
    #[error("sim double expected node count {expected}, got {actual}")]
    NodeCountMismatch {
        /// Expected node count.
        expected: u32,
        /// Actual node count.
        actual: u32,
    },
    /// The shared-memory setup header failed ABI validation.
    #[error("sim double setup region validation failed")]
    SetupRegion {
        /// Underlying setup-region validation error.
        #[from]
        source: RegionSetupValidationError,
    },
    /// A frame payload was invalid for the shared-memory ABI.
    #[error("sim double frame entry is invalid")]
    FrameEntry {
        /// Underlying frame-entry error.
        #[from]
        source: FrameEntryError,
    },
    /// Access to the typed shared-memory allocation failed.
    #[error("sim double shared-memory region access failed")]
    RegionAccess {
        /// Underlying region-allocation access error.
        #[from]
        source: RegionAllocationAccessError,
    },
    /// A node slot publish failed.
    #[error("sim double node slot publish failed")]
    NodeSlot {
        /// Underlying node-slot error.
        #[from]
        source: NodeSlotError,
    },
    /// The outbound frame stream exhausted its real plugin sequence range.
    #[error("sim double outbound sequence overflow at {sequence}")]
    OutboundSequenceOverflow {
        /// The sequence value that could not be advanced.
        sequence: u32,
    },
    /// The lookahead ceiling rejected an advance.
    #[error("sim double advance ceiling rejected the requested horizon")]
    Lookahead {
        /// Underlying lookahead-gate error.
        #[from]
        source: crucible_shmem::LookaheadGateError,
    },
    /// The scheduler rejected a cross-node send under the current topology.
    #[error("sim double scheduler send authorization failed: {source}")]
    SchedulerSendAuthorization {
        /// Underlying scheduler authorization error.
        #[from]
        source: SchedulerError,
    },
    /// The backend rejected an operation.
    #[error("sim double backend operation failed")]
    Backend {
        /// Underlying backend error.
        #[from]
        source: BackendError,
    },
}

fn sim_scheduler_node_for_slot(slot: u32) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: format!("slot-{slot}"),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

#[derive(Clone)]
struct SimDoubleShmem {
    allocation: RegionAllocation,
}

impl SimDoubleShmem {
    fn new(config: RegionConfig) -> Result<Self, RegionLayoutError> {
        Ok(Self {
            allocation: RegionAllocation::new_model(config)?,
        })
    }

    fn layout(&self) -> RegionLayout {
        self.allocation.layout()
    }

    fn header_snapshot(&self) -> RegionHeaderSnapshot {
        self.allocation.header().snapshot()
    }

    fn node_slot(&self, slot_index: u32) -> Result<&crucible_shmem::NodeSlot, SimDoubleError> {
        self.allocation
            .node_slot(slot_index)
            .ok_or(SimDoubleError::SlotOutOfRange {
                slot_index,
                vm_node_count: self.layout().vm_node_count,
            })
    }

    fn slot(&self, slot_index: u32) -> crucible_shmem::NodeSlotSnapshot {
        self.allocation
            .node_slot(slot_index)
            .map(crucible_shmem::NodeSlot::snapshot)
            .unwrap_or_else(|| crucible_shmem::NodeSlot::default().snapshot())
    }

    fn inbound_sources(&self, dst_slot: u32) -> Vec<u32> {
        self.allocation
            .rings()
            .iter()
            .filter(|ring| ring.dst_slot == dst_slot)
            .map(|ring| ring.src_slot)
            .collect()
    }

    fn enqueue_directed_frame(
        &mut self,
        src_slot: u32,
        dst_slot: u32,
        frame: &FrameEntry,
    ) -> Result<(), SimDoubleError> {
        Ok(self
            .allocation
            .enqueue_directed_frame(src_slot, dst_slot, frame)?)
    }

    fn peek_directed_frame(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<FrameEntry>, SimDoubleError> {
        Ok(self.allocation.peek_directed_frame(src_slot, dst_slot)?)
    }

    fn dequeue_directed_frame(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<FrameEntry>, SimDoubleError> {
        Ok(self.allocation.dequeue_directed_frame(src_slot, dst_slot)?)
    }

    fn earliest_inbound_delivery_key(
        &self,
        dst_slot: u32,
    ) -> Result<Option<FrameDeliveryKey>, SimDoubleError> {
        let mut earliest = None;
        for src_slot in self.inbound_sources(dst_slot) {
            let Some(frame) = self.peek_directed_frame(src_slot, dst_slot)? else {
                continue;
            };
            let key = frame.delivery_key();
            if earliest
                .map(|current: FrameDeliveryKey| key < current)
                .unwrap_or(true)
            {
                earliest = Some(key);
            }
        }
        Ok(earliest)
    }
}

fn authorize_sim_double_delivery_ceiling(
    current_icount: u64,
    max_advance_icount: u64,
    earliest_possible_delivery_icount: Option<u64>,
) -> Result<AdvanceCeiling, crucible_shmem::LookaheadGateError> {
    if earliest_possible_delivery_icount == Some(max_advance_icount) {
        authorize_advance_ceiling(current_icount, max_advance_icount, None)
    } else {
        authorize_advance_ceiling(
            current_icount,
            max_advance_icount,
            earliest_possible_delivery_icount,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeId;

    static ALLOW_ALL_SENDS: AllowAllSchedulerSendAuthorizer = AllowAllSchedulerSendAuthorizer;

    struct AllowAllSchedulerSendAuthorizer;

    impl SchedulerSendAuthorizer for AllowAllSchedulerSendAuthorizer {
        fn authorize_cross_node_send(
            &self,
            producer: &SchedulerNodeId,
            consumer: &SchedulerNodeId,
        ) -> Result<crate::SchedulerSendAuthorization, SchedulerError> {
            Ok(crate::SchedulerSendAuthorization {
                producer: producer.clone(),
                consumer: consumer.clone(),
                topology_epoch: 0,
            })
        }
    }

    #[test]
    fn sim_backend_advances_and_fingerprints_deterministically() {
        let mut first = SimBackend::new();
        let mut second = SimBackend::new();
        let input = BackendInput {
            node: NodeId {
                name: String::from("node-a"),
            },
            payload: b"hello".to_vec(),
        };

        assert_eq!(first.deliver_input(input.clone()), Ok(()));
        assert_eq!(second.deliver_input(input), Ok(()));
        assert_eq!(
            first.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 25 },
            }),
            Ok(AdvanceOutcome::ReachedHorizon)
        );
        assert_eq!(
            second.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 25 },
            }),
            Ok(AdvanceOutcome::ReachedHorizon)
        );

        assert_eq!(
            Backend::fingerprint(&mut first),
            Backend::fingerprint(&mut second)
        );
    }

    #[test]
    fn sim_backend_snapshots_and_restores_small_state() {
        let mut backend = SimBackend::new();
        assert_eq!(
            backend.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 7 },
            }),
            Ok(AdvanceOutcome::ReachedHorizon)
        );
        let checkpoint = match Backend::snapshot(&mut backend) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("snapshot should succeed: {error}"),
        };
        assert!(matches!(
            checkpoint.node_blob(&NodeId {
                name: String::from("sim"),
            }),
            Some(NodeBlobRef::CowDelta { .. })
        ));
        assert_eq!(
            backend.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 9 },
            }),
            Ok(AdvanceOutcome::ReachedHorizon)
        );

        assert_eq!(Backend::restore(&mut backend, &checkpoint), Ok(()));

        assert_eq!(backend.state().icount, Icount { retired: 7 });
    }

    #[test]
    fn sim_backend_rejects_backward_advance_and_post_shutdown_mutation() {
        let mut backend = SimBackend::from_state(SimBackendState {
            icount: Icount { retired: 9 },
            delivered_inputs: Vec::new(),
            shutdown: false,
        });

        assert!(matches!(
            backend.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 8 },
            }),
            Err(BackendError::Rejected { .. })
        ));
        assert_eq!(Backend::shutdown(&mut backend), Ok(()));
        assert!(matches!(
            backend.advance_to_horizon(ExecutionHorizon {
                icount: Icount { retired: 10 },
            }),
            Err(BackendError::Rejected { message }) if message == "sim backend is shut down; cannot advance"
        ));
        assert!(matches!(
            backend.deliver_input(BackendInput {
                node: NodeId {
                    name: String::from("node-a"),
                },
                payload: Vec::new(),
            }),
            Err(BackendError::Rejected { .. })
        ));
    }

    #[test]
    fn sim_backend_rejects_unknown_checkpoint_deterministically() {
        let mut backend = SimBackend::new();
        let unknown = Checkpoint::new(
            ContentHash { bytes: [7; 32] },
            ContentHash::default(),
            CheckpointKind::Fat,
        );

        assert!(matches!(
            Backend::restore(&mut backend, &unknown),
            Err(BackendError::Rejected { message }) if message == "sim backend cannot restore unknown checkpoint"
        ));
    }

    #[test]
    fn sim_backend_restorable_checkpoint_constructor_seeds_restore() {
        let mut unknown = Checkpoint::new(
            ContentHash { bytes: [7; 32] },
            ContentHash::default(),
            CheckpointKind::Fat,
        );
        unknown.virtual_time = VirtualTime { ticks: 3 };
        unknown.node_icounts.insert(
            NodeId {
                name: String::from("node-a"),
            },
            Icount { retired: 11 },
        );
        let mut backend = SimBackend::from_restorable_checkpoint(&unknown);

        assert_eq!(Backend::restore(&mut backend, &unknown), Ok(()));
        assert_eq!(backend.state().icount, Icount { retired: 11 });
    }

    #[test]
    fn sim_backend_satisfies_simulation_backend_trait() {
        let mut backend = SimBackend::new();
        let ceiling = VirtualTime { ticks: 13 };

        let observation = match SimulationBackend::step_to(&mut backend, ceiling) {
            Ok(observation) => observation,
            Err(error) => panic!("sim backend should advance through trait: {error}"),
        };
        assert_eq!(observation.reached, ceiling);
        assert_eq!(SimulationBackend::now(&backend), ceiling);

        assert!(matches!(
            SimulationBackend::apply(
                &mut backend,
                &BackendEffect::Noop,
                VirtualTime { ticks: ceiling.ticks - 1 },
            ),
            Err(BackendError::Rejected { message })
                if message.contains("does not match scheduler time")
        ));
        if let Err(error) = SimulationBackend::apply(
            &mut backend,
            &BackendEffect::DeliverInput(BackendInput {
                node: NodeId {
                    name: String::from("node-a"),
                },
                payload: b"input".to_vec(),
            }),
            ceiling,
        ) {
            panic!("sim backend should accept delivered input through trait: {error}");
        }
        let snapshot = match SimulationBackend::snapshot(&mut backend) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("sim backend should snapshot through trait: {error}"),
        };
        if let Err(error) = SimulationBackend::step_to(&mut backend, VirtualTime { ticks: 21 }) {
            panic!("sim backend should advance after snapshot: {error}");
        }
        if let Err(error) = SimulationBackend::restore(&mut backend, &snapshot) {
            panic!("sim backend should restore through trait: {error}");
        }
        assert_eq!(SimulationBackend::now(&backend), ceiling);
        let sample = match SimulationBackend::fingerprint(
            &mut backend,
            NodeId {
                name: String::from("node-a"),
            },
        ) {
            Ok(sample) => sample,
            Err(error) => panic!("sim backend should fingerprint through trait: {error}"),
        };
        assert_eq!(sample.at, ceiling);
    }

    #[test]
    fn sim_double_rejects_gdbstub_capability_with_typed_error() {
        let mut double = match SimDouble::new(SimDoubleConfig::default()) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        let listen = match GdbListen::new("127.0.0.1:9000") {
            Ok(listen) => listen,
            Err(error) => panic!("test listen endpoint should be valid: {error}"),
        };
        let error = SimulationBackend::open_gdbstub(
            &mut double,
            NodeId {
                name: String::from("node-a"),
            },
            listen,
        )
        .expect_err("SimDouble must not fake a gdbstub");

        assert_eq!(
            error,
            BackendError::Unsupported {
                capability: "open_gdbstub",
            }
        );
    }

    #[test]
    fn sim_double_speaks_real_control_protocol_lifecycle() {
        let mut double = match SimDouble::new(SimDoubleConfig::default()) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        let hello = match crucible_protocol::control_decode_plugin_msg(&double.plugin_hello_frame())
        {
            Ok(hello) => hello,
            Err(error) => panic!("sim double hello should decode: {error}"),
        };

        assert_eq!(
            hello,
            PluginMsg::Hello {
                proto_version: CONTROL_PROTOCOL_VERSION,
                abi_version: ABI_VERSION,
            }
        );

        let hello_ack = crucible_protocol::control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index: 0,
            node_count: double.shmem_layout().node_count,
        });
        assert_eq!(double.accept_host_control_frame(&hello_ack), Ok(None));

        let setup = crucible_protocol::control_encode_host_msg(&HostMsg::Setup {
            region_len: double.shmem_layout().region_size,
        });
        let setup_ack = match double.accept_host_control_frame(&setup) {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!("setup should produce a SetupAck frame"),
            Err(error) => panic!("setup should succeed: {error}"),
        };
        let decoded_setup_ack = match crucible_protocol::control_decode_plugin_msg(&setup_ack) {
            Ok(message) => message,
            Err(error) => panic!("setup ack should decode: {error}"),
        };

        assert_eq!(
            decoded_setup_ack,
            PluginMsg::SetupAck {
                status: SETUP_ACK_STATUS_READY,
            }
        );
        assert_eq!(double.control_events().len(), 2);
        assert_eq!(double.shmem_header_snapshot().abi_version, ABI_VERSION);
        assert_eq!(
            double.shmem_header_snapshot().region_size,
            double.shmem_layout().region_size
        );
    }

    #[test]
    fn sim_double_runs_script_through_real_spsc_ring_and_fingerprint() {
        let script = SimInstructionScript::new(vec![SimInstructionStep {
            instruction_budget: 5,
            outbound_frames: vec![SimOutboundFrame {
                dst_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
                delivery_icount: 5,
                payload: b"guest-to-router".to_vec(),
            }],
        }]);
        let config = SimDoubleConfig {
            script,
            ..SimDoubleConfig::default()
        };
        let mut first = match SimDouble::new(config.clone()) {
            Ok(double) => double,
            Err(error) => panic!("first sim double should construct: {error}"),
        };
        let mut second = match SimDouble::new(config) {
            Ok(double) => double,
            Err(error) => panic!("second sim double should construct: {error}"),
        };

        for double in [&mut first, &mut second] {
            complete_sim_double_setup(double);
            if let Err(error) = double.enqueue_inbound_frame(
                crucible_shmem::SLOT_NET_ROUTER as u32,
                5,
                b"router-to-guest",
            ) {
                panic!("inbound frame should enqueue: {error}");
            }
            assert_eq!(
                double.advance_scripted_quantum(
                    ExecutionHorizon {
                        icount: Icount { retired: 10 },
                    },
                    &ALLOW_ALL_SENDS
                ),
                Ok(AdvanceOutcome::Paused {
                    at: Icount { retired: 5 },
                })
            );
            assert_eq!(double.backend_state().icount, Icount { retired: 5 });
            assert_eq!(double.delivered_frames().len(), 1);
            assert_eq!(double.delivered_frames()[0].payload, b"router-to-guest");
            assert_eq!(
                double.synthetic_register_file(),
                [5, 1, 2, 1],
                "synthetic register file should be a pure function of script state"
            );
        }

        assert_eq!(
            first.synthetic_fingerprint(),
            second.synthetic_fingerprint()
        );
    }

    #[test]
    fn sim_double_rejects_bad_protocol_and_region_shape() {
        let mut double = match SimDouble::new(SimDoubleConfig::default()) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        let bad_version = crucible_protocol::control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: CONTROL_PROTOCOL_VERSION + 1,
            abi_version: ABI_VERSION,
            slot_index: 0,
            node_count: double.shmem_layout().node_count,
        });
        assert!(matches!(
            double.accept_host_control_frame(&bad_version),
            Err(SimDoubleError::Handshake {
                source: HandshakeError::NegotiatedProtocolOutOfRange { .. },
            })
        ));

        let mut double = match SimDouble::new(SimDoubleConfig::default()) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        accept_hello_ack(&mut double);
        let setup = crucible_protocol::control_encode_host_msg(&HostMsg::Setup {
            region_len: double.shmem_layout().region_size + 1,
        });
        assert!(matches!(
            double.accept_host_control_frame(&setup),
            Err(SimDoubleError::SetupRegion {
                source: RegionSetupValidationError::RegionLengthMismatch { .. },
            })
        ));

        assert!(matches!(
            SimDouble::new(SimDoubleConfig {
                slot_index: 1,
                ..SimDoubleConfig::default()
            }),
            Err(SimDoubleError::SlotOutOfRange { .. })
        ));
    }

    #[test]
    fn sim_double_rejects_out_of_order_control_lifecycle() {
        let mut double = match SimDouble::new(SimDoubleConfig::default()) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        let setup = crucible_protocol::control_encode_host_msg(&HostMsg::Setup {
            region_len: double.shmem_layout().region_size,
        });

        assert!(matches!(
            double.accept_host_control_frame(&setup),
            Err(SimDoubleError::ControlLifecycle {
                source: ControlLifecycleError::UnexpectedEvent { .. },
            })
        ));
    }

    #[test]
    fn sim_double_does_not_advance_past_pending_inbound_delivery() {
        let script = SimInstructionScript::new(vec![SimInstructionStep::budget(8)]);
        let mut double = match SimDouble::new(SimDoubleConfig {
            script,
            ..SimDoubleConfig::default()
        }) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        complete_sim_double_setup(&mut double);

        if let Err(error) =
            double.enqueue_inbound_frame(crucible_shmem::SLOT_NET_ROUTER as u32, 4, b"due")
        {
            panic!("inbound frame should enqueue: {error}");
        }

        assert_eq!(
            double.advance_scripted_quantum(
                ExecutionHorizon {
                    icount: Icount { retired: 10 },
                },
                &ALLOW_ALL_SENDS
            ),
            Ok(AdvanceOutcome::Paused {
                at: Icount { retired: 4 },
            })
        );
        assert_eq!(double.backend_state().icount, Icount { retired: 4 });
        assert_eq!(double.delivered_frames()[0].delivery_icount, 4);
    }

    #[test]
    fn sim_double_delivers_inbound_frames_by_canonical_key() {
        let mut double = match SimDouble::new(SimDoubleConfig {
            script: SimInstructionScript::new(vec![SimInstructionStep::budget(5)]),
            ..SimDoubleConfig::default()
        }) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        complete_sim_double_setup(&mut double);

        for (src_slot, payload) in [
            (crucible_shmem::SLOT_NET_ROUTER as u32, b"net".as_slice()),
            (crucible_shmem::SLOT_BLK_IO as u32, b"blk".as_slice()),
            (crucible_shmem::SLOT_9P_IO as u32, b"ninep".as_slice()),
        ] {
            if let Err(error) = double.enqueue_inbound_frame_with_sequence(src_slot, 0, 5, payload)
            {
                panic!("inbound frame should enqueue: {error}");
            }
        }

        assert_eq!(
            double.advance_scripted_quantum(
                ExecutionHorizon {
                    icount: Icount { retired: 5 },
                },
                &ALLOW_ALL_SENDS
            ),
            Ok(AdvanceOutcome::ReachedHorizon)
        );
        let payloads = double
            .delivered_frames()
            .iter()
            .map(|frame| frame.payload.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(
            payloads,
            vec![b"ninep".as_slice(), b"blk".as_slice(), b"net".as_slice()]
        );
    }

    #[test]
    fn sim_double_rejects_outbound_sequence_overflow_like_real_plugin_tx() {
        let mut double = match SimDouble::new(SimDoubleConfig {
            script: SimInstructionScript::new(vec![SimInstructionStep {
                instruction_budget: 1,
                outbound_frames: vec![SimOutboundFrame {
                    dst_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
                    delivery_icount: 1,
                    payload: b"overflow".to_vec(),
                }],
            }]),
            ..SimDoubleConfig::default()
        }) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        complete_sim_double_setup(&mut double);
        double.next_outbound_sequence = u32::MAX;

        assert_eq!(
            double.advance_scripted_quantum(
                ExecutionHorizon {
                    icount: Icount { retired: 1 },
                },
                &ALLOW_ALL_SENDS
            ),
            Err(SimDoubleError::OutboundSequenceOverflow { sequence: u32::MAX })
        );
        assert_eq!(double.next_outbound_sequence, u32::MAX);
        assert!(
            !double
                .host_observable_schedule()
                .iter()
                .any(|event| matches!(event, SimDoubleHostScheduleEvent::FrameEmission { .. }))
        );
    }

    #[test]
    fn sim_double_outbound_enqueue_uses_scheduler_send_authorizer() {
        let mut double = match SimDouble::new(SimDoubleConfig {
            script: SimInstructionScript::new(vec![SimInstructionStep {
                instruction_budget: 1,
                outbound_frames: vec![SimOutboundFrame {
                    dst_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
                    delivery_icount: 1,
                    payload: b"frozen".to_vec(),
                }],
            }]),
            ..SimDoubleConfig::default()
        }) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        complete_sim_double_setup(&mut double);
        let scheduler = pending_sim_topology_scheduler();

        let result = double.advance_scripted_quantum(
            ExecutionHorizon {
                icount: Icount { retired: 1 },
            },
            &scheduler,
        );

        assert!(matches!(
            &result,
            Err(SimDoubleError::SchedulerSendAuthorization { .. })
        ));
        assert!(
            result
                .expect_err("send should be frozen")
                .to_string()
                .contains("cross-node sends frozen")
        );
        assert_eq!(double.next_outbound_sequence, 0);
        assert!(
            !double
                .host_observable_schedule()
                .iter()
                .any(|event| matches!(event, SimDoubleHostScheduleEvent::FrameEmission { .. }))
        );
    }

    #[test]
    fn sim_double_satisfies_simulation_backend_trait() {
        let mut double = match SimDouble::new(SimDoubleConfig {
            script: SimInstructionScript::new(vec![
                SimInstructionStep {
                    instruction_budget: 5,
                    outbound_frames: Vec::new(),
                },
                SimInstructionStep {
                    instruction_budget: 1,
                    outbound_frames: Vec::new(),
                },
                SimInstructionStep {
                    instruction_budget: 100,
                    outbound_frames: Vec::new(),
                },
            ]),
            ..SimDoubleConfig::default()
        }) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        complete_sim_double_setup(&mut double);
        let ceiling = VirtualTime { ticks: 5 };

        let observation = match SimulationBackend::step_to(&mut double, ceiling) {
            Ok(observation) => observation,
            Err(error) => panic!("sim double should advance through trait: {error}"),
        };

        assert_eq!(observation.reached, ceiling);
        assert_eq!(SimulationBackend::now(&double), ceiling);
        let sample = match SimulationBackend::fingerprint(
            &mut double,
            NodeId {
                name: String::from("slot-0"),
            },
        ) {
            Ok(sample) => sample,
            Err(error) => panic!("sim double should fingerprint through trait: {error}"),
        };
        assert_eq!(sample.node.name, "slot-0");
        assert_eq!(sample.at, ceiling);

        assert!(matches!(
            SimulationBackend::apply(
                &mut double,
                &BackendEffect::Noop,
                VirtualTime { ticks: ceiling.ticks - 1 },
            ),
            Err(BackendError::Rejected { message })
                if message.contains("does not match scheduler time")
        ));
        let snapshot = match SimulationBackend::snapshot(&mut double) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("sim double should snapshot through trait: {error}"),
        };
        if let Err(error) = SimulationBackend::step_to(&mut double, VirtualTime { ticks: 6 }) {
            panic!("sim double should advance after snapshot: {error}");
        }
        let advanced = match SimulationBackend::fingerprint(
            &mut double,
            NodeId {
                name: String::from("slot-0"),
            },
        ) {
            Ok(sample) => sample,
            Err(error) => panic!("sim double should fingerprint after advance: {error}"),
        };
        assert_ne!(advanced.fingerprint, sample.fingerprint);

        if let Err(error) = SimulationBackend::restore(&mut double, &snapshot) {
            panic!("sim double should restore through trait: {error}");
        }
        assert_eq!(SimulationBackend::now(&double), ceiling);
        let restored = match SimulationBackend::fingerprint(
            &mut double,
            NodeId {
                name: String::from("slot-0"),
            },
        ) {
            Ok(sample) => sample,
            Err(error) => panic!("sim double should fingerprint after restore: {error}"),
        };
        assert_eq!(restored.fingerprint, sample.fingerprint);

        let replayed_step = match SimulationBackend::step_to(&mut double, VirtualTime { ticks: 15 })
        {
            Ok(observation) => observation,
            Err(error) => panic!("sim double should replay restored script cursor: {error}"),
        };
        assert_eq!(replayed_step.reached, VirtualTime { ticks: 6 });
        assert!(matches!(
            replayed_step.outcome,
            AdvanceOutcome::Paused {
                at: Icount { retired: 6 },
            }
        ));
    }

    #[test]
    fn sim_double_simulation_backend_rejects_outbound_without_scheduler_authorization() {
        let mut double = match SimDouble::new(SimDoubleConfig {
            script: SimInstructionScript::new(vec![SimInstructionStep {
                instruction_budget: 1,
                outbound_frames: vec![SimOutboundFrame {
                    dst_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
                    delivery_icount: 3,
                    payload: b"blocked".to_vec(),
                }],
            }]),
            ..SimDoubleConfig::default()
        }) {
            Ok(double) => double,
            Err(error) => panic!("sim double should construct: {error}"),
        };
        complete_sim_double_setup(&mut double);

        let error = SimulationBackend::step_to(&mut double, VirtualTime { ticks: 1 })
            .expect_err("trait step must not authorize cross-node sends itself");

        assert!(
            error
                .to_string()
                .contains("lacks scheduler send authorization")
        );
        assert_eq!(double.next_outbound_sequence, 0);
        assert!(
            !double
                .host_observable_schedule()
                .iter()
                .any(|event| matches!(event, SimDoubleHostScheduleEvent::FrameEmission { .. }))
        );
    }

    fn pending_sim_topology_scheduler() -> crate::SingleScheduler {
        let producer = sim_scheduler_node_for_slot(0);
        let consumer = sim_scheduler_node_for_slot(crucible_shmem::SLOT_NET_ROUTER as u32);
        let scenario = crate::SchedulerLivenessScenario::from_canonical_material(
            "sim-double-send-freeze",
            crate::Shift::new(0).expect("test shift should be valid"),
            8,
            crate::SimInstant { nanos: 40 },
            vec![crate::SchedulerScenarioNode {
                id: producer.clone(),
                counter: crate::NodeCounter { ticks: 0 },
                activity: crate::SchedulerNodeActivity::Runnable,
                network_lookahead: crate::NetworkLookahead::Infinite,
                exact_local_event: crate::ExactLocalEvent::NoArmedTimer,
            }],
            Vec::new(),
        )
        .with_effective_topology_edges(vec![crate::SchedulerLookaheadEdge::new(
            producer.clone(),
            consumer.clone(),
            crate::SimDuration { nanos: 20 },
        )]);
        let mut scheduler = crate::SingleScheduler::new(scenario).expect("scenario should build");
        scheduler.queue_topology_change(crate::SchedulerTopologyChange::new(
            1,
            crate::SchedulerTopologyChangeTrigger::LatencyChange,
            vec![crate::SchedulerLookaheadEdge::new(
                producer,
                consumer,
                crate::SimDuration { nanos: 5 },
            )],
        ));
        scheduler
    }

    fn complete_sim_double_setup(double: &mut SimDouble) {
        accept_hello_ack(double);
        let setup = crucible_protocol::control_encode_host_msg(&HostMsg::Setup {
            region_len: double.shmem_layout().region_size,
        });
        match double.accept_host_control_frame(&setup) {
            Ok(Some(_setup_ack)) => {}
            Ok(None) => panic!("setup should produce a SetupAck frame"),
            Err(error) => panic!("setup should succeed: {error}"),
        }
    }

    fn accept_hello_ack(double: &mut SimDouble) {
        let hello_ack = crucible_protocol::control_encode_host_msg(&HostMsg::HelloAck {
            proto_version: CONTROL_PROTOCOL_VERSION,
            abi_version: ABI_VERSION,
            slot_index: 0,
            node_count: double.shmem_layout().node_count,
        });
        if let Err(error) = double.accept_host_control_frame(&hello_ack) {
            panic!("hello ack should succeed: {error}");
        }
    }
}
