//! World topology, device declarations, and the complete fault taxonomy.

use super::*;

/// A node identifier inside a scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId {
    /// The canonical node name.
    pub name: String,
}

/// A scheduler graph node, including VM nodes and deterministic I/O sub-nodes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulerNodeId {
    /// The scenario node that owns this scheduler node.
    pub node: NodeId,
    /// The kind of scheduler node.
    pub kind: SchedulingNodeKind,
}

/// The kind of node participating in the scheduler graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SchedulingNodeKind {
    /// A VM backend node.
    Vm,
    /// A deterministic disk sub-node.
    Disk,
    /// A deterministic 9p sub-node.
    NineP,
    /// A deterministic network-link sub-node.
    Network,
    /// The session actor boundary.
    ControlPlane,
}

/// A supported virtual-machine architecture for a spatial world node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VmArchitecture {
    /// x86-64 guest machine architecture.
    X86_64,
    /// AArch64 guest machine architecture.
    Aarch64,
}

impl VmArchitecture {
    pub(super) fn material(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// One node's model-level ready-point configuration inside a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorldNode {
    /// Stable node identity within the world.
    pub id: NodeId,
    /// Guest virtual-machine architecture.
    pub arch: VmArchitecture,
    /// Guest virtual-machine memory in MiB.
    pub memory_mib: u32,
    /// Guest kernel command line.
    pub cmdline: String,
    /// The deterministic point where this node reaches `t = 0`.
    pub ready_point: ReadyPoint,
    /// Whether this node opts into the white-box guest-host channel.
    pub white_box: WhiteBoxPolicy,
    /// Fixed QEMU vCPU count for this node.
    pub smp_vcpus: u16,
    /// Fixed QEMU icount shift for this node.
    pub icount_shift: u8,
    /// Optional content-addressed guest kernel blob.
    pub kernel: Option<ContentAddressedBlobRef>,
    /// Optional content-addressed read-only root-image blob.
    pub root_image: Option<ContentAddressedBlobRef>,
    /// Optional content-addressed initrd blob.
    pub initrd: Option<ContentAddressedBlobRef>,
}

/// The deterministic I/O family owned by a world-declared I/O sub-node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorldDeviceKind {
    /// A block-device sub-node.
    Block,
    /// A 9p filesystem sub-node.
    NineP,
}

/// Logical clock configuration shared by block and 9p I/O sub-nodes.
///
/// Completion-order source numbers and request/response ring capacities are
/// physical transport layout. They are deliberately absent from this World
/// value and are derived at instantiation time ([SPAT-14], [SPAT-15]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldIoCoreConfig {
    /// Fixed virtual-time clock shift owned by the I/O sub-node.
    pub shift_bits: u8,
}

impl WorldIoCoreConfig {
    /// Builds an explicit logical I/O clock configuration.
    #[must_use]
    pub const fn new(shift_bits: u8) -> Self {
        Self { shift_bits }
    }
}

/// Static deterministic block-completion latency parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldBlockLatency {
    /// Fixed read latency floor in virtual nanoseconds.
    pub read_base_ns: u64,
    /// Fixed write latency floor in virtual nanoseconds.
    pub write_base_ns: u64,
    /// Fixed flush latency in virtual nanoseconds.
    pub flush_ns: u64,
    /// Fixed get-length latency in virtual nanoseconds.
    pub get_length_ns: u64,
    /// Per-byte transfer cost in virtual nanoseconds.
    pub per_byte_ns: u64,
}

impl WorldBlockLatency {
    /// Builds explicit deterministic block latency parameters.
    #[must_use]
    pub const fn new(
        read_base_ns: u64,
        write_base_ns: u64,
        flush_ns: u64,
        get_length_ns: u64,
        per_byte_ns: u64,
    ) -> Self {
        Self {
            read_base_ns,
            write_base_ns,
            flush_ns,
            get_length_ns,
            per_byte_ns,
        }
    }
}

/// Static deterministic 9p-completion latency parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldNinePLatency {
    /// Fixed metadata/control-message latency in virtual nanoseconds.
    pub control_ns: u64,
    /// Fixed read/readdir latency in virtual nanoseconds.
    pub data_ns: u64,
    /// Per-frame-byte transfer cost in virtual nanoseconds.
    pub per_byte_ns: u64,
}

impl WorldNinePLatency {
    /// Builds explicit deterministic 9p latency parameters.
    #[must_use]
    pub const fn new(control_ns: u64, data_ns: u64, per_byte_ns: u64) -> Self {
        Self {
            control_ns,
            data_ns,
            per_byte_ns,
        }
    }
}

/// Kind-specific immutable artifact and latency configuration for an I/O node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorldIoNodeKind {
    /// A block sub-node over one immutable base image.
    Block {
        /// BLAKE3 address of the exact base-image bytes.
        base_image: ContentAddressedBlobRef,
        /// Exact base-image length in bytes.
        base_length: u64,
        /// Deterministic completion-latency parameters.
        latency: WorldBlockLatency,
    },
    /// A 9p sub-node over one canonical immutable filesystem tree.
    NineP {
        /// BLAKE3 address of the exact canonical [`crucible_device::FsTree`] bytes.
        tree: ContentAddressedBlobRef,
        /// Deterministic completion-latency parameters.
        latency: WorldNinePLatency,
    },
}

impl WorldIoNodeKind {
    /// Returns the fault-taxonomy family implemented by this I/O node.
    #[must_use]
    pub const fn family(&self) -> WorldDeviceKind {
        match self {
            Self::Block { .. } => WorldDeviceKind::Block,
            Self::NineP { .. } => WorldDeviceKind::NineP,
        }
    }
}

/// A first-class deterministic block or 9p scheduling node in a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldIoNode {
    /// Stable node identity, unique across every VM and I/O node in the world.
    pub id: NodeId,
    /// VM node that consumes this sub-node's completions.
    pub owner: NodeId,
    /// Logical scheduler-clock configuration.
    pub core: WorldIoCoreConfig,
    /// Kind-specific immutable artifact and latency configuration.
    pub kind: WorldIoNodeKind,
}

impl WorldIoNode {
    /// Builds a block I/O node over an immutable content-addressed base image.
    #[must_use]
    pub fn block(
        id: NodeId,
        owner: NodeId,
        core: WorldIoCoreConfig,
        base_image: ContentAddressedBlobRef,
        base_length: u64,
        latency: WorldBlockLatency,
    ) -> Self {
        Self {
            id,
            owner,
            core,
            kind: WorldIoNodeKind::Block {
                base_image,
                base_length,
                latency,
            },
        }
    }

    /// Builds a 9p I/O node over an immutable content-addressed filesystem tree.
    #[must_use]
    pub fn ninep(
        id: NodeId,
        owner: NodeId,
        core: WorldIoCoreConfig,
        tree: ContentAddressedBlobRef,
        latency: WorldNinePLatency,
    ) -> Self {
        Self {
            id,
            owner,
            core,
            kind: WorldIoNodeKind::NineP { tree, latency },
        }
    }

    /// Returns the content-derived fault target for this complete node definition.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        let hash = self.fault_target_hash();
        DeviceId::from_name(ContentAddressedBlobRef::from_hash(hash).to_uri())
    }

    /// Returns the immutable content identity used by fault selectors.
    #[must_use]
    pub fn fault_target_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            "crucible.model.world-io-node.v1",
            &world_io_node_material(self),
        )
    }

    /// Projects this world node to its concrete scheduler graph identity.
    #[must_use]
    pub fn scheduler_node_id(&self) -> SchedulerNodeId {
        SchedulerNodeId {
            node: self.id.clone(),
            kind: match &self.kind {
                WorldIoNodeKind::Block { .. } => SchedulingNodeKind::Disk,
                WorldIoNodeKind::NineP { .. } => SchedulingNodeKind::NineP,
            },
        }
    }
}

/// One heterogeneous logical node in a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WorldNodeDef {
    /// A QEMU virtual-machine node.
    Vm(WorldNode),
    /// A deterministic block or 9p scheduling sub-node.
    Io(WorldIoNode),
}

impl WorldNodeDef {
    /// Returns the stable node id shared by both node kinds.
    #[must_use]
    pub fn id(&self) -> &NodeId {
        match self {
            Self::Vm(node) => &node.id,
            Self::Io(node) => &node.id,
        }
    }
}

impl WorldNode {
    /// Returns the supported in-guest workload selected by this node, if any.
    #[must_use]
    pub fn guest_workload(&self) -> Option<GuestWorkloadBinary> {
        GuestWorkloadBinary::from_cmdline(&self.cmdline)
    }

    /// Returns the explicit workload seed delivered to this node, if any.
    #[must_use]
    pub fn guest_workload_seed(&self) -> Option<GuestWorkloadSeed> {
        GuestWorkloadSeed::from_cmdline(&self.cmdline)
    }

    /// Returns the scalar workload parameters selected by this node.
    #[must_use]
    pub fn guest_workload_scalar_parameters(&self) -> BTreeMap<GuestWorkloadParameterKey, String> {
        parse_guest_workload_scalar_parameters(&self.cmdline)
    }

    /// Returns the structured workload config tree selected by this node, if any.
    #[must_use]
    pub fn guest_workload_config_tree(&self) -> Option<GuestWorkloadConfigTreeRef> {
        GuestWorkloadConfigTreeRef::from_cmdline(&self.cmdline)
    }

    /// Returns the in-guest load pattern selected by this node, if any.
    #[must_use]
    pub fn guest_workload_pattern(&self) -> Option<GuestWorkloadPattern> {
        GuestWorkloadPattern::from_cmdline(&self.cmdline)
    }

    /// Returns the spike mode selected by this node, if any.
    #[must_use]
    pub fn guest_workload_spike_mode(&self) -> Option<GuestWorkloadSpikeMode> {
        GuestWorkloadSpikeMode::from_cmdline(&self.cmdline)
    }

    /// Returns the load-shape time source selected by this node, if any.
    #[must_use]
    pub fn guest_workload_time_source(&self) -> Option<GuestWorkloadTimeSource> {
        GuestWorkloadTimeSource::from_cmdline(&self.cmdline)
    }
}

/// One logical symmetric link between two nodes in a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LinkDef {
    pub(super) endpoint_a: NodeId,
    pub(super) endpoint_b: NodeId,
    pub(super) latency: SimDuration,
    pub(super) jitter: SimDuration,
    pub(super) loss: LinkLossProbability,
    pub(super) bandwidth_bps: Option<u64>,
}

/// A deterministic fixed-point link loss probability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkLossProbability {
    pub(super) millionths: u32,
}

impl LinkLossProbability {
    /// The lossless probability value.
    pub const ZERO: Self = Self { millionths: 0 };

    /// The always-drop probability value.
    pub const ONE: Self = Self {
        millionths: MAX_LINK_LOSS_MILLIONTHS,
    };

    /// Builds a probability from millionths in the closed range `[0, 1_000_000]`.
    ///
    /// `0` represents `0.0`, and `1_000_000` represents `1.0`. The fixed-point
    /// representation avoids floating-point ambiguity in canonical link
    /// material.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::LinkLossProbabilityOutOfRange`] when
    /// `millionths` is greater than `1_000_000`.
    pub fn from_millionths(millionths: u32) -> Result<Self, EngineError> {
        if millionths > MAX_LINK_LOSS_MILLIONTHS {
            return Err(EngineError::LinkLossProbabilityOutOfRange {
                millionths,
                maximum: MAX_LINK_LOSS_MILLIONTHS,
            });
        }

        Ok(Self { millionths })
    }

    /// Returns this probability as millionths in the closed range `[0, 1_000_000]`.
    #[must_use]
    pub fn millionths(self) -> u32 {
        self.millionths
    }
}

impl LinkDef {
    /// Returns the deterministic segment identity exposed to fault selectors.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError::InvalidId`] only if the implementation's
    /// fixed `segment-<digest>` spelling violates its own identifier contract.
    pub fn fault_segment_id(&self) -> Result<FaultObjectId, FaultContractError> {
        let (left, right) = self.endpoints();
        let material = format!("endpoint-a={}\nendpoint-b={}", left.name, right.name);
        let digest = ContentHash::from_canonical_material(
            "crucible.model.network-segment-identity.v1",
            &material,
        );
        FaultObjectId::parse(format!("segment-{}", digest.to_hex()))
    }

    /// Builds a link with a canonical endpoint ordering.
    ///
    /// `LinkDef::new(a, b)` and `LinkDef::new(b, a)` produce equal links. A
    /// self-loop is rejected because a world link must reference exactly two
    /// distinct node endpoints. The link uses the minimum legal latency, no
    /// jitter, lossless delivery, and no bandwidth cap.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::WorldLinkSelfLoop`] when both endpoints name the
    /// same node.
    pub fn new(left: NodeId, right: NodeId) -> Result<Self, EngineError> {
        Self::with_transport(
            left,
            right,
            MIN_LINK_LATENCY,
            SimDuration::default(),
            LinkLossProbability::ZERO,
            None,
        )
    }

    /// Builds a link with explicit transport characteristics.
    ///
    /// Endpoints are canonically ordered before validation. `latency` is the
    /// one-way base latency; `jitter` is the maximum subtractive jitter allowed
    /// by the model; `loss` is a fixed-point probability; and `bandwidth_bps`
    /// is an optional bits-per-virtual-second cap.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::WorldLinkSelfLoop`] when both endpoints name the
    /// same node, [`EngineError::WorldLinkLatencyBelowFloor`] when `latency` is
    /// below [`MIN_LINK_LATENCY`], or
    /// [`EngineError::WorldLinkJitterBelowLatencyFloor`] when
    /// `latency - jitter` could fall below [`MIN_LINK_LATENCY`].
    pub fn with_transport(
        left: NodeId,
        right: NodeId,
        latency: SimDuration,
        jitter: SimDuration,
        loss: LinkLossProbability,
        bandwidth_bps: Option<u64>,
    ) -> Result<Self, EngineError> {
        if left == right {
            return Err(EngineError::WorldLinkSelfLoop { node: left });
        }

        let link = if left <= right {
            Self {
                endpoint_a: left,
                endpoint_b: right,
                latency,
                jitter,
                loss,
                bandwidth_bps,
            }
        } else {
            Self {
                endpoint_a: right,
                endpoint_b: left,
                latency,
                jitter,
                loss,
                bandwidth_bps,
            }
        };

        validate_link_transport(&link)?;
        Ok(link)
    }

    /// Returns the canonical endpoint pair.
    #[must_use]
    pub fn endpoints(&self) -> (&NodeId, &NodeId) {
        (&self.endpoint_a, &self.endpoint_b)
    }

    /// Returns the one-way base latency for this link.
    #[must_use]
    pub fn latency(&self) -> SimDuration {
        self.latency
    }

    /// Returns the maximum deterministic latency jitter for this link.
    #[must_use]
    pub fn jitter(&self) -> SimDuration {
        self.jitter
    }

    /// Returns the fixed-point frame-loss probability for this link.
    #[must_use]
    pub fn loss(&self) -> LinkLossProbability {
        self.loss
    }

    /// Returns the optional bits-per-virtual-second bandwidth cap for this link.
    #[must_use]
    pub fn bandwidth_bps(&self) -> Option<u64> {
        self.bandwidth_bps
    }

    /// Derives the first-class scheduler identity for this logical network link.
    ///
    /// The identity covers the complete transport-bearing link definition, not
    /// only its endpoint pair, so runtime event producers and the World's static
    /// scheduling-node projection cannot diverge.
    #[must_use]
    pub fn scheduler_node_id(&self) -> SchedulerNodeId {
        let hash = ContentHash::from_canonical_material(
            "crucible.model.world-network-scheduling-node.v1",
            &world_link_material(self),
        );
        SchedulerNodeId {
            node: NodeId {
                name: ContentAddressedBlobRef::from_hash(hash).to_uri(),
            },
            kind: SchedulingNodeKind::Network,
        }
    }
}

/// The deterministic ready-point policy used by `bake`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReadyPoint {
    /// Snapshot after retiring exactly this many guest instructions.
    FixedIcount {
        /// The target retired-instruction count.
        icount: Icount,
    },
    /// Snapshot after the first network-idle quiescence window.
    NetworkIdle {
        /// Required idle span before the node is considered ready.
        window: SimDuration,
    },
    /// Snapshot when a marker appears on the guest console.
    ConsoleMarker {
        /// Marker matched on the guest console stream.
        marker: String,
    },
    /// Snapshot when the optional in-guest agent signals readiness.
    AgentSignal,
}

/// Whether a node opts into the white-box guest-host channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WhiteBoxPolicy {
    /// The guest-host channel is disabled.
    #[default]
    Disabled,
    /// The guest-host channel is enabled.
    Enabled,
}

impl WhiteBoxPolicy {
    /// Returns whether this policy enables the white-box channel.
    #[must_use]
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// A homogeneous content-addressed VM-state reference for one node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeBlobRef {
    /// The baked ready-point VM blob for a node in the world's genesis.
    Baked(ContentHash),
    /// A copy-on-write delta layered over a parent VM blob.
    CowDelta {
        /// The parent VM blob content address.
        parent: ContentHash,
        /// The delta content address.
        delta: ContentHash,
        /// The resolved VM-state content address after applying `delta`.
        resolved: ContentHash,
    },
}

impl NodeBlobRef {
    /// Builds a baked ready-point VM blob reference.
    #[must_use]
    pub fn baked(blob: ContentHash) -> Self {
        Self::Baked(blob)
    }

    /// Builds a copy-on-write delta VM blob reference.
    #[must_use]
    pub fn cow_delta(parent: ContentHash, delta: ContentHash, resolved: ContentHash) -> Self {
        Self::CowDelta {
            parent,
            delta,
            resolved,
        }
    }

    /// Returns the resolved VM-state content address denoted by this blob reference.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        match self {
            Self::Baked(blob) => *blob,
            Self::CowDelta { resolved, .. } => *resolved,
        }
    }

    /// Returns the stored CoW delta object, when this blob is layered.
    #[must_use]
    pub fn cow_delta_ref(&self) -> Option<CowDeltaRef> {
        match self {
            Self::Baked(_) => None,
            Self::CowDelta { delta, .. } => Some(CowDeltaRef::new(CowDeltaKind::VmMemory, *delta)),
        }
    }
}

/// A vCPU identifier within one node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VcpuId {
    /// The zero-based vCPU index.
    pub index: u32,
}

/// An interrupt vector identifier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrqVector {
    /// The interrupt vector number.
    pub vector: u32,
}

/// A deterministic event key recorded by delivery-order decisions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventKey {
    /// The virtual time at which the event was delivered.
    pub virtual_time: VirtualTime,
    /// The scheduler node that consumed the event.
    pub consumer: SchedulerNodeId,
    /// The scheduler node that produced the event.
    pub producer: SchedulerNodeId,
    /// The per-producer/consumer event sequence.
    pub sequence: u64,
}

impl EventKey {
    /// Builds a delivery-order event key from the fully ordered scheduler fields.
    #[must_use]
    pub fn new(
        virtual_time: VirtualTime,
        consumer: SchedulerNodeId,
        producer: SchedulerNodeId,
        sequence: u64,
    ) -> Self {
        Self {
            virtual_time,
            consumer,
            producer,
            sequence,
        }
    }
}
