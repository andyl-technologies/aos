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

impl WorldDeviceKind {
    pub(super) fn material(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::NineP => "9p",
        }
    }
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

/// A fault identifier inside a scenario plan.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultId {
    /// The canonical fault name.
    pub name: String,
}

/// A stable tag used to activate and heal a planned fault.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultTag {
    /// The canonical tag name.
    pub name: String,
}

impl FaultTag {
    /// Builds a fault tag from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Restart behavior used when a crash fault heals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RestartPolicy {
    /// Reboot the node from its baked ready-point checkpoint.
    FromReadyPoint,
    /// Resume the node from its most recent pre-crash checkpoint.
    FromLastCheckpoint,
    /// Keep the node stopped until a later explicit start command.
    StayDown,
}

/// Direction for a planned partition over a declared link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartitionDirection {
    /// Suppress delivery in both directions.
    Bidirectional,
    /// Suppress delivery from `endpoint_a` to `endpoint_b`.
    EndpointAToEndpointB,
    /// Suppress delivery from `endpoint_b` to `endpoint_a`.
    EndpointBToEndpointA,
}

/// Mode used when a block fault fails an I/O operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IoFailureMode {
    /// Complete the operation with a modeled I/O error status.
    ErrorStatus,
    /// Drop the operation so it never completes.
    Drop,
}

/// A positive POSIX errno value returned by a 9p failure fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NinePErrno {
    pub(super) code: i32,
}

impl NinePErrno {
    /// The portable `EIO` errno value.
    pub const EIO: Self = Self { code: 5 };

    /// Builds a positive errno code for 9p failure injection.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::NinePErrnoMustBePositive`] when `code` is zero or
    /// negative.
    pub fn from_code(code: i32) -> Result<Self, EngineError> {
        if code <= 0 {
            return Err(EngineError::NinePErrnoMustBePositive { code });
        }

        Ok(Self { code })
    }

    /// Returns this errno as its positive integer code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.code
    }
}

/// A fixed-point fault probability or ratio in integer basis points.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultRateBasisPoints {
    pub(super) basis_points: u16,
}

impl FaultRateBasisPoints {
    /// The denominator for every basis-point rate.
    pub const DENOMINATOR: u32 = MAX_FAULT_RATE_BASIS_POINTS;

    /// The zero-rate value.
    pub const ZERO: Self = Self { basis_points: 0 };

    /// The always-on or full-scale value.
    pub const ONE: Self = Self {
        basis_points: MAX_FAULT_RATE_BASIS_POINTS as u16,
    };

    /// Builds a basis-point value in the closed range `[0, 10_000]`.
    ///
    /// `0` represents `0.00%`, and `10_000` represents `100.00%`. The
    /// representation is integer-only so canonical fault material never depends
    /// on floating-point formatting or rounding.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::FaultRateBasisPointsOutOfRange`] when
    /// `basis_points` is greater than `10_000`.
    pub fn from_basis_points(basis_points: u32) -> Result<Self, EngineError> {
        if basis_points > Self::DENOMINATOR {
            return Err(EngineError::FaultRateBasisPointsOutOfRange {
                basis_points,
                maximum: Self::DENOMINATOR,
            });
        }

        Ok(Self {
            basis_points: basis_points as u16,
        })
    }

    /// Reduces a recorded raw RNG draw into the basis-point bucket space.
    ///
    /// The result is always in `[0, 10_000)`. Bernoulli decisions compare this
    /// integer bucket directly against [`Self::basis_points`], keeping
    /// determinism-relevant effect choices out of floating-point arithmetic.
    #[must_use]
    pub const fn draw_bucket(raw_draw: u64) -> u16 {
        (raw_draw % Self::DENOMINATOR as u64) as u16
    }

    /// Returns whether `raw_draw` fires this basis-point rate.
    ///
    /// This is the exact integer Bernoulli rule for deterministic fault rates:
    /// `draw_bucket(raw_draw) < basis_points`. The raw draw remains schedule
    /// material; the bucket and comparison are derived deterministically.
    #[must_use]
    pub const fn fires_on_draw(self, raw_draw: u64) -> bool {
        Self::draw_bucket(raw_draw) < self.basis_points
    }

    /// Returns this value as integer basis points.
    #[must_use]
    pub fn basis_points(self) -> u16 {
        self.basis_points
    }
}

/// A fixed-point slowdown factor in integer basis points.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultSlowdownFactorBasisPoints {
    pub(super) basis_points: u32,
}

impl FaultSlowdownFactorBasisPoints {
    /// The identity slowdown factor, equal to `1.0`.
    pub const ONE: Self = Self {
        basis_points: MIN_FAULT_SLOWDOWN_FACTOR_BASIS_POINTS,
    };

    /// Builds a slowdown factor in basis points.
    ///
    /// `10_000` represents `1.0`, `20_000` represents `2.0`, and so on. Values
    /// below `10_000` would speed a node up and are outside the fault taxonomy.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::FaultSlowdownFactorBelowOne`] when
    /// `basis_points` is less than `10_000`.
    pub fn from_basis_points(basis_points: u32) -> Result<Self, EngineError> {
        if basis_points < MIN_FAULT_SLOWDOWN_FACTOR_BASIS_POINTS {
            return Err(EngineError::FaultSlowdownFactorBelowOne {
                basis_points,
                minimum: MIN_FAULT_SLOWDOWN_FACTOR_BASIS_POINTS,
            });
        }

        Ok(Self { basis_points })
    }

    /// Returns this slowdown factor as integer basis points.
    #[must_use]
    pub const fn basis_points(self) -> u32 {
        self.basis_points
    }
}

/// An integer virtual-time duration used by fault parameters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultDuration {
    pub(super) nanos: u64,
}

impl FaultDuration {
    /// The zero-length duration.
    pub const ZERO: Self = Self { nanos: 0 };

    /// Builds a duration from integer virtual nanoseconds.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// Returns this duration as integer virtual nanoseconds.
    #[must_use]
    pub const fn nanos(self) -> u64 {
        self.nanos
    }

    /// Adds two fault durations, saturating at `u64::MAX`.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            nanos: self.nanos.saturating_add(other.nanos),
        }
    }

    /// Converts this duration to the shared execution-model duration type.
    #[must_use]
    pub const fn to_sim_duration(self) -> SimDuration {
        SimDuration { nanos: self.nanos }
    }
}

/// An integer bandwidth limit used by network faults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultBandwidthBitsPerSecond {
    pub(super) bits_per_second: u64,
}

impl FaultBandwidthBitsPerSecond {
    /// Builds a nonzero integer bits-per-virtual-second bandwidth limit.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::FaultBandwidthMustBeNonZero`] when
    /// `bits_per_second` is zero.
    pub fn new(bits_per_second: u64) -> Result<Self, EngineError> {
        if bits_per_second == 0 {
            return Err(EngineError::FaultBandwidthMustBeNonZero { bits_per_second });
        }

        Ok(Self { bits_per_second })
    }

    /// Returns this limit as integer bits per virtual second.
    #[must_use]
    pub const fn bits_per_second(self) -> u64 {
        self.bits_per_second
    }
}

/// The complete RFC-0010 fault taxonomy.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fault {
    /// A network-link fault.
    Network(NetworkFault),
    /// A node/runtime fault.
    Node(NodeFault),
    /// A block-device fault.
    Block(BlockFault),
    /// A 9p-device fault.
    NineP(NinePFault),
}

impl Fault {
    /// Returns a stable dotted taxonomy key for this fault.
    #[must_use]
    pub fn kind_key(&self) -> &'static str {
        match self {
            Self::Network(fault) => fault.kind_key(),
            Self::Node(fault) => fault.kind_key(),
            Self::Block(fault) => fault.kind_key(),
            Self::NineP(fault) => fault.kind_key(),
        }
    }

    /// Returns canonical line-oriented material for this fault.
    ///
    /// The material includes only integer fields and stable target identifiers,
    /// making it suitable for deterministic content addressing and guard tests.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        match self {
            Self::Network(fault) => format!("category=network\n{}", fault.canonical_material()),
            Self::Node(fault) => format!("category=node\n{}", fault.canonical_material()),
            Self::Block(fault) => format!("category=block\n{}", fault.canonical_material()),
            Self::NineP(fault) => format!("category=9p\n{}", fault.canonical_material()),
        }
    }

    /// Computes the content address of this fault taxonomy value.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::from_canonical_material(
            "crucible.fault.taxonomy.v1",
            &self.canonical_material(),
        )
    }
}

/// Network fault variants over a declared logical link.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkFault {
    /// Suppress delivery for one direction or both directions of a link.
    Partition {
        /// Link affected by the partition.
        link: LinkId,
        /// Direction of delivery suppression.
        direction: PartitionDirection,
    },
    /// Drop frames with a fixed basis-point probability.
    Loss {
        /// Link whose frames may be dropped.
        link: LinkId,
        /// Drop probability in basis points.
        rate: FaultRateBasisPoints,
    },
    /// Delay delivery within an integer virtual-time reorder window.
    Reorder {
        /// Link whose frame order may change.
        link: LinkId,
        /// Maximum integer virtual-time reorder window.
        window: FaultDuration,
    },
    /// Emit a second delivery with a fixed basis-point probability.
    Duplicate {
        /// Link whose frames may be duplicated.
        link: LinkId,
        /// Duplicate probability in basis points.
        rate: FaultRateBasisPoints,
        /// Integer virtual-time gap before the duplicate delivery.
        gap: FaultDuration,
    },
    /// Mutate delivered frame bytes.
    Corruption {
        /// Link whose frames may be corrupted.
        link: LinkId,
        /// Corruption mode and parameters.
        kind: NetworkCorruptionFault,
    },
    /// Cap link throughput with an integer bandwidth limit.
    Bandwidth {
        /// Link affected by the cap.
        link: LinkId,
        /// Integer bits-per-virtual-second limit.
        limit: FaultBandwidthBitsPerSecond,
    },
    /// Add deterministic integer virtual-time latency to deliveries.
    LatencyBump {
        /// Link whose deliveries are delayed.
        link: LinkId,
        /// Extra integer virtual-time latency.
        extra: FaultDuration,
    },
}

impl NetworkFault {
    /// Returns a stable dotted taxonomy key for this network fault.
    #[must_use]
    pub fn kind_key(&self) -> &'static str {
        match self {
            Self::Partition { .. } => "network.partition",
            Self::Loss { .. } => "network.loss",
            Self::Reorder { .. } => "network.reorder",
            Self::Duplicate { .. } => "network.duplicate",
            Self::Corruption { kind, .. } => kind.kind_key(),
            Self::Bandwidth { .. } => "network.bandwidth",
            Self::LatencyBump { .. } => "network.latency-bump",
        }
    }

    fn canonical_material(&self) -> String {
        match self {
            Self::Partition { link, direction } => {
                format!(
                    "kind=network.partition\n{}\ndirection={}",
                    fault_link_material(link),
                    partition_direction_key(*direction)
                )
            }
            Self::Loss { link, rate } => format!(
                "kind=network.loss\n{}\nrate_basis_points={}",
                fault_link_material(link),
                rate.basis_points()
            ),
            Self::Reorder { link, window } => format!(
                "kind=network.reorder\n{}\nwindow_nanos={}",
                fault_link_material(link),
                window.nanos()
            ),
            Self::Duplicate { link, rate, gap } => format!(
                "kind=network.duplicate\n{}\nrate_basis_points={}\ngap_nanos={}",
                fault_link_material(link),
                rate.basis_points(),
                gap.nanos()
            ),
            Self::Corruption { link, kind } => {
                format!(
                    "{}\n{}",
                    kind.canonical_material(),
                    fault_link_material(link)
                )
            }
            Self::Bandwidth { link, limit } => format!(
                "kind=network.bandwidth\n{}\nbits_per_second={}",
                fault_link_material(link),
                limit.bits_per_second()
            ),
            Self::LatencyBump { link, extra } => format!(
                "kind=network.latency-bump\n{}\nextra_nanos={}",
                fault_link_material(link),
                extra.nanos()
            ),
        }
    }
}

/// Network payload corruption modes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkCorruptionFault {
    /// Flip up to `max_bits` payload bits.
    BitFlip {
        /// Bit-flip probability in basis points.
        rate: FaultRateBasisPoints,
        /// Maximum number of bits to flip in one frame.
        max_bits: u32,
    },
    /// Mutate one modeled protocol field.
    FieldMutation {
        /// Field-mutation probability in basis points.
        rate: FaultRateBasisPoints,
    },
    /// Truncate delivered payloads.
    Truncation {
        /// Truncation probability in basis points.
        rate: FaultRateBasisPoints,
        /// Maximum number of bytes removed from a frame.
        max_bytes: u64,
    },
}

impl NetworkCorruptionFault {
    /// Returns a stable dotted taxonomy key for this corruption mode.
    #[must_use]
    pub fn kind_key(&self) -> &'static str {
        match self {
            Self::BitFlip { .. } => "network.corruption.bit-flip",
            Self::FieldMutation { .. } => "network.corruption.field-mutation",
            Self::Truncation { .. } => "network.corruption.truncation",
        }
    }

    fn canonical_material(&self) -> String {
        match self {
            Self::BitFlip { rate, max_bits } => format!(
                "kind=network.corruption.bit-flip\nrate_basis_points={}\nmax_bits={max_bits}",
                rate.basis_points()
            ),
            Self::FieldMutation { rate } => format!(
                "kind=network.corruption.field-mutation\nrate_basis_points={}",
                rate.basis_points()
            ),
            Self::Truncation { rate, max_bytes } => format!(
                "kind=network.corruption.truncation\nrate_basis_points={}\nmax_bytes={max_bytes}",
                rate.basis_points()
            ),
        }
    }
}

/// Node/runtime fault variants over a declared VM node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeFault {
    /// Stop a node until a restart policy acts.
    Crash {
        /// Node affected by the crash.
        node: NodeId,
        /// Restart behavior when the crash heals.
        restart: RestartPolicy,
    },
    /// Stretch the node's virtual-time mapping by an integer basis-point rate.
    Slow {
        /// Node affected by the slowdown.
        node: NodeId,
        /// Slowdown factor in basis points, where `10_000` is the identity.
        factor: FaultSlowdownFactorBasisPoints,
    },
    /// Offset guest-visible time-of-day without moving scheduler virtual time.
    ClockSkew {
        /// Node whose guest-visible clock is skewed.
        node: NodeId,
        /// Signed integer virtual-time offset.
        offset: SimOffset,
    },
}

impl NodeFault {
    /// Returns a stable dotted taxonomy key for this node fault.
    #[must_use]
    pub fn kind_key(&self) -> &'static str {
        match self {
            Self::Crash { .. } => "node.crash",
            Self::Slow { .. } => "node.slow",
            Self::ClockSkew { .. } => "node.clock-skew",
        }
    }

    fn canonical_material(&self) -> String {
        match self {
            Self::Crash { node, restart } => format!(
                "kind=node.crash\n{}\nrestart={}",
                fault_node_material(node),
                restart_policy_key(*restart)
            ),
            Self::Slow { node, factor } => format!(
                "kind=node.slow\n{}\nfactor_basis_points={}",
                fault_node_material(node),
                factor.basis_points()
            ),
            Self::ClockSkew { node, offset } => format!(
                "kind=node.clock-skew\n{}\noffset_nanos={}",
                fault_node_material(node),
                offset.nanos
            ),
        }
    }
}

/// Block-device fault variants over a declared block device.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockFault {
    /// Add integer virtual-time latency to block completions.
    Latency {
        /// Block device affected by the latency.
        device: DeviceId,
        /// Extra integer virtual-time latency.
        extra: FaultDuration,
        /// Integer virtual-time latency jitter.
        jitter: FaultDuration,
    },
    /// Fail block operations with a fixed basis-point probability.
    Failure {
        /// Block device affected by the failure.
        device: DeviceId,
        /// Failure probability in basis points.
        rate: FaultRateBasisPoints,
        /// Mode used to fail the operation.
        mode: IoFailureMode,
    },
    /// Reorder block completions inside an integer virtual-time window.
    Reorder {
        /// Block device affected by reordering.
        device: DeviceId,
        /// Maximum integer virtual-time reorder window.
        window: FaultDuration,
    },
    /// Emit a duplicate block completion with a fixed basis-point probability.
    Duplicate {
        /// Block device affected by duplication.
        device: DeviceId,
        /// Duplicate probability in basis points.
        rate: FaultRateBasisPoints,
        /// Integer virtual-time gap before the duplicate delivery.
        gap: FaultDuration,
    },
    /// Corrupt block response bytes by flipping seeded payload bits.
    Corruption {
        /// Block device affected by corruption.
        device: DeviceId,
        /// Corruption probability in basis points.
        rate: FaultRateBasisPoints,
        /// Maximum number of response bits to flip.
        bit_flips: u32,
    },
    /// Cap block transfer throughput with an integer bandwidth limit.
    Bandwidth {
        /// Block device affected by the cap.
        device: DeviceId,
        /// Integer bits-per-virtual-second limit.
        limit: FaultBandwidthBitsPerSecond,
    },
}

impl BlockFault {
    /// Returns a stable dotted taxonomy key for this block fault.
    #[must_use]
    pub fn kind_key(&self) -> &'static str {
        match self {
            Self::Latency { .. } => "block.latency",
            Self::Failure { .. } => "block.failure",
            Self::Reorder { .. } => "block.reorder",
            Self::Duplicate { .. } => "block.duplicate",
            Self::Corruption { .. } => "block.corruption.bit-flip",
            Self::Bandwidth { .. } => "block.bandwidth",
        }
    }

    fn canonical_material(&self) -> String {
        match self {
            Self::Latency {
                device,
                extra,
                jitter,
            } => format!(
                "kind=block.latency\n{}\nextra_nanos={}\njitter_nanos={}",
                fault_device_material(device),
                extra.nanos(),
                jitter.nanos()
            ),
            Self::Failure { device, rate, mode } => format!(
                "kind=block.failure\n{}\nrate_basis_points={}\nmode={}",
                fault_device_material(device),
                rate.basis_points(),
                io_failure_mode_key(*mode)
            ),
            Self::Reorder { device, window } => format!(
                "kind=block.reorder\n{}\nwindow_nanos={}",
                fault_device_material(device),
                window.nanos()
            ),
            Self::Duplicate { device, rate, gap } => format!(
                "kind=block.duplicate\n{}\nrate_basis_points={}\ngap_nanos={}",
                fault_device_material(device),
                rate.basis_points(),
                gap.nanos()
            ),
            Self::Corruption {
                device,
                rate,
                bit_flips,
            } => format!(
                "kind=block.corruption.bit-flip\n{}\nrate_basis_points={}\nbit_flips={bit_flips}",
                fault_device_material(device),
                rate.basis_points()
            ),
            Self::Bandwidth { device, limit } => format!(
                "kind=block.bandwidth\n{}\nbits_per_second={}",
                fault_device_material(device),
                limit.bits_per_second()
            ),
        }
    }
}

/// 9p-device fault variants over a declared 9p device.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NinePFault {
    /// Add integer virtual-time latency to 9p completions.
    Latency {
        /// 9p device affected by the latency.
        device: DeviceId,
        /// Extra integer virtual-time latency.
        extra: FaultDuration,
        /// Integer virtual-time latency jitter.
        jitter: FaultDuration,
    },
    /// Fail 9p operations with a fixed basis-point probability.
    Failure {
        /// 9p device affected by the failure.
        device: DeviceId,
        /// Failure probability in basis points.
        rate: FaultRateBasisPoints,
        /// Errno returned by the failed operation.
        errno: NinePErrno,
    },
    /// Reorder 9p completions inside an integer virtual-time window.
    Reorder {
        /// 9p device affected by reordering.
        device: DeviceId,
        /// Maximum integer virtual-time reorder window.
        window: FaultDuration,
    },
    /// Emit a duplicate 9p reply with a fixed basis-point probability.
    Duplicate {
        /// 9p device affected by duplication.
        device: DeviceId,
        /// Duplicate probability in basis points.
        rate: FaultRateBasisPoints,
        /// Integer virtual-time gap before the duplicate delivery.
        gap: FaultDuration,
    },
    /// Corrupt 9p reply bytes by flipping seeded payload bits.
    Corruption {
        /// 9p device affected by corruption.
        device: DeviceId,
        /// Corruption probability in basis points.
        rate: FaultRateBasisPoints,
        /// Maximum number of response bits to flip.
        bit_flips: u32,
    },
    /// Cap 9p transfer throughput with an integer bandwidth limit.
    Bandwidth {
        /// 9p device affected by the cap.
        device: DeviceId,
        /// Integer bits-per-virtual-second limit.
        limit: FaultBandwidthBitsPerSecond,
    },
}

impl NinePFault {
    /// Returns a stable dotted taxonomy key for this 9p fault.
    #[must_use]
    pub fn kind_key(&self) -> &'static str {
        match self {
            Self::Latency { .. } => "9p.latency",
            Self::Failure { .. } => "9p.failure",
            Self::Reorder { .. } => "9p.reorder",
            Self::Duplicate { .. } => "9p.duplicate",
            Self::Corruption { .. } => "9p.corruption.bit-flip",
            Self::Bandwidth { .. } => "9p.bandwidth",
        }
    }

    fn canonical_material(&self) -> String {
        match self {
            Self::Latency {
                device,
                extra,
                jitter,
            } => format!(
                "kind=9p.latency\n{}\nextra_nanos={}\njitter_nanos={}",
                fault_device_material(device),
                extra.nanos(),
                jitter.nanos()
            ),
            Self::Failure {
                device,
                rate,
                errno,
            } => format!(
                "kind=9p.failure\n{}\nrate_basis_points={}\nerrno={}",
                fault_device_material(device),
                rate.basis_points(),
                errno.code()
            ),
            Self::Reorder { device, window } => format!(
                "kind=9p.reorder\n{}\nwindow_nanos={}",
                fault_device_material(device),
                window.nanos()
            ),
            Self::Duplicate { device, rate, gap } => format!(
                "kind=9p.duplicate\n{}\nrate_basis_points={}\ngap_nanos={}",
                fault_device_material(device),
                rate.basis_points(),
                gap.nanos()
            ),
            Self::Corruption {
                device,
                rate,
                bit_flips,
            } => format!(
                "kind=9p.corruption.bit-flip\n{}\nrate_basis_points={}\nbit_flips={bit_flips}",
                fault_device_material(device),
                rate.basis_points()
            ),
            Self::Bandwidth { device, limit } => format!(
                "kind=9p.bandwidth\n{}\nbits_per_second={}",
                fault_device_material(device),
                limit.bits_per_second()
            ),
        }
    }
}

/// The deterministic, target-grouped combination of active fault taxonomy values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CombinedFaults {
    /// Combined network-link faults keyed by declared link.
    pub network: BTreeMap<LinkId, CombinedNetworkFaults>,
    /// Combined node/runtime faults keyed by declared node.
    pub node: BTreeMap<NodeId, CombinedNodeFaults>,
    /// Combined block-device faults keyed by declared device.
    pub block: BTreeMap<DeviceId, CombinedBlockFaults>,
    /// Combined 9p-device faults keyed by declared device.
    pub ninep: BTreeMap<DeviceId, CombinedNinePFaults>,
}

impl CombinedFaults {
    /// Combines active faults by target and kind.
    ///
    /// The result is a pure function of the supplied set: input order does not
    /// affect output maps, rate lists, selected maximums, summed delays, or fixed
    /// corruption strategy order.
    #[must_use]
    pub fn from_faults(faults: &[Fault]) -> Self {
        let mut combined = Self::default();

        for fault in faults {
            match fault {
                Fault::Network(fault) => combine_network_fault(&mut combined.network, fault),
                Fault::Node(fault) => combine_node_fault(&mut combined.node, fault),
                Fault::Block(fault) => combine_block_fault(&mut combined.block, fault),
                Fault::NineP(fault) => combine_ninep_fault(&mut combined.ninep, fault),
            }
        }

        combined.finish()
    }

    /// Combines active membership faults that have a scheduler-table projection.
    #[must_use]
    pub fn from_membership_faults<'a>(
        faults: impl IntoIterator<Item = &'a MembershipFault>,
    ) -> Self {
        let faults = faults
            .into_iter()
            .filter_map(MembershipFault::table_fault)
            .collect::<Vec<_>>();
        Self::from_faults(&faults)
    }

    fn finish(mut self) -> Self {
        for effects in self.network.values_mut() {
            effects.finish();
        }
        for effects in self.block.values_mut() {
            effects.finish();
        }
        for effects in self.ninep.values_mut() {
            effects.finish();
        }
        self
    }
}

/// Direction key for a materialized network active-fault table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActiveNetworkEdgeDirection {
    /// The directed edge carries traffic from endpoint A to endpoint B.
    EndpointAToEndpointB,
    /// The directed edge carries traffic from endpoint B to endpoint A.
    EndpointBToEndpointA,
}

/// Stable directed-edge key for materialized network active faults.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActiveNetworkEdgeKey {
    /// Declared logical link identity.
    pub link: LinkId,
    /// Direction through the declared logical link.
    pub direction: ActiveNetworkEdgeDirection,
}

impl ActiveNetworkEdgeKey {
    /// Builds a directed network active-fault key.
    #[must_use]
    pub fn new(link: LinkId, direction: ActiveNetworkEdgeDirection) -> Self {
        Self { link, direction }
    }
}

/// Materialized active-fault lookup table captured by the scheduler.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ActiveFaultTable {
    /// Link-, node-, block-, and 9p-keyed combined taxonomy faults.
    pub combined: CombinedFaults,
    /// Directed network lookup table keyed by logical link and direction.
    pub network_edges: BTreeMap<ActiveNetworkEdgeKey, CombinedNetworkFaults>,
    /// Active legacy membership faults that do not have a pure taxonomy projection.
    pub legacy_membership: BTreeMap<FaultTag, MembershipFault>,
}

impl ActiveFaultTable {
    /// Builds the active table from currently active tagged membership faults.
    #[must_use]
    pub fn from_active_faults(active_faults: &BTreeMap<FaultTag, MembershipFault>) -> Self {
        let combined = CombinedFaults::from_membership_faults(active_faults.values());
        let network_edges = directed_network_fault_table(&combined.network);
        let legacy_membership = active_faults
            .iter()
            .filter(|(_tag, fault)| fault.table_fault().is_none())
            .map(|(tag, fault)| (tag.clone(), fault.clone()))
            .collect();
        Self {
            combined,
            network_edges,
            legacy_membership,
        }
    }
}

pub(super) fn directed_network_fault_table(
    network: &BTreeMap<LinkId, CombinedNetworkFaults>,
) -> BTreeMap<ActiveNetworkEdgeKey, CombinedNetworkFaults> {
    let mut table = BTreeMap::new();
    for (link, faults) in network {
        table.insert(
            ActiveNetworkEdgeKey::new(
                link.clone(),
                ActiveNetworkEdgeDirection::EndpointAToEndpointB,
            ),
            directed_network_faults(faults, ActiveNetworkEdgeDirection::EndpointAToEndpointB),
        );
        table.insert(
            ActiveNetworkEdgeKey::new(
                link.clone(),
                ActiveNetworkEdgeDirection::EndpointBToEndpointA,
            ),
            directed_network_faults(faults, ActiveNetworkEdgeDirection::EndpointBToEndpointA),
        );
    }
    table
}

pub(super) fn directed_network_faults(
    faults: &CombinedNetworkFaults,
    direction: ActiveNetworkEdgeDirection,
) -> CombinedNetworkFaults {
    let mut directed = faults.clone();
    directed.partition = faults.partition.and_then(|partition| {
        let covered = match direction {
            ActiveNetworkEdgeDirection::EndpointAToEndpointB => partition.endpoint_a_to_endpoint_b,
            ActiveNetworkEdgeDirection::EndpointBToEndpointA => partition.endpoint_b_to_endpoint_a,
        };
        covered.then_some(match direction {
            ActiveNetworkEdgeDirection::EndpointAToEndpointB => CombinedPartitionFault {
                endpoint_a_to_endpoint_b: true,
                endpoint_b_to_endpoint_a: false,
            },
            ActiveNetworkEdgeDirection::EndpointBToEndpointA => CombinedPartitionFault {
                endpoint_a_to_endpoint_b: false,
                endpoint_b_to_endpoint_a: true,
            },
        })
    });
    directed
}

/// Combined network-link effects for one link.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CombinedNetworkFaults {
    /// Directed partition coverage; absent when no partition is active.
    pub partition: Option<CombinedPartitionFault>,
    /// Loss rates evaluated highest-first for the any-fires rule.
    pub loss_rates: Vec<FaultRateBasisPoints>,
    /// Total fixed latency bump from all active latency faults.
    pub latency: FaultDuration,
    /// Widest active reorder window.
    pub reorder_window: Option<FaultDuration>,
    /// Highest-rate duplicate fault, with deterministic tie-breaking for gap.
    pub duplicate: Option<CombinedDuplicateFault>,
    /// Highest-rate corruption decision and fixed-order strategies.
    pub corruption: Option<CombinedNetworkCorruptionFault>,
    /// Active bandwidth limits, all contributing integer serialization delay.
    pub bandwidth_limits: Vec<FaultBandwidthBitsPerSecond>,
}

impl CombinedNetworkFaults {
    fn finish(&mut self) {
        sort_rates_highest_first(&mut self.loss_rates);
        self.bandwidth_limits.sort();
        if let Some(corruption) = &mut self.corruption {
            corruption
                .strategies
                .sort_by(network_corruption_strategy_cmp);
        }
    }
}

/// Directed partition coverage for one link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CombinedPartitionFault {
    /// Whether endpoint A to endpoint B is suppressed.
    pub endpoint_a_to_endpoint_b: bool,
    /// Whether endpoint B to endpoint A is suppressed.
    pub endpoint_b_to_endpoint_a: bool,
}

impl CombinedPartitionFault {
    fn cover(&mut self, direction: PartitionDirection) {
        match direction {
            PartitionDirection::Bidirectional => {
                self.endpoint_a_to_endpoint_b = true;
                self.endpoint_b_to_endpoint_a = true;
            }
            PartitionDirection::EndpointAToEndpointB => {
                self.endpoint_a_to_endpoint_b = true;
            }
            PartitionDirection::EndpointBToEndpointA => {
                self.endpoint_b_to_endpoint_a = true;
            }
        }
    }
}

/// The effective duplicate rule for one link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CombinedDuplicateFault {
    /// Highest active duplicate rate.
    pub rate: FaultRateBasisPoints,
    /// Deterministically selected duplicate gap among faults at that rate.
    pub gap: FaultDuration,
}

/// The effective corruption rule for one link.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CombinedNetworkCorruptionFault {
    /// Highest active corruption rate.
    pub rate: FaultRateBasisPoints,
    /// Corruption strategies applied in fixed kind order when the rate fires.
    pub strategies: Vec<NetworkCorruptionFault>,
}

/// The effective bit-flip corruption rule for one I/O device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CombinedIoCorruptionFault {
    /// Highest active corruption rate.
    pub rate: FaultRateBasisPoints,
    /// Maximum active bit-flip count at the selected rate.
    pub bit_flips: u32,
}

/// Combined node/runtime effects for one node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CombinedNodeFaults {
    /// Most conservative restart policy when any crash fault names the node.
    pub crash_restart: Option<RestartPolicy>,
    /// Largest active slowdown factor.
    pub slow_factor: Option<FaultSlowdownFactorBasisPoints>,
    /// Saturating sum of all signed clock-skew offsets.
    pub clock_skew: SimOffset,
}

impl CombinedNodeFaults {
    /// Returns whether at least one active crash fault names this node.
    #[must_use]
    pub const fn is_crashed(&self) -> bool {
        self.crash_restart.is_some()
    }
}

/// Combined block-device effects for one block device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CombinedBlockFaults {
    /// Total fixed latency from all active block latency faults.
    pub latency_extra: FaultDuration,
    /// Total jitter window from all active block latency faults.
    pub latency_jitter: FaultDuration,
    /// Failure rates evaluated highest-first for the any-fires rule.
    pub failure_rates: Vec<FaultRateBasisPoints>,
    /// Most severe failure mode among active block failure faults.
    pub failure_mode: Option<IoFailureMode>,
    /// Widest active block reorder window.
    pub reorder_window: Option<FaultDuration>,
    /// Highest-rate active block duplicate fault.
    pub duplicate: Option<CombinedDuplicateFault>,
    /// Highest-rate active block bit-flip corruption fault.
    pub corruption: Option<CombinedIoCorruptionFault>,
    /// Active bandwidth limits, all contributing integer serialization delay.
    pub bandwidth_limits: Vec<FaultBandwidthBitsPerSecond>,
}

impl CombinedBlockFaults {
    fn finish(&mut self) {
        sort_rates_highest_first(&mut self.failure_rates);
        self.bandwidth_limits.sort();
    }
}

/// Combined 9p-device effects for one 9p device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CombinedNinePFaults {
    /// Total fixed latency from all active 9p latency faults.
    pub latency_extra: FaultDuration,
    /// Total jitter window from all active 9p latency faults.
    pub latency_jitter: FaultDuration,
    /// Failure choices evaluated highest-rate-first for the any-fires rule.
    pub failures: Vec<CombinedNinePFailureFault>,
    /// Widest active 9p reorder window.
    pub reorder_window: Option<FaultDuration>,
    /// Highest-rate active 9p duplicate fault.
    pub duplicate: Option<CombinedDuplicateFault>,
    /// Highest-rate active 9p bit-flip corruption fault.
    pub corruption: Option<CombinedIoCorruptionFault>,
    /// Active bandwidth limits, all contributing integer serialization delay.
    pub bandwidth_limits: Vec<FaultBandwidthBitsPerSecond>,
}

/// One 9p failure choice kept with its errno payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CombinedNinePFailureFault {
    /// Failure probability in basis points.
    pub rate: FaultRateBasisPoints,
    /// Errno returned when this failure choice fires.
    pub errno: NinePErrno,
}

impl CombinedNinePFaults {
    fn finish(&mut self) {
        self.failures.sort_by(|left, right| {
            right
                .rate
                .cmp(&left.rate)
                .then_with(|| left.errno.cmp(&right.errno))
        });
        self.bandwidth_limits.sort();
    }
}

pub(super) fn combine_network_fault(
    combined: &mut BTreeMap<LinkId, CombinedNetworkFaults>,
    fault: &NetworkFault,
) {
    match fault {
        NetworkFault::Partition { link, direction } => {
            combined
                .entry(link.clone())
                .or_default()
                .partition
                .get_or_insert_with(CombinedPartitionFault::default)
                .cover(*direction);
        }
        NetworkFault::Loss { link, rate } => {
            combined
                .entry(link.clone())
                .or_default()
                .loss_rates
                .push(*rate);
        }
        NetworkFault::Reorder { link, window } => {
            let entry = combined.entry(link.clone()).or_default();
            entry.reorder_window = Some(max_duration(entry.reorder_window, *window));
        }
        NetworkFault::Duplicate { link, rate, gap } => {
            let entry = combined.entry(link.clone()).or_default();
            let candidate = CombinedDuplicateFault {
                rate: *rate,
                gap: *gap,
            };
            entry.duplicate = Some(match entry.duplicate {
                Some(current) => max_duplicate(current, candidate),
                None => candidate,
            });
        }
        NetworkFault::Corruption { link, kind } => {
            let entry = combined.entry(link.clone()).or_default();
            match &mut entry.corruption {
                Some(corruption) => {
                    corruption.rate = corruption.rate.max(corruption_rate(kind));
                    corruption.strategies.push(kind.clone());
                }
                None => {
                    entry.corruption = Some(CombinedNetworkCorruptionFault {
                        rate: corruption_rate(kind),
                        strategies: vec![kind.clone()],
                    });
                }
            }
        }
        NetworkFault::Bandwidth { link, limit } => {
            combined
                .entry(link.clone())
                .or_default()
                .bandwidth_limits
                .push(*limit);
        }
        NetworkFault::LatencyBump { link, extra } => {
            let entry = combined.entry(link.clone()).or_default();
            entry.latency = entry.latency.saturating_add(*extra);
        }
    }
}

pub(super) fn combine_node_fault(
    combined: &mut BTreeMap<NodeId, CombinedNodeFaults>,
    fault: &NodeFault,
) {
    match fault {
        NodeFault::Crash { node, restart } => {
            let entry = combined.entry(node.clone()).or_default();
            entry.crash_restart = Some(
                entry
                    .crash_restart
                    .map_or(*restart, |current| current.max(*restart)),
            );
        }
        NodeFault::Slow { node, factor } => {
            let entry = combined.entry(node.clone()).or_default();
            entry.slow_factor = Some(
                entry
                    .slow_factor
                    .map_or(*factor, |current| current.max(*factor)),
            );
        }
        NodeFault::ClockSkew { node, offset } => {
            let entry = combined.entry(node.clone()).or_default();
            entry.clock_skew = saturating_offset_add(entry.clock_skew, *offset);
        }
    }
}

pub(super) fn combine_block_fault(
    combined: &mut BTreeMap<DeviceId, CombinedBlockFaults>,
    fault: &BlockFault,
) {
    match fault {
        BlockFault::Latency {
            device,
            extra,
            jitter,
        } => {
            let entry = combined.entry(device.clone()).or_default();
            entry.latency_extra = entry.latency_extra.saturating_add(*extra);
            entry.latency_jitter = entry.latency_jitter.saturating_add(*jitter);
        }
        BlockFault::Failure { device, rate, mode } => {
            let entry = combined.entry(device.clone()).or_default();
            entry.failure_rates.push(*rate);
            entry.failure_mode = Some(
                entry
                    .failure_mode
                    .map_or(*mode, |current| current.max(*mode)),
            );
        }
        BlockFault::Reorder { device, window } => {
            let entry = combined.entry(device.clone()).or_default();
            entry.reorder_window = Some(max_duration(entry.reorder_window, *window));
        }
        BlockFault::Duplicate { device, rate, gap } => {
            let entry = combined.entry(device.clone()).or_default();
            let candidate = CombinedDuplicateFault {
                rate: *rate,
                gap: *gap,
            };
            entry.duplicate = Some(match entry.duplicate {
                Some(current) => max_duplicate(current, candidate),
                None => candidate,
            });
        }
        BlockFault::Corruption {
            device,
            rate,
            bit_flips,
        } => {
            let entry = combined.entry(device.clone()).or_default();
            let candidate = CombinedIoCorruptionFault {
                rate: *rate,
                bit_flips: *bit_flips,
            };
            entry.corruption = Some(match entry.corruption {
                Some(current) => max_io_corruption(current, candidate),
                None => candidate,
            });
        }
        BlockFault::Bandwidth { device, limit } => {
            combined
                .entry(device.clone())
                .or_default()
                .bandwidth_limits
                .push(*limit);
        }
    }
}

pub(super) fn combine_ninep_fault(
    combined: &mut BTreeMap<DeviceId, CombinedNinePFaults>,
    fault: &NinePFault,
) {
    match fault {
        NinePFault::Latency {
            device,
            extra,
            jitter,
        } => {
            let entry = combined.entry(device.clone()).or_default();
            entry.latency_extra = entry.latency_extra.saturating_add(*extra);
            entry.latency_jitter = entry.latency_jitter.saturating_add(*jitter);
        }
        NinePFault::Failure {
            device,
            rate,
            errno,
        } => {
            let entry = combined.entry(device.clone()).or_default();
            entry.failures.push(CombinedNinePFailureFault {
                rate: *rate,
                errno: *errno,
            });
        }
        NinePFault::Reorder { device, window } => {
            let entry = combined.entry(device.clone()).or_default();
            entry.reorder_window = Some(max_duration(entry.reorder_window, *window));
        }
        NinePFault::Duplicate { device, rate, gap } => {
            let entry = combined.entry(device.clone()).or_default();
            let candidate = CombinedDuplicateFault {
                rate: *rate,
                gap: *gap,
            };
            entry.duplicate = Some(match entry.duplicate {
                Some(current) => max_duplicate(current, candidate),
                None => candidate,
            });
        }
        NinePFault::Corruption {
            device,
            rate,
            bit_flips,
        } => {
            let entry = combined.entry(device.clone()).or_default();
            let candidate = CombinedIoCorruptionFault {
                rate: *rate,
                bit_flips: *bit_flips,
            };
            entry.corruption = Some(match entry.corruption {
                Some(current) => max_io_corruption(current, candidate),
                None => candidate,
            });
        }
        NinePFault::Bandwidth { device, limit } => {
            combined
                .entry(device.clone())
                .or_default()
                .bandwidth_limits
                .push(*limit);
        }
    }
}

pub(super) fn max_duration(
    current: Option<FaultDuration>,
    candidate: FaultDuration,
) -> FaultDuration {
    current.map_or(candidate, |current| current.max(candidate))
}

pub(super) fn max_duplicate(
    current: CombinedDuplicateFault,
    candidate: CombinedDuplicateFault,
) -> CombinedDuplicateFault {
    match candidate.rate.cmp(&current.rate) {
        std::cmp::Ordering::Greater => candidate,
        std::cmp::Ordering::Equal if candidate.gap > current.gap => candidate,
        _ => current,
    }
}

pub(super) fn max_io_corruption(
    current: CombinedIoCorruptionFault,
    candidate: CombinedIoCorruptionFault,
) -> CombinedIoCorruptionFault {
    match candidate.rate.cmp(&current.rate) {
        std::cmp::Ordering::Greater => candidate,
        std::cmp::Ordering::Equal if candidate.bit_flips > current.bit_flips => candidate,
        _ => current,
    }
}

pub(super) fn corruption_rate(fault: &NetworkCorruptionFault) -> FaultRateBasisPoints {
    match fault {
        NetworkCorruptionFault::BitFlip { rate, .. }
        | NetworkCorruptionFault::FieldMutation { rate }
        | NetworkCorruptionFault::Truncation { rate, .. } => *rate,
    }
}

pub(super) fn network_corruption_strategy_cmp(
    left: &NetworkCorruptionFault,
    right: &NetworkCorruptionFault,
) -> std::cmp::Ordering {
    network_corruption_kind_order(left)
        .cmp(&network_corruption_kind_order(right))
        .then_with(|| left.canonical_material().cmp(&right.canonical_material()))
}

pub(super) fn network_corruption_kind_order(fault: &NetworkCorruptionFault) -> u8 {
    match fault {
        NetworkCorruptionFault::BitFlip { .. } => 0,
        NetworkCorruptionFault::FieldMutation { .. } => 1,
        NetworkCorruptionFault::Truncation { .. } => 2,
    }
}

pub(super) fn sort_rates_highest_first(rates: &mut [FaultRateBasisPoints]) {
    rates.sort_by(|left, right| right.cmp(left));
}

pub(super) fn saturating_offset_add(left: SimOffset, right: SimOffset) -> SimOffset {
    let sum = i128::from(left.nanos) + i128::from(right.nanos);
    SimOffset {
        nanos: sum.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
    }
}

pub(super) fn partition_direction_key(direction: PartitionDirection) -> &'static str {
    match direction {
        PartitionDirection::Bidirectional => "bidirectional",
        PartitionDirection::EndpointAToEndpointB => "endpoint-a-to-endpoint-b",
        PartitionDirection::EndpointBToEndpointA => "endpoint-b-to-endpoint-a",
    }
}

pub(super) fn restart_policy_key(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::FromReadyPoint => "from-ready-point",
        RestartPolicy::FromLastCheckpoint => "from-last-checkpoint",
        RestartPolicy::StayDown => "stay-down",
    }
}

pub(super) fn io_failure_mode_key(mode: IoFailureMode) -> &'static str {
    match mode {
        IoFailureMode::Drop => "drop",
        IoFailureMode::ErrorStatus => "error-status",
    }
}

pub(super) fn fault_link_material(link: &LinkId) -> String {
    format!("link_len={}\nlink={}", link.name.len(), link.name)
}

pub(super) fn fault_node_material(node: &NodeId) -> String {
    format!("node_len={}\nnode={}", node.name.len(), node.name)
}

pub(super) fn fault_device_material(device: &DeviceId) -> String {
    format!("device_len={}\ndevice={}", device.name.len(), device.name)
}

/// A membership-dynamics fault layered over a static [`World`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MembershipFault {
    /// Stop a declared node until the fault heals or its restart policy acts.
    Crash {
        /// The declared node that stops.
        node: NodeId,
        /// How the node restarts when the crash heals.
        restart: RestartPolicy,
    },
    /// Suppress delivery on a declared link without removing it from the world.
    Partition {
        /// One declared endpoint of the partitioned link.
        endpoint_a: NodeId,
        /// The other declared endpoint of the partitioned link.
        endpoint_b: NodeId,
        /// Direction of delivery suppression.
        direction: PartitionDirection,
    },
    /// Suppress all links incident to a declared node without removing the node.
    Isolate {
        /// The declared node held isolated.
        node: NodeId,
    },
    /// Hold a declared node inactive until a later heal/rejoin event.
    NotYetJoined {
        /// The declared participant that starts inactive.
        node: NodeId,
    },
    /// Carry a complete RFC-0010 fault-taxonomy value through the trigger path.
    Taxonomy {
        /// The full network, node, block, or 9p fault to activate.
        fault: Fault,
    },
}

impl MembershipFault {
    /// Wraps a complete RFC-0010 fault-taxonomy value for trigger injection.
    #[must_use]
    pub fn taxonomy(fault: Fault) -> Self {
        Self::Taxonomy { fault }
    }

    /// Returns the wrapped taxonomy fault, when this is not a legacy membership fault.
    #[must_use]
    pub fn as_taxonomy_fault(&self) -> Option<&Fault> {
        match self {
            Self::Taxonomy { fault } => Some(fault),
            Self::Crash { .. }
            | Self::Partition { .. }
            | Self::Isolate { .. }
            | Self::NotYetJoined { .. } => None,
        }
    }

    /// Returns the full-taxonomy value used by the active-fault table.
    #[must_use]
    pub fn table_fault(&self) -> Option<Fault> {
        match self {
            Self::Taxonomy { fault } => Some(fault.clone()),
            Self::Crash { node, restart } => Some(Fault::Node(NodeFault::Crash {
                node: node.clone(),
                restart: *restart,
            })),
            Self::Partition {
                endpoint_a,
                endpoint_b,
                direction,
            } => {
                let canonical = canonical_partition_fault(endpoint_a, endpoint_b, *direction);
                Some(Fault::Network(NetworkFault::Partition {
                    link: link_id_for_canonical_endpoint_pair(
                        &canonical.endpoint_a,
                        &canonical.endpoint_b,
                    ),
                    direction: canonical.direction,
                }))
            }
            Self::Isolate { .. } | Self::NotYetJoined { .. } => None,
        }
    }
}

pub(super) struct CanonicalPartitionFault {
    pub(super) endpoint_a: NodeId,
    pub(super) endpoint_b: NodeId,
    pub(super) direction: PartitionDirection,
}

pub(super) fn canonical_partition_fault(
    endpoint_a: &NodeId,
    endpoint_b: &NodeId,
    direction: PartitionDirection,
) -> CanonicalPartitionFault {
    if endpoint_a <= endpoint_b {
        CanonicalPartitionFault {
            endpoint_a: endpoint_a.clone(),
            endpoint_b: endpoint_b.clone(),
            direction,
        }
    } else {
        CanonicalPartitionFault {
            endpoint_a: endpoint_b.clone(),
            endpoint_b: endpoint_a.clone(),
            direction: inverted_partition_direction(direction),
        }
    }
}
