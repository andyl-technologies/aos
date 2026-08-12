//! Scheduling sub-nodes: the L3 seam that drives L1 I/O devices from the scheduler.
//!
//! Spec index: RFC-0010 file 15 (I/O sub-nodes) §15.1, file 08 (scheduling)
//! §8.4.1, §8.9.4.
//!
//! This module is the integration capstone that wires the `crucible-device` (L1)
//! block and 9p exact-completion sub-nodes into the
//! [`SingleScheduler`](crate::SingleScheduler) (L3) so that **cross-node I/O
//! injection is icount-deterministic** (Contract B, [IO-2], [IO-4],
//! [SCHED-29]). A [`DeviceSchedulingSubNode`] holds a concrete device's
//! [`IoCore`] — the in-flight queue of
//! computed-not-delivered responses — together with its scheduling identity.
//! Network-link sub-nodes have their own delivery
//! queue in `crucible-device`; their live latency changes enter the scheduler
//! through [`SingleScheduler::schedule_link_latency_recompute`](crate::SingleScheduler::schedule_link_latency_recompute).
//!
//! # The two scheduler couplings
//!
//! 1. **Horizon term.** A sub-node's
//!    [`next_exact_local_event`](DeviceSchedulingSubNode::next_exact_local_event)
//!    is its in-flight head's **final** (post-fault) `delivery_icount` ([IO-31]).
//!    The scheduler folds it into the owning VM node's
//!    [`ExactLocalEvent::IoCompletion`](crate::scheduler::ExactLocalEvent::IoCompletion)
//!    term, so an otherwise-idle requester is fast-forwarded **exactly** to its
//!    next I/O completion with no conservative slack ([IO-3], [SCHED-10]).
//! 2. **RESOLVE delivery.** When the requester's frontier reaches a completion's
//!    `delivery_icount`, [`DeviceSchedulingSubNode::deliver_due`] makes the
//!    response visible at exactly that icount in the canonical
//!    `(delivery_icount, src_node, seq)` total order ([IO-10], [SCHED-29]),
//!    transport-timing-independent. Signal-driven storage and 9p mutations are
//!    applied by the production adapters before completions enter this scheduler
//!    bridge; there is no second completion-fault table here.
//!
//! ```text
//! submit(req):  COMPUTE response -> buffer exact completion in the inflight queue
//! horizon:      next_exact_local_event() = inflight head delivery_icount
//! deliver_due(consumer_icount):
//!               for each completion with delivery_icount <= consumer_icount, in
//!               (delivery_icount, src_node, seq) order:
//!                 emit IoCompletion @ delivery_icount ; append its buffered decisions
//! ```

use std::collections::BTreeMap;

use crate::model::WorldCompletionDurability;
use crucible_device::block::{BlockCompletionDurability, BlockDurabilityConfig};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, DeviceError, FsTree, FsTreeDecodeError,
    IoCore, NinepDevice, NinepLatency, PendingResponse,
};

use crate::scheduler::IoCompletion;
use crate::{
    ContentHash, DagStore, DagStoreError, Decision, DeviceId, NodeId, SchedulerNodeId, Seed, World,
    WorldDeviceKind, WorldIoNodeKind,
};

mod checkpoint;
pub use checkpoint::{DeviceSchedulingSubNodeCheckpoint, DeviceSchedulingSubNodeCheckpointError};

/// Default physical request-ring capacity selected at instantiation time.
pub const DEFAULT_WORLD_IO_INBOX_CAPACITY: u64 = 256;

/// Default physical response-ring capacity selected at instantiation time.
pub const DEFAULT_WORLD_IO_OUTBOX_CAPACITY: u64 = 256;

/// Host/transport layout policy for instantiated World I/O nodes.
///
/// This value is intentionally not part of [`World`] or [`DeviceId`]. Changing
/// either capacity changes only physical buffering, never scenario identity
/// ([SPAT-14], [SPAT-15]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldIoLayoutPolicy {
    /// Physical inbound request-ring capacity for every instantiated I/O node.
    pub inbox_capacity: u64,
    /// Physical outbound response-ring capacity for every instantiated I/O node.
    pub outbox_capacity: u64,
}

impl Default for WorldIoLayoutPolicy {
    fn default() -> Self {
        Self {
            inbox_capacity: DEFAULT_WORLD_IO_INBOX_CAPACITY,
            outbox_capacity: DEFAULT_WORLD_IO_OUTBOX_CAPACITY,
        }
    }
}

/// One deterministic logical-to-physical I/O binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldIoRuntimeLayout {
    /// Numeric producer id derived from the canonical I/O-node order.
    pub source_node: u32,
    /// Physical inbound request-ring capacity.
    pub inbox_capacity: u64,
    /// Physical outbound response-ring capacity.
    pub outbox_capacity: u64,
}

/// Complete instantiation-time layout derived from a logical [`World`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldIoInstantiationLayout {
    bindings: BTreeMap<NodeId, WorldIoRuntimeLayout>,
}

impl WorldIoInstantiationLayout {
    /// Derives physical bindings from canonical I/O-node order and `policy`.
    ///
    /// The same World and policy always produce identical source numbers, while
    /// changing the policy leaves the World and every [`DeviceId`] unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`WorldIoLayoutError::InvalidRingCapacity`] when either capacity
    /// is zero or not a power of two, or [`WorldIoLayoutError::TooManyIoNodes`]
    /// when a source number cannot be represented as `u32`.
    pub fn derive(world: &World, policy: WorldIoLayoutPolicy) -> Result<Self, WorldIoLayoutError> {
        validate_layout_capacity("inbox", policy.inbox_capacity)?;
        validate_layout_capacity("outbox", policy.outbox_capacity)?;
        let mut bindings = BTreeMap::new();
        for (index, node) in world.io_nodes().enumerate() {
            let source_node = u32::try_from(index)
                .map_err(|_| WorldIoLayoutError::TooManyIoNodes { count: index })?;
            bindings.insert(
                node.id.clone(),
                WorldIoRuntimeLayout {
                    source_node,
                    inbox_capacity: policy.inbox_capacity,
                    outbox_capacity: policy.outbox_capacity,
                },
            );
        }
        Ok(Self { bindings })
    }

    /// Returns the derived physical binding for one I/O node.
    #[must_use]
    pub fn get(&self, node: &NodeId) -> Option<WorldIoRuntimeLayout> {
        self.bindings.get(node).copied()
    }

    /// Iterates all bindings in canonical node-id order.
    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &WorldIoRuntimeLayout)> {
        self.bindings.iter()
    }
}

/// Error returned while deriving a physical I/O layout.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WorldIoLayoutError {
    /// A physical ring capacity is zero or not a power of two.
    #[error("world I/O {ring} ring capacity {capacity} is not a nonzero power of two")]
    InvalidRingCapacity {
        /// Stable ring name (`inbox` or `outbox`).
        ring: &'static str,
        /// Rejected physical capacity.
        capacity: u64,
    },
    /// Canonical source-number assignment exceeded `u32`.
    #[error("world has too many I/O nodes for deterministic source numbering")]
    TooManyIoNodes {
        /// First node index that did not fit in `u32`.
        count: usize,
    },
    /// A layout derived for another topology lacks the requested I/O node.
    #[error("instantiation layout contains no binding for I/O node {node:?}")]
    MissingBinding {
        /// I/O node absent from the layout.
        node: NodeId,
    },
}

/// Validates one physical ring capacity.
fn validate_layout_capacity(ring: &'static str, capacity: u64) -> Result<(), WorldIoLayoutError> {
    if capacity == 0 || !capacity.is_power_of_two() {
        return Err(WorldIoLayoutError::InvalidRingCapacity { ring, capacity });
    }
    Ok(())
}

type ModeledKey = (u64, u32, u32);

/// One exact completion the device computed, ordered by its delivery key.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ModeledCompletion {
    /// The exact completion icount.
    modeled_icount: u64,
    /// The source-node id stamped into the delivery order key.
    src_node: u32,
    /// The per-completion sequence stamped by the device core.
    seq: u32,
    /// The exact response payload.
    payload: Vec<u8>,
}

impl ModeledCompletion {
    fn key(&self) -> ModeledKey {
        (self.modeled_icount, self.src_node, self.seq)
    }
}

/// One pending exact device completion.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingCompletion {
    /// The modeled completion this pending item came from.
    modeled_key: ModeledKey,
    /// The icount at which the response becomes visible ([IO-2]).
    delivery_icount: u64,
    /// The source-node id stamped into the delivery order key.
    src_node: u32,
    /// The per-completion sequence number, breaking same-icount ties.
    seq: u32,
    /// The deterministic response payload.
    payload: Option<Vec<u8>>,
    /// Scheduler decisions attached by the producing adapter.
    decisions: Vec<Decision>,
    /// Whether this item has already been drained through RESOLVE.
    delivered: bool,
}

impl PendingCompletion {
    fn delivery_key(&self) -> (u64, u32, u32) {
        (self.delivery_icount, self.src_node, self.seq)
    }
}

/// One due item drained from a device scheduling sub-node.
///
/// Items carry a visible [`IoCompletion`] and any deterministic decisions the
/// producing adapter attached, so the schedule records the
/// effect choice without fabricating a VM-visible response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceDelivery {
    /// The exact device icount at which this delivery item resolves.
    pub delivery_icount: u64,
    /// The scheduling sub-node that produced this delivery item.
    pub sub_node: SchedulerNodeId,
    /// The source-node id stamped into the device delivery order key.
    pub source_node: u32,
    /// The per-completion sequence stamped into the device delivery order key.
    pub sequence: u32,
    /// The completion emitted to the target VM, if the response was not dropped.
    pub completion: Option<IoCompletion>,
    /// The fault decisions this due item drew, recorded at RESOLVE.
    pub decisions: Vec<Decision>,
}

/// Error returned when a concrete runtime artifact cannot bind to a world I/O node.
#[derive(Debug, thiserror::Error)]
pub enum DeviceSubNodeBindingError {
    /// No first-class I/O node with the requested node id exists.
    #[error("world contains no I/O node named `{node}`")]
    UnknownIoNode {
        /// The undeclared I/O node id.
        node: String,
    },
    /// The selected world I/O node belongs to the other device family.
    #[error("world I/O node `{node}` is {actual:?}, not {expected:?}")]
    KindMismatch {
        /// The mismatched I/O node id.
        node: String,
        /// Family required by the binding function.
        expected: WorldDeviceKind,
        /// Family declared by the world.
        actual: WorldDeviceKind,
    },
    /// Supplied immutable artifact bytes do not match the world declaration.
    #[error("runtime artifact for world I/O node `{node}` has the wrong content hash")]
    ArtifactMismatch {
        /// The mismatched I/O node id.
        node: String,
        /// Content address declared by the world.
        expected: ContentHash,
        /// Content address recomputed from the supplied artifact.
        actual: ContentHash,
    },
    /// A supplied block image has the right hash declaration but the wrong length.
    #[error(
        "runtime block image for world I/O node `{node}` has length {actual}, expected {expected}"
    )]
    BlockLengthMismatch {
        /// The mismatched block I/O node id.
        node: String,
        /// Length declared by the world.
        expected: u64,
        /// Length observed from the supplied base image.
        actual: u64,
    },
    /// The logical clock plus derived runtime layout could not instantiate an I/O core.
    #[error("world I/O node `{node}` has an unusable derived runtime core: {source}")]
    RuntimeCore {
        /// The I/O node whose core failed to construct.
        node: String,
        /// Concrete runtime validation failure.
        #[source]
        source: DeviceError,
    },
    /// The exact World storage durability contract could not configure the device.
    #[error("world I/O node `{node}` has an unusable storage durability contract: {source}")]
    StorageConfiguration {
        /// I/O node whose storage contract failed.
        node: String,
        /// Concrete storage-state validation failure.
        #[source]
        source: DeviceError,
    },
    /// The physical instantiation layout is invalid or lacks this I/O node.
    #[error("world I/O node `{node}` has no valid instantiation-time layout: {source}")]
    Layout {
        /// I/O node whose physical binding could not be obtained.
        node: String,
        /// Layout derivation or lookup failure.
        #[source]
        source: WorldIoLayoutError,
    },
}

/// Error returned while resolving and instantiating all World I/O artifacts.
#[derive(Debug, thiserror::Error)]
pub enum WorldIoInstantiationError {
    /// Physical logical-to-runtime layout derivation failed.
    #[error("cannot derive World I/O runtime layout: {0}")]
    Layout(#[from] WorldIoLayoutError),
    /// A content-addressed artifact could not be read from the DAG store.
    #[error("cannot resolve artifact for World I/O node {node:?}: {source}")]
    ArtifactStore {
        /// I/O node whose immutable artifact was requested.
        node: NodeId,
        /// Underlying content-addressed store failure.
        #[source]
        source: DagStoreError,
    },
    /// Canonical 9p tree bytes failed structural or namespace validation.
    #[error("cannot decode canonical 9p artifact for World I/O node {node:?}: {source}")]
    NinePArtifactDecode {
        /// 9p I/O node whose tree artifact was invalid.
        node: NodeId,
        /// Canonical decoder failure.
        #[source]
        source: FsTreeDecodeError,
    },
    /// Resolved bytes did not bind to the logical World declaration.
    #[error("cannot bind World I/O node {node:?}: {source}")]
    Binding {
        /// I/O node whose concrete device could not be built.
        node: NodeId,
        /// Artifact, family, or runtime-core binding failure.
        #[source]
        source: Box<DeviceSubNodeBindingError>,
    },
}

/// Resolves and instantiates every block/9p sub-node declared by `world`.
///
/// Artifacts are fetched by their content address from `store`, decoded (for
/// 9p), re-hashed by the binding path, and attached to a physical layout derived
/// only at this instantiation boundary. Results follow canonical I/O-node order.
/// This is the production bridge from logical World declarations to concrete
/// [`DeviceSchedulingSubNode`] values.
///
/// # Errors
///
/// Returns [`WorldIoInstantiationError`] when physical layout derivation fails,
/// an artifact is missing/corrupt, canonical 9p decoding fails, or the resolved
/// bytes do not match the declared kind, hash, or block length.
pub fn instantiate_world_io_sub_nodes(
    world: &World,
    store: &dyn DagStore,
    seed: Seed,
    policy: WorldIoLayoutPolicy,
) -> Result<Vec<DeviceSchedulingSubNode>, WorldIoInstantiationError> {
    let layout = WorldIoInstantiationLayout::derive(world, policy)?;
    let mut sub_nodes = Vec::with_capacity(world.io_nodes().count());
    for node in world.io_nodes() {
        let artifact = match &node.kind {
            WorldIoNodeKind::Block { base_image, .. } => *base_image,
            WorldIoNodeKind::NineP { tree, .. } => *tree,
        };
        let bytes = store.get(&artifact.hash()).map_err(|source| {
            WorldIoInstantiationError::ArtifactStore {
                node: node.id.clone(),
                source,
            }
        })?;
        let sub_node = match &node.kind {
            WorldIoNodeKind::Block { .. } => DeviceSchedulingSubNode::bind_world_block_with_layout(
                world,
                &layout,
                &node.id,
                BaseImage::new(bytes),
                seed,
            ),
            WorldIoNodeKind::NineP { .. } => {
                let tree = FsTree::from_canonical_bytes(&bytes).map_err(|source| {
                    WorldIoInstantiationError::NinePArtifactDecode {
                        node: node.id.clone(),
                        source,
                    }
                })?;
                DeviceSchedulingSubNode::bind_world_ninep_with_layout(
                    world, &layout, &node.id, tree, seed,
                )
            }
        }
        .map_err(|source| WorldIoInstantiationError::Binding {
            node: node.id.clone(),
            source: Box::new(source),
        })?;
        sub_nodes.push(sub_node);
    }
    Ok(sub_nodes)
}

/// A disk/9p device modeled as a first-class scheduling sub-node ([IO-1]).
///
/// Holds a concrete block or 9p sub-node, its scheduling identity
/// ([`SchedulerNodeId`]), the target VM [`NodeId`] that observes its completions,
/// and the exact completions already produced by its authoritative adapter. The
/// scheduler reads
/// [`DeviceSchedulingSubNode::next_exact_local_event`] to bound the requester's
/// horizon and calls [`DeviceSchedulingSubNode::deliver_due`] at RESOLVE to make
/// completions visible at their exact icount.
#[derive(Clone, Debug)]
pub struct DeviceSchedulingSubNode {
    sub_node: SchedulerNodeId,
    target: NodeId,
    device_id: DeviceId,
    device: ScheduledDevice,
    /// The exact modeled completions, kept in delivery-key order.
    modeled: Vec<ModeledCompletion>,
    /// Every pending completion in `(delivery_icount, src_node, seq)` order.
    resolved: Vec<PendingCompletion>,
}

impl DeviceSchedulingSubNode {
    /// Binds and instantiates a declared block I/O node over `base`.
    ///
    /// The world is authoritative for scheduling identity, owning VM, logical
    /// clock, latency, and the base-image content address. Physical source/ring
    /// geometry is derived at this instantiation boundary. This function
    /// recomputes the supplied [`BaseImage`] hash and length before constructing
    /// the runtime device, so a plan-valid target cannot bind to unrelated bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSubNodeBindingError::UnknownIoNode`] when `node_id` is not a
    /// declared I/O node, [`DeviceSubNodeBindingError::KindMismatch`] for a 9p
    /// declaration, [`DeviceSubNodeBindingError::ArtifactMismatch`] or
    /// [`DeviceSubNodeBindingError::BlockLengthMismatch`] for artifact drift, and
    /// [`DeviceSubNodeBindingError::RuntimeCore`] if core construction fails.
    pub fn bind_world_block(
        world: &World,
        node_id: &NodeId,
        base: BaseImage,
        seed: Seed,
    ) -> Result<Self, DeviceSubNodeBindingError> {
        let layout = WorldIoInstantiationLayout::derive(world, WorldIoLayoutPolicy::default())
            .map_err(|source| DeviceSubNodeBindingError::Layout {
                node: node_id.name.clone(),
                source,
            })?;
        Self::bind_world_block_with_layout(world, &layout, node_id, base, seed)
    }

    /// Binds a declared block node using an explicit instantiation-time layout.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`DeviceSchedulingSubNode::bind_world_block`]
    /// and rejects a layout that does not contain the selected I/O node.
    pub fn bind_world_block_with_layout(
        world: &World,
        layout: &WorldIoInstantiationLayout,
        node_id: &NodeId,
        base: BaseImage,
        seed: Seed,
    ) -> Result<Self, DeviceSubNodeBindingError> {
        let node =
            world
                .io_node(node_id)
                .ok_or_else(|| DeviceSubNodeBindingError::UnknownIoNode {
                    node: node_id.name.clone(),
                })?;
        let WorldIoNodeKind::Block {
            base_image,
            base_length,
            latency,
        } = &node.kind
        else {
            return Err(DeviceSubNodeBindingError::KindMismatch {
                node: node.id.name.clone(),
                expected: WorldDeviceKind::Block,
                actual: node.kind.family(),
            });
        };
        let actual = ContentHash { bytes: base.hash() };
        if actual != base_image.hash() {
            return Err(DeviceSubNodeBindingError::ArtifactMismatch {
                node: node.id.name.clone(),
                expected: base_image.hash(),
                actual,
            });
        }
        if base.len() != *base_length {
            return Err(DeviceSubNodeBindingError::BlockLengthMismatch {
                node: node.id.name.clone(),
                expected: *base_length,
                actual: base.len(),
            });
        }
        let runtime_layout =
            layout
                .get(&node.id)
                .ok_or_else(|| DeviceSubNodeBindingError::Layout {
                    node: node.id.name.clone(),
                    source: WorldIoLayoutError::MissingBinding {
                        node: node.id.clone(),
                    },
                })?;
        let core = world_io_core(node, runtime_layout).map_err(|source| {
            DeviceSubNodeBindingError::RuntimeCore {
                node: node.id.name.clone(),
                source,
            }
        })?;
        let latency = BlockLatency::new(
            latency.read_base_ns,
            latency.write_base_ns,
            latency.flush_ns,
            latency.get_length_ns,
            latency.per_byte_ns,
        );
        let mut device = BlockDevice::new(core, base, latency);
        if let Some(storage) = world
            .fault_topology()
            .storage_devices
            .iter()
            .find(|storage| storage.device.as_str() == node.id.name.as_str())
        {
            let completion_durability = match storage.persistence.completion_durability {
                WorldCompletionDurability::ControllerAccepted => {
                    BlockCompletionDurability::ControllerAccepted
                }
                WorldCompletionDurability::VolatileCacheAccepted => {
                    BlockCompletionDurability::VolatileCacheAccepted
                }
                WorldCompletionDurability::Durable => BlockCompletionDurability::Durable,
            };
            device
                .configure_storage_faults(
                    BlockDurabilityConfig {
                        length_bytes: storage.persistence.length_bytes,
                        atomic_write_bytes: storage.persistence.atomic_write_bytes,
                        maximum_request_bytes: storage.persistence.maximum_request_bytes,
                        discard_granularity_bytes: storage.persistence.discard_granularity_bytes,
                        discard_semantics: match storage.persistence.discard_semantics {
                            crate::model::WorldDiscardSemantics::DeterministicZero => {
                                crucible_device::block::BlockDiscardSemantics::DeterministicZero
                            }
                            crate::model::WorldDiscardSemantics::ReadsOldData => {
                                crucible_device::block::BlockDiscardSemantics::ReadsOldData
                            }
                            crate::model::WorldDiscardSemantics::UndefinedRecorded => {
                                crucible_device::block::BlockDiscardSemantics::UndefinedKeyed
                            }
                        },
                        volatile_cache_bytes: storage.persistence.volatile_cache_bytes,
                        cache_entries: storage.persistence.cache_entries,
                        controller_buffer_bytes: storage.persistence.controller_buffer_bytes,
                        controller_entries: storage.persistence.controller_entries,
                        persistence_dependencies: storage.persistence.persistence_dependencies,
                        retained_versions: u32::from(
                            storage.persistence.retained_versions_per_interval,
                        ),
                        completion_durability,
                    },
                    false,
                )
                .map_err(|source| DeviceSubNodeBindingError::StorageConfiguration {
                    node: node.id.name.clone(),
                    source,
                })?;
        }
        Ok(Self::new(
            node.scheduler_node_id(),
            node.owner.clone(),
            node.device_id(),
            device,
            seed,
        ))
    }

    /// Binds and instantiates a declared 9p I/O node over `tree`.
    ///
    /// The supplied [`FsTree`] is hashed through its versioned canonical artifact
    /// encoding and must match the world declaration before the concrete 9p server
    /// is built.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSubNodeBindingError::UnknownIoNode`] when `node_id` is not a
    /// declared I/O node, [`DeviceSubNodeBindingError::KindMismatch`] for a block
    /// declaration, [`DeviceSubNodeBindingError::ArtifactMismatch`] for tree drift,
    /// and [`DeviceSubNodeBindingError::RuntimeCore`] if core construction fails.
    pub fn bind_world_ninep(
        world: &World,
        node_id: &NodeId,
        tree: FsTree,
        seed: Seed,
    ) -> Result<Self, DeviceSubNodeBindingError> {
        let layout = WorldIoInstantiationLayout::derive(world, WorldIoLayoutPolicy::default())
            .map_err(|source| DeviceSubNodeBindingError::Layout {
                node: node_id.name.clone(),
                source,
            })?;
        Self::bind_world_ninep_with_layout(world, &layout, node_id, tree, seed)
    }

    /// Binds a declared 9p node using an explicit instantiation-time layout.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`DeviceSchedulingSubNode::bind_world_ninep`]
    /// and rejects a layout that does not contain the selected I/O node.
    pub fn bind_world_ninep_with_layout(
        world: &World,
        layout: &WorldIoInstantiationLayout,
        node_id: &NodeId,
        tree: FsTree,
        seed: Seed,
    ) -> Result<Self, DeviceSubNodeBindingError> {
        let node =
            world
                .io_node(node_id)
                .ok_or_else(|| DeviceSubNodeBindingError::UnknownIoNode {
                    node: node_id.name.clone(),
                })?;
        let WorldIoNodeKind::NineP {
            tree: artifact,
            latency,
        } = &node.kind
        else {
            return Err(DeviceSubNodeBindingError::KindMismatch {
                node: node.id.name.clone(),
                expected: WorldDeviceKind::NineP,
                actual: node.kind.family(),
            });
        };
        let actual = ContentHash {
            bytes: tree.content_hash(),
        };
        if actual != artifact.hash() {
            return Err(DeviceSubNodeBindingError::ArtifactMismatch {
                node: node.id.name.clone(),
                expected: artifact.hash(),
                actual,
            });
        }
        let runtime_layout =
            layout
                .get(&node.id)
                .ok_or_else(|| DeviceSubNodeBindingError::Layout {
                    node: node.id.name.clone(),
                    source: WorldIoLayoutError::MissingBinding {
                        node: node.id.clone(),
                    },
                })?;
        let core = world_io_core(node, runtime_layout).map_err(|source| {
            DeviceSubNodeBindingError::RuntimeCore {
                node: node.id.name.clone(),
                source,
            }
        })?;
        let latency = NinepLatency::new(latency.control_ns, latency.data_ns, latency.per_byte_ns);
        Ok(Self::new_ninep(
            node.scheduler_node_id(),
            node.owner.clone(),
            node.device_id(),
            NinepDevice::new(core, tree, latency),
            seed,
        ))
    }

    /// Builds a scheduling sub-node over a block device for a target VM node.
    ///
    /// `sub_node` is the device's scheduling identity (the event producer);
    /// `target` is the VM node whose horizon the device's completions bound and
    /// which observes them. The seed argument is retained as part of the general
    /// world-instantiation signature; fault randomness is owned by signal bindings.
    #[must_use]
    pub fn new(
        sub_node: SchedulerNodeId,
        target: NodeId,
        device_id: DeviceId,
        device: BlockDevice,
        _seed: Seed,
    ) -> Self {
        Self {
            sub_node,
            target,
            device_id,
            device: ScheduledDevice::Block(Box::new(device)),
            modeled: Vec::new(),
            resolved: Vec::new(),
        }
    }

    /// Builds a scheduling sub-node over a 9p device for a target VM node.
    ///
    /// This is the filesystem twin of [`DeviceSchedulingSubNode::new`]: the same
    /// scheduler-facing machinery owns the device and exposes its exact in-flight
    /// head as the requester's local event.
    #[must_use]
    pub fn new_ninep(
        sub_node: SchedulerNodeId,
        target: NodeId,
        device_id: DeviceId,
        device: NinepDevice,
        _seed: Seed,
    ) -> Self {
        Self {
            sub_node,
            target,
            device_id,
            device: ScheduledDevice::Ninep(Box::new(device)),
            modeled: Vec::new(),
            resolved: Vec::new(),
        }
    }

    /// Returns the device's scheduling-graph identity (the completion producer).
    #[must_use]
    pub fn sub_node(&self) -> &SchedulerNodeId {
        &self.sub_node
    }

    /// Returns the VM node whose horizon this device's completions bound ([IO-3]).
    #[must_use]
    pub fn target(&self) -> &NodeId {
        &self.target
    }

    /// Returns the device's content-addressed identity ([IO-26]).
    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Returns a shared view of the held block device, when this is a disk sub-node.
    #[must_use]
    pub fn block_device(&self) -> Option<&BlockDevice> {
        match &self.device {
            ScheduledDevice::Block(device) => Some(device),
            ScheduledDevice::Ninep(_) => None,
        }
    }

    /// Returns a shared view of the held block device, when this is a disk sub-node.
    ///
    /// This migration accessor is equivalent to
    /// [`DeviceSchedulingSubNode::block_device`]. It returns `None` for a 9p
    /// sub-node because [`DeviceSchedulingSubNode`] now owns either concrete
    /// device kind. New code should use [`DeviceSchedulingSubNode::block_device`]
    /// or [`DeviceSchedulingSubNode::ninep_device`] so the expected concrete
    /// device kind is visible at the call site.
    #[must_use]
    pub fn device(&self) -> Option<&BlockDevice> {
        self.block_device()
    }

    /// Returns a shared view of the held 9p device, when this is a filesystem sub-node.
    #[must_use]
    pub fn ninep_device(&self) -> Option<&NinepDevice> {
        match &self.device {
            ScheduledDevice::Block(_) => None,
            ScheduledDevice::Ninep(device) => Some(device),
        }
    }

    /// Submits a block request at `request_icount` and COMPUTEs its completion.
    ///
    /// Computes the exact `(delivery_icount, payload)` through the device and
    /// records it in delivery-key order. The device's own clock
    /// is never advanced here; delivery is driven solely by the scheduler through
    /// [`DeviceSchedulingSubNode::deliver_due`].
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the device cannot encode the request, when its
    /// inbound ring is full ([IO-32]), or when its COMPUTE step fails (a
    /// clock/overflow/past-delivery guard). Returns
    /// [`DeviceError::WrongDeviceKind`] when called on a 9p sub-node.
    pub fn submit(
        &mut self,
        request_icount: u64,
        request: &BlockRequest,
    ) -> Result<(), DeviceError> {
        self.device.submit_block(request_icount, request)?;
        self.collect_modeled_completions();
        self.resolve_all();
        Ok(())
    }

    /// Submits a raw 9p request frame at `request_icount` and COMPUTEs its reply.
    ///
    /// This mirrors [`DeviceSchedulingSubNode::submit`] for the 9p sub-node:
    /// COMPUTE pins the exact modeled reply and
    /// [`DeviceSchedulingSubNode::deliver_due`] later makes it visible.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the 9p device cannot enqueue or COMPUTE the
    /// frame, including ring-full backpressure and clock/overflow guards. Returns
    /// [`DeviceError::WrongDeviceKind`] when called on a block sub-node.
    pub fn submit_ninep_frame(
        &mut self,
        request_icount: u64,
        frame: &[u8],
    ) -> Result<(), DeviceError> {
        self.device.submit_ninep(request_icount, frame)?;
        self.collect_modeled_completions();
        self.resolve_all();
        Ok(())
    }

    /// Pulls newly modeled completions out of the held device in canonical order.
    fn collect_modeled_completions(&mut self) {
        // Pull every modeled completion the device has COMPUTEd into the modeled
        // set (deduplicated by delivery key), keeping it in delivery-key order so
        // fault resolution is submit-order-independent.
        for modeled in self.device.inflight() {
            let candidate = ModeledCompletion {
                modeled_icount: modeled.key.delivery_icount,
                src_node: modeled.key.src_node,
                seq: modeled.key.seq,
                payload: modeled.response.payload,
            };
            if self.modeled.iter().any(|existing| {
                existing.modeled_icount == candidate.modeled_icount
                    && existing.src_node == candidate.src_node
                    && existing.seq == candidate.seq
            }) {
                continue;
            }
            let pos = self.modeled.partition_point(|existing| {
                (existing.modeled_icount, existing.src_node, existing.seq)
                    <= (candidate.modeled_icount, candidate.src_node, candidate.seq)
            });
            self.modeled.insert(pos, candidate);
        }
    }

    /// Rebuilds exact pending completions in canonical delivery order.
    fn resolve_all(&mut self) {
        let mut resolved = self
            .resolved
            .iter()
            .filter(|completion| completion.delivered)
            .cloned()
            .collect::<Vec<_>>();
        for modeled in &self.modeled {
            if resolved
                .iter()
                .any(|completion| completion.modeled_key == modeled.key())
            {
                continue;
            }
            resolved.push(PendingCompletion {
                modeled_key: modeled.key(),
                delivery_icount: modeled.modeled_icount,
                src_node: modeled.src_node,
                seq: modeled.seq,
                payload: Some(modeled.payload.clone()),
                decisions: Vec::new(),
                delivered: false,
            });
        }
        resolved.sort_by_key(PendingCompletion::delivery_key);
        self.resolved = resolved;
    }

    /// Returns the next not-yet-delivered completion's final delivery icount: the
    /// sub-node's next exact local event ([IO-31], [SCHED-10]).
    ///
    /// This is what the scheduler folds into the owning VM node's
    /// [`ExactLocalEvent::IoCompletion`](crate::scheduler::ExactLocalEvent::IoCompletion)
    /// term, so an idle requester is fast-forwarded exactly to its next I/O
    /// completion.
    /// Returns `None` when nothing is in flight.
    #[must_use]
    pub fn next_exact_local_event(&self) -> Option<u64> {
        self.resolved
            .iter()
            .find(|completion| !completion.delivered)
            .map(|head| head.delivery_icount)
    }

    /// DELIVERs every completion due at or before `consumer_icount` in canonical
    /// order, emitting [`IoCompletion`] events and the fault decisions they drew
    /// (RFC-0010 [SCHED-29], [SCHED-30], §8.9.4).
    ///
    /// A completion is **made visible at exactly its `delivery_icount`** — never
    /// at the consumer's later frontier — in the `(delivery_icount, src_node,
    /// seq)` total order ([IO-10], [SCHED-15]), independent of host or transport
    /// timing (Contract B). Each delivered completion contributes its buffered
    /// fault [`Decision`]s, in delivery order, so the recorded schedule is
    /// appended in the §8.6 total order ([SCHED-30]). Future completions stay in
    /// flight at their exact icounts.
    ///
    /// Returns the `(event, decisions)` pairs in delivery order.
    #[must_use]
    pub fn deliver_due(&mut self, consumer_icount: u64) -> Vec<DeviceDelivery> {
        let mut delivered = Vec::new();
        for completion in &mut self.resolved {
            if completion.delivered {
                continue;
            }
            if completion.delivery_icount > consumer_icount {
                break;
            }
            let event = completion.payload.as_ref().map(|payload| IoCompletion {
                sub_node: self.sub_node.clone(),
                target: self.target.clone(),
                delivery_icount: crate::Icount {
                    retired: completion.delivery_icount,
                },
                payload: payload.clone(),
            });
            delivered.push(DeviceDelivery {
                delivery_icount: completion.delivery_icount,
                sub_node: self.sub_node.clone(),
                source_node: completion.src_node,
                sequence: completion.seq,
                completion: event,
                decisions: completion.decisions.clone(),
            });
            completion.delivered = true;
        }
        delivered
    }
}

/// Builds the concrete uniform I/O core from one validated world I/O node.
fn world_io_core(
    node: &crate::WorldIoNode,
    layout: WorldIoRuntimeLayout,
) -> Result<IoCore, DeviceError> {
    IoCore::new(
        node.core.shift_bits,
        layout.source_node,
        layout.inbox_capacity,
        layout.outbox_capacity,
    )
}

/// The concrete device a scheduler sub-node owns.
///
/// The scheduler bridge treats block and 9p uniformly after COMPUTE: each
/// exposes modeled in-flight completions, an active fault table, and a fixed
/// clock shift. The concrete request submission step remains device-specific.
#[derive(Clone, Debug)]
enum ScheduledDevice {
    /// A block device sub-node.
    Block(Box<BlockDevice>),
    /// A 9p filesystem sub-node.
    Ninep(Box<NinepDevice>),
}

impl ScheduledDevice {
    /// Submits a block request to the held device.
    fn submit_block(
        &mut self,
        request_icount: u64,
        request: &BlockRequest,
    ) -> Result<(), DeviceError> {
        match self {
            ScheduledDevice::Block(device) => device.submit(request_icount, request),
            ScheduledDevice::Ninep(_) => Err(DeviceError::WrongDeviceKind {
                expected: "block",
                actual: "9p",
            }),
        }
    }

    /// Submits a 9p frame to the held device.
    fn submit_ninep(&mut self, request_icount: u64, frame: &[u8]) -> Result<(), DeviceError> {
        match self {
            ScheduledDevice::Block(_) => Err(DeviceError::WrongDeviceKind {
                expected: "9p",
                actual: "block",
            }),
            ScheduledDevice::Ninep(device) => device.submit(request_icount, frame),
        }
    }

    /// Returns the modeled in-flight completions currently held by the device.
    fn inflight(&self) -> Vec<PendingResponse> {
        match self {
            ScheduledDevice::Block(device) => device.core().snapshot().inflight,
            ScheduledDevice::Ninep(device) => device.core().snapshot().inflight,
        }
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- unit-test fixtures and assertions fail loudly.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crucible_device::ninep::codec;
    use crucible_device::{
        BaseImage, BlockLatency, FsTree, IoCore, NinepDevice, NinepLatency, Node,
    };

    use crate::SchedulingNodeKind;

    fn device_id(name: &str) -> DeviceId {
        DeviceId {
            name: name.to_owned(),
        }
    }

    fn node_id(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn sub_node_id(name: &str) -> SchedulerNodeId {
        SchedulerNodeId {
            node: node_id(name),
            kind: SchedulingNodeKind::Disk,
        }
    }

    fn ninep_sub_node_id(name: &str) -> SchedulerNodeId {
        SchedulerNodeId {
            node: node_id(name),
            kind: SchedulingNodeKind::NineP,
        }
    }

    /// Builds a fault-free disk sub-node over a small base image.
    fn fresh_disk(seed: Seed) -> DeviceSchedulingSubNode {
        let core = match IoCore::new(0, 7, 16, 16) {
            Ok(core) => core,
            Err(error) => panic!("io core should construct: {error}"),
        };
        let base = BaseImage::new(vec![0xab; 4096]);
        let device = BlockDevice::new(core, base, BlockLatency::default());
        DeviceSchedulingSubNode::new(
            sub_node_id("disk-sub"),
            node_id("vm-a"),
            device_id("disk"),
            device,
            seed,
        )
    }

    /// Builds a 9p sub-node over a read-only tree.
    fn fresh_ninep(seed: Seed) -> DeviceSchedulingSubNode {
        let core = match IoCore::new(0, 9, 16, 16) {
            Ok(core) => core,
            Err(error) => panic!("io core should construct: {error}"),
        };
        let mut root = BTreeMap::new();
        root.insert(
            "alpha".to_owned(),
            Node::File {
                content: b"alpha".to_vec(),
            },
        );
        let tree = FsTree::try_new(Node::Directory { children: root })
            .expect("test 9p tree components are valid");
        let device = NinepDevice::new(core, tree, NinepLatency::default());
        DeviceSchedulingSubNode::new_ninep(
            ninep_sub_node_id("ninep-sub"),
            node_id("vm-a"),
            device_id("fs"),
            device,
            seed,
        )
    }

    fn read_request(request_id: u32, offset: u64, count: u32) -> BlockRequest {
        BlockRequest::read(request_id, offset, count)
    }

    fn frame(msg_type: u8, tag: u16, body: &[u8]) -> Vec<u8> {
        let size = (codec::HEADER_LEN + body.len()) as u32;
        let mut frame = Vec::new();
        frame.extend_from_slice(&size.to_le_bytes());
        frame.push(msg_type);
        frame.extend_from_slice(&tag.to_le_bytes());
        frame.extend_from_slice(body);
        frame
    }

    fn string_bytes(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }

    fn tversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
        let mut body = msize.to_le_bytes().to_vec();
        body.extend_from_slice(&string_bytes(version));
        frame(codec::TVERSION, tag, &body)
    }

    #[test]
    fn next_exact_local_event_is_the_inflight_head_final_icount() {
        let mut disk = fresh_disk(Seed::from_u64(0xd15c));
        // Two reads at different request icounts -> two completions in flight.
        disk.submit(0, &read_request(1, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
        disk.submit(100, &read_request(2, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));

        let head = disk
            .next_exact_local_event()
            .unwrap_or_else(|| panic!("a completion must be in flight"));
        // The earlier request completes first (lower delivery icount).
        let second = disk
            .resolved
            .get(1)
            .unwrap_or_else(|| panic!("two completions in flight"))
            .delivery_icount;
        assert!(head < second, "head is the earliest completion");
    }

    #[test]
    fn deliver_due_makes_completions_visible_at_exact_icount_in_order() {
        let mut disk = fresh_disk(Seed::from_u64(0xd15c));
        disk.submit(0, &read_request(1, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
        let delivery = disk
            .next_exact_local_event()
            .unwrap_or_else(|| panic!("a completion must be in flight"));

        // Below the delivery icount: nothing is visible.
        assert!(disk.deliver_due(delivery - 1).is_empty());
        // At exactly the delivery icount: the completion becomes visible.
        let delivered = disk.deliver_due(delivery);
        assert_eq!(delivered.len(), 1);
        let event = delivered[0]
            .completion
            .as_ref()
            .unwrap_or_else(|| panic!("fault-free delivery should emit a completion"));
        assert_eq!(event.delivery_icount.retired, delivery);
        assert_eq!(event.target, node_id("vm-a"));
        assert!(disk.next_exact_local_event().is_none());
    }

    #[test]
    fn wrong_request_kind_fails_loudly_without_computing() {
        let mut fs = fresh_ninep(Seed::from_u64(0x9f5));
        let result = fs.submit(0, &read_request(1, 0, 8));
        assert!(matches!(
            result,
            Err(DeviceError::WrongDeviceKind {
                expected: "block",
                actual: "9p"
            })
        ));
        assert!(fs.next_exact_local_event().is_none());

        let mut disk = fresh_disk(Seed::from_u64(0xd15c));
        let result = disk.submit_ninep_frame(0, &tversion(7, 4096, codec::PROTOCOL_VERSION));
        assert!(matches!(
            result,
            Err(DeviceError::WrongDeviceKind {
                expected: "9p",
                actual: "block"
            })
        ));
        assert!(disk.next_exact_local_event().is_none());
    }

    #[test]
    fn block_sub_node_checkpoint_round_trips_pending_completion() {
        let seed = Seed::from_u64(0xd15c);
        let mut disk = fresh_disk(seed);
        disk.submit(41, &read_request(7, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
        let checkpoint = disk.checkpoint();
        let bytes = checkpoint
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("sub-node checkpoint should encode: {error}"));
        let decoded = DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("sub-node checkpoint should decode: {error}"));
        let mut restored = fresh_disk(seed);
        restored
            .restore_checkpoint(&decoded)
            .unwrap_or_else(|error| panic!("sub-node checkpoint should restore: {error}"));

        assert_eq!(restored.checkpoint(), checkpoint);
        assert_eq!(
            decoded
                .canonical_bytes()
                .unwrap_or_else(|error| panic!("decoded checkpoint should encode: {error}")),
            bytes
        );
    }

    #[test]
    fn ninep_sub_node_checkpoint_round_trips_protocol_state() {
        let seed = Seed::from_u64(0x9f5);
        let mut fs = fresh_ninep(seed);
        fs.submit_ninep_frame(19, &tversion(3, 4096, codec::PROTOCOL_VERSION))
            .unwrap_or_else(|error| panic!("9p submit should succeed: {error}"));
        let checkpoint = fs.checkpoint();
        let bytes = checkpoint
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("9p sub-node checkpoint should encode: {error}"));
        let decoded = DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("9p sub-node checkpoint should decode: {error}"));
        let mut restored = fresh_ninep(seed);
        restored
            .restore_checkpoint(&decoded)
            .unwrap_or_else(|error| panic!("9p sub-node checkpoint should restore: {error}"));

        assert_eq!(restored.checkpoint(), checkpoint);
    }
}
