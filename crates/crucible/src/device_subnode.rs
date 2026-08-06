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
//! computed-not-delivered responses — together with its scheduling identity and
//! the per-device fault table. Network-link sub-nodes have their own delivery
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
//!    transport-timing-independent, and appends the per-device fault
//!    [`Decision`]s the completion drew ([SCHED-30]).
//!
//! # When effect choices are drawn vs recorded
//!
//! A probabilistic device fault (jitter/reorder/loss/duplicate/corrupt/bandwidth)
//! is **drawn from the per-device RNG at COMPUTE**, when
//! [`DeviceSchedulingSubNode::submit`] resolves the modeled completion through
//! [`crucible_device::IoFaults::resolve`]. Drawing at COMPUTE is what lets the
//! perturbed (final) `delivery_icount` enter the in-flight queue, so the horizon
//! term the scheduler reads is the **exact** completion the requester will
//! observe — never a pre-fault estimate the run would then have to deliver late.
//! The raw draws and effect outcomes are buffered with the pending completion and
//! **recorded as [`Decision`]s on the RESOLVE path**, in delivery
//! order, so the recorded schedule is appended in the §8.6 total order exactly as
//! [`resolve_frame`](crate::scheduler) records a link-loss outcome ([SCHED-30]).
//!
//! ```text
//! submit(req):  COMPUTE response -> IoFaults::resolve(rng)  -> final delivery_icount
//!               buffer { delivery_icount, payload, decisions } in the inflight queue
//! horizon:      next_exact_local_event() = inflight head final delivery_icount
//! deliver_due(consumer_icount):
//!               for each completion with delivery_icount <= consumer_icount, in
//!               (delivery_icount, src_node, seq) order:
//!                 emit IoCompletion @ delivery_icount ; append its buffered decisions
//! ```

mod reseed;

use std::collections::{BTreeMap, BTreeSet};

use crucible_device::ninep::codec as ninep_codec;
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, BlockResponse, DeviceError, FsTree,
    FsTreeDecodeError, IoCore, IoFaults, NinepDevice, NinepLatency, PendingResponse,
    ResponseStatus,
};

use crate::scheduler::{IoCompletion, SchedulerDiscardedIoCompletion};
use crate::{
    ContentHash, DagStore, DagStoreError, Decision, DeviceId, EffectOutcomeDecision, FaultId,
    NodeId, RngDecision, SchedulerNodeId, Seed, World, WorldDeviceKind, WorldIoNodeKind,
};

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

/// High-bit tie-break namespace for duplicate-fault completions.
///
/// A duplicate response shares its primary's `src_node` and is delivered a fixed
/// gap later, but it must never collide with a *sibling* request's primary `seq`
/// in the `(delivery_icount, src_node, seq)` order. Primary `seq` values are small
/// sequential request counts from the device core, so OR-ing this top bit places
/// every duplicate in a disjoint namespace.
const DUPLICATE_SEQ_NAMESPACE: u32 = 1 << 31;

type ModeledKey = (u64, u32, u32);

/// One modeled (pre-fault) completion the device COMPUTEd, ordered by its
/// modeled delivery key. Fault resolution is a pure function of the *sorted* set
/// of these, so COMPUTE/submit order never affects the result ([IO-4]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ModeledCompletion {
    /// The modeled (pre-fault) completion icount.
    modeled_icount: u64,
    /// The source-node id stamped into the delivery order key.
    src_node: u32,
    /// The per-completion sequence stamped by the device core.
    seq: u32,
    /// The modeled response status.
    status: ResponseStatus,
    /// The modeled response payload.
    payload: Vec<u8>,
}

impl ModeledCompletion {
    fn key(&self) -> ModeledKey {
        (self.modeled_icount, self.src_node, self.seq)
    }
}

/// One pending device completion: its final delivery icount, payload, and the
/// fault decisions it drew (recorded at RESOLVE, [SCHED-30]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingCompletion {
    /// The modeled completion this resolved item came from.
    modeled_key: ModeledKey,
    /// The post-fault icount at which the response becomes visible ([IO-2]).
    delivery_icount: u64,
    /// The source-node id stamped into the delivery order key.
    src_node: u32,
    /// The per-completion sequence number, breaking same-icount ties.
    seq: u32,
    /// The deterministic response payload, or `None` for a drop-mode failure.
    payload: Option<Vec<u8>>,
    /// The fault [`Decision`]s this completion drew, recorded at RESOLVE in
    /// delivery order ([SCHED-30]).
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
/// Most items carry a visible [`IoCompletion`]. Drop-mode block failures carry
/// only the buffered fault decisions so the schedule records the deterministic
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
        source: DeviceSubNodeBindingError,
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
            source,
        })?;
        sub_nodes.push(sub_node);
    }
    Ok(sub_nodes)
}

/// A disk/9p device modeled as a first-class scheduling sub-node ([IO-1]).
///
/// Holds a concrete block or 9p sub-node, its scheduling identity
/// ([`SchedulerNodeId`]), the target VM [`NodeId`] that observes its completions,
/// and the seeded per-device RNG forked by name-hash from the scenario seed
/// ([IO-21], [DET-25]). The scheduler reads
/// [`DeviceSchedulingSubNode::next_exact_local_event`] to bound the requester's
/// horizon and calls [`DeviceSchedulingSubNode::deliver_due`] at RESOLVE to make
/// completions visible at their exact icount.
#[derive(Clone, Debug)]
pub struct DeviceSchedulingSubNode {
    sub_node: SchedulerNodeId,
    target: NodeId,
    device_id: DeviceId,
    device: ScheduledDevice,
    seed: Seed,
    /// The modeled (pre-fault) completions, kept in delivery-key order. Fault
    /// resolution recomputes [`resolved`] from this set, so the result is a pure
    /// function of the sorted set and never depends on submit/COMPUTE order
    /// ([IO-4]).
    modeled: Vec<ModeledCompletion>,
    /// Every modeled completion resolved through the fault table in delivery
    /// order, recomputed whenever [`modeled`] grows. Ordered by
    /// `(delivery_icount, src_node, seq)`.
    resolved: Vec<PendingCompletion>,
    /// Modeled completions whose resolved outcomes must not be recomputed after
    /// at least one delivery has become visible.
    frozen_modeled: BTreeSet<ModeledKey>,
    /// Device RNG position after every frozen modeled completion.
    frozen_rng_position: Option<u64>,
    /// The device RNG cursor after resolving every modeled completion ([IO-23]).
    rng_position: u64,
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
        Ok(Self::new(
            node.scheduler_node_id(),
            node.owner.clone(),
            node.device_id(),
            BlockDevice::new(core, base, latency),
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
    /// The sub-node owns the device and a seeded per-device RNG forked by
    /// name-hash from `seed` for `device_id` ([IO-21]). `sub_node` is the
    /// device's scheduling identity (the event producer); `target` is the VM node
    /// whose horizon the device's completions bound and which observes them.
    #[must_use]
    pub fn new(
        sub_node: SchedulerNodeId,
        target: NodeId,
        device_id: DeviceId,
        device: BlockDevice,
        seed: Seed,
    ) -> Self {
        Self {
            sub_node,
            target,
            device_id,
            device: ScheduledDevice::Block(device),
            seed,
            modeled: Vec::new(),
            resolved: Vec::new(),
            frozen_modeled: BTreeSet::new(),
            frozen_rng_position: None,
            rng_position: 0,
        }
    }

    /// Builds a scheduling sub-node over a 9p device for a target VM node.
    ///
    /// This is the filesystem twin of [`DeviceSchedulingSubNode::new`]: the same
    /// scheduler-facing machinery owns the device, resolves its completion faults
    /// through the per-device RNG, records the resulting decisions, and exposes
    /// the final post-fault in-flight head as the requester's exact local event.
    /// Keeping 9p on the same path as block is the load-bearing uniformity claim
    /// of [IO-25] and [IO-26].
    #[must_use]
    pub fn new_ninep(
        sub_node: SchedulerNodeId,
        target: NodeId,
        device_id: DeviceId,
        device: NinepDevice,
        seed: Seed,
    ) -> Self {
        Self {
            sub_node,
            target,
            device_id,
            device: ScheduledDevice::Ninep(device),
            seed,
            modeled: Vec::new(),
            resolved: Vec::new(),
            frozen_modeled: BTreeSet::new(),
            frozen_rng_position: None,
            rng_position: 0,
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

    /// Returns the seeded per-device RNG cursor (draws consumed so far, [IO-23]).
    #[must_use]
    pub fn rng_position(&self) -> u64 {
        self.rng_position
    }

    /// Returns the active I/O fault table installed on this sub-node.
    #[must_use]
    pub fn io_faults(&self) -> &IoFaults {
        self.device.faults()
    }

    /// Installs an active I/O fault table on this sub-node.
    ///
    /// Existing modeled completions are recomputed immediately so the in-flight
    /// horizon and RESOLVE delivery reflect the live fault set.
    pub fn set_io_faults(&mut self, faults: IoFaults) {
        self.device.set_faults(faults);
        if self.resolved.iter().any(|completion| completion.delivered) {
            self.frozen_modeled
                .extend(self.modeled.iter().map(ModeledCompletion::key));
            self.frozen_rng_position = Some(self.rng_position);
        }
        self.resolve_all();
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
    /// COMPUTEs the modeled `(delivery_icount, status, payload)` through the
    /// device and records it in delivery-key order. Fault resolution — which
    /// fixes the **final** (post-fault) `delivery_icount` the horizon reads and
    /// draws every probabilistic choice from the per-device RNG — is deferred to
    /// `DeviceSchedulingSubNode::resolve_all`, run over the *sorted* modeled set,
    /// so the result is a pure function of the request set and the seed and is
    /// **independent of the COMPUTE/submit order** ([IO-4]). The device's own clock
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
    /// COMPUTE pins the modeled reply, the bridge resolves active I/O faults
    /// through the per-device RNG in sorted delivery-key order, and
    /// [`DeviceSchedulingSubNode::deliver_due`] later records the buffered
    /// `RngDraw` / `EffectOutcome` decisions when the reply becomes visible
    /// ([IO-21], [IO-25], [SCHED-30]).
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
                status: modeled.response.status,
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

    /// Recomputes every modeled completion through the fault table, in delivery
    /// order, from a fresh per-device RNG (RFC-0010 [IO-25], [IO-21], [IO-4]).
    ///
    /// Because resolution iterates the *sorted* modeled set from RNG position
    /// zero, the post-fault delivery icounts, the recorded draws, and the fault
    /// outcomes are a pure function of `(request set, seed)` — never of the order
    /// the requests were submitted. Already-delivered completions are preserved at
    /// their cursor so a recompute after a partial delivery never re-emits them.
    fn resolve_all(&mut self) {
        if self.resolved.iter().any(|completion| completion.delivered) {
            let has_unfrozen_resolved = self
                .resolved
                .iter()
                .any(|completion| !self.frozen_modeled.contains(&completion.modeled_key));
            if has_unfrozen_resolved || self.frozen_rng_position.is_none() {
                self.frozen_modeled.extend(
                    self.resolved
                        .iter()
                        .map(|completion| completion.modeled_key),
                );
                self.frozen_rng_position = Some(self.rng_position);
            }
        }

        let mut rng = crate::device::device_rng(
            self.seed,
            &self.device_id,
            self.frozen_rng_position.unwrap_or(0),
        );
        let stream = crate::device::device_stream_id(&self.device_id);
        let mut resolved = self
            .resolved
            .iter()
            .filter(|completion| self.frozen_modeled.contains(&completion.modeled_key))
            .cloned()
            .collect::<Vec<_>>();
        for modeled in self.modeled.clone() {
            if self.frozen_modeled.contains(&modeled.key()) {
                continue;
            }
            let before = rng.position();
            let outcome = self.device.resolve_response(
                modeled.modeled_icount,
                modeled.status,
                modeled.payload.clone(),
                &mut rng,
            );
            let after = rng.position();

            // Record one RngDraw per raw value this completion consumed (in order),
            // then a EffectOutcome for each probabilistic effect outcome ([SCHED-30]).
            let mut decisions = Vec::new();
            let mut replay = crate::device::device_rng(self.seed, &self.device_id, before);
            let at = crate::VirtualTime {
                ticks: modeled.modeled_icount,
            };
            for _ in before..after {
                decisions.push(Decision::RngDraw(RngDecision {
                    stream: stream.clone(),
                    value: replay.next_u64(),
                }));
            }
            push_effect_outcome(
                &mut decisions,
                at,
                &self.device_id,
                "loss",
                outcome.loss_fired,
            );
            push_effect_outcome(
                &mut decisions,
                at,
                &self.device_id,
                "duplicate",
                outcome.duplicate_fired,
            );
            push_effect_outcome(
                &mut decisions,
                at,
                &self.device_id,
                "corrupt",
                outcome.corrupt_fired,
            );

            let primary_payload = if outcome.dropped {
                None
            } else {
                Some(self.device.resolved_payload(
                    &modeled.payload,
                    &outcome.primary,
                    outcome.failure_errno,
                ))
            };
            resolved.push(PendingCompletion {
                modeled_key: modeled.key(),
                delivery_icount: outcome.primary.delivery_icount,
                src_node: modeled.src_node,
                seq: modeled.seq,
                payload: primary_payload,
                decisions,
                delivered: false,
            });
            if let Some(duplicate) = outcome.duplicate {
                let payload = self.device.resolved_payload(
                    &modeled.payload,
                    &duplicate,
                    outcome.failure_errno,
                );
                resolved.push(PendingCompletion {
                    modeled_key: modeled.key(),
                    delivery_icount: duplicate.delivery_icount,
                    src_node: modeled.src_node,
                    // Duplicates live in a SEPARATE high-bit tie-break namespace
                    // (`seq | DUPLICATE_SEQ_NAMESPACE`) so a duplicate can never
                    // collide with any sibling request's primary `seq` (which are
                    // small sequential request counts). Tie-break only orders
                    // same-icount completions, so the namespace bit is harmless to
                    // ordering while guaranteeing uniqueness.
                    seq: modeled.seq | DUPLICATE_SEQ_NAMESPACE,
                    payload: Some(payload),
                    decisions: Vec::new(),
                    delivered: false,
                });
            }
        }
        resolved.sort_by_key(PendingCompletion::delivery_key);
        self.rng_position = rng.position();
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

    /// Discards every not-yet-delivered completion owned by this sub-node.
    ///
    /// Crash handling uses this to void in-flight device responses before they
    /// can become scheduler-visible events. Returned completions are ordered by
    /// the sub-node's deterministic delivery order.
    #[must_use]
    pub fn discard_in_flight(&mut self) -> Vec<SchedulerDiscardedIoCompletion> {
        let discarded = self
            .resolved
            .iter()
            .filter(|completion| !completion.delivered)
            .filter_map(|completion| {
                completion
                    .payload
                    .as_ref()
                    .map(|payload| SchedulerDiscardedIoCompletion {
                        sub_node: self.sub_node.clone(),
                        target: self.target.clone(),
                        delivery_icount: crate::Icount {
                            retired: completion.delivery_icount,
                        },
                        source_node: completion.src_node,
                        sequence: completion.seq,
                        payload: payload.clone(),
                    })
            })
            .collect::<Vec<_>>();
        self.modeled.clear();
        self.resolved.clear();
        self.frozen_modeled.clear();
        self.frozen_rng_position = None;
        self.device.discard_inflight();
        discarded
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
    Block(BlockDevice),
    /// A 9p filesystem sub-node.
    Ninep(NinepDevice),
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

    /// Discards all concrete in-flight completions held by the device core.
    fn discard_inflight(&mut self) -> Vec<PendingResponse> {
        match self {
            ScheduledDevice::Block(device) => device.core_mut().discard_inflight(),
            ScheduledDevice::Ninep(device) => device.core_mut().discard_inflight(),
        }
    }

    /// Returns the held device's active I/O fault table.
    fn faults(&self) -> &IoFaults {
        match self {
            ScheduledDevice::Block(device) => device.faults(),
            ScheduledDevice::Ninep(device) => device.faults(),
        }
    }

    /// Installs an active I/O fault table on the held device.
    fn set_faults(&mut self, faults: IoFaults) {
        match self {
            ScheduledDevice::Block(device) => device.set_faults(faults),
            ScheduledDevice::Ninep(device) => device.set_faults(faults),
        }
    }

    /// Resolves a modeled response through the held device's active fault table.
    fn resolve_response(
        &mut self,
        primary_icount: u64,
        status: ResponseStatus,
        payload: Vec<u8>,
        rng: &mut crucible_device::DeviceRng,
    ) -> crucible_device::IoFaultOutcome {
        match self {
            ScheduledDevice::Block(device) => {
                device.resolve_response(primary_icount, status, payload, rng)
            }
            ScheduledDevice::Ninep(device) => {
                device.resolve_response(primary_icount, status, payload, rng)
            }
        }
    }

    /// Re-encodes a protocol-native error payload when a failure fault fires.
    fn resolved_payload(
        &self,
        modeled_payload: &[u8],
        outcome: &crucible_device::ResolvedResponse,
        failure_errno: Option<u32>,
    ) -> Vec<u8> {
        if outcome.status != ResponseStatus::Error || failure_errno.is_none() {
            return outcome.payload.clone();
        }

        match self {
            ScheduledDevice::Block(_) => {
                block_error_payload(modeled_payload).unwrap_or_else(|| outcome.payload.clone())
            }
            ScheduledDevice::Ninep(_) => ninep_error_payload(modeled_payload, failure_errno)
                .unwrap_or_else(|| outcome.payload.clone()),
        }
    }
}

fn block_error_payload(modeled_payload: &[u8]) -> Option<Vec<u8>> {
    let response = BlockResponse::decode(modeled_payload).ok()?;
    BlockResponse::error(response.request_id).encode().ok()
}

fn ninep_error_payload(modeled_payload: &[u8], failure_errno: Option<u32>) -> Option<Vec<u8>> {
    let errno = failure_errno?;
    let tag_bytes = modeled_payload.get(5..7)?;
    let tag = u16::from_le_bytes([tag_bytes[0], tag_bytes[1]]);
    ninep_codec::encode_rlerror(tag, errno).ok()
}

/// Pushes a [`Decision::EffectOutcome`] for one I/O fault kind that could fire.
///
/// The fault id is the device-scoped tag [`crate::device::io_fault_id`] keys an
/// active I/O fault by ([IO-26]), so block/9p/link faults live in one namespace.
fn push_effect_outcome(
    decisions: &mut Vec<Decision>,
    at: crate::VirtualTime,
    device: &DeviceId,
    kind: &str,
    fired: bool,
) {
    let fault: FaultId = crate::device::io_fault_id(device, kind);
    decisions.push(Decision::EffectOutcome(EffectOutcomeDecision {
        at,
        fault,
        fired,
    }));
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- unit-test fixtures and assertions fail loudly.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crucible_device::ninep::codec;
    use crucible_device::{
        BaseImage, BlockLatency, FsTree, IoCore, IoFaults, NinepDevice, NinepLatency, Node,
        Probability,
    };

    use crate::SchedulingNodeKind;

    mod branch_reseed;

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
    fn fresh_disk(seed: Seed, faults: IoFaults) -> DeviceSchedulingSubNode {
        let core = match IoCore::new(0, 7, 16, 16) {
            Ok(core) => core,
            Err(error) => panic!("io core should construct: {error}"),
        };
        let base = BaseImage::new(vec![0xab; 4096]);
        let mut device = BlockDevice::new(core, base, BlockLatency::default());
        device.set_faults(faults);
        DeviceSchedulingSubNode::new(
            sub_node_id("disk-sub"),
            node_id("vm-a"),
            device_id("disk"),
            device,
            seed,
        )
    }

    /// Builds a 9p sub-node over a read-only tree.
    fn fresh_ninep(seed: Seed, faults: IoFaults) -> DeviceSchedulingSubNode {
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
        let mut device = NinepDevice::new(core, tree, NinepLatency::default());
        device.set_faults(faults);
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
        let mut disk = fresh_disk(Seed::from_u64(0xd15c), IoFaults::none());
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
        let mut disk = fresh_disk(Seed::from_u64(0xd15c), IoFaults::none());
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
    fn effect_choices_are_drawn_from_the_device_rng_and_recorded_as_decisions() {
        // A loss fault that always fires: the completion records an RngDraw (the
        // loss draw) and a EffectOutcome(loss, fired=true) on the RESOLVE path.
        let faults = IoFaults {
            loss: Probability::ALWAYS,
            ..IoFaults::none()
        };
        let mut disk = fresh_disk(Seed::from_u64(0xfa17), faults);
        disk.submit(0, &read_request(1, 0, 8))
            .unwrap_or_else(|error| panic!("submit should succeed: {error}"));
        let delivery = disk
            .next_exact_local_event()
            .unwrap_or_else(|| panic!("a completion must be in flight"));
        let delivered = disk.deliver_due(delivery);
        assert_eq!(delivered.len(), 1);
        let decisions = &delivered[0].decisions;

        assert!(
            decisions
                .iter()
                .any(|decision| matches!(decision, Decision::RngDraw(_))),
            "the device RNG draws must be recorded as decisions"
        );
        assert!(
            decisions.iter().any(|decision| matches!(
                decision,
                Decision::EffectOutcome(EffectOutcomeDecision { fired: true, fault, .. })
                    if fault == &crate::device::io_fault_id(&device_id("disk"), "loss")
            )),
            "the loss effect outcome must be recorded as fired"
        );
        // The RNG cursor advanced (the faults consumed draws).
        assert!(disk.rng_position() > 0);
        let block_rng_position = disk
            .block_device()
            .unwrap_or_else(|| panic!("disk sub-node should hold a block device"))
            .rng_position();
        assert_eq!(
            block_rng_position,
            disk.rng_position(),
            "the concrete block device cursor must match the scheduler bridge cursor"
        );
    }

    #[test]
    fn ninep_effect_choices_use_the_same_scheduler_bridge() {
        let faults = IoFaults {
            duplicate: Probability::ALWAYS,
            duplicate_gap_ns: 1,
            corrupt: Probability::ALWAYS,
            corrupt_bit_flips: 1,
            ..IoFaults::none()
        };
        let mut fs = fresh_ninep(Seed::from_u64(0x9f5), faults);
        fs.submit_ninep_frame(0, &tversion(7, 4096, codec::PROTOCOL_VERSION))
            .unwrap_or_else(|error| panic!("9p submit should succeed: {error}"));

        let first_delivery = fs
            .next_exact_local_event()
            .unwrap_or_else(|| panic!("a 9p completion must be in flight"));
        let delivered = fs.deliver_due(u64::MAX);
        assert!(
            delivered.len() >= 2,
            "duplicate fault should emit a second 9p reply"
        );
        let event = delivered[0]
            .completion
            .as_ref()
            .unwrap_or_else(|| panic!("9p delivery should emit a completion"));
        let decisions = &delivered[0].decisions;
        assert_eq!(event.delivery_icount.retired, first_delivery);
        assert_eq!(event.target, node_id("vm-a"));
        assert!(
            decisions
                .iter()
                .any(|decision| matches!(decision, Decision::RngDraw(_))),
            "9p device RNG draws must be recorded as decisions"
        );
        assert!(
            decisions.iter().any(|decision| matches!(
                decision,
                Decision::EffectOutcome(EffectOutcomeDecision { fired: true, fault, .. })
                    if fault == &crate::device::io_fault_id(&device_id("fs"), "duplicate")
            )),
            "the 9p duplicate effect outcome must be recorded as fired"
        );
        assert!(
            decisions.iter().any(|decision| matches!(
                decision,
                Decision::EffectOutcome(EffectOutcomeDecision { fired: true, fault, .. })
                    if fault == &crate::device::io_fault_id(&device_id("fs"), "corrupt")
            )),
            "the 9p corrupt effect outcome must be recorded as fired"
        );
        assert!(fs.rng_position() > 0);
        let ninep_rng_position = fs
            .ninep_device()
            .unwrap_or_else(|| panic!("9p sub-node should hold a 9p device"))
            .rng_position();
        assert_eq!(
            ninep_rng_position,
            fs.rng_position(),
            "the concrete 9p device cursor must match the scheduler bridge cursor"
        );
    }

    #[test]
    fn wrong_request_kind_fails_loudly_without_computing() {
        let mut fs = fresh_ninep(Seed::from_u64(0x9f5), IoFaults::none());
        let result = fs.submit(0, &read_request(1, 0, 8));
        assert!(matches!(
            result,
            Err(DeviceError::WrongDeviceKind {
                expected: "block",
                actual: "9p"
            })
        ));
        assert!(fs.next_exact_local_event().is_none());

        let mut disk = fresh_disk(Seed::from_u64(0xd15c), IoFaults::none());
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
}
