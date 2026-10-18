//! Canonical World queue numbering and physical buffer policy.
//!
//! Layouts retain their original World through cloning; matching names or
//! source numbers cannot rebind them before block or filesystem construction.

use std::collections::BTreeMap;

use super::{
    ContentHash, DEFAULT_WORLD_IO_INBOX_CAPACITY, DEFAULT_WORLD_IO_OUTBOX_CAPACITY, NodeId, World,
};

/// Host/transport layout policy for instantiated World I/O nodes.
///
/// This value is intentionally not part of [`World`] or [`crate::DeviceId`]. Changing
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
    world: ContentHash,
    bindings: BTreeMap<NodeId, WorldIoRuntimeLayout>,
}

impl WorldIoInstantiationLayout {
    /// Derives physical bindings from canonical I/O-node order and `policy`.
    ///
    /// The same World and policy always produce identical source numbers, while
    /// changing the policy leaves the World and every [`crate::DeviceId`] unchanged.
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
        Ok(Self {
            world: world.id(),
            bindings,
        })
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

    // Matching names or source numbers do not bind a layout to its World.
    // Retain the actual canonical owner through cloning and validate it before
    // constructing either concrete device. Capacity policy stays physical.
    pub(super) fn validate_world(&self, world: &World) -> Result<(), WorldIoLayoutError> {
        let expected = world.id();
        if self.world != expected {
            return Err(WorldIoLayoutError::WorldMismatch {
                expected,
                actual: self.world,
            });
        }
        Ok(())
    }
}

/// Error returned while deriving a physical I/O layout.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WorldIoLayoutError {
    /// A layout belongs to a different canonical World.
    #[error("I/O layout World {actual:?} differs from the binding World {expected:?}")]
    WorldMismatch {
        /// Canonical World being instantiated.
        expected: ContentHash,
        /// Canonical World retained when the layout was derived.
        actual: ContentHash,
    },
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
