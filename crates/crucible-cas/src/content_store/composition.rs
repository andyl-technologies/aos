//! Initial immutable-store composition primitives.
//!
//! These types enforce their local invariants. The complete closed-graph
//! admission validator remains required before the module becomes public.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::*;

/// Logical-verification facade around one child store.
pub struct VerifiedStore {
    name: String,
    child: Arc<dyn ImmutableBlobBackend>,
}

impl VerifiedStore {
    /// Wraps `child` with full logical verification before range slicing.
    #[must_use]
    pub fn new(name: impl Into<String>, child: Arc<dyn ImmutableBlobBackend>) -> Self {
        Self {
            name: name.into(),
            child,
        }
    }
}

impl ImmutableBlobBackend for VerifiedStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.child.read(id, None) {
            Ok(bytes) => {
                validate_bytes(id, &bytes)?;
                Ok(true)
            }
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
        let bytes = self.child.read(id, None)?;
        validate_bytes(id, &bytes)?;
        slice_range(bytes, range)
    }

    fn put_if_absent(&self, id: ContentId, bytes: &[u8]) -> Result<PutReceipt, StoreError> {
        validate_bytes(id, bytes)?;
        self.child.put_if_absent(id, bytes)
    }
}

/// Routes logical object kinds to explicitly configured child stores.
pub struct RoutedStore {
    name: String,
    routes: BTreeMap<ObjectKind, Arc<dyn ImmutableBlobBackend>>,
}

impl RoutedStore {
    /// Builds a routed store and rejects an empty routing table.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when `routes` is empty.
    pub fn new(
        name: impl Into<String>,
        routes: BTreeMap<ObjectKind, Arc<dyn ImmutableBlobBackend>>,
    ) -> Result<Self, StoreError> {
        if routes.is_empty() {
            return Err(StoreError::InvalidComposition {
                reason: "routed store requires at least one object-kind route",
            });
        }
        Ok(Self {
            name: name.into(),
            routes,
        })
    }

    fn route(&self, id: ContentId) -> Result<&Arc<dyn ImmutableBlobBackend>, StoreError> {
        self.routes
            .get(&id.kind())
            .ok_or(StoreError::InvalidComposition {
                reason: "no child route exists for the logical object kind",
            })
    }
}

impl ImmutableBlobBackend for RoutedStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        let mut capabilities = BackendCapabilities {
            durable: true,
            range_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: true,
            planned_delete: true,
        };
        for child in self.routes.values() {
            let child = child.capabilities();
            capabilities.durable &= child.durable;
            capabilities.range_read &= child.range_read;
            capabilities.conditional_create &= child.conditional_create;
            capabilities.streaming_put &= child.streaming_put;
            capabilities.repair_inventory &= child.repair_inventory;
            capabilities.planned_delete &= child.planned_delete;
        }
        capabilities
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.route(id)?.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
        self.route(id)?.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, bytes: &[u8]) -> Result<PutReceipt, StoreError> {
        validate_bytes(id, bytes)?;
        self.route(id)?.put_if_absent(id, bytes)
    }
}

/// Ordered read tiers with one explicit write tier and optional read promotion.
pub struct TieredStore {
    name: String,
    tiers: Vec<Arc<dyn ImmutableBlobBackend>>,
    write_tier: usize,
    promote_reads: bool,
}

impl TieredStore {
    /// Builds a tiered store.
    ///
    /// Only a genuine [`StoreError::NotFound`] falls through to a lower tier;
    /// corruption, authorization, and availability failures remain visible.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] for no tiers or an invalid
    /// write-tier index.
    pub fn new(
        name: impl Into<String>,
        tiers: Vec<Arc<dyn ImmutableBlobBackend>>,
        write_tier: usize,
        promote_reads: bool,
    ) -> Result<Self, StoreError> {
        if tiers.is_empty() {
            return Err(StoreError::InvalidComposition {
                reason: "tiered store requires at least one child",
            });
        }
        if write_tier >= tiers.len() {
            return Err(StoreError::InvalidComposition {
                reason: "tiered store write tier is out of range",
            });
        }
        Ok(Self {
            name: name.into(),
            tiers,
            write_tier,
            promote_reads,
        })
    }

    fn read_full(&self, id: ContentId) -> Result<(usize, Vec<u8>), StoreError> {
        for (index, tier) in self.tiers.iter().enumerate() {
            match tier.read(id, None) {
                Ok(bytes) => {
                    validate_bytes(id, &bytes)?;
                    return Ok((index, bytes));
                }
                Err(StoreError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::NotFound { id })
    }
}

impl ImmutableBlobBackend for TieredStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.tiers[self.write_tier].capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.read_full(id) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
        let (found_tier, bytes) = self.read_full(id)?;
        if self.promote_reads && found_tier > 0 {
            for tier in &self.tiers[..found_tier] {
                let _promotion = tier.put_if_absent(id, &bytes);
            }
        }
        slice_range(bytes, range)
    }

    fn put_if_absent(&self, id: ContentId, bytes: &[u8]) -> Result<PutReceipt, StoreError> {
        self.tiers[self.write_tier].put_if_absent(id, bytes)
    }
}

/// Write-through mirror for immutable logical objects.
pub struct WriteThroughStore {
    name: String,
    children: Vec<Arc<dyn ImmutableBlobBackend>>,
}

impl WriteThroughStore {
    /// Builds a write-through store with at least one child.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when `children` is empty.
    pub fn new(
        name: impl Into<String>,
        children: Vec<Arc<dyn ImmutableBlobBackend>>,
    ) -> Result<Self, StoreError> {
        if children.is_empty() {
            return Err(StoreError::InvalidComposition {
                reason: "write-through store requires at least one child",
            });
        }
        Ok(Self {
            name: name.into(),
            children,
        })
    }
}

impl ImmutableBlobBackend for WriteThroughStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        let mut capabilities = self.children[0].capabilities();
        for child in &self.children[1..] {
            let child = child.capabilities();
            capabilities.durable |= child.durable;
            capabilities.range_read &= child.range_read;
            capabilities.conditional_create &= child.conditional_create;
            capabilities.streaming_put &= child.streaming_put;
            capabilities.repair_inventory &= child.repair_inventory;
            capabilities.planned_delete &= child.planned_delete;
        }
        capabilities
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        for child in &self.children {
            if !child.contains(id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<Vec<u8>, StoreError> {
        for child in &self.children {
            match child.read(id, range) {
                Ok(bytes) => return Ok(bytes),
                Err(StoreError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::NotFound { id })
    }

    fn put_if_absent(&self, id: ContentId, bytes: &[u8]) -> Result<PutReceipt, StoreError> {
        validate_bytes(id, bytes)?;
        let mut placements = Vec::new();
        for child in &self.children {
            let receipt = child.put_if_absent(id, bytes)?;
            placements.extend(receipt.placements);
        }
        Ok(PutReceipt { id, placements })
    }
}
