//! Initial immutable-store composition primitives.
//!
//! These types enforce their local invariants. The complete closed-graph
//! admission validator remains required before the module becomes public.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let blob = self.child.read(id, None)?;
        blob.verified_as(id)?.slice(range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let source = source.verified_as(id)?;
        self.child.put_if_absent(id, &source)
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
            deferred_write: false,
            range_read: true,
            streaming_read: true,
            conditional_create: true,
            streaming_put: true,
            repair_inventory: true,
            planned_delete: true,
        };
        for child in self.routes.values() {
            let child = child.capabilities();
            capabilities.durable &= child.durable;
            capabilities.deferred_write |= child.deferred_write;
            capabilities.range_read &= child.range_read;
            capabilities.streaming_read &= child.streaming_read;
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

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.route(id)?.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let source = source.verified_as(id)?;
        self.route(id)?.put_if_absent(id, &source)
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

    fn read_full(&self, id: ContentId) -> Result<(usize, BlobHandle), StoreError> {
        for (index, tier) in self.tiers.iter().enumerate() {
            match tier.read(id, None) {
                Ok(blob) => {
                    return Ok((index, blob));
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
        let mut capabilities = self.tiers[self.write_tier].capabilities();
        capabilities.range_read = self.tiers.iter().all(|tier| tier.capabilities().range_read);
        capabilities.streaming_read = self
            .tiers
            .iter()
            .all(|tier| tier.capabilities().streaming_read)
            && (!self.promote_reads
                || self.tiers[..self.tiers.len().saturating_sub(1)]
                    .iter()
                    .all(|tier| tier.capabilities().streaming_put));
        capabilities
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.read_full(id) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        let (found_tier, blob) = self.read_full(id)?;
        if self.promote_reads && found_tier > 0 {
            for tier in &self.tiers[..found_tier] {
                let _promotion = tier.put_if_absent(id, &blob);
            }
        }
        blob.slice(range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.tiers[self.write_tier].put_if_absent(id, source)
    }
}

/// Two-child read-through cache for immutable logical objects.
pub struct ReadThroughStore {
    name: String,
    cache: Arc<dyn ImmutableBlobBackend>,
    source: Arc<dyn ImmutableBlobBackend>,
}

impl ReadThroughStore {
    /// Builds a read-through cache over one authoritative source child.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        cache: Arc<dyn ImmutableBlobBackend>,
        source: Arc<dyn ImmutableBlobBackend>,
    ) -> Self {
        Self {
            name: name.into(),
            cache,
            source,
        }
    }

    fn read_full(&self, id: ContentId) -> Result<BlobHandle, StoreError> {
        match self.cache.read(id, None) {
            Ok(blob) => Ok(blob),
            Err(StoreError::NotFound { .. }) => {
                let blob = self.source.read(id, None)?;
                // Promotion is an operational cache optimization. A cache
                // outage or quota limit cannot make an authenticated source
                // object unavailable to the logical caller.
                let _promotion = self.cache.put_if_absent(id, &blob);
                Ok(blob)
            }
            Err(error) => Err(error),
        }
    }
}

impl ImmutableBlobBackend for ReadThroughStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        let cache = self.cache.capabilities();
        let mut capabilities = self.source.capabilities();
        capabilities.range_read &= cache.range_read;
        capabilities.streaming_read &= cache.streaming_read && cache.streaming_put;
        capabilities
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        match self.read_full(id) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.read_full(id)?.slice(range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.source.put_if_absent(id, source)
    }
}

#[derive(Default)]
pub(crate) struct MetricsState {
    contains_calls: AtomicU64,
    contains_hits: AtomicU64,
    read_calls: AtomicU64,
    read_logical_bytes: AtomicU64,
    put_calls: AtomicU64,
    put_logical_bytes: AtomicU64,
    failures: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MetricsSnapshot {
    pub contains_calls: u64,
    pub contains_hits: u64,
    pub read_calls: u64,
    pub read_logical_bytes: u64,
    pub put_calls: u64,
    pub put_logical_bytes: u64,
    pub failures: u64,
}

impl MetricsState {
    fn increment(counter: &AtomicU64, amount: u64) {
        let _prior = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(amount))
        });
    }

    pub(crate) fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            contains_calls: self.contains_calls.load(Ordering::Relaxed),
            contains_hits: self.contains_hits.load(Ordering::Relaxed),
            read_calls: self.read_calls.load(Ordering::Relaxed),
            read_logical_bytes: self.read_logical_bytes.load(Ordering::Relaxed),
            put_calls: self.put_calls.load(Ordering::Relaxed),
            put_logical_bytes: self.put_logical_bytes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
        }
    }
}

/// Operational counters around one immutable child store.
pub struct MetricsStore {
    name: String,
    child: Arc<dyn ImmutableBlobBackend>,
    state: Arc<MetricsState>,
}

impl MetricsStore {
    /// Wraps `child` and returns the shared counter state used by graph
    /// introspection.
    #[must_use]
    pub(crate) fn new(
        name: impl Into<String>,
        child: Arc<dyn ImmutableBlobBackend>,
    ) -> (Self, Arc<MetricsState>) {
        let state = Arc::new(MetricsState::default());
        (
            Self {
                name: name.into(),
                child,
                state: state.clone(),
            },
            state,
        )
    }
}

impl ImmutableBlobBackend for MetricsStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        MetricsState::increment(&self.state.contains_calls, 1);
        let result = self.child.contains(id);
        match result {
            Ok(present) => {
                if present {
                    MetricsState::increment(&self.state.contains_hits, 1);
                }
                Ok(present)
            }
            Err(error) => {
                MetricsState::increment(&self.state.failures, 1);
                Err(error)
            }
        }
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        MetricsState::increment(&self.state.read_calls, 1);
        let result = self.child.read(id, range);
        match result {
            Ok(blob) => {
                MetricsState::increment(&self.state.read_logical_bytes, blob.logical_length());
                Ok(blob)
            }
            Err(error) => {
                MetricsState::increment(&self.state.failures, 1);
                Err(error)
            }
        }
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        MetricsState::increment(&self.state.put_calls, 1);
        let result = self.child.put_if_absent(id, source);
        match result {
            Ok(receipt) => {
                MetricsState::increment(&self.state.put_logical_bytes, source.logical_length());
                Ok(receipt)
            }
            Err(error) => {
                MetricsState::increment(&self.state.failures, 1);
                Err(error)
            }
        }
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
            capabilities.deferred_write |= child.deferred_write;
            capabilities.range_read &= child.range_read;
            capabilities.streaming_read &= child.streaming_read;
            capabilities.conditional_create &= child.conditional_create;
            capabilities.streaming_put &= child.streaming_put;
            capabilities.repair_inventory &= child.repair_inventory;
            capabilities.planned_delete &= child.planned_delete;
        }
        capabilities
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        for child in &self.children {
            match child.contains(id) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        for child in &self.children {
            match child.read(id, range) {
                Ok(blob) => return Ok(blob),
                Err(StoreError::NotFound { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        Err(StoreError::NotFound { id })
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        let mut placements = Vec::new();
        for child in &self.children {
            let receipt = child.put_if_absent(id, source)?;
            placements.extend(receipt.placements);
        }
        Ok(PutReceipt { id, placements })
    }
}
