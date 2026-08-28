//! Kernel-enforced physical quota boundaries for persistent store leaves.
//!
//! The store graph records only non-secret quota policy identity and exact hard
//! limits. An external binder authenticates an operator-installed filesystem
//! quota on the exclusively owned leaf root and returns a guard that can
//! revalidate that same pinned quota incarnation. The kernel, rather than this
//! facade, rejects physical allocation beyond the admitted byte or inode
//! ceiling, including staging, compression, encryption, and pack slack.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::path::Path;
use std::sync::Arc;

use super::{
    BackendCapabilities, BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary,
    BlobStoreAdmin, ByteRange, ContentId, ImmutableBlobBackend, PlannedDeleteDisposition,
    PutReceipt, StoreError,
};

const MAX_PHYSICAL_QUOTA_POLICY_ID_BYTES: usize = 512;
const MAX_PHYSICAL_QUOTA_POLICY_SEGMENT_BYTES: usize = 255;

/// Validated non-secret identity of one physical-filesystem quota policy.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorePhysicalQuotaPolicyId(String);

impl StorePhysicalQuotaPolicyId {
    /// Validates one bounded slash-separated quota-policy identifier.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the value is empty,
    /// exceeds 512 bytes, contains an empty, `.` or `..` segment, has a segment
    /// longer than 255 bytes, or uses characters outside ASCII letters,
    /// digits, `.`, `_`, and `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_PHYSICAL_QUOTA_POLICY_ID_BYTES
            && value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.len() <= MAX_PHYSICAL_QUOTA_POLICY_SEGMENT_BYTES
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            });
        if !valid {
            return Err(StoreError::InvalidComposition {
                reason: "store physical-quota policy identifier is invalid",
            });
        }
        Ok(Self(value))
    }

    /// Returns the validated policy identifier spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bound authority for one exact kernel-enforced physical quota incarnation.
pub trait StorePhysicalQuotaGuard: Send + Sync {
    /// Reauthenticates the pinned root, hard limits, and current bounded usage.
    ///
    /// The guard must fail closed if the configured filesystem quota no longer
    /// names the root incarnation bound by [`StorePhysicalQuotaBinder::bind`],
    /// if either hard limit changed, or if observed use exceeds a limit.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Quota`] for exhausted or mismatched quota state,
    /// or another store error when the kernel-backed decision is unavailable.
    fn verify(&self) -> Result<(), StoreError>;
}

/// External capability that binds one persistent leaf to a hard physical quota.
pub trait StorePhysicalQuotaBinder: Send + Sync {
    /// Authenticates and pins one exact operator-installed quota boundary.
    ///
    /// `root` is the exclusively owned physical leaf root. The implementation
    /// must authenticate root identity without following a replaceable final
    /// symlink, require inheritance for `project_id`, require byte and inode
    /// hard limits no greater than the requested ceilings, and retain enough
    /// authority for the returned guard to detect path-incarnation or quota
    /// drift. The operator must exclude concurrent quota-control mutation for
    /// the lifetime of the returned guard.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Quota`] when the requested ceiling is not enforced,
    /// [`StoreError::Unauthorized`] when the capability cannot bind this root,
    /// or another store error when authentication cannot complete safely.
    fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError>;
}

/// External physical-quota capabilities used while constructing a store graph.
#[derive(Default)]
pub struct StoreGraphPhysicalQuotaBinders {
    binders: BTreeMap<StorePhysicalQuotaPolicyId, Arc<dyn StorePhysicalQuotaBinder>>,
}

impl StoreGraphPhysicalQuotaBinders {
    /// Creates an empty physical-quota capability collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            binders: BTreeMap::new(),
        }
    }

    /// Inserts the capability for one exact physical-quota policy.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidComposition`] when the policy already has
    /// a capability in this collection.
    pub fn insert(
        &mut self,
        policy: StorePhysicalQuotaPolicyId,
        binder: Arc<dyn StorePhysicalQuotaBinder>,
    ) -> Result<(), StoreError> {
        match self.binders.entry(policy) {
            Entry::Vacant(entry) => {
                entry.insert(binder);
                Ok(())
            }
            Entry::Occupied(_) => Err(StoreError::InvalidComposition {
                reason: "store physical-quota capability collection contains a duplicate identifier",
            }),
        }
    }

    pub(super) fn resolve(
        &self,
        policy: &StorePhysicalQuotaPolicyId,
    ) -> Result<Arc<dyn StorePhysicalQuotaBinder>, StoreError> {
        self.binders
            .get(policy)
            .cloned()
            .ok_or(StoreError::Unauthorized)
    }
}

/// Physical-quota facade and administrative owner for one physical leaf.
pub(super) struct PhysicalQuotaStore {
    name: String,
    child: Arc<dyn ImmutableBlobBackend>,
    child_admin: Arc<dyn BlobStoreAdmin>,
    guard: Arc<dyn StorePhysicalQuotaGuard>,
}

impl PhysicalQuotaStore {
    pub(super) fn new(
        name: impl Into<String>,
        child: Arc<dyn ImmutableBlobBackend>,
        child_admin: Arc<dyn BlobStoreAdmin>,
        guard: Arc<dyn StorePhysicalQuotaGuard>,
    ) -> Result<Self, StoreError> {
        guard.verify()?;
        Ok(Self {
            name: name.into(),
            child,
            child_admin,
            guard,
        })
    }

    fn rewrite_receipt(&self, mut receipt: PutReceipt) -> PutReceipt {
        for placement in &mut receipt.placements {
            placement.backend.clone_from(&self.name);
        }
        receipt
    }
}

impl ImmutableBlobBackend for PhysicalQuotaStore {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.guard.verify()?;
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.guard.verify()?;
        self.child.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.guard.verify()?;
        self.child
            .put_if_absent(id, source)
            .map(|receipt| self.rewrite_receipt(receipt))
    }
}

impl BlobStoreAdmin for PhysicalQuotaStore {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        self.guard.verify()?;
        Ok(Box::new(PhysicalQuotaInventoryFence {
            store: self,
            child: self.child_admin.acquire_inventory_fence()?,
        }))
    }
}

struct PhysicalQuotaInventoryFence<'a> {
    store: &'a PhysicalQuotaStore,
    child: Box<dyn BlobInventoryFence + 'a>,
}

impl BlobInventoryFence for PhysicalQuotaInventoryFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.store.guard.verify()?;
        let summary = self.child.visit_inventory(visitor)?;
        if summary.backend() != self.store.child.name() {
            return Err(StoreError::InvalidComposition {
                reason: "physical quota child inventory summary is inconsistent",
            });
        }
        Ok(BlobInventorySummary::new(
            self.store.name.clone(),
            summary.generation(),
            summary.objects(),
            summary.logical_bytes(),
        ))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        self.store.guard.verify()?;
        self.child.delete_candidate(id)
    }
}
