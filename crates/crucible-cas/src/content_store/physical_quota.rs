//! Kernel-enforced physical quota boundaries for persistent store leaves.
//!
//! The store graph records only non-secret quota policy identity and exact hard
//! limits. An external binder authenticates an operator-installed filesystem
//! quota on the exclusively owned leaf root and returns a guard that can
//! revalidate that same pinned quota incarnation. The kernel, rather than this
//! facade, rejects physical allocation beyond the admitted byte or inode
//! ceiling, including staging, compression, encryption, and pack slack.

use super::ObjectKind;

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use super::admin::{PhysicalRepairAuthority, PreparedResources};
use crate::owned_decode::{DecodeBudget, DecodeScratch};

use super::{
    BackendCapabilities, BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary,
    BlobSource, BlobStoreAdmin, ByteRange, ContentId, DeleteBatchReceipt, ImmutableBlobBackend,
    InventorySummaryReceipt, OwnedBlobBytes, PlannedDeleteDisposition, PutBatchReceipt, PutReceipt,
    StoreError,
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
    /// Returns the original authored Rust metadata subset available to decoders.
    ///
    /// SQLite allocator credits and native guest memory are excluded. A
    /// returned maximum is an admission ceiling; every retained allocation
    /// must still obtain its own resource loan before allocation.
    ///
    /// # Errors
    /// Returns [`StoreError::Unsupported`] when the original owner has no
    /// explicit Rust metadata contract.
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Err(StoreError::Unsupported {
            capability: "decoded-metadata-limit",
        })
    }

    /// Opens an isolated GC mark backend under this exact retained namespace.
    ///
    /// The implementation retains the original quota, resource allocator, and
    /// finite supervisor. It must reject ambiguous or unavailable namespace
    /// authority rather than create an independent scratch store.
    ///
    /// # Errors
    /// Returns [`StoreError::Unsupported`] when this guard cannot securely
    /// prepare a mark namespace, or the original admission refuses the work.
    fn gc_mark_backend(
        self: Arc<Self>,
        _scope: &str,
    ) -> Result<Arc<dyn super::ImmutableBlobBackend>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "gc-mark-backend",
        })
    }

    /// Reserves actual descriptor and resident credits before a retained loan.
    ///
    /// The returned owner keeps the original capacity and quota custody alive.
    /// Resident metadata is a subset of the complete resident peak; it is never
    /// added a second time to global usage. Callers close borrowed resources
    /// before dropping this credit. No unmetered success receipt is permitted.
    ///
    /// # Errors
    /// Refuses unavailable or exhausted original admission and supervision.
    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<Arc<dyn Send + Sync>, StoreError>;

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
    /// drift. Existing descendants must be audited under exclusive startup
    /// namespace authority. The operator must exclude external project-attribute,
    /// mount, rename/link and quota-control mutation for the guard's lifetime;
    /// trusted writers may create only project-inheriting descendants. A scan
    /// alone does not establish this continuing namespace exclusion.
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
    directory_costs: Option<DirectoryResourceCosts>,
    _child_resources: Option<Arc<dyn Send + Sync>>,
    _resources: Arc<dyn Send + Sync>,
}

/// Audited additional allocations of the loose-directory implementation.
#[derive(Clone, Copy)]
pub(super) struct DirectoryResourceCosts {
    pub(super) source_bytes: u64,
    pub(super) reader_bytes: u64,
    pub(super) operation_bytes: u64,
}

impl PhysicalQuotaStore {
    pub(super) fn new(
        name: impl Into<String>,
        child: Arc<dyn ImmutableBlobBackend>,
        child_admin: Arc<dyn BlobStoreAdmin>,
        guard: Arc<dyn StorePhysicalQuotaGuard>,
    ) -> Result<Self, StoreError> {
        guard.verify()?;
        let name = name.into();
        let resources = guard.reserve_resources(
            0,
            (facade_metadata_bytes() as u64)
                .checked_add(name.capacity() as u64)
                .ok_or(StoreError::Quota)?,
        )?;
        Ok(Self {
            name,
            child,
            child_admin,
            guard,
            directory_costs: None,
            _child_resources: None,
            _resources: resources,
        })
    }

    pub(super) fn with_directory_costs(mut self, costs: DirectoryResourceCosts) -> Self {
        self.directory_costs = Some(costs);
        self
    }

    pub(super) fn with_child_resources(mut self, resources: Arc<dyn Send + Sync>) -> Self {
        self._child_resources = Some(resources);
        self
    }

    fn operation_resources(&self) -> Result<Arc<dyn Send + Sync>, StoreError> {
        self.guard.reserve_resources(
            if self.directory_costs.is_some() { 6 } else { 0 },
            self.directory_costs
                .map_or(0, |costs| costs.operation_bytes)
                + std::mem::size_of::<PhysicalQuotaInventoryFence<'_>>() as u64,
        )
    }

    fn rewrite_receipt(&self, mut receipt: PutReceipt) -> PutReceipt {
        for placement in &mut receipt.placements {
            placement.backend.clone_from(&self.name);
        }
        receipt
    }
}

impl ImmutableBlobBackend for PhysicalQuotaStore {
    fn put_many_if_absent_with_boundary(
        &self,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        boundary()?;
        self.guard.verify()?;
        let resources = self.operation_resources()?;
        let account = super::batch::account()?;
        let mut check = || {
            boundary()?;
            self.guard.verify()
        };
        let mut receipts = self
            .child
            .put_many_if_absent_with_boundary(objects, &mut check)?;
        let mut growth_bytes = 0_u64;
        for receipt in &receipts.receipts {
            for placement in &receipt.placements {
                let capacity = placement.backend.capacity();
                if self.name.len() > capacity {
                    // String::clone_from may geometrically grow its allocation.
                    // Retain the replacement extent as well as the leaf's old
                    // allocation until the final receipt owner closes.
                    let replacement = capacity
                        .checked_mul(2)
                        .ok_or(StoreError::Quota)?
                        .max(self.name.len())
                        .max(8);
                    growth_bytes = growth_bytes
                        .checked_add(replacement as u64)
                        .ok_or(StoreError::Quota)?;
                }
            }
        }
        receipts.retain_resources(&account, resources, growth_bytes)?;
        for receipt in &mut receipts.receipts {
            check()?;
            for placement in &mut receipt.placements {
                placement.backend.clone_from(&self.name);
            }
        }
        check()?;
        account.verify_live().map_err(super::batch::admission)?;
        Ok(receipts)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn metadata_resources(&self) -> Result<Arc<dyn super::StorePhysicalQuotaGuard>, StoreError> {
        Ok(Arc::clone(&self.guard))
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.child.capabilities()
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.guard.verify()?;
        self.child.admit_object_graph(objects)
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.guard.verify()?;
        let _resources = self.operation_resources()?;
        self.child.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.guard.verify()?;
        let costs = self.directory_costs;
        let resources = self.guard.reserve_resources(
            u64::from(costs.is_some()),
            (deferred_source_metadata_bytes() as u64)
                .checked_add(costs.map_or(0, |costs| costs.source_bytes))
                .ok_or(StoreError::Quota)?,
        )?;
        let handle = self.child.read(id, range)?;
        let source = Arc::new(PhysicalQuotaBlobSource {
            handle: handle.clone(),
            guard: self.guard.clone(),
            reader_bytes: costs.map_or(0, |costs| costs.reader_bytes),
            _resources: resources,
        });
        Ok(handle.with_observed_source(source))
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.guard.verify()?;
        let _resources = self.operation_resources()?;
        self.child
            .put_if_absent(id, source)
            .map(|receipt| self.rewrite_receipt(receipt))
    }
}

// Deferred handles retain the exact quota/service custody after the facade
// drops. Each open/read revalidates authority before consuming backing bytes.
struct PhysicalQuotaBlobSource {
    handle: BlobHandle,
    guard: Arc<dyn StorePhysicalQuotaGuard>,
    reader_bytes: u64,
    _resources: Arc<dyn Send + Sync>,
}

pub(super) const fn deferred_source_metadata_bytes() -> usize {
    std::mem::size_of::<PhysicalQuotaBlobSource>() + 2 * std::mem::size_of::<usize>()
}

impl BlobSource for PhysicalQuotaBlobSource {
    fn read_all_with_boundary(
        &self,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        let mut check = || {
            boundary()?;
            self.guard.verify()
        };
        self.handle.read_all_with_boundary(maximum, &mut check)
    }

    fn logical_length(&self) -> u64 {
        self.handle.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.guard.verify()?;
        let resources = self.guard.reserve_resources(
            0,
            (deferred_reader_metadata_bytes() as u64)
                .checked_add(self.reader_bytes)
                .ok_or(StoreError::Quota)?,
        )?;
        Ok(Box::new(PhysicalQuotaReader {
            reader: self.handle.open()?,
            guard: self.guard.clone(),
            // The child reader and its pinned source close before credits.
            _source_resources: self._resources.clone(),
            _resources: resources,
        }))
    }
}

struct PhysicalQuotaReader {
    reader: Box<dyn Read + Send>,
    guard: Arc<dyn StorePhysicalQuotaGuard>,
    _source_resources: Arc<dyn Send + Sync>,
    _resources: Arc<dyn Send + Sync>,
}

pub(super) const fn deferred_reader_metadata_bytes() -> usize {
    std::mem::size_of::<PhysicalQuotaReader>()
}

pub(super) const fn facade_metadata_bytes() -> usize {
    std::mem::size_of::<PhysicalQuotaStore>() + 2 * std::mem::size_of::<usize>()
}

impl Read for PhysicalQuotaReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.guard.verify().map_err(io::Error::other)?;
        self.reader.read(buffer)
    }
}

impl BlobStoreAdmin for PhysicalQuotaStore {
    fn acquire_inventory_fence_with_boundary(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        let account = super::batch::account()?;
        boundary()?;
        self.guard.verify()?;
        let credit = account
            .reserve_scratch_array::<PhysicalQuotaInventoryFence<'_>>(1)
            .map_err(super::batch::admission)?;
        // The checked SQL child opens exactly one retained flock descriptor.
        // Opaque children still refuse their checked acquisition; no ordinary
        // acquisition is substituted after that refusal.
        let resources = self.guard.reserve_resources(
            self.directory_costs.map_or(1, |_| 6),
            std::mem::size_of::<PhysicalQuotaInventoryFence<'_>>() as u64
                + self
                    .directory_costs
                    .map_or(0, |costs| costs.operation_bytes),
        )?;
        let mut original = || {
            account.verify_live().map_err(super::batch::admission)?;
            boundary()?;
            self.guard.verify()?;
            account.verify_live().map_err(super::batch::admission)
        };
        let mut child = self
            .child_admin
            .acquire_inventory_fence_with_boundary(&mut original)?;
        if let Err(error) = original() {
            return Err(child.retain_checked_failure(error));
        }
        Ok(Box::new(PhysicalQuotaInventoryFence {
            store: self,
            child,
            checked_account: Some(account),
            _resources: resources,
            _checked_credit: Some(credit),
        }))
    }

    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        self.guard.verify()?;
        let resources = self.operation_resources()?;
        Ok(Box::new(PhysicalQuotaInventoryFence {
            store: self,
            child: self.child_admin.acquire_inventory_fence()?,
            checked_account: None,
            _resources: resources,
            _checked_credit: None,
        }))
    }
}

struct PhysicalQuotaInventoryFence<'a> {
    store: &'a PhysicalQuotaStore,
    child: Box<dyn BlobInventoryFence + 'a>,
    checked_account: Option<DecodeBudget>,
    _resources: Arc<dyn Send + Sync>,
    _checked_credit: Option<DecodeScratch>,
}

impl BlobInventoryFence for PhysicalQuotaInventoryFence<'_> {
    fn retain_checked_failure(&mut self, error: StoreError) -> StoreError {
        self.child.retain_checked_failure(error)
    }

    fn delete_candidates_with_boundary(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        let result = (|| {
            let account = self
                .checked_account
                .as_ref()
                .ok_or(StoreError::Unsupported {
                    capability: "ordinary-fence-has-no-checked-origin",
                })?;
            let _scope = account.enter();
            account.verify_live().map_err(super::batch::admission)?;
            boundary()?;
            self.store.guard.verify()?;
            let prepared = PreparedResources::new(account, self._resources.clone(), 0)?;
            let mut original = || {
                account.verify_live().map_err(super::batch::admission)?;
                boundary()?;
                self.store.guard.verify()?;
                account.verify_live().map_err(super::batch::admission)
            };
            let receipt = self
                .child
                .delete_candidates_with_boundary(ids, &mut original)?;
            let mut receipt = receipt.check(|_| original())?;
            receipt.retain_resources(prepared);
            Ok(receipt)
        })();
        result.map_err(|error| self.child.retain_checked_failure(error))
    }

    fn visit_inventory_with_boundary(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        let result = (|| {
            let account = self
                .checked_account
                .as_ref()
                .ok_or(StoreError::Unsupported {
                    capability: "ordinary-fence-has-no-checked-origin",
                })?;
            let _scope = account.enter();
            account.verify_live().map_err(super::batch::admission)?;
            boundary()?;
            self.store.guard.verify()?;
            let prepared = PreparedResources::new(
                account,
                self._resources.clone(),
                self.store.name.len() as u64,
            )?;
            let mut name = String::new();
            name.try_reserve_exact(self.store.name.len())
                .map_err(super::batch::allocation)?;
            name.push_str(&self.store.name);
            let mut original = || {
                account.verify_live().map_err(super::batch::admission)?;
                boundary()?;
                self.store.guard.verify()?;
                account.verify_live().map_err(super::batch::admission)
            };
            let receipt = self
                .child
                .visit_inventory_with_boundary(visitor, &mut original)?;
            let mut receipt = receipt.check(|summary| {
                if summary.backend() != self.store.child.name() {
                    return Err(StoreError::InvalidComposition {
                        reason: "physical quota child inventory summary is inconsistent",
                    });
                }
                original()?;
                *summary = BlobInventorySummary::new(
                    name,
                    summary.storage_identity(),
                    summary.generation(),
                    summary.objects(),
                    summary.logical_bytes(),
                );
                Ok(())
            })?;
            receipt.retain_resources(prepared);
            Ok(receipt)
        })();
        result.map_err(|error| self.child.retain_checked_failure(error))
    }

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
            summary.storage_identity(),
            summary.generation(),
            summary.objects(),
            summary.logical_bytes(),
        ))
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        self.store.guard.verify()?;
        self.child.delete_candidate(id)
    }

    fn repair_put_if_absent(
        &mut self,
        authority: &PhysicalRepairAuthority,
        id: ContentId,
        source: &BlobHandle,
    ) -> Result<PutReceipt, StoreError> {
        self.store.guard.verify()?;
        self.child
            .repair_put_if_absent(authority, id, source)
            .map(|receipt| self.store.rewrite_receipt(receipt))
    }
}
