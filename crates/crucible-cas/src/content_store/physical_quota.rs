//! Kernel-enforced physical quota boundaries for persistent store leaves.
//!
//! The store graph records only non-secret quota policy identity and exact hard
//! limits. An external binder authenticates an operator-installed filesystem
//! quota on the exclusively owned leaf root and returns a guard that can
//! revalidate that same pinned quota incarnation. The kernel, rather than this
//! facade, rejects physical allocation beyond the admitted byte or inode
//! ceiling, including staging, compression, encryption, and pack slack.

use super::batch::{admission_under, allocation_under};
use super::{CheckedInventoryFence, CheckedPublicationMetadata};

use super::ObjectKind;

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use super::admin::{PhysicalRepairAuthority, PreparedResources};

use super::{
    BackendCapabilities, BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary,
    BlobSource, BlobStoreAdmin, ByteRange, ContentId, DeleteBatchReceipt, ImmutableBlobBackend,
    InventorySummaryReceipt, PlannedDeleteDisposition, PutBatchReceipt, PutReceipt, StoreError,
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
    /// Checks original provider authority using its own precharged error slot.
    ///
    /// The issuing provider occupies its slot before any lower check. Success
    /// returns storage custody after the unchanged real checks accept; failure
    /// retains its typed cause and original service together. No caller may
    /// supply an unrelated permit or renew the original supervision.
    ///
    /// # Errors
    /// Refuses an occupied slot, an unbounded diagnostic path, unsupported
    /// genuine storage, or the original lower quota/supervision checks. Slot
    /// and path-bound refusal creates no source body.
    fn begin_provider_diagnostic(
        self: Arc<Self>,
    ) -> Result<super::ProviderDiagnosticPermit, StoreError> {
        Err(StoreError::Unsupported {
            capability: "precharged-provider-diagnostic",
        })
    }

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
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError>;

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
    /// Reserves fixed map-node custody from the provider's original service.
    ///
    /// This grant authenticates no filesystem or disk quota. The existing
    /// opaque binder retains the actual service owner, and the returned loan
    /// prepays its own control before allocation in the same original accounts.
    ///
    /// # Errors
    /// Refuses unsupported memory admission or unavailable original capacity.
    fn reserve_memory_namespace(
        &self,
        _bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        Err(StoreError::Unsupported {
            capability: "memory-namespace-grant",
        })
    }

    /// Checks the original service before a covered memory namespace effect.
    ///
    /// This check neither binds a disk root nor renews an operation deadline.
    /// It supplies execution permission for map mutation, not later reads.
    ///
    /// # Errors
    /// Refuses unsupported memory admission or closed original service authority.
    fn verify_memory_namespace(&self) -> Result<(), StoreError> {
        Err(StoreError::Unsupported {
            capability: "memory-namespace-grant",
        })
    }

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

mod binder_handle;

pub use binder_handle::StorePhysicalQuotaBinderHandle;

/// External physical-quota capabilities used while constructing a store graph.
#[derive(Default)]
pub struct StoreGraphPhysicalQuotaBinders {
    binders: BTreeMap<StorePhysicalQuotaPolicyId, StorePhysicalQuotaBinderHandle>,
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
        binder: StorePhysicalQuotaBinderHandle,
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
    ) -> Result<StorePhysicalQuotaBinderHandle, StoreError> {
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
    _child_resources: crate::owned_decode::ResourceLoanSlot,
    _resources: crate::owned_decode::ResourceLoan,
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
            _child_resources: Default::default(),
            _resources: resources,
        })
    }

    pub(super) fn with_directory_costs(mut self, costs: DirectoryResourceCosts) -> Self {
        self.directory_costs = Some(costs);
        self
    }

    pub(super) fn with_child_resources(
        mut self,
        resources: crate::owned_decode::ResourceLoan,
    ) -> Self {
        self._child_resources = resources.into();
        self
    }

    fn operation_resources(&self) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
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
    fn read_bounded_with_boundary(
        &self,
        request: &mut crate::ram::BoundedReadRequest<'_, '_>,
    ) -> Result<(), StoreError> {
        // Selection is effect-free. SQL checks these exact physical owners at
        // its I/O edges; a generic leaf reads through this checked facade once.
        request.with_physical(self.guard.as_ref(), self, |request| {
            self.child.read_bounded_with_boundary(request)
        })
    }

    fn checked_publication_metadata(
        &self,
        kind: ObjectKind,
    ) -> Result<CheckedPublicationMetadata, StoreError> {
        let child = self.child.checked_publication_metadata(kind)?;
        if child.maximum_placements != 1 {
            return Err(StoreError::InvalidComposition {
                reason: "physical checked publisher must declare one placement",
            });
        }
        Ok(CheckedPublicationMetadata {
            maximum_placements: 1,
            maximum_backend_name_bytes: self.name.len(),
        })
    }

    fn put_many_if_absent_with_boundary(
        &self,
        account: &crate::owned_decode::DecodeBudget,
        objects: &[(ContentId, BlobHandle)],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<PutBatchReceipt, StoreError> {
        account
            .verify_live()
            .map_err(|error| admission_under(account, error))?;
        if objects.len() > 64 {
            return Err(StoreError::Quota);
        }
        boundary()?;
        account
            .verify_live()
            .map_err(|error| admission_under(account, error))?;
        self.guard.verify()?;
        let resources = self.operation_resources()?;
        let rewrite_names = self.name != self.child.name();
        let name_bytes = if rewrite_names {
            (self.name.len() as u64)
                .checked_mul(objects.len() as u64)
                .ok_or(StoreError::Quota)?
        } else {
            0
        };
        let prepared = PreparedResources::new(account, resources, name_bytes)?;
        // Common managed leaves already use this facade's label. Different
        // labels move pre-funded final strings rather than growing after COMMIT.
        let _label_array = rewrite_names
            .then(|| account.reserve_scratch_array::<String>(objects.len()))
            .transpose()
            .map_err(|error| admission_under(account, error))?;
        let mut labels = if rewrite_names {
            let mut labels = Vec::new();
            labels
                .try_reserve_exact(objects.len())
                .map_err(|error| allocation_under(account, error))?;
            for _ in objects {
                let mut label = String::new();
                label
                    .try_reserve_exact(self.name.len())
                    .map_err(|error| allocation_under(account, error))?;
                label.push_str(&self.name);
                labels.push(label);
            }
            Some(labels.into_iter())
        } else {
            None
        };
        let mut check = || {
            account
                .verify_live()
                .map_err(|error| admission_under(account, error))?;
            boundary()?;
            account
                .verify_live()
                .map_err(|error| admission_under(account, error))?;
            self.guard.verify()?;
            account
                .verify_live()
                .map_err(|error| admission_under(account, error))
        };
        let mut receipts = self
            .child
            .put_many_if_absent_with_boundary(account, objects, &mut check)?;
        receipts.retain_resources(prepared);
        // Unconsumed prepared labels close inside the check, before a refused
        // receipt releases the resources that fund those final strings.
        receipts.check(move |receipts| {
            if receipts.len() != objects.len() {
                return Err(StoreError::InvalidComposition {
                    reason: "physical leaf batch receipt count differs from input",
                });
            }
            for receipt in receipts {
                check()?;
                // The checked producer is one physical leaf. Reject
                // unexpected composition before consuming any prepared label.
                if receipt.placements.len() != 1
                    || receipt.placements[0].backend != self.child.name()
                {
                    return Err(StoreError::InvalidComposition {
                        reason: "physical leaf batch placement is inconsistent",
                    });
                }
                if let Some(labels) = &mut labels {
                    receipt.placements[0].backend =
                        labels.next().ok_or(StoreError::InvalidComposition {
                            reason: "physical leaf batch label count is inconsistent",
                        })?;
                }
            }
            check()
        })
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

    fn read_with_boundary(
        &self,
        account: &crate::owned_decode::DecodeBudget,
        id: ContentId,
        range: Option<ByteRange>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<BlobHandle, StoreError> {
        let original = account.clone();
        let mut check = || {
            super::checked_reader::check(&original, boundary)?;
            self.guard.verify()
        };
        check()?;
        let costs = self.directory_costs;
        let credit = original
            .reserve_scratch_bytes(deferred_source_metadata_bytes() as u64)
            .map_err(|error| super::batch::admission_under(&original, error))?;
        let resources = self.guard.reserve_resources(
            u64::from(costs.is_some()),
            (deferred_source_metadata_bytes() as u64)
                .checked_add(costs.map_or(0, |costs| costs.source_bytes))
                .ok_or(StoreError::Quota)?,
        )?;
        let handle = self
            .child
            .read_with_boundary(&original, id, range, &mut check)?;
        check()?;
        let source = PhysicalQuotaBlobSource {
            handle: handle.clone(),
            guard: self.guard.clone(),
            reader_bytes: costs.map_or(0, |costs| costs.reader_bytes),
            _credit: Some(credit),
            _resources: resources,
        };
        Ok(handle.with_observed_source(source))
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
        let source = PhysicalQuotaBlobSource {
            handle: handle.clone(),
            guard: self.guard.clone(),
            reader_bytes: costs.map_or(0, |costs| costs.reader_bytes),
            _credit: None,
            _resources: resources,
        };
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
    _credit: Option<crate::owned_decode::DecodeScratch>,
    _resources: crate::owned_decode::ResourceLoan,
}

pub(super) const fn deferred_source_metadata_bytes() -> usize {
    std::mem::size_of::<PhysicalQuotaBlobSource>() + 2 * std::mem::size_of::<usize>()
}

impl BlobSource for PhysicalQuotaBlobSource {
    fn checked_read_access(&self) -> super::CheckedReadAccess {
        self.handle.checked_read_access()
    }

    fn read_all_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<super::OwnedBlobBytes, StoreError> {
        let mut check = || {
            super::checked_reader::check(original, boundary)?;
            self.guard.verify()
        };
        check()?;
        // This synchronous borrower retains the same physical source and
        // reader reservation through child EOF and the final acceptance cut.
        // Streaming opens continue to own their checked reader separately.
        let _resources = self.guard.reserve_resources(
            0,
            (std::mem::size_of::<PhysicalCheckedReader>() as u64)
                .checked_add(self.reader_bytes)
                .ok_or(StoreError::Quota)?,
        )?;
        let bytes = self
            .handle
            .read_all_with_boundary(original, maximum, &mut check)?;
        check()?;
        Ok(bytes)
    }

    fn open_with_boundary(
        &self,
        caller: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<super::CheckedReader, StoreError> {
        let original = caller.clone();
        let mut check = || {
            super::checked_reader::check(&original, boundary)?;
            self.guard.verify()
        };
        check()?;
        let credit = original
            .reserve_scratch_array::<PhysicalCheckedReader>(1)
            .map_err(|error| super::batch::admission_under(&original, error))?;
        let resources = self.guard.reserve_resources(
            0,
            (std::mem::size_of::<PhysicalCheckedReader>() as u64)
                .checked_add(self.reader_bytes)
                .ok_or(StoreError::Quota)?,
        )?;
        let reader = super::checked_reader::open_handle(&self.handle, caller, &mut check)?;
        check()?;
        Ok(super::CheckedReader::admitted(
            Box::new(PhysicalCheckedReader {
                reader,
                guard: self.guard.clone(),
                original,
                failed: false,
                _source_resources: self._resources.clone(),
            }),
            credit,
            resources.into(),
        ))
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
    _source_resources: crate::owned_decode::ResourceLoan,
    _resources: crate::owned_decode::ResourceLoan,
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
    ) -> Result<CheckedInventoryFence<'_>, StoreError> {
        let account = super::batch::account()?;
        boundary()?;
        account
            .verify_live()
            .map_err(|error| admission_under(&account, error))?;
        self.guard.verify()?;
        let credit = account
            .reserve_scratch_array::<PhysicalQuotaInventoryFence<'_>>(1)
            .map_err(|error| admission_under(&account, error))?;
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
            account
                .verify_live()
                .map_err(|error| admission_under(&account, error))?;
            boundary()?;
            account
                .verify_live()
                .map_err(|error| admission_under(&account, error))?;
            self.guard.verify()?;
            account
                .verify_live()
                .map_err(|error| admission_under(&account, error))
        };
        let mut child = {
            let _scope = account.enter();
            self.child_admin
                .acquire_inventory_fence_with_boundary(&mut original)?
        };
        if let Err(error) = original() {
            return Err(child.retain_checked_failure(error));
        }
        let external_resources = resources.clone();
        Ok(CheckedInventoryFence::new_with_resources(
            Box::new(PhysicalQuotaInventoryFence {
                store: self,
                child,
                checked_account: account.into(),
                _resources: resources,
            }),
            credit,
            external_resources,
        ))
    }

    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        self.guard.verify()?;
        let resources = self.operation_resources()?;
        Ok(Box::new(PhysicalQuotaInventoryFence {
            store: self,
            child: CheckedInventoryFence::ordinary(self.child_admin.acquire_inventory_fence()?),
            checked_account: crate::owned_decode::DecodeBudgetSlot::default(),
            _resources: resources,
        }))
    }
}

struct PhysicalQuotaInventoryFence<'a> {
    store: &'a PhysicalQuotaStore,
    child: CheckedInventoryFence<'a>,
    checked_account: crate::owned_decode::DecodeBudgetSlot,
    _resources: crate::owned_decode::ResourceLoan,
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
            account
                .verify_live()
                .map_err(|error| admission_under(account, error))?;
            boundary()?;
            account
                .verify_live()
                .map_err(|error| admission_under(account, error))?;
            self.store.guard.verify()?;
            let prepared = PreparedResources::new(account, self._resources.clone(), 0)?;
            let mut original = || {
                account
                    .verify_live()
                    .map_err(|error| admission_under(account, error))?;
                boundary()?;
                account
                    .verify_live()
                    .map_err(|error| admission_under(account, error))?;
                self.store.guard.verify()?;
                account
                    .verify_live()
                    .map_err(|error| admission_under(account, error))
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
            account
                .verify_live()
                .map_err(|error| admission_under(account, error))?;
            boundary()?;
            account
                .verify_live()
                .map_err(|error| admission_under(account, error))?;
            self.store.guard.verify()?;
            let prepared = PreparedResources::new(
                account,
                self._resources.clone(),
                self.store.name.len() as u64,
            )?;
            let mut name = String::new();
            name.try_reserve_exact(self.store.name.len())
                .map_err(|error| allocation_under(account, error))?;
            name.push_str(&self.store.name);
            let mut original = || {
                account
                    .verify_live()
                    .map_err(|error| admission_under(account, error))?;
                boundary()?;
                account
                    .verify_live()
                    .map_err(|error| admission_under(account, error))?;
                self.store.guard.verify()?;
                account
                    .verify_live()
                    .map_err(|error| admission_under(account, error))
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

// Both child and physical source loans outlive every deferred checked read.
struct PhysicalCheckedReader {
    reader: super::CheckedReader,
    guard: Arc<dyn StorePhysicalQuotaGuard>,
    original: crate::owned_decode::DecodeBudget,
    failed: bool,
    _source_resources: crate::owned_decode::ResourceLoan,
}

impl super::checked_reader::AuditedCheckedBlobReader for PhysicalCheckedReader {}

impl super::CheckedBlobReader for PhysicalCheckedReader {
    fn full_eof_identity(&self) -> Option<ContentId> {
        self.reader.full_eof_identity()
    }

    fn original_account(&self) -> &crate::owned_decode::DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(super::checked_reader::failed());
        }
        let original = &self.original;
        let mut check = || {
            super::checked_reader::check(original, boundary)?;
            self.guard.verify()
        };
        let result = self.reader.read_with_boundary(output, &mut check);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[cfg(test)]
mod checked_capability_tests;
