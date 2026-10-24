//! Process-private lifetime exclusion for retained whole-VM ring mappings.
//!
//! Every mapping made by the public mapper joins its backing-object domain.
//! Selecting the original domain fences its already-created aliases and new
//! mappings before release, restore, inheritance or mapping effects. No state
//! in this module is placed in shared memory. Each process must independently
//! select its authentic original owner through the qualified constructor.
//!
//! A selected epoch is correlation, not native eligibility. This module has
//! no terminal release operation: ACK consumption cannot release a mapping.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, Weak};

#[path = "selected_lifecycle/retention.rs"]
mod retention;
use retention::RetentionSlot;

#[path = "selected_lifecycle/registry_map.rs"]
mod registry_map;
use registry_map::RegistryMap;

use super::{MappedSetupRegion, SetupRegionBackingIdentity, SetupRegionMapError};

/// A refusal from the original mapping's retained lifecycle domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WholeMappingCustodyError {
    /// Another original lifecycle operation retains the mutation loan.
    #[error("the original mapping lifecycle is busy")]
    Busy,
    /// A lifecycle operation panicked while retaining the mutation loan.
    #[error("the original mapping lifecycle is poisoned")]
    Poisoned,
    /// The original backing object is already selected for whole execution.
    #[error("the original mapping remains selected and held")]
    Selected,
    /// The original mapping is not registered in the current process.
    #[error("the original mapping has no current registered owner")]
    Unregistered,
    /// A zero epoch cannot identify a constructor selection.
    #[error("the original whole mapping epoch is zero")]
    ZeroEpoch,
    /// Actual ring admission was not completely held and drained.
    #[error("the original whole mapping is not held and drained")]
    NotQuiescent,
    /// A bounded process-private registry or retention allocation is full.
    #[error("the original mapping custody storage limit is exhausted")]
    ResourceLimit,
}

#[derive(Clone, Copy)]
enum Selection {
    Ordinary,
    Selected { epoch: u64, uncertain: bool },
}

// The backing fence excludes ordinary alias mutation for every endpoint.
// Native epochs and operation counters belong to the original mmap instead.
struct Domain {
    selected: AtomicBool,
    selection: Mutex<Selection>,
}

struct ScopeCell {
    active_scope: Mutex<Option<paired_service::ActiveScope>>,
    lease_alive: AtomicBool,
    lease_sequence: std::sync::atomic::AtomicU64,
    lease_owner: std::sync::atomic::AtomicUsize,
    epoch: std::sync::atomic::AtomicU64,
    next_sequence: std::sync::atomic::AtomicU64,
    pending_completion: Mutex<Option<paired_service::ScopeIdentity>>,
    selected: AtomicBool,
    selection: Mutex<Selection>,
}

impl ScopeCell {
    fn new() -> Self {
        Self {
            active_scope: Mutex::new(None),
            lease_alive: AtomicBool::new(false),
            lease_sequence: std::sync::atomic::AtomicU64::new(0),
            lease_owner: std::sync::atomic::AtomicUsize::new(0),
            epoch: std::sync::atomic::AtomicU64::new(0),
            next_sequence: std::sync::atomic::AtomicU64::new(1),
            pending_completion: Mutex::new(None),
            selected: AtomicBool::new(false),
            selection: Mutex::new(Selection::Ordinary),
        }
    }
}

struct MappingRecord {
    length: usize,
    identity: SetupRegionBackingIdentity,
    process: u32,
    domain: Arc<Domain>,
    cell: Arc<ScopeCell>,
}

#[derive(Default)]
struct Registry {
    mappings: RegistryMap<usize, MappingRecord>,
    domains: RegistryMap<(u32, u64, u64), Weak<Domain>>,
}

const MAX_MAPPING_RECORDS: usize = 65_536;
const MAX_RETAINED_MAPPINGS: usize = 4_096;

#[derive(Default)]
struct Quarantine {
    owners: Vec<Arc<MappedSetupRegion>>,
    reserved: usize,
}

fn quarantine() -> &'static Mutex<Quarantine> {
    &generation().quarantine
}

fn reserve_quarantine() -> Result<(), WholeMappingCustodyError> {
    let mut owners = try_lock(quarantine())?;
    let occupied = owners
        .owners
        .len()
        .checked_add(owners.reserved)
        .ok_or(WholeMappingCustodyError::ResourceLimit)?;
    if occupied >= MAX_RETAINED_MAPPINGS {
        return Err(WholeMappingCustodyError::ResourceLimit);
    }
    let additional = owners.reserved + 1;
    owners
        .owners
        .try_reserve(additional)
        .map_err(|_| WholeMappingCustodyError::ResourceLimit)?;
    owners.reserved += 1;
    Ok(())
}

fn backing_key(process: u32, identity: SetupRegionBackingIdentity) -> (u32, u64, u64) {
    // Growing a shrink-sealed file must not create a new lifecycle domain.
    (process, identity.device(), identity.inode())
}

fn locked_registry() -> Result<MutexGuard<'static, Registry>, WholeMappingCustodyError> {
    // Distinct ordinary mappings may publish concurrently. Brief registry
    // bookkeeping waits rather than spuriously refusing an unrelated owner.
    registry()
        .lock()
        .map_err(|_| WholeMappingCustodyError::Poisoned)
}

struct RegistryGeneration {
    process: u32,
    records: Mutex<Registry>,
    quarantine: Mutex<Quarantine>,
}

fn generation() -> &'static RegistryGeneration {
    use std::sync::atomic::AtomicPtr;

    static CURRENT: AtomicPtr<RegistryGeneration> = AtomicPtr::new(std::ptr::null_mut());
    let process = std::process::id();
    loop {
        let original = CURRENT.load(Ordering::Acquire);
        if !original.is_null() {
            // SAFETY: published generations are immutable headers backed by
            // permanently retained Box allocations. Acquire observes their
            // initialized PID without entering a possibly inherited mutex.
            let generation = unsafe { &*original };
            if generation.process == process {
                return generation;
            }
        }

        let replacement = Box::into_raw(Box::new(RegistryGeneration {
            process,
            records: Mutex::new(Registry::default()),
            quarantine: Mutex::new(Quarantine::default()),
        }));
        if CURRENT
            .compare_exchange(original, replacement, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // SAFETY: this process published the fully initialized allocation.
            // Old generations remain allocated: an inherited caller may still
            // hold an old guard, and destroying its mutex would be unsound.
            return unsafe { &*replacement };
        }
        // SAFETY: replacement was never published and this invocation alone
        // owns it. A competing initializer cannot refer to this allocation.
        drop(unsafe { Box::from_raw(replacement) });
    }
}

fn registry() -> &'static Mutex<Registry> {
    &generation().records
}

/// Retains immutable original registration across a process fork.
pub(super) struct MappingRegistration {
    owner: MappingOwnerKey,
    domain: Arc<Domain>,
    cell: Arc<ScopeCell>,
}

fn try_lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, WholeMappingCustodyError> {
    mutex.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => WholeMappingCustodyError::Busy,
        TryLockError::Poisoned(_) => WholeMappingCustodyError::Poisoned,
    })
}

fn ordinary(domain: &Domain) -> Result<MutexGuard<'_, Selection>, WholeMappingCustodyError> {
    let selection = try_lock(&domain.selection)?;
    if domain.selected.load(Ordering::Acquire) || !matches!(*selection, Selection::Ordinary) {
        return Err(WholeMappingCustodyError::Selected);
    }
    Ok(selection)
}

fn domain_at(address: usize) -> Result<Option<Arc<Domain>>, WholeMappingCustodyError> {
    let records = locked_registry()?;
    let process = std::process::id();
    Ok(records.mappings.iter().find_map(|(&start, record)| {
        let end = start.checked_add(record.length)?;
        (record.process == process && start <= address && address < end)
            .then(|| Arc::clone(&record.domain))
    }))
}

/// Authenticates mapping metadata before any typed memory or kernel effect.
#[derive(Clone, Copy)]
pub(super) struct MappingOwnerKey {
    address: usize,
    length: usize,
    identity: SetupRegionBackingIdentity,
    process: u32,
}

fn registered_domain(owner: MappingOwnerKey) -> Result<Arc<Domain>, WholeMappingCustodyError> {
    if owner.process != std::process::id() {
        return Err(WholeMappingCustodyError::Unregistered);
    }
    let records = locked_registry()?;
    let record = records
        .mappings
        .get(&owner.address)
        .ok_or(WholeMappingCustodyError::Unregistered)?;
    if record.process != owner.process
        || record.length != owner.length
        || record.identity != owner.identity
    {
        return Err(WholeMappingCustodyError::Unregistered);
    }
    Ok(Arc::clone(&record.domain))
}

fn registered_cell(owner: MappingOwnerKey) -> Result<Arc<ScopeCell>, WholeMappingCustodyError> {
    if owner.process != std::process::id() {
        return Err(WholeMappingCustodyError::Unregistered);
    }
    let records = locked_registry()?;
    let record = records
        .mappings
        .get(&owner.address)
        .ok_or(WholeMappingCustodyError::Unregistered)?;
    if record.process != owner.process
        || record.length != owner.length
        || record.identity != owner.identity
    {
        return Err(WholeMappingCustodyError::Unregistered);
    }
    Ok(Arc::clone(&record.cell))
}

/// Runs a mutation under the authenticated current mapping's ordinary loan.
///
/// # Errors
///
/// Refuses missing or foreign process registration and selected, busy or
/// poisoned original custody before invoking the mutation.
pub(super) fn ordinary_owned_mutation<T>(
    owner: MappingOwnerKey,
    mutate: impl FnOnce() -> T,
) -> Result<T, WholeMappingCustodyError> {
    let domain = registered_domain(owner)?;
    let _loan = ordinary(&domain)?;
    Ok(mutate())
}

/// Runs a header mutation under its backing domain's ordinary loan.
///
/// Standalone headers outside registered mappings retain ordinary behavior.
///
/// # Errors
///
/// Refuses selected, busy or poisoned registered mapping custody.
pub(super) fn ordinary_mutation<T>(
    address: usize,
    mutate: impl FnOnce() -> T,
) -> Result<T, WholeMappingCustodyError> {
    let domain = domain_at(address)?;
    let _loan = domain.as_ref().map(|domain| ordinary(domain)).transpose()?;
    Ok(mutate())
}

// RingHeader addresses are process-private observations, never wire fields.
// Standalone headers outside registered mappings retain ordinary behavior.
/// Fences an ordinary raw-header mutation through its original domain.
///
/// # Errors
///
/// Refuses selected, busy or poisoned registered mapping custody.
pub(crate) fn ordinary_header_mutation<T>(
    address: usize,
    mutate: impl FnOnce() -> T,
) -> Result<T, WholeMappingCustodyError> {
    ordinary_mutation(address, mutate)
}

fn admitted_domain(
    identity: SetupRegionBackingIdentity,
) -> Result<Arc<Domain>, WholeMappingCustodyError> {
    let mut records = locked_registry()?;
    let key = backing_key(std::process::id(), identity);
    if let Some(domain) = records.domains.get(&key).and_then(Weak::upgrade) {
        return Ok(domain);
    }

    // Expired Weak entries carry no admitted mapper or live alias. Removing
    // only those entries preserves the same backing domain during admission.
    records
        .domains
        .retain(|_, domain| domain.strong_count() != 0);
    if records.domains.len() >= MAX_MAPPING_RECORDS {
        return Err(WholeMappingCustodyError::ResourceLimit);
    }
    records
        .domains
        .try_reserve(1)
        .map_err(|_| WholeMappingCustodyError::ResourceLimit)?;
    let domain = Arc::new(Domain {
        selected: AtomicBool::new(false),
        selection: Mutex::new(Selection::Ordinary),
    });
    records.domains.insert(key, Arc::downgrade(&domain));
    Ok(domain)
}

/// Admits and publishes the actual mapper under one backing domain.
///
/// # Errors
///
/// Refuses bounded storage exhaustion, selected or unavailable custody, or
/// propagates the mapper's original descriptor and kernel mapping error.
pub(super) fn map_registered(
    identity: SetupRegionBackingIdentity,
    map: impl FnOnce() -> Result<MappedSetupRegion, SetupRegionMapError>,
) -> Result<MappedSetupRegion, SetupRegionMapError> {
    // This strong owner spans admission, the ordinary loan and publication.
    // Last-alias teardown cannot detach a mapper that has not published yet.
    let domain =
        admitted_domain(identity).map_err(|source| SetupRegionMapError::WholeCustody { source })?;
    #[cfg(all(
        test,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_abi = "",
        target_endian = "little",
        target_pointer_width = "64"
    ))]
    tests::after_map_admission();
    let _loan = ordinary(&domain).map_err(|source| SetupRegionMapError::WholeCustody { source })?;
    let mut records =
        locked_registry().map_err(|source| SetupRegionMapError::WholeCustody { source })?;
    reserve_mapping_record(&mut records)
        .map_err(|source| SetupRegionMapError::WholeCustody { source })?;
    // Each original mapping gets private bounded operation state before mmap.
    let cell = Arc::new(ScopeCell::new());
    // Allocation admission and registry ownership precede the real mmap.
    let mut mapped = map()?;
    mapped.mapping_registration = Some(MappingRegistration {
        owner: mapped.mapping_owner_key(),
        domain: Arc::clone(&domain),
        cell: Arc::clone(&cell),
    });
    records.mappings.insert(
        mapped.mapping_start(),
        MappingRecord {
            length: mapped.len,
            identity,
            process: std::process::id(),
            domain: Arc::clone(&domain),
            cell,
        },
    );
    Ok(mapped)
}

fn reserve_mapping_record(records: &mut Registry) -> Result<(), WholeMappingCustodyError> {
    if records.mappings.len() >= MAX_MAPPING_RECORDS {
        return Err(WholeMappingCustodyError::ResourceLimit);
    }
    records
        .mappings
        .try_reserve(1)
        .map_err(|_| WholeMappingCustodyError::ResourceLimit)
}

/// Registers exact child replacement under both original backing loans.
///
/// # Errors
///
/// Refuses unauthenticated, selected, busy, poisoned or exhausted custody;
/// the inner result retains the replacement installer's original error.
pub(super) fn install_registered<E>(
    mapping: &mut MappedSetupRegion,
    identity: SetupRegionBackingIdentity,
    install: impl FnOnce(&mut MappedSetupRegion) -> Result<(), E>,
) -> Result<Result<(), E>, WholeMappingCustodyError> {
    let original_owner = mapping.mapping_owner_key();
    let registration = mapping
        .mapping_registration
        .as_ref()
        .ok_or(WholeMappingCustodyError::Unregistered)?;
    if registration.owner.address != original_owner.address
        || registration.owner.length != original_owner.length
        || registration.owner.identity != original_owner.identity
        || registration.owner.process != original_owner.process
    {
        return Err(WholeMappingCustodyError::Unregistered);
    }

    let original = Arc::clone(&registration.domain);
    let current_process = std::process::id();
    let _original_loan = if original_owner.process == current_process {
        // The live parent uses the same authenticated ordinary loan. The fork
        // child must never enter a copied registry or domain mutex instead.
        let current = registered_domain(original_owner)?;
        if !Arc::ptr_eq(&current, &original) {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        Some(ordinary(&original)?)
    } else {
        if original.selected.load(Ordering::Acquire) {
            return Err(WholeMappingCustodyError::Selected);
        }
        None
    };
    let destination = admitted_domain(identity)?;
    let _destination_loan = if Arc::ptr_eq(&original, &destination) {
        None
    } else {
        Some(ordinary(&destination)?)
    };
    let mut records = locked_registry()?;
    reserve_mapping_record(&mut records)?;
    let cell = Arc::new(ScopeCell::new());
    let result = install(mapping);
    if result.is_ok() {
        mapping.mapping_registration = Some(MappingRegistration {
            owner: mapping.mapping_owner_key(),
            domain: Arc::clone(&destination),
            cell: Arc::clone(&cell),
        });
        records.mappings.insert(
            mapping.mapping_start(),
            MappingRecord {
                length: mapping.len,
                identity: mapping.backing_identity,
                process: current_process,
                domain: Arc::clone(&destination),
                cell,
            },
        );
    }
    Ok(result)
}

/// Retains registration ownership across actual ordinary unmap and removal.
///
/// # Errors
///
/// Refuses a foreign process, mismatched original record, or selected, busy
/// or poisoned custody before invoking the unmap callback.
pub(super) fn unmap_ordinary(
    mapping: &MappedSetupRegion,
    unmap: impl FnOnce() -> bool,
) -> Result<(), WholeMappingCustodyError> {
    let process = std::process::id();
    if mapping.mapping_process_id as u32 != process {
        // A DONTFORK child has this Rust value without its original VMA.
        return Err(WholeMappingCustodyError::Unregistered);
    }
    let address = mapping.mapping_start();
    let domain = domain_at(address)?.ok_or(WholeMappingCustodyError::Unregistered)?;
    if domain.selected.load(Ordering::Acquire) {
        return Err(WholeMappingCustodyError::Selected);
    }
    // An ordinary alias Drop retains its owner while waiting for the existing
    // mutation loan. Busy is not an owning teardown disposition.
    #[cfg(all(
        test,
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_abi = "",
        target_endian = "little",
        target_pointer_width = "64"
    ))]
    tests::before_unmap_domain_lock(address);
    let _loan = domain
        .selection
        .lock()
        .map_err(|_| WholeMappingCustodyError::Poisoned)?;
    if domain.selected.load(Ordering::Acquire) || !matches!(*_loan, Selection::Ordinary) {
        return Err(WholeMappingCustodyError::Selected);
    }
    let mut records = locked_registry()?;
    let record = records
        .mappings
        .get(&address)
        .ok_or(WholeMappingCustodyError::Unregistered)?;
    if record.process != process
        || record.length != mapping.len
        || record.identity != mapping.backing_identity
        || !Arc::ptr_eq(&record.domain, &domain)
    {
        return Err(WholeMappingCustodyError::Unregistered);
    }

    // Keep registration ownership across the actual syscall and removal.
    // A new VMA may reuse the address after munmap, but cannot publish its
    // record until this authenticated original record is removed.
    if unmap() {
        records.mappings.remove(&address);
    }
    // Failed munmap leaves the original record/domain retained. Weak backing
    // entries expire only when mappings AND in-flight admissions are gone.
    Ok(())
}

/// Retains the original mapped owner after sticky whole selection.
///
/// The constructor must obtain the epoch from the actual installed native
/// owner. This type alone authenticates neither that epoch nor a grant. Its
/// status reflects only local lifetime exclusion and actual HELD ring state.
/// Dropping this owner transfers the same allocation into owning quarantine;
/// it never clears HELD, unmaps memory, or infers shutdown from an ACK.
pub struct RetainedWholeMapping {
    mapping: Arc<MappedSetupRegion>,
    domain: Option<Arc<Domain>>,
    cell: Option<Arc<ScopeCell>>,
    ring_headers: Arc<[usize]>,
    roster_narrowed: bool,
    epoch: u64,
    operation_capacity: u64,
    quarantine_reserved: bool,
    retention_slot: Option<Arc<RetentionSlot>>,
    status: Result<(), WholeMappingCustodyError>,
}

impl RetainedWholeMapping {
    /// Returns the immutable epoch supplied by the authentic constructor.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the retained local selection and held-ring validation outcome.
    ///
    /// # Errors
    ///
    /// Returns the original selection refusal. A successful result grants no
    /// native execution or release authority.
    pub fn selection_status(&self) -> Result<(), WholeMappingCustodyError> {
        self.status?;
        let mapping = self.mapping.as_ref();
        let domain = registered_domain(mapping.mapping_owner_key())?;
        if !self
            .domain
            .as_ref()
            .is_some_and(|original| Arc::ptr_eq(original, &domain))
        {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        let cell = registered_cell(mapping.mapping_owner_key())?;
        if !self
            .cell
            .as_ref()
            .is_some_and(|original| Arc::ptr_eq(original, &cell))
        {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        let selection = try_lock(&cell.selection)?;
        match *selection {
            Selection::Selected {
                epoch,
                uncertain: false,
            } if epoch == self.epoch && cell.epoch.load(Ordering::Acquire) == self.epoch => Ok(()),
            _ => Err(WholeMappingCustodyError::Selected),
        }
    }

    /// Restricts local paired admission to the original constructor's ring offsets.
    ///
    /// The provider first joins these offsets to the exact original native
    /// QueuePlan, registered handles and source-constructor receipt. This
    /// method verifies local mapping membership only; caller offsets alone
    /// establish no native readiness or enrollment authority. Unadvertised
    /// rings remain held behind the same backing-wide lifecycle fence.
    ///
    /// The roster may be restricted exactly once, before the first command.
    /// A failed restriction makes this mapping's custody uncertain.
    ///
    /// # Errors
    ///
    /// Refuses prior restriction or service, foreign ownership, unavailable
    /// storage, an empty or oversized roster, duplicate offsets, and offsets
    /// that do not identify actual original mapped ring headers.
    pub fn restrict_paired_header_offsets(
        &mut self,
        offsets: &[u64],
    ) -> Result<(), WholeMappingCustodyError> {
        let result = (|| {
            self.selection_status()?;
            if self.roster_narrowed {
                return Err(WholeMappingCustodyError::Selected);
            }
            self.roster_narrowed = true;
            let cell = self
                .cell
                .as_ref()
                .ok_or(WholeMappingCustodyError::Unregistered)?;
            let mut selection = try_lock(&cell.selection)?;
            *selection = Selection::Selected {
                epoch: self.epoch,
                uncertain: true,
            };
            if cell.next_sequence.load(Ordering::Acquire) != 1
                || try_lock(&cell.active_scope)?.is_some()
                || try_lock(&cell.pending_completion)?.is_some()
                || offsets.is_empty()
                || offsets.len() > 6
            {
                return Err(WholeMappingCustodyError::Selected);
            }
            let mut headers = Vec::new();
            headers
                .try_reserve_exact(offsets.len())
                .map_err(|_| WholeMappingCustodyError::ResourceLimit)?;
            for &offset in offsets {
                let offset =
                    usize::try_from(offset).map_err(|_| WholeMappingCustodyError::Selected)?;
                let address = self
                    .mapping
                    .mapping_start()
                    .checked_add(offset)
                    .ok_or(WholeMappingCustodyError::Selected)?;
                if self.ring_headers.binary_search(&address).is_err() {
                    return Err(WholeMappingCustodyError::Selected);
                }
                headers.push(address);
            }
            headers.sort_unstable();
            if headers.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(WholeMappingCustodyError::Selected);
            }
            self.ring_headers = headers.into();
            *selection = Selection::Selected {
                epoch: self.epoch,
                uncertain: false,
            };
            Ok(())
        })();
        if result.is_err() {
            self.status = Err(WholeMappingCustodyError::Selected);
            self.refuse_active_loan();
        }
        result
    }

    /// Borrows the same retained mapping without transferring its ownership.
    ///
    /// The mapping's destructive ordinary methods continue to consult the
    /// selected domain, including methods reached through another live alias.
    #[must_use]
    pub fn mapping(&self) -> Option<&MappedSetupRegion> {
        Some(self.mapping.as_ref())
    }

    /// Executes a separately authenticated service within this same local loan.
    ///
    /// The native callback must authenticate the full current scope before
    /// calling this method. A foreign epoch or incomplete service makes local
    /// custody uncertain. Ordinary release and restore remain unavailable.
    ///
    /// # Errors
    ///
    /// Returns a local custody refusal, or the original service error. This
    /// loan supplies no native grant, payload acceptance or result authority.
    pub fn with_selected_scope<T, E>(
        &mut self,
        epoch: u64,
        service: impl FnOnce(&mut MappedSetupRegion) -> Result<T, E>,
    ) -> Result<Result<T, E>, WholeMappingCustodyError> {
        self.selection_status()?;
        let mapping = Arc::get_mut(&mut self.mapping).ok_or(WholeMappingCustodyError::Busy)?;
        let cell = registered_cell(mapping.mapping_owner_key())?;
        let mut selection = try_lock(&cell.selection)?;
        match *selection {
            Selection::Selected {
                epoch: actual,
                uncertain: false,
            } if actual == epoch => {}
            Selection::Selected { epoch: actual, .. } => {
                *selection = Selection::Selected {
                    epoch: actual,
                    uncertain: true,
                };
                return Err(WholeMappingCustodyError::Selected);
            }
            Selection::Ordinary => return Err(WholeMappingCustodyError::Selected),
        }
        *selection = Selection::Selected {
            epoch,
            uncertain: true,
        };
        let result = service(mapping);
        // Generic closure success cannot authenticate paired admission balance
        // or native retirement. The selected owner remains uncertain.
        Ok(result)
    }
}

impl Drop for RetainedWholeMapping {
    fn drop(&mut self) {
        let mapping_owner = Arc::as_ptr(&self.mapping) as usize;
        paired_service::revoke_owner(mapping_owner);
        if let Some(cell) = &self.cell
            && cell.lease_owner.load(Ordering::Acquire) == mapping_owner
        {
            cell.lease_alive.store(false, Ordering::Release);
        }
        if let Some(slot) = &self.retention_slot {
            slot.retain(Arc::clone(&self.mapping));
            return;
        }
        // Retain the actual mapping owner, not a copied address or receipt.
        // A poisoned quarantine still leaves a strong owner alive forever.
        let mapping = Arc::clone(&self.mapping);
        match quarantine().lock() {
            Ok(mut owners)
                if self.quarantine_reserved
                    && self.mapping.mapping_process_id as u32 == std::process::id() =>
            {
                owners.reserved -= 1;
                // Selection reserved this exact slot before native effects.
                owners.owners.push(mapping);
            }
            _ => std::mem::forget(mapping),
        }
    }
}

impl RetainedWholeMapping {
    fn unvalidated(mapping: Arc<MappedSetupRegion>, epoch: u64) -> Self {
        Self {
            mapping,
            domain: None,
            cell: None,
            ring_headers: Arc::from([]),
            roster_narrowed: false,
            epoch,
            operation_capacity: 16,
            quarantine_reserved: false,
            retention_slot: None,
            status: Err(WholeMappingCustodyError::Selected),
        }
    }

    fn select_original_mapping(&mut self) {
        self.select_original_mapping_preselected(None);
    }

    fn select_original_mapping_preselected(&mut self, preselected: Option<&Arc<Domain>>) {
        let epoch = self.epoch;
        let mut ring_headers: Arc<[usize]> = Arc::from([]);
        let status = (|| {
            let domain = registered_domain(self.mapping.mapping_owner_key())?;
            self.domain = Some(Arc::clone(&domain));
            let cell = registered_cell(self.mapping.mapping_owner_key())?;
            if !self
                .mapping
                .mapping_registration
                .as_ref()
                .is_some_and(|registration| Arc::ptr_eq(&registration.cell, &cell))
            {
                return Err(WholeMappingCustodyError::Unregistered);
            }
            self.cell = Some(Arc::clone(&cell));
            // Every endpoint shares the backing fence but adopts its own
            // original mmap cell once. A second node never renews this cell.
            domain.selected.store(true, Ordering::Release);
            if let Some(original) = preselected
                && !Arc::ptr_eq(original, &domain)
            {
                return Err(WholeMappingCustodyError::Unregistered);
            }
            cell.selected
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| WholeMappingCustodyError::Selected)?;
            let _backing_loan = try_lock(&domain.selection)?;
            let mut selection = try_lock(&cell.selection)?;
            *selection = Selection::Selected {
                epoch,
                uncertain: true,
            };
            cell.epoch.store(epoch, Ordering::Release);
            if self.retention_slot.is_none() {
                reserve_quarantine()?;
                self.quarantine_reserved = true;
            }
            if self.operation_capacity == 0 || self.operation_capacity > 65_536 {
                return Err(WholeMappingCustodyError::ResourceLimit);
            }
            if epoch == 0 {
                return Err(WholeMappingCustodyError::ZeroEpoch);
            }

            let rings = self
                .mapping
                .hot_fork_ring_io_snapshot()
                .map_err(|_| WholeMappingCustodyError::NotQuiescent)?;
            if !rings.quiescent() {
                return Err(WholeMappingCustodyError::NotQuiescent);
            }
            ring_headers = self.mapping.selected_ring_header_addresses()?.into();
            *selection = Selection::Selected {
                epoch,
                uncertain: false,
            };
            Ok(())
        })();
        self.ring_headers = ring_headers;
        self.status = status;
    }
}

impl MappedSetupRegion {
    /// Captures current owner metadata without dereferencing the mapping.
    pub(super) fn mapping_owner_key(&self) -> MappingOwnerKey {
        MappingOwnerKey {
            address: self.mapping_start(),
            length: self.len,
            identity: self.backing_identity,
            process: self.mapping_process_id as u32,
        }
    }

    /// Consumes the original mapping into sticky whole-controller custody.
    ///
    /// Selection precedes fallible validation. Refusal retains the actual
    /// mapping owner and cannot fall back to ordinary release. The supplied
    /// epoch remains correlation until the native constructor authenticates it.
    #[must_use]
    pub fn retain_whole_mapping(self, epoch: u64) -> RetainedWholeMapping {
        let mut retained = RetainedWholeMapping::unvalidated(Arc::new(self), epoch);
        retained.select_original_mapping();
        retained
    }
}

#[path = "selected_lifecycle/owned_setup.rs"]
mod owned_setup;

pub use owned_setup::OwnedSetupMapping;

#[cfg(all(
    test,
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
#[path = "selected_lifecycle_tests.rs"]
mod tests;

#[path = "selected_lifecycle/paired_service.rs"]
mod paired_service;

pub use paired_service::{SelectedRingAdmissionBudget, SelectedRingCompletion};

pub(crate) use paired_service::{admit_selected_header, refuse_selected_admission};

/// Authorizes a typed view before any access to mapped memory.
///
/// # Errors
///
/// Refuses unregistered or foreign process ownership and selected access
/// outside the exact original current thread's live paired permit.
pub(super) fn authorize_mutable_view(
    owner: MappingOwnerKey,
) -> Result<(), WholeMappingCustodyError> {
    let domain = registered_domain(owner)?;
    let cell = registered_cell(owner)?;
    if paired_service::authorize_selected_mapping(&cell, domain.selected.load(Ordering::Acquire)) {
        Ok(())
    } else {
        Err(WholeMappingCustodyError::Selected)
    }
}

#[path = "selected_lifecycle/shared_owned_setup.rs"]
mod shared_owned_setup;

pub use shared_owned_setup::{
    OrdinaryPreparationView, PreparedDirectedRingHoldError, PreparedDirectedRingHoldSnapshot,
    PreparedDirectedRingRoster, SharedOwnedSetupMapping, SharedSetupMappingReadGuard,
};

/// Checks exact selected targets before any mutable entry slice is created.
///
/// # Errors
///
/// Refuses a foreign current mapping or a target outside its live permit.
pub(super) fn authorize_mutable_headers(
    mapping: &MappedSetupRegion,
    offsets: &[usize],
) -> Result<(), WholeMappingCustodyError> {
    let owner = mapping.mapping_owner_key();
    let domain = registered_domain(owner)?;
    let cell = registered_cell(owner)?;
    let backing_selected = domain.selected.load(Ordering::Acquire);
    if backing_selected
        && !mapping
            .hot_fork_ring_io_snapshot()
            .map_err(|_| WholeMappingCustodyError::NotQuiescent)?
            .quiescent()
    {
        paired_service::refuse_selected_admission();
        return Err(WholeMappingCustodyError::NotQuiescent);
    }

    for &offset in offsets {
        let address = owner
            .address
            .checked_add(offset)
            .ok_or(WholeMappingCustodyError::Selected)?;
        if !paired_service::authorize_selected_view(&cell, backing_selected, address) {
            return Err(WholeMappingCustodyError::Selected);
        }
    }
    Ok(())
}
