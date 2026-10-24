//! PID-tagged ownership for the original setup field and short native callbacks.
//!
//! A fork child never enters a copied parent ownership mutex. It authenticates
//! immutable registration, installs the actual replacement, and publishes fresh
//! process-private control in the same setup wrapper. No private pointer enters
//! the shared-memory protocol.

use std::cell::RefCell;
use std::ops::Deref;
use std::sync::atomic::AtomicPtr;

use crate::HotForkChildMappingInstallError;

use super::{
    Arc, AtomicBool, Domain, MappedSetupRegion, MappingOwnerKey, MappingRegistration, Mutex,
    MutexGuard, Ordering, OwnedSetupMapping, RetainedWholeMapping, ScopeCell,
    SetupRegionBackingIdentity, WholeMappingCustodyError, registered_cell, registered_domain,
    try_lock,
};

struct OwnerGeneration {
    process: u32,
    registration: ForkRegistration,
    owner: Mutex<OwnedSetupMapping>,
    domain: Result<Arc<Domain>, WholeMappingCustodyError>,
    cell: Result<Arc<ScopeCell>, WholeMappingCustodyError>,
    intent: AtomicBool,
    prepared_hold: AtomicBool,
    selected: AtomicBool,
    failed: AtomicBool,
    retention_slot: Arc<super::RetentionSlot>,
}

impl OwnerGeneration {
    fn new(mapping: MappedSetupRegion) -> Self {
        let domain = registered_domain(mapping.mapping_owner_key());
        let cell = registered_cell(mapping.mapping_owner_key());
        let registration = ForkRegistration {
            owner: mapping.mapping_owner_key(),
            region_len: mapping.region_len,
            domain: domain.clone(),
            cell: cell.clone(),
        };
        let owner = OwnedSetupMapping::new(mapping);
        let retention_slot = owner.retention_slot();
        Self {
            process: std::process::id(),
            registration,
            owner: Mutex::new(owner),
            retention_slot,
            domain,
            cell,
            intent: AtomicBool::new(false),
            prepared_hold: AtomicBool::new(false),
            selected: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }
    }

    fn refuse_control(&self) {
        self.failed.store(true, Ordering::Release);
        if let Ok(cell) = &self.cell {
            cell.lease_alive.store(false, Ordering::Release);
            super::paired_service::revoke_cell(cell);
        }
    }
}

struct ForkRegistration {
    owner: MappingOwnerKey,
    region_len: u64,
    domain: Result<Arc<Domain>, WholeMappingCustodyError>,
    cell: Result<Arc<ScopeCell>, WholeMappingCustodyError>,
}

thread_local! {
    // A live read guard or mutable construction loan in the calling thread
    // must not survive child replacement. Vanished threads never drop guards.
    static READ_OWNERS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// Holds a read reference to the original mapping under its ownership guard.
///
/// References obtained through this guard cannot outlive it. The guard must
/// end before returning to native code or requesting a selected mutable loan.
pub struct SharedSetupMappingReadGuard<'a> {
    owner: MutexGuard<'a, OwnedSetupMapping>,
    wrapper: usize,
}

impl Deref for SharedSetupMappingReadGuard<'_> {
    type Target = MappedSetupRegion;

    fn deref(&self) -> &Self::Target {
        self.owner.mapping()
    }
}

impl Drop for SharedSetupMappingReadGuard<'_> {
    fn drop(&mut self) {
        READ_OWNERS.with(|owners| {
            if let Ok(mut owners) = owners.try_borrow_mut()
                && let Some(index) = owners.iter().rposition(|owner| *owner == self.wrapper)
            {
                owners.remove(index);
            }
        });
    }
}

/// Lends original queue construction without transferring mapped-resource ownership.
///
/// The view has no constructor, mutable-map accessor or `DerefMut` implementation.
/// Queue references borrow this view and retain the mapped region's existing
/// validation and ordinary gates. This Rust borrow grants no native permission.
///
/// Replacing the mapped resource through a safe callback is unavailable:
///
/// ```compile_fail
/// use crucible_qemu_shmem::{MappedSetupRegion, OrdinaryPreparationView};
/// fn replace_original(view: &mut OrdinaryPreparationView<'_>, replacement: MappedSetupRegion) {
///     std::mem::replace(view, replacement);
/// }
/// ```
/// Distinct callback loans also cannot exchange their private map borrows:
///
/// ```compile_fail
/// use crucible_qemu_shmem::SharedOwnedSetupMapping;
/// fn swap_originals(first: &SharedOwnedSetupMapping, second: &SharedOwnedSetupMapping) {
///     let _ = first.with_ordinary_preparation(|first_view| {
///         let _ = second.with_ordinary_preparation(|second_view| {
///             std::mem::swap(first_view, second_view);
///             Ok::<_, ()>(())
///         });
///         Ok::<_, ()>(())
///     });
/// }
/// ```
pub struct OrdinaryPreparationView<'mapping> {
    mapping: &'mapping mut MappedSetupRegion,
}

impl OrdinaryPreparationView<'_> {
    /// Returns the original process-private VMA address without reading its pages.
    pub fn mapping_start(&self) -> usize {
        self.mapping.mapping_start()
    }

    /// Returns the original retained backing identity without inspecting headers.
    pub fn backing_identity(&self) -> SetupRegionBackingIdentity {
        self.mapping.backing_identity()
    }

    /// Borrows two original directed rings for construction of queue adapters.
    ///
    /// Both ring references end with this view's borrow. This method preserves
    /// the original region's checked geometry and ordinary mutation gates.
    ///
    /// # Errors
    /// Refuses invalid headers, absent nodes or rings, duplicate rings, foreign
    /// ownership, selected custody or out-of-bounds typed segments.
    pub fn node_directed_ring_pair_mut(
        &mut self,
        node_slot: u32,
        first_src_slot: u32,
        first_dst_slot: u32,
        second_src_slot: u32,
        second_dst_slot: u32,
    ) -> Result<crate::MappedNodeRingPairMut<'_>, crate::MappedSetupRegionAccessError> {
        self.mapping.node_directed_ring_pair_mut(
            node_slot,
            first_src_slot,
            first_dst_slot,
            second_src_slot,
            second_dst_slot,
        )
    }
}

/// Owns the original setup field through process-private callback generations.
///
/// Native callbacks borrow this field through shared userdata. Short ownership
/// guards end before returning to C. Fork replacement also uses shared access:
/// it authenticates immutable parent registration without entering inherited
/// locks, then publishes only the actual current-process replacement owner.
pub struct SharedOwnedSetupMapping {
    current: AtomicPtr<OwnerGeneration>,
}

struct SharedPreparationFence<'a> {
    owner: &'a SharedOwnedSetupMapping,
    process: u32,
    wrapper: usize,
    registered: bool,
    succeeded: bool,
}

impl Drop for SharedPreparationFence<'_> {
    fn drop(&mut self) {
        if self.process != std::process::id() {
            return;
        }
        if self.registered {
            READ_OWNERS.with(|owners| {
                if let Ok(mut owners) = owners.try_borrow_mut()
                    && let Some(index) = owners.iter().rposition(|owner| *owner == self.wrapper)
                {
                    owners.remove(index);
                }
            });
        }
        if !self.succeeded {
            self.owner.refuse_whole_control();
        }
    }
}

struct SharedCallbackFence<'a> {
    generation: &'a OwnerGeneration,
    succeeded: bool,
}

impl Drop for SharedCallbackFence<'_> {
    fn drop(&mut self) {
        if !self.succeeded {
            self.generation.refuse_control();
        }
    }
}

impl SharedOwnedSetupMapping {
    /// Wraps the original setup mapping before registering callbacks.
    #[must_use]
    pub fn new(mapping: MappedSetupRegion) -> Self {
        Self {
            current: AtomicPtr::new(Box::into_raw(Box::new(OwnerGeneration::new(mapping)))),
        }
    }

    fn generation(&self) -> Result<&OwnerGeneration, WholeMappingCustodyError> {
        let pointer = self.current.load(Ordering::Acquire);
        // SAFETY: construction always publishes one initialized Box. A shared
        // child install retains previous generations permanently, and only
        // exclusive wrapper Drop destroys its final current allocation.
        let generation = unsafe { &*pointer };
        if generation.process != std::process::id() {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        Ok(generation)
    }

    /// Borrows the same immutable mapping under a short ownership guard.
    ///
    /// # Errors
    ///
    /// Refuses foreign process ownership before any inherited mutex, then
    /// refuses busy, poisoned or unregistered current ownership.
    pub fn mapping(&self) -> Result<SharedSetupMappingReadGuard<'_>, WholeMappingCustodyError> {
        let generation = self.generation()?;
        let owner = try_lock(&generation.owner)?;
        registered_domain(owner.mapping().mapping_owner_key())?;
        let wrapper = std::ptr::from_ref(self) as usize;
        READ_OWNERS.with(|owners| {
            let mut owners = owners
                .try_borrow_mut()
                .map_err(|_| WholeMappingCustodyError::Busy)?;
            owners
                .try_reserve(1)
                .map_err(|_| WholeMappingCustodyError::ResourceLimit)?;
            owners.push(wrapper);
            Ok::<_, WholeMappingCustodyError>(())
        })?;
        Ok(SharedSetupMappingReadGuard { owner, wrapper })
    }

    /// Borrows the unique ordinary mapping before callback registration.
    ///
    /// # Errors
    ///
    /// Refuses foreign ownership, sticky selection, poisoning or another
    /// strong map owner. Shared child replacement uses its separate API.
    pub fn ordinary_mapping_mut(
        &mut self,
    ) -> Result<&mut MappedSetupRegion, WholeMappingCustodyError> {
        let pointer = *self.current.get_mut();
        // SAFETY: exclusive access to the wrapper excludes every generation
        // guard and callback borrowed through it. The current Box is live.
        let generation = unsafe { &mut *pointer };
        if generation.process != std::process::id() {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        if generation.intent.load(Ordering::Acquire)
            || generation.prepared_hold.load(Ordering::Acquire)
            || generation.selected.load(Ordering::Acquire)
            || generation.failed.load(Ordering::Acquire)
        {
            return Err(WholeMappingCustodyError::Selected);
        }
        generation
            .owner
            .get_mut()
            .map_err(|_| WholeMappingCustodyError::Poisoned)?
            .ordinary_mapping_mut()
    }

    /// Lends the unique ordinary mapping for stopped callback construction.
    ///
    /// The caller reserves owning retention and authenticates its native
    /// preparation before entering this closure. It constructs registered
    /// queue handles from this same mapping,
    /// then ends the loan before native setters or HOLD. No mapping reference
    /// can escape. The helper creates no native preparation or execution grant.
    /// Per-method ordinary mutation gates remain active; no backing-domain
    /// selection lock spans the callback.
    ///
    /// # Errors
    ///
    /// Refuses foreign PID before inherited locks, intent, selection, sticky
    /// failure, unprepared retention, busy or poisoned ownership, or another
    /// strong mapping owner. Current-generation error or panic sticks refusal.
    /// Concurrent whole intent makes the result unavailable even when the
    /// callback itself succeeds.
    pub fn with_ordinary_preparation<T, E>(
        &self,
        callback: impl FnOnce(&mut OrdinaryPreparationView<'_>) -> Result<T, E>,
    ) -> Result<Result<T, E>, WholeMappingCustodyError> {
        let generation = self.generation()?;
        let mut fence = SharedPreparationFence {
            owner: self,
            process: generation.process,
            wrapper: std::ptr::from_ref(self) as usize,
            registered: false,
            succeeded: false,
        };
        if !generation.retention_slot.armed() {
            return Err(WholeMappingCustodyError::ResourceLimit);
        }
        let domain = generation.domain.as_ref().map_err(|error| *error)?;
        let ordinary_current = || {
            !generation.intent.load(Ordering::Acquire)
                && !generation.selected.load(Ordering::Acquire)
                && !generation.failed.load(Ordering::Acquire)
                && !domain.selected.load(Ordering::Acquire)
        };
        if !ordinary_current() {
            return Err(WholeMappingCustodyError::Selected);
        }
        let mut owner = try_lock(&generation.owner)?;
        if !ordinary_current() {
            return Err(WholeMappingCustodyError::Selected);
        }
        let mapping = owner.ordinary_mapping_mut()?;
        // Shared child replacement must see this current-thread mutable loan
        // just as it sees immutable mapping guards. Admission allocates and
        // publishes the marker before callback construction or mapped effects.
        READ_OWNERS.with(|owners| {
            let mut owners = owners
                .try_borrow_mut()
                .map_err(|_| WholeMappingCustodyError::Busy)?;
            owners
                .try_reserve(1)
                .map_err(|_| WholeMappingCustodyError::ResourceLimit)?;
            owners.push(fence.wrapper);
            Ok::<_, WholeMappingCustodyError>(())
        })?;
        fence.registered = true;
        let mut construction = OrdinaryPreparationView { mapping };
        let result = callback(&mut construction);
        // A callback which forks cannot return copied ownership or generic
        // destructors through this process-private loan. Only the original
        // parent may unlock its guard or publish its construction result.
        if generation.process != std::process::id() {
            std::mem::forget(result);
            std::mem::forget(fence);
            std::mem::forget(owner);
            return Err(WholeMappingCustodyError::Unregistered);
        }
        if !std::ptr::eq(self.generation()?, generation) {
            return Err(WholeMappingCustodyError::Unregistered);
        }

        if !ordinary_current() {
            return Err(WholeMappingCustodyError::Selected);
        }
        fence.succeeded = result.is_ok();
        Ok(result)
    }

    /// Reserves bounded owning retention before any native source HOLD.
    ///
    /// Constructor preparation calls this before native HOLD, registration or
    /// getter effects. It allocates only process-private retention storage and
    /// neither fences aliases nor inspects mapped headers. Once successful,
    /// the same original allocation can remain owned through every failed
    /// intent and selected adoption without another retention allocation.
    ///
    /// # Errors
    ///
    /// Refuses foreign, previously failed, busy, poisoned or exhausted
    /// retention. Failure must stop construction before native source effects.
    pub fn prepare_whole_intent_retention(&self) -> Result<(), WholeMappingCustodyError> {
        let generation = self.generation()?;
        if generation.failed.load(Ordering::Acquire) {
            return Err(WholeMappingCustodyError::Selected);
        }
        if let Err(error) = generation.retention_slot.reserve() {
            generation.refuse_control();
            return Err(error);
        }
        if generation.failed.load(Ordering::Acquire) {
            return Err(WholeMappingCustodyError::Selected);
        }
        Ok(())
    }

    /// Fences ordinary aliases before observing the original native constructor.
    ///
    /// Preparation reserves retention before the real HOLD barrier. The
    /// source invokes this after that barrier and before fallible
    /// getter or body observation. The backing fence is sticky and reaches
    /// every alias before waiting on any existing ordinary mutation loan.
    /// Its short loan ends before native reentry. No epoch, permit, credit,
    /// native readiness or execution authority is created by this operation.
    ///
    /// # Errors
    ///
    /// Refuses foreign, unavailable, busy, poisoned or previously failed
    /// ownership. A failed intent remains fenced and retains its actual owner.
    pub fn begin_whole_intent(&self) -> Result<(), WholeMappingCustodyError> {
        let generation = self.generation()?;
        if !generation.retention_slot.armed() {
            generation.refuse_control();
            return Err(WholeMappingCustodyError::ResourceLimit);
        }
        generation.intent.store(true, Ordering::Release);
        let result = (|| {
            let domain = generation.domain.as_ref().map_err(|error| *error)?;
            domain.selected.store(true, Ordering::Release);
            if generation.failed.load(Ordering::Acquire) {
                return Err(WholeMappingCustodyError::Selected);
            }
            // The fence prevents new loans; existing ordinary work must have
            // ended before the caller makes any native getter observation.
            let _ordinary_loan = try_lock(&domain.selection)?;
            Ok(())
        })();
        if result.is_err() {
            generation.refuse_control();
        }
        result
    }

    /// Cancels the original local scope before any native failure is returned.
    ///
    /// The provider calls this on every failure after whole intent, including
    /// failures before it can borrow selected custody or validate native
    /// currentness. Cancellation touches only private generation/cell atomics
    /// and this thread's exact-cell TLS permit. It enters no ownership mutex
    /// and reads no mapped header, including for a copied foreign-PID owner.
    ///
    /// The same allocation remains intent-fenced and failed. No stopped cut,
    /// native retirement, release, ACK consumption or new credit is inferred.
    pub fn refuse_whole_control(&self) {
        let pointer = self.current.load(Ordering::Acquire);
        // SAFETY: the initialized current generation remains live while this
        // shared wrapper borrow exists. Refusal needs only immutable private
        // references, and never enters a potentially inherited mutex.
        let generation = unsafe { &*pointer };
        if generation.retention_slot.armed() {
            generation.intent.store(true, Ordering::Release);
            if let Ok(domain) = &generation.domain {
                domain.selected.store(true, Ordering::Release);
            }
        }
        generation.refuse_control();
    }

    /// Selects the default sixteen command slots in this same setup field.
    ///
    /// # Errors
    ///
    /// Returns the same sticky custody refusals as [`Self::select_whole_bounded`].
    pub fn select_whole(&self, epoch: u64) -> Result<(), WholeMappingCustodyError> {
        self.select_whole_bounded(epoch, 16)
    }

    /// Selects constructor-bounded whole custody from shared native userdata.
    ///
    /// Selection fences every ordinary alias before a fallible owner lock.
    /// Each original mapping retains its own epoch and operation counter.
    /// The native constructor separately authenticates epoch and capacity.
    ///
    /// # Errors
    ///
    /// Refuses foreign ownership, prior selection, invalid bounds, unavailable
    /// storage or registration, and rings that are not held and drained.
    pub fn select_whole_bounded(
        &self,
        epoch: u64,
        operation_capacity: u64,
    ) -> Result<(), WholeMappingCustodyError> {
        self.select_whole_inner(epoch, operation_capacity, None)
    }

    /// Adopts the exact source-constructor roster under one original owner guard.
    ///
    /// The native getter and original constructor receipt authenticate this
    /// epoch, capacity and roster before adoption. The backing fence, original
    /// mapping cell and restricted roster are installed before this method
    /// returns. No ownership guard crosses a native callback boundary.
    ///
    /// # Errors
    ///
    /// Returns sticky selection or original-header roster refusal. A failed
    /// or concurrently refused adoption cannot publish successful custody.
    /// This method establishes no native readiness or execution authority.
    pub fn select_whole_roster_bounded(
        &self,
        epoch: u64,
        operation_capacity: u64,
        header_offsets: &[u64],
    ) -> Result<(), WholeMappingCustodyError> {
        self.select_whole_inner(epoch, operation_capacity, Some(header_offsets))
    }

    fn select_whole_inner(
        &self,
        epoch: u64,
        operation_capacity: u64,
        header_offsets: Option<&[u64]>,
    ) -> Result<(), WholeMappingCustodyError> {
        let generation = self.generation()?;
        if let Err(error) = generation.retention_slot.reserve() {
            generation.refuse_control();
            return Err(error);
        }
        generation.intent.store(true, Ordering::Release);
        if generation.failed.load(Ordering::Acquire) {
            generation.refuse_control();
            return Err(WholeMappingCustodyError::Selected);
        }
        let result = (|| {
            generation
                .selected
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| WholeMappingCustodyError::Selected)?;
            let domain = generation.domain.as_ref().map_err(|error| *error)?;
            domain.selected.store(true, Ordering::Release);
            let mut owner = try_lock(&generation.owner)?;
            owner.select_whole_preselected(epoch, operation_capacity, domain)?;
            if let Some(offsets) = header_offsets {
                owner
                    .selected_mut()?
                    .restrict_paired_header_offsets(offsets)?;
            }
            if generation.failed.load(Ordering::Acquire) {
                return Err(WholeMappingCustodyError::Selected);
            }
            Ok(())
        })();
        if result.is_err() {
            generation.refuse_control();
        }
        result
    }

    /// Borrows selected custody for one short native callback.
    ///
    /// The callback may begin, end or retire a paired scope. Existing registered
    /// queue handles perform native IO between begin and end using its TLS
    /// permit. No borrowed mapping reference can escape this closure.
    ///
    /// # Errors
    ///
    /// Refuses foreign, ordinary, failed, busy or poisoned custody, or retains
    /// the callback's original error. Native authentication remains separate.
    pub fn with_selected<T, E>(
        &self,
        callback: impl FnOnce(&mut RetainedWholeMapping) -> Result<T, E>,
    ) -> Result<Result<T, E>, WholeMappingCustodyError> {
        let generation = self.generation()?;
        if generation.failed.load(Ordering::Acquire) {
            generation.refuse_control();
            return Err(WholeMappingCustodyError::Selected);
        }
        if !generation.selected.load(Ordering::Acquire) {
            return Err(WholeMappingCustodyError::Unregistered);
        }
        let mut owner = match try_lock(&generation.owner) {
            Ok(owner) => owner,
            Err(error) => {
                generation.refuse_control();
                return Err(error);
            }
        };
        let selected = match owner.selected_mut() {
            Ok(selected) => selected,
            Err(error) => {
                generation.refuse_control();
                return Err(error);
            }
        };
        let mut fence = SharedCallbackFence {
            generation,
            succeeded: false,
        };
        let result = callback(selected);
        fence.succeeded = result.is_ok();
        if result.is_err() {
            generation.refuse_control();
        }
        Ok(result)
    }

    /// Installs the actual fork replacement through shared setup userdata.
    ///
    /// Foreign generations are authenticated before locks or mapped reads.
    /// The fresh owner and all control storage are allocated before the actual
    /// exact-address install. Parent mutexes and abandoned parent guards remain
    /// in their old generation; no mutable parent reference is manufactured.
    ///
    /// # Errors
    ///
    /// Refuses current-process reuse, inherited selection, a calling-thread
    /// read guard, unavailable storage or registration, and the original
    /// replacement descriptor or exact-address mapping errors.
    pub fn install_hot_fork_child_mapping(
        &self,
        fd: std::os::fd::BorrowedFd<'_>,
        expected: SetupRegionBackingIdentity,
    ) -> Result<(), HotForkChildMappingInstallError> {
        let refusal = |source| HotForkChildMappingInstallError::WholeCustody { source };
        let original_pointer = self.current.load(Ordering::Acquire);
        // SAFETY: published owner generations have immutable PID headers and
        // remain live until exclusive Drop. This does not enter their mutex.
        let parent = unsafe { &*original_pointer };
        if parent.process == std::process::id() {
            return Err(refusal(WholeMappingCustodyError::Unregistered));
        }
        let wrapper = std::ptr::from_ref(self) as usize;
        if READ_OWNERS.with(|owners| owners.borrow().contains(&wrapper)) {
            return Err(refusal(WholeMappingCustodyError::Busy));
        }
        let domain = parent
            .registration
            .domain
            .as_ref()
            .map_err(|error| refusal(*error))?;
        if parent.intent.load(Ordering::Acquire)
            || parent.selected.load(Ordering::Acquire)
            || domain.selected.load(Ordering::Acquire)
        {
            return Err(refusal(WholeMappingCustodyError::Selected));
        }
        let cell = parent
            .registration
            .cell
            .as_ref()
            .map_err(|error| refusal(*error))?;
        let key = parent.registration.owner;
        let mapping = MappedSetupRegion {
            address: key.address,
            len: key.length,
            region_len: parent.registration.region_len,
            backing_identity: key.identity,
            mapping_process_id: key.process as libc::pid_t,
            mapping_registration: Some(MappingRegistration {
                owner: key,
                domain: Arc::clone(domain),
                cell: Arc::clone(cell),
            }),
        };
        let mut replacement = Box::new(OwnerGeneration::new(mapping));
        let owner = replacement
            .owner
            .get_mut()
            .map_err(|_| refusal(WholeMappingCustodyError::Poisoned))?;
        owner
            .ordinary_mapping_mut()
            .map_err(refusal)?
            .install_hot_fork_child_mapping(fd, expected)?;
        replacement.domain = registered_domain(owner.mapping().mapping_owner_key());
        replacement.cell = registered_cell(owner.mapping().mapping_owner_key());
        replacement.registration = ForkRegistration {
            owner: owner.mapping().mapping_owner_key(),
            region_len: owner.mapping().region_len,
            domain: replacement.domain.clone(),
            cell: replacement.cell.clone(),
        };
        replacement
            .domain
            .as_ref()
            .map_err(|error| refusal(*error))?;
        replacement.cell.as_ref().map_err(|error| refusal(*error))?;
        let replacement_pointer = Box::into_raw(replacement);
        if self
            .current
            .compare_exchange(
                original_pointer,
                replacement_pointer,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // SAFETY: this candidate was never published. Its actual mapping
            // owner removes only its authenticated current record on Drop.
            drop(unsafe { Box::from_raw(replacement_pointer) });
            return Err(refusal(WholeMappingCustodyError::Busy));
        }
        // Retain the inherited generation: its copied mutex guard may still
        // exist in the child calling thread, and must not be destroyed here.
        Ok(())
    }
}

impl Drop for SharedOwnedSetupMapping {
    fn drop(&mut self) {
        let pointer = *self.current.get_mut();
        // SAFETY: exclusive wrapper Drop excludes its live borrowed guards.
        // Previous generations were retained on replacement and are separate.
        let mut generation = unsafe { Box::from_raw(pointer) };
        if generation.process != std::process::id() {
            // A child may drop a copied parent guard later. Keep its private
            // mutex and owner live rather than destroying inherited storage.
            std::mem::forget(generation);
            return;
        }
        generation.refuse_control();
        if generation.intent.load(Ordering::Acquire)
            || generation.selected.load(Ordering::Acquire)
            || generation.prepared_hold.load(Ordering::Acquire)
            || (generation.retention_slot.armed()
                && generation
                    .domain
                    .as_ref()
                    .is_ok_and(|domain| domain.selected.load(Ordering::Acquire)))
        {
            let owner = match generation.owner.get_mut() {
                Ok(owner) => owner,
                Err(poisoned) => poisoned.into_inner(),
            };
            owner.retain_failed_selection_owner();
        }
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_abi = "",
    target_endian = "little",
    target_pointer_width = "64"
))]
#[path = "shared_owned_setup_tests.rs"]
mod tests;

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_abi = "",
    target_endian = "little",
    target_pointer_width = "64"
))]
#[path = "shared_owned_setup/ordinary_preparation_tests.rs"]
mod ordinary_preparation_tests;

#[path = "shared_owned_setup/prepared_directed.rs"]
mod prepared_directed;

pub use prepared_directed::{
    PreparedDirectedRingHoldError, PreparedDirectedRingHoldSnapshot, PreparedDirectedRingRoster,
};
