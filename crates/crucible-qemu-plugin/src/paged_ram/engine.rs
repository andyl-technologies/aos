//! Owns paused cold activation and an independently progressing fault service.
//!
//! This backend reserves complete logical RAM between eviction boundaries. It
//! never holds a capacity fault waiting for a boundary that the fault prevents.
//! Native physical-borrow authority is required through destructive activation;
//! BQL ownership alone is insufficient. Fault service uses no QEMU mutex, replay
//! token, root callback, simulated event, or guest clock.

use std::io;
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

use crate::ram_error::RamError;
use crucible_ram::MetadataReservation;

mod failure;
pub(crate) use failure::RetainedOperationalFailure;
mod admission;
use admission::{ServiceConfiguration, prepare_service, prepare_service_for_inventory};
mod mutation;
mod scheduling;
mod statistics;
pub(crate) use statistics::PagingStatistics;
use statistics::{PagingCounters, count_bulk_completed, count_completed};
mod fork;
mod locking;
mod mixed;
mod placement;
mod strict_placement;
use mixed::{ArenaPlacement, validate_arena};
mod service;
pub(crate) use fork::{ChildArenaConfiguration, ChildPagingCustody, PreparedChildArenas};
use service::{FaultService, operational_read, operational_rearm, root_scratch_read};

use super::restore::{
    PreparedRestoreMapping, PreparedRestoreSource, RestoreMappingOwner, RestorePageSource,
    ValidatedRestoreSource,
};
use super::source::{
    NativePageHasher, SourceOperation, SourceOperationClass, SourceOperationFactory,
};
use super::{FaultEvent, PAGE_BYTES, Registration};
use crate::args::PluginRamResources;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeArena {
    schema: u32,
    region_index: u32,
    topology_generation: u64,
    host_address: u64,
    mapping_length: u64,
    logical_length: u64,
    flags: u64,
}

type ReadArena = extern "C" fn(u64, u32, *mut NativeArena) -> c_int;
type PhysicalCallback = extern "C" fn(*mut c_void) -> c_int;
type PhysicalRun = extern "C" fn(PhysicalCallback, *mut c_void) -> c_int;
type PhysicalBegin = extern "C" fn(u64, *mut u64) -> c_int;
type PhysicalValidate = extern "C" fn(u64, u64) -> c_int;
type PhysicalEnd = extern "C" fn(u64) -> c_int;
type PinTopology = extern "C" fn(u64, u64) -> c_int;
type MarkWrite = extern "C" fn(u64, u32, u64) -> c_int;
type ReadWriteGeneration = extern "C" fn(u64, u64, *mut u64) -> c_int;
type AcknowledgeSource = extern "C" fn(u64) -> c_int;
type OperationalRead = extern "C" fn(u64, *mut u8, u32) -> c_int;

/// Contains a synchronous full-root reader's private page scratch.
#[repr(C)]
struct NativeRootScratch {
    bytes: [u8; PAGE_BYTES],
}

type RootScratchRead =
    extern "C" fn(u64, *mut NativeRootScratch, u32, *const NativePageHasher) -> c_int;
type Rearm = extern "C" fn(u64) -> c_int;
type RegisterRearm = extern "C" fn(Option<Rearm>) -> c_int;
type RegisterPlacement = extern "C" fn(extern "C" fn() -> c_int) -> c_int;
type RegisterReaders = extern "C" fn(Option<OperationalRead>, Option<RootScratchRead>) -> c_int;
type ServiceWorker = extern "C" fn(u32, u64, u64, u32) -> c_int;

pub(crate) const PAGER_STACK_BYTES: usize = 2 * 1024 * 1024;

static NEXT_WORKER_GENERATION: AtomicU64 = AtomicU64::new(1);
static OPERATIONAL_OWNER: OnceLock<Mutex<Option<Arc<PausedPagingOwner>>>> = OnceLock::new();

#[derive(Clone, Copy)]
struct NativeOperations {
    arena: ReadArena,
    run: PhysicalRun,
    begin: PhysicalBegin,
    validate: PhysicalValidate,
    end: PhysicalEnd,
    pin: PinTopology,
    mark_write: MarkWrite,
    write_generation: ReadWriteGeneration,
    acknowledge: AcknowledgeSource,
    worker: ServiceWorker,
}

impl NativeOperations {
    fn resolve() -> Result<Self, RamError> {
        // SAFETY: each pointer is paired with its exact GPL-private native ABI.
        unsafe {
            Ok(Self {
                arena: std::mem::transmute::<*mut c_void, ReadArena>(symbol(
                    b"qemu_plugin_crucible_ram_arena_region_v1\0",
                )?),
                run: std::mem::transmute::<*mut c_void, PhysicalRun>(symbol(
                    b"qemu_plugin_crucible_ram_physical_run_v1\0",
                )?),
                begin: std::mem::transmute::<*mut c_void, PhysicalBegin>(symbol(
                    b"qemu_plugin_crucible_ram_physical_begin_v1\0",
                )?),
                validate: std::mem::transmute::<*mut c_void, PhysicalValidate>(symbol(
                    b"qemu_plugin_crucible_ram_physical_validate_v1\0",
                )?),
                end: std::mem::transmute::<*mut c_void, PhysicalEnd>(symbol(
                    b"qemu_plugin_crucible_ram_physical_end_v1\0",
                )?),
                pin: std::mem::transmute::<*mut c_void, PinTopology>(symbol(
                    b"qemu_plugin_crucible_ram_pin_topology_v1\0",
                )?),
                mark_write: std::mem::transmute::<*mut c_void, MarkWrite>(symbol(
                    b"qemu_plugin_crucible_ram_mark_write_v1\0",
                )?),
                write_generation: std::mem::transmute::<*mut c_void, ReadWriteGeneration>(symbol(
                    b"qemu_plugin_crucible_ram_write_generation_v1\0",
                )?),
                acknowledge: std::mem::transmute::<*mut c_void, AcknowledgeSource>(symbol(
                    b"qemu_plugin_crucible_ram_restore_ack_source_v1\0",
                )?),
                worker: std::mem::transmute::<*mut c_void, ServiceWorker>(symbol(
                    b"qemu_plugin_crucible_ram_service_worker_v1\0",
                )?),
            })
        }
    }
}

#[derive(Clone, Copy)]
struct Arena {
    native: NativeArena,
    page_start: usize,
    placement: ArenaPlacement,
}

#[derive(Clone, Default)]
struct PageState {
    version: u64,
    resident: bool,
    writable: bool,
    preserved: Option<super::PageRecord>,
}

/// Owns admitted full-peak arenas and retains fault authority through failures.
pub(crate) struct PausedPagingOwner {
    resources: PluginRamResources,
    operations: Arc<dyn SourceOperationFactory>,
    counters: Arc<PagingCounters>,
    active: Arc<Mutex<Option<Arc<FaultService>>>>,
    preparing: AtomicBool,
    failed: AtomicBool,
    first_operational_failure: OnceLock<RetainedOperationalFailure>,
    spill: Mutex<Option<Arc<Mutex<super::PreservedPages>>>>,
    performance_installed: AtomicBool,
    logical_bytes: AtomicU64,
    permanent_resident_bytes: AtomicU64,
    topology_generation: AtomicU64,
    policy: Mutex<Option<crucible_protocol::ram_control::RamControlPolicy>>,
    queued_operation: Mutex<Option<scheduling::QueuedPlacement>>,
    policy_generation: AtomicU64,
    requested_policy_revision: AtomicU64,
    placement_epoch: Arc<AtomicU64>,
    placement_receipt:
        Arc<Mutex<Option<crucible_protocol::ram_control::RamControlPlacementReceipt>>>,
    prepared_placement_receipt:
        Mutex<Option<crucible_protocol::ram_control::RamControlPlacementReceipt>>,
    locks: Arc<Mutex<Option<Arc<locking::LockedMemory>>>>,
    retained_lock_transition: Mutex<Option<strict_placement::LockTransition>>,
    write_preparation: Mutex<Option<mutation::WritePreparation>>,
    write_scratch: Mutex<Option<mutation::WriteScratch>>,
    write_generation: AtomicU64,
    kernel_probe: OnceLock<crucible_protocol::ram_control::RamControlKernelProbe>,
}

/// A bounded authority snapshot; physical counters require independent sampling.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PagingAuthoritySnapshot {
    pub(crate) logical_bytes: u64,
    pub(crate) topology_generation: u64,
    pub(crate) activated: bool,
    pub(crate) failed: bool,
    pub(crate) full_peak_bytes: u64,
    pub(crate) permanent_resident_bytes: u64,
}

impl PausedPagingOwner {
    /// Samples actual spill diagnostics without native or guest execution locks.
    pub(crate) fn performance(
        &self,
        action: crucible_protocol::ram_control::RamControlPerformanceAction,
    ) -> Result<Option<crucible_protocol::ram_control::RamControlPerformance>, RamError> {
        use crucible_protocol::ram_control::RamControlPerformanceAction;
        if action != RamControlPerformanceAction::Start
            && !self.performance_installed.load(Ordering::Acquire)
        {
            return Ok(None);
        }

        let budget = if action == RamControlPerformanceAction::Start {
            Some(crate::ram_fingerprint::fork_metadata_budget()?)
        } else {
            None
        };
        let spill = self
            .spill
            .try_lock()
            .map_err(|_| "performance spill ownership busy")?
            .as_ref()
            .cloned()
            .ok_or("performance spill not installed")?;
        let mut spill = spill.try_lock().map_err(|_| "performance spill I/O busy")?;
        if let Some(budget) = budget {
            spill.start_performance(&budget)?;
            // Publish only the installed bank. Stop retains this marker so its
            // completed interval stays observable; a fresh child starts false.
            self.performance_installed.store(true, Ordering::Release);
        }
        Ok(spill.performance(action == RamControlPerformanceAction::Stop)?)
    }

    /// Observes actual actor membership and retained failure without guest locks.
    pub(crate) fn fault_actor_report(
        &self,
    ) -> Result<Option<crucible_protocol::ram_control::RamControlFaultActorReport>, RamError> {
        let active = self
            .active
            .try_lock()
            .map_err(|_| "fault actor owner unavailable")?;
        let Some(service) = active.as_ref() else {
            return Ok(None);
        };
        let lifetime = service
            .lifetime
            .try_lock()
            .map_err(|_| "fault actor report unavailable")?;
        Ok(lifetime.report(service.worker_generation))
    }

    /// Requests the exact active actor's terminal return; all other custody stays.
    pub(crate) fn request_fault_actor_test_exit(&self, generation: u64) -> Result<(), RamError> {
        let active = self
            .active
            .try_lock()
            .map_err(|_| "fault actor owner unavailable")?;
        let service = active.as_ref().ok_or("fault actor is not active")?;
        if service.worker_generation != generation || !service.activated.load(Ordering::Acquire) {
            return Err(RamError::Invariant("fault actor generation is not active"));
        }
        service
            .lifetime
            .try_lock()
            .map_err(|_| "fault actor request unavailable")?
            .request_exit()
    }

    /// Returns the fixed pager actor stack, guard, and page-scratch peak.
    pub(crate) const fn required_staging_bytes() -> u64 {
        (PAGER_STACK_BYTES + PAGE_BYTES + PAGE_BYTES) as u64
    }

    /// Establishes the actual launched entitlement and live supervision owner.
    ///
    /// # Errors
    /// Returns incomplete resource admission or invalid operational ownership.
    pub(crate) fn new(
        resources: PluginRamResources,
        operations: Arc<dyn SourceOperationFactory>,
    ) -> Result<Arc<Self>, RamError> {
        if resources.resident_peak_bytes == 0
            || resources.metadata_bytes == 0
            || resources.paging_io_slots == 0
            || resources.task_slots == 0
            || resources.file_descriptors < 3
        {
            return Err(RamError::Invariant(
                "paging resource envelope is incomplete",
            ));
        }
        Ok(Arc::new(Self {
            resources,
            operations,
            counters: Arc::new(PagingCounters::default()),
            active: Arc::new(Mutex::new(None)),
            preparing: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            first_operational_failure: OnceLock::new(),
            spill: Mutex::new(None),
            performance_installed: AtomicBool::new(false),
            logical_bytes: AtomicU64::new(0),
            permanent_resident_bytes: AtomicU64::new(0),
            topology_generation: AtomicU64::new(0),
            policy: Mutex::new(None),
            queued_operation: Mutex::new(None),
            policy_generation: AtomicU64::new(0),
            requested_policy_revision: AtomicU64::new(0),
            placement_epoch: Arc::new(AtomicU64::new(0)),
            placement_receipt: Arc::new(Mutex::new(None)),
            prepared_placement_receipt: Mutex::new(None),
            locks: Arc::new(Mutex::new(None)),
            retained_lock_transition: Mutex::new(None),
            write_preparation: Mutex::new(None),
            write_scratch: Mutex::new(None),
            write_generation: AtomicU64::new(0),
            kernel_probe: OnceLock::new(),
        }))
    }

    /// Reports immutable facts obtained from this process's successful kernel negotiation.
    pub(crate) fn kernel_probe(
        &self,
    ) -> Option<crucible_protocol::ram_control::RamControlKernelProbe> {
        self.kernel_probe.get().copied()
    }

    fn record_kernel_probe(&self, registration: &Registration) -> Result<(), RamError> {
        self.kernel_probe
            .set(registration.kernel_probe())
            .map_err(|_| RamError::Invariant("kernel paging probe already sealed"))
    }

    /// Rebinds a fully quiesced resident child to fresh policy/source authority.
    ///
    /// # Errors
    /// Refuses active cold authority, changed ownership, or unavailable copied state.
    pub(crate) fn rebind_resident(
        resources: PluginRamResources,
        operations: Arc<dyn SourceOperationFactory>,
        generation: u64,
        logical_bytes: u64,
    ) -> Result<Arc<Self>, RamError> {
        let owner = OPERATIONAL_OWNER
            .get()
            .ok_or(RamError::Invariant("operational RAM owner absent"))?;
        let old = owner
            .try_lock()
            .map_err(|_| RamError::Invariant("operational RAM owner unavailable"))?
            .clone()
            .ok_or(RamError::Invariant("operational RAM owner absent"))?;
        if old.has_cold_authority()? {
            return Err(RamError::Invariant(
                "cold child requires independently rebound fault authority",
            ));
        }
        let replacement = Self::new(resources, operations)?;
        replacement.seal_geometry(generation, logical_bytes)?;
        // Parent preparation joined every actor before fork, so this copied
        // child mutex is unlocked. Native callback addresses remain unchanged;
        // only the process-private operational owner is replaced here.
        let mut current = owner
            .try_lock()
            .map_err(|_| RamError::Invariant("operational RAM owner unavailable"))?;
        if !current
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &old))
        {
            return Err(RamError::Invariant(
                "resident child operational owner changed",
            ));
        }
        *current = Some(replacement.clone());
        Ok(replacement)
    }

    /// Seals actual native geometry after the authenticated startup grant.
    ///
    /// # Errors
    /// Refuses zero geometry or a second seal.
    pub(crate) fn seal_geometry(
        &self,
        generation: u64,
        logical_bytes: u64,
    ) -> Result<(), RamError> {
        if generation == 0
            || logical_bytes == 0
            || self
                .topology_generation
                .compare_exchange(0, generation, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(RamError::Invariant(
                "paging geometry is invalid or already sealed",
            ));
        }
        self.logical_bytes.store(logical_bytes, Ordering::Release);
        Ok(())
    }

    /// Observes retained mapping custody without waiting for guest or backing I/O.
    ///
    /// # Errors
    /// Returns unavailable ownership or peak arithmetic overflow.
    pub(crate) fn authority_snapshot(&self) -> Result<PagingAuthoritySnapshot, RamError> {
        let active = self
            .active
            .try_lock()
            .map_err(|_| "paging authority snapshot unavailable")?;
        let logical_bytes = self.logical_bytes.load(Ordering::Acquire);
        let full_peak_bytes = logical_bytes
            .checked_add(self.resources.metadata_bytes)
            .and_then(|bytes| bytes.checked_add(self.resources.staging_bytes))
            .ok_or("paging peak snapshot overflow")?;
        Ok(PagingAuthoritySnapshot {
            logical_bytes,
            topology_generation: self.topology_generation.load(Ordering::Acquire),
            activated: active
                .as_ref()
                .is_some_and(|service| service.activated.load(Ordering::Acquire)),
            failed: self.failed.load(Ordering::Acquire)
                || active
                    .as_ref()
                    .is_some_and(|service| service.failed.load(Ordering::Acquire)),
            full_peak_bytes,
            permanent_resident_bytes: self.permanent_resident_bytes.load(Ordering::Acquire).max(
                self.locks
                    .try_lock()
                    .ok()
                    .and_then(|locks| locks.as_ref().and_then(|locks| locks.verified_bytes()))
                    .unwrap_or(0),
            ),
        })
    }

    /// Returns completed operational counters without reading guest memory.
    pub(crate) fn statistics(&self) -> PagingStatistics {
        self.counters.snapshot()
    }

    /// Validates initial paused-backend placement without claiming convergence.
    ///
    /// # Errors
    /// Refuses unsound execution capacity, unsupported modes, or invalid I/O controls.
    pub(crate) fn admit_policy(
        &self,
        policy: &crucible_protocol::ram_control::RamControlPolicy,
    ) -> Result<(), RamError> {
        use crucible_protocol::ram_control::RamControlMode;
        let snapshot = self.authority_snapshot()?;
        if snapshot.logical_bytes == 0 || snapshot.failed {
            return Err(RamError::Invariant(
                "paging geometry/authority is unavailable",
            ));
        }
        if self.resources.resident_peak_bytes < snapshot.full_peak_bytes {
            return Err(RamError::MetadataAdmission {
                required: snapshot.full_peak_bytes,
                admitted: self.resources.resident_peak_bytes,
            });
        }
        if policy.maximum_paging_io_in_flight == 0
            || policy.eviction_preference > 100
            || policy.writeback_bytes_per_second == 0
            || u64::from(policy.maximum_paging_io_in_flight) > self.resources.paging_io_slots
        {
            return Err(RamError::Invariant(
                "policy exceeds admitted paging I/O slots",
            ));
        }
        if policy.mode == RamControlMode::ResidentRequired {
            let admitted = locking::maximum_locked_bytes()?;
            if admitted < snapshot.logical_bytes {
                return Err(RamError::LockedMemoryAdmission {
                    required: snapshot.logical_bytes,
                    admitted,
                });
            }
        }
        Ok(())
    }

    /// Validates policy against the actual sealed single-actor resource envelope.
    ///
    /// # Errors
    /// Refuses changed complete peaks, retained plane subsets, worker or descriptor
    /// capacities, and parallel I/O beyond the implemented service actor.
    pub(crate) fn admit_resource_policy(
        &self,
        policy: &crucible_protocol::ram_control::RamControlPolicy,
        resources: &PluginRamResources,
    ) -> Result<(), RamError> {
        if *resources != self.resources
            || resources.paging_io_slots > 1
            || policy.maximum_paging_io_in_flight > 1
        {
            return Err(RamError::Invariant(
                "resource amendment exceeds sealed single-actor capacity",
            ));
        }
        // Root views, spill slots, actor stack and inherited fork obligations
        // were admitted together. No mutable ledger or buffer-resize protocol
        // exists here, so reducing those retained subsets is also unsupported.
        self.admit_policy(policy)
    }

    /// Applies a policy only after its exact resource assignment is accepted.
    ///
    /// # Errors
    /// Returns unsupported resource transitions or effectful queue/guard failures.
    pub(crate) fn apply_resource_policy(
        &self,
        policy: &crucible_protocol::ram_control::RamControlPolicy,
        resources: &PluginRamResources,
        revision: u64,
    ) -> Result<(), RamError> {
        self.admit_resource_policy(policy, resources)?;
        self.apply_policy(policy, revision)
    }

    /// Applies actual operational configuration without claiming physical convergence.
    ///
    /// # Errors
    /// Returns policy admission failures or unavailable mutable ownership.
    pub(crate) fn apply_policy(
        &self,
        policy: &crucible_protocol::ram_control::RamControlPolicy,
        revision: u64,
    ) -> Result<(), RamError> {
        self.admit_policy(policy)?;
        if revision == 0 {
            return Err(RamError::Invariant("paging policy revision is zero"));
        }
        let mut current = self
            .policy
            .try_lock()
            .map_err(|_| "paging policy owner unavailable")?;
        let generation = self
            .policy_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map_err(|_| RamError::Invariant("policy generation exhausted"))?
            + 1;
        *current = Some(*policy);
        self.requested_policy_revision
            .store(revision, Ordering::Release);
        drop(current);
        if let Err(error) = self.schedule_reclaim(generation) {
            self.retain_operational_failure(SourceOperationClass::Quiescence, &error);
            return Err(error);
        }
        Ok(())
    }

    /// Returns only a completed strict transition for this actual arena owner.
    pub(crate) fn placement_receipt(
        &self,
    ) -> Option<crucible_protocol::ram_control::RamControlPlacementReceipt> {
        self.placement_receipt
            .try_lock()
            .ok()
            .and_then(|receipt| *receipt)
    }

    /// Connects cold-safe observation to the actual process-lifetime owner.
    ///
    /// # Errors
    /// Returns missing native capabilities or failed callback registration.
    pub(crate) fn install_reader(self: &Arc<Self>) -> Result<(), RamError> {
        // SAFETY: the resolved registrar has the matching native-private ABI.
        let register = unsafe {
            std::mem::transmute::<*mut c_void, RegisterReaders>(symbol(
                b"qemu_plugin_crucible_register_ram_readers_v3\0",
            )?)
        };
        // SAFETY: the registrar matches this process-private scalar callback.
        let register_rearm = unsafe {
            std::mem::transmute::<*mut c_void, RegisterRearm>(symbol(
                b"qemu_plugin_crucible_register_ram_rearm_v1\0",
            )?)
        };
        // SAFETY: this callback registrar is a process-private GPL ABI.
        let register_placement = unsafe {
            std::mem::transmute::<*mut c_void, RegisterPlacement>(symbol(
                b"qemu_plugin_crucible_register_ram_placement_v1\0",
            )?)
        };
        let owner = OPERATIONAL_OWNER.get_or_init(|| Mutex::new(None));
        let mut current = owner
            .try_lock()
            .map_err(|_| RamError::Invariant("operational RAM owner unavailable"))?;
        if current.is_some() {
            return Err(RamError::Invariant(
                "operational RAM owner already installed",
            ));
        }
        *current = Some(self.clone());
        drop(current);
        let status = register(Some(operational_read), Some(root_scratch_read));
        if status != 0 {
            return Err(RamError::Native {
                operation: "operational RAM reader registration refused",
                status,
            });
        }
        let status = register_rearm(Some(operational_rearm));
        if status != 0 {
            return Err(RamError::Native {
                operation: "RAM write rearm registration refused",
                status,
            });
        }
        let status = register_placement(placement::placement_before_resume);
        if status != 0 {
            return Err(RamError::Native {
                operation: "RAM placement registration",
                status,
            });
        }
        mutation::install()?;
        Ok(())
    }

    /// Reports whether active mapping authority requires worker/fd handoff.
    ///
    /// # Errors
    /// Returns poisoned mapping ownership.
    pub(crate) fn has_cold_authority(&self) -> Result<bool, RamError> {
        self.active
            .lock()
            .map(|active| active.is_some())
            .map_err(|_| RamError::Invariant("paging authority owner is poisoned"))
    }
}

impl SourceOperationFactory for PausedPagingOwner {
    fn begin(&self, class: SourceOperationClass) -> io::Result<Box<dyn SourceOperation>> {
        self.operations.begin(class)
    }
}

impl RestoreMappingOwner for PausedPagingOwner {
    fn prepare(
        &self,
        source: ValidatedRestoreSource,
    ) -> Result<Box<dyn PreparedRestoreMapping>, RamError> {
        if self.preparing.swap(true, Ordering::AcqRel) {
            return Err(RamError::Invariant("another arena transition is preparing"));
        }
        let _preparing = PreparationAdmission(&self.preparing);
        if self
            .active
            .lock()
            .map_err(|_| "paging authority owner is poisoned")?
            .is_some()
        {
            return Err(RamError::Invariant(
                "an arena/source transition already owns this process",
            ));
        }
        let logical_bytes = source
            .native_regions
            .iter()
            .try_fold(0_u64, |sum, region| {
                sum.checked_add(region.logical_length())
                    .ok_or("logical RAM peak overflow")
            })?;
        if logical_bytes != self.logical_bytes.load(Ordering::Acquire)
            || source.topology_generation != self.topology_generation.load(Ordering::Acquire)
        {
            return Err(RamError::Invariant(
                "restore source differs from admitted paging geometry",
            ));
        }
        let required_peak = logical_bytes
            .checked_add(self.resources.metadata_bytes)
            .and_then(|bytes| bytes.checked_add(self.resources.staging_bytes))
            .ok_or("complete paging peak overflow")?;
        if self.resources.resident_peak_bytes < required_peak {
            return Err(RamError::Invariant(
                "paused paging requires the full between-boundary logical RAM peak",
            ));
        }
        if self.resources.staging_bytes < Self::required_staging_bytes() {
            return Err(RamError::MetadataAdmission {
                required: Self::required_staging_bytes(),
                admitted: self.resources.staging_bytes,
            });
        }
        let native = NativeOperations::resolve()?;
        let spill = self
            .spill
            .try_lock()
            .map_err(|_| "spill authority unavailable")?
            .clone()
            .ok_or("real disk spill authority was not installed")?;
        let service = prepare_service(
            &source,
            self.operations.clone(),
            native,
            spill,
            self.counters.clone(),
        )?;
        self.check_mapping_peak(&service)?;
        if let Err(error) = service.start() {
            service.stop_before_activation()?;
            return Err(error);
        }
        // Retain the real actor/source even when a native partial cleanup fails.
        // No engine mutex remains held while native writer barriers are acquired.
        *self
            .active
            .lock()
            .map_err(|_| "paging authority owner is poisoned")? = Some(service.clone());
        let mut preflight = PhysicalPreflight {
            native,
            generation: source.topology_generation,
            token: 0,
            service: service.clone(),
            error: None,
        };
        let status = (native.run)(
            physical_preflight,
            (&mut preflight as *mut PhysicalPreflight).cast(),
        );
        if status != 0 {
            if preflight.token == 0 {
                service.stop_before_activation()?;
                *self
                    .active
                    .lock()
                    .map_err(|_| "paging authority owner is poisoned")? = None;
            } else {
                service.failed.store(true, Ordering::Release);
            }
            return Err(preflight.error.take().unwrap_or(RamError::Native {
                operation: "physical RAM preflight",
                status,
            }));
        }
        // Reset is allowed between prepare and commit. Its writes cannot use
        // restored pages, and no physical hold survives that transition.
        let cache = match source.prepare_cache(service.worker_generation) {
            Ok(cache) => cache,
            Err(error) => {
                service.stop_before_activation()?;
                *self
                    .active
                    .lock()
                    .map_err(|_| "paging authority owner is poisoned")? = None;
                return Err(error);
            }
        };
        Ok(Box::new(PreparedArenas {
            service,
            cache: Some(cache),
            owner: self.active.clone(),
            native,
            token: 0,
            destructive: false,
            completed: false,
            commit_error: None,
        }))
    }
}

struct PhysicalPreflight {
    native: NativeOperations,
    generation: u64,
    token: u64,
    service: Arc<FaultService>,
    error: Option<RamError>,
}

extern "C" fn physical_preflight(opaque: *mut c_void) -> c_int {
    // SAFETY: synchronous mainloop dispatch borrows this exclusive stack value
    // until the call returns; neither native mailbox nor callback retains it.
    let preflight = unsafe { &mut *opaque.cast::<PhysicalPreflight>() };
    let status = (preflight.native.begin)(preflight.generation, &mut preflight.token);
    if status != 0 {
        return status;
    }
    if preflight.token == 0 {
        return -libc::EIO;
    }
    let validation = PreparedArenas::restore_pinned_pages(&preflight.service, true);
    let status = (preflight.native.end)(preflight.token);
    if status == 0 {
        preflight.token = 0;
    }
    if let Err(error) = validation {
        preflight.error = Some(error);
        return -libc::EIO;
    }
    status
}

struct PreparationAdmission<'a>(&'a AtomicBool);

impl Drop for PreparationAdmission<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct PreparedArenas {
    service: Arc<FaultService>,
    cache: Option<PreparedRestoreSource>,
    owner: Arc<Mutex<Option<Arc<FaultService>>>>,
    native: NativeOperations,
    token: u64,
    destructive: bool,
    completed: bool,
    commit_error: Option<RamError>,
}

impl PreparedArenas {
    fn commit_on_main_loop(&mut self) -> Result<(), RamError> {
        if self.destructive || self.completed {
            return Err(RamError::Invariant(
                "arena transition already entered commit",
            ));
        }
        self.destructive = true;
        let cache = self.cache.as_mut().ok_or("arena identity receipt absent")?;
        let status = (self.native.begin)(cache.topology_generation, &mut self.token);
        if status != 0 || self.token == 0 {
            self.service.failed.store(true, Ordering::Release);
            return Err(RamError::Native {
                operation: "post-reset physical RAM exclusion",
                status,
            });
        }
        let status = (self.native.validate)(self.token, cache.topology_generation);
        if status != 0 || self.service.failed.load(Ordering::Acquire) {
            self.service.failed.store(true, Ordering::Release);
            return Err(RamError::Native {
                operation: "post-reset physical RAM authority invalid",
                status,
            });
        }
        // Reset must not have replaced or resized any prepared anonymous arena.
        for prepared in &self.service.arenas {
            let mut current = NativeArena::default();
            let status = (self.native.arena)(
                cache.topology_generation,
                prepared.native.region_index,
                &mut current,
            );
            if status != 0
                || current.host_address != prepared.native.host_address
                || current.mapping_length != prepared.native.mapping_length
                || current.flags != prepared.native.flags
            {
                self.service.failed.store(true, Ordering::Release);
                return Err(RamError::Native {
                    operation: "post-reset stable arena changed",
                    status,
                });
            }
        }
        let status = (self.native.pin)(self.token, cache.topology_generation);
        if status != 0 {
            self.service.failed.store(true, Ordering::Release);
            return Err(RamError::Native {
                operation: "stable paging topology pin refused",
                status,
            });
        }
        for arena in &self.service.arenas {
            if arena.placement != ArenaPlacement::Pageable {
                continue;
            }
            // SAFETY: the native scalar certificate retains stable anonymous
            // mapping and complete accessor/physical-borrow exclusion. Kernel
            // registration occurs after reset and before any destructive discard.
            unsafe {
                self.service
                    .registration
                    .register(arena.native.host_address, arena.native.mapping_length)
            }
            .map_err(RamError::from)?;
        }
        Self::restore_pinned_pages(&self.service, true)?;
        cache.begin_mapping_commit()?;
        Self::restore_pinned_pages(&self.service, false)?;
        self.service.registration.retain_until_process_exit();
        self.service.destructive.store(true, Ordering::Release);
        for arena in &self.service.arenas {
            if arena.placement != ArenaPlacement::Pageable {
                continue;
            }
            // SAFETY: all ranges are registered and their source is retained.
            // The certificate excludes ordinary access until all discards and
            // coherent source publication finish. Failure retains the barrier.
            let result = unsafe {
                libc::madvise(
                    arena.native.host_address as *mut c_void,
                    usize::try_from(arena.native.mapping_length)
                        .map_err(|_| "arena length overflow")?,
                    libc::MADV_DONTNEED,
                )
            };
            if result != 0 {
                self.service.failed.store(true, Ordering::Release);
                return Err(io::Error::last_os_error().into());
            }
        }
        for arena in &self.service.arenas {
            if arena.placement == ArenaPlacement::Pageable {
                count_bulk_completed(
                    &self.service.counters.physical_discards,
                    arena.native.logical_length / PAGE_BYTES as u64,
                )?;
            }
        }
        if self.service.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant(
                "fault service failed before cold-source publication",
            ));
        }
        cache.publish_after_mapping_commit()?;
        let status = (self.native.acknowledge)(cache.topology_generation);
        if status != 0 {
            self.service.failed.store(true, Ordering::Release);
            return Err(RamError::Native {
                operation: "restored source dirty baseline rejected",
                status,
            });
        }
        self.service.activated.store(true, Ordering::Release);
        let status = (self.native.end)(self.token);
        if status != 0 {
            self.service.failed.store(true, Ordering::Release);
            return Err(RamError::Native {
                operation: "physical RAM authority release failed",
                status,
            });
        }
        self.token = 0;
        self.completed = true;
        Ok(())
    }

    fn restore_pinned_pages(service: &FaultService, readonly_pass: bool) -> Result<(), RamError> {
        let source = service.source.as_ref().ok_or("restore source missing")?;
        let mut scratch = [0_u8; PAGE_BYTES];
        for arena in &service.arenas {
            let ArenaPlacement::ResidentPinned { readonly } = arena.placement else {
                continue;
            };
            if readonly != readonly_pass {
                continue;
            }
            let pages = arena.native.logical_length.div_ceil(PAGE_BYTES as u64);
            for page in 0..pages {
                let offset = page * PAGE_BYTES as u64;
                let valid = (arena.native.logical_length - offset).min(PAGE_BYTES as u64) as usize;
                let (length, _) = source.fetch(arena.native.region_index, page, &mut scratch)?;
                if length as usize != valid {
                    return Err(RamError::Invariant("pinned restore page geometry changed"));
                }
                let address = arena.native.host_address + offset;
                if readonly {
                    // SAFETY: complete physical exclusion retains this native
                    // immutable file authority and its exact logical extent.
                    let live = unsafe { std::slice::from_raw_parts(address as *const u8, valid) };
                    if live != &scratch[..valid] {
                        return Err(RamError::Invariant(
                            "read-only resident image differs from authenticated source",
                        ));
                    }
                } else {
                    // SAFETY: retained physical exclusion owns writable pinned
                    // bytes; authenticated staging fits the exact logical tail.
                    unsafe {
                        std::ptr::copy_nonoverlapping(scratch.as_ptr(), address as *mut u8, valid)
                    };
                }
            }
        }
        Ok(())
    }
}

extern "C" fn physical_commit(opaque: *mut c_void) -> c_int {
    // SAFETY: the native synchronous runner borrows the exclusive prepared
    // receipt until completion and never publishes this GPL-private pointer.
    let prepared = unsafe { &mut *opaque.cast::<PreparedArenas>() };
    match prepared.commit_on_main_loop() {
        Ok(()) => 0,
        Err(error) => {
            prepared.service.failed.store(true, Ordering::Release);
            prepared.commit_error = Some(error);
            -libc::EIO
        }
    }
}

impl PreparedRestoreMapping for PreparedArenas {
    fn commit(&mut self) -> Result<(), RamError> {
        if self.destructive || self.completed {
            return Err(RamError::Invariant(
                "arena transition already entered commit",
            ));
        }
        let run = self.native.run;
        let status = run(physical_commit, (self as *mut Self).cast());
        if status != 0 {
            self.service.failed.store(true, Ordering::Release);
            return Err(self.commit_error.take().unwrap_or(RamError::Native {
                operation: "mainloop physical activation",
                status,
            }));
        }
        if !self.completed {
            return Err(RamError::Invariant(
                "mainloop activation returned without a completed receipt",
            ));
        }
        Ok(())
    }

    fn abort_before_commit(&mut self) -> Result<(), RamError> {
        if self.destructive || self.completed {
            return Err(RamError::Invariant(
                "destructive arena authority must remain until containment",
            ));
        }
        let cache = self.cache.take().ok_or("arena identity receipt absent")?;
        if let Err(cache) = cache.abort_before_mapping_commit() {
            self.cache = Some(cache);
            return Err(RamError::Invariant(
                "arena identity rollback authority uncertain",
            ));
        }
        if self.token != 0 {
            return Err(RamError::Invariant(
                "physical cleanup authority remains retained",
            ));
        }
        self.service.stop_before_activation()?;
        let mut owner = self
            .owner
            .lock()
            .map_err(|_| "paging authority owner is poisoned")?;
        if !owner
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &self.service))
        {
            return Err(RamError::Invariant(
                "arena rollback does not own the active source",
            ));
        }
        *owner = None;
        self.completed = true;
        Ok(())
    }
}

fn symbol(name: &'static [u8]) -> Result<*mut c_void, RamError> {
    // SAFETY: names are static NUL-terminated strings selecting this QEMU image.
    let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr().cast()) };
    if pointer.is_null() {
        return Err(RamError::MissingSymbol(name));
    }
    Ok(pointer)
}
