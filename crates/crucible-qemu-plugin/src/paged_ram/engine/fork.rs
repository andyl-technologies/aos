//! Stages private paging metadata and rebinds actual immediate-child fault custody.
//!
//! Fork inherits guest mappings and current logical identity, while the immutable
//! cold source retains its original root. A new userfaultfd is created only in
//! the child: a parent-created descriptor governs the parent's address space.

use std::fs::File;
use std::os::fd::RawFd;

use crate::ram_fingerprint::RamProofSource;

use super::*;

/// Preallocated child state, filled only after the parent actor is joined.
pub(crate) struct PreparedChildArenas {
    generation: u64,
    source_process: u32,
    parent: Arc<PausedPagingOwner>,
    parent_service: Arc<FaultService>,
    resources: PluginRamResources,
    operations: Arc<dyn SourceOperationFactory>,
    source: Option<Arc<RestorePageSource>>,
    spill: Arc<Mutex<super::super::PreservedPages>>,
    arenas: Option<Vec<Arena>>,
    states: Option<Vec<PageState>>,
    reservation: Option<MetadataReservation>,
    arena_reservation: Option<MetadataReservation>,
    captured: bool,
}

/// Proves fresh child fault service and transfer of inherited descriptor custody.
pub(crate) struct ChildPagingCustody {
    pub(crate) owner: Arc<PausedPagingOwner>,
    pub(crate) retained: [RawFd; 4],
    pub(crate) retained_count: usize,
    pub(crate) closed: [RawFd; 4],
    pub(crate) closed_count: usize,
    generation: u64,
    _prior_proof_source: Option<Arc<dyn RamProofSource>>,
}

impl ChildPagingCustody {
    /// Identifies the exact staged epoch that owns this disposition.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

impl PausedPagingOwner {
    /// Preallocates source and metadata without creating a parent-bound child pager.
    ///
    /// # Errors
    /// Refuses mismatched immutable sources, insufficient entitlement, or failed staging allocation.
    pub(crate) fn prepare_child(
        self: &Arc<Self>,
        generation: u64,
        resources: PluginRamResources,
        operations: Arc<dyn SourceOperationFactory>,
        source: Option<ValidatedRestoreSource>,
        spill_file: File,
        spill_quota: u64,
    ) -> Result<PreparedChildArenas, RamError> {
        self.require_no_prepared_write()?;
        if generation == 0
            || resources.metadata_bytes < self.resources.metadata_bytes
            || resources.resident_peak_bytes < self.authority_snapshot()?.full_peak_bytes
            || resources.staging_bytes < Self::required_staging_bytes()
        {
            return Err(RamError::Invariant(
                "child paging entitlement is incomplete",
            ));
        }
        let parent_service = self
            .active
            .try_lock()
            .map_err(|_| "paging authority unavailable")?
            .clone()
            .ok_or("cold child requires an active parent source")?;
        if !parent_service.activated.load(Ordering::Acquire)
            || parent_service.failed.load(Ordering::Acquire)
        {
            return Err(RamError::Invariant("parent paging authority is not active"));
        }
        let budget = crate::ram_fingerprint::fork_metadata_budget()?;
        match (source.as_ref(), parent_service.source.as_ref()) {
            (Some(child), Some(parent))
                if child.topology_generation
                    == self.topology_generation.load(Ordering::Acquire)
                    && child.source.source_root() == parent.source_root()
                    && child.source.source_record() == parent.source_record() => {}
            (None, None) => {}
            _ => {
                return Err(RamError::Invariant(
                    "child cold source differs from original base",
                ));
            }
        }
        if spill_quota == 0 || spill_quota > resources.backing_peak_bytes {
            return Err(RamError::Invariant(
                "child spill quota exceeds backing entitlement",
            ));
        }
        if parent_service
            .spill
            .try_lock()
            .map_err(|_| RamError::Invariant("parent spill ownership unavailable"))?
            .shares_backing_file(&spill_file)?
        {
            return Err(RamError::Invariant(
                "child spill writer aliases parent storage",
            ));
        }
        let operation = operations.begin(SourceOperationClass::ControlSetup)?;
        let spill = Arc::new(Mutex::new(super::super::PreservedPages::new(
            spill_file,
            spill_quota,
        )?));
        operation.complete()?;
        spill
            .try_lock()
            .map_err(|_| "child spill metadata unavailable")?
            .admit_metadata(&budget)?;
        let pages = parent_service
            .states
            .try_lock()
            .map_err(|_| "parent paging state unavailable")?
            .len();
        let metadata_bytes = pages
            .checked_mul(size_of::<PageState>())
            .ok_or("child paging metadata overflow")?;
        let reservation = budget.reserve_bytes(metadata_bytes as u64)?;
        let arena_bytes = parent_service
            .arenas
            .len()
            .checked_mul(size_of::<Arena>())
            .and_then(|bytes| bytes.checked_add(1024))
            .ok_or("child arena metadata overflow")?;
        let arena_reservation = budget.reserve_bytes(arena_bytes as u64)?;
        let mut states = Vec::new();
        states.try_reserve_exact(pages)?;
        states.resize(pages, PageState::default());
        let mut arenas = Vec::new();
        arenas.try_reserve_exact(parent_service.arenas.len())?;
        arenas.extend_from_slice(&parent_service.arenas);
        // Negotiate host capability only. This descriptor is unregistered and
        // closed before the fork; its mm identity is never reused by the child.
        drop(Registration::open()?);
        Ok(PreparedChildArenas {
            generation,
            source_process: std::process::id(),
            parent: self.clone(),
            parent_service,
            resources,
            operations,
            source: source.map(ValidatedRestoreSource::into_page_source),
            spill,
            arenas: Some(arenas),
            states: Some(states),
            reservation: Some(reservation),
            arena_reservation: Some(arena_reservation),
            captured: false,
        })
    }

    /// Restarts the original parent actor after its completed fork disposition.
    ///
    /// # Errors
    /// Refuses missing, failed, or incompletely held parent authority.
    pub(crate) fn resume_cold_parent(&self) -> Result<(), RamError> {
        let service = self
            .active
            .try_lock()
            .map_err(|_| "parent paging authority unavailable")?
            .clone()
            .ok_or("parent cold authority absent")?;
        service.resume_after_fork()
    }
}

impl PreparedChildArenas {
    /// Joins the parent actor and copies current versions under the retained writer fence.
    ///
    /// # Errors
    /// Returns an unsettled actor, stale page inventory, or authenticated spill copy failure.
    pub(crate) fn capture_parent(&mut self) -> Result<(), RamError> {
        self.parent.require_no_prepared_write()?;
        if self.captured || std::process::id() != self.source_process {
            return Err(RamError::Invariant(
                "child paging capture belongs to another fork epoch",
            ));
        }
        self.parent_service.stop_for_fork()?;
        let current = self
            .parent_service
            .states
            .try_lock()
            .map_err(|_| "parent paging state unavailable")?;
        let states = self
            .states
            .as_mut()
            .ok_or("staged child paging state absent")?;
        if states.len() != current.len() || current.iter().any(|state| state.version == 0) {
            return Err(RamError::Invariant(
                "parent paging state changed after child staging",
            ));
        }
        states.clone_from_slice(&current);
        drop(current);
        let mut scratch = [0_u8; PAGE_BYTES];
        for state in states {
            if state.resident {
                // Private inherited resident bytes are the child's source;
                // historical preservation can be regenerated after its writes.
                state.preserved = None;
                continue;
            }
            if let Some(record) = state.preserved.as_ref() {
                let operation = self.operations.begin(SourceOperationClass::Writeback)?;
                self.parent_service
                    .spill
                    .try_lock()
                    .map_err(|_| "parent spill unavailable")?
                    .read(record, &mut scratch)?;
                state.preserved = Some(
                    self.spill
                        .try_lock()
                        .map_err(|_| "child spill unavailable")?
                        .preserve(&scratch, record.valid_length(), state.version)?,
                );
                operation.complete()?;
            } else if self.source.is_none() {
                return Err(RamError::Invariant(
                    "cold child page has no preserved authority",
                ));
            }
        }
        self.captured = true;
        Ok(())
    }

    /// Installs independently serviceable child mappings before reconstruction reads RAM.
    ///
    /// # Errors
    /// Returns a stale epoch or failed fresh registration/source handoff; partial authority remains retained.
    pub(crate) fn activate_child(mut self) -> Result<ChildPagingCustody, RamError> {
        if !self.captured || std::process::id() == self.source_process {
            return Err(RamError::Invariant(
                "child paging activation lacks its captured parent epoch",
            ));
        }
        let owner = PausedPagingOwner::new(self.resources, self.operations.clone())?;
        owner.seal_geometry(
            self.parent.topology_generation.load(Ordering::Acquire),
            self.parent.logical_bytes.load(Ordering::Acquire),
        )?;
        *owner
            .spill
            .try_lock()
            .map_err(|_| "child spill owner unavailable")? = Some(self.spill.clone());
        let registration = Arc::new(Registration::open()?);
        owner.record_kernel_probe(&registration)?;
        // Inherited missing pages already require authority before registration.
        // Any partial failure retains this new descriptor until child reap.
        registration.retain_until_process_exit();
        let worker_generation = NEXT_WORKER_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| "child paging incarnation exhausted")?;
        let service = Arc::new(FaultService {
            registration,
            counters: owner.counters.clone(),
            source: self.source.clone(),
            spill: self.spill.clone(),
            arenas: self.arenas.take().ok_or("child arenas already consumed")?,
            states: Mutex::new(
                self.states
                    .take()
                    .ok_or("child versions already consumed")?,
            ),
            worker: Mutex::new(None),
            stop: AtomicBool::new(false),
            activated: AtomicBool::new(false),
            destructive: AtomicBool::new(true),
            retained_token: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            operations: self.operations.clone(),
            worker_generation,
            native: self.parent_service.native,
            _reservation: self
                .reservation
                .take()
                .ok_or("child metadata receipt absent")?,
            _arena_reservation: self
                .arena_reservation
                .take()
                .ok_or("child arena receipt absent")?,
        });
        owner.check_mapping_peak(&service)?;
        *owner
            .active
            .try_lock()
            .map_err(|_| "child paging owner unavailable")? = Some(service.clone());
        let operational = OPERATIONAL_OWNER
            .get()
            .ok_or("operational paging owner absent")?;
        *operational
            .try_lock()
            .map_err(|_| "child operational paging owner unavailable")? = Some(owner.clone());
        for arena in &service.arenas {
            if arena.placement != ArenaPlacement::Pageable {
                continue;
            }
            // SAFETY: immediate child is the sole surviving guest accessor;
            // stable inherited mappings and private metadata are already staged.
            unsafe {
                service
                    .registration
                    .register(arena.native.host_address, arena.native.mapping_length)
            }?;
        }
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "child versions unavailable")?;
            for arena in &service.arenas {
                if arena.placement != ArenaPlacement::Pageable {
                    continue;
                }
                let pages = usize::try_from(arena.native.mapping_length / PAGE_BYTES as u64)
                    .map_err(|_| "child arena page count overflow")?;
                for page in 0..pages {
                    let state = states
                        .get_mut(arena.page_start + page)
                        .ok_or("child page coordinate absent")?;
                    if state.resident {
                        service.registration.protect(
                            arena.native.host_address + page as u64 * PAGE_BYTES as u64,
                            PAGE_BYTES as u64,
                            true,
                        )?;
                    }
                    state.writable = false;
                }
            }
        }
        service.activated.store(true, Ordering::Release);
        service.start()?;
        let mut retained = [-1; 4];
        let mut closed = [-1; 4];
        retained[0] = service.registration.raw_descriptor();
        retained[1] = service
            .spill
            .try_lock()
            .map_err(|_| "child spill unavailable")?
            .descriptor()?;
        closed[0] = self.parent_service.registration.raw_descriptor();
        closed[1] = self
            .parent_service
            .spill
            .try_lock()
            .map_err(|_| "parent spill unavailable")?
            .disarm_inherited()?;
        let mut count = 2;
        let prior_proof_source = if let Some(source) = self.source.as_ref() {
            let prior = crate::ram_fingerprint::rebind_proof_source(source.clone())?;
            let old_source = self
                .parent_service
                .source
                .as_ref()
                .ok_or("parent source absent")?
                .disarm_inherited()?;
            let new_source = source.endpoint_descriptors()?;
            retained[2..].copy_from_slice(&new_source);
            closed[2..].copy_from_slice(&old_source);
            count = 4;
            Some(prior)
        } else {
            None
        };
        Ok(ChildPagingCustody {
            owner,
            retained,
            retained_count: count,
            closed,
            closed_count: count,
            generation: self.generation,
            _prior_proof_source: prior_proof_source,
        })
    }
}
