//! Activates stable resident arenas and reclaims authenticated pages while paused.
//!
//! The native mainloop owns the complete physical barrier through register,
//! preserve and discard. No ownership mutex is held during barrier acquisition;
//! failure retains registration and any unreleased certificate until reap.

use std::fs::File;

use super::*;

impl PausedPagingOwner {
    /// Retains the paid service before worker or mapping effects can begin.
    ///
    /// # Errors
    /// Refuses unavailable custody or an already retained service.
    pub(super) fn retain_service(&self, service: &Arc<FaultService>) -> Result<(), RamError> {
        let mut active = self
            .active
            .try_lock()
            .map_err(|_| RamError::Invariant("paging authority unavailable"))?;
        if active.is_some() {
            return Err(RamError::Invariant("paging authority already retained"));
        }
        *active = Some(service.clone());
        Ok(())
    }

    /// Reserves a real private disk file before any physical removal is admitted.
    ///
    /// # Errors
    /// Refuses an invalid quota, non-disk file, failed capacity reservation, or repeated installation.
    pub(crate) fn install_spill(&self, file: File, quota: u64) -> Result<(), RamError> {
        let operation = self.operations.begin(SourceOperationClass::ControlSetup)?;
        if quota == 0 || quota > self.resources.backing_peak_bytes {
            return Err(RamError::Invariant(
                "spill quota exceeds backing entitlement",
            ));
        }
        // An unregistered capability probe precedes disk reservation and
        // admission publication. Closing it cannot change any guest mapping.
        let registration = Registration::open()?;
        let store = super::super::PreservedPages::new(file, quota)?;
        operation.complete()?;
        let mut spill = self
            .spill
            .try_lock()
            .map_err(|_| "spill ownership unavailable")?;
        if spill.is_some() {
            return Err(RamError::Invariant("spill authority already installed"));
        }
        self.record_kernel_probe(&registration)?;
        *spill = Some(Arc::new(Mutex::new(store)));
        Ok(())
    }

    /// Activates original anonymous guest RAM without changing its logical bytes.
    ///
    /// # Errors
    /// Returns unavailable inventory, insufficient peak resources, or failed native/kernel activation.
    pub(crate) fn activate_resident_at_boundary(&self) -> Result<(), RamError> {
        self.activate_resident_with_operation(None, Arc::new(AtomicU64::new(0)))
    }

    pub(super) fn activate_resident_with_operation(
        &self,
        operation: Option<Arc<dyn SourceOperation>>,
        completed_work: Arc<AtomicU64>,
    ) -> Result<(), RamError> {
        if self.preparing.swap(true, Ordering::AcqRel) {
            return Err(RamError::PlacementDeferred {
                operation: "arena transition already preparing",
                status: -libc::EBUSY,
            });
        }
        let _admission = PreparationAdmission(&self.preparing);
        let existing = self
            .active
            .try_lock()
            .map_err(|_| "paging ownership unavailable")?
            .clone();
        if let Some(service) = existing {
            if service.failed.load(Ordering::Acquire) {
                return Err(RamError::Invariant("failed activation authority"));
            }
            if service.activated.load(Ordering::Acquire) {
                return Ok(());
            }
            if service.source.is_some() {
                // A prepared restore owns this inactive source-backed service
                // until commit or abort. Policy placement must wait for that cut.
                return Err(RamError::PlacementDeferred {
                    operation: "prepared restore excludes resident activation",
                    status: -libc::EBUSY,
                });
            }
            return self.activate_service(service, operation, completed_work);
        }
        let (generation, regions, budget, _inventory) =
            crate::ram_fingerprint::admitted_inventory()?;
        let snapshot = self.authority_snapshot()?;
        if generation != snapshot.topology_generation
            || self.resources.resident_peak_bytes < snapshot.full_peak_bytes
            || self.resources.staging_bytes < Self::required_staging_bytes()
        {
            return Err(RamError::Invariant(
                "initial paused execution peak not admitted",
            ));
        }
        let spill = self
            .spill
            .try_lock()
            .map_err(|_| "spill authority unavailable")?
            .clone()
            .ok_or("real disk spill authority missing")?;
        let native = NativeOperations::resolve()?;
        let service = prepare_service_for_inventory(
            &regions,
            &budget,
            ServiceConfiguration {
                topology_generation: generation,
                operations: self.operations.clone(),
                native,
                spill,
                source: None,
                resident: true,
                counters: self.counters.clone(),
            },
        )?;
        self.check_mapping_peak(&service)?;
        self.retain_service(&service)?;
        service.start()?;
        self.activate_service(service, operation, completed_work)
    }

    fn activate_service(
        &self,
        service: Arc<FaultService>,
        operation: Option<Arc<dyn SourceOperation>>,
        completed_work: Arc<AtomicU64>,
    ) -> Result<(), RamError> {
        let mut action = PhysicalPlacement {
            owner: self,
            service,
            generation: self.topology_generation.load(Ordering::Acquire),
            token: 0,
            activate: true,
            target: u64::MAX,
            eviction_preference: 0,
            writeback_rate: 1,
            prefetch: false,
            policy_revision: 0,
            policy_generation: self.policy_generation.load(Ordering::Acquire),
            mode: crucible_qemu_protocol::ram_control::RamControlMode::Managed,
            receipt: None,
            resident_observation: None,
            establish_guarantee: false,
            operation,
            completed_work,
            error: None,
        };
        action.dispatch()
    }

    /// Converges the requested soft target only at a physically excluded pause.
    ///
    /// # Errors
    /// Returns unavailable policy, failed authority, or storage/physical transition failure.
    pub(crate) fn reclaim_at_boundary(&self) -> Result<(), RamError> {
        self.reclaim_with_operation(None, Arc::new(AtomicU64::new(0)))
    }

    pub(super) fn reclaim_with_operation(
        &self,
        operation: Option<Arc<dyn SourceOperation>>,
        completed_work: Arc<AtomicU64>,
    ) -> Result<(), RamError> {
        if self.preparing.load(Ordering::Acquire) {
            return Err(RamError::PlacementDeferred {
                operation: "page preparation excludes physical reclaim",
                status: -libc::EBUSY,
            });
        }
        let policy = self
            .policy
            .lock()
            .map_err(|_| "paging policy unavailable")?
            .as_ref()
            .copied()
            .ok_or("paging policy was not applied")?;
        let service = self
            .active
            .try_lock()
            .map_err(|_| "paging authority unavailable")?
            .clone()
            .ok_or("paging arenas are not active")?;
        if service.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant(
                "failed paging authority cannot reclaim",
            ));
        }
        if !service.activated.load(Ordering::Acquire) {
            return Err(RamError::PlacementDeferred {
                operation: "inactive paging arenas exclude reclaim",
                status: -libc::EBUSY,
            });
        }
        let mut action = PhysicalPlacement {
            owner: self,
            service,
            generation: self.topology_generation.load(Ordering::Acquire),
            token: 0,
            activate: false,
            target: policy.resident_target_bytes,
            eviction_preference: policy.eviction_preference,
            writeback_rate: policy.writeback_bytes_per_second,
            prefetch: policy.prefetch_on_increase,
            policy_revision: self.requested_policy_revision.load(Ordering::Acquire),
            policy_generation: self.policy_generation.load(Ordering::Acquire),
            mode: policy.mode,
            receipt: None,
            resident_observation: None,
            establish_guarantee: self.placement_receipt().is_none_or(|receipt| {
                receipt.policy_revision != self.requested_policy_revision.load(Ordering::Acquire)
                    || receipt.mode != policy.mode
            }),
            operation,
            completed_work,
            error: None,
        };
        action.dispatch()
    }
}

pub(super) struct PhysicalPlacement<'a> {
    pub(super) owner: &'a PausedPagingOwner,
    pub(super) service: Arc<FaultService>,
    pub(super) generation: u64,
    pub(super) token: u64,
    pub(super) activate: bool,
    target: u64,
    eviction_preference: u8,
    pub(super) writeback_rate: u64,
    prefetch: bool,
    pub(super) policy_revision: u64,
    pub(super) policy_generation: u64,
    pub(super) mode: crucible_qemu_protocol::ram_control::RamControlMode,
    pub(super) receipt: Option<crucible_qemu_protocol::ram_control::RamControlPlacementReceipt>,
    pub(super) establish_guarantee: bool,
    pub(super) resident_observation:
        Option<crucible_qemu_protocol::ram_control::RamControlResidentObservation>,
    pub(super) operation: Option<Arc<dyn SourceOperation>>,
    completed_work: Arc<AtomicU64>,
    error: Option<RamError>,
}

impl PhysicalPlacement<'_> {
    fn dispatch(&mut self) -> Result<(), RamError> {
        let complete_here = self.operation.is_none();
        let operation: Arc<dyn SourceOperation> = match self.operation.as_ref() {
            Some(operation) => operation.clone(),
            None => Arc::from(
                self.service
                    .operations
                    .begin(SourceOperationClass::Quiescence)?,
            ),
        };
        self.operation = Some(operation.clone());
        let service = self.service.clone();
        let journal = service.capture_work.placement_dispatch()?;
        self.check_budget()?;
        journal.reset()?;
        loop {
            self.check_budget()?;
            journal.callback_entered.store(false, Ordering::Release);
            journal.callback_returned.store(false, Ordering::Release);
            journal.runner_returned.store(false, Ordering::Release);
            journal.runner_entered.store(true, Ordering::Release);
            let status = (self.service.native.run)(physical_placement, (self as *mut Self).cast());
            journal.runner_status.store(status, Ordering::Release);
            journal.runner_returned.store(true, Ordering::Release);
            journal.record_first_negative(status);
            if status == 0 {
                if !journal.callback_returned.load(Ordering::Acquire)
                    || journal.callback_status.load(Ordering::Acquire) != 0
                    || !journal.action_completed.load(Ordering::Acquire)
                {
                    self.service.failed.store(true, Ordering::Release);
                    return Err(RamError::Invariant("placement runner omitted completed callback"));
                }
                break;
            }
            if journal.retry_before_action(status, self.token) {
                if !complete_here {
                    // No RAM action/end was admitted. Scheduling retains the
                    // same Original; only this pre-entry dispatch has returned.
                    journal.settled.store(true, Ordering::Release);
                    let first = self.error.take().unwrap_or(RamError::Native {
                        operation: "paused placement requires mainloop progress",
                        status,
                    });
                    return Err(match first {
                        RamError::Native { operation, status }
                            if status == -libc::EAGAIN || status == -libc::EBUSY =>
                        {
                            RamError::PlacementDeferred { operation, status }
                        }
                        first => first,
                    });
                }
                self.error = None;
                let slice = operation
                    .wait_slice()?
                    .min(std::time::Duration::from_millis(10));
                std::thread::sleep(slice);
                continue;
            }
            self.service.failed.store(true, Ordering::Release);
            let first = self.error.take().unwrap_or(RamError::Native {
                operation: "physical placement dispatch",
                status,
            });
            // Scheduling's outer refusal route must see the same no-replay
            // disposition. Preserve the native first cause and raw status.
            return Err(match first {
                RamError::Native { operation, status } => {
                    RamError::PlacementNotRetryable { operation, status }
                }
                first => first,
            });
        }
        self.check_budget()?;
        if complete_here {
            operation.complete()?;
        }
        if !self.activate {
            self.publish_placement(complete_here)?;
            self.check_policy_generation()?;
            *self
                .service
                .resident_observation
                .try_lock()
                .map_err(|_| "resident observation publication unavailable")? =
                self.resident_observation;
        }
        journal.settled.store(true, Ordering::Release);
        Ok(())
    }

    fn run(
        &mut self,
        action: &service::capture_work::physical_end::PhysicalActionAdmission<'_>,
    ) -> Result<(), RamError> {
        self.check_budget()?;
        let mut locks = self.prepare_locks()?;
        let result = self.run_with_locks(&mut locks, action);
        if let Err(error) = &result {
            let retry = match (error, self.service.capture_work.placement_dispatch()) {
                (RamError::Native { status, .. }, Ok(journal)) => {
                    journal.retry_before_action(*status, self.token)
                }
                _ => false,
            };
            if !retry {
                self.service.lifetime.failed(error.clone());
                if self.token != 0 {
                    if let Err(post) = self
                        .service
                        .capture_work
                        .retain_physical_action_failure(self.token, error)
                    {
                        self.service.lifetime.cleanup_failed(post);
                    }
                }
            }
        }
        if result.is_err() && self.token != 0 && locks.is_some() {
            // End may have partially returned physical borrowers. Retain the
            // exact verification FD and cleanup identity until independent
            // disposition is known; a signed failure does not prove exclusion.
            match self.owner.retained_lock_transition.try_lock() {
                Ok(mut retained) if retained.is_none() => *retained = locks.take(),
                _ => std::mem::forget(locks.take()),
            }
        }
        result
    }

    fn run_with_locks(
        &mut self,
        locks: &mut Option<super::strict_placement::LockTransition>,
        action: &service::capture_work::physical_end::PhysicalActionAdmission<'_>,
    ) -> Result<(), RamError> {
        let native = self.service.native;
        let service = self.service.clone();
        let journal = service.capture_work.placement_dispatch()?;
        let born = self
            .service
            .capture_work
            .begin_physical(&service, self.generation, action)?;
        self.token = born.token;
        let status = born.status;
        if status != 0 || self.token == 0 {
            return Err(RamError::Native {
                operation: "physical placement exclusion",
                status,
            });
        }
        self.check_budget()?;
        let status = (native.validate)(self.token, self.generation);
        if status != 0 {
            return Err(RamError::Native {
                operation: "physical placement validation",
                status,
            });
        }
        if self.activate {
            // Original anonymous RAM may still have empty PTEs. Missing-fault
            // registration must not reinterpret that untouched original state
            // as a recoverable cold page without any preservation authority.
            // Resolve original PTEs and private COW before registering, while
            // complete physical exclusion and the full interval peak are held.
            for arena in &self.service.arenas {
                if arena.placement != ArenaPlacement::Pageable {
                    continue;
                }
                for page in 0..arena.native.mapping_length / PAGE_BYTES as u64 {
                    self.check_budget()?;
                    let address = arena.native.host_address + page * PAGE_BYTES as u64;
                    prefault_original_page(address);
                    self.progress_work()?;
                }
            }
            let status = (native.pin)(self.token, self.generation);
            if status != 0 {
                return Err(RamError::Native {
                    operation: "initial arena topology pin",
                    status,
                });
            }
            self.service.registration.retain_until_process_exit();
            for arena in &self.service.arenas {
                self.check_budget()?;
                if arena.placement != ArenaPlacement::Pageable {
                    continue;
                }
                // SAFETY: the certificate retains stable private anonymous RAM
                // and excludes every admitted physical borrower/accessor.
                unsafe {
                    self.service
                        .registration
                        .register(arena.native.host_address, arena.native.mapping_length)
                }?;
                self.service.registration.protect(
                    arena.native.host_address,
                    arena.native.mapping_length,
                    true,
                )?;
                self.progress_work()?;
            }
            self.service.destructive.store(true, Ordering::Release);
            self.service.activated.store(true, Ordering::Release);
        } else {
            self.apply_placement(locks)?;
        }
        self.check_budget()?;
        let ended = self.service.capture_work.end_physical(native, self.token)?;
        let token = self.token;
        // Only the actual producer's return_complete consumes identity. The
        // signed end and observer results remain separately owned in the body.
        if ended.returned {
            self.token = 0;
            self.service.retained_token.store(0, Ordering::Release);
        }
        if let Some(error) = ended.failure.as_ref() {
            self.service.failed.store(true, Ordering::Release);
            self.service.lifetime.failed(error.clone());
        }
        let gate_return = if ended.returned {
            self.service.capture_work.return_gate_after_end(token)
        } else {
            Ok(())
        };
        if let Some(error) = ended.failure {
            return Err(error);
        }
        gate_return?;
        journal.action_completed.store(true, Ordering::Release);
        Ok(())
    }

    pub(super) fn reclaim_pages(&mut self) -> Result<(), RamError> {
        let service = self.service.clone();
        let mut work = service.capture_work.placement_work(self)?;
        self.reclaim_pages_with_work(&mut work)?;
        // The same prepaid scratch is exclusive through this journal/sample.
        // A retained journal forbids reuse even after its actor has returned.
        self.resident_observation = Some(self.sample_residency(work.idle_scratch()?)?);
        work.return_at_boundary()
    }

    fn reclaim_pages_with_work(
        &mut self,
        work: &mut service::capture_work::FaultWork,
    ) -> Result<(), RamError> {
        let mut resident = self
            .service
            .states
            .try_lock()
            .map_err(|_| "paging state unavailable")?
            .iter()
            .filter(|state| state.resident)
            .count() as u64
            * PAGE_BYTES as u64;
        if self.prefetch && resident < self.target {
            self.prefetch_pages(&mut resident, work.idle_scratch()?)?;
        }
        let removable = resident.saturating_sub(self.target);
        let quota = resident
            .saturating_mul(u64::from(self.eviction_preference))
            .div_ceil(100);
        let stop_at = resident.saturating_sub(removable.min(quota));
        for arena in &self.service.arenas {
            if arena.placement != ArenaPlacement::Pageable {
                continue;
            }
            let pages = usize::try_from(arena.native.mapping_length / PAGE_BYTES as u64)
                .map_err(|_| "reclaim page count overflow")?;
            for page in 0..pages {
                self.check_budget()?;
                if resident <= stop_at {
                    return Ok(());
                }
                let coordinate = arena.page_start + page;
                let state = self
                    .service
                    .states
                    .try_lock()
                    .map_err(|_| "paging state unavailable")?
                    .get(coordinate)
                    .ok_or("reclaim page absent")?
                    .clone();
                if !state.resident {
                    continue;
                }
                work.evict_at_boundary(self, arena, page, coordinate, state)?;
                resident -= PAGE_BYTES as u64;
            }
        }
        Ok(())
    }

    pub(super) fn progress_work(&self) -> Result<(), RamError> {
        let completed = self
            .completed_work
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "physical placement work authority exhausted")?
            + 1;
        self.operation
            .as_ref()
            .ok_or("physical placement supervisor absent")?
            .progress(completed)?;
        Ok(())
    }

    pub(super) fn check_budget(&self) -> Result<(), RamError> {
        let operation = self
            .operation
            .as_ref()
            .ok_or("physical placement supervisor absent")?;
        check_placement_operation(
            operation.as_ref(),
            &self.owner.failed,
            &self.service.failed,
            &self.service.stop,
        )
    }

    fn prefetch_pages(
        &self,
        resident: &mut u64,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<(), RamError> {
        for arena in &self.service.arenas {
            if arena.placement != ArenaPlacement::Pageable {
                continue;
            }
            let pages = arena.native.mapping_length / PAGE_BYTES as u64;
            for page in 0..pages {
                self.check_budget()?;
                if *resident >= self.target {
                    return Ok(());
                }
                let coordinate = arena.page_start + page as usize;
                let present = self
                    .service
                    .states
                    .try_lock()
                    .map_err(|_| "prefetch state unavailable")?
                    .get(coordinate)
                    .ok_or("prefetch coordinate absent")?
                    .resident;
                if present {
                    continue;
                }
                let operation = self
                    .service
                    .operations
                    .begin(SourceOperationClass::PageIn)?;
                let valid = self.service.read_page_source(
                    arena,
                    page,
                    coordinate,
                    operation.as_ref(),
                    scratch,
                )?;
                if valid as usize != PAGE_BYTES {
                    return Err(RamError::Invariant("prefetch source length changed"));
                }
                operation.wait_slice()?;
                self.check_budget()?;
                let address = arena.native.host_address + page * PAGE_BYTES as u64;
                self.service.registration.populate(address, scratch)?;
                self.service
                    .states
                    .try_lock()
                    .map_err(|_| "prefetch state unavailable")?
                    .get_mut(coordinate)
                    .ok_or("prefetch coordinate absent")?
                    .resident = true;
                count_completed(&self.service.counters.prefetched_pages)?;
                operation.wait_slice()?;
                self.check_budget()?;
                self.service.registration.wake(address)?;
                operation.complete()?;
                *resident += PAGE_BYTES as u64;
                self.progress_work()?;
            }
        }
        Ok(())
    }
}

/// Refuses already-known operational failure without taking the actor's locks.
///
/// These local checks do not replace native validation of the physical hold or
/// atomically exclude an actor failure racing with its eventual release.
fn check_placement_operation(
    operation: &dyn SourceOperation,
    owner_failed: &AtomicBool,
    service_failed: &AtomicBool,
    stopping: &AtomicBool,
) -> Result<(), RamError> {
    let check_health = || {
        if owner_failed.load(Ordering::Acquire) || service_failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("physical placement authority failed"));
        }
        if stopping.load(Ordering::Acquire) {
            return Err(RamError::Invariant("physical placement worker is stopping"));
        }
        Ok(())
    };

    check_health()?;
    operation.wait_slice()?;
    check_health()
}

fn prefault_original_page(address: u64) {
    // SAFETY: the caller retains complete physical exclusion for this private
    // writable anonymous page. The identical volatile store resolves its PTE
    // and private COW without changing a logical byte or invoking guest hooks.
    unsafe {
        let pointer = address as *mut u8;
        let original = std::ptr::read_volatile(pointer);
        std::ptr::write_volatile(pointer, original);
    }
}

extern "C" fn physical_placement(opaque: *mut c_void) -> c_int {
    // SAFETY: the synchronous native runner lends this exclusive context until
    // completion and never publishes its process-private pointer.
    let placement = unsafe { &mut *opaque.cast::<PhysicalPlacement<'_>>() };
    let service = placement.service.clone();
    let journal = match service.capture_work.placement_dispatch() {
        Ok(journal) => journal,
        Err(error) => {
            placement.error = Some(error);
            return -libc::EIO;
        }
    };
    journal.callback_entered.store(true, Ordering::Release);
    let action = service.capture_work.admit_physical_action();
    let result = match action.as_ref() {
        Ok(action) => placement.run(action),
        Err(error) => Err(error.clone()),
    };
    let mut status = match result {
        Ok(()) => 0,
        Err(error) => {
            let retry = match &error {
                RamError::Native { status, .. }
                    if journal.retry_before_action(*status, placement.token) =>
                {
                    Some(*status)
                }
                _ => None,
            };
            if retry.is_none() {
                placement
                    .owner
                    .retain_operational_failure(SourceOperationClass::Quiescence, &error);
                placement.service.failed.store(true, Ordering::Release);
            }
            placement.error = Some(error);
            retry.unwrap_or(-libc::EIO)
        }
    };
    journal.callback_status.store(status, Ordering::Release);
    journal.record_first_negative(status);
    if let Ok(action) = action {
        if let Err(post) = action.finish() {
            service.failed.store(true, Ordering::Release);
            service.lifetime.cleanup_failed(post.clone());
            if placement.error.is_none() {
                placement.error = Some(post);
            }
            status = -libc::EIO;
            journal.callback_status.store(status, Ordering::Release);
        }
    }
    journal.callback_returned.store(true, Ordering::Release);
    journal.record_first_negative(status);
    status
}

#[cfg(test)]
mod health_tests;

pub(super) extern "C" fn placement_before_resume() -> c_int {
    let owner = OPERATIONAL_OWNER
        .get()
        .and_then(|holder| holder.try_lock().ok())
        .and_then(|owner| owner.clone());
    let Some(owner) = owner else {
        return -libc::EIO;
    };
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), RamError> {
            if owner.execute_scheduled_before_resume()? {
                return Ok(());
            }
            owner.activate_resident_at_boundary()?;
            owner.reclaim_at_boundary()
        }));
    match result {
        Ok(Ok(())) => 0,
        _ => {
            owner.failed.store(true, Ordering::Release);
            -libc::EIO
        }
    }
}

pub(super) fn pace_writeback(
    operation: &dyn SourceOperation,
    bytes_per_second: u64,
) -> Result<(), RamError> {
    if bytes_per_second == 0 {
        return Err(RamError::Invariant("zero writeback rate"));
    }
    let nanos = (PAGE_BYTES as u64 * 1_000_000_000).div_ceil(bytes_per_second);
    let mut remaining = std::time::Duration::from_nanos(nanos);
    while !remaining.is_zero() {
        let slice = remaining
            .min(operation.wait_slice()?)
            .min(std::time::Duration::from_millis(10));
        std::thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
    operation.wait_slice()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AnonymousPage(*mut c_void);

    impl AnonymousPage {
        fn new() -> Self {
            // SAFETY: mmap owns a fresh private writable host page; its checked
            // result remains alive until this test owner's Drop implementation.
            let page = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PAGE_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                    -1,
                    0,
                )
            };
            assert_ne!(page, libc::MAP_FAILED);
            Self(page)
        }

        fn resident(&self) -> bool {
            let mut resident = 0_u8;
            // SAFETY: the owned page covers this complete range and the output
            // is a writable byte for the single requested host page.
            let result = unsafe { libc::mincore(self.0, PAGE_BYTES, &mut resident) };
            assert_eq!(result, 0);
            resident & 1 != 0
        }
    }

    impl Drop for AnonymousPage {
        fn drop(&mut self) {
            // SAFETY: this test owner exclusively owns the original full mapping.
            assert_eq!(unsafe { libc::munmap(self.0, PAGE_BYTES) }, 0);
        }
    }

    #[test]
    fn original_untouched_zero_page_is_populated_without_changing_bytes() {
        let page = AnonymousPage::new();
        assert!(!page.resident());

        prefault_original_page(page.0 as u64);

        assert!(page.resident());
        // SAFETY: the test mapping remains exclusively owned and all requested
        // bytes lie within its complete readable original page.
        let bytes = unsafe { std::slice::from_raw_parts(page.0.cast::<u8>(), PAGE_BYTES) };
        assert_eq!(bytes, &[0_u8; PAGE_BYTES]);
    }
}
