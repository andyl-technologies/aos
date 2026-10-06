//! Activates stable resident arenas and reclaims authenticated pages while paused.
//!
//! The native mainloop owns the complete physical barrier through register,
//! preserve and discard. No ownership mutex is held during barrier acquisition;
//! failure retains registration and any unreleased certificate until reap.

use std::fs::File;

use super::*;

impl PausedPagingOwner {
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
            return Err(RamError::Native {
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
            if service.activated.load(Ordering::Acquire) {
                return Ok(());
            }
            if service.failed.load(Ordering::Acquire) {
                return Err(RamError::Invariant("failed activation authority"));
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
        service.start()?;
        *self
            .active
            .try_lock()
            .map_err(|_| "paging authority unavailable")? = Some(service.clone());
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
            mode: crucible_protocol::ram_control::RamControlMode::Managed,
            receipt: None,
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
            return Err(RamError::Native {
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
    pub(super) mode: crucible_protocol::ram_control::RamControlMode,
    pub(super) receipt: Option<crucible_protocol::ram_control::RamControlPlacementReceipt>,
    pub(super) establish_guarantee: bool,
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
        loop {
            operation.wait_slice()?;
            let status = (self.service.native.run)(physical_placement, (self as *mut Self).cast());
            if status == 0 {
                break;
            }
            if self.token == 0
                && matches!(status, value if value == -libc::EAGAIN || value == -libc::EBUSY)
            {
                if !complete_here {
                    return Err(self.error.take().unwrap_or(RamError::Native {
                        operation: "paused placement requires mainloop progress",
                        status,
                    }));
                }
                self.error = None;
                let slice = operation
                    .wait_slice()?
                    .min(std::time::Duration::from_millis(10));
                std::thread::sleep(slice);
                continue;
            }
            self.service.failed.store(true, Ordering::Release);
            return Err(self.error.take().unwrap_or(RamError::Native {
                operation: "physical placement dispatch",
                status,
            }));
        }
        if complete_here {
            operation.complete()?;
        }
        if !self.activate {
            self.publish_placement(complete_here)?;
        }
        Ok(())
    }

    fn run(&mut self) -> Result<(), RamError> {
        self.check_budget()?;
        let mut locks = self.prepare_locks()?;
        let result = self.run_with_locks(&mut locks);
        if result.is_err() && self.token != 0 && locks.is_some() {
            // The failed certificate still owns this exact verification FD.
            // Retain it instead of allowing numeric descriptor reuse under a
            // physical hold whose cleanup can no longer be established.
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
    ) -> Result<(), RamError> {
        let native = self.service.native;
        let status = (native.begin)(self.generation, &mut self.token);
        if status != 0 || self.token == 0 {
            return Err(RamError::Native {
                operation: "physical placement exclusion",
                status,
            });
        }
        self.service
            .retained_token
            .store(self.token, Ordering::Release);
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
        let status = (native.end)(self.token);
        if status != 0 {
            return Err(RamError::Native {
                operation: "physical placement release",
                status,
            });
        }
        self.token = 0;
        self.service.retained_token.store(0, Ordering::Release);
        Ok(())
    }

    pub(super) fn reclaim_pages(&mut self) -> Result<(), RamError> {
        let mut resident = self
            .service
            .states
            .try_lock()
            .map_err(|_| "paging state unavailable")?
            .iter()
            .filter(|state| state.resident)
            .count() as u64
            * PAGE_BYTES as u64;
        let mut scratch = [0_u8; PAGE_BYTES];
        if self.prefetch && resident < self.target {
            self.prefetch_pages(&mut resident, &mut scratch)?;
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
                let address = arena.native.host_address + page as u64 * PAGE_BYTES as u64;
                let mut writeback = None;
                // Version one has never admitted a write: the retained original
                // authenticated source is already a complete preservation lease.
                let record = if state.version == 1
                    && state.preserved.is_none()
                    && self.service.source.is_some()
                {
                    None
                } else {
                    Some(
                        match state
                            .preserved
                            .filter(|record| record.page_version() == state.version)
                        {
                            Some(record) => record,
                            None => {
                                let operation = self
                                    .service
                                    .operations
                                    .begin(SourceOperationClass::Writeback)?;
                                pace_writeback(operation.as_ref(), self.writeback_rate)?;
                                // SAFETY: the retained physical certificate excludes all
                                // writers and the selected page is still resident.
                                unsafe {
                                    std::ptr::copy_nonoverlapping(
                                        address as *const u8,
                                        scratch.as_mut_ptr(),
                                        PAGE_BYTES,
                                    )
                                };
                                let record = self
                                    .service
                                    .spill
                                    .try_lock()
                                    .map_err(|_| "spill authority unavailable")?
                                    .preserve(&scratch, PAGE_BYTES as u32, state.version)
                                    .map_err(|error| self.owner.writeback_failure(error.into()))?;
                                count_completed(&self.service.counters.preserved_writes)?;
                                operation.wait_slice()?;
                                writeback = Some(operation);
                                record
                            }
                        },
                    )
                };
                self.check_budget()?;
                // Publication precedes physical removal. The actor can recover
                // exact authenticated bytes even if removal subsequently fails.
                {
                    let mut states = self
                        .service
                        .states
                        .try_lock()
                        .map_err(|_| "paging state unavailable")?;
                    let current = states.get_mut(coordinate).ok_or("reclaim page absent")?;
                    if current.version != state.version || !current.resident {
                        return Err(RamError::Invariant(
                            "page changed under physical certificate",
                        ));
                    }
                    current.preserved = record;
                    current.writable = false;
                    current.resident = false;
                }
                // SAFETY: the original logical version has been reread and
                // authenticated on reserved disk; registration remains owned.
                if unsafe { libc::madvise(address as *mut c_void, PAGE_BYTES, libc::MADV_DONTNEED) }
                    != 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                count_completed(&self.service.counters.physical_discards)?;
                if let Some(operation) = writeback {
                    operation.complete()?;
                }
                resident -= PAGE_BYTES as u64;
                self.progress_work()?;
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
        self.operation
            .as_ref()
            .ok_or("physical placement supervisor absent")?
            .wait_slice()?;
        Ok(())
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
                let valid = self
                    .service
                    .read_cold(arena, page, coordinate, false, scratch)?;
                if valid as usize != PAGE_BYTES {
                    return Err(RamError::Invariant("prefetch source length changed"));
                }
                operation.wait_slice()?;
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
                self.service.registration.wake(address)?;
                operation.complete()?;
                *resident += PAGE_BYTES as u64;
                self.progress_work()?;
            }
        }
        Ok(())
    }
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
    match placement.run() {
        Ok(()) => 0,
        Err(error) => {
            let retry = match &error {
                RamError::Native { status, .. }
                    if placement.token == 0
                        && (*status == -libc::EAGAIN || *status == -libc::EBUSY) =>
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
    }
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
