//! Services authenticated page faults and cold-safe coherent observations.
//!
//! The actor never enters QEMU replay, BQL, RCU, device, or root observer locks.
//! Its registered native lifetime remains visible through failed certificates.

use super::*;

mod actor_lifetime;
pub(super) use actor_lifetime::ActorLifetime;

pub(super) struct FaultService {
    pub(super) registration: Arc<Registration>,
    pub(super) counters: Arc<PagingCounters>,
    pub(super) source: Option<Arc<RestorePageSource>>,
    pub(super) spill: Arc<Mutex<super::super::PreservedPages>>,
    pub(super) arenas: Vec<Arena>,
    pub(super) states: Mutex<Vec<PageState>>,
    pub(super) placement_dependency: Mutex<Option<Arc<dyn SourceOperation>>>,
    pub(super) worker: Mutex<Option<JoinHandle<Result<(), RamError>>>>,
    pub(super) stop: AtomicBool,
    pub(super) activated: AtomicBool,
    pub(super) destructive: AtomicBool,
    pub(super) failed: AtomicBool,
    pub(super) lifetime: Mutex<ActorLifetime>,
    pub(super) retained_token: AtomicU64,
    pub(super) operations: Arc<dyn SourceOperationFactory>,
    pub(super) worker_generation: u64,
    pub(super) native: NativeOperations,
    pub(super) _reservation: MetadataReservation,
    pub(super) _arena_reservation: MetadataReservation,
}

impl FaultService {
    pub(super) fn start(self: &Arc<Self>) -> Result<(), RamError> {
        let operation = self
            .operations
            .begin(SourceOperationClass::ControlSetup)
            .map_err(RamError::from)?;
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| "paging worker owner is poisoned")?;
        if worker.is_some() {
            return Err(RamError::Invariant("paging worker is already running"));
        }
        let service = self.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        *worker = Some(
            std::thread::Builder::new()
                .name("guest-page-service".to_owned())
                .stack_size(PAGER_STACK_BYTES)
                .spawn(move || {
                    // SAFETY: gettid has no pointer operands and identifies this actual
                    // actor; native registry checks caller identity rather than names.
                    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
                    let status =
                        (service.native.worker)(1, service.worker_generation, tid as u64, 1);
                    if status != 0 {
                        let _ = ready_tx.send(status);
                        service.failed.store(true, Ordering::Release);
                        return Err(RamError::Native {
                            operation: "paging worker registration refused",
                            status,
                        });
                    }
                    service
                        .lifetime
                        .lock()
                        .map_err(|_| RamError::Invariant("fault actor lifetime poisoned"))?
                        .admitted(tid as u64);
                    if ready_tx.send(0).is_err() {
                        service.failed.store(true, Ordering::Release);
                        let release =
                            (service.native.worker)(1, service.worker_generation, tid as u64, 0);
                        return Err(RamError::Native {
                            operation: "paging worker admission abandoned",
                            status: release,
                        });
                    }
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| service.run()))
                            .unwrap_or(Err(RamError::Invariant("paging fault actor panicked")));
                    if let Err(error) = &result {
                        service
                            .lifetime
                            .lock()
                            .map_err(|_| {
                                RamError::Invariant("fault actor failure publication poisoned")
                            })?
                            .failed(error.clone());
                        service.failed.store(true, Ordering::Release);
                    }
                    let mut release =
                        (service.native.worker)(1, service.worker_generation, tid as u64, 0);
                    while release == -libc::EBUSY {
                        // Existing membership stays alive while a certificate retains
                        // it. Failure never disappears from the held physical inventory.
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        release =
                            (service.native.worker)(1, service.worker_generation, tid as u64, 0);
                    }
                    if release != 0 {
                        service.failed.store(true, Ordering::Release);
                        return Err(RamError::Native {
                            operation: "paging worker membership release failed",
                            status: release,
                        });
                    }
                    service
                        .lifetime
                        .lock()
                        .map_err(|_| RamError::Invariant("fault actor disposition poisoned"))?
                        .released();
                    result
                })
                .map_err(RamError::from)?,
        );
        drop(worker);
        loop {
            let slice = operation.wait_slice().map_err(RamError::from)?;
            match ready_rx.recv_timeout(slice) {
                Ok(0) => break,
                Ok(status) => {
                    return Err(RamError::Native {
                        operation: "paging worker registration",
                        status,
                    });
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => {
                    return Err(RamError::Invariant(
                        "paging worker startup channel disconnected",
                    ));
                }
            }
        }
        operation.complete().map_err(RamError::from)?;
        Ok(())
    }

    pub(super) fn stop_for_fork(&self) -> Result<(), RamError> {
        let operation = self.operations.begin(SourceOperationClass::Cleanup)?;
        self.stop.store(true, Ordering::Release);
        loop {
            let finished = self
                .worker
                .try_lock()
                .map_err(|_| RamError::Invariant("paging worker owner unavailable"))?
                .as_ref()
                .is_none_or(JoinHandle::is_finished);
            if finished {
                break;
            }
            let slice = operation.wait_slice()?;
            std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));
        }
        let worker = self
            .worker
            .try_lock()
            .map_err(|_| RamError::Invariant("paging worker owner unavailable"))?
            .take();
        if let Some(worker) = worker {
            worker
                .join()
                .map_err(|_| RamError::Invariant("paging worker panicked during fork hold"))??;
        }
        operation.complete()?;
        if self.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("paging worker failed during fork hold"));
        }
        Ok(())
    }

    pub(super) fn resume_after_fork(self: &Arc<Self>) -> Result<(), RamError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("failed paging authority cannot resume"));
        }
        if self
            .worker
            .try_lock()
            .map_err(|_| RamError::Invariant("paging worker owner unavailable"))?
            .is_some()
        {
            return Err(RamError::Invariant(
                "paging worker has no completed fork disposition",
            ));
        }
        self.stop.store(false, Ordering::Release);
        self.start()
    }

    pub(super) fn stop_before_activation(&self) -> Result<(), RamError> {
        if self.activated.load(Ordering::Acquire) {
            return Err(RamError::Invariant(
                "active paging worker requires a cold-source lifecycle handoff",
            ));
        }
        self.stop.store(true, Ordering::Release);
        let worker = self
            .worker
            .lock()
            .map_err(|_| "paging worker owner is poisoned")?
            .take();
        if let Some(worker) = worker {
            worker
                .join()
                .map_err(|_| "paging worker panicked before activation")??;
        }
        Ok(())
    }

    fn run(&self) -> Result<(), RamError> {
        let mut scratch = [0; PAGE_BYTES];
        while !self.stop.load(Ordering::Acquire) {
            self.lifetime
                .lock()
                .map_err(|_| RamError::Invariant("fault actor poll publication poisoned"))?
                .poll()?;
            self.registration.wait(10).map_err(RamError::from)?;
            if !self.activated.load(Ordering::Acquire) {
                continue;
            }
            while let Some(fault) = self.registration.read_fault().map_err(RamError::from)? {
                self.resolve(fault, &mut scratch)?;
            }
        }
        Ok(())
    }

    pub(super) fn read_cold(
        &self,
        arena: &Arena,
        page_index: u64,
        coordinate: usize,
        observation: bool,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<u32, RamError> {
        self.read_cold_with_hasher::<false>(
            arena,
            page_index,
            coordinate,
            observation,
            scratch,
            None,
        )
    }

    fn read_cold_with_hasher<const BORROWED: bool>(
        &self,
        arena: &Arena,
        page_index: u64,
        coordinate: usize,
        observation: bool,
        scratch: &mut [u8; PAGE_BYTES],
        hasher: Option<&NativePageHasher>,
    ) -> Result<u32, RamError> {
        let record = self
            .states
            .try_lock()
            .map_err(|_| "cold page ownership unavailable")?
            .get(coordinate)
            .ok_or("cold page coordinate absent")?
            .preserved
            .clone();
        if let Some(record) = record {
            let class = if observation {
                SourceOperationClass::FingerprintUpdate
            } else {
                SourceOperationClass::PageIn
            };
            let operation = self.operations.begin(class)?;
            let spill = self
                .spill
                .try_lock()
                .map_err(|_| "spill ownership unavailable")?;
            if BORROWED {
                spill.read_with_borrowed_hasher(&record, scratch, hasher)?;
            } else {
                spill.read(&record, scratch)?;
            }
            drop(spill);
            operation.complete()?;
            count_completed(&self.counters.preserved_reads)?;
            return Ok(record.valid_length());
        }
        let source = self
            .source
            .as_ref()
            .ok_or("cold page has no authenticated preservation")?;
        let (valid, _) = if BORROWED {
            source
                .fetch_with_borrowed_hasher(arena.native.region_index, page_index, scratch, hasher)
                // The source mutex and operation close before the historical
                // service error conversion; only logical errors bypass it.
                .map_err(crate::paged_ram::source::SourceFetchError::into_ram)?
        } else if observation {
            source.fetch_for_observation(arena.native.region_index, page_index, scratch)?
        } else {
            source.fetch(arena.native.region_index, page_index, scratch)?
        };
        Ok(valid)
    }

    fn resolve(&self, fault: FaultEvent, scratch: &mut [u8; PAGE_BYTES]) -> Result<(), RamError> {
        self.lifetime
            .lock()
            .map_err(|_| "fault actor poll publication poisoned")?
            .poll()?;
        self.check_placement_dependency()?;
        let operation = self
            .operations
            .begin(SourceOperationClass::PageIn)
            .map_err(RamError::from)?;
        let address = fault.address & !(PAGE_BYTES as u64 - 1);
        let arena = self
            .arenas
            .iter()
            .find(|arena| {
                address >= arena.native.host_address
                    && address < arena.native.host_address + arena.native.mapping_length
            })
            .ok_or("fault address is outside retained arenas")?;
        let page_index = (address - arena.native.host_address) / PAGE_BYTES as u64;
        let coordinate = arena
            .page_start
            .checked_add(usize::try_from(page_index).map_err(|_| "fault page index overflow")?)
            .ok_or("fault coordinate overflow")?;
        if fault.thread_id == 0 || (fault.write_protected && !fault.write) {
            return Err(RamError::Invariant(
                "fault accessor identity or flags are invalid",
            ));
        }
        if fault.write_protected {
            let mut states = self
                .states
                .lock()
                .map_err(|_| "paging state ownership uncertain")?;
            let state = states
                .get_mut(coordinate)
                .ok_or("fault coordinate absent")?;
            if !state.resident {
                return Err(RamError::Invariant(
                    "write fault does not match retained page state",
                ));
            }
            // Multiple blocked accessors can queue the same WP event. Only the
            // first transition advances its version; later events merely wake.
            if !state.writable {
                state.version = state
                    .version
                    .checked_add(1)
                    .ok_or("page write version exhausted")?;
                let status = (self.native.mark_write)(
                    arena.native.topology_generation,
                    arena.native.region_index,
                    page_index,
                );
                if status != 0 {
                    return Err(RamError::Native {
                        operation: "logical write ownership refused",
                        status,
                    });
                }
                self.registration
                    .protect(address, PAGE_BYTES as u64, false)
                    .map_err(RamError::from)?;
                state.writable = true;
                count_completed(&self.counters.write_transitions)?;
            }
        } else {
            let resident = self
                .states
                .lock()
                .map_err(|_| "paging state ownership uncertain")?
                .get(coordinate)
                .ok_or("fault coordinate absent")?
                .resident;
            if resident {
                // A prior service of another queued accessor already installed
                // this page; no removal is admitted while this service is active.
                self.check_placement_dependency()?;
                self.registration.wake(address).map_err(RamError::from)?;
                return operation.complete().map_err(RamError::from);
            }
            let valid = self.read_cold(arena, page_index, coordinate, false, scratch)?;
            // A terminal request accepted while backing I/O was pending refuses
            // installation after the original read returns, retaining UFFD.
            self.lifetime
                .lock()
                .map_err(|_| "fault actor poll publication poisoned")?
                .poll()?;
            if valid as usize != PAGE_BYTES {
                return Err(RamError::Invariant(
                    "source page length differs from admitted host mapping",
                ));
            }
            operation.wait_slice().map_err(RamError::from)?;
            self.check_placement_dependency()?;
            self.registration
                .populate(address, scratch)
                .map_err(RamError::from)?;
            self.states
                .lock()
                .map_err(|_| "paging state ownership uncertain")?
                .get_mut(coordinate)
                .ok_or("fault coordinate absent")?
                .resident = true;
            count_completed(&self.counters.missing_installs)?;
            if fault.write {
                count_completed(&self.counters.successful_missing_write_installs)?;
            } else {
                count_completed(&self.counters.successful_missing_read_installs)?;
            }
        }
        operation.wait_slice().map_err(RamError::from)?;
        self.check_placement_dependency()?;
        self.registration.wake(address).map_err(RamError::from)?;
        operation.complete().map_err(RamError::from)
    }

    fn check_placement_dependency(&self) -> Result<(), RamError> {
        let dependency = self
            .placement_dependency
            .try_lock()
            .map_err(|_| "page fault placement dependency unavailable")?
            .clone();
        if let Some(dependency) = dependency {
            dependency.wait_slice()?;
        }
        Ok(())
    }
}

pub(super) extern "C" fn operational_rearm(generation: u64) -> c_int {
    let result = rearm_resident_pages(generation);
    match result {
        Ok(()) => 0,
        Err(_) => -libc::EIO,
    }
}

fn rearm_resident_pages(generation: u64) -> Result<(), RamError> {
    let owner = OPERATIONAL_OWNER
        .get()
        .ok_or(RamError::Invariant("operational RAM owner absent"))?
        .try_lock()
        .map_err(|_| RamError::Invariant("operational RAM owner unavailable"))?
        .clone()
        .ok_or(RamError::Invariant("operational RAM owner absent"))?;
    let service = owner
        .active
        .lock()
        .map_err(|_| "paging authority owner poisoned")?
        .clone();
    let Some(service) = service else {
        return Ok(());
    };
    if !service.destructive.load(Ordering::Acquire) {
        return Ok(());
    }
    if !service.activated.load(Ordering::Acquire) || service.failed.load(Ordering::Acquire) {
        return Err(RamError::Invariant(
            "write tracking authority is not active",
        ));
    }
    let preparation = owner
        .write_preparation
        .lock()
        .map_err(|_| "prepared write rearm ownership unavailable")?;
    let mut states = service
        .states
        .lock()
        .map_err(|_| "paging state ownership uncertain")?;
    for arena in &service.arenas {
        if arena.placement != ArenaPlacement::Pageable {
            continue;
        }
        if arena.native.topology_generation != generation {
            return Err(RamError::Invariant("write rearm topology changed"));
        }
        let pages = usize::try_from(arena.native.mapping_length / PAGE_BYTES as u64)
            .map_err(|_| "arena page count overflow")?;
        for page in 0..pages {
            if preparation.as_ref().is_some_and(|preparation| {
                preparation.contains(arena.native.region_index, page as u64)
            }) {
                continue;
            }
            let state = states
                .get_mut(arena.page_start + page)
                .ok_or("write rearm page absent")?;
            if state.resident && state.writable {
                service
                    .registration
                    .protect(
                        arena.native.host_address + page as u64 * PAGE_BYTES as u64,
                        PAGE_BYTES as u64,
                        true,
                    )
                    .map_err(RamError::from)?;
                state.writable = false;
            }
        }
    }
    Ok(())
}

pub(super) extern "C" fn operational_read(address: u64, output: *mut u8, valid: u32) -> c_int {
    if output.is_null() || valid == 0 || valid as usize > PAGE_BYTES {
        return -libc::EINVAL;
    }
    read_operational_page::<false>(address, output, valid as usize, None)
}

/// Reads into the full-root caller's existing private page scratch.
///
/// Native full-root traversal exclusively owns this buffer until return. It
/// discards any partial bytes on failure before hashing or publishing a root.
pub(super) extern "C" fn root_scratch_read(
    address: u64,
    scratch: *mut NativeRootScratch,
    valid: u32,
    hasher: *const NativePageHasher,
) -> c_int {
    let hasher = if hasher.is_null() {
        None
    } else {
        // SAFETY: only the matching native root reader lends this initialized
        // stack record. Its hasher context remains exclusively borrowed until
        // this synchronous callback returns; neither pointer escapes here.
        let hasher = unsafe { &*hasher };
        if hasher.validate().is_err() {
            return -libc::EINVAL;
        }
        Some(hasher)
    };
    read_operational_page::<true>(address, scratch.cast(), valid as usize, hasher)
}

fn complete_root_scratch_read(
    scratch: *mut NativeRootScratch,
    valid: u32,
    read: impl FnOnce(&mut [u8; PAGE_BYTES]) -> Result<(), RamError>,
) -> c_int {
    if scratch.is_null() || valid == 0 || valid as usize > PAGE_BYTES {
        return -libc::EINVAL;
    }
    // SAFETY: the matching native registrar installs this nominal callback for
    // full-root-owned scratch alone. That traversal lends one initialized,
    // exclusively writable page for this synchronous call and neither hashes
    // nor publishes its contents until success. The loan does not escape here.
    let bytes = unsafe { &mut (*scratch).bytes };
    match read(bytes) {
        Ok(()) => 0,
        Err(_) => -libc::EIO,
    }
}

fn complete_operational_read(
    output: *mut u8,
    valid: usize,
    read: impl FnOnce(&mut [u8; PAGE_BYTES]) -> Result<(), RamError>,
) -> c_int {
    // Staging belongs to this caller. A failed read may modify private scratch,
    // but it cannot publish even a partial authenticated page to native output.
    let mut bytes = [0; PAGE_BYTES];
    match read(&mut bytes) {
        Ok(()) => {
            // SAFETY: native capture lends a writable valid-byte output buffer
            // for this call; the page scratch is fully authenticated beforehand.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, valid) };
            0
        }
        Err(_) => -libc::EIO,
    }
}

// Buffer ownership specializes at compile time; authentication and refusal
// order remain shared. Ordinary callers stage, while full-root traversal lends
// its existing nominal page and discards any partial result on failure.
fn read_operational_page<const ROOT_SCRATCH: bool>(
    address: u64,
    output: *mut u8,
    valid: usize,
    hasher: Option<&NativePageHasher>,
) -> c_int {
    let read = |bytes: &mut [u8; PAGE_BYTES]| -> Result<(), RamError> {
        let owner = OPERATIONAL_OWNER
            .get()
            .ok_or(RamError::Invariant("operational RAM owner absent"))?
            .try_lock()
            .map_err(|_| RamError::Invariant("operational RAM owner unavailable"))?
            .clone()
            .ok_or(RamError::Invariant("operational RAM owner absent"))?;
        let service = owner
            .active
            .lock()
            .map_err(|_| "paging authority owner poisoned")?
            .clone();
        if let Some(service) = service {
            if service.failed.load(Ordering::Acquire) {
                return Err(RamError::Invariant("paging authority failed"));
            }
            if service.destructive.load(Ordering::Acquire) {
                if !service.activated.load(Ordering::Acquire) {
                    return Err(RamError::Invariant(
                        "cold source publication remains incomplete",
                    ));
                }
                let arena = service
                    .arenas
                    .iter()
                    .find(|arena| {
                        address >= arena.native.host_address
                            && address < arena.native.host_address + arena.native.mapping_length
                    })
                    .ok_or("operational page is outside retained arena")?;
                let page_index = (address - arena.native.host_address) / PAGE_BYTES as u64;
                let coordinate = arena.page_start
                    + usize::try_from(page_index).map_err(|_| "page index overflow")?;
                let resident = service
                    .states
                    .lock()
                    .map_err(|_| "paging state ownership uncertain")?
                    .get(coordinate)
                    .ok_or("operational page coordinate absent")?
                    .resident;
                if !resident {
                    let length = if ROOT_SCRATCH {
                        match service.read_cold_with_hasher::<true>(
                            arena, page_index, coordinate, true, bytes, hasher,
                        ) {
                            Ok(length) => length,
                            Err(error) => {
                                owner.retain_operational_failure_owned(
                                    SourceOperationClass::FingerprintUpdate,
                                    error,
                                );
                                return Err(RamError::Invariant(
                                    "original root source failure is retained",
                                ));
                            }
                        }
                    } else {
                        service.read_cold(arena, page_index, coordinate, true, bytes)?
                    };
                    if length as usize != valid {
                        return Err(RamError::Invariant(
                            "operational source page length differs",
                        ));
                    }
                    return Ok(());
                }
            }
        }
        // SAFETY: native capture retains a coherent writer/physical-access fence and
        // lends this valid RAM range. Cold pages returned above never dereference it.
        unsafe { std::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), valid) };
        Ok(())
    };

    if ROOT_SCRATCH {
        complete_root_scratch_read(output.cast(), valid as u32, read)
    } else {
        complete_operational_read(output, valid, read)
    }
}

#[cfg(test)]
mod operational_read_tests;
