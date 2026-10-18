//! Services authenticated page faults and cold-safe coherent observations.
//!
//! The actor never enters QEMU replay, BQL, RCU, device, or root observer locks.
//! Its registered native lifetime remains visible through failed certificates.

use super::super::source::{RootSourceFailure, SourceFetchError};
use super::*;

pub(in crate::paged_ram::engine) mod capture_work;
use capture_work::FaultWorkOwner;

mod actor_lifetime;
mod page_read;
pub(super) use actor_lifetime::ActorLifetime;

/// Borrows the native hasher and callback-local failure destination together.
///
/// The destination stays synchronous with this read and its caller records the
/// failure after the source operation and mutex have closed.
struct BorrowedRootRead<'a> {
    hasher: Option<&'a NativePageHasher>,
    failure: &'a mut Option<RootSourceFailure>,
}

/// Leaves root source failures owned until their original failure cut is recorded.
///
/// Ordinary callers retain their original conversion point. This private relay
/// has no persistent storage; the borrowed slot closes in the same callback.
pub(super) fn source_read_failure(
    error: SourceFetchError,
    root_failure: Option<&mut Option<RootSourceFailure>>,
) -> RamError {
    match (error, root_failure) {
        (SourceFetchError::Io(error), Some(slot)) => {
            *slot = Some(RootSourceFailure::Io(error));
            RamError::Invariant("root source I/O awaits failure custody")
        }
        (SourceFetchError::Diagnostic(error), Some(slot)) => {
            *slot = Some(RootSourceFailure::Diagnostic(error));
            RamError::Invariant("root source diagnostic awaits failure custody")
        }
        (error, _) => error.into_ram(),
    }
}

pub(super) struct FaultService {
    pub(super) registration: Arc<Registration>,
    pub(super) counters: Arc<PagingCounters>,
    pub(super) source: Option<Arc<RestorePageSource>>,
    pub(super) spill: Arc<Mutex<super::super::PreservedPages>>,
    pub(super) arenas: Vec<Arena>,
    pub(super) states: Mutex<PageStates>,
    pub(super) placement_dependency: Mutex<Option<Arc<dyn SourceOperation>>>,
    pub(super) worker: Mutex<Option<JoinHandle<Result<(), RamError>>>>,
    pub(super) capture_work: FaultWorkOwner,
    pub(super) stop: AtomicBool,
    pub(super) activated: AtomicBool,
    pub(super) destructive: AtomicBool,
    pub(super) failed: AtomicBool,
    pub(super) lifetime: ActorLifetime,
    pub(super) retained_token: AtomicU64,
    pub(super) resident_observation: super::physical_observation::ResidentObservationState,
    pub(super) operations: Arc<dyn SourceOperationFactory>,
    pub(super) worker_generation: u64,
    pub(super) native: NativeOperations,
    pub(super) _reservation: MetadataReservation,
    pub(super) _arena_reservation: MetadataReservation,
}

impl FaultService {
    pub(super) fn start(self: &Arc<Self>) -> Result<(), RamError> {
        let mut worker = self
            .worker
            .try_lock()
            .map_err(|_| RamError::Invariant("paging worker owner unavailable"))?;
        self.start_with_worker(&mut worker)
    }

    fn start_with_worker(
        self: &Arc<Self>,
        worker: &mut Option<JoinHandle<Result<(), RamError>>>,
    ) -> Result<(), RamError> {
        let result = self.start_worker(worker);
        if let Err(error) = &result {
            self.failed.store(true, Ordering::Release);
            self.stop.store(true, Ordering::Release);
            self.lifetime.failed(error.clone());
        }
        result
    }

    fn start_worker(
        self: &Arc<Self>,
        worker: &mut Option<JoinHandle<Result<(), RamError>>>,
    ) -> Result<(), RamError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("failed paging authority cannot start"));
        }
        let operation = self
            .operations
            .begin(SourceOperationClass::ControlSetup)
            .map_err(RamError::from)?;
        if worker.is_some() {
            return Err(RamError::Invariant("paging worker is already running"));
        }
        let service = self.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        *worker = Some(
            std::thread::Builder::new()
                .name("guest-page-service".to_owned())
                .stack_size(PAGER_STACK_BYTES)
                .spawn(move || service.run_worker(ready_tx))
                .map_err(RamError::from)?,
        );
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

    fn run_worker(&self, ready: std::sync::mpsc::SyncSender<i32>) -> Result<(), RamError> {
        // SAFETY: gettid has no pointer operands and identifies this actual
        // actor; native registry checks caller identity rather than names.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        let status = (self.native.worker)(1, self.worker_generation, tid, 1);
        if status != 0 {
            let error = RamError::Native {
                operation: "paging worker registration refused",
                status,
            };
            self.failed.store(true, Ordering::Release);
            self.lifetime.failed(error.clone());
            let _ = ready.send(status);
            return Err(error);
        }

        // Every exit after real native admission passes through membership
        // release, including journal poison, abandoned startup and body panic.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.lifetime.admitted(tid)?;
            ready
                .send(0)
                .map_err(|_| RamError::Invariant("paging worker admission abandoned"))?;
            self.run()
        }))
        .unwrap_or(Err(RamError::Invariant("paging fault actor panicked")));
        if let Err(error) = &result {
            self.failed.store(true, Ordering::Release);
            self.lifetime.failed(error.clone());
        }
        // A failed startup must notify its original waiter even when physical
        // membership release remains held by an independent certificate.
        drop(ready);

        let mut release = (self.native.worker)(1, self.worker_generation, tid, 0);
        while release == -libc::EBUSY {
            // Existing membership stays alive while a certificate retains
            // it. Failure never disappears from the held physical inventory.
            std::thread::sleep(std::time::Duration::from_millis(10));
            release = (self.native.worker)(1, self.worker_generation, tid, 0);
        }
        if release != 0 {
            let error = RamError::Native {
                operation: "paging worker membership release failed",
                status: release,
            };
            self.failed.store(true, Ordering::Release);
            self.lifetime.failed(error.clone());
            return Err(error);
        }
        self.lifetime.released();
        result
    }

    pub(super) fn stop_for_fork(&self) -> Result<(), RamError> {
        self.stop_and_join()?;
        if self.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("paging worker failed during fork hold"));
        }
        Ok(())
    }

    fn stop_and_join(&self) -> Result<(), RamError> {
        let operation = match self.operations.begin(SourceOperationClass::Cleanup) {
            Ok(operation) => operation,
            Err(error) => {
                let error = RamError::from(error);
                self.retain_cleanup_failure(&error);
                return Err(error);
            }
        };
        self.stop.store(true, Ordering::Release);
        join_stopped_worker(&self.worker, operation.as_ref(), |error| {
            self.retain_cleanup_failure(error);
        })
    }

    fn retain_cleanup_failure(&self, error: &RamError) {
        self.failed.store(true, Ordering::Release);
        self.lifetime.cleanup_failed(error.clone());
    }

    pub(super) fn resume_after_fork(self: &Arc<Self>) -> Result<(), RamError> {
        let mut worker = self
            .worker
            .try_lock()
            .map_err(|_| RamError::Invariant("paging worker owner unavailable"))?;
        if self.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("failed paging authority cannot resume"));
        }
        if worker.is_some() {
            return Err(RamError::Invariant(
                "paging worker has no completed fork disposition",
            ));
        }
        self.lifetime.check_clean_disposition()?;
        self.stop.store(false, Ordering::Release);
        self.start_with_worker(&mut worker)
    }

    pub(super) fn stop_before_activation(&self) -> Result<(), RamError> {
        if self.activated.load(Ordering::Acquire) {
            return Err(RamError::Invariant(
                "active paging worker requires a cold-source lifecycle handoff",
            ));
        }
        self.stop_and_join()
    }

    fn run(&self) -> Result<(), RamError> {
        while !self.stop.load(Ordering::Acquire) {
            self.lifetime.poll()?;
            self.registration.wait(10).map_err(RamError::from)?;
            if !self.activated.load(Ordering::Acquire) {
                continue;
            }
            loop {
                // The body owns a consumed event before operation admission and
                // retains its actual scratch/claim on every unresolved return.
                let mut work = self.capture_work.try_lock()?;
                if self.capture_work.acknowledge_pause_at_boundary(&work)? {
                    break;
                }
                let Some(fault) = work.read_fault(&self.registration)? else {
                    break;
                };
                work.claim(fault, self.operations.as_ref())?;
                let result = {
                    let (fault, operation, scratch) = work.request()?;
                    self.resolve(fault, operation, scratch)
                };
                match result {
                    Ok(()) => work.settled()?,
                    Err(error) => {
                        work.fail();
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn read_cold_for_observation(
        &self,
        arena: &Arena,
        page_index: u64,
        coordinate: usize,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<u32, RamError> {
        self.read_cold_with_hasher::<false>(arena, page_index, coordinate, scratch, None)
    }

    fn read_cold_with_hasher<const BORROWED: bool>(
        &self,
        arena: &Arena,
        page_index: u64,
        coordinate: usize,
        scratch: &mut [u8; PAGE_BYTES],
        root: Option<BorrowedRootRead<'_>>,
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
            if BORROWED {
                let (hasher, root_failure) = match root {
                    Some(root) => (root.hasher, Some(root.failure)),
                    None => (None, None),
                };
                super::super::source::with_observation_operation(|operation| {
                    // The native Root owns this running Original. Check it
                    // before backing I/O; completion supplies the post cut.
                    operation.wait_slice_for_observation()?;
                    let spill = self.spill.try_lock().map_err(|_| {
                        SourceFetchError::Owner(RamError::Invariant("spill ownership unavailable"))
                    })?;
                    spill.read_with_borrowed_hasher(&record, scratch, hasher)?;
                    drop(spill);
                    operation.complete_observation()?;
                    count_completed(&self.counters.preserved_reads)
                        .map_err(SourceFetchError::Owner)?;
                    Ok(())
                })
                .map_err(|error| source_read_failure(error, root_failure))?;
                return Ok(record.valid_length());
            }
            let operation = self
                .operations
                .begin(SourceOperationClass::FingerprintUpdate)?;
            let spill = self
                .spill
                .try_lock()
                .map_err(|_| "spill ownership unavailable")?;
            spill.read(&record, scratch)?;
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
            let (hasher, root_failure) = match root {
                Some(root) => (root.hasher, Some(root.failure)),
                None => (None, None),
            };
            source
                .fetch_with_borrowed_hasher(arena.native.region_index, page_index, scratch, hasher)
                // The source mutex and operation close at the historical
                // conversion boundary. Root causes stay owned until their caller
                // records the same first-failure cut.
                .map_err(|error| source_read_failure(error, root_failure))?
        } else {
            source.fetch_for_observation(arena.native.region_index, page_index, scratch)?
        };
        Ok(valid)
    }

    fn resolve(
        &self,
        fault: FaultEvent,
        operation: &dyn SourceOperation,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<(), RamError> {
        self.lifetime.poll()?;
        self.check_placement_dependency()?;
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
                operation.wait_slice().map_err(RamError::from)?;
                self.registration.wake(address).map_err(RamError::from)?;
                return Ok(());
            }
            // The consumed fault already owns its PageIn Original. The backing
            // exchange reports one authenticated unit without completing it;
            // ioctl, page publication and wake still belong to the same fault.
            let valid = self.read_page_source(arena, page_index, coordinate, operation, scratch)?;
            // A terminal request accepted while backing I/O was pending refuses
            // installation after the original read returns, retaining UFFD.
            self.lifetime.poll()?;
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
        Ok(())
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

fn wait_for_worker_return(
    worker: Option<&JoinHandle<Result<(), RamError>>>,
    operation: &dyn SourceOperation,
) -> Result<(), RamError> {
    loop {
        let slice = operation.wait_slice()?;
        let finished = worker.is_none_or(JoinHandle::is_finished);
        if finished {
            return Ok(());
        }
        std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));
    }
}

fn join_stopped_worker(
    worker: &Mutex<Option<JoinHandle<Result<(), RamError>>>>,
    operation: &dyn SourceOperation,
    retain_failure: impl FnOnce(&RamError),
) -> Result<(), RamError> {
    let mut worker = match worker.try_lock() {
        Ok(worker) => worker,
        Err(_) => {
            let error = RamError::Invariant("paging worker owner unavailable");
            retain_failure(&error);
            return Err(error);
        }
    };
    // The actor never locks this slot. Keep it exclusive until the actual join
    // and Cleanup post complete, so empty cannot expose a half-finished stop.
    let result: Result<(), RamError> = (|| {
        wait_for_worker_return(worker.as_ref(), operation)?;
        if let Some(worker) = worker.take() {
            worker
                .join()
                .map_err(|_| RamError::Invariant("paging worker panicked during shutdown"))??;
        }
        operation.complete()?;
        Ok(())
    })();
    if let Err(error) = &result {
        retain_failure(error);
    }
    result
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
        // The current Native Root supplies its factual initialization/update
        // class. Outside that borrowed view, this is the existing independent
        // proof-hydration observation, not a baseline initialization issuer.
        let class = crate::ram_fingerprint::borrowed_original_class()?
            .unwrap_or(SourceOperationClass::FingerprintUpdate);
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
                    let length = {
                        let mut source_failure = None;
                        match service.read_cold_with_hasher::<true>(
                            arena,
                            page_index,
                            coordinate,
                            bytes,
                            Some(BorrowedRootRead {
                                hasher,
                                failure: &mut source_failure,
                            }),
                        ) {
                            Ok(length) => length,
                            Err(error) => {
                                if let Some(original) = source_failure {
                                    owner.retain_operational_source_failure(class, original);
                                } else {
                                    owner.retain_operational_failure_owned(class, error);
                                }
                                return Err(RamError::Invariant(
                                    "original root source failure is retained",
                                ));
                            }
                        }
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

#[cfg(test)]
mod worker_join_tests {
    //! Checks local Rust handle retention, without issuing native membership.

    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use crate::paged_ram::source::ObservationOperationError;

    struct CleanupSlices {
        allowed: usize,
        checked: AtomicUsize,
    }

    impl SourceOperation for CleanupSlices {
        fn wait_slice(&self) -> io::Result<Duration> {
            if self.checked.fetch_add(1, Ordering::SeqCst) < self.allowed {
                Ok(Duration::ZERO)
            } else {
                Err(io::Error::from_raw_os_error(libc::ETIMEDOUT))
            }
        }

        fn complete(&self) -> io::Result<()> {
            panic!("waiting cannot claim completion");
        }

        fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
            self.wait_slice().map_err(Into::into)
        }

        fn complete_observation(&self) -> Result<(), ObservationOperationError> {
            panic!("waiting cannot claim observation completion");
        }
    }

    #[test]
    fn expired_cleanup_refuses_even_without_a_worker_to_wait_for() {
        let worker = Mutex::new(None);
        let operation = CleanupSlices {
            allowed: 0,
            checked: AtomicUsize::new(0),
        };

        let result = join_stopped_worker(&worker, &operation, |_| {});

        assert!(
            matches!(result, Err(RamError::Io(error)) if error.raw_os_error() == Some(libc::ETIMEDOUT))
        );
        assert_eq!(operation.checked.load(Ordering::SeqCst), 1);
        assert!(worker.lock().unwrap().is_none());
    }

    #[test]
    fn cleanup_refusal_keeps_the_same_blocked_worker_handle() {
        for allowed in 0..=2 {
            let (release, waiting) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                waiting.recv().unwrap();
                Ok(())
            });
            let identity = handle.thread().id();
            let worker = Mutex::new(Some(handle));
            let operation = CleanupSlices {
                allowed,
                checked: AtomicUsize::new(0),
            };

            let result = join_stopped_worker(&worker, &operation, |_| {});

            assert!(
                matches!(result, Err(RamError::Io(error)) if error.raw_os_error() == Some(libc::ETIMEDOUT))
            );
            assert_eq!(operation.checked.load(Ordering::SeqCst), allowed + 1);
            assert_eq!(
                worker.lock().unwrap().as_ref().unwrap().thread().id(),
                identity
            );

            release.send(()).unwrap();
            worker
                .into_inner()
                .unwrap()
                .unwrap()
                .join()
                .unwrap()
                .unwrap();
        }
    }

    struct CompletionCheck<'a> {
        worker: &'a Mutex<Option<JoinHandle<Result<(), RamError>>>>,
        refuse: bool,
        completed: AtomicUsize,
    }

    impl SourceOperation for CompletionCheck<'_> {
        fn wait_slice(&self) -> io::Result<Duration> {
            Ok(Duration::ZERO)
        }

        fn complete(&self) -> io::Result<()> {
            assert!(matches!(
                self.worker.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            self.completed.fetch_add(1, Ordering::SeqCst);
            if self.refuse {
                return Err(io::Error::from_raw_os_error(libc::ECANCELED));
            }
            Ok(())
        }

        fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
            self.wait_slice().map_err(Into::into)
        }

        fn complete_observation(&self) -> Result<(), ObservationOperationError> {
            self.complete().map_err(Into::into)
        }
    }

    #[test]
    fn cleanup_post_and_failure_publication_keep_the_worker_slot_exclusive() {
        for refuse in [false, true] {
            let worker = Mutex::new(None);
            let operation = CompletionCheck {
                worker: &worker,
                refuse,
                completed: AtomicUsize::new(0),
            };
            let failure_retained = Cell::new(false);

            let result = join_stopped_worker(&worker, &operation, |error| {
                assert!(matches!(
                    worker.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                assert!(
                    matches!(error, RamError::Io(error) if error.raw_os_error() == Some(libc::ECANCELED))
                );
                failure_retained.set(true);
            });

            assert_eq!(result.is_err(), refuse);
            assert_eq!(failure_retained.get(), refuse);
            assert_eq!(operation.completed.load(Ordering::SeqCst), 1);
            assert!(worker.try_lock().unwrap().is_none());
        }
    }
}
