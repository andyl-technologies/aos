//! Retains target-page ownership before an atomic authored memory mutation.
//!
//! Native preparation resolves private COW and write protection using identical
//! bytes before constructing the logical baseline. This receipt prevents a root
//! refresh from rearming those pages and excludes placement or fork until all
//! mutation paths release it. No receipt lock is held while guest memory faults.

use super::*;

const MAX_PREPARED_PAGES: usize = 65536;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct WriteCoordinate {
    region_index: u32,
    reserved: u32,
    page_index: u64,
}

type Begin = extern "C" fn(u64, u64, *const WriteCoordinate, usize, *mut u64) -> c_int;
type Check = extern "C" fn(u64, u32) -> c_int;
type Finish = extern "C" fn(u64) -> c_int;
type Progress = extern "C" fn(u64, u64) -> c_int;
type ScratchReserve = extern "C" fn(u64, *mut u64) -> c_int;
type Register = extern "C" fn(Begin, Check, Finish, Progress, ScratchReserve, Finish) -> c_int;

pub(super) struct WriteScratch {
    token: u64,
    operation: Arc<dyn SourceOperation>,
    _reservation: MetadataReservation,
}

pub(super) struct WritePreparation {
    token: u64,
    generation: u64,
    pages: Vec<WriteCoordinate>,
    service: Arc<FaultService>,
    operation: Arc<dyn SourceOperation>,
    ready: bool,
    completed_targets: usize,
    _reservation: MetadataReservation,
}

impl WritePreparation {
    pub(super) fn contains(&self, region_index: u32, page_index: u64) -> bool {
        self.ready
            && self
                .pages
                .binary_search(&WriteCoordinate {
                    region_index,
                    reserved: 0,
                    page_index,
                })
                .is_ok()
    }

    fn check(&mut self, token: u64, ready: bool) -> Result<(), RamError> {
        if token != self.token || self.service.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("prepared write authority changed"));
        }
        self.operation.wait_slice()?;
        if ready {
            if self.completed_targets != self.pages.len() {
                return Err(RamError::Invariant(
                    "prepared write page work is incomplete",
                ));
            }
            let states = self
                .service
                .states
                .lock()
                .map_err(|_| "prepared write state is unavailable")?;
            for page in &self.pages {
                let arena = self.arena(*page)?;
                let state = states
                    .get(
                        arena.page_start
                            + usize::try_from(page.page_index)
                                .map_err(|_| "prepared page index exceeds address space")?,
                    )
                    .ok_or("prepared write page is absent")?;
                if !state.resident
                    || (arena.placement == ArenaPlacement::Pageable && !state.writable)
                {
                    return Err(RamError::Invariant(
                        "prepared write page has not resolved host COW and write protection",
                    ));
                }
            }
            self.ready = true;
        }
        Ok(())
    }

    fn arena(&self, coordinate: WriteCoordinate) -> Result<&Arena, RamError> {
        let arena = self
            .service
            .arenas
            .get(coordinate.region_index as usize)
            .ok_or("prepared write region is absent")?;
        if arena.native.topology_generation != self.generation
            || coordinate.page_index >= arena.native.logical_length.div_ceil(PAGE_BYTES as u64)
            || matches!(
                arena.placement,
                ArenaPlacement::ResidentPinned { readonly: true }
            )
        {
            return Err(RamError::Invariant("prepared write coordinate is invalid"));
        }
        Ok(arena)
    }

    fn finish(&self) -> Result<(), RamError> {
        self.operation.wait_slice()?;
        if self.service.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("prepared write fault service failed"));
        }
        let mut states = self
            .service
            .states
            .lock()
            .map_err(|_| "prepared write state is unavailable")?;
        for page in &self.pages {
            let arena = self.arena(*page)?;
            if arena.placement != ArenaPlacement::Pageable {
                continue;
            }
            let state = states
                .get_mut(
                    arena.page_start
                        + usize::try_from(page.page_index)
                            .map_err(|_| "prepared page index exceeds address space")?,
                )
                .ok_or("prepared write page is absent")?;
            if state.resident && state.writable {
                self.service.registration.protect(
                    arena.native.host_address + page.page_index * PAGE_BYTES as u64,
                    PAGE_BYTES as u64,
                    true,
                )?;
                state.writable = false;
            }
        }
        drop(states);
        self.operation.complete()?;
        Ok(())
    }
}

impl PausedPagingOwner {
    pub(super) fn require_no_prepared_write(&self) -> Result<(), RamError> {
        if self
            .write_preparation
            .try_lock()
            .map_err(|_| "prepared write admission unavailable")?
            .is_some()
            || self
                .write_scratch
                .try_lock()
                .map_err(|_| "prepared write scratch unavailable")?
                .is_some()
        {
            return Err(RamError::Native {
                operation: "prepared write excludes lifecycle handoff",
                status: -libc::EBUSY,
            });
        }
        Ok(())
    }

    fn begin_write(
        &self,
        generation: u64,
        scratch_token: u64,
        pages: &[WriteCoordinate],
    ) -> Result<u64, RamError> {
        if pages.is_empty()
            || pages.len() > MAX_PREPARED_PAGES
            || pages.iter().any(|page| page.reserved != 0)
            || pages.windows(2).any(|pair| pair[0] >= pair[1])
            || generation != self.topology_generation.load(Ordering::Acquire)
            || self.failed.load(Ordering::Acquire)
        {
            return Err(RamError::Invariant("prepared write inventory is invalid"));
        }
        let operation = {
            let scratch = self
                .write_scratch
                .lock()
                .map_err(|_| "prepared write scratch is unavailable")?;
            scratch
                .as_ref()
                .filter(|scratch| scratch.token == scratch_token)
                .ok_or("prepared write scratch token changed")?
                .operation
                .clone()
        };
        operation.wait_slice()?;
        let service = self
            .active
            .lock()
            .map_err(|_| "prepared write owner is unavailable")?
            .clone()
            .ok_or("prepared write requires active paging authority")?;
        if !service.activated.load(Ordering::Acquire) || service.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant("prepared write authority is inactive"));
        }
        let budget = crate::ram_fingerprint::fork_metadata_budget()?;
        let bytes = pages
            .len()
            .checked_mul(std::mem::size_of::<WriteCoordinate>())
            .and_then(|bytes| bytes.checked_add(PAGE_BYTES - 1))
            .map(|bytes| bytes & !(PAGE_BYTES - 1))
            .and_then(|bytes| bytes.checked_add(PAGE_BYTES))
            .ok_or("prepared write metadata overflow")?;
        let reservation = budget.reserve_bytes(bytes as u64)?;
        let mut owned_pages = Vec::new();
        owned_pages.try_reserve_exact(pages.len())?;
        owned_pages.extend_from_slice(pages);
        let token = self
            .write_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| "prepared write generation exhausted")?
            + 1;
        let preparation = WritePreparation {
            token,
            generation,
            pages: owned_pages,
            service,
            operation,
            ready: false,
            completed_targets: 0,
            _reservation: reservation,
        };
        // Each possible first WP transition needs a fresh page version before
        // any authored store. Same-content native touches perform that work.
        {
            let states = preparation
                .service
                .states
                .lock()
                .map_err(|_| "prepared write states are unavailable")?;
            for page in pages {
                let arena = preparation.arena(*page)?;
                let state = states
                    .get(
                        arena.page_start
                            + usize::try_from(page.page_index)
                                .map_err(|_| "prepared page index exceeds address space")?,
                    )
                    .ok_or("prepared write page is absent")?;
                if state.version == u64::MAX && !state.writable {
                    return Err(RamError::Invariant("prepared page version exhausted"));
                }
            }
        }
        let mut admission = self
            .write_preparation
            .lock()
            .map_err(|_| "prepared write admission is unavailable")?;
        if admission.is_some() {
            return Err(RamError::Invariant("prepared write admission is occupied"));
        }
        *admission = Some(preparation);
        Ok(token)
    }
}

fn owner() -> Result<Arc<PausedPagingOwner>, RamError> {
    OPERATIONAL_OWNER
        .get()
        .ok_or("prepared write owner is absent")?
        .try_lock()
        .map_err(|_| "prepared write owner is unavailable")?
        .clone()
        .ok_or(RamError::Invariant("prepared write owner is absent"))
}

extern "C" fn begin(
    generation: u64,
    scratch_token: u64,
    pages: *const WriteCoordinate,
    count: usize,
    token: *mut u64,
) -> c_int {
    if pages.is_null() || token.is_null() || count == 0 || count > MAX_PREPARED_PAGES {
        return -libc::EINVAL;
    }
    // SAFETY: the native writer fence loans this bounded coordinate array and
    // writable scalar output until callback return; no pointers are retained.
    let pages = unsafe { std::slice::from_raw_parts(pages, count) };
    match owner().and_then(|owner| owner.begin_write(generation, scratch_token, pages)) {
        Ok(value) => {
            // SAFETY: the checked native output is a writable scalar loan.
            unsafe { token.write(value) };
            0
        }
        Err(error) => preflight_status(error),
    }
}

extern "C" fn check(token: u64, require_ready: u32) -> c_int {
    if require_ready > 1 {
        return -libc::EINVAL;
    }
    let result = (|| {
        let owner = owner()?;
        let mut admission = owner
            .write_preparation
            .lock()
            .map_err(|_| "prepared write admission unavailable")?;
        admission
            .as_mut()
            .ok_or("prepared write receipt absent")?
            .check(token, require_ready == 1)
    })();
    match result {
        Ok(()) => 0,
        Err(_) => -libc::EIO,
    }
}

extern "C" fn finish(token: u64) -> c_int {
    let result = (|| {
        let owner = owner()?;
        let mut admission = owner
            .write_preparation
            .lock()
            .map_err(|_| "prepared write admission unavailable")?;
        let preparation = admission.as_ref().ok_or("prepared write receipt absent")?;
        if token != preparation.token {
            return Err(RamError::Invariant("prepared write token changed"));
        }
        if let Err(error) = preparation.finish() {
            owner.failed.store(true, Ordering::Release);
            return Err(error);
        }
        admission.take();
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(_) => -libc::EIO,
    }
}

extern "C" fn progress(token: u64, completed: u64) -> c_int {
    let result = (|| {
        let owner = owner()?;
        let mut admission = owner
            .write_preparation
            .lock()
            .map_err(|_| "prepared write progress authority unavailable")?;
        let preparation = admission.as_mut().ok_or("prepared write receipt absent")?;
        if token != preparation.token || completed != preparation.completed_targets as u64 + 1 {
            return Err(RamError::Invariant("prepared write work cursor is invalid"));
        }
        let page = *preparation
            .pages
            .get(preparation.completed_targets)
            .ok_or("prepared write work exceeds admitted pages")?;
        let arena = preparation.arena(page)?;
        {
            let states = preparation
                .service
                .states
                .lock()
                .map_err(|_| "prepared write progress state unavailable")?;
            let state = states
                .get(
                    arena.page_start
                        + usize::try_from(page.page_index)
                            .map_err(|_| "prepared page index exceeds address space")?,
                )
                .ok_or("prepared write progress page absent")?;
            if !state.resident || (arena.placement == ArenaPlacement::Pageable && !state.writable) {
                return Err(RamError::Invariant("prepared page work is not complete"));
            }
        }
        preparation.operation.progress(completed)?;
        preparation.completed_targets += 1;
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(_) => -libc::EIO,
    }
}

fn preflight_status(error: RamError) -> c_int {
    match error {
        RamError::Core(crucible_ram::RamError::ResourceLimit)
        | RamError::MetadataAdmission { .. } => -libc::ENOSPC,
        RamError::Allocation(_) => -libc::ENOMEM,
        RamError::Native { status, .. } => status,
        _ => -libc::EIO,
    }
}

extern "C" fn scratch_reserve(bytes: u64, output: *mut u64) -> c_int {
    if bytes == 0 || output.is_null() {
        return -libc::EINVAL;
    }
    let result = (|| {
        let owner = owner()?;
        if owner.preparing.swap(true, Ordering::AcqRel) {
            return Err(RamError::Native {
                operation: "write scratch overlaps physical preparation",
                status: -libc::EBUSY,
            });
        }
        let admitted = (|| {
            let budget = crate::ram_fingerprint::fork_metadata_budget()?;
            let reservation = budget.reserve_bytes(bytes)?;
            let token = owner
                .write_generation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| "write scratch generation exhausted")?
                + 1;
            let operation = Arc::from(owner.operations.begin(SourceOperationClass::Quiescence)?);
            let mut scratch = owner
                .write_scratch
                .lock()
                .map_err(|_| "write scratch authority unavailable")?;
            if scratch.is_some() {
                return Err(RamError::Invariant("write scratch authority occupied"));
            }
            *scratch = Some(WriteScratch {
                token,
                operation,
                _reservation: reservation,
            });
            Ok(token)
        })();
        if admitted.is_err() {
            owner.preparing.store(false, Ordering::Release);
        }
        admitted
    })();
    match result {
        Ok(token) => {
            // SAFETY: native loans this writable scalar until callback return.
            unsafe { output.write(token) };
            0
        }
        Err(error) => preflight_status(error),
    }
}

extern "C" fn scratch_release(token: u64) -> c_int {
    let result = (|| {
        let owner = owner()?;
        let preparation = owner
            .write_preparation
            .lock()
            .map_err(|_| "write receipt authority unavailable")?;
        if preparation.is_some() {
            return Err(RamError::Invariant(
                "write scratch still owns a page receipt",
            ));
        }
        let mut scratch = owner
            .write_scratch
            .lock()
            .map_err(|_| "write scratch authority unavailable")?;
        if !scratch
            .as_ref()
            .is_some_and(|scratch| scratch.token == token)
        {
            return Err(RamError::Invariant("write scratch token changed"));
        }
        scratch.take();
        owner.preparing.store(false, Ordering::Release);
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(_) => -libc::EIO,
    }
}

pub(super) fn install() -> Result<(), RamError> {
    // SAFETY: the registrar's callback types match the GPL-private native ABI.
    let register = unsafe {
        std::mem::transmute::<*mut c_void, Register>(symbol(
            b"qemu_plugin_crucible_register_ram_write_preparation_v1\0",
        )?)
    };
    let status = register(
        begin,
        check,
        finish,
        progress,
        scratch_reserve,
        scratch_release,
    );
    if status != 0 {
        return Err(RamError::Native {
            operation: "prepared write registrar",
            status,
        });
    }
    Ok(())
}
