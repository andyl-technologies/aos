//! Journals one eviction under the existing native paused physical owner.
//!
//! The fault-work mutex serializes this transaction with consumed faults and
//! lends its already paid scratch. This module issues no live progress domain,
//! resident entitlement, native exclusion, or replacement authority.

// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::paged_ram::PageRecord;
use crate::paged_ram::engine::placement::{PhysicalPlacement, pace_writeback};

/// Retains each attempted effect independently of later publication failures.
#[derive(Default)]
enum Effect {
    #[default]
    NotStarted,
    Started,
    Complete,
    // Refusal can include partial effects; it is never evidence of no mutation.
    Failed(RamError),
}

impl Effect {
    fn check_complete(&self) -> Result<(), RamError> {
        match self {
            Self::Complete => Ok(()),
            Self::Failed(error) => Err(error.clone()),
            Self::NotStarted | Self::Started => {
                Err(RamError::Invariant("eviction effect remains unsettled"))
            }
        }
    }

    fn finish(&mut self, result: Result<(), RamError>) -> Result<(), RamError> {
        *self = match &result {
            Ok(()) => Self::Complete,
            Err(error) => Self::Failed(error.clone()),
        };
        result
    }
}

/// Lives inline in the admitted body through all uncertain physical outcomes.
pub(super) struct EvictionJournal {
    coordinate: usize,
    address: u64,
    selected: PageState,
    protection: Effect,
    preservation: Effect,
    preserved: Option<PageRecord>,
    published: bool,
    discard: Effect,
    residency_returned: bool,
    writeback: Option<Box<dyn SourceOperation>>,
    writeback_post: Effect,
    writeback_completion: Effect,
    first_failure: Option<RamError>,
}

impl EvictionJournal {
    fn new(coordinate: usize, address: u64, selected: PageState) -> Self {
        Self {
            coordinate,
            address,
            selected,
            protection: Effect::NotStarted,
            preservation: Effect::NotStarted,
            preserved: None,
            published: false,
            discard: Effect::NotStarted,
            residency_returned: false,
            writeback: None,
            writeback_post: Effect::NotStarted,
            writeback_completion: Effect::NotStarted,
            first_failure: None,
        }
    }

    fn selected_state<'a>(
        &self,
        states: &'a mut PageStates,
    ) -> Result<&'a mut PageState, RamError> {
        let state = states
            .get_mut(self.coordinate)
            .ok_or("eviction page is absent or fenced")?;
        if !self.selected.resident || !state.resident || state.version != self.selected.version {
            return Err(RamError::Invariant(
                "eviction page changed under physical owner",
            ));
        }
        Ok(state)
    }

    fn run(
        &mut self,
        placement: &PhysicalPlacement<'_>,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<(), RamError> {
        let service = &placement.service;
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "eviction state unavailable")?;
            self.selected_state(&mut states)?;
        }

        self.protection = Effect::Started;
        self.protection.finish(
            service
                .registration
                .protect(self.address, PAGE_BYTES as u64, true)
                .map_err(Into::into),
        )?;
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "eviction state unavailable")?;
            self.selected_state(&mut states)?.writable = false;
        }
        placement.check_budget()?;

        self.preservation = Effect::Started;
        let preservation = self.preserve(placement, scratch);
        self.finish_preservation(preservation, &service.counters)?;
        placement.check_budget()?;
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "eviction state unavailable")?;
            // Preserve the original lease in `selected` until settlement; the
            // new immutable record is visible before any resident PTE removal.
            self.selected_state(&mut states)?.preserved = self.preserved.clone();
            self.published = true;
        }
        placement.check_budget()?;
        let status = (service.native.validate)(placement.token, placement.generation);
        if status != 0 {
            return Err(RamError::Native {
                operation: "eviction physical owner before discard",
                status,
            });
        }

        self.discard = Effect::Started;
        // SAFETY: this exact mapping remains owned by the validated native
        // physical certificate. WP completed and preservation is authenticated.
        let discarded = unsafe { discard_page(self.address) }.map_err(RamError::from);
        self.discard.finish(discarded)?;
        {
            let mut states = service
                .states
                .try_lock()
                .map_err(|_| "eviction state unavailable")?;
            // Only successful physical discard can return this residency slot.
            // Full guest-RAM entitlement remains held; shared COW backing may
            // still exist and this does not refund a Source/process debit.
            self.selected_state(&mut states)?.resident = false;
            self.residency_returned = true;
        }
        count_completed(&service.counters.physical_discards)?;
        if let Some(operation) = self.writeback.as_ref() {
            self.writeback_completion = Effect::Started;
            self.writeback_completion
                .finish(operation.complete().map_err(Into::into))?;
        }
        placement.progress_work()?;
        Ok(())
    }

    fn finish_preservation(
        &mut self,
        result: Result<(), RamError>,
        counters: &PagingCounters,
    ) -> Result<(), RamError> {
        // Save the actual preservation result before entering the Original's
        // independent post, including pacing/I/O failures after its birth.
        let preservation = self.preservation.finish(result);
        let post = if let Some(operation) = self.writeback.as_ref() {
            self.writeback_post = Effect::Started;
            self.writeback_post
                .finish(operation.wait_slice().map(|_| ()).map_err(Into::into))
        } else {
            Ok(())
        };
        let counted = if preservation.is_ok() && self.writeback.is_some() {
            count_completed(&counters.preserved_writes)
        } else {
            Ok(())
        };

        // A later post/counter refusal cannot replace preservation's first
        // cause. Neither failed preservation nor failed post permits complete.
        preservation?;
        post?;
        counted
    }

    fn preserve(
        &mut self,
        placement: &PhysicalPlacement<'_>,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<(), RamError> {
        let service = &placement.service;
        // The sealed original source already owns version one's exact bytes.
        if self.selected.version == 1
            && self.selected.preserved.is_none()
            && service.source.is_some()
        {
            return Ok(());
        }
        if let Some(record) = self.selected.preserved.as_ref().filter(|record| {
            record.page_version() == self.selected.version
                && record.valid_length() as usize == PAGE_BYTES
        }) {
            self.preserved = Some(record.clone());
            return Ok(());
        }

        // Publish the actual Original before pacing, copying or backing I/O.
        // A later refusal retains it in this journal instead of dropping it.
        self.writeback = Some(service.operations.begin(SourceOperationClass::Writeback)?);
        let operation = self
            .writeback
            .as_deref()
            .ok_or("eviction Writeback disappeared")?;
        pace_writeback(operation, placement.writeback_rate)?;
        // SAFETY: physical exclusion owns a resident page; synchronous WP has
        // completed. No concurrent actor can clear WP while this body is held.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.address as *const u8,
                scratch.as_mut_ptr(),
                PAGE_BYTES,
            );
        }
        self.preserved = Some(
            service
                .spill
                .try_lock()
                .map_err(|_| "spill authority unavailable")?
                .preserve(scratch, PAGE_BYTES as u32, self.selected.version)
                .map_err(|error| placement.owner.writeback_failure(error.into()))?,
        );
        // PreservedPages returns only after actual write, sync_data and digest
        // verification. Keep that returned lease before inspecting supervision.
        Ok(())
    }

    fn check_settled(&self) -> Result<(), RamError> {
        if let Some(error) = self.first_failure.as_ref() {
            return Err(error.clone());
        }
        self.protection.check_complete()?;
        self.preservation.check_complete()?;
        self.discard.check_complete()?;
        if !self.published || !self.residency_returned {
            return Err(RamError::Invariant(
                "eviction publication remains unsettled",
            ));
        }
        if self.writeback.is_some() {
            self.writeback_post.check_complete()?;
            self.writeback_completion.check_complete()?;
        }
        Ok(())
    }
}

impl FaultWork {
    /// Runs one serialized transaction at an already authenticated paused cut.
    ///
    /// The borrowed placement owns actual native exclusion and full entitlement;
    /// its numeric token is validated by that existing owner, never an issuer.
    ///
    /// # Errors
    /// Retains scratch, Original, leases and every attempted effect on refusal.
    pub(in crate::paged_ram::engine) fn evict_at_boundary(
        &mut self,
        placement: &PhysicalPlacement<'_>,
        arena: &Arena,
        page: usize,
        coordinate: usize,
        selected: PageState,
    ) -> Result<(), RamError> {
        if self.unresolved() {
            return Err(RamError::Invariant("eviction fault work remains unsettled"));
        }
        let status = (placement.service.native.validate)(placement.token, placement.generation);
        if status != 0 {
            return Err(RamError::Native {
                operation: "eviction physical owner",
                status,
            });
        }
        if arena.placement != ArenaPlacement::Pageable
            || page as u64 >= arena.native.mapping_length / PAGE_BYTES as u64
            || arena.page_start.checked_add(page) != Some(coordinate)
            || !placement
                .service
                .arenas
                .iter()
                .any(|owned| std::ptr::eq(owned, arena))
        {
            return Err(RamError::Invariant("eviction mapping owner changed"));
        }
        let address = arena.native.host_address + page as u64 * PAGE_BYTES as u64;
        self.eviction = Some(EvictionJournal::new(coordinate, address, selected));
        let journal = self.eviction.as_mut().ok_or("eviction journal absent")?;
        let result = journal
            .run(placement, &mut self.scratch)
            .and_then(|()| journal.check_settled());
        if let Err(error) = result {
            if journal.first_failure.is_none() {
                journal.first_failure = Some(error.clone());
            }
            self.fail();
            return Err(error);
        }
        self.eviction.take();
        self.scratch.fill(0);
        Ok(())
    }
}

/// Removes a single physical page without interpreting metadata or counters.
///
/// # Safety
/// The caller owns the complete mapping and excludes every accessor that could
/// lose bytes or physical backing. Uncertain outcomes retain that same owner.
unsafe fn discard_page(address: u64) -> io::Result<()> {
    // SAFETY: the caller supplies the complete retained mapping exclusion.
    if unsafe { libc::madvise(address as *mut c_void, PAGE_BYTES, libc::MADV_DONTNEED) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
