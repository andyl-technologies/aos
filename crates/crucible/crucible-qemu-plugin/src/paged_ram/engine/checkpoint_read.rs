//! Reads only the same held page vector and its retained source/spill allocations.
//!
//! A genuine native CandidateReadLoan authenticates entry outside this module.
//! This keeper clones existing allocations and their already-issued fence;
//! transaction coordinates cannot construct it or open ordinary page mutation.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Keeps the actual source, spill and complete vector through a native read call.
pub(crate) struct HeldCheckpointRead {
    owner: Arc<PausedPagingOwner>,
    service: Arc<FaultService>,
    fence: page_versions::NativePageFence,
    transaction: u64,
}

impl HeldCheckpointRead {
    pub(super) fn retain(
        owner: Arc<PausedPagingOwner>,
        service: Arc<FaultService>,
        fence: page_versions::NativePageFence,
        transaction: u64,
    ) -> Self {
        Self {
            owner,
            service,
            fence,
            transaction,
        }
    }

    /// Moves the same authentic source refusal before returning native failure.
    ///
    /// Returns the retained-failure marker after moving the original typed cause
    /// into this actual owner's preallocated failure slot; no Arc is created.
    pub(in crate::paged_ram) fn retain_source_error(
        &self,
        error: super::super::source::SourceFetchError,
    ) -> RamError {
        let mut failure = None;
        let cause = service::source_read_failure(error, Some(&mut failure));
        if let Some(failure) = failure {
            self.owner.retain_operational_source_failure(
                SourceOperationClass::FingerprintUpdate,
                failure,
            );
        } else {
            self.owner
                .retain_operational_failure_owned(SourceOperationClass::FingerprintUpdate, cause);
        }
        RamError::Invariant("held reader original source failure retained")
    }

    fn check(&self) -> Result<(), RamError> {
        let active = self
            .owner
            .active
            .try_lock()
            .map_err(|_| RamError::Invariant("held reader service busy"))?;
        if !active
            .as_ref()
            .is_some_and(|service| Arc::ptr_eq(service, &self.service))
            || self.owner.failed.load(Ordering::Acquire)
            || self.service.failed.load(Ordering::Acquire)
            || self.service.stop.load(Ordering::Acquire)
            || !Arc::ptr_eq(&self.owner.operations, &self.service.operations)
            || !self
                .service
                .capture_work
                .pause_acknowledged(self.transaction)
        {
            return Err(RamError::Invariant("held reader service or pause changed"));
        }
        drop(active);
        self.service
            .states
            .try_lock()
            .map_err(|_| RamError::Invariant("held reader page vector busy"))?
            .check(&self.fence)
    }

    /// Reads into the native reader's existing private page scratch.
    ///
    /// # Errors
    /// Refuses changed allocations/fences, coordinates, source authentication or
    /// the caller's same-original supervision. No operation factory is entered,
    /// guest page is populated, or writer is rearmed during this immutable read.
    pub(crate) fn read_page(
        &self,
        address: u64,
        valid: usize,
        operation: &dyn SourceOperation,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<(), RamError> {
        self.check()?;
        operation
            .wait_slice_for_observation()
            .map_err(super::super::source::SourceFetchError::from)
            .map_err(|error| self.retain_source_error(error))?;
        let arena = self
            .service
            .arenas
            .iter()
            .find(|arena| {
                address >= arena.native.host_address
                    && address - arena.native.host_address < arena.native.logical_length
            })
            .ok_or(RamError::Invariant(
                "held reader page is outside retained inventory",
            ))?;
        let offset = address - arena.native.host_address;
        let expected = (arena.native.logical_length - offset).min(PAGE_BYTES as u64);
        if !offset.is_multiple_of(PAGE_BYTES as u64) || valid == 0 || valid as u64 != expected {
            return Err(RamError::Invariant("held reader page geometry changed"));
        }
        let page = offset / PAGE_BYTES as u64;
        let coordinate = arena
            .page_start
            .checked_add(usize::try_from(page).map_err(|_| "held reader coordinate overflow")?)
            .ok_or(RamError::Invariant("held reader coordinate overflow"))?;
        let (resident, preserved) = {
            let states = self
                .service
                .states
                .try_lock()
                .map_err(|_| RamError::Invariant("held reader vector unavailable"))?;
            states.check(&self.fence)?;
            let state = states
                .get(coordinate)
                .ok_or(RamError::Invariant("held reader page coordinate absent"))?;
            (state.resident, state.preserved.clone())
        };

        if !resident && self.service.destructive.load(Ordering::Acquire) {
            if !self.service.activated.load(Ordering::Acquire) {
                return Err(RamError::Invariant(
                    "held reader cold source is unpublished",
                ));
            }
            let preserved_read = preserved.is_some();
            let read = if let Some(record) = preserved {
                let spill = self
                    .service
                    .spill
                    .try_lock()
                    .map_err(|_| RamError::Invariant("held reader spill busy"))?;
                let result = spill.read_with_borrowed_hasher(&record, scratch, None);
                drop(spill);
                result
                    .and_then(|()| operation.complete_observation().map_err(Into::into))
                    .map(|()| record.valid_length())
            } else {
                self.service
                    .source
                    .as_ref()
                    .ok_or(RamError::Invariant(
                        "held reader authenticated source absent",
                    ))?
                    .fetch_with_retained_operation(
                        arena.native.region_index,
                        page,
                        operation,
                        scratch,
                        None,
                    )
                    .map(|(length, _)| length)
            };
            match read {
                Ok(length) if length as usize == valid => {
                    if preserved_read {
                        count_completed(&self.service.counters.preserved_reads)?;
                    }
                }
                Ok(_) => return Err(RamError::Invariant("held reader source length changed")),
                Err(error) => return Err(self.retain_source_error(error)),
            }
        } else {
            scratch.fill(0);
            // SAFETY: native's genuine Main/Stopped reader retains the exact RAM
            // inventory and physical collector. The same real held vector proves
            // this page resident; cold pages above never dereference guest RAM.
            unsafe {
                std::ptr::copy_nonoverlapping(address as *const u8, scratch.as_mut_ptr(), valid);
            }
            operation
                .complete_observation()
                .map_err(super::super::source::SourceFetchError::from)
                .map_err(|error| self.retain_source_error(error))?;
        }
        self.check()
    }
}
