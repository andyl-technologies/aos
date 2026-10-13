//! Holds the installed service and its actual mutation gate for ordinary capture.
//!
//! The registered native loan authenticates entry. Its same paid outer operation
//! owns the holder through rearm, independent post, dirty retirement and physical
//! return. Read exchanges borrow existing source/spill and never populate RAM.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Retains the real service allocation and distinct ordinary pause/vector gate.
pub(in crate::paged_ram) struct OrdinaryPagingCustody {
    owner: Arc<PausedPagingOwner>,
    service: Option<Arc<FaultService>>,
    identity: u64,
    pause_requested: bool,
    pages_held: bool,
}

impl OrdinaryPagingCustody {
    /// Retains existing allocations before fallible pause admission.
    ///
    /// # Errors
    /// Refuses a missing/replaced live service or a zero actual holder identity.
    pub(in crate::paged_ram) fn retain(
        owner: Arc<PausedPagingOwner>,
        identity: u64,
        _native: &crate::runtime::FingerprintBorrowContext,
    ) -> Result<Self, RamError> {
        if identity == 0 {
            return Err(RamError::Invariant("ordinary capture holder is absent"));
        }
        let service = owner
            .active
            .try_lock()
            .map_err(|_| RamError::Invariant("ordinary capture service busy"))?
            .clone();
        let custody = Self {
            owner,
            service,
            identity,
            pause_requested: false,
            pages_held: false,
        };
        custody.check_allocation()?;
        Ok(custody)
    }

    fn check_allocation(&self) -> Result<(), RamError> {
        let active = self
            .owner
            .active
            .try_lock()
            .map_err(|_| RamError::Invariant("ordinary capture allocation busy"))?;
        match (active.as_ref(), self.service.as_ref()) {
            (Some(active), Some(service))
                if Arc::ptr_eq(active, service)
                    && Arc::ptr_eq(&self.owner.operations, &service.operations) => {}
            (None, None) => {}
            _ => return Err(RamError::Invariant("ordinary capture allocation changed")),
        }
        Ok(())
    }

    /// Closes fault admission and waits only under the already-entered Original.
    ///
    /// # Errors
    /// Retains a requested pause or page gate on any source/Original refusal.
    pub(in crate::paged_ram) fn settle(
        &mut self,
        operation: &dyn SourceOperation,
    ) -> Result<(), RamError> {
        self.check_allocation()?;
        // No installed fault service means there is no worker/vector to pause.
        // The genuine native callback retains its stopped writer boundary and
        // the actual admitted owner; this branch creates no UFFD or actor.
        let Some(service) = self.service.as_ref() else {
            return Ok(());
        };
        if !self.pause_requested {
            service.capture_work.request_ordinary_pause(self.identity)?;
            self.pause_requested = true;
        }
        while !service
            .capture_work
            .ordinary_pause_acknowledged(self.identity)
        {
            let slice = operation
                .wait_slice_for_observation()
                .map_err(super::super::source::SourceFetchError::from)
                .map_err(|error| self.retain_source_error(error))?;
            if service.failed.load(Ordering::Acquire) || service.stop.load(Ordering::Acquire) {
                return Err(RamError::Invariant("ordinary capture fault actor failed"));
            }
            std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));
        }
        let mut states = service
            .states
            .try_lock()
            .map_err(|_| RamError::Invariant("ordinary capture page vector busy"))?;
        states.hold_ordinary(self.identity)?;
        self.pages_held = true;
        Ok(())
    }

    /// Rearms only the same held vector while its worker remains acknowledged.
    ///
    /// # Errors
    /// Refuses changed topology/allocation/Original and preserves partial effects.
    pub(in crate::paged_ram) fn rearm(
        &self,
        topology: u64,
        operation: &dyn SourceOperation,
    ) -> Result<(), RamError> {
        self.check_allocation()?;
        let Some(service) = self.service.as_ref() else {
            if self.pause_requested || self.pages_held {
                return Err(RamError::Invariant(
                    "resident capture has spurious paging custody",
                ));
            }
            return Ok(());
        };
        if !self.pages_held
            || !service
                .capture_work
                .ordinary_pause_acknowledged(self.identity)
        {
            return Err(RamError::Invariant("ordinary capture exclusion is absent"));
        }
        if !service.destructive.load(Ordering::Acquire) {
            return Ok(());
        }
        if !service.activated.load(Ordering::Acquire) || service.failed.load(Ordering::Acquire) {
            return Err(RamError::Invariant(
                "ordinary capture source is unavailable",
            ));
        }
        let preparation = self
            .owner
            .write_preparation
            .try_lock()
            .map_err(|_| RamError::Invariant("ordinary capture write preparation busy"))?;
        if preparation.is_some() {
            return Err(RamError::Invariant(
                "ordinary capture intersects prepared writes",
            ));
        }
        let mut states = service
            .states
            .try_lock()
            .map_err(|_| RamError::Invariant("ordinary capture page vector busy"))?;
        states.check_ordinary(self.identity)?;
        for arena in &service.arenas {
            if arena.native.topology_generation != topology {
                return Err(RamError::Invariant("ordinary capture topology changed"));
            }
            if arena.placement != ArenaPlacement::Pageable {
                continue;
            }
            let pages = usize::try_from(arena.native.mapping_length / PAGE_BYTES as u64)
                .map_err(|_| "ordinary capture page extent overflow")?;
            for page in 0..pages {
                operation
                    .wait_slice_for_observation()
                    .map_err(super::super::source::SourceFetchError::from)
                    .map_err(|error| self.retain_source_error(error))?;
                let state = states
                    .get_mut_ordinary(self.identity, arena.page_start + page)
                    .ok_or("ordinary capture page ownership changed")?;
                if state.resident && state.writable {
                    service.registration.protect(
                        arena.native.host_address + page as u64 * PAGE_BYTES as u64,
                        PAGE_BYTES as u64,
                        true,
                    )?;
                    state.writable = false;
                }
            }
        }
        Ok(())
    }

    /// Returns physical exclusion without checking or renewing semantic time.
    ///
    /// # Errors
    /// Retains exact live custody if page or worker admission cannot be returned.
    pub(in crate::paged_ram) fn return_identity(&mut self) -> Result<(), RamError> {
        self.check_allocation()?;
        let Some(service) = self.service.as_ref() else {
            if self.pause_requested || self.pages_held {
                return Err(RamError::Invariant("resident return has paging custody"));
            }
            return Ok(());
        };
        if self.pages_held {
            service
                .states
                .try_lock()
                .map_err(|_| RamError::Invariant("ordinary capture page return busy"))?
                .release_ordinary(self.identity)?;
            self.pages_held = false;
        }
        if self.pause_requested {
            service.capture_work.return_ordinary_pause(self.identity)?;
            self.pause_requested = false;
        }
        Ok(())
    }

    fn retain_source_error(&self, error: super::super::source::SourceFetchError) -> RamError {
        let mut original = None;
        let cause = service::source_read_failure(error, Some(&mut original));
        if let Some(original) = original {
            self.owner.retain_operational_source_failure(
                SourceOperationClass::FingerprintUpdate,
                original,
            );
        } else {
            self.owner
                .retain_operational_failure_owned(SourceOperationClass::FingerprintUpdate, cause);
        }
        RamError::Invariant("ordinary capture original failure retained")
    }
}
