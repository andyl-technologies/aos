//! Holds the installed service and its actual mutation gate for ordinary capture.
//!
//! The registered native loan authenticates entry. Its same paid outer operation
//! owns the holder through rearm, independent post, dirty retirement and physical
//! return. Read exchanges borrow existing source/spill and never populate RAM.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Retains the real service allocation and distinct ordinary pause/vector gate.
pub(crate) struct OrdinaryPagingCustody {
    owner: Arc<PausedPagingOwner>,
    service: Option<Arc<FaultService>>,
    identity: u64,
    pause_requested: bool,
    pages_held: bool,
    original_class: Option<SourceOperationClass>,
}

impl OrdinaryPagingCustody {
    /// Retains existing allocations before fallible pause admission.
    ///
    /// # Errors
    /// Refuses a missing or replaced live service allocation.
    pub(crate) fn retain(
        owner: Arc<PausedPagingOwner>,
        _native: &crate::runtime::FingerprintBorrowContext,
    ) -> Result<Self, RamError> {
        let service = owner
            .active
            .try_lock()
            .map_err(|_| RamError::Invariant("ordinary capture service busy"))?
            .clone();
        let custody = Self {
            owner,
            service,
            identity: 0,
            pause_requested: false,
            pages_held: false,
            original_class: None,
        };
        custody.check_allocation()?;
        Ok(custody)
    }

    /// Retains the serial and producing class of the already-borrowed Original.
    ///
    /// # Errors
    /// Refuses zero serials, non-fingerprint classes or changed provenance.
    /// This records no deadline and enters no operation.
    pub(crate) fn bind_original(
        &mut self,
        serial: u64,
        class: SourceOperationClass,
    ) -> Result<(), RamError> {
        if serial == 0
            || (self.identity != 0 && self.identity != serial)
            || !matches!(
                class,
                SourceOperationClass::FingerprintInitialization
                    | SourceOperationClass::FingerprintUpdate
            )
            || self
                .original_class
                .is_some_and(|previous| previous != class)
        {
            return Err(RamError::Invariant(
                "ordinary capture Original identity changed",
            ));
        }
        // The native loan address can be reused between captures. Source's
        // operation serial distinguishes their pause requests and acknowledgments.
        self.identity = serial;
        self.original_class = Some(class);
        Ok(())
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
    pub(crate) fn settle(&mut self, operation: &dyn SourceOperation) -> Result<(), RamError> {
        self.check_allocation()?;
        if self.original_class.is_none() {
            return Err(RamError::Invariant(
                "ordinary capture Original class absent",
            ));
        }
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
    pub(crate) fn rearm(
        &self,
        topology: u64,
        operation: &dyn SourceOperation,
    ) -> Result<(), RamError> {
        self.check_allocation()?;
        if self.original_class.is_none() {
            return Err(RamError::Invariant(
                "ordinary capture Original class absent",
            ));
        }
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
        for arena in &service.arenas {
            if arena.native.topology_generation != topology {
                return Err(RamError::Invariant("ordinary capture topology changed"));
            }
            if arena.placement != ArenaPlacement::Pageable {
                continue;
            }
            let pages = usize::try_from(arena.native.mapping_length / PAGE_BYTES as u64)
                .map_err(|_| "ordinary capture page extent overflow")?;
            let mut page = 0;
            while page < pages {
                // Bound scans of already protected pages as well as effects.
                // A Source query never crosses either mutation guard.
                operation
                    .wait_slice_for_observation()
                    .map_err(super::super::source::SourceFetchError::from)
                    .map_err(|error| self.retain_source_error(error))?;
                self.check_allocation()?;
                let protected = {
                    let preparation = self.owner.write_preparation.try_lock().map_err(|_| {
                        RamError::Invariant("ordinary capture write preparation busy")
                    })?;
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
                    let scan_end = page.saturating_add(64).min(pages);
                    let mut start = None;
                    while page < scan_end {
                        let state = states
                            .get(arena.page_start + page)
                            .ok_or("ordinary capture page ownership changed")?;
                        if state.resident && state.writable {
                            start.get_or_insert(page);
                        } else if start.is_some() {
                            break;
                        }
                        page += 1;
                    }
                    if let Some(start) = start {
                        // Only a bounded contiguous resident writable run is
                        // covered; cold pages and gaps never enter the ioctl.
                        service.registration.protect(
                            arena.native.host_address + start as u64 * PAGE_BYTES as u64,
                            (page - start) as u64 * PAGE_BYTES as u64,
                            true,
                        )?;
                        for protected in start..page {
                            states
                                .get_mut_ordinary(self.identity, arena.page_start + protected)
                                .ok_or("ordinary capture page ownership changed")?
                                .writable = false;
                        }
                        true
                    } else {
                        false
                    }
                };
                if protected {
                    // The effect and metadata are retained before its genuine
                    // independent post; refusal does not undo their custody.
                    operation
                        .wait_slice_for_observation()
                        .map_err(super::super::source::SourceFetchError::from)
                        .map_err(|error| self.retain_source_error(error))?;
                }
            }
        }
        // An interleaving preparation refuses settlement after any partial
        // protection. The actual retained gate remains owned for physical end.
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
        service
            .states
            .try_lock()
            .map_err(|_| RamError::Invariant("ordinary capture page vector busy"))?
            .check_ordinary(self.identity)?;
        Ok(())
    }

    /// Returns physical exclusion without checking or renewing semantic time.
    ///
    /// # Errors
    /// Retains exact live custody if page or worker admission cannot be returned.
    pub(crate) fn return_identity(&mut self) -> Result<(), RamError> {
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
        // settle/rearm require the authentic class before they can query time.
        // A failed first class projection is retained by the FP owner instead.
        if let Some(class) = self.original_class {
            if let Some(original) = original {
                self.owner
                    .retain_operational_source_failure(class, original);
            } else {
                self.owner.retain_operational_failure_owned(class, cause);
            }
        }
        RamError::Invariant("ordinary capture original failure retained")
    }
}
