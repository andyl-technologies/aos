//! Retains the actual paging service before a checkpoint requests worker pause.
//!
//! The service owns its complete source, spill, registration and page vector.
//! Keeping this allocation alive does not issue a native fence or a cold-reader
//! loan. Those proofs remain separate from the worker's acknowledged pause.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;

/// Keeps the same installed service through pending and refused capture cuts.
pub(in crate::paged_ram) struct RetainedCheckpointService {
    owner: Arc<PausedPagingOwner>,
    service: Arc<FaultService>,
    requested_epoch: Option<u64>,
    page_fence: Option<page_versions::NativePageFence>,
    pause_released: bool,
}

impl RetainedCheckpointService {
    /// Retains the actual installed service without creating a new allocation.
    ///
    /// # Errors
    /// Refuses busy, missing, replaced, failed or stopped service ownership.
    pub(in crate::paged_ram) fn retain(owner: Arc<PausedPagingOwner>) -> Result<Self, RamError> {
        let service = owner
            .active
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint service ownership busy"))?
            .as_ref()
            .cloned()
            .ok_or(RamError::Invariant("checkpoint fault service absent"))?;
        let retained = Self {
            owner,
            service,
            requested_epoch: None,
            page_fence: None,
            pause_released: false,
        };
        retained.check_service()?;
        Ok(retained)
    }

    /// Rechecks the same installed allocation without constructing a page fence.
    ///
    /// # Errors
    /// Refuses changed service, failed operational state or stopped ownership.
    pub(in crate::paged_ram) fn check_retained(&self) -> Result<(), RamError> {
        self.check_service()
    }

    /// Borrows the actual fenced allocations for an independently issued reader.
    ///
    /// # Errors
    /// Refuses an unmatched transaction, unacknowledged worker, replaced service
    /// or absent page hold. This clone starts no operation or native read loan.
    pub(in crate::paged_ram) fn retain_read(
        &self,
        transaction: u64,
    ) -> Result<super::HeldCheckpointRead, RamError> {
        if !self.pause_acknowledged(transaction)? || self.pause_released {
            return Err(RamError::Invariant("checkpoint held reader pause changed"));
        }
        let fence = self.page_fence.as_ref().ok_or(RamError::Invariant(
            "checkpoint held reader page fence absent",
        ))?;
        self.service
            .states
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint held reader vector busy"))?
            .check(fence)?;
        Ok(super::HeldCheckpointRead::retain(
            self.owner.clone(),
            self.service.clone(),
            fence.clone(),
            transaction,
        ))
    }

    fn check_service(&self) -> Result<(), RamError> {
        let active = self
            .owner
            .active
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint service ownership busy"))?;
        if !active
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.service))
            || self.owner.failed.load(Ordering::Acquire)
            || self.service.failed.load(Ordering::Acquire)
            || self.service.stop.load(Ordering::Acquire)
            || !Arc::ptr_eq(&self.owner.operations, &self.service.operations)
        {
            return Err(RamError::Invariant("checkpoint retained service changed"));
        }
        Ok(())
    }

    /// Requests one pause while retaining its epoch before the fallible cut.
    ///
    /// # Errors
    /// Refuses another epoch, changed service or the actual worker pause refusal.
    pub(in crate::paged_ram) fn request_pause(&mut self, epoch: u64) -> Result<(), RamError> {
        self.check_service()?;
        if let Some(requested) = self.requested_epoch {
            if requested != epoch {
                return Err(RamError::Invariant("checkpoint pause epoch changed"));
            }
        } else {
            self.requested_epoch = Some(epoch);
        }
        self.service.capture_work.request_pause(epoch)
    }

    /// Holds the actual existing page vector after worker ACK and native checking.
    ///
    /// # Errors
    /// Refuses an unacknowledged worker, changed source or active native proof.
    pub(in crate::paged_ram) fn hold_pages(
        &mut self,
        root: &crate::runtime::NativeRoot,
    ) -> Result<(), RamError> {
        if !self.pause_acknowledged(root.transaction())? {
            return Err(RamError::Invariant("checkpoint fault pause still pending"));
        }
        let source_address = self
            .service
            .source
            .as_ref()
            .map_or(Arc::as_ptr(&self.service.spill) as usize, |source| {
                Arc::as_ptr(source) as usize
            });
        let page_address = std::ptr::from_ref(&self.service.states) as usize;
        let source_owner = u64::try_from(source_address)
            .map_err(|_| RamError::Invariant("checkpoint source owner width overflow"))?;
        let page_owner = u64::try_from(page_address)
            .map_err(|_| RamError::Invariant("checkpoint page owner width overflow"))?;
        if self.page_fence.is_none() {
            let fence =
                page_versions::NativePageFence::from_active_root(root, source_owner, page_owner)?;
            self.page_fence = Some(fence);
        }
        let fence = self
            .page_fence
            .as_ref()
            .ok_or(RamError::Invariant("checkpoint retained page fence absent"))?;
        let mut states = self
            .service
            .states
            .try_lock()
            .map_err(|_| RamError::Invariant("checkpoint page vector busy"))?;
        states.hold(fence)?;
        states.check(fence)
    }

    /// Disposes real page/fault holds during the same native local observer cut.
    ///
    /// # Errors
    /// Refuses another original, unmatched page ownership or an unresolved worker.
    /// Each successful local action is recorded before the next fallible action.
    pub(in crate::paged_ram) fn dispose_local(
        &mut self,
        disposition: &crate::runtime::LocalDisposition<'_>,
    ) -> Result<(), RamError> {
        let epoch = self
            .requested_epoch
            .filter(|epoch| *epoch == disposition.transaction())
            .ok_or(RamError::Invariant("checkpoint local pause epoch changed"))?;
        if let Some(fence) = self.page_fence.as_ref() {
            let disposed = fence.disposed(disposition)?;
            self.service
                .states
                .try_lock()
                .map_err(|_| RamError::Invariant("checkpoint page vector busy"))?
                .release(&disposed)?;
            self.page_fence.take();
        }
        // Keep the acknowledged worker paused through native physical cleanup.
        // Releasing here could admit another UFFD read before State reopens.
        if !self.pause_released && !self.service.capture_work.pause_acknowledged(epoch) {
            return Err(RamError::Invariant(
                "checkpoint fault pause disposition changed",
            ));
        }
        Ok(())
    }

    /// Reopens the same worker only after actual native retirement acknowledgment.
    ///
    /// # Errors
    /// Refuses an unmatched epoch or a changed actual pause. A failed final tail
    /// keeps policy/queue admission closed without reading the retired root again.
    pub(in crate::paged_ram) fn release_worker_after_retirement(
        &mut self,
        root: &crate::runtime::NativeRoot,
    ) -> Result<(), RamError> {
        if !root.is_acknowledged() || self.requested_epoch != Some(root.transaction()) {
            return Err(RamError::Invariant(
                "checkpoint final fault disposition unavailable",
            ));
        }
        if !self.pause_released {
            self.service
                .capture_work
                .release_pause(root.transaction())?;
            self.pause_released = true;
        }
        Ok(())
    }

    /// Observes the same worker's settled boundary without consuming its claim.
    ///
    /// # Errors
    /// Refuses a replaced service or an epoch that this owner never requested.
    pub(in crate::paged_ram) fn pause_acknowledged(&self, epoch: u64) -> Result<bool, RamError> {
        self.check_service()?;
        if self.requested_epoch != Some(epoch) {
            return Err(RamError::Invariant("checkpoint pause was not requested"));
        }
        Ok(self.service.capture_work.pause_acknowledged(epoch))
    }
}
