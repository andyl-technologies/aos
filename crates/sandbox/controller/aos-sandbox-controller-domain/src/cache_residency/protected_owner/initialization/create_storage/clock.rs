//! Shares clock custody while selected name checks retain their own originals.
//!
//! Every selected caller holds the actual Cache writers and surrounds use with
//! the complete retained fixed-root/name/witness engine. These helpers perform
//! only the same held-clock identity/time checks between those bookends; the
//! ordinary clock methods and their original native check schedule are unchanged.

use super::*;

impl ProtectedCacheClockV1 {
    pub(super) fn hold_writer_for_create_storage_readback(
        &self,
        original: &mut crate::journal::CreateStorageWriterPositionOriginalV1,
    ) -> Result<CacheClockWriterReadbackGuard<'_>, CacheResidencyProtectedJournalErrorV1> {
        let mut state = self.state.lock().map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if state.readback_held || self.root != Path::new(PROTECTED_CACHE_ROOT) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        let journal = state.journal.as_ref().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?;
        original.capture_cache_once(journal, InitializerJournal::Clock, self.owner_uid);
        let witness = original.take_witness_once()?;
        state.readback_held = true;
        Ok(CacheClockWriterReadbackGuard { clock: self, witness })
    }
}

impl CacheClockWriterReadbackGuard<'_> {
    pub(in crate::cache_residency) fn require_create_storage_shape_v1(
        &self,
        shape: &CacheHeldWriterShapeV1,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.require_create_storage_hold_v1()?;
        shape.require_witness(&self.witness)?;
        Ok(())
    }

    pub(in crate::cache_residency) fn require_create_storage_hold_v1(
        &self,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        let state = self.clock.state.lock().map_err(|_| ProtectedDomainJournalErrorV1::StaleAuthority)?;
        if !state.readback_held || self.clock.root != Path::new(PROTECTED_CACHE_ROOT) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        state.journal.as_ref().ok_or(ProtectedDomainJournalErrorV1::StaleAuthority)?
            .require_cache_held_config_v1(InitializerJournal::Clock, self.clock.owner_uid)?;
        Ok(())
    }

    pub(in crate::cache_residency) fn require_create_storage_time_authority_v1(
        &self,
        authority: &Arc<dyn CacheResidencyCurrentTimeAuthorityV1>,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.require_create_storage_hold_v1()?;
        if !std::ptr::addr_eq(Arc::as_ptr(authority), self.clock as *const ProtectedCacheClockV1) {
            return Err(ProtectedDomainJournalErrorV1::StaleAuthority);
        }
        Ok(())
    }

    pub(in crate::cache_residency) fn require_create_storage_targets_v1(
        &self,
        state: &Journal,
        authority: &Journal,
    ) -> Result<(), CacheResidencyProtectedJournalErrorV1> {
        self.require_create_storage_hold_v1()?;
        state.require_cache_held_config_v1(InitializerJournal::State, self.clock.owner_uid)?;
        authority.require_cache_held_config_v1(InitializerJournal::Authority, self.clock.owner_uid)?;
        Ok(())
    }

    pub(in crate::cache_residency) fn create_storage_unix_seconds_v1(
        &self,
    ) -> Result<u64, CacheResidencyProtectedJournalErrorV1> {
        self.require_create_storage_hold_v1()?;
        // The actual guard keeps readback_held true. The existing clock owner
        // still checks owner scope, wall-clock monotonicity and its saved floor,
        // without persisting a new clock transaction during this held cut.
        let current = self.clock.current_unix_seconds()?;
        self.require_create_storage_hold_v1()?;
        Ok(current)
    }
}
