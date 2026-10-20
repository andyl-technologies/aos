//! Borrows actual initialized Cache writer geometry and compares retained replay.
//!
//! This private DATA seam shares the existing staged readonly/native engine.
//! It creates no writer, grant, original-owner identity or reusable permit.

use super::{Journal, JournalError, JournalLimits, ReadOnlyProtectedJournal,
    ProtectedJournalPreopenReplayExtentV1, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheJournalDataV1;

/// Holds comparison DATA captured under the actual initialized Cache borrow.
pub(crate) struct CacheHeldWriterShapeV1 {
    original: usize,
    identities: [super::FileIdentity; 3],
    pub(crate) coordinates: CacheJournalDataV1,
    pub(crate) extent: ProtectedJournalPreopenReplayExtentV1,
    pub(crate) uid: u32,
}

impl CacheHeldWriterShapeV1 {
    /// Borrows the exact compiled/native limits used by the captured writer.
    pub(crate) fn limits(&self) -> JournalLimits { self.extent.limits }

    /// Compares the same held materialization without performing fresh IO.
    ///
    /// The closed Cache producer separately retains complete name/metadata
    /// bookends around every use; this helper cannot replace those checks.
    ///
    /// # Errors
    /// Refuses a different writer, health, UID, limits or native NEXT.
    pub(crate) fn require(&self, journal: &Journal) -> Result<(), JournalError> {
        journal.ensure_healthy()?;
        if self.original != journal as *const Journal as usize
            || journal.snapshot_sequence() != self.coordinates.next
            || journal.configured_limits() != self.extent.limits
            || journal.protected_owner_uid()? != self.uid
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Compares the full witness already held by the same actual clock guard.
    pub(crate) fn require_witness(&self, witness: &super::ProtectedWriterNameWitness) -> Result<(), JournalError> {
        if self.identities != [witness.directory(), witness.file(), witness.lock()] {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Compares a complete independently retained fresh position check.
    pub(crate) fn require_observed(
        &self,
        journal: &Journal,
        observed: &super::CreateStorageWriterPositionOriginalV1,
    ) -> Result<(), JournalError> {
        self.require(journal)?;
        let position = observed.position()?;
        let witness = observed.witness()?;
        if position.names != self.coordinates.names || position.next != self.coordinates.next
            || position.end != self.coordinates.end
            || self.identities != [witness.directory(), witness.file(), witness.lock()]
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

}

impl Journal {
    /// Compares only the closed configured recipe between retained bookends.
    pub(crate) fn require_cache_held_config_v1(
        &self,
        role: crate::cache_residency::InitializerJournal,
        uid: u32,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        let (_, name, limits) = role.recipe();
        let location = self.native.protected_view().ok_or(JournalError::ProtectedBoundary)?;
        if location.name() != name || location.expected_uid() != uid || self.configured_limits() != limits {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Captures fixed current geometry after the same J has paid metadata entry.
    ///
    /// # Errors
    /// Refuses unhealthy/unprotected writers or checked representation overflow.
    pub(crate) fn capture_cache_held_shape_v1(
        &self,
        original: &mut super::CreateStorageWriterPositionOriginalV1,
        role: crate::cache_residency::InitializerJournal,
        uid: u32,
    ) -> Result<CacheHeldWriterShapeV1, JournalError> {
        original.capture_cache_once(self, role, uid);
        self.cache_held_shape_from_observed_v1(original)
    }

    fn cache_held_shape_from_observed_v1(
        &self,
        original: &super::CreateStorageWriterPositionOriginalV1,
    ) -> Result<CacheHeldWriterShapeV1, JournalError> {
        self.ensure_healthy()?;
        let position = original.position()?;
        let witness = original.witness()?;
        let extent = super::protected_journal_preopen_replay_extent_for_prefix_v1(
            self.configured_limits(), position.end,
        )?;
        Ok(CacheHeldWriterShapeV1 {
            original: self as *const Journal as usize,
            coordinates: CacheJournalDataV1 {
                names: position.names, next: position.next, end: position.end,
            },
            extent, uid: self.protected_owner_uid()?,
            identities: [witness.directory(), witness.file(), witness.lock()],
        })
    }

    /// Compares the sole retained readonly replay to this actual held writer.
    ///
    /// Names and whole native materialization must match, including foreign
    /// namespaces, idempotency, transaction identities and every native count.
    /// No hash-only map shortcut or decoded live-authority constructor occurs.
    ///
    /// # Errors
    /// Rejects changed original names, a different complete native image or a
    /// readonly result belonging to another protected directory/writer/lock.
    pub(crate) fn require_cache_held_readback_v1(
        &self,
        expected: &CacheHeldWriterShapeV1,
        readback: &mut ReadOnlyProtectedJournal,
    ) -> Result<(), JournalError> {
        expected.require(self)?;
        readback.check_named_currentness()?;
        if readback.physical_names_v1() != expected.coordinates.names {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let replay = readback.journal_mut();
        replay.ensure_healthy()?;
        if replay.snapshot_sequence() != self.snapshot_sequence()
            || replay.configured_limits() != self.configured_limits()
            || replay.native.materialized_bytes() != self.native.materialized_bytes()
            || replay.native.state() != self.native.state()
            || *replay.native.idempotency() != *self.native.idempotency()
            || replay.native.transaction_ids() != self.native.transaction_ids()
            || replay.native.committed_namespaces() != self.native.committed_namespaces()
            || replay.native.committed_transactions() != self.native.committed_transactions()
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        expected.require(self)?;
        readback.check_named_currentness()
    }

    /// Prices the actual current/proposed rows before the closed append engine.
    ///
    /// # Errors
    /// Retains the shared reached semantic geometry refusal. This passive
    /// calculation performs no IO and admits no allocation or native append.
    pub(crate) fn cache_held_append_semantic_demand_v1(
        &self,
        transaction: &super::JournalTransaction,
    ) -> Result<aos_sandbox_model::ResourceVector, JournalError> {
        super::source_readonly_semantic_demand_v1(self.native.state(), Some(transaction))
    }

    /// Denies ordinary Cache gates after any new continuation history appears.
    ///
    /// A malformed or foreign row also denies. Cold bytes never authorize
    /// release, renewal or a replacement owner. Future exact release handling
    /// must enter through its own actual closed Native original.
    pub(crate) fn require_no_cache_held_history_v1(&self) -> Result<(), JournalError> {
        if self.records(RecordNamespace::CreateStorageHistory).next().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

impl super::ReadOnlyJournalOpenOriginalsV1 {
    // Compact success DATA is available only after the original Native reader
    // itself is wholly positive. The actual Cache owner still owes its own
    // independent names/clock/physical/suffix posts and concrete disposal.
    pub(crate) fn cache_held_attempted_v1(&self) -> bool { self.attempted }

    pub(crate) fn cache_held_report_data_v1(&self) -> Option<super::RecoveryReport> {
        if self.failure().is_some() { return None; }
        self.returned.as_ref()?.as_ref().ok().copied()
    }
}

#[cfg(test)]
mod tests;
