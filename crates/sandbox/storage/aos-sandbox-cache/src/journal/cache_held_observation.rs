//! Borrows actual initialized Cache writer geometry and compares retained replay.
//!
//! This private DATA seam shares the existing staged readonly/native engine.
//! It creates no writer, grant, original-owner identity or reusable permit.

use super::{Journal, JournalError, JournalLimits, ReadOnlyProtectedJournal,
    ProtectedJournalPreopenReplayExtentV1};
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
    pub(crate) fn limits(&self) -> JournalLimits { self.extent.limits() }

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
            || journal.limits() != self.extent.limits()
            || journal.protected_owner_uid()? != self.uid
        {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        Ok(())
    }

    /// Compares the full witness already held by the same actual clock guard.
    pub(crate) fn require_witness(&self, witness: &super::ProtectedWriterNameWitness) -> Result<(), JournalError> {
        if self.identities != [witness.directory(), witness.file(), witness.lock()] {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
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
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        Ok(())
    }

}

impl Journal {
    /// Compares only the closed configured recipe between retained bookends.
    pub(crate) fn require_cache_held_config_v1(
        &self,
        role: crate::InitializerJournal,
        uid: u32,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        let (_, name, limits) = role.recipe();
        let location = self.read_view().protected_view().ok_or(JournalError::boundary())?;
        if location.name() != name || location.expected_uid() != uid || self.limits() != limits {
            return Err(JournalError::boundary());
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
        role: crate::InitializerJournal,
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
            self.limits(), position.end,
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
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
        }
        let replay = readback.journal_mut();
        replay.ensure_healthy()?;
        if replay.snapshot_sequence() != self.snapshot_sequence()
            || replay.limits() != self.limits()
            || replay.read_view().materialized_bytes() != self.read_view().materialized_bytes()
            || replay.read_view().state() != self.read_view().state()
            || *replay.read_view().idempotency_index() != *self.read_view().idempotency_index()
            || replay.read_view().transaction_ids() != self.read_view().transaction_ids()
            || replay.read_view().committed_namespaces() != self.read_view().committed_namespaces()
            || replay.read_view().committed_transactions() != self.read_view().committed_transactions()
        {
            return Err(JournalError::Mechanical(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::StaleAuthoritySnapshot));
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
        aos_sandbox_ledger_replay::geometry::reached::semantic_demand_v1(
            self.read_view().state(), Some(transaction),
        ).map_err(JournalError::from)
    }


}


#[cfg(test)]
mod tests;
