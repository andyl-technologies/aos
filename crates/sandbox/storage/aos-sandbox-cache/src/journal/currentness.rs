//! Retains Cache's actual named-writer and rooted-directory observations.
//!
//! The common read view runs the existing native operations into the same
//! prepaid destination. Cache keeps its concrete protected name, UID, limits
//! and health comparisons; no successful DATA creates a new writer or loan.

use std::path::Path;

use aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1;

use super::{Journal, JournalError, JournalLimits};

pub(crate) type CacheWriterCurrentnessOriginalV1 = WriterCurrentnessOriginalsV1<JournalError>;

impl Journal {
    pub(crate) fn require_names_with_originals_v1(
        &self,
        originals: &mut CacheWriterCurrentnessOriginalV1,
    ) -> Result<(), JournalError> {
        self.read_view().observe_names_into(originals)
    }

    pub(crate) fn require_location_with_originals_v1(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        limits: JournalLimits,
        originals: &mut CacheWriterCurrentnessOriginalV1,
    ) -> Result<(), JournalError> {
        let view = self.read_view();
        if view.protected_name() != Some(name)
            || view.protected_uid() != Some(uid)
            || view.limits() != limits
        {
            return Err(JournalError::boundary());
        }

        view.observe_directory_binding_into(directory, uid, originals)?;
        self.ensure_healthy()
    }

    // The order matches the old captured Cache constructor: names first,
    // independent rooted directory next, then the health bookend. A failed
    // original remains resident and is selected before its coarse marker.
    pub(crate) fn observe_opening_names_once_v1(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        limits: JournalLimits,
        originals: &mut CacheWriterCurrentnessOriginalV1,
    ) -> Result<(), JournalError> {
        originals.begin(true)?;
        let returned = (|| {
            self.require_names_with_originals_v1(originals)?;
            self.require_location_with_originals_v1(directory, name, uid, limits, originals)
        })();
        originals.finish(returned)
    }
}

impl Journal {
    pub(crate) fn require_protected_names_current(&self) -> Result<(), JournalError> {
        self.read_view().require_names()
    }

    pub(crate) fn protected_writer_name_witness(
        &self,
    ) -> Result<aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness, JournalError>
    {
        self.read_view().writer_witness()
    }

    pub(crate) fn validate_protected_writer_name_witness(
        &self,
        witness: &aos_sandbox_journal::protected_storage::ProtectedWriterNameWitness,
    ) -> Result<(), JournalError> {
        self.require_protected_names_current()?;
        self.read_view().require_writer_witness(witness)
    }

    pub(crate) fn protected_writer_physical_names_v1(
        &self,
    ) -> Result<
        aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
        JournalError,
    > {
        self.require_protected_names_current()?;
        let witness = self.protected_writer_name_witness()?;
        let directory = witness.directory();
        let journal = witness.file();
        let lock = witness.lock();
        Ok(aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1::
            from_historical_fields(
                directory.physical_pair(), journal.physical_pair(), lock.physical_pair(),
            ))
    }

    // This is the existing private state/authority interlock association. It
    // does not create a hold, Root loan or effect permission. Every use still
    // compares the actual held directory and both native file witnesses.
    pub(crate) fn enable_cache_policy_hold_gate(
        &mut self,
        directory: &Path,
        uid: u32,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let view = self.read_view();
        if view.protected_uid() != Some(uid)
            || !matches!(
                view.protected_name(),
                Some("state.journal" | "authority.journal")
            )
        {
            return Err(JournalError::boundary());
        }
        self.cache_policy_gate = Some((directory.to_owned(), uid));
        Ok(())
    }
}

impl Journal {
    // A caller-supplied pathname is comparison DATA. The same captured append
    // owner keeps its native traversal when that old interval is active.
    pub(crate) fn require_protected_location(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let view = self.read_view();
        let retained = view.protected_view().ok_or(JournalError::boundary())?;
        if retained.name() != name || retained.expected_uid() != uid || view.limits() != limits {
            return Err(JournalError::boundary());
        }

        // Keep the independent directory through the original health bookend.
        let _current = retained.require_directory::<JournalError>(directory, uid)?;
        self.ensure_healthy()
    }

    pub(crate) fn require_protected_named_location(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        self.require_protected_location(directory, name, uid, limits)?;
        self.require_protected_names_current()
    }

    #[cfg(any(test, all(feature = "test-fixtures", debug_assertions)))]
    pub(crate) fn require_protected_named_location_at_uid_for_test(
        &self,
        directory: &Path,
        name: &str,
        uid: u32,
        limits: JournalLimits,
    ) -> Result<(), JournalError> {
        let view = self.read_view();
        let retained = view.protected_view().ok_or(JournalError::boundary())?;
        if retained.name() != name || retained.expected_uid() != uid || view.limits() != limits {
            return Err(JournalError::boundary());
        }

        // The existing fixture path still uses its explicit actual UID.
        let _current =
            retained.require_directory_at_uid_for_test::<JournalError>(directory, uid)?;
        self.require_protected_names_current()
    }

    pub(crate) fn protected_owner_uid(&self) -> Result<u32, JournalError> {
        self.read_view()
            .protected_uid()
            .ok_or(JournalError::boundary())
    }
}
