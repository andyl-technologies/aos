//! Keeps Cache's private readonly journal and actual native name witnesses.
//!
//! A readonly reader owns the same retained file but takes no writer flock and
//! grants no mutation. Ordinary Root/signer observations dispose scratch at
//! their old frontiers. Captured Cache observations retain their finite native
//! name archive and return only a stopping selector while that archive keeps
//! the precise owning cause.

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryHeldJournalV1, CanonicalOrdinaryReadonlyOpeningV1,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use std::path::Path;

use super::{
    CacheCompactionSelectionV1, CacheJournalInstanceV1, Journal, JournalError,
    JournalLimits, RecoveryReport,
};

pub(crate) struct ReadOnlyProtectedJournal {
    pub(super) journal: Journal,
    pub(super) witness: ReadOnlyJournalNameWitness,
    pub(super) named_receiving: Option<ReadonlyNameArchiveV1>,
}

pub(crate) struct ReadOnlyJournalNameWitness {
    pub(super) physical: aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness,
}

impl ReadOnlyProtectedJournal {
    pub(crate) fn journal_mut(&mut self) -> &mut Journal {
        &mut self.journal
    }

    pub(crate) fn check_named_currentness(&self) -> Result<(), JournalError> {
        if let Some(archive) = &self.named_receiving {
            return archive.observe(&self.witness, &self.journal.native);
        }
        self.witness.check_named_currentness()?;
        self.journal.native.require_readonly_identity_v1::<JournalError>(&self.witness.physical)?;
        Ok(())
    }

    pub(crate) fn physical_names_v1(&self) -> ProtectedJournalNamesV1 {
        let (directory, journal, lock) = self.witness.physical.physical_pairs();
        ProtectedJournalNamesV1::from_historical_fields(directory, journal, lock)
    }

    #[cfg(test)]
    pub(crate) fn check_named_currentness_at_uid_for_test(&self) -> Result<(), JournalError> {
        self.witness.check_named_currentness_at_uid_for_test()?;
        self.journal.native.require_readonly_identity_v1::<JournalError>(&self.witness.physical)?;
        Ok(())
    }

    pub(crate) fn into_parts(self) -> (Journal, ReadOnlyJournalNameWitness) {
        (self.journal, self.witness)
    }

    pub(crate) fn named_receiving_failure(&self, index: u8) -> Option<&JournalError> {
        self.named_receiving.as_ref()?.failure_at(index)
    }
}

impl ReadOnlyJournalNameWitness {
    pub(super) fn name(&self) -> &str {
        self.physical.name()
    }

    pub(crate) fn check_named_currentness(&self) -> Result<(), JournalError> {
        self.physical.check_named_currentness::<JournalError>()
    }

    #[cfg(test)]
    pub(crate) fn check_named_currentness_at_uid_for_test(&self) -> Result<(), JournalError> {
        self.physical.check_named_currentness_at_uid_for_test::<JournalError>()
    }
}

// The five current Cache observations remain separate from Root's six-slot
// roster. No copied Root archive or spare sixth Cache observation is allowed.
pub(super) struct ReadonlyNameArchiveV1(
    aos_sandbox_journal::protected_storage::ReadonlyNameArchiveV1<JournalError>,
);

impl ReadonlyNameArchiveV1 {
    const OBSERVATIONS: usize = 5;

    pub(super) fn new() -> Self {
        Self(aos_sandbox_journal::protected_storage::ReadonlyNameArchiveV1::new(Self::OBSERVATIONS))
    }

    pub(super) fn observe(
        &self,
        witness: &ReadOnlyJournalNameWitness,
        held: &CanonicalOrdinaryHeldJournalV1<CacheCompactionSelectionV1, CacheJournalInstanceV1>,
    ) -> Result<(), JournalError> {
        held.observe_readonly_archive_v1(&self.0, &witness.physical)
            .map_err(JournalError::ReadOnlyNameReceivingFailure)
    }

    pub(super) fn observe_opening_v1(
        &self,
        witness: &ReadOnlyJournalNameWitness,
        opening: &CanonicalOrdinaryReadonlyOpeningV1<JournalError>,
    ) -> Result<(), JournalError> {
        opening.observe_archived_names_v1(&self.0, &witness.physical)
            .map_err(JournalError::ReadOnlyNameReceivingFailure)
    }

    pub(super) fn failure_at(&self, index: u8) -> Option<&JournalError> {
        self.0.failure_at(index)
    }

    pub(super) fn receiving_demand_v1() -> Result<ResourceVector, JournalError> {
        use aos_sandbox_protocol::cache_state::fixed_journals::{
            CACHE_BOOTSTRAP_DIRECTORY_V1, CACHE_JOURNAL_DIRECTORY_V1,
        };
        let cache = Self::demand(CACHE_JOURNAL_DIRECTORY_V1)?;
        let bootstrap = Self::demand(CACHE_BOOTSTRAP_DIRECTORY_V1)?;
        Ok(D::ALL.into_iter().fold(cache, |value, dimension| {
            value.with(dimension, value.get(dimension).max(bootstrap.get(dimension)))
        }))
    }

    fn demand(path: &str) -> Result<ResourceVector, JournalError> {
        let geometry = aos_sandbox_journal::protected_storage::ReadonlyNameArchiveV1::<JournalError>::
            receiving_geometry_v1(Self::OBSERVATIONS, path)
            .ok_or_else(|| JournalError::limit_exceeded("readonly name receiving geometry"))?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, geometry.memory_bytes)
            .with(D::OpenFiles, geometry.open_files)
            .with(D::MetadataEntries, geometry.namespace_entries))
    }
}

impl Journal {
    /// Replays one protected name without writing or taking the writer lock.
    ///
    /// This is diagnostic evidence only. The caller must check all names again
    /// after use and must not turn the result into effect or publication authority.
    pub(crate) fn open_read_only_protected_at(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        Self::open_read_only_protected_at_with_identity(directory_path, name, limits, 0, None)
    }

    /// Replays one protected name only from the observed idmapped directory.
    ///
    /// The resolved directory descriptor must match the caller's mount witness
    /// before opening or replaying either file. Callers must still recheck the
    /// mount and original source name after the full observation.
    pub(crate) fn open_read_only_protected_at_for_uid_bound(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
        expected_directory_identity: (u64, u64),
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        Self::open_read_only_protected_at_with_identity(
            directory_path,
            name,
            limits,
            expected_uid,
            Some(expected_directory_identity),
        )
    }

    pub(super) fn open_read_only_protected_at_with_identity(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
        expected_directory_identity: Option<(u64, u64)>,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        let (readback, report) = Self::open_actual_ordinary_readonly_v1(
            directory_path, name, limits, expected_uid, expected_directory_identity,
            #[cfg(test)]
            false,
        )?;
        readback.check_named_currentness()?;
        Ok((readback, report))
    }

    #[cfg(test)]
    /// Opens the actual provided test directory without a root-ancestry grant.
    pub(crate) fn open_read_only_protected_at_uid_for_test(
        directory_path: &Path,
        name: &str,
        limits: JournalLimits,
        expected_uid: u32,
    ) -> Result<(ReadOnlyProtectedJournal, RecoveryReport), JournalError> {
        let (readback, report) = Self::open_actual_ordinary_readonly_v1(
            directory_path, name, limits, expected_uid, None, true,
        )?;
        readback.check_named_currentness_at_uid_for_test()?;
        Ok((readback, report))
    }

}

#[cfg(test)]
mod roster_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;
    #[test]
    #[cfg(target_os = "linux")]
    fn cache_roster_refuses_sixth_observation_without_entering_the_spare_source_slot() {
        let directory = tempfile::tempdir().unwrap();
        let file = tempfile::tempfile().unwrap();
        let identity = aos_sandbox_journal::protected_storage::FileIdentity::of::<JournalError>(&file).unwrap();
        let witness = ReadOnlyJournalNameWitness {
            physical: aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness::from_original_parts((
                directory.path().join("absent"), "state.journal".to_owned(),
                file.metadata().unwrap().uid(), identity, identity, identity,
            )),
        };
        let archive = ReadonlyNameArchiveV1::new();

        // Actual negative Native observations exercise the closed roster only;
        // this fixture supplies no genuine J loan or paid positive Cache cut.
        for expected in 0..ReadonlyNameArchiveV1::OBSERVATIONS {
            assert!(matches!(archive.0.observe(&witness.physical, &file).map_err(JournalError::ReadOnlyNameReceivingFailure),
                Err(JournalError::ReadOnlyNameReceivingFailure(index)) if usize::from(index) == expected));
        }
        assert!(matches!(archive.0.observe(&witness.physical, &file).map_err(JournalError::ReadOnlyNameReceivingFailure),
            Err(JournalError::ReadOnlyNameReceivingFailure(u8::MAX))));

        assert_eq!(archive.0.observation_count(), ReadonlyNameArchiveV1::OBSERVATIONS);
        assert!(archive.failure_at(ReadonlyNameArchiveV1::OBSERVATIONS as u8).is_none());
        assert_eq!(ReadonlyNameArchiveV1::receiving_demand_v1().unwrap().get(D::OpenFiles), 40);
    }
}
