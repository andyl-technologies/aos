//! Retains the finite selected readonly name roster on the actual reader.
//!
//! The remaining Root reader owns six observations. Existing ordinary readers
//! carry no archive and keep their original temporary snapshot disposition.
//! Cache owns five observations through its file-only audit posts.

use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryHeldJournalV1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::{JournalError, ReadOnlyJournalNameWitness};
use super::super::{JournalAuthorityInstance, native_backing::Selection};

const SOURCE_OBSERVATIONS: usize = 6;
#[cfg(target_os = "linux")]
const CACHE_OBSERVATIONS: usize = 5;

pub(in crate::journal) struct ReadonlyNameArchiveV1(
    aos_sandbox_journal::protected_storage::ReadonlyNameArchiveV1<JournalError>,
);

impl ReadonlyNameArchiveV1 {


    #[cfg(target_os = "linux")]
    pub(super) fn cache() -> Self { Self::new(CACHE_OBSERVATIONS) }

    #[cfg(target_os = "linux")]
    pub(super) fn root_controller() -> Self { Self::new(SOURCE_OBSERVATIONS) }

    #[cfg(target_os = "linux")]
    pub(super) fn root_controller_demand() -> Result<ResourceVector, JournalError> {
        Self::demand(SOURCE_OBSERVATIONS, super::super::ROOT_CONTROLLER_DIRECTORY_V1)
    }

    fn new(limit: usize) -> Self {
        Self(aos_sandbox_journal::protected_storage::ReadonlyNameArchiveV1::new(limit))
    }

    pub(super) fn observe(
        &self, witness: &ReadOnlyJournalNameWitness,
        held: &CanonicalOrdinaryHeldJournalV1<Selection, JournalAuthorityInstance>,
    ) -> Result<(), JournalError> {
        held.observe_readonly_archive_v1(&self.0, &witness.physical)
            .map_err(JournalError::ReadOnlyNameReceivingFailure)
    }

    // These negative fixtures retain real initial files without adopting a
    // Journal. Production observations borrow only the actual held owner.
    #[cfg(test)]
    fn observe_original_for_test(
        &self, witness: &ReadOnlyJournalNameWitness, held_file: &std::fs::File,
    ) -> Result<(), JournalError> {
        self.0.observe(&witness.physical, held_file)
            .map_err(JournalError::ReadOnlyNameReceivingFailure)
    }

    pub(super) fn observe_opening_v1(
        &self,
        witness: &ReadOnlyJournalNameWitness,
        opening: &aos_sandbox_broker::canonical_journal::CanonicalOrdinaryReadonlyOpeningV1<JournalError>,
    ) -> Result<(), JournalError> {
        opening.observe_archived_names_v1(&self.0, &witness.physical)
            .map_err(JournalError::ReadOnlyNameReceivingFailure)
    }

    pub(super) fn failure_at(&self, index: u8) -> Option<&JournalError> {
        self.0.failure_at(index)
    }



    #[cfg(target_os = "linux")]
    pub(super) fn cache_demand() -> Result<ResourceVector, JournalError> {
        let cache = Self::demand(CACHE_OBSERVATIONS, crate::cache_residency::PROTECTED_CACHE_ROOT)?;
        let source = Self::demand(CACHE_OBSERVATIONS,
            crate::cache_residency::CONTROLLER_CACHE_READONLY_ROOT_V1)?;
        Ok(D::ALL.into_iter().fold(cache, |value, dimension| {
            value.with(dimension, value.get(dimension).max(source.get(dimension)))
        }))
    }

    fn demand(observations: usize, path: &str) -> Result<ResourceVector, JournalError> {
        let geometry = aos_sandbox_journal::protected_storage::ReadonlyNameArchiveV1::<JournalError>::
            receiving_geometry_v1(observations, path)
            .ok_or(JournalError::LimitExceeded("readonly name receiving geometry"))?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, geometry.memory_bytes)
            .with(D::OpenFiles, geometry.open_files)
            .with(D::MetadataEntries, geometry.namespace_entries))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn finite_archive_keeps_prior_native_cause_through_independent_posts_and_exhaustion() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("state.journal");
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true)
            .open(path).unwrap();
        let identity = aos_sandbox_journal::protected_storage::FileIdentity::of::<JournalError>(&file).unwrap();
        let witness = ReadOnlyJournalNameWitness {
            physical: aos_sandbox_journal::protected_storage::ReadOnlyJournalNameWitness::from_original_parts((
                directory.path().join("absent").to_path_buf(), "state.journal".to_owned(),
                file.metadata().unwrap().uid(), identity, identity, identity,
            )),
        };
        let archive = ReadonlyNameArchiveV1::new(SOURCE_OBSERVATIONS);

        // Real negative native opening only. This fixture creates no genuine
        // Source original, paid receiving interval or supported positive view.
        assert!(matches!(archive.observe_original_for_test(&witness, &file),
            Err(JournalError::ReadOnlyNameReceivingFailure(0))));
        let first = archive.failure_at(0).unwrap() as *const JournalError;
        for expected in 1..SOURCE_OBSERVATIONS {
            assert!(matches!(archive.observe_original_for_test(&witness, &file),
                Err(JournalError::ReadOnlyNameReceivingFailure(index)) if usize::from(index) == expected));
        }
        assert!(matches!(archive.observe_original_for_test(&witness, &file),
            Err(JournalError::ReadOnlyNameReceivingFailure(u8::MAX))));

        assert!(std::ptr::eq(archive.failure_at(0).unwrap(), first));
        assert_eq!(archive.0.observation_count(), SOURCE_OBSERVATIONS);
    }

    #[test]
    fn archive_uses_sync_safe_slots_and_prices_all_six_rooted_observations() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<ReadonlyNameArchiveV1>();

        let demand = ReadonlyNameArchiveV1::demand(SOURCE_OBSERVATIONS, "/run/aos/sandbox-source-signer-journal").unwrap();

        assert_eq!(demand.get(D::OpenFiles), 6 * (4 + 2));
        assert!(demand.get(D::MemoryBytes) > std::mem::size_of::<ReadonlyNameArchiveV1>() as u64);
    }

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
        let archive = ReadonlyNameArchiveV1::cache();

        // Actual negative Native observations exercise the closed roster only;
        // this fixture supplies no genuine J loan or paid positive Cache cut.
        for expected in 0..CACHE_OBSERVATIONS {
            assert!(matches!(archive.observe_original_for_test(&witness, &file),
                Err(JournalError::ReadOnlyNameReceivingFailure(index)) if usize::from(index) == expected));
        }
        assert!(matches!(archive.observe_original_for_test(&witness, &file),
            Err(JournalError::ReadOnlyNameReceivingFailure(u8::MAX))));

        assert_eq!(archive.0.observation_count(), CACHE_OBSERVATIONS);
        assert!(archive.failure_at(CACHE_OBSERVATIONS as u8).is_none());
        assert_eq!(ReadonlyNameArchiveV1::cache_demand().unwrap().get(D::OpenFiles), 40);
    }
}
