//! Retains physical main-writer bookends across initial approval verification.
//!
//! The original Source pays both observations before the readback loan exists.
//! Every reached native outcome stays resident through the final Source post;
//! these metadata comparisons grant no durable intent or physical TPM authority.

use aos_sandbox_journal::protected_storage::{FileIdentity, WriterWitnessOriginalsV1};

use super::*;

pub(super) struct ApprovalCurrentnessOriginalV1 {
    quote: Option<Result<ResourceVector, JournalError>>,
    replayed_file: Option<FileIdentity>,
    names: [super::super::super::ProtectedJournalCurrentnessOriginalsV1; 2],
    witnesses: [WriterWitnessOriginalsV1<JournalError>; 2],
    results: [Option<Result<(), JournalError>>; 2],
    entered: bool,
    closed: Option<JournalError>,
    directory_publication: bool,
}

impl ApprovalCurrentnessOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            quote: None,
            replayed_file: None,
            names: std::array::from_fn(|_| {
                super::super::super::ProtectedJournalCurrentnessOriginalsV1::new()
            }),
            witnesses: std::array::from_fn(|_| WriterWitnessOriginalsV1::new()),
            results: [None, None],
            entered: false,
            closed: None,
            directory_publication: false,
        }
    }

    pub(super) fn for_initial_intent_publication() -> Self {
        let mut original = Self::new();
        // Creating and renaming the fixed sibling changes directory size and
        // timestamps. The protected name samples still validate its UID, mode
        // and physical identity. Main and lock retain full metadata equality.
        original.directory_publication = true;
        original
    }

    fn demand(journal: &Journal) -> Result<ResourceVector, JournalError> {
        let failed = || JournalError::LimitExceeded("initial approval currentness geometry");
        let witness = WriterWitnessOriginalsV1::<JournalError>::receiving_footprint_v1()
            .ok_or_else(failed)?;
        let memory = witness
            .memory_bytes
            .checked_add(std::mem::size_of::<Self>())
            .ok_or_else(failed)?;
        let per_sample = journal
            .held_names_receiving_demand_v2()?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| failed())?)
                    .with(
                        D::OpenFiles,
                        u64::try_from(witness.open_files).map_err(|_| failed())?,
                    )
                    .with(
                        D::MetadataEntries,
                        u64::try_from(witness.metadata_cells).map_err(|_| failed())?,
                    ),
            )
            .map_err(|_| failed())?;
        per_sample.checked_add(per_sample).map_err(|_| failed())
    }

    pub(super) fn quote_once(
        &mut self,
        journal: &Journal,
        replayed_file: FileIdentity,
    ) -> Option<ResourceVector> {
        if self.quote.is_some() || self.entered || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        self.replayed_file = Some(replayed_file);
        self.quote = Some(Self::demand(journal));
        self.quote
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
    }

    pub(super) fn before_once(&mut self, journal: &Journal) -> Result<(), JournalError> {
        if self.entered || self.closed.is_some() || !matches!(self.quote, Some(Ok(_))) {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        self.results[0] = Some((|| {
            journal.observe_held_physical_names_retaining_v1(
                &mut self.names[0],
                &mut self.witnesses[0],
            )?;
            let observed = self.witnesses[0]
                .completed_witness()
                .ok_or(JournalError::ProtectedBoundary)?;
            if Some(observed.file()) != self.replayed_file {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            Ok(())
        })());
        self.before_completed()
    }

    fn before_completed(&self) -> Result<(), JournalError> {
        if self.closed.is_none()
            && matches!(self.results[0], Some(Ok(())))
            && self.witnesses[0].completed_witness().is_some()
        {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn finish_after_owed(&mut self, journal: &Journal) -> Result<(), JournalError> {
        if !self.entered {
            return Ok(());
        }
        if self.results[1].is_none() {
            // The new native sample is owed even when the first sample failed.
            // Compare only after retaining its actual names and metadata results.
            self.results[1] = Some((|| {
                journal.observe_held_physical_names_retaining_v1(
                    &mut self.names[1],
                    &mut self.witnesses[1],
                )?;
                let before = self.witnesses[0]
                    .completed_witness()
                    .ok_or(JournalError::ProtectedBoundary)?;
                let after = self.witnesses[1]
                    .completed_witness()
                    .ok_or(JournalError::ProtectedBoundary)?;
                let same_directory = if self.directory_publication {
                    before.directory().physical_pair() == after.directory().physical_pair()
                } else {
                    before.directory() == after.directory()
                };
                if !same_directory || before.file() != after.file() || before.lock() != after.lock()
                {
                    return Err(JournalError::StaleAuthoritySnapshot);
                }
                Ok(())
            })());
        }
        self.before_completed()?;
        if matches!(self.results[1], Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn sample_failure(&self, index: usize) -> Option<&(dyn Error + 'static)> {
        self.names[index]
            .failure()
            .or_else(|| self.witnesses[index].failure())
            .or_else(|| {
                self.results[index]
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|error| error as _)
            })
    }

    pub(super) fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.quote
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|error| error as _)
            .or_else(|| self.sample_failure(0))
    }

    pub(super) fn after_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.sample_failure(1)
    }

    pub(super) fn order_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.closed.as_ref().map(|error| error as _)
    }

    #[cfg(test)]
    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_failure()
            .or_else(|| self.after_failure())
            .or_else(|| self.order_failure())
    }
}

impl Method46InitialMainWriterOriginalV1 {
    pub(crate) fn quote_approval_currentness_once(&mut self) -> Option<ResourceVector> {
        if !self.readback_available_data() {
            self.closed.get_or_insert(JournalError::ProtectedBoundary);
            return None;
        }
        let replayed_file = self
            .inner
            .original
            .captured_replay_file_identity_data_v1()?;
        self.approval_currentness
            .quote_once(self.inner.original.journal_data_v1()?, replayed_file)
    }

    pub(super) fn observe_approval_before_once(&mut self) -> Result<(), JournalError> {
        let journal = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.approval_currentness.before_once(journal)
    }

    pub(crate) fn finish_approval_currentness_after_owed(&mut self) -> Result<(), JournalError> {
        if !self.approval_currentness.entered {
            return Ok(());
        }
        let journal = self
            .inner
            .original
            .journal_data_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.approval_currentness.finish_after_owed(journal)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek as _, SeekFrom, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{Duration, SystemTime};

    use super::*;

    fn native_writer() -> (tempfile::TempDir, Journal, FileIdentity) {
        // A real protected writer tests the mechanical metadata recipe only.
        // This fixture supplies no genuine Source, schema or approval authority.
        let executable = std::env::current_exe().unwrap();
        let directory = tempfile::Builder::new()
            .prefix("initial-approval-currentness-")
            .tempdir_in(executable.parent().unwrap())
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let mut opening = ProtectedWriterOpenOriginalsV1::new();
        opening.prepare_captured_for_uid_once(
            directory.path(),
            "journal",
            JournalLimits::default(),
            uid,
            true,
        );
        assert!(opening.failure().is_none(), "{:?}", opening.failure());
        opening.replay_prepared_once();
        let replayed_file = opening.captured_replay_file_identity_data_v1().unwrap();
        let (journal, _) = opening.take_captured_opened().unwrap();
        (directory, journal, replayed_file)
    }

    #[test]
    fn method46_initial_approval_metadata_requires_original_geometry_before_native_entry() {
        let (_directory, journal, replayed_file) = native_writer();
        let mut original = ApprovalCurrentnessOriginalV1::new();

        assert!(original.before_once(&journal).is_err());
        assert!(!original.entered);
        assert!(original.quote_once(&journal, replayed_file).is_none());
        assert!(original.failure().is_some());
    }

    #[test]
    fn method46_initial_approval_unchanged_writer_preserves_both_native_samples() {
        let (_directory, journal, replayed_file) = native_writer();
        let mut original = ApprovalCurrentnessOriginalV1::new();
        assert!(original.quote_once(&journal, replayed_file).is_some());

        original.before_once(&journal).unwrap();
        original.finish_after_owed(&journal).unwrap();

        assert!(
            original
                .witnesses
                .iter()
                .all(|sample| sample.completed_witness().is_some())
        );
        assert!(
            original
                .results
                .iter()
                .all(|result| matches!(result, Some(Ok(()))))
        );
        assert!(original.failure().is_none());
        // Final Source cleanup revisits the existing result without native IO.
        original.finish_after_owed(&journal).unwrap();
        assert!(original.failure().is_none());
    }

    #[test]
    fn method46_initial_approval_rejects_in_place_append_overwrite_and_replaced_names() {
        for mutation in 0..4 {
            let (directory, journal, replayed_file) = native_writer();
            let mut original = ApprovalCurrentnessOriginalV1::new();
            assert!(original.quote_once(&journal, replayed_file).is_some());
            original.before_once(&journal).unwrap();

            let path = directory.path().join("journal");
            match mutation {
                0 => {
                    OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap()
                        .write_all(b"extra")
                        .unwrap();
                }
                1 => {
                    let mut file = OpenOptions::new().write(true).open(&path).unwrap();
                    file.seek(SeekFrom::Start(0)).unwrap();
                    file.write_all(b"x").unwrap();
                    // Make the metadata change deterministic on coarse clocks.
                    file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                        .unwrap();
                }
                2 => {
                    std::fs::rename(&path, directory.path().join("old-journal")).unwrap();
                    std::fs::write(&path, b"replacement").unwrap();
                }
                3 => std::fs::remove_file(directory.path().join("journal.lock")).unwrap(),
                _ => unreachable!(),
            }

            assert!(
                original.finish_after_owed(&journal).is_err(),
                "mutation {mutation}"
            );
            assert!(original.results[1].as_ref().unwrap().is_err());
            let first = original.failure().unwrap() as *const dyn Error as *const ();
            assert!(original.finish_after_owed(&journal).is_err());
            assert_eq!(
                original.failure().unwrap() as *const dyn Error as *const (),
                first
            );
        }
    }

    #[test]
    fn method46_initial_approval_cannot_rebase_onto_a_file_changed_after_replay() {
        let (directory, journal, replayed_file) = native_writer();
        let mut original = ApprovalCurrentnessOriginalV1::new();
        assert!(original.quote_once(&journal, replayed_file).is_some());
        OpenOptions::new()
            .append(true)
            .open(directory.path().join("journal"))
            .unwrap()
            .write_all(b"changed after replay")
            .unwrap();

        assert!(original.before_once(&journal).is_err());
        assert!(original.witnesses[0].completed_witness().is_some());
        assert!(matches!(
            original.results[0],
            Some(Err(JournalError::StaleAuthoritySnapshot))
        ));
        assert!(original.finish_after_owed(&journal).is_err());
        assert!(original.results[1].is_some());
    }

    #[test]
    fn method46_initial_approval_failed_before_still_attempts_its_independent_after() {
        let (directory, journal, replayed_file) = native_writer();
        let mut original = ApprovalCurrentnessOriginalV1::new();
        assert!(original.quote_once(&journal, replayed_file).is_some());
        let path = directory.path().join("journal");
        let saved = directory.path().join("saved-journal");
        std::fs::rename(&path, &saved).unwrap();

        assert!(original.before_once(&journal).is_err());
        let first = original.failure().unwrap() as *const dyn Error as *const ();
        std::fs::rename(saved, path).unwrap();
        assert!(original.finish_after_owed(&journal).is_err());

        assert!(original.results[1].is_some());
        assert!(original.witnesses[1].completed_witness().is_some());
        assert_eq!(
            original.failure().unwrap() as *const dyn Error as *const (),
            first
        );
    }
}
