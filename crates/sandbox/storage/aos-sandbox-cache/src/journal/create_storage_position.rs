//! Parks one actual fixed Cache writer position and every failed prefix.
//!
//! Rooted directory, held binding, both native names, witness and metadata
//! complete in their old order. Positive checks dispose only fresh descriptors;
//! the retained position is comparison DATA, never a writer or financial loan.

use std::fs::{File, Metadata};
use std::path::Path;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_journal::protected_storage::{
    ProtectedFileNamesCurrentOriginalsV1, ProtectedWriterNameWitness,
    resolve_protected_directory_from_root_original,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::CacheJournalDataV1;

use super::{Journal, JournalError, JournalLimits, ProtectedJournalNamesV1};
use crate::InitializerJournal;

type CreateStorageWriterPositionV1 = CacheJournalDataV1;

// A temporary private leaf cannot satisfy production's rooted ancestry law.
// This test-only choice still opens and validates the actual named directory.
#[cfg(test)]
#[derive(Clone, Copy)]
enum FixtureDirectoryObservationV1 {
    Rooted,
    PrivateLeaf,
}

// Retain the actual fixture comparison without projecting its private File.
// Production continues to use its original File result slot below.
#[cfg(test)]
enum FixtureDirectoryOriginalV1 {
    Rooted(File),
    PrivateLeaf(
        aos_sandbox_broker::canonical_journal::coordinator::CanonicalDirectoryComparisonDataV1,
    ),
}

/// Retains the native observations of one existing fixed Cache writer.
#[derive(Default)]
pub(crate) struct CreateStorageWriterPositionOriginalV1 {
    ancestors: Vec<File>,
    root_error: Option<rustix::io::Errno>,
    #[cfg(not(test))]
    directory: Option<Result<File, JournalError>>,
    #[cfg(test)]
    directory: Option<Result<FixtureDirectoryOriginalV1, JournalError>>,
    directory_binding: Option<Result<(), JournalError>>,
    names: Option<ProtectedFileNamesCurrentOriginalsV1<JournalError>>,
    witness: Option<Result<ProtectedWriterNameWitness, JournalError>>,
    metadata: Option<std::io::Result<Metadata>>,
    result: Option<Result<CreateStorageWriterPositionV1, JournalError>>,
}

impl CreateStorageWriterPositionOriginalV1 {
    fn rooted_metadata_cells_v1(root: &Path) -> Result<usize, JournalError> {
        // Names: two validated files and four fstats. Held writer: three
        // identities plus end metadata. Rooted path: ancestry per anchor,
        // final directory validation and the retained-directory identity.
        root.components()
            .filter(|part| matches!(part, std::path::Component::Normal(_)))
            .count()
            .checked_add(1)
            .and_then(|anchors| anchors.checked_add(12))
            .ok_or_else(|| Mechanical::JournalTooLarge.into())
    }

    /// Counts the same fixed Cache recipe's reached native metadata carriers.
    ///
    /// # Errors
    /// Refuses an unrepresentable rooted metadata count. This quote supplies
    /// no native sample, paid interval or ownership of a writer.
    pub(crate) fn cache_receiving_metadata_cells_v1(
        role: InitializerJournal,
    ) -> Result<usize, JournalError> {
        Self::rooted_metadata_cells_v1(role.recipe().0)
    }

    /// Captures the original native position of one fixed Cache recipe.
    pub(crate) fn capture_cache_once(
        &mut self,
        journal: &Journal,
        role: InitializerJournal,
        uid: u32,
    ) {
        let (root, name, limits) = role.recipe();
        self.capture_fixed_once(
            journal,
            (root, name, limits, uid),
            #[cfg(test)]
            FixtureDirectoryObservationV1::Rooted,
        );
    }

    // Exercises the same observation body on an actual temporary private leaf;
    // it cannot construct a production fixed Cache owner or a funding loan.
    #[cfg(test)]
    pub(super) fn capture_fixture_once(&mut self, journal: &Journal, directory: &Path) {
        let location = journal.read_view().protected_view();
        let Some(location) = location else { return; };
        self.capture_fixed_once(
            journal,
            (directory, location.name(), journal.limits(), location.expected_uid()),
            FixtureDirectoryObservationV1::PrivateLeaf,
        );
    }

    fn capture_fixed_once(
        &mut self,
        journal: &Journal,
        recipe: (&Path, &str, JournalLimits, u32),
        #[cfg(test)] fixture_directory: FixtureDirectoryObservationV1,
    ) {
        if self.result.is_some() {
            return;
        }
        self.result = Some(self.capture_inner(
            journal,
            recipe,
            #[cfg(test)]
            fixture_directory,
        ));
        if matches!(self.result, Some(Ok(_))) {
            // All native observations completed. Dispose only fresh Files;
            // the retained witness, metadata and exact position stay resident.
            self.names = None;
            self.directory = None;
            self.ancestors = Vec::new();
        }
    }

    fn capture_inner(
        &mut self,
        journal: &Journal,
        recipe: (&Path, &str, JournalLimits, u32),
        #[cfg(test)] fixture_directory: FixtureDirectoryObservationV1,
    ) -> Result<CreateStorageWriterPositionV1, JournalError> {
        journal.ensure_healthy()?;
        let location = journal.read_view().protected_view().ok_or(JournalError::boundary())?;
        let (root, name, limits, uid) = recipe;
        if location.name() != name || journal.limits() != limits || uid != location.expected_uid() {
            return Err(JournalError::boundary());
        }

        #[cfg(not(test))]
        {
            self.directory = Some(resolve_protected_directory_from_root_original::<JournalError>(
                root,
                location.expected_uid(),
                Some(&mut self.ancestors),
                Some(&mut self.root_error),
            ));
        }
        #[cfg(test)]
        {
            self.directory = Some(match fixture_directory {
                FixtureDirectoryObservationV1::Rooted => {
                    resolve_protected_directory_from_root_original::<JournalError>(
                        root,
                        location.expected_uid(),
                        Some(&mut self.ancestors),
                        Some(&mut self.root_error),
                    )
                    .map(FixtureDirectoryOriginalV1::Rooted)
                }
                FixtureDirectoryObservationV1::PrivateLeaf => {
                    location.require_directory_at_uid_for_test::<JournalError>(root, uid)
                        .map(FixtureDirectoryOriginalV1::PrivateLeaf)
                }
            });
        }
        let directory = match self.directory.as_ref() {
            Some(Ok(directory)) => directory,
            _ => return Err(JournalError::boundary()),
        };
        #[cfg(not(test))]
        {
            self.directory_binding = Some(location.require_opened_directory::<JournalError>(directory));
        }
        #[cfg(test)]
        {
            self.directory_binding = Some(match directory {
                FixtureDirectoryOriginalV1::Rooted(directory) => {
                    location.require_opened_directory::<JournalError>(directory)
                }
                // This original exists only after the same held/named identity
                // comparison succeeded; keep it resident through the observation.
                FixtureDirectoryOriginalV1::PrivateLeaf(_comparison) => Ok(()),
            });
        }
        if !matches!(self.directory_binding, Some(Ok(()))) {
            return Err(JournalError::boundary());
        }
        journal.ensure_healthy()?;

        self.names = Some(ProtectedFileNamesCurrentOriginalsV1::new());
        let names = self.names.as_mut().ok_or(JournalError::boundary())?;
        journal.read_view().observe_named_files_into(names)?;
        if !names.is_complete() {
            return Err(JournalError::boundary());
        }
        self.witness = Some(location.writer_witness::<JournalError>());
        let witness = match self.witness.as_ref() {
            Some(Ok(witness)) => witness,
            _ => return Err(JournalError::boundary()),
        };
        self.metadata = Some(journal.read_view().metadata());
        let metadata = match self.metadata.as_ref() {
            Some(Ok(metadata)) => metadata,
            _ => return Err(JournalError::boundary()),
        };
        journal.ensure_healthy()?;

        Ok(CreateStorageWriterPositionV1 {
            names: ProtectedJournalNamesV1::from_historical_fields(
                witness.directory().physical_pair(),
                witness.file().physical_pair(),
                witness.lock().physical_pair(),
            ),
            next: journal.snapshot_sequence(),
            end: metadata.len(),
        })
    }

    /// Copies the completed original native position as comparison DATA.
    ///
    /// # Errors
    /// Refuses absent or failed capture without replacing its retained cause.
    pub(crate) fn position(&self) -> Result<CreateStorageWriterPositionV1, JournalError> {
        match self.result.as_ref() {
            Some(Ok(position)) => Ok(*position),
            _ => Err(JournalError::boundary()),
        }
    }

    /// Borrows the complete witness after a positive original capture.
    ///
    /// # Errors
    /// Refuses absent or failed capture, or an already moved witness.
    pub(crate) fn witness(&self) -> Result<&ProtectedWriterNameWitness, JournalError> {
        self.position()?;
        match self.witness.as_ref() {
            Some(Ok(witness)) => Ok(witness),
            _ => Err(JournalError::boundary()),
        }
    }

    /// Moves the checked witness into the same actual clock guard.
    ///
    /// # Errors
    /// Refuses absent or failed capture, or a repeated witness transfer.
    pub(crate) fn take_witness_once(&mut self) -> Result<ProtectedWriterNameWitness, JournalError> {
        self.position()?;
        match self.witness.take() {
            Some(Ok(witness)) => Ok(witness),
            _ => Err(JournalError::boundary()),
        }
    }

    /// Borrows the first reached native cause without consuming its prefix.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.root_error.as_ref().map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.directory.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.directory_binding.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.names.as_ref().and_then(ProtectedFileNamesCurrentOriginalsV1::failure).map(|error| error as _))
            .or_else(|| self.witness.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.metadata.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| self.result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
    }
}
