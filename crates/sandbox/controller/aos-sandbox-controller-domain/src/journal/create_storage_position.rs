//! Parks one selected C/Source physical position and every failed fresh prefix.
//!
//! Source uses its existing fixed rooted directory recipe; Controller preserves
//! the original retained-directory contract. Complete positive checks dispose
//! their temporary descriptors before yielding nonauthorizing position DATA.

use std::fs::{File, Metadata};
use std::path::Path;

use aos_sandbox_journal::protected_storage::{
    ProtectedFileNamesCurrentOriginalsV1, ProtectedWriterNameWitness,
    resolve_protected_directory_from_root_original,
};

use super::{Journal, JournalError, JournalLimits, ProtectedJournalNamesV1};
use crate::controller_resource_reservation::{CreateStorageWriterPositionV1, HistoryRoleV1};

#[derive(Default)]
pub(crate) struct CreateStorageWriterPositionOriginalV1 {
    ancestors: Vec<File>,
    root_error: Option<rustix::io::Errno>,
    directory: Option<Result<File, JournalError>>,
    directory_binding: Option<Result<(), JournalError>>,
    names: Option<ProtectedFileNamesCurrentOriginalsV1<JournalError>>,
    witness: Option<Result<ProtectedWriterNameWitness, JournalError>>,
    metadata: Option<std::io::Result<Metadata>>,
    result: Option<Result<CreateStorageWriterPositionV1, JournalError>>,
}

impl CreateStorageWriterPositionOriginalV1 {
    /// Counts logical native metadata carriers for an existing C/Source sample.
    ///
    /// The complete retained history remains charged after fresh Files dispose.
    /// This passive geometry cannot create a position, native owner or payer.
    pub(crate) fn receiving_metadata_cells_v1(role: HistoryRoleV1)
        -> Result<usize, JournalError>
    {
        match role {
            HistoryRoleV1::Controller => Ok(10),
            HistoryRoleV1::Source => Self::rooted_metadata_cells_v1(
                Path::new(crate::source_domain::PROTECTED_SOURCE_DOMAIN_ROOT)),
        }
    }

    /// Counts the SAME fixed Client position recipe's native metadata carriers.
    pub(crate) fn controller_storage_client_receiving_metadata_cells_v1()
        -> Result<usize, JournalError>
    {
        Self::rooted_metadata_cells_v1(Path::new(
            super::broker_session_receiving::CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1))
    }

    fn rooted_metadata_cells_v1(root: &Path) -> Result<usize, JournalError> {
        // Names: two validated files and four fstats. Held writer: three
        // identities plus end metadata. Rooted path: ancestry per anchor,
        // final directory validation and the retained-directory identity.
        root.components().filter(|part| matches!(part, std::path::Component::Normal(_)))
            .count().checked_add(1).and_then(|anchors| anchors.checked_add(12))
            .ok_or(JournalError::JournalTooLarge)
    }

    pub(crate) fn capture_once(&mut self, journal: &Journal, role: HistoryRoleV1) {
        let recipe = matches!(role, HistoryRoleV1::Source).then(|| (
            Path::new(crate::source_domain::PROTECTED_SOURCE_DOMAIN_ROOT),
            crate::source_domain::PROTECTED_SOURCE_DOMAIN_JOURNAL,
            crate::source_domain::source_domain_journal_limits(),
            journal.native.protected_view().map(|location| location.expected_uid()),
        ));
        self.capture_fixed_once(journal, recipe);
    }




    /// Captures the fixed Controller Storage Client location on its same writer.
    ///
    /// The expected UID comes from the genuine Controller original, never a
    /// caller hint. The shared retained-name engine owns all reached prefixes.
    pub(crate) fn capture_controller_storage_client_once(
        &mut self,
        journal: &Journal,
        controller: &Journal,
    ) {
        let uid = controller.native.protected_view().map(|location| location.expected_uid());
        self.capture_fixed_once(journal, Some((
            Path::new(super::broker_session_receiving::CONTROLLER_STORAGE_CLIENT_JOURNAL_ROOT_V1),
            super::broker_session_receiving::PROTECTED_SESSION_JOURNAL_V1,
            super::broker_session_receiving::protected_session_journal_limits_v1(),
            uid,
        )));
    }

    fn capture_fixed_once(
        &mut self,
        journal: &Journal,
        recipe: Option<(&Path, &str, JournalLimits, Option<u32>)>,
    ) {
        if self.result.is_some() { return; }
        self.result = Some(self.capture_inner(journal, recipe));
        if matches!(self.result, Some(Ok(_))) {
            // All metadata, rooted binding, both names and health completed.
            // Drop actual fresh descriptors now; the retained Position is DATA.
            self.names = None;
            self.directory = None;
            self.ancestors = Vec::new();
        }
    }

    fn capture_inner(
        &mut self,
        journal: &Journal,
        recipe: Option<(&Path, &str, JournalLimits, Option<u32>)>,
    ) -> Result<CreateStorageWriterPositionV1, JournalError> {
        journal.ensure_healthy()?;
        let location = journal.native.protected_view().ok_or(JournalError::ProtectedBoundary)?;
        if let Some((root, name, limits, uid)) = recipe {
            if location.name() != name || journal.native.limits() != limits
                || uid != Some(location.expected_uid())
            {
                return Err(JournalError::ProtectedBoundary);
            }
            self.directory = Some(resolve_protected_directory_from_root_original::<JournalError>(
                root, location.expected_uid(), Some(&mut self.ancestors), Some(&mut self.root_error)));
            let directory = match self.directory.as_ref() {
                Some(Ok(directory)) => directory,
                Some(Err(_)) => return Err(JournalError::ProtectedBoundary),
                None => return Err(JournalError::ProtectedBoundary),
            };
            self.directory_binding = Some(location.require_opened_directory::<JournalError>(directory));
            if !matches!(self.directory_binding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
            journal.ensure_healthy()?;
        }
        self.names = Some(ProtectedFileNamesCurrentOriginalsV1::new());
        let names = self.names.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        journal.native.read_view().observe_named_files_into(names)?;
        if !names.is_complete() { return Err(JournalError::ProtectedBoundary); }
        self.witness = Some(location.writer_witness::<JournalError>());
        let witness = match self.witness.as_ref() { Some(Ok(witness)) => witness, _ => return Err(JournalError::ProtectedBoundary) };
        self.metadata = Some(journal.native.metadata());
        let metadata = match self.metadata.as_ref() { Some(Ok(metadata)) => metadata, _ => return Err(JournalError::ProtectedBoundary) };
        journal.ensure_healthy()?;
        Ok(CreateStorageWriterPositionV1 {
            names: ProtectedJournalNamesV1::from_historical_fields(witness.directory().physical_pair(),
                witness.file().physical_pair(), witness.lock().physical_pair()),
            next: journal.snapshot_sequence(), end: metadata.len(),
        })
    }

    pub(crate) fn position(&self) -> Result<CreateStorageWriterPositionV1, JournalError> {
        match self.result.as_ref() { Some(Ok(position)) => Ok(*position), _ => Err(JournalError::ProtectedBoundary) }
    }

    /// Borrows the complete retained metadata after a positive original check.
    pub(crate) fn witness(&self) -> Result<&ProtectedWriterNameWitness, JournalError> {
        self.position()?;
        match self.witness.as_ref() {
            Some(Ok(witness)) => Ok(witness),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    /// Moves the already checked witness into the same actual clock guard.
    pub(crate) fn take_witness_once(&mut self) -> Result<ProtectedWriterNameWitness, JournalError> {
        self.position()?;
        match self.witness.take() {
            Some(Ok(witness)) => Ok(witness),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

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

// Actual Source path has five descendants plus the root. Both a failed primary
// pair and its independent pair can coexist: 2*(Controller2 + Source(6+2)).
// A failed primary and its independent clock post can each retain one boot
// file. Positive canonical primitive files close before the next clock step;
// no later phase may reuse a negative original or its retained descriptor.
pub(crate) fn create_storage_name_peak_demand_v1()
    -> Result<aos_sandbox_model::ResourceVector, JournalError>
{
    use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
    let anchors = Path::new(crate::source_domain::PROTECTED_SOURCE_DOMAIN_ROOT)
        .components().filter(|component| matches!(component, std::path::Component::Normal(_))).count()
        .checked_add(1).ok_or(JournalError::JournalTooLarge)?;
    let files = anchors.checked_add(4).and_then(|n| n.checked_mul(2)).and_then(|n| n.checked_add(
        crate::policy_compiler::RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)?))
        .ok_or(JournalError::JournalTooLarge)?;
    // Seven Source sample Vec backings remain across the two pairs,
    // covered by eight fixed lanes; basename formatting is bounded by the existing strict grammar.
    let memory = anchors.checked_mul(8 * std::mem::size_of::<File>())
        .and_then(|n| n.checked_add(4 * (aos_sandbox_journal::protected_storage::MAXIMUM_PROTECTED_JOURNAL_BASENAME_BYTES + 5)))
        .ok_or(JournalError::JournalTooLarge)?;
    Ok(ResourceVector::ZERO.with(D::OpenFiles, u64::try_from(files).map_err(|_| JournalError::JournalTooLarge)?)
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| JournalError::JournalTooLarge)?)
        .with(D::MetadataEntries, u64::try_from(files).map_err(|_| JournalError::JournalTooLarge)?))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    #[test]
    fn missing_journal_keeps_the_fresh_lock_and_first_native_cause_through_posts() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(directory.path(), "history.journal",
            super::super::JournalLimits::default(), uid).unwrap();
        std::fs::remove_file(directory.path().join("history.journal")).unwrap();

        let mut primary = CreateStorageWriterPositionOriginalV1::default();
        primary.capture_once(&journal, HistoryRoleV1::Controller);
        assert!(primary.position().is_err());
        assert_eq!(primary.names.as_ref().unwrap().retained_file_count(), 1);
        let first = primary.failure().unwrap().downcast_ref::<JournalError>().unwrap() as *const JournalError;
        assert!(std::error::Error::source(primary.failure().unwrap()).is_some());

        // An independent later failure cannot replace or dispose the first
        // named-lock original. Reentry cannot open a replacement either.
        std::fs::remove_file(directory.path().join("history.journal.lock")).unwrap();
        let mut post = CreateStorageWriterPositionOriginalV1::default();
        post.capture_once(&journal, HistoryRoleV1::Controller);
        assert!(post.failure().is_some());
        assert_eq!(post.names.as_ref().unwrap().retained_file_count(), 0);
        primary.capture_once(&journal, HistoryRoleV1::Controller);
        assert_eq!(primary.names.as_ref().unwrap().retained_file_count(), 1);
        assert_eq!(primary.failure().unwrap().downcast_ref::<JournalError>().unwrap() as *const _, first);
    }

    #[test]
    fn complete_positive_check_disposes_fresh_files_before_returning_position_data() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = directory.path().metadata().unwrap().uid();
        let (journal, _) = Journal::open_protected_at_uid(directory.path(), "history.journal",
            super::super::JournalLimits::default(), uid).unwrap();
        let mut original = CreateStorageWriterPositionOriginalV1::default();

        original.capture_once(&journal, HistoryRoleV1::Controller);

        let position = original.position().unwrap();
        assert_eq!(position.names, journal.protected_writer_physical_names_v1().unwrap());
        assert_eq!(position.next, journal.snapshot_sequence());
        assert!(original.names.is_none());
        assert!(original.directory.is_none());
        assert!(original.ancestors.is_empty());
        assert!(original.failure().is_none());
    }
}
