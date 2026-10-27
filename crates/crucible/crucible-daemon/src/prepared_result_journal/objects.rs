//! Content-addressed object directories owned by one prepared-result journal.
//!
//! A prepared result names some of its content only by identity: attempt-log
//! and resolved-effect trace segments, and finding replay records. Staging copies each named object into
//! a journal subdirectory, authenticated and synchronized, before the result
//! and state files are written, so a journal never depends on the stores the
//! attempt wrote:
//!
//! ```text
//! <journal>/<family>/<64 hex><suffix>              one complete object
//! <journal>/<family>/.<64 hex><suffix>.<pid>.<n>   staging temporary
//! ```
//!
//! Readers resolve object names through a duplicated directory descriptor, so
//! a reopened result keeps reading the same inode across the
//! staged-to-visible rename.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crucible_store::content_store::ContentId;
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

use super::{
    MAX_RUNTIME_JOURNAL_ENTRIES, PreparedResultJournalError, anchored_journal_error,
    is_current_temporary_name, is_lower_hex, write_atomic,
};
use crate::anchored_fs::AnchoredDirectory;

/// One family of journal-owned objects and its directory layout.
#[derive(Debug)]
pub(super) struct ObjectFamily {
    /// Name of the journal subdirectory that holds the family.
    pub(super) directory: &'static str,
    /// Suffix of one complete object file.
    pub(super) suffix: &'static str,
    /// Largest object the family's format admits.
    pub(super) maximum_bytes: usize,
}

impl ObjectFamily {
    pub(super) fn file_name(&self, id: ContentId) -> String {
        let digest = id
            .digest()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("{digest}{}", self.suffix)
    }

    fn is_file_name(&self, name: &str) -> bool {
        name.strip_suffix(self.suffix)
            .is_some_and(|digest| is_lower_hex(digest, 64))
    }

    fn is_temporary_name(&self, name: &str) -> bool {
        name.get(1..65)
            .filter(|digest| is_lower_hex(digest, 64))
            .is_some_and(|digest| {
                is_current_temporary_name(name, &format!("{digest}{}", self.suffix))
            })
    }
}

/// Creates the family's subdirectory in a staging journal.
pub(super) fn create_directory(
    root: &AnchoredDirectory,
    family: &ObjectFamily,
) -> Result<AnchoredDirectory, PreparedResultJournalError> {
    root.create_new_directory(
        &root.path().join(family.directory),
        "create-journal-objects",
    )
    .map_err(|source| anchored_journal_error(source, "create-journal-objects"))
}

/// Writes one authenticated object into a staging subdirectory.
pub(super) fn write_object(
    directory: &AnchoredDirectory,
    family: &ObjectFamily,
    id: ContentId,
    bytes: &[u8],
) -> Result<(), PreparedResultJournalError> {
    write_atomic(directory, &family.file_name(id), bytes)
}

/// Synchronizes a staged subdirectory and opens a reader over it.
pub(super) fn seal_directory(
    directory: &AnchoredDirectory,
    family: &'static ObjectFamily,
) -> Result<JournalObjectSource, PreparedResultJournalError> {
    directory
        .sync()
        .map_err(|source| anchored_journal_error(source, "sync-journal-objects"))?;
    JournalObjectSource::open(directory, family)
}

/// Opens the objects of a journal whose state binds `expected_count` of them.
///
/// The subdirectory must hold exactly that many complete object files and
/// nothing else. Their contents are authenticated when the result is decoded.
pub(super) fn open_objects(
    root: &AnchoredDirectory,
    family: &'static ObjectFamily,
    expected_count: u64,
) -> Result<JournalObjectSource, PreparedResultJournalError> {
    let path = root.path().join(family.directory);
    let directory = root
        .open_directory(&path, "open-journal-objects")
        .map_err(|source| anchored_journal_error(source, "open-journal-objects"))?;
    let maximum = usize::try_from(expected_count)
        .ok()
        .and_then(|count| count.checked_add(1))
        .filter(|maximum| *maximum <= MAX_RUNTIME_JOURNAL_ENTRIES)
        .ok_or(PreparedResultJournalError::InvalidState)?;
    let names = directory
        .entry_names(maximum, "read-journal-objects")
        .map_err(|source| anchored_journal_error(source, "read-journal-objects"))?;
    if names.len() as u64 != expected_count {
        return Err(PreparedResultJournalError::Incomplete);
    }
    for name in names {
        let name = name
            .into_string()
            .map_err(|_| PreparedResultJournalError::InvalidDirectory)?;
        if !family.is_file_name(&name) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
    }
    JournalObjectSource::open(&directory, family)
}

/// Validates one object subdirectory during namespace inventory.
///
/// A staged journal may also hold staging temporaries.
pub(super) fn validate_objects_directory(
    journal: &AnchoredDirectory,
    family: &ObjectFamily,
    incomplete: bool,
    total_entries: &mut usize,
) -> Result<(), PreparedResultJournalError> {
    let path = journal.path().join(family.directory);
    let directory = journal
        .open_directory(&path, "open-runtime-journal-objects")
        .map_err(|source| anchored_journal_error(source, "open-runtime-journal-objects"))?;
    let remaining = MAX_RUNTIME_JOURNAL_ENTRIES.saturating_sub(*total_entries);
    let names = directory
        .entry_names(remaining, "read-runtime-journal-objects")
        .map_err(|_| PreparedResultJournalError::RecoveryRequired)?;
    *total_entries = total_entries
        .checked_add(names.len())
        .ok_or(PreparedResultJournalError::RecoveryRequired)?;

    for name in names {
        let name = name
            .into_string()
            .map_err(|_| PreparedResultJournalError::InvalidDirectory)?;
        if !family.is_file_name(&name) && !(incomplete && family.is_temporary_name(&name)) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let file = directory
            .open_regular_optional(&path.join(&name), "open-runtime-journal-object")
            .map_err(|source| anchored_journal_error(source, "open-runtime-journal-object"))?
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        let length = file
            .length()
            .map_err(|source| anchored_journal_error(source, "inspect-runtime-journal-object"))?;
        if length > family.maximum_bytes as u64 {
            return Err(PreparedResultJournalError::InvalidState);
        }
    }
    Ok(())
}

/// Removes an orphan journal's object subdirectory and every file in it.
///
/// Returns whether the subdirectory existed. Any name other than an object or
/// staging temporary fails closed before anything is removed.
pub(super) fn remove_objects_directory(
    journal: &AnchoredDirectory,
    journal_path: &Path,
    family: &ObjectFamily,
) -> Result<bool, PreparedResultJournalError> {
    let path = journal_path.join(family.directory);
    let Some(directory) = journal
        .open_directory_optional(&path, "open-journal-orphan-objects")
        .map_err(|source| anchored_journal_error(source, "open-journal-orphan-objects"))?
    else {
        return Ok(false);
    };
    let names = directory
        .entry_names(MAX_RUNTIME_JOURNAL_ENTRIES, "read-journal-orphan-objects")
        .map_err(|source| anchored_journal_error(source, "read-journal-orphan-objects"))?;

    let mut files = Vec::with_capacity(names.len());
    for name in names {
        let name = name
            .into_string()
            .map_err(|_| PreparedResultJournalError::InvalidDirectory)?;
        if !family.is_file_name(&name) && !family.is_temporary_name(&name) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let file = directory
            .open_regular_optional(&path.join(&name), "open-journal-orphan-object")
            .map_err(|source| anchored_journal_error(source, "open-journal-orphan-object"))?
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        files.push(file);
    }
    for file in files {
        directory
            .remove_file(&file, "remove-journal-orphan-object")
            .map_err(|source| anchored_journal_error(source, "remove-journal-orphan-object"))?;
    }
    journal
        .remove_directory(&directory, "remove-journal-orphan-objects")
        .map_err(|source| anchored_journal_error(source, "remove-journal-orphan-objects"))?;
    Ok(true)
}

/// Reads journal-owned objects through a duplicated directory descriptor.
#[derive(Debug)]
pub(super) struct JournalObjectSource {
    directory: File,
    family: &'static ObjectFamily,
}

impl JournalObjectSource {
    fn open(
        directory: &AnchoredDirectory,
        family: &'static ObjectFamily,
    ) -> Result<Self, PreparedResultJournalError> {
        let directory = directory
            .try_clone_descriptor()
            .map_err(|source| anchored_journal_error(source, "retain-journal-objects"))?;
        Ok(Self { directory, family })
    }

    /// Reads one object, refusing anything longer than the family admits.
    pub(super) fn read(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let descriptor = openat2(
            &self.directory,
            self.family.file_name(id),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?;
        let mut bytes = Vec::new();
        File::from(descriptor)
            .take(self.family.maximum_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > self.family.maximum_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal object exceeds its format bound",
            ));
        }
        Ok(bytes)
    }
}
