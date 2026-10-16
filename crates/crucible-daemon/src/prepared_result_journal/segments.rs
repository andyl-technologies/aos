//! Attempt-log segments owned by one prepared-result journal.
//!
//! A prepared result names its log segments by identity. Staging copies each
//! referenced segment into the journal, authenticated and synchronized, before
//! the result and state files are written, so a journal never depends on the
//! attempt's own segment directory once it is staged:
//!
//! ```text
//! <journal>/segments/<64 hex>.segment              one complete segment
//! <journal>/segments/.<64 hex>.segment.<pid>.<n>   staging temporary
//! ```
//!
//! State binds the number of referenced segments and a hash over their ordered
//! references. Readers resolve segment names through a duplicated directory
//! descriptor, so a reopened result keeps reading the same inode across the
//! staged-to-visible rename.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use crucible_cas::content_store::ContentId;
use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

use super::{
    MAX_RUNTIME_JOURNAL_ENTRIES, PreparedResultJournalError, anchored_journal_error,
    is_current_temporary_name, is_lower_hex, write_atomic,
};
use crate::anchored_fs::AnchoredDirectory;
use crate::{
    AttemptLogSegmentRef, AttemptLogSegmentSource, AttemptLogSegmentSources,
    MAX_ATTEMPT_LOG_SEGMENT_BYTES, PreparedSemanticAttemptResult,
};

/// Name of the journal subdirectory that holds referenced segments.
pub(super) const JOURNAL_SEGMENTS_DIRECTORY: &str = "segments";

/// Domain separating the journal's segment-set hash from other content.
const SEGMENT_SET_HASH_DOMAIN: &str = "crucible.executor.prepared-result-journal-segments.v1";

/// Suffix of one complete segment file.
const SEGMENT_FILE_SUFFIX: &str = ".segment";

/// Returns the count and ordered hash of the segments a result references.
pub(super) fn segment_set_identity(segments: &[AttemptLogSegmentRef]) -> (u64, [u8; 32]) {
    let mut hasher = blake3::Hasher::new_derive_key(SEGMENT_SET_HASH_DOMAIN);
    for segment in segments {
        let encoded = segment.id.encode();
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(encoded.as_bytes());
        hasher.update(&segment.first_sequence.to_be_bytes());
        hasher.update(&segment.entry_count.to_be_bytes());
        hasher.update(&segment.encoded_bytes.to_be_bytes());
    }
    (segments.len() as u64, *hasher.finalize().as_bytes())
}

/// Copies every segment `result` references into a new journal subdirectory.
///
/// Each segment is read from the result's current stores, authenticated
/// against its reference, and written atomically, one at a time. Returns the
/// result rebound to read only the journal's copies.
pub(super) fn stage_segments(
    root: &AnchoredDirectory,
    result: PreparedSemanticAttemptResult,
) -> Result<PreparedSemanticAttemptResult, PreparedResultJournalError> {
    let path = root.path().join(JOURNAL_SEGMENTS_DIRECTORY);
    let directory = root
        .create_new_directory(&path, "create-journal-segments")
        .map_err(|source| anchored_journal_error(source, "create-journal-segments"))?;

    for segment in result.referenced_log_segments() {
        let bytes = result
            .log_segments()
            .segment(segment.id)
            .map_err(|source| {
                segment_error(segment.id, crate::AttemptEventLogError::Store { source })
            })?;
        crate::decode_segment(&segment, &bytes)
            .map_err(|source| segment_error(segment.id, source))?;
        write_atomic(&directory, &segment_file_name(segment.id), &bytes)?;
    }

    directory
        .sync()
        .map_err(|source| anchored_journal_error(source, "sync-journal-segments"))?;
    let segments = JournalSegmentSource::open(&directory)?;
    Ok(result.with_log_segments(segments.into_sources()))
}

/// Opens the segments of a journal whose state binds `expected_count` of them.
///
/// The directory must hold exactly that many complete segment files and
/// nothing else. Their contents are authenticated when the result is decoded.
pub(super) fn open_segments(
    root: &AnchoredDirectory,
    expected_count: u64,
) -> Result<AttemptLogSegmentSources, PreparedResultJournalError> {
    let path = root.path().join(JOURNAL_SEGMENTS_DIRECTORY);
    let directory = root
        .open_directory(&path, "open-journal-segments")
        .map_err(|source| anchored_journal_error(source, "open-journal-segments"))?;
    let maximum = usize::try_from(expected_count)
        .ok()
        .and_then(|count| count.checked_add(1))
        .filter(|maximum| *maximum <= MAX_RUNTIME_JOURNAL_ENTRIES)
        .ok_or(PreparedResultJournalError::InvalidState)?;
    let names = directory
        .entry_names(maximum, "read-journal-segments")
        .map_err(|source| anchored_journal_error(source, "read-journal-segments"))?;
    if names.len() as u64 != expected_count {
        return Err(PreparedResultJournalError::Incomplete);
    }
    for name in names {
        let name = name
            .into_string()
            .map_err(|_| PreparedResultJournalError::InvalidDirectory)?;
        if !is_segment_file_name(&name) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
    }
    Ok(JournalSegmentSource::open(&directory)?.into_sources())
}

/// Validates a journal's segment subdirectory during namespace inventory.
///
/// A staged journal may also hold staging temporaries.
pub(super) fn validate_segments_directory(
    journal: &AnchoredDirectory,
    incomplete: bool,
    total_entries: &mut usize,
) -> Result<(), PreparedResultJournalError> {
    let path = journal.path().join(JOURNAL_SEGMENTS_DIRECTORY);
    let directory = journal
        .open_directory(&path, "open-runtime-journal-segments")
        .map_err(|source| anchored_journal_error(source, "open-runtime-journal-segments"))?;
    let remaining = MAX_RUNTIME_JOURNAL_ENTRIES.saturating_sub(*total_entries);
    let names = directory
        .entry_names(remaining, "read-runtime-journal-segments")
        .map_err(|_| PreparedResultJournalError::RecoveryRequired)?;
    *total_entries = total_entries
        .checked_add(names.len())
        .ok_or(PreparedResultJournalError::RecoveryRequired)?;

    for name in names {
        let name = name
            .into_string()
            .map_err(|_| PreparedResultJournalError::InvalidDirectory)?;
        if !is_segment_file_name(&name) && !(incomplete && is_segment_temporary_name(&name)) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let file = directory
            .open_regular_optional(&path.join(&name), "open-runtime-journal-segment")
            .map_err(|source| anchored_journal_error(source, "open-runtime-journal-segment"))?
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        let length = file
            .length()
            .map_err(|source| anchored_journal_error(source, "inspect-runtime-journal-segment"))?;
        if length > MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64 {
            return Err(PreparedResultJournalError::InvalidState);
        }
    }
    Ok(())
}

/// Removes an orphan journal's segment subdirectory and every file in it.
///
/// Returns whether the subdirectory existed. Any name other than a segment or
/// staging temporary fails closed before anything is removed.
pub(super) fn remove_segments_directory(
    journal: &AnchoredDirectory,
    journal_path: &Path,
) -> Result<bool, PreparedResultJournalError> {
    let path = journal_path.join(JOURNAL_SEGMENTS_DIRECTORY);
    let Some(directory) = journal
        .open_directory_optional(&path, "open-journal-orphan-segments")
        .map_err(|source| anchored_journal_error(source, "open-journal-orphan-segments"))?
    else {
        return Ok(false);
    };
    let names = directory
        .entry_names(MAX_RUNTIME_JOURNAL_ENTRIES, "read-journal-orphan-segments")
        .map_err(|source| anchored_journal_error(source, "read-journal-orphan-segments"))?;

    let mut files = Vec::with_capacity(names.len());
    for name in names {
        let name = name
            .into_string()
            .map_err(|_| PreparedResultJournalError::InvalidDirectory)?;
        if !is_segment_file_name(&name) && !is_segment_temporary_name(&name) {
            return Err(PreparedResultJournalError::InvalidDirectory);
        }
        let file = directory
            .open_regular_optional(&path.join(&name), "open-journal-orphan-segment")
            .map_err(|source| anchored_journal_error(source, "open-journal-orphan-segment"))?
            .ok_or(PreparedResultJournalError::InvalidDirectory)?;
        files.push(file);
    }
    for file in files {
        directory
            .remove_file(&file, "remove-journal-orphan-segment")
            .map_err(|source| anchored_journal_error(source, "remove-journal-orphan-segment"))?;
    }
    journal
        .remove_directory(&directory, "remove-journal-orphan-segments")
        .map_err(|source| anchored_journal_error(source, "remove-journal-orphan-segments"))?;
    Ok(true)
}

/// Reads journal-owned segments through a duplicated directory descriptor.
#[derive(Debug)]
struct JournalSegmentSource {
    directory: File,
}

impl JournalSegmentSource {
    fn open(directory: &AnchoredDirectory) -> Result<Self, PreparedResultJournalError> {
        let directory = directory
            .try_clone_descriptor()
            .map_err(|source| anchored_journal_error(source, "retain-journal-segments"))?;
        Ok(Self { directory })
    }

    fn into_sources(self) -> AttemptLogSegmentSources {
        let mut sources = AttemptLogSegmentSources::default();
        sources.push(Arc::new(self));
        sources
    }
}

impl AttemptLogSegmentSource for JournalSegmentSource {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let descriptor = openat2(
            &self.directory,
            segment_file_name(id),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )?;
        let mut bytes = Vec::new();
        File::from(descriptor)
            .take(MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_ATTEMPT_LOG_SEGMENT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal segment exceeds its format bound",
            ));
        }
        Ok(bytes)
    }
}

fn segment_file_name(id: ContentId) -> String {
    let digest = id
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{digest}{SEGMENT_FILE_SUFFIX}")
}

fn is_segment_file_name(name: &str) -> bool {
    name.strip_suffix(SEGMENT_FILE_SUFFIX)
        .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn is_segment_temporary_name(name: &str) -> bool {
    name.get(1..65)
        .filter(|digest| is_lower_hex(digest, 64))
        .is_some_and(|digest| {
            is_current_temporary_name(name, &format!("{digest}{SEGMENT_FILE_SUFFIX}"))
        })
}

fn segment_error(
    segment: ContentId,
    source: crate::AttemptEventLogError,
) -> PreparedResultJournalError {
    PreparedResultJournalError::Segment { segment, source }
}

#[cfg(test)]
#[path = "segments_tests.rs"]
mod tests;
