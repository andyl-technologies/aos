//! Attempt-log segments owned by one prepared-result journal.
//!
//! A prepared result names its log segments by identity. Staging copies each
//! referenced segment into the journal's [`objects`](super::objects) family
//! before the result and state files are written:
//!
//! ```text
//! <journal>/segments/<64 hex>.segment              one complete segment
//! <journal>/segments/.<64 hex>.segment.<pid>.<n>   staging temporary
//! ```
//!
//! State binds the number of referenced segments and a hash over their ordered
//! references.

use std::io;
use std::sync::Arc;

use crucible_cas::content_store::ContentId;

use super::PreparedResultJournalError;
use super::objects::{self, JournalObjectSource, ObjectFamily};
use crate::anchored_fs::AnchoredDirectory;
use crate::{
    AttemptLogSegmentRef, AttemptLogSegmentSource, AttemptLogSegmentSources,
    MAX_ATTEMPT_LOG_SEGMENT_BYTES, PreparedSemanticAttemptResult,
};

/// Journal subdirectory and file layout for referenced segments.
pub(super) static SEGMENTS: ObjectFamily = ObjectFamily {
    directory: "segments",
    suffix: ".segment",
    maximum_bytes: MAX_ATTEMPT_LOG_SEGMENT_BYTES,
};

/// Domain separating the journal's segment-set hash from other content.
const SEGMENT_SET_HASH_DOMAIN: &str = "crucible.executor.prepared-result-journal-segments.v1";

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
    let directory = objects::create_directory(root, &SEGMENTS)?;

    for segment in result.referenced_log_segments() {
        let bytes = result
            .log_segments()
            .segment(segment.id)
            .map_err(|source| {
                segment_error(segment.id, crate::AttemptEventLogError::Store { source })
            })?;
        crate::decode_segment(&segment, &bytes)
            .map_err(|source| segment_error(segment.id, source))?;
        objects::write_object(&directory, &SEGMENTS, segment.id, &bytes)?;
    }

    let segments = objects::seal_directory(&directory, &SEGMENTS)?;
    Ok(result.with_log_segments(into_sources(segments)))
}

/// Opens the segments of a journal whose state binds `expected_count` of them.
pub(super) fn open_segments(
    root: &AnchoredDirectory,
    expected_count: u64,
) -> Result<AttemptLogSegmentSources, PreparedResultJournalError> {
    objects::open_objects(root, &SEGMENTS, expected_count).map(into_sources)
}

fn into_sources(source: JournalObjectSource) -> AttemptLogSegmentSources {
    let mut sources = AttemptLogSegmentSources::default();
    sources.push(Arc::new(JournalSegmentSource(source)));
    sources
}

/// Reads journal-owned segments.
#[derive(Debug)]
struct JournalSegmentSource(JournalObjectSource);

impl AttemptLogSegmentSource for JournalSegmentSource {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.0.read(id)
    }
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
