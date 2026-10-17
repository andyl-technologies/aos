//! Attempt-log and resolved-effect trace segments owned by one
//! prepared-result journal.
//!
//! A prepared result names its attempt-log segments and its resolved-effect
//! trace segments by identity. Staging copies each referenced segment into
//! the journal's [`objects`](super::objects) family before the result and
//! state files are written. Both kinds share one directory because their
//! content identities are domain-separated by object kind, so digests never
//! collide:
//!
//! ```text
//! <journal>/segments/<64 hex>.segment              one complete segment
//! <journal>/segments/.<64 hex>.segment.<pid>.<n>   staging temporary
//! ```
//!
//! State binds the number of referenced segments and a hash over their ordered
//! references, attempt-log segments first, then trace segments.

use std::io;
use std::sync::Arc;

use crucible_cas::content_store::ContentId;

use super::PreparedResultJournalError;
use super::objects::{self, JournalObjectSource, ObjectFamily};
use crate::anchored_fs::AnchoredDirectory;
use crate::{
    AttemptLogSegmentSource, AttemptLogSegmentSources, MAX_ATTEMPT_LOG_SEGMENT_BYTES,
    PreparedSemanticAttemptResult,
};

/// Journal subdirectory and file layout for referenced segments.
pub(super) static SEGMENTS: ObjectFamily = ObjectFamily {
    directory: "segments",
    suffix: ".segment",
    maximum_bytes: MAX_ATTEMPT_LOG_SEGMENT_BYTES,
};

/// Domain separating the journal's segment-set hash from other content.
const SEGMENT_SET_HASH_DOMAIN: &str = "crucible.executor.prepared-result-journal-segments.v2";

/// Returns the count and ordered hash of the segments a result references.
///
/// Attempt-log references come first, then the trace segment identities; the
/// count of each is hashed before its list, so neither list can absorb the
/// other.
pub(super) fn segment_set_identity(result: &PreparedSemanticAttemptResult) -> (u64, [u8; 32]) {
    let log_segments = result.referenced_log_segments();
    let trace_segments = result.referenced_trace_segments();
    let mut hasher = blake3::Hasher::new_derive_key(SEGMENT_SET_HASH_DOMAIN);

    hasher.update(&(log_segments.len() as u64).to_be_bytes());
    for segment in &log_segments {
        hash_identity(&mut hasher, segment.id);
        hasher.update(&segment.first_sequence.to_be_bytes());
        hasher.update(&segment.entry_count.to_be_bytes());
        hasher.update(&segment.encoded_bytes.to_be_bytes());
    }
    hasher.update(&(trace_segments.len() as u64).to_be_bytes());
    for segment in trace_segments {
        hash_identity(&mut hasher, *segment);
    }

    let count = (log_segments.len() + trace_segments.len()) as u64;
    (count, *hasher.finalize().as_bytes())
}

fn hash_identity(hasher: &mut blake3::Hasher, id: ContentId) {
    let encoded = id.encode();
    hasher.update(&(encoded.len() as u64).to_be_bytes());
    hasher.update(encoded.as_bytes());
}

/// Copies every segment `result` references into a new journal subdirectory.
///
/// Each segment is read from the result's current stores, authenticated
/// against its reference, and written atomically, one at a time. Trace
/// segments are authenticated by identity here and decoded when the result is
/// verified. Returns the result rebound to read only the journal's copies.
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
    if let Some(trace_sources) = result.observation().resolved_effect_trace_segments() {
        for &segment in result.referenced_trace_segments() {
            let bytes = read_trace_segment(trace_sources, segment)?;
            objects::write_object(&directory, &SEGMENTS, segment, &bytes)?;
        }
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

/// Reads one trace segment and authenticates it against its identity.
fn read_trace_segment(
    sources: &AttemptLogSegmentSources,
    segment: ContentId,
) -> Result<Vec<u8>, PreparedResultJournalError> {
    let bytes = sources
        .segment(segment)
        .map_err(|source| segment_error(segment, crate::AttemptEventLogError::Store { source }))?;
    if bytes.len() > MAX_ATTEMPT_LOG_SEGMENT_BYTES || !segment.authenticates(&bytes) {
        return Err(segment_error(
            segment,
            crate::AttemptEventLogError::Store {
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trace segment does not authenticate against its identity",
                ),
            },
        ));
    }
    Ok(bytes)
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
