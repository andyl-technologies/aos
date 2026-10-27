//! Finding replay records owned by one prepared-result journal.
//!
//! A prepared finding names the replay records both minimization passes
//! retain by identity. Staging copies each record into the journal's
//! [`objects`](super::objects) family before the result and state files are
//! written, so a journal never depends on the preparation's record directory:
//!
//! ```text
//! <journal>/records/<64 hex>.record                one complete record
//! <journal>/records/.<64 hex>.record.<pid>.<n>     staging temporary
//! ```
//!
//! State binds the number of retained records and a hash over their ordered
//! identities.

use std::io;
use std::sync::Arc;

use crucible_store::content_store::ContentId;

use super::PreparedResultJournalError;
use super::objects::{self, JournalObjectSource, ObjectFamily};
use crate::anchored_fs::AnchoredDirectory;
use crate::{
    MAX_REPLAY_RECORD_BYTES, PreparedSemanticAttemptResult, ReplayRecordSource, ReplayRecordSources,
};

/// Journal subdirectory and file layout for retained replay records.
pub(super) static RECORDS: ObjectFamily = ObjectFamily {
    directory: "records",
    suffix: ".record",
    maximum_bytes: MAX_REPLAY_RECORD_BYTES,
};

/// Domain separating the journal's record-set hash from other content.
const RECORD_SET_HASH_DOMAIN: &str = "crucible.executor.prepared-result-journal-records.v1";

/// Returns the count and ordered hash of the records a result retains.
pub(super) fn record_set_identity(records: &[ContentId]) -> (u64, [u8; 32]) {
    let mut hasher = blake3::Hasher::new_derive_key(RECORD_SET_HASH_DOMAIN);
    for record in records {
        let encoded = record.encode();
        hasher.update(&(encoded.len() as u64).to_be_bytes());
        hasher.update(encoded.as_bytes());
    }
    (records.len() as u64, *hasher.finalize().as_bytes())
}

/// Copies every record `result` retains into a new journal subdirectory.
///
/// Each record is read from the result's current stores, authenticated
/// against its identity, and written atomically, one at a time. Returns the
/// result rebound to read only the journal's copies.
pub(super) fn stage_records(
    root: &AnchoredDirectory,
    result: PreparedSemanticAttemptResult,
) -> Result<PreparedSemanticAttemptResult, PreparedResultJournalError> {
    let directory = objects::create_directory(root, &RECORDS)?;
    result.try_for_each_replay_record(|record, bytes| {
        objects::write_object(&directory, &RECORDS, record, bytes)
    })?;

    let records = objects::seal_directory(&directory, &RECORDS)?;
    Ok(result.with_replay_records(into_sources(records)))
}

/// Opens the records of a journal whose state binds `expected_count` of them.
pub(super) fn open_records(
    root: &AnchoredDirectory,
    expected_count: u64,
) -> Result<ReplayRecordSources, PreparedResultJournalError> {
    objects::open_objects(root, &RECORDS, expected_count).map(into_sources)
}

fn into_sources(source: JournalObjectSource) -> ReplayRecordSources {
    let mut sources = ReplayRecordSources::default();
    sources.push(Arc::new(JournalRecordSource(source)));
    sources
}

/// Reads journal-owned replay records.
#[derive(Debug)]
struct JournalRecordSource(JournalObjectSource);

impl ReplayRecordSource for JournalRecordSource {
    fn record(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.0.read(id)
    }
}
