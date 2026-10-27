//! Content-addressed storage for the records a finding's replays retain.
//!
//! Signature-preserving minimization replays a finding up to twice per
//! candidate, and every observed replay yields typed campaign records:
//! configurations, measurement sets, property verdicts, coverage projections,
//! selectable declarations, choice domains, choice opportunities, and
//! selections. A finding retains each distinct record once. Opportunities and
//! selections grow with the replayed run, so the records are written here as
//! they arrive, and the replay transcript and prepared result keep only their
//! identities.
//!
//! - [`ReplayRecordStore`] is the store one finding preparation writes: a
//!   directory created in the executor's attempt namespace, or memory without
//!   one.
//! - [`MemoryReplayRecordStore`] keeps records in memory for in-process callers
//!   and tests.
//! - [`ReplayRecordSources`] holds read handles to every store that may hold a
//!   prepared result's records.
//!
//! A directory holds one file per record, named by the lowercase hex digest of
//! its identity:
//!
//! ```text
//! <directory>/
//!   <64 hex digits>.record                  complete, synchronized record
//!   .<64 hex digits>.<pid>.<n>.partial      in-flight write, never read
//! ```
//!
//! Stores return whatever bytes they hold under an identity. Every reader
//! decodes the record and rederives its identity with [`load_replay_record`],
//! so a store that lacks a record, or holds foreign bytes under its name, can
//! only make a read fail.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use crucible_campaign::{
    CampaignCodecError, ChoiceDomain, ChoiceDomainId, ChoiceOpportunity, ChoiceOpportunityId,
    ConfigurationArtifact, ConfigurationArtifactId, CoverageProjection, CoverageProjectionId,
    MeasurementSet, MeasurementSetId, PropertyVerdictSet, PropertyVerdictSetId,
    SelectableDeclaration, SelectableId, Selection, SelectionId,
};
use crucible_store::content_store::ContentId;

use crate::attempt_event_log::{AttemptLogDirectory, read_content_file, write_content_file};

/// Maximum canonical bytes of one retained replay record.
pub const MAX_REPLAY_RECORD_BYTES: usize = 64 * 1024 * 1024;

/// Suffix of one complete record file.
const RECORD_FILE_SUFFIX: &str = ".record";

/// Read access to retained replay records, addressed by content identity.
pub trait ReplayRecordSource {
    /// Reads one record's canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the record is absent, unreadable, or larger
    /// than [`MAX_REPLAY_RECORD_BYTES`].
    fn record(&self, id: ContentId) -> io::Result<Vec<u8>>;
}

/// In-memory record store for bounded in-process callers and tests.
///
/// Record bytes are immutable and shared, so cloning a store copies only its
/// index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryReplayRecordStore {
    records: BTreeMap<ContentId, Arc<[u8]>>,
}

impl MemoryReplayRecordStore {
    /// Returns the number of stored records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no record is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn put(&mut self, id: ContentId, bytes: &[u8]) {
        self.records.entry(id).or_insert_with(|| Arc::from(bytes));
    }
}

impl ReplayRecordSource for MemoryReplayRecordStore {
    fn record(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.records
            .get(&id)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "replay record absent"))
    }
}

/// Record store backed by one host-owned directory.
///
/// Cloning shares the directory, which is removed when the last handle drops.
#[derive(Clone, Debug)]
pub(crate) struct DirectoryReplayRecordStore {
    directory: Arc<AttemptLogDirectory>,
}

impl ReplayRecordSource for DirectoryReplayRecordStore {
    fn record(&self, id: ContentId) -> io::Result<Vec<u8>> {
        read_content_file(
            self.directory.path(),
            id,
            RECORD_FILE_SUFFIX,
            MAX_REPLAY_RECORD_BYTES,
        )
    }
}

/// The record store one finding preparation writes: memory or one directory.
#[derive(Clone, Debug)]
pub(crate) enum ReplayRecordStore {
    /// Records held in memory.
    Memory(MemoryReplayRecordStore),
    /// Records held as files in one directory.
    Directory(DirectoryReplayRecordStore),
}

impl Default for ReplayRecordStore {
    fn default() -> Self {
        Self::memory()
    }
}

impl ReplayRecordStore {
    /// Keeps records in memory.
    pub(crate) const fn memory() -> Self {
        Self::Memory(MemoryReplayRecordStore {
            records: BTreeMap::new(),
        })
    }

    /// Writes records into `directory`, which the store then shares.
    pub(crate) fn directory(directory: Arc<AttemptLogDirectory>) -> Self {
        Self::Directory(DirectoryReplayRecordStore { directory })
    }

    /// Stores one record's canonical bytes under its identity.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a directory record cannot be durably written.
    pub(crate) fn put(&mut self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Memory(store) => {
                store.put(id, bytes);
                Ok(())
            }
            Self::Directory(store) => {
                write_content_file(store.directory.path(), id, RECORD_FILE_SUFFIX, bytes)
            }
        }
    }

    /// Returns a read handle to everything this store holds now and later.
    ///
    /// A memory store is snapshotted; a directory store is shared.
    pub(crate) fn sources(&self) -> ReplayRecordSources {
        let mut sources = ReplayRecordSources::default();
        match self {
            Self::Memory(store) if store.is_empty() => {}
            Self::Memory(store) => sources.push(Arc::new(store.clone())),
            Self::Directory(store) => sources.push(Arc::new(store.clone())),
        }
        sources
    }
}

impl ReplayRecordSource for ReplayRecordStore {
    fn record(&self, id: ContentId) -> io::Result<Vec<u8>> {
        match self {
            Self::Memory(store) => store.record(id),
            Self::Directory(store) => store.record(id),
        }
    }
}

/// Shared read handles to every store that may hold a result's records.
///
/// Lookups try each store in order. Every typed read authenticates the bytes
/// it receives, so the order only decides which copy is read.
#[derive(Clone, Default)]
pub struct ReplayRecordSources {
    sources: Vec<Arc<dyn ReplayRecordSource + Send + Sync>>,
}

impl ReplayRecordSources {
    /// Adds `source` after every store already held.
    pub fn push(&mut self, source: Arc<dyn ReplayRecordSource + Send + Sync>) {
        self.sources.push(source);
    }

    /// Adds every store of `other` after the stores already held.
    pub fn extend(&mut self, other: Self) {
        self.sources.extend(other.sources);
    }

    /// Returns whether no store is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

impl std::fmt::Debug for ReplayRecordSources {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayRecordSources")
            .field("stores", &self.sources.len())
            .finish()
    }
}

impl From<MemoryReplayRecordStore> for ReplayRecordSources {
    fn from(store: MemoryReplayRecordStore) -> Self {
        ReplayRecordStore::Memory(store).sources()
    }
}

impl ReplayRecordSource for ReplayRecordSources {
    fn record(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let mut last_error = None;
        for source in &self.sources {
            match source.record(id) {
                Ok(bytes) => return Ok(bytes),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "replay record absent")))
    }
}

/// One typed campaign record a finding replay retains.
pub(crate) trait ReplayRecord: Sized {
    /// The record's typed content identity.
    type Id: Copy + Ord;

    /// Decodes strict canonical record bytes.
    fn decode(bytes: &[u8]) -> Result<Self, CampaignCodecError>;

    /// Returns strict canonical record bytes.
    fn encode(&self) -> Vec<u8>;

    /// Derives the record's typed identity.
    fn record_id(&self) -> Result<Self::Id, CampaignCodecError>;

    /// Returns the backend-independent identity behind a typed identity.
    fn content_id(id: Self::Id) -> ContentId;
}

macro_rules! replay_record {
    ($($record:ty => $id:ty),+ $(,)?) => {$(
        impl ReplayRecord for $record {
            type Id = $id;

            fn decode(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
                <$record>::from_canonical_bytes(bytes)
            }

            fn encode(&self) -> Vec<u8> {
                self.canonical_bytes()
            }

            fn record_id(&self) -> Result<Self::Id, CampaignCodecError> {
                self.id()
            }

            fn content_id(id: Self::Id) -> ContentId {
                id.content_id()
            }
        }
    )+};
}

replay_record!(
    ConfigurationArtifact => ConfigurationArtifactId,
    MeasurementSet => MeasurementSetId,
    PropertyVerdictSet => PropertyVerdictSetId,
    CoverageProjection => CoverageProjectionId,
    SelectableDeclaration => SelectableId,
    ChoiceDomain => ChoiceDomainId,
    ChoiceOpportunity => ChoiceOpportunityId,
    Selection => SelectionId,
);

/// Failure to write or read one retained replay record.
#[derive(Debug, thiserror::Error)]
pub enum ReplayRecordError {
    /// The record store could not be created.
    #[error("replay record store is unavailable: {source}")]
    StoreUnavailable {
        /// Creation failure.
        source: io::Error,
    },
    /// The record could not be durably written to its store.
    #[error("replay record {record} could not be written: {source}")]
    Unwritable {
        /// Content identity of the record being written.
        record: ContentId,
        /// Write failure.
        source: io::Error,
    },
    /// The record is absent or unreadable in every store.
    #[error("replay record {record} is unavailable: {source}")]
    Unavailable {
        /// Content identity of the requested record.
        record: ContentId,
        /// Read failure from the last store tried.
        source: io::Error,
    },
    /// The bytes do not decode as the requested record type.
    #[error("replay record {record} does not decode: {source}")]
    Decode {
        /// Content identity of the requested record.
        record: ContentId,
        /// Strict decoder failure.
        source: CampaignCodecError,
    },
    /// The decoded record derives a different identity.
    #[error("replay record {record} holds a different record")]
    Substituted {
        /// Content identity of the requested record.
        record: ContentId,
    },
}

/// Executor publication reports an unreadable local record as a store failure.
impl From<ReplayRecordError> for crucible_campaign::CampaignRepositoryError {
    fn from(error: ReplayRecordError) -> Self {
        use crucible_store::content_store::StoreError;

        match error {
            ReplayRecordError::StoreUnavailable { source } => Self::Store(StoreError::StreamIo {
                operation: "create-finding-replay-record-store",
                source,
            }),
            ReplayRecordError::Unwritable { source, .. } => Self::Store(StoreError::StreamIo {
                operation: "write-finding-replay-record",
                source,
            }),
            ReplayRecordError::Unavailable { source, .. } => Self::Store(StoreError::StreamIo {
                operation: "read-finding-replay-record",
                source,
            }),
            ReplayRecordError::Decode { source, .. } => Self::Codec(source),
            ReplayRecordError::Substituted { record } => {
                Self::Store(StoreError::Corrupt { id: record })
            }
        }
    }
}

/// Reads one record and authenticates it against its typed identity.
///
/// Returns the record with its canonical byte length.
///
/// # Errors
///
/// Returns [`ReplayRecordError`] when the record is absent, does not decode,
/// or derives another identity.
pub(crate) fn load_replay_record<T: ReplayRecord>(
    source: &dyn ReplayRecordSource,
    id: T::Id,
) -> Result<(T, usize), ReplayRecordError> {
    let record = T::content_id(id);
    let bytes = source
        .record(record)
        .map_err(|source| ReplayRecordError::Unavailable { record, source })?;
    let value = T::decode(&bytes).map_err(|source| ReplayRecordError::Decode { record, source })?;
    let derived = value
        .record_id()
        .map_err(|source| ReplayRecordError::Decode { record, source })?;
    if derived != id {
        return Err(ReplayRecordError::Substituted { record });
    }
    Ok((value, bytes.len()))
}

/// Reads one record named only by its content identity and types it.
///
/// The record is decoded as `T` and its derived identity must equal
/// `content`, which proves both the bytes and the record type. Returns the
/// typed identity with the record's canonical length.
///
/// # Errors
///
/// Returns [`ReplayRecordError`] when the record is absent, does not decode as
/// `T`, or derives another identity.
pub(crate) fn load_replay_record_by_content<T: ReplayRecord>(
    source: &dyn ReplayRecordSource,
    content: ContentId,
) -> Result<(T::Id, usize), ReplayRecordError> {
    let bytes = source
        .record(content)
        .map_err(|source| ReplayRecordError::Unavailable {
            record: content,
            source,
        })?;
    let value = T::decode(&bytes).map_err(|source| ReplayRecordError::Decode {
        record: content,
        source,
    })?;
    let id = value
        .record_id()
        .map_err(|source| ReplayRecordError::Decode {
            record: content,
            source,
        })?;
    if T::content_id(id) != content {
        return Err(ReplayRecordError::Substituted { record: content });
    }
    Ok((id, bytes.len()))
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeSet;

    use crucible_campaign::CampaignHash;

    use super::*;

    fn coverage(label: &[u8]) -> CoverageProjection {
        CoverageProjection::new(
            BTreeSet::from([CampaignHash::derive("test", label)]),
            BTreeSet::new(),
        )
        .expect("coverage fixture")
    }

    #[test]
    fn directory_records_round_trip_and_authenticate_on_read() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let directory =
            AttemptLogDirectory::create(parent.path().join("records")).expect("record directory");
        let mut store = ReplayRecordStore::directory(directory);
        let first = coverage(b"first");
        let second = coverage(b"second");
        let first_id = first.id().expect("first identity");
        let second_id = second.id().expect("second identity");

        store
            .put(first_id.content_id(), &first.canonical_bytes())
            .expect("write first record");
        store
            .put(first_id.content_id(), &first.canonical_bytes())
            .expect("rewriting a record is idempotent");
        let sources = store.sources();

        let (loaded, length) =
            load_replay_record::<CoverageProjection>(&sources, first_id).expect("read back");
        assert_eq!(loaded, first);
        assert_eq!(length, first.canonical_bytes().len());
        assert!(matches!(
            load_replay_record::<CoverageProjection>(&sources, second_id),
            Err(ReplayRecordError::Unavailable { .. })
        ));

        // Foreign bytes under a record's name never authenticate.
        store
            .put(second_id.content_id(), &first.canonical_bytes())
            .expect("write substituted record");
        assert!(matches!(
            load_replay_record::<CoverageProjection>(&sources, second_id),
            Err(ReplayRecordError::Substituted { .. })
        ));
    }

    #[test]
    fn memory_sources_are_a_snapshot_of_the_store() {
        let mut store = ReplayRecordStore::default();
        let record = coverage(b"memory");
        let id = record.id().expect("identity");
        let empty = store.sources();

        store
            .put(id.content_id(), &record.canonical_bytes())
            .expect("memory write");

        assert!(empty.is_empty());
        assert!(load_replay_record::<CoverageProjection>(&store.sources(), id).is_ok());
    }
}
