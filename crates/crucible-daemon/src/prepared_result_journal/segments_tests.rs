//! Journal-owned segment staging, reopening, and fail-closed validation.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crucible::model::{MeasurementDefinitions, MeasurementTerminalState};
use crucible::{
    EventAttributeValue, EventLevel, EventLogTime, EventPayload, EventSource,
    SchedulerEventLogClass, SchedulerEventLogEntry, VirtualTime,
};
use crucible_campaign::{CampaignHash, ConfigurationId, ExecutionId, ScenarioDefId};
use tempfile::TempDir;

use super::super::tests::{TEST_PAYLOAD_LIMIT, observation_candidate, semantic_key};
use super::super::{
    DirectoryPreparedResultJournal, PreparedResultJournalError, PreparedResultJournalNamespace,
};
use super::JOURNAL_SEGMENTS_DIRECTORY;
use crate::{
    AttemptLogSegmentSource, AttemptLogSegmentSources,
    MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES, MemorySegmentStore,
    PreparedSemanticAttemptResult, PreparedSemanticResultCodecError,
};

/// Text carried by every fixture entry, so a payload that embedded segment
/// bytes would contain it.
const ENTRY_TEXT_MARKER: &str = "journal-segment-fixture-text";

const V9_MAGIC: &[u8] = b"crucible.executor.prepared-semantic-attempt-result.v9\0";

fn entry(sequence: u64) -> SchedulerEventLogEntry {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("text"),
        EventAttributeValue::String(ENTRY_TEXT_MARKER.repeat(64)),
    );
    SchedulerEventLogEntry::from_retained_open_event(
        sequence,
        EventLogTime::from_virtual_time(VirtualTime { ticks: 0 }),
        EventSource::Engine,
        EventLevel::Info,
        SchedulerEventLogClass::Observational,
        EventPayload::new("console_output", attributes),
    )
    .unwrap_or_else(|error| panic!("fixture entry should build: {error}"))
}

/// Builds a result whose measurement leaf references a non-empty log.
fn result_with_segments(
    marker: u8,
    key: crate::AttemptExecutionKey,
) -> (PreparedSemanticAttemptResult, MemorySegmentStore) {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", &[marker, 0]));
    let configuration = ConfigurationId::from_hash(CampaignHash::derive("test", &[marker, 2]));
    let (publication, segments) = crate::crucible_measurement::test_measurement_publication(
        scenario,
        configuration,
        &MeasurementDefinitions::empty(),
        (0..8).map(entry).collect(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: VirtualTime { ticks: 0 },
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: true,
        },
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    )
    .unwrap_or_else(|error| panic!("measurement publication: {error}"));
    let (evidence, _, measurements) = publication.into_parts();
    let candidate = observation_candidate(marker, key.attempt(), measurements);
    let result =
        PreparedSemanticAttemptResult::new(candidate, vec![evidence], segments.clone(), None)
            .unwrap_or_else(|error| panic!("prepared result: {error}"));
    assert!(!result.referenced_log_segments().is_empty());
    (result, segments)
}

fn segment_files(journal: &DirectoryPreparedResultJournal) -> Vec<PathBuf> {
    let mut files = fs::read_dir(journal.root().join(JOURNAL_SEGMENTS_DIRECTORY))
        .unwrap_or_else(|error| panic!("list journal segments: {error}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("journal segment entry: {error}"))
                .path()
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

/// Returns a source that serves different bytes under every identity.
struct SubstitutingSource;

impl AttemptLogSegmentSource for SubstitutingSource {
    fn segment(&self, _id: crucible_cas::content_store::ContentId) -> std::io::Result<Vec<u8>> {
        Ok(b"not the referenced segment".to_vec())
    }
}

#[test]
fn v9_payload_names_segments_without_their_bytes() {
    let key = semantic_key(b"v9-payload");
    let (result, segments) = result_with_segments(0x71, key);

    let payload = result
        .canonical_bytes_with_limit(TEST_PAYLOAD_LIMIT)
        .unwrap_or_else(|error| panic!("v9 payload: {error}"));

    assert!(payload.starts_with(V9_MAGIC));
    assert!(
        !payload
            .windows(ENTRY_TEXT_MARKER.len())
            .any(|window| window == ENTRY_TEXT_MARKER.as_bytes()),
        "the payload must reference segments, not embed them"
    );
    assert!((payload.len() as u64) < segments.total_bytes());
}

#[test]
fn v8_payload_is_rejected() {
    let key = semantic_key(b"v8-payload");
    let (result, segments) = result_with_segments(0x72, key);
    let mut payload = result
        .canonical_bytes_with_limit(TEST_PAYLOAD_LIMIT)
        .unwrap_or_else(|error| panic!("v9 payload: {error}"));
    // The version digit precedes the magic's terminating NUL.
    let version = V9_MAGIC.len() - 2;
    payload[version] = b'8';

    let decoded = PreparedSemanticAttemptResult::from_canonical_bytes(&payload, segments);

    assert!(matches!(
        decoded,
        Err(PreparedSemanticResultCodecError::Version)
    ));
}

#[test]
fn new_rejects_absent_or_substituted_segment() {
    let key = semantic_key(b"absent-segment");
    let (result, _segments) = result_with_segments(0x73, key);
    let observation = result.observation().clone();
    let evidence = result.measurement_replay_evidence().to_vec();
    let mut substituting = AttemptLogSegmentSources::default();
    substituting.push(std::sync::Arc::new(SubstitutingSource));

    let absent = PreparedSemanticAttemptResult::new(
        observation.clone(),
        evidence.clone(),
        AttemptLogSegmentSources::default(),
        None,
    );
    let substituted = PreparedSemanticAttemptResult::new(observation, evidence, substituting, None);

    assert!(matches!(
        absent,
        Err(PreparedSemanticResultCodecError::LogSegment { .. })
    ));
    assert!(matches!(
        substituted,
        Err(PreparedSemanticResultCodecError::LogSegment { .. })
    ));
}

#[test]
fn journal_v3_reopens_segments_after_source_dropped() {
    let namespace = TempDir::new().unwrap_or_else(|error| panic!("journal namespace: {error}"));
    let runtime = PreparedResultJournalNamespace::open(namespace.path())
        .unwrap_or_else(|error| panic!("runtime: {error}"));
    let key = semantic_key(b"segment-reopen");
    let execution =
        ExecutionId::from_bytes([0x74; 16]).unwrap_or_else(|error| panic!("execution: {error}"));
    let (result, segments) = result_with_segments(0x74, key);
    let referenced = result.referenced_log_segments();

    let (journal, _) = DirectoryPreparedResultJournal::create(
        &runtime,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        result.clone(),
    )
    .unwrap_or_else(|error| panic!("create journal: {error}"));
    let staged_files = segment_files(&journal).len();
    drop(journal);
    drop(segments);
    let reopened =
        DirectoryPreparedResultJournal::open(&runtime, key, execution, TEST_PAYLOAD_LIMIT)
            .unwrap_or_else(|error| panic!("reopen journal: {error}"));

    assert_eq!(staged_files, referenced.len());
    assert_eq!(reopened.result(), &result);
    for segment in &referenced {
        let bytes = reopened
            .result()
            .log_segments()
            .segment(segment.id)
            .unwrap_or_else(|error| panic!("journal segment: {error}"));
        crate::decode_segment(segment, &bytes)
            .unwrap_or_else(|error| panic!("authentic journal segment: {error}"));
    }
    reopened
        .remove()
        .unwrap_or_else(|error| panic!("remove journal: {error}"));
    assert!(!reopened.root().exists());
}

#[test]
fn journal_rejects_missing_corrupt_or_extra_segment_file() {
    let namespace = TempDir::new().unwrap_or_else(|error| panic!("journal namespace: {error}"));
    let runtime = PreparedResultJournalNamespace::open(namespace.path())
        .unwrap_or_else(|error| panic!("runtime: {error}"));
    let key = semantic_key(b"segment-tamper");
    let execution =
        ExecutionId::from_bytes([0x75; 16]).unwrap_or_else(|error| panic!("execution: {error}"));
    let (result, _segments) = result_with_segments(0x75, key);
    let (journal, _) = DirectoryPreparedResultJournal::create(
        &runtime,
        key,
        execution,
        TEST_PAYLOAD_LIMIT,
        result,
    )
    .unwrap_or_else(|error| panic!("create journal: {error}"));
    let segment = segment_files(&journal)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("journal owns a segment"));
    let original = fs::read(&segment).unwrap_or_else(|error| panic!("read segment: {error}"));
    let extra = journal
        .root()
        .join(JOURNAL_SEGMENTS_DIRECTORY)
        .join(format!("{}.segment", "0".repeat(64)));
    drop(journal);
    let reopen =
        || DirectoryPreparedResultJournal::open(&runtime, key, execution, TEST_PAYLOAD_LIMIT);

    fs::remove_file(&segment).unwrap_or_else(|error| panic!("remove segment: {error}"));
    let missing = reopen();
    fs::write(&segment, b"corrupt").unwrap_or_else(|error| panic!("corrupt segment: {error}"));
    let corrupt = reopen();
    fs::write(&segment, &original).unwrap_or_else(|error| panic!("restore segment: {error}"));
    fs::write(&extra, &original).unwrap_or_else(|error| panic!("extra segment: {error}"));
    let with_extra = reopen();
    fs::remove_file(&extra).unwrap_or_else(|error| panic!("remove extra segment: {error}"));
    let restored = reopen();

    assert!(matches!(
        missing,
        Err(PreparedResultJournalError::Incomplete)
    ));
    assert!(matches!(
        corrupt,
        Err(PreparedResultJournalError::Result(
            PreparedSemanticResultCodecError::LogSegment { .. }
        ))
    ));
    assert!(matches!(
        with_extra,
        Err(PreparedResultJournalError::Incomplete)
    ));
    assert!(restored.is_ok());
}
