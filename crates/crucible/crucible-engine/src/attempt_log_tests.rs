//! Tests the attempt-log manifest codec and the complete-log writer.

use std::collections::BTreeMap;

use super::*;
use crate::segment_store::SharedSegmentStore;
use crate::{
    EventAttributeValue, EventLevel, EventLogTime, EventPayload, EventSource,
    SchedulerEventLogClass, VirtualTime,
};

/// Builds one observational entry carrying `text_bytes` of payload text.
fn entry(sequence: u64, text_bytes: usize) -> SchedulerEventLogEntry {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("text"),
        EventAttributeValue::String("x".repeat(text_bytes)),
    );
    SchedulerEventLogEntry::from_retained_open_event(
        sequence,
        EventLogTime::from_virtual_time(VirtualTime {
            ticks: 1_000 * sequence,
        }),
        EventSource::Engine,
        EventLevel::Info,
        SchedulerEventLogClass::Observational,
        EventPayload::new("console_output", attributes),
    )
    .unwrap_or_else(|error| panic!("fixture entry should build: {error}"))
}

fn entries(count: u64, text_bytes: usize) -> Vec<SchedulerEventLogEntry> {
    (0..count)
        .map(|sequence| entry(sequence, text_bytes))
        .collect()
}

#[test]
fn sealed_log_reads_back_and_its_manifest_round_trips() -> Result<(), AttemptEventLogError> {
    let written = entries(20, 1024 * 1024);
    let store = SharedSegmentStore::new();
    let manifest = seal_attempt_log(&written, &store)?;

    assert!(manifest.segments().len() >= 3);
    assert_eq!(manifest.entry_count(), 20);
    let read = manifest
        .entries(&store)
        .collect::<Result<Vec<_>, AttemptEventLogError>>()?;
    assert_eq!(read, written);

    let bytes = manifest.to_bytes();
    assert_eq!(AttemptLogManifest::from_bytes(&bytes)?, manifest);
    assert_eq!(
        AttemptLogManifest::from_bytes(&seal_attempt_log(&[], &store)?.to_bytes())?.entry_count(),
        0
    );
    Ok(())
}

#[test]
fn manifest_decoding_rejects_altered_or_truncated_bytes() -> Result<(), AttemptEventLogError> {
    let store = SharedSegmentStore::new();
    let manifest = seal_attempt_log(&entries(3, 16), &store)?;
    let bytes = manifest.to_bytes();

    let mut altered_count = bytes.clone();
    altered_count[MANIFEST_MAGIC.len()] ^= 1;
    assert!(AttemptLogManifest::from_bytes(&altered_count).is_err());

    let mut altered_chain = bytes.clone();
    altered_chain[MANIFEST_MAGIC.len() + 8] ^= 1;
    assert!(AttemptLogManifest::from_bytes(&altered_chain).is_err());

    assert!(AttemptLogManifest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(AttemptLogManifest::from_bytes(&trailing).is_err());
    Ok(())
}

#[test]
fn complete_log_writer_refuses_a_non_dense_log() {
    let store = SharedSegmentStore::new();
    let mut gapped = entries(3, 16);
    gapped.remove(1);

    assert!(matches!(
        seal_attempt_log(&gapped, &store),
        Err(AttemptEventLogError::NonDense {
            expected: 1,
            actual: 2
        })
    ));
}
