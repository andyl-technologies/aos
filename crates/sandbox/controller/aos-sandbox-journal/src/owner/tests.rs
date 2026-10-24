//! Genuine-file regressions for resident native state and staged publication.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;

use super::{NativeJournal, NativeJournalState};
use crate::framing::FrameError;
use crate::geometry::NativeGeometryBounds;
use crate::materialized::RecordMutationRef;
use crate::storage::tests::TemporaryFile;
use crate::transaction::NativeRecordRef;

fn limits() -> NativeGeometryBounds {
    NativeGeometryBounds {
        maximum_journal_bytes: 4096,
        maximum_record_bytes: 1024,
        maximum_key_bytes: 128,
        maximum_records_per_transaction: 8,
        maximum_transaction_bytes: 2048,
        maximum_transactions: 8,
        maximum_materialized_bytes: 2048,
        maximum_materialized_records: 8,
    }
}

fn empty_prefix() -> NativeJournalState<u8> {
    NativeJournalState::from_owned_parts(1, 0, BTreeSet::new(), BTreeSet::new(), BTreeMap::new(), 0)
}

#[test]
fn adoption_retains_original_files_configuration_and_namespace_provenance() {
    let mut data = TemporaryFile::new(b"prefix");
    let mut lock = TemporaryFile::new(b"");
    let file = data.take_file();
    let lock_file = lock.take_file();
    let data_descriptor = file.as_raw_fd();
    let lock_descriptor = lock_file.as_raw_fd();
    let state = BTreeMap::from([((7, b"key".to_vec()), b"value".to_vec())]);
    let original_value = state.values().next().unwrap().as_ptr();
    let prefix = NativeJournalState::from_owned_parts(
        11,
        1,
        BTreeSet::from([[1; 16]]),
        BTreeSet::from([7, 8]),
        state,
        8,
    );

    let owner = NativeJournal::from_owned_parts(
        PathBuf::from("native.journal"),
        file,
        lock_file,
        limits(),
        prefix,
    );

    assert_eq!(owner.file().as_raw_fd(), data_descriptor);
    assert_eq!(owner.lock_file().as_raw_fd(), lock_descriptor);
    assert_eq!(owner.path(), &PathBuf::from("native.journal"));
    assert_eq!(owner.limits(), limits());
    assert_eq!(owner.next_sequence(), 11);
    assert_eq!(owner.committed_transactions(), 1);
    assert_eq!(owner.transaction_ids(), &BTreeSet::from([[1; 16]]));
    assert_eq!(owner.committed_namespaces(), &BTreeSet::from([7, 8]));
    assert_eq!(
        owner.state().values().next().unwrap().as_ptr(),
        original_value
    );
    assert_eq!(owner.materialized_bytes(), 8);
}

#[test]
fn native_append_row_application_and_bookkeeping_remain_separate_steps() {
    let mut data = TemporaryFile::new(b"");
    let mut lock = TemporaryFile::new(b"");
    let mut owner = NativeJournal::from_owned_parts(
        PathBuf::from("native.journal"),
        data.take_file(),
        lock.take_file(),
        limits(),
        empty_prefix(),
    );
    let mutation = RecordMutationRef {
        namespace: 7,
        key: b"key",
        value: Some(b"value"),
    };
    let projected = owner.projected_change([mutation]).unwrap();
    let frames = owner
        .encode_at_head(
            [2; 16],
            [NativeRecordRef {
                namespace_byte: 7,
                key: b"key",
                value: Some(b"value"),
            }]
            .into_iter(),
        )
        .unwrap();
    let expected = owner.expected_append_length(&frames).unwrap();

    assert_eq!(owner.file().metadata().unwrap().len(), 0);
    assert!(owner.state().is_empty());
    assert_eq!(owner.next_sequence(), 1);
    let durable = owner.append_exact(&frames, expected).unwrap();

    assert_eq!(durable, expected);
    assert!(owner.state().is_empty());
    assert_eq!(owner.next_sequence(), 1);
    assert!(owner.transaction_ids().is_empty());
    owner.apply_mutation(mutation);

    assert_eq!(owner.state().get(&(7, b"key".to_vec())).unwrap(), b"value");
    assert_eq!(owner.materialized_bytes(), 0);
    assert!(owner.committed_namespaces().is_empty());
    owner.publish_append(projected, 4, [2; 16], [7]);

    assert_eq!(owner.materialized_bytes(), 8);
    assert_eq!(owner.next_sequence(), 4);
    assert_eq!(owner.committed_transactions(), 1);
    assert_eq!(owner.transaction_ids(), &BTreeSet::from([[2; 16]]));
    assert_eq!(owner.committed_namespaces(), &BTreeSet::from([7]));
}

#[test]
fn projection_refusal_preserves_original_native_and_materialized_state() {
    let mut data = TemporaryFile::new(b"prefix");
    let mut lock = TemporaryFile::new(b"");
    let bounds = NativeGeometryBounds {
        maximum_materialized_bytes: 1,
        ..limits()
    };
    let owner = NativeJournal::from_owned_parts(
        PathBuf::from("native.journal"),
        data.take_file(),
        lock.take_file(),
        bounds,
        empty_prefix(),
    );

    let outcome = owner.projected_change([RecordMutationRef {
        namespace: 7,
        key: b"key",
        value: Some(b"value"),
    }]);

    assert!(matches!(
        outcome,
        Err(FrameError::LimitExceeded("materialized state bytes"))
    ));
    assert_eq!(owner.file().metadata().unwrap().len(), 6);
    assert!(owner.state().is_empty());
    assert_eq!(owner.next_sequence(), 1);
    assert!(!owner.is_poisoned());
}

#[test]
fn failed_native_append_keeps_resident_state_and_poisons_the_original_owner() {
    let data = TemporaryFile::new(b"prefix");
    let mut lock = TemporaryFile::new(b"");
    let prefix = NativeJournalState::from_owned_parts(
        11,
        1,
        BTreeSet::from([[1; 16]]),
        BTreeSet::from([7]),
        BTreeMap::from([((7, b"key".to_vec()), b"value".to_vec())]),
        8,
    );
    let mut owner = NativeJournal::from_owned_parts(
        PathBuf::from("native.journal"),
        data.read_only(),
        lock.take_file(),
        limits(),
        prefix,
    );
    let frames = vec![b"append".to_vec()];
    let expected = owner.expected_append_length(&frames).unwrap();

    let outcome = owner.append_exact(&frames, expected);

    assert!(matches!(outcome, Err(FrameError::Io(_))));
    assert!(owner.is_poisoned());
    assert_eq!(owner.file().metadata().unwrap().len(), 6);
    assert_eq!(owner.next_sequence(), 11);
    assert_eq!(owner.committed_transactions(), 1);
    assert_eq!(owner.transaction_ids(), &BTreeSet::from([[1; 16]]));
    assert_eq!(owner.state().get(&(7, b"key".to_vec())).unwrap(), b"value");
    assert_eq!(owner.materialized_bytes(), 8);
}

#[test]
fn replayed_file_replacement_retains_lock_poison_and_adopts_actual_map_storage() {
    let mut data = TemporaryFile::new(b"old");
    let mut lock = TemporaryFile::new(b"");
    let mut replacement = TemporaryFile::new(b"new");
    let mut owner = NativeJournal::from_owned_parts(
        PathBuf::from("native.journal"),
        data.take_file(),
        lock.take_file(),
        limits(),
        empty_prefix(),
    );
    let lock_descriptor = owner.lock_file().as_raw_fd();
    let lock_identity = owner.lock_file().metadata().unwrap();
    let file = replacement.take_file();
    let replacement_descriptor = file.as_raw_fd();
    let state = BTreeMap::from([((8, b"new-key".to_vec()), b"new-value".to_vec())]);
    let original_value = state.values().next().unwrap().as_ptr();
    let prefix = NativeJournalState::from_owned_parts(
        21,
        2,
        BTreeSet::from([[2; 16], [3; 16]]),
        BTreeSet::from([8, 9]),
        state,
        16,
    );
    owner.poison();

    owner.replace_replayed_file(file, prefix);

    assert_eq!(owner.file().as_raw_fd(), replacement_descriptor);
    assert_eq!(owner.lock_file().as_raw_fd(), lock_descriptor);
    let retained_lock = owner.lock_file().metadata().unwrap();
    assert_eq!(
        (retained_lock.dev(), retained_lock.ino()),
        (lock_identity.dev(), lock_identity.ino())
    );
    assert!(owner.is_poisoned());
    assert_eq!(owner.path(), &PathBuf::from("native.journal"));
    assert_eq!(owner.limits(), limits());
    assert_eq!(owner.next_sequence(), 21);
    assert_eq!(owner.committed_transactions(), 2);
    assert_eq!(owner.transaction_ids(), &BTreeSet::from([[2; 16], [3; 16]]));
    assert_eq!(owner.committed_namespaces(), &BTreeSet::from([8, 9]));
    assert_eq!(
        owner.state().values().next().unwrap().as_ptr(),
        original_value
    );
    assert_eq!(owner.materialized_bytes(), 16);
}
