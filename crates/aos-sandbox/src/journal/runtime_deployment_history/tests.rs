//! UNRUN same-native-codec vectors; no protected startup or floor is fabricated.

use std::io::{Read as _, Seek as _, Write as _};

use crate::runtime_deployment::DeploymentHistoryFixtureV1;

use super::*;
use super::super::{JournalRecord, encode_transaction, write_compacted};

struct NativeFixture {
    signed: DeploymentHistoryFixtureV1,
    rows: BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transactions: Vec<JournalTransaction>,
}

impl NativeFixture {
    fn new(with_phases: bool) -> Self {
        let signed = DeploymentHistoryFixtureV1::new();
        let steps = if with_phases { signed.canonical_steps() } else { Vec::new() };
        assert!(signed.current(&steps).is_ok());

        let mut rows = BTreeMap::from([((NAMESPACE, GENESIS_KEY.to_vec()), signed.exact.clone())]);
        let mut transactions = vec![JournalTransaction::new(
            genesis_native_transaction_v1(&signed.exact).unwrap(),
            vec![JournalRecord::put(NAMESPACE, GENESIS_KEY.to_vec(), signed.exact.clone())],
        ).unwrap()];
        for (key, bytes) in steps {
            let identity = bytes[160..176].try_into().unwrap();
            rows.insert((NAMESPACE, key.clone()), bytes.clone());
            transactions.push(JournalTransaction::new(
                identity, vec![JournalRecord::put(NAMESPACE, key, bytes)],
            ).unwrap());
        }
        Self { signed, rows, transactions }
    }

    fn bytes(&self) -> Vec<u8> {
        native_bytes(&self.transactions)
    }

    fn audit<R: Read + Seek + Borrow<File>>(
        &self,
        reader: &mut R,
        length: u64,
    ) -> Result<ReplayState, JournalError> {
        let mut observer = HistoryAuditV1::from_bindings(
            &self.rows, &self.signed.exact, &self.signed.genesis,
            self.signed.signer.verifying_key(),
        )?;
        let replayed = replay_observed(reader, MAIN_LIMITS, Some(&mut observer))?;
        observer.finish(&replayed)?;
        if replayed.durable_end != length {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(replayed)
    }

    fn audit_bytes(&self, bytes: &[u8]) -> Result<ReplayState, JournalError> {
        let mut file = tempfile::tempfile()?;
        file.write_all(bytes)?;
        self.audit(&mut file, bytes.len() as u64)
    }
}

fn native_bytes(transactions: &[JournalTransaction]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut sequence = 1;
    for transaction in transactions {
        for frame in encode_transaction(transaction, sequence).unwrap() {
            bytes.extend_from_slice(&frame);
        }
        sequence += transaction.records().len() as u64 + 2;
    }
    bytes
}

fn normal_replay(bytes: &[u8]) -> ReplayState {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    replay_observed(&mut file, MAIN_LIMITS, None).unwrap()
}

#[test]
fn unrun_original_genesis_and_every_exact_phase_prefix_pass_same_native_parser() {
    let fixture = NativeFixture::new(true);
    for count in 1..=fixture.transactions.len() {
        let transactions = fixture.transactions[..count].to_vec();
        let rows = fixture.rows.iter().filter(|((_, key), _)| {
            transactions.iter().any(|transaction| transaction.records()[0].key() == key.as_slice())
        }).map(|(key, value)| (key.clone(), value.clone())).collect();
        let prefix = NativeFixture {
            signed: DeploymentHistoryFixtureV1::new(), rows, transactions,
        };
        let bytes = prefix.bytes();

        let replayed = prefix.audit_bytes(&bytes).unwrap();
        assert_eq!(replayed.next_sequence, 1 + count as u64 * 3);
        assert_eq!(replayed.committed_transactions, count);
        assert_eq!(replayed.state, prefix.rows);
    }
}

#[test]
fn unrun_wrong_native_uuid_and_reordered_same_map_history_refuse() {
    let fixture = NativeFixture::new(true);
    let original = normal_replay(&fixture.bytes());
    let mut wrong_uuid = fixture.transactions.clone();
    wrong_uuid[1] = JournalTransaction::new([90; 16], wrong_uuid[1].records().to_vec()).unwrap();
    let wrong_uuid = native_bytes(&wrong_uuid);
    let replayed = normal_replay(&wrong_uuid);
    assert_eq!(replayed.state, original.state);
    assert_eq!(replayed.next_sequence, original.next_sequence);
    assert!(fixture.audit_bytes(&wrong_uuid).is_err());

    let mut reordered = fixture.transactions.clone();
    reordered.swap(1, 2);
    let reordered = native_bytes(&reordered);
    let replayed = normal_replay(&reordered);
    assert_eq!(replayed.state, original.state);
    assert_eq!(replayed.next_sequence, original.next_sequence);
    assert!(fixture.audit_bytes(&reordered).is_err());

    let mut wrong_genesis = fixture.transactions.clone();
    wrong_genesis[0] = JournalTransaction::new([91; 16], wrong_genesis[0].records().to_vec()).unwrap();
    assert!(fixture.audit_bytes(&native_bytes(&wrong_genesis)).is_err());
}

#[test]
fn unrun_overwrite_delete_batch_foreign_and_extra_native_transactions_refuse() {
    let fixture = NativeFixture::new(true);
    let mut overwritten = fixture.transactions.clone();
    overwritten.push(JournalTransaction::new([92; 16], overwritten[1].records().to_vec()).unwrap());
    let bytes = native_bytes(&overwritten);
    assert_eq!(normal_replay(&bytes).state, fixture.rows);
    assert!(fixture.audit_bytes(&bytes).is_err());

    let mut deleted = fixture.transactions.clone();
    deleted.push(JournalTransaction::new([93; 16], vec![
        JournalRecord::delete(NAMESPACE, deleted[1].records()[0].key().to_vec()),
    ]).unwrap());
    assert!(fixture.audit_bytes(&native_bytes(&deleted)).is_err());

    let mut batch = fixture.transactions.clone();
    batch[1] = JournalTransaction::new(*batch[1].id(), vec![
        batch[1].records()[0].clone(), batch[2].records()[0].clone(),
    ]).unwrap();
    assert!(fixture.audit_bytes(&native_bytes(&batch)).is_err());

    let mut foreign = fixture.transactions.clone();
    foreign[1] = JournalTransaction::new(*foreign[1].id(), vec![JournalRecord::put(
        RecordNamespace::DesiredState, foreign[1].records()[0].key().to_vec(),
        foreign[1].records()[0].value().unwrap().to_vec(),
    )]).unwrap();
    assert!(fixture.audit_bytes(&native_bytes(&foreign)).is_err());

    let mut extra = fixture.transactions.clone();
    extra.push(JournalTransaction::new([94; 16], vec![
        JournalRecord::put(NAMESPACE, b"unknown-row".to_vec(), b"unknown".to_vec()),
    ]).unwrap());
    assert!(fixture.audit_bytes(&native_bytes(&extra)).is_err());
}

#[test]
fn unrun_actual_native_compactor_preserves_map_but_both_histories_refuse() {
    for with_phases in [false, true] {
        let fixture = NativeFixture::new(with_phases);
        let original = normal_replay(&fixture.bytes());
        let mut file = tempfile::tempfile().unwrap();
        write_compacted(&mut file, &fixture.rows, MAIN_LIMITS).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut compacted = Vec::new();
        file.read_to_end(&mut compacted).unwrap();

        let replayed = normal_replay(&compacted);
        assert_eq!(replayed.state, original.state);
        assert_eq!(replayed.next_sequence, original.next_sequence);
        assert!(fixture.audit_bytes(&compacted).is_err());
    }
}

#[test]
fn unrun_read_at_audit_preserves_writer_cursor_on_success_and_error() {
    let fixture = NativeFixture::new(true);
    let mut file = tempfile::tempfile().unwrap();
    let bytes = fixture.bytes();
    file.write_all(&bytes).unwrap();
    file.seek(SeekFrom::Start(7)).unwrap();
    let mut writer_description = &file;
    let mut reader = ReadAtCursorV1::new(&file, bytes.len() as u64);

    assert!(fixture.audit(&mut reader, bytes.len() as u64).is_ok());
    assert_eq!(writer_description.stream_position().unwrap(), 7);
    let mut short_reader = ReadAtCursorV1::new(&file, bytes.len() as u64 - 1);
    assert!(fixture.audit(&mut short_reader, bytes.len() as u64 - 1).is_err());
    assert_eq!(writer_description.stream_position().unwrap(), 7);
    assert!(short_reader.seek(SeekFrom::End(1)).is_err());
    assert!(short_reader.seek(SeekFrom::Start(0)).is_ok());
    assert!(short_reader.seek(SeekFrom::Current(-1)).is_err());
}

#[test]
fn unrun_complete_physical_cut_and_original_snapshot_equality_are_required() {
    let fixture = NativeFixture::new(true);
    let bytes = fixture.bytes();
    let mut incomplete = bytes.clone();
    incomplete.push(b'A');
    assert_eq!(normal_replay(&incomplete).state, fixture.rows);
    assert!(fixture.audit_bytes(&incomplete).is_err());

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inert.journal");
    std::fs::write(&path, &bytes).unwrap();
    let (journal, _) = Journal::open(&path, MAIN_LIMITS).unwrap();
    let mut replayed = normal_replay(&bytes);
    assert!(journal.require_deployment_replayed_snapshot(&replayed, bytes.len() as u64).is_ok());
    assert!(journal.require_deployment_replayed_snapshot(&replayed, bytes.len() as u64 + 1).is_err());
    replayed.state.get_mut(&(NAMESPACE, GENESIS_KEY.to_vec())).unwrap()[0] ^= 1;
    assert!(journal.require_deployment_replayed_snapshot(&replayed, bytes.len() as u64).is_err());
}

#[test]
fn unrun_no_compaction_is_closed_to_exact_path_not_namespace_or_basename() {
    assert!(OriginalCompactionSelectionV1::capture(
        Path::new("/var/lib/aos/sandbox/runtime-deployment"), "preparation.journal",
    ) == OriginalCompactionSelectionV1::DeploymentMain);
    assert!(OriginalCompactionSelectionV1::capture(
        Path::new("/var/lib/aos/sandbox/runtime"), "preparation.journal",
    ) == OriginalCompactionSelectionV1::Other);
    assert!(OriginalCompactionSelectionV1::capture(
        Path::new("/var/lib/aos/sandbox/runtime-deployment"), "tpm-floor.journal",
    ) == OriginalCompactionSelectionV1::DeploymentSidecar);

    let directory = tempfile::tempdir().unwrap();
    let (mut unrelated, _) = Journal::open(directory.path().join("preparation.journal"), MAIN_LIMITS).unwrap();
    unrelated.commit(&JournalTransaction::new([95; 16], vec![
        JournalRecord::put(NAMESPACE, b"catalog-data".to_vec(), b"unrelated".to_vec()),
    ]).unwrap()).unwrap();

    // Exercise only the deny predicate with inert pathname DATA. This does
    // not call a protected opener, compact that path or fabricate a floor.
    let actual_inert_path = unrelated.path.clone();
    unrelated.path = Path::new(MAIN_DIRECTORY_V1).join(MAIN_NAME);
    assert!(require_no_compaction(&unrelated).is_err());
    unrelated.path = actual_inert_path;
    assert!(unrelated.compact().is_ok());
}

#[test]
fn unrun_actual_unrelated_protected_opener_captures_other_and_keeps_compaction() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = std::fs::metadata(directory.path()).unwrap().uid();
    let (mut journal, _) = Journal::open_protected_at_uid(
        directory.path(), MAIN_NAME, MAIN_LIMITS, uid,
    ).unwrap();
    assert!(journal.protected.as_ref().unwrap().original_compaction_selection
        == OriginalCompactionSelectionV1::Other);

    journal.commit(&JournalTransaction::new([96; 16], vec![
        JournalRecord::put(NAMESPACE, b"unrelated-catalog".to_vec(), b"data".to_vec()),
    ]).unwrap()).unwrap();
    assert!(require_no_compaction(&journal).is_ok());
    assert!(journal.compact().is_ok());
}

#[test]
fn unrun_closed_native_observer_refuses_oversized_retention_before_replay() {
    let fixture = NativeFixture::new(false);
    let mut oversized = fixture.rows.clone();
    for index in 0..MAIN_LIMITS.maximum_materialized_records {
        oversized.insert((NAMESPACE, index.to_be_bytes().to_vec()), vec![0]);
    }

    assert!(HistoryAuditV1::from_bindings(
        &oversized, &fixture.signed.exact, &fixture.signed.genesis,
        fixture.signed.signer.verifying_key(),
    ).is_err());
}

#[test]
fn unrun_read_at_cursor_borrows_the_original_file_identity() {
    let fixture = NativeFixture::new(true);
    let mut file = tempfile::tempfile().unwrap();
    let bytes = fixture.bytes();
    file.write_all(&bytes).unwrap();
    file.seek(SeekFrom::Start(11)).unwrap();

    let mut reader = ReadAtCursorV1::new(&file, bytes.len() as u64);
    let original = FileIdentity::of(&file).unwrap();
    let borrowed = <ReadAtCursorV1<'_> as Borrow<File>>::borrow(&reader);

    assert!(FileIdentity::of(borrowed).unwrap() == original);
    assert!(fixture.audit(&mut reader, bytes.len() as u64).is_ok());
    let after = FileIdentity::of(
        <ReadAtCursorV1<'_> as Borrow<File>>::borrow(&reader),
    )
    .unwrap();
    assert!(after == original);
    assert_eq!((&file).stream_position().unwrap(), 11);
}

#[test]
fn unrun_unobserved_facade_preserves_original_engine_replay_results() {
    let transaction = JournalTransaction::new(
        [97; 16],
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            b"ordinary".to_vec(),
            b"value".to_vec(),
        )],
    )
    .unwrap();
    let bytes = native_bytes(&[transaction]);
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();

    let original = super::super::replay(&mut file, MAIN_LIMITS).unwrap();
    let observed = replay_observed(&mut file, MAIN_LIMITS, None).unwrap();

    assert_eq!(observed.state, original.state);
    assert_eq!(observed.durable_end, original.durable_end);
    assert_eq!(observed.next_sequence, original.next_sequence);
    assert_eq!(
        observed.committed_transactions,
        original.committed_transactions,
    );
    assert_eq!(observed.committed_records, original.committed_records);
    assert_eq!(observed.transaction_ids, original.transaction_ids);
    assert_eq!(observed.committed_namespaces, original.committed_namespaces);
    assert_eq!(observed.materialized_bytes, original.materialized_bytes);
    assert_eq!(observed.idempotency, original.idempotency);
    assert_eq!(
        observed.source_history_compacted,
        original.source_history_compacted,
    );
    assert!(!observed.source_original_replay.has_dependencies());
    assert_eq!(
        observed.source_challenge_history.len(),
        original.source_challenge_history.len(),
    );
}

#[test]
fn unrun_readonly_and_existing_openers_capture_actual_unrelated_origin() {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        directory.path(), std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let uid = std::fs::metadata(directory.path()).unwrap().uid();
    let (mut writer, _) = Journal::open_protected_at_uid(
        directory.path(),
        MAIN_NAME,
        MAIN_LIMITS,
        uid,
    )
    .unwrap();
    let transaction = JournalTransaction::new(
        [98; 16],
        vec![JournalRecord::put(NAMESPACE, b"unrelated".to_vec(), b"data".to_vec())],
    )
    .unwrap();
    writer.commit(&transaction).unwrap();

    let (readonly, _) = Journal::open_read_only_protected_at_uid_for_test(
        directory.path(),
        MAIN_NAME,
        MAIN_LIMITS,
        uid,
    )
    .unwrap();

    assert!(readonly.journal.protected.as_ref().unwrap().original_compaction_selection
        == OriginalCompactionSelectionV1::Other);
    assert!(require_no_compaction(&readonly.journal).is_ok());
    drop(readonly);
    drop(writer);

    let (existing, _) = Journal::open_existing_protected_at_uid(
        directory.path(),
        MAIN_NAME,
        MAIN_LIMITS,
        uid,
    )
    .unwrap();
    assert!(existing.protected.as_ref().unwrap().original_compaction_selection
        == OriginalCompactionSelectionV1::Other);
    assert!(require_no_compaction(&existing).is_ok());
}
