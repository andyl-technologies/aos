//! Commit-protocol, torn-tail, and streaming-verification tests for the
//! completed-exit log.

use super::*;

const SCENARIO: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// Returns the exact canonical log line for one valid exit, as documented in
/// the module overview.
fn exit_line(transaction: u64, node: &str) -> String {
    format!(
        concat!(
            r#"{{"transaction":{},"node":"{}","#,
            r#""process":{{"process_id":7,"start_time_ticks":9,"executable":"/aos/vm"}},"#,
            r#""generation":1,"transition":"Crash","action_sha256":"{}","#,
            r#""evidence_sha256":"{}","expected_exit_code":70,"observed_exit_code":70}}"#,
        ),
        transaction,
        node,
        "1".repeat(64),
        "2".repeat(64),
    )
}

fn exit(transaction: u64, node: &str) -> ProductionLifecycleCompletedExit {
    serde_json::from_str(&exit_line(transaction, node))
        .unwrap_or_else(|error| panic!("exit fixture should decode: {error}"))
}

fn committed_journal(
    transaction: u64,
    exit_log: ProductionLifecycleExitLog,
) -> ProductionLifecycleJournal {
    ProductionLifecycleJournal {
        version: 1,
        transaction,
        phase: ProductionLifecycleJournalPhase::Committed,
        nodes: Vec::new().into(),
        exit_log,
        pending_exits: Vec::new(),
    }
}

fn manifest() -> ProductionRunManifest {
    ProductionRunManifest {
        version: 2,
        scenario: String::from(SCENARIO),
        owner: exit(1, "owner").process,
        processes: crate::vm_lifecycle::process_owners::ProductionProcessOwners::new(),
        staged_processes: crate::vm_lifecycle::process_owners::ProductionProcessOwners::new(),
        clean_shutdown: true,
        recovered_after_host_exit: false,
    }
}

/// Appends `exits` after `committed` and returns the longer reference.
fn append(
    directory: &Path,
    committed: &ProductionLifecycleExitLog,
    exits: &[ProductionLifecycleCompletedExit],
) -> ProductionLifecycleExitLog {
    let staged = stage_lifecycle_exits(committed, exits)
        .unwrap_or_else(|error| panic!("exits should stage: {error}"));
    append_lifecycle_exits(
        &directory.join(PRODUCTION_LIFECYCLE_EXIT_LOG_FILE),
        committed,
        &staged,
    )
    .unwrap_or_else(|error| panic!("exits should append: {error}"));
    staged.next
}

fn verify(directory: &Path, journal: &ProductionLifecycleJournal) -> Result<(), String> {
    verify_lifecycle_exit_log(directory, journal, FaultResourceLimits::default())
        .map_err(|error| error.to_string())
}

fn log_bytes(directory: &Path) -> Vec<u8> {
    fs::read(directory.join(PRODUCTION_LIFECYCLE_EXIT_LOG_FILE))
        .unwrap_or_else(|error| panic!("exit log should read: {error}"))
}

fn write_log(directory: &Path, bytes: &[u8]) {
    fs::write(directory.join(PRODUCTION_LIFECYCLE_EXIT_LOG_FILE), bytes)
        .unwrap_or_else(|error| panic!("exit log fixture should write: {error}"));
}

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap_or_else(|error| panic!("run directory should build: {error}"))
}

#[test]
fn empty_reference_is_canonical_and_round_trips_the_chain() {
    let empty = ProductionLifecycleExitLog::empty();

    assert!(empty.validate().is_ok());
    assert_eq!(
        decode_chain(&empty.chain_sha256),
        Some(EMPTY_EXIT_LOG_CHAIN)
    );
    assert_eq!(decode_chain("0"), None);
    assert_eq!(decode_chain(&"A".repeat(64)), None);
}

#[test]
fn record_count_and_byte_length_agree_on_emptiness() {
    let mut records_without_bytes = ProductionLifecycleExitLog::empty();
    records_without_bytes.records = 1;
    assert!(records_without_bytes.validate().is_err());

    let mut populated = records_without_bytes.clone();
    populated.bytes = 10;
    assert!(populated.validate().is_ok());

    let mut bytes_without_records = populated;
    bytes_without_records.records = 0;
    assert!(bytes_without_records.validate().is_err());
}

#[test]
fn staged_lines_use_the_documented_canonical_encoding() {
    let staged = stage_lifecycle_exits(
        &ProductionLifecycleExitLog::empty(),
        &[exit(1, "node-a"), exit(2, "node-b")],
    )
    .unwrap_or_else(|error| panic!("exits should stage: {error}"));

    let expected = format!("{}\n{}\n", exit_line(1, "node-a"), exit_line(2, "node-b"));
    assert_eq!(staged.lines, expected.as_bytes());
    assert_eq!(staged.next.records, 2);
    assert_eq!(staged.next.bytes, expected.len() as u64);
}

#[test]
fn committed_exits_recover_through_the_run_state_reference() {
    let directory = tempdir();
    let first = append(
        directory.path(),
        &ProductionLifecycleExitLog::empty(),
        &[exit(1, "node-a"), exit(1, "node-b")],
    );
    let second = append(directory.path(), &first, &[exit(2, "node-a")]);
    assert_eq!(
        (second.records, second.bytes),
        (3, log_bytes(directory.path()).len() as u64)
    );

    let journal = committed_journal(2, second.clone());
    persist_run_state_atomic(
        &directory.path().join(PRODUCTION_RUN_STATE_FILE),
        &manifest(),
        &journal,
        FaultResourceLimits::default(),
        0,
        0,
    )
    .unwrap_or_else(|error| panic!("run state should persist: {error}"));
    let (_, recovered, _, _) =
        decode_prior_run_state(directory.path(), SCENARIO, FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("run state should recover: {error}"));

    assert_eq!(recovered.exit_log, second);
    assert!(recovered.pending_exits.is_empty());
    let run_state = fs::read_to_string(directory.path().join(PRODUCTION_RUN_STATE_FILE))
        .unwrap_or_else(|error| panic!("run state should read: {error}"));
    assert!(!run_state.contains("node-a"), "exits stay out of run state");
}

#[test]
fn exit_log_bytes_are_charged_before_the_log_is_read() {
    let directory = tempdir();
    let exit_log = append(
        directory.path(),
        &ProductionLifecycleExitLog::empty(),
        &[exit(1, "node-a")],
    );
    let journal = committed_journal(1, exit_log.clone());
    let run_state = directory.path().join(PRODUCTION_RUN_STATE_FILE);
    persist_run_state_atomic(
        &run_state,
        &manifest(),
        &journal,
        FaultResourceLimits::default(),
        0,
        0,
    )
    .unwrap_or_else(|error| panic!("run state should persist: {error}"));
    let state_bytes = fs::metadata(&run_state)
        .unwrap_or_else(|error| panic!("run state should stat: {error}"))
        .len();

    let limits = FaultResourceLimits {
        event_log_bytes: state_bytes + exit_log.bytes - 1,
        ..FaultResourceLimits::default()
    };
    let error = decode_prior_run_state(directory.path(), SCENARIO, limits)
        .err()
        .unwrap_or_else(|| panic!("aggregate log bytes should exceed the limit"));
    assert!(matches!(
        error,
        DurableRunStateError::ResourceLimit {
            field: "event_log_bytes",
            current,
            requested,
            ..
        } if current == exit_log.bytes && requested == state_bytes
    ));
}

#[test]
fn retried_append_replaces_an_unreferenced_tail() {
    let directory = tempdir();
    let committed = append(
        directory.path(),
        &ProductionLifecycleExitLog::empty(),
        &[exit(1, "node-a")],
    );
    let expected = append(directory.path(), &committed, &[exit(2, "node-a")]);
    let expected_bytes = log_bytes(directory.path());

    // A failed publication restores the committed reference; the retry must
    // reproduce the same bytes instead of appending a second copy.
    let mut torn = expected_bytes.clone();
    torn.extend_from_slice(b"{\"transaction\":");
    write_log(directory.path(), &torn);
    let retried = append(directory.path(), &committed, &[exit(2, "node-a")]);

    assert_eq!(retried, expected);
    assert_eq!(log_bytes(directory.path()), expected_bytes);
}

#[test]
fn readers_ignore_and_takeover_truncates_a_torn_tail() {
    let directory = tempdir();
    let exit_log = append(
        directory.path(),
        &ProductionLifecycleExitLog::empty(),
        &[exit(1, "node-a")],
    );
    let journal = committed_journal(1, exit_log.clone());
    let mut torn = log_bytes(directory.path());
    let committed_length = torn.len();
    torn.extend_from_slice(b"{\"transaction\":2,\"no");
    write_log(directory.path(), &torn);

    assert_eq!(verify(directory.path(), &journal), Ok(()));
    truncate_lifecycle_exit_log_tail(directory.path(), &exit_log)
        .unwrap_or_else(|error| panic!("torn tail should truncate: {error}"));
    assert_eq!(log_bytes(directory.path()).len(), committed_length);
    assert_eq!(verify(directory.path(), &journal), Ok(()));
}

#[test]
fn missing_or_shortened_committed_prefix_fails_closed() {
    let directory = tempdir();
    let empty_journal = committed_journal(1, ProductionLifecycleExitLog::empty());
    assert_eq!(verify(directory.path(), &empty_journal), Ok(()));
    truncate_lifecycle_exit_log_tail(directory.path(), &empty_journal.exit_log)
        .unwrap_or_else(|error| panic!("an absent empty log needs no truncation: {error}"));

    let exit_log = append(
        directory.path(),
        &ProductionLifecycleExitLog::empty(),
        &[exit(1, "node-a")],
    );
    let journal = committed_journal(1, exit_log.clone());
    let mut shortened = log_bytes(directory.path());
    shortened.pop();
    write_log(directory.path(), &shortened);

    assert!(verify(directory.path(), &journal).is_err());
    assert!(truncate_lifecycle_exit_log_tail(directory.path(), &exit_log).is_err());
    let staged = stage_lifecycle_exits(&exit_log, &[exit(2, "node-a")])
        .unwrap_or_else(|error| panic!("exit should stage: {error}"));
    assert!(
        append_lifecycle_exits(
            &directory.path().join(PRODUCTION_LIFECYCLE_EXIT_LOG_FILE),
            &exit_log,
            &staged,
        )
        .is_err()
    );

    fs::remove_file(directory.path().join(PRODUCTION_LIFECYCLE_EXIT_LOG_FILE))
        .unwrap_or_else(|error| panic!("exit log should unlink: {error}"));
    assert!(verify(directory.path(), &journal).is_err());
}

#[test]
fn altered_committed_record_breaks_the_chain() {
    let directory = tempdir();
    let exit_log = append(
        directory.path(),
        &ProductionLifecycleExitLog::empty(),
        &[exit(1, "node-a"), exit(1, "node-b")],
    );
    let journal = committed_journal(1, exit_log);
    let original = log_bytes(directory.path());

    // Swapping node names keeps every record canonical and valid; only the
    // chain detects the change.
    let swapped = String::from_utf8(original)
        .unwrap_or_else(|error| panic!("log should be UTF-8: {error}"))
        .replace("node-a", "node-x")
        .replace("node-b", "node-a")
        .replace("node-x", "node-b");
    write_log(directory.path(), swapped.as_bytes());

    assert!(verify(directory.path(), &journal).is_err());
}

#[test]
fn invalid_ordered_or_duplicated_records_fail_verification() {
    let cases: [(&str, Vec<ProductionLifecycleCompletedExit>); 6] = [
        (
            "boot is not an exit transition",
            vec![ProductionLifecycleCompletedExit {
                transition: String::from("Boot"),
                ..exit(1, "node-a")
            }],
        ),
        ("transaction zero", vec![exit(0, "node-a")]),
        ("transaction beyond the journal", vec![exit(3, "node-a")]),
        (
            "exit code disagrees with its transition",
            vec![ProductionLifecycleCompletedExit {
                expected_exit_code: 71,
                observed_exit_code: 71,
                ..exit(1, "node-a")
            }],
        ),
        (
            "transactions regress",
            vec![exit(2, "node-a"), exit(1, "node-b")],
        ),
        (
            "node repeats within a transaction",
            vec![exit(1, "node-a"), exit(1, "node-a")],
        ),
    ];
    for (case, exits) in cases {
        let directory = tempdir();
        let exit_log = append(
            directory.path(),
            &ProductionLifecycleExitLog::empty(),
            &exits,
        );
        assert!(
            verify(directory.path(), &committed_journal(2, exit_log)).is_err(),
            "{case}"
        );
    }

    let directory = tempdir();
    let exit_log = append(
        directory.path(),
        &ProductionLifecycleExitLog::empty(),
        &[exit(1, "node-a"), exit(2, "node-a")],
    );
    assert_eq!(
        verify(directory.path(), &committed_journal(2, exit_log)),
        Ok(())
    );
}

#[test]
fn escaped_exit_strings_are_rejected_before_staging() {
    let escaped = ProductionLifecycleCompletedExit {
        node: String::from("node\"a"),
        ..exit(1, "node-a")
    };
    assert!(stage_lifecycle_exits(&ProductionLifecycleExitLog::empty(), &[escaped]).is_err());
}
