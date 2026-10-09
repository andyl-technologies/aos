//! Owned-file and thread controls for the passive diagnostic exporter.

use super::*;
use std::sync::mpsc;
use tempfile::{NamedTempFile, TempDir};

fn row(stage: &str, node: usize) -> String {
    format!("CRUCIBLE-RUNTIME-PROGRESS-V1 stage={stage} node=\"node-{node}\" quanta=7\n")
}

fn sample(observer: &OwnedProgressObserver) {
    let (sent, received) = mpsc::channel();
    observer
        .control
        .send(ObserverCommand::Sample(sent))
        .unwrap();
    received.recv_timeout(Duration::from_secs(2)).unwrap();
}

fn frames(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn live_progress_parser_keeps_complete_bounded_prefix_records() {
    let now = Instant::now();
    let mut records = Records::default();
    let line = row("before-quantum", 0);
    records.ingest(&line.as_bytes()[..17], now);
    assert!(records.rows.is_empty());
    records.ingest(&line.as_bytes()[17..], now);
    assert_eq!(records.rows.len(), 1);
    assert_eq!(records.rows.values().next().unwrap().offset, 0);
    records.ingest(b"ordinary CRUCIBLE-RUNTIME-PROGRESS-V1 stage=fake\n", now);
    records.ingest(b"CRUCIBLE-RUNTIME-PROGRESS-V10 stage=fake\n", now);
    records.ingest(b"CRUCIBLE-RUNTIME-BOOT-V1 node=\xff\n", now);
    records.ingest(&vec![b'x'; MAX_RECORD_BYTES + 10], now);
    records.ingest(
        b"\nCRUCIBLE-RUNTIME-BOOT-V1 node=\"n\" console_bytes=1",
        now,
    );
    assert_eq!(records.rows.len(), 1);
    assert_eq!(records.malformed, 1);
    assert_eq!(records.oversized, 1);
    assert_eq!(records.unrelated, 2);
    assert!(!records.partial.is_empty());
    records.ingest(b"\n", now);
    assert_eq!(records.rows.len(), 2);
}

#[test]
fn live_progress_reads_owned_fd_incrementally_beyond_recent_tail() {
    let mut source = NamedTempFile::new().unwrap();
    source
        .write_all(row("before-quantum", 0).as_bytes())
        .unwrap();
    source
        .write_all(&vec![b'x'; MAX_CYCLE_BYTES as usize + 100])
        .unwrap();
    source.write_all(b"\n").unwrap();
    source
        .write_all(row("after-quantum", 0).as_bytes())
        .unwrap();
    source.flush().unwrap();
    let mut reader = source.reopen().unwrap();
    let mut records = Records::default();
    assert!(read_cycle(&mut reader, &mut records).unwrap() > 0);
    assert_eq!(records.offset, MAX_CYCLE_BYTES);
    assert_eq!(records.rows.len(), 1);
    assert_eq!(read_cycle(&mut reader, &mut records).unwrap(), 0);
    assert_eq!(records.rows.len(), 2);
    let offsets = records
        .rows
        .values()
        .map(|record| record.offset)
        .collect::<Vec<_>>();
    let cursor = records.offset;
    assert_eq!(read_cycle(&mut reader, &mut records).unwrap(), 0);
    assert_eq!(records.offset, cursor);
    assert_eq!(
        records
            .rows
            .values()
            .map(|record| record.offset)
            .collect::<Vec<_>>(),
        offsets
    );
}

#[test]
fn live_progress_worker_runs_while_main_operation_is_blocked_and_joins() {
    let temporary = TempDir::new().unwrap();
    let path = temporary.path().join("progress.jsonl");
    let output = ProgressOutput::create(&path).unwrap();
    let mut source = NamedTempFile::new().unwrap();
    source
        .write_all(row("before-quantum", 0).as_bytes())
        .unwrap();
    source.flush().unwrap();
    let mut observer = OwnedProgressObserver::start(source.reopen().unwrap(), 123, output).unwrap();
    let (release, blocked) = mpsc::channel();
    let operation = thread::spawn(move || blocked.recv().unwrap());
    sample(&observer);
    assert_eq!(frames(&path).len(), 1);
    assert!(!operation.is_finished());
    observer.stop("owned-service-exit=exit-status:0");
    assert!(observer.worker.is_none());
    assert_eq!(frames(&path).len(), 2);
    release.send(()).unwrap();
    operation.join().unwrap();
}

#[test]
fn live_progress_forged_uart_setup_text_remains_advisory_only() {
    let now = Instant::now();
    let mut records = Records::default();
    records.ingest(b"lifecycle.setup_complete\n", now);
    assert!(records.rows.is_empty());
    // Even producer-shaped text is copied as text, never decoded into a setup
    // receipt, accepted operation, PASS, or guest execution decision.
    records.ingest(
        b"CRUCIBLE-RUNTIME-BOOT-V1 node=\"n\" setup_receipts=1\n",
        now,
    );
    let frame = records.sample(now);
    assert!(frame.get("setup_receipts").is_none());
    assert!(frame.get("accepted").is_none());
    assert!(frame.get("completed").is_none());
    assert_eq!(frame["record"]["producer_age"], "unknown");
}

#[test]
fn live_progress_before_rows_cannot_be_cleared_by_cached_after_rows() {
    let now = Instant::now();
    let mut records = Records::default();
    records.ingest(row("after-quantum", 0).as_bytes(), now);
    records.ingest(row("before-quantum", 0).as_bytes(), now);
    let mut snapshots = [records.sample(now), records.sample(now + INTERVAL)];
    snapshots.sort_by_key(|frame| frame["record"]["source_offset"].as_u64().unwrap());
    assert!(
        snapshots[0]["record"]["line"]
            .as_str()
            .unwrap()
            .contains("stage=after-quantum")
    );
    assert!(
        snapshots[1]["record"]["line"]
            .as_str()
            .unwrap()
            .contains("stage=before-quantum")
    );
    assert!(
        snapshots
            .iter()
            .all(|frame| frame.get("completed").is_none())
    );
    assert_eq!(snapshots[1]["record"]["observed_age_ms"], 5000);
}

#[test]
fn live_progress_cache_frames_and_total_output_have_fixed_limits() {
    let now = Instant::now();
    let mut records = Records::default();
    for node in 0..MAX_KEYS + 5 {
        records.ingest(row("before-quantum", node).as_bytes(), now);
    }
    assert_eq!(records.rows.len(), MAX_KEYS);
    assert_eq!(records.omitted_keys, 5);
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..MAX_KEYS {
        visited.insert(
            records.sample(now)["record"]["key"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(visited.len(), MAX_KEYS);

    let temporary = TempDir::new().unwrap();
    let path = temporary.path().join("progress.jsonl");
    let output = ProgressOutput::create(&path).unwrap();
    let large = json!({"record": {"line": "x".repeat(MAX_RECORD_BYTES)}, "advisory": true});
    for _ in 0..MAX_PERIODIC_FRAMES + 2 {
        output.emit(large.clone(), false).unwrap();
    }
    for _ in 0..MAX_TERMINAL_FRAMES + 2 {
        output
            .emit(json!({"terminal_reason": "owned-exit"}), true)
            .unwrap();
    }
    let frames = frames(&path);
    assert_eq!(frames.len(), MAX_PERIODIC_FRAMES + MAX_TERMINAL_FRAMES);
    assert!(frames[0]["record"].is_null());
    assert_eq!(
        frames[0]["record_unavailable"]["reason"],
        "encoded-frame-limit"
    );
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .all(|line| line.len() < MAX_FRAME_BYTES)
    );
    assert!(std::fs::metadata(path).unwrap().len() <= 1_851_392);
}

#[test]
fn live_progress_disabled_path_has_no_output_and_truncation_invalidates_cache() {
    let temporary = TempDir::new().unwrap();
    let path = temporary.path().join("absent.jsonl");
    assert!(
        ProgressOutput::configured(false, Some(path.as_os_str()))
            .unwrap()
            .is_none()
    );
    assert!(!path.exists());
    let mut source = NamedTempFile::new().unwrap();
    source
        .write_all(row("before-quantum", 0).as_bytes())
        .unwrap();
    source.flush().unwrap();
    let mut reader = source.reopen().unwrap();
    let mut records = Records::default();
    read_cycle(&mut reader, &mut records).unwrap();
    assert_eq!(records.rows.len(), 1);
    source.as_file().set_len(0).unwrap();
    read_cycle(&mut reader, &mut records).unwrap();
    assert!(records.rows.is_empty());
    assert_eq!(records.generation, 1);
    assert_eq!(records.offset, 0);
    assert!(ProgressOutput::configured(true, None).is_err());
}

#[test]
fn live_progress_sink_failure_does_not_replace_status_or_leave_worker() {
    use super::super::{CampaignServiceChild, wait_for_exit};
    use std::process::{Command, Stdio};

    for argument in ["--help", "--not-a-libtest-option"] {
        let source = NamedTempFile::new().unwrap();
        let destination = NamedTempFile::new().unwrap();
        let output = Arc::new(ProgressOutput {
            state: Mutex::new(OutputState {
                file: File::open(destination.path()).unwrap(),
                periodic: 0,
                terminal: 0,
                bytes: 0,
            }),
        });
        let observer = OwnedProgressObserver::start(source.reopen().unwrap(), 123, output).unwrap();
        sample(&observer);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg(argument)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let original = wait_for_exit(&mut child, Duration::from_secs(5)).unwrap();
        assert_eq!(original.success(), argument == "--help");
        let mut service = CampaignServiceChild {
            child,
            #[cfg(feature = "packaged-midpoint-flight")]
            daemon_url: String::new(),
            stderr: source,
            kill_on_drop: true,
            live_progress: Some(observer),
        };
        let result = service.stop();
        assert_eq!(result.is_ok(), original.success());
        if !original.success() {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains(&original.to_string())
            );
        }
        assert_eq!(service.child.try_wait().unwrap(), Some(original));
        assert!(service.live_progress.as_ref().unwrap().worker.is_none());
        assert_eq!(std::fs::metadata(destination.path()).unwrap().len(), 0);
    }
}
