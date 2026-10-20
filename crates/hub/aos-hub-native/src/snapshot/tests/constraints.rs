//! Actual workflow rejection of correctly signed retained SQL violations.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use serde_json::{json, Value as Json};

use super::{budget, fixture as custody_fixture, private_file, reader_credentials, source};
use crate::snapshot::workflow::{self, SnapshotError, SnapshotScratchLimits};

#[path = "constraints_fixture.rs"]
mod archive_fixture;

fn archive_directory(
    custody: &super::Fixture,
    archive: &archive_fixture::Fixture,
    name: &str,
) -> std::path::PathBuf {
    let directory = custody.directory.path().join(name);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&directory, "archive.json", archive.output.root.as_bytes());
    private_file(&directory, "metadata.aosh", &archive.output.metadata);
    private_file(&directory, "private.aosh", &archive.output.private);
    fs::write(&custody.credentials.wrapping.metadata_file, [2; 32]).unwrap();
    fs::write(&custody.credentials.wrapping.private_file, [3; 32]).unwrap();
    let trust = json!({"version":1,"signers":[{
        "id":archive.signer.id(), "ed25519_public_key_hex":hex::encode(archive.signer.public_key())
    }]});
    fs::write(
        &custody.credentials.signer_trust_file,
        serde_json::to_vec(&trust).unwrap(),
    )
    .unwrap();
    directory
}

fn cell(metadata: &mut [Json], table: &str, row_index: usize, column: &str, scalar: Json) {
    let start = metadata
        .iter()
        .position(|line| line["kind"] == "table_start" && line["table"] == table)
        .unwrap();
    let mut row = 0;
    for line in &mut metadata[start + 1..] {
        if line["kind"] == "table_end" {
            break;
        }
        if line["kind"] == "cell" && line["column"] == column && row == row_index {
            assert!(!line["scalar"].is_null());
            line["scalar"] = scalar;
            return;
        }
        if line["kind"] == "row_end" {
            row += 1;
        }
    }
    panic!("fixture cell absent");
}

fn duplicate_user(metadata: &mut Vec<Json>, private: &mut [Json]) {
    let table = metadata
        .iter()
        .position(|line| line["kind"] == "table_start" && line["table"] == "users")
        .unwrap();
    let first = table + 1;
    let first_end = first
        + metadata[first..]
            .iter()
            .position(|line| line["kind"] == "row_end")
            .unwrap();
    let second = first_end + 1;
    let second_end = second
        + metadata[second..]
            .iter()
            .position(|line| line["kind"] == "row_end")
            .unwrap();
    let sequence = metadata[second]["row"].clone();
    let mut replacement = metadata[first..=first_end].to_vec();
    for line in &mut replacement {
        if line.get("row").is_some() {
            line["row"] = sequence.clone();
        }
    }
    metadata.splice(second..=second_end, replacement);
    let originals: Vec<_> = private
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            line["kind"] == "private_cell" && line["dependency"]["table"] == "users"
        })
        .map(|(index, _)| index)
        .collect();
    assert_eq!(originals.len(), 2);
    let mut repeated = private[originals[0]].clone();
    repeated["row"] = sequence;
    private[originals[1]] = repeated;
}

async fn rejected_violation(kind: &str) {
    let custody = custody_fixture();
    let mut archive = archive_fixture::fixture().await;
    let (metadata, private) = archive_fixture::plaintext(&archive);
    let mut metadata = archive_fixture::lines(&metadata);
    let mut private = archive_fixture::lines(&private);
    match kind {
        "pk" => duplicate_user(&mut metadata, &mut private),
        "unique" => cell(
            &mut metadata,
            "users",
            1,
            "email",
            json!({"kind":"text","value":"a@example.invalid"}),
        ),
        "check" => cell(
            &mut metadata,
            "egress_request_nonces",
            0,
            "expires_at",
            json!({"kind":"integer","value":"1"}),
        ),
        "fk" => cell(
            &mut metadata,
            "user_identities",
            0,
            "user_id",
            json!({"kind":"integer","value":"9999"}),
        ),
        _ => panic!("unrecognized test violation"),
    }
    archive_fixture::reseal(&mut archive, metadata, private);
    // Real signed framing, all table/count grammar and exact private pairing
    // pass. The workflow must refuse the new independent SQL replay.
    assert_eq!(
        archive_fixture::verify(&archive).unwrap().counts(),
        &archive.output.counts
    );
    let directory = archive_directory(&custody, &archive, "invalid-capture");
    let error = workflow::verify(&directory, &reader_credentials(&custody), budget())
        .await
        .unwrap_err();
    assert!(matches!(error, SnapshotError::Verification));
    assert!(!format!("{error:?} {error}").contains("private-credential"));
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 3);

    // Optional author probe copies only synthetic test archives/custody into
    // a private gate directory. No production fixture or CLI API is exposed.
    if let Some(output) = std::env::var_os("AOS_SNAPSHOT_TEST_FIXTURE_DIR") {
        let output = std::path::Path::new(&output).join(kind);
        fs::create_dir(&output).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["archive.json", "metadata.aosh", "private.aosh"] {
            private_file(&output, name, &fs::read(directory.join(name)).unwrap());
        }
        private_file(
            output.parent().unwrap(),
            &format!("{kind}-pins.json"),
            &fs::read(&custody.credentials.signer_trust_file).unwrap(),
        );
        private_file(output.parent().unwrap(), "metadata.key", &[2; 32]);
        private_file(output.parent().unwrap(), "private.key", &[3; 32]);
    }
}

#[tokio::test]
async fn correctly_signed_duplicate_pk_fails_actual_workflow_sql_verification() {
    rejected_violation("pk").await;
}

#[tokio::test]
async fn correctly_signed_duplicate_unique_fails_actual_workflow_sql_verification() {
    rejected_violation("unique").await;
}

#[tokio::test]
async fn correctly_signed_false_check_fails_actual_workflow_sql_verification() {
    rejected_violation("check").await;
}

#[tokio::test]
async fn correctly_signed_dangling_fk_fails_actual_workflow_sql_verification() {
    rejected_violation("fk").await;
}

#[tokio::test]
async fn scratch_work_limits_refuse_capture_publication_and_existing_verify() {
    let custody = custody_fixture();
    let source = source(custody.directory.path()).await;
    let valid = custody.directory.path().join("valid");
    workflow::capture(&source, &valid, &custody.credentials, budget())
        .await
        .unwrap();
    let cases = [
        SnapshotScratchLimits {
            max_database_bytes: 4096,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_retained_rows: 1,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_value_bytes: 1,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_progress_callbacks: 1,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_duration: Duration::from_nanos(1),
            ..Default::default()
        },
    ];
    for (index, limits) in cases.into_iter().enumerate() {
        let destination = custody.directory.path().join(format!("limited-{index}"));
        let failure = workflow::capture(
            &source,
            &destination,
            &custody.credentials,
            budget().with_scratch_limits(limits).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(failure, SnapshotError::Limits));
        assert!(!destination.exists());
        let failure = workflow::verify(
            &valid,
            &reader_credentials(&custody),
            budget().with_scratch_limits(limits).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(matches!(failure, SnapshotError::Limits));
        assert_eq!(fs::read_dir(&valid).unwrap().count(), 3);
    }
    assert!(!fs::read_dir(custody.directory.path())
        .unwrap()
        .any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".aos-snapshot-")));
}

#[test]
fn unsupported_scratch_limits_are_refused_before_path_or_key_reads() {
    for limits in [
        SnapshotScratchLimits {
            max_database_bytes: 4095,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_database_bytes: 256 * 1024 * 1024 + 1,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_retained_rows: 0,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_retained_rows: 10_000_001,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_value_bytes: 0,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_value_bytes: 1024 * 1024 * 1024 + 1,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_duration: Duration::ZERO,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_duration: Duration::from_secs(3601),
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_progress_callbacks: 0,
            ..Default::default()
        },
        SnapshotScratchLimits {
            max_progress_callbacks: 1_000_001,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            budget().with_scratch_limits(limits),
            Err(SnapshotError::Limits)
        ));
    }
}

async fn wait_for_scratch_read(gate: &workflow::ScratchReadGate) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !gate.entered.load(std::sync::atomic::Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_during_actual_scratch_replay_returns_after_cleanup_without_report() {
    let custody = custody_fixture();
    let archive = archive_fixture::fixture().await;
    let directory = archive_directory(&custody, &archive, "valid-capture");
    let gate = std::sync::Arc::new(workflow::ScratchReadGate::default());
    let work = budget().with_read_gate(gate.clone());
    let signal = work.clone();
    let credentials = reader_credentials(&custody);
    let task = tokio::spawn(async move { workflow::verify(&directory, &credentials, work).await });
    wait_for_scratch_read(&gate).await;
    signal.cancel();
    assert!(matches!(task.await.unwrap(), Err(SnapshotError::Cancelled)));
    // Returning from the scratch API requires actual rollback/connection close.
    assert_eq!(
        fs::read_dir(custody.directory.path().join("valid-capture"))
            .unwrap()
            .count(),
        3
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_outer_verification_cancels_live_scratch_read_and_returns_no_report() {
    let custody = custody_fixture();
    let archive = archive_fixture::fixture().await;
    let directory = archive_directory(&custody, &archive, "valid-capture");
    let gate = std::sync::Arc::new(workflow::ScratchReadGate::default());
    let work = budget().with_read_gate(gate.clone());
    let observed = work.clone();
    let credentials = reader_credentials(&custody);
    let task = tokio::spawn(async move { workflow::verify(&directory, &credentials, work).await });
    wait_for_scratch_read(&gate).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(observed.is_cancelled_for_test());
    // The shared budget releases the paused read cooperatively. The independently
    // qualified scratch drop guard owns eventual rollback/destruction; this test
    // makes no immediate blocked-I/O cleanup guarantee.
    assert_eq!(
        fs::read_dir(custody.directory.path().join("valid-capture"))
            .unwrap()
            .count(),
        3
    );
}
