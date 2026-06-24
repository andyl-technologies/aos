//! Checks the minimal typed QMP client.

#![forbid(unsafe_code)]

use std::error::Error;
use std::io::{self, Cursor, Read, Write};

use crucible::{Checkpoint, CheckpointKind, ContentHash};
use crucible_qemu::{
    QMP_CAPABILITIES_COMMAND, QMP_QUERY_JOBS_COMMAND, QMP_QUIT_COMMAND_NAME,
    QMP_SNAPSHOT_LOAD_COMMAND, QMP_SNAPSHOT_SAVE_COMMAND, QMP_SNAPSHOT_VMSTATE_DEVICE,
    QemuSavevmCompletenessPolicy, QmpClient, QmpCommandKind, QmpError, QmpGreeting,
    QmpJobPollPolicy, QmpSnapshotTag,
};
use serde_json::Value;

const HASH_AB_TAG: &str =
    "crucible-abababababababababababababababababababababababababababababababab";
const HASH_CD_TAG: &str =
    "crucible-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const HASH_EF_TAG: &str =
    "crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

#[test]
fn qmp_connect_reads_greeting_and_negotiates_capabilities() -> Result<(), Box<dyn Error>> {
    let client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{"qemu":{"major":10,"minor":0,"micro":0}},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
    ]))?;

    assert_eq!(
        client.greeting(),
        QmpGreeting {
            version_present: true,
            capabilities_present: true,
        }
    );
    let stream = client.into_inner();
    let lines = written_json_lines(&stream)?;
    assert_eq!(
        execute_name(json_line(&lines, 0)),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    Ok(())
}

#[test]
fn savevm_uses_snapshot_save_with_checkpoint_derived_tag() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
    ]))?;
    let checkpoint = checkpoint_with_hash_byte(0xab);
    let tag = QmpSnapshotTag::from_checkpoint(&checkpoint);

    let complete = client.savevm(&tag)?;
    assert_eq!(complete.command, QmpCommandKind::SaveVm);

    let stream = client.into_inner();
    let lines = written_json_lines(&stream)?;
    let request = json_line(&lines, 1);
    assert_eq!(execute_name(request), Some(QMP_SNAPSHOT_SAVE_COMMAND));
    assert_eq!(
        request.pointer("/arguments/tag").and_then(Value::as_str),
        Some(HASH_AB_TAG)
    );
    assert_eq!(
        request
            .pointer("/arguments/vmstate")
            .and_then(Value::as_str),
        Some(QMP_SNAPSHOT_VMSTATE_DEVICE)
    );
    assert_eq!(
        request
            .pointer("/arguments/devices/0")
            .and_then(Value::as_str),
        Some(QMP_SNAPSHOT_VMSTATE_DEVICE)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    Ok(())
}

#[test]
fn loadvm_and_quit_are_typed_qmp_commands() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-load-crucible-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]))?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xcd));

    assert_eq!(
        client.loadvm(&tag, loadvm_probe_authorization())?.command,
        QmpCommandKind::LoadVm
    );
    assert_eq!(client.quit()?.command, QmpCommandKind::Quit);

    let stream = client.into_inner();
    let lines = written_json_lines(&stream)?;
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_SNAPSHOT_LOAD_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/tag")
            .and_then(Value::as_str),
        Some(HASH_CD_TAG)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 3)),
        Some(QMP_QUIT_COMMAND_NAME)
    );
    Ok(())
}

#[test]
fn qmp_client_skips_async_events_until_command_return() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"event":"STOP","timestamp":{"seconds":1,"microseconds":2}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"concluded"}]}"#,
    ]))?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    assert_eq!(client.savevm(&tag)?.command, QmpCommandKind::SaveVm);
    Ok(())
}

#[test]
fn qmp_snapshot_job_error_is_typed_result_error() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"concluded","error":{"class":"GenericError","desc":"job failed"}}]}"#,
    ]))?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    match client.savevm(&tag) {
        Ok(_) => panic!("expected typed QMP job error"),
        Err(QmpError::JobFailed {
            command,
            job_id,
            detail,
        }) => {
            assert_eq!(command, QmpCommandKind::SaveVm);
            assert_eq!(job_id, format!("crucible-save-{HASH_EF_TAG}"));
            assert!(detail.contains("job failed"));
        }
        Err(other) => panic!("expected QMP job error, got {other:?}"),
    }
    Ok(())
}

#[test]
fn qmp_snapshot_job_polling_waits_until_concluded() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect_with_job_poll_policy(
        scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            r#"{"return":{}}"#,
            r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"running"}]}"#,
            r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"concluded"}]}"#,
        ]),
        QmpJobPollPolicy::fast_test(4),
    )?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    assert_eq!(client.savevm(&tag)?.command, QmpCommandKind::SaveVm);

    let stream = client.into_inner();
    let lines = written_json_lines(&stream)?;
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 3)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    Ok(())
}

#[test]
fn qmp_snapshot_job_timeout_is_typed_result_error() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect_with_job_poll_policy(
        scripted_qmp([
            r#"{"QMP":{"version":{},"capabilities":[]}}"#,
            r#"{"return":{}}"#,
            r#"{"return":{}}"#,
            r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"running"}]}"#,
            r#"{"return":[{"id":"crucible-save-crucible-efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","status":"running"}]}"#,
        ]),
        QmpJobPollPolicy::fast_test(2),
    )?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    match client.savevm(&tag) {
        Ok(_) => panic!("expected QMP job timeout"),
        Err(QmpError::JobNotConcluded {
            command,
            job_id,
            polls,
        }) => {
            assert_eq!(command, QmpCommandKind::SaveVm);
            assert_eq!(job_id, format!("crucible-save-{HASH_EF_TAG}"));
            assert_eq!(polls, 2);
        }
        Err(other) => panic!("expected QMP job timeout, got {other:?}"),
    }
    Ok(())
}

#[test]
fn qmp_error_response_is_typed_result_error() -> Result<(), Box<dyn Error>> {
    let mut client = QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"error":{"class":"GenericError","desc":"snapshot missing"}}"#,
    ]))?;
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    match client.loadvm(&tag, loadvm_probe_authorization()) {
        Ok(_) => panic!("expected typed QMP error"),
        Err(QmpError::Command {
            command,
            class,
            description,
        }) => {
            assert_eq!(command, QmpCommandKind::LoadVm);
            assert_eq!(class, "GenericError");
            assert_eq!(description, "snapshot missing");
        }
        Err(other) => panic!("expected QMP command error, got {other:?}"),
    }
    Ok(())
}

#[test]
fn unexpected_qmp_shapes_are_typed_errors() {
    match QmpClient::connect(scripted_qmp([r#"{"event":"RESET"}"#])) {
        Ok(_) => panic!("expected unexpected greeting error"),
        Err(QmpError::UnexpectedGreeting { response }) => {
            assert!(response.contains("RESET"));
        }
        Err(other) => panic!("expected unexpected greeting error, got {other:?}"),
    }
    match QmpClient::connect(scripted_qmp([r#"{"QMP":{"version":{}}}"#])) {
        Ok(_) => panic!("expected incomplete greeting error"),
        Err(QmpError::UnexpectedGreeting { response }) => {
            assert!(response.contains("version"));
        }
        Err(other) => panic!("expected incomplete greeting error, got {other:?}"),
    }

    let mut client = match QmpClient::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"timestamp":{"seconds":1}}"#,
    ])) {
        Ok(client) => client,
        Err(error) => panic!("connect failed unexpectedly: {error}"),
    };
    let tag = QmpSnapshotTag::from_checkpoint_content_address(content_hash_with_byte(0xef));

    match client.savevm(&tag) {
        Ok(_) => panic!("expected unexpected response error"),
        Err(QmpError::UnexpectedResponse { command, response }) => {
            assert_eq!(command, QmpCommandKind::SaveVm);
            assert!(response.contains("timestamp"));
        }
        Err(other) => panic!("expected unexpected response error, got {other:?}"),
    }
}

#[test]
fn snapshot_tags_are_derived_from_checkpoint_content_hash() {
    let checkpoint = checkpoint_with_hash_byte(0xab);

    assert_eq!(
        QmpSnapshotTag::from_checkpoint(&checkpoint),
        QmpSnapshotTag::from_checkpoint_content_address(checkpoint.id)
    );
    assert_eq!(
        QmpSnapshotTag::from_checkpoint(&checkpoint).as_str(),
        HASH_AB_TAG
    );
}

fn loadvm_probe_authorization() -> crucible_qemu::QemuLoadvmCommandAuthorization {
    QemuSavevmCompletenessPolicy::phase0_fallback().authorize_loadvm_probe()
}

fn scripted_qmp<const N: usize>(lines: [&str; N]) -> ScriptedQmpStream {
    let mut input = Vec::new();
    for line in lines {
        input.extend_from_slice(line.as_bytes());
        input.extend_from_slice(b"\r\n");
    }
    ScriptedQmpStream {
        read: Cursor::new(input),
        written: Vec::new(),
    }
}

fn written_json_lines(stream: &ScriptedQmpStream) -> Result<Vec<Value>, serde_json::Error> {
    String::from_utf8_lossy(&stream.written)
        .lines()
        .map(serde_json::from_str)
        .collect()
}

fn json_line(lines: &[Value], index: usize) -> &Value {
    match lines.get(index) {
        Some(line) => line,
        None => panic!("missing written QMP line {index}"),
    }
}

fn execute_name(value: &Value) -> Option<&str> {
    value.get("execute").and_then(Value::as_str)
}

fn checkpoint_with_hash_byte(byte: u8) -> Checkpoint {
    Checkpoint {
        id: content_hash_with_byte(byte),
        configuration: content_hash_with_byte(byte.wrapping_add(1)),
        kind: CheckpointKind::Fat,
    }
}

fn content_hash_with_byte(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}

#[derive(Debug)]
struct ScriptedQmpStream {
    read: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl Read for ScriptedQmpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read.read(buf)
    }
}

impl Write for ScriptedQmpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
