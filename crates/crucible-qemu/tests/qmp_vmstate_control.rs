//! Checks checkpoint-tagged QMP VMState control.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::io::{self, Cursor, Read, Write};
use std::time::Duration;

use crucible::{Checkpoint, CheckpointKind, ContentHash};
use crucible_qemu::{
    QMP_CAPABILITIES_COMMAND, QMP_QUERY_JOBS_COMMAND, QMP_QUIT_COMMAND_NAME,
    QMP_SNAPSHOT_LOAD_COMMAND, QMP_SNAPSHOT_SAVE_COMMAND, QemuQmpVmStateControlChannel,
    QemuSavevmCompletenessPolicy, QmpCommandKind, QmpSnapshotTag, QmpTimeoutStream,
};
use serde_json::Value;

const HASH_AB_TAG: &str =
    "crucible-abababababababababababababababababababababababababababababababab";

#[test]
fn vmstate_control_saves_and_restores_checkpoint_tags() -> Result<(), Box<dyn Error>> {
    let mut control = QemuQmpVmStateControlChannel::connect(scripted_qmp([
        r#"{"QMP":{"version":{},"capabilities":[]}}"#,
        r#"{"return":{}}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-save-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
        r#"{"return":[{"id":"crucible-load-crucible-abababababababababababababababababababababababababababababababab","status":"concluded"}]}"#,
        r#"{"return":{}}"#,
    ]))?;
    let checkpoint = checkpoint_with_hash_byte(0xab);

    assert_eq!(
        control.save_checkpoint_vmstate(&checkpoint)?.command,
        QmpCommandKind::SaveVm
    );
    assert_eq!(
        control
            .restore_checkpoint_vmstate(&checkpoint, loadvm_probe_authorization())?
            .command,
        QmpCommandKind::LoadVm
    );
    assert_eq!(control.quit()?.command, QmpCommandKind::Quit);

    let stream = control.into_inner().into_inner();
    let lines = written_json_lines(&stream)?;
    assert_eq!(
        execute_name(json_line(&lines, 0)),
        Some(QMP_CAPABILITIES_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 1)),
        Some(QMP_SNAPSHOT_SAVE_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 1)
            .pointer("/arguments/tag")
            .and_then(Value::as_str),
        Some(HASH_AB_TAG)
    );
    assert_eq!(
        execute_name(json_line(&lines, 2)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 3)),
        Some(QMP_SNAPSHOT_LOAD_COMMAND)
    );
    assert_eq!(
        json_line(&lines, 3)
            .pointer("/arguments/tag")
            .and_then(Value::as_str),
        Some(HASH_AB_TAG)
    );
    assert_eq!(
        execute_name(json_line(&lines, 4)),
        Some(QMP_QUERY_JOBS_COMMAND)
    );
    assert_eq!(
        execute_name(json_line(&lines, 5)),
        Some(QMP_QUIT_COMMAND_NAME)
    );
    Ok(())
}

#[test]
fn vmstate_control_uses_the_public_snapshot_tag_derivation() {
    let checkpoint = checkpoint_with_hash_byte(0xab);
    let tag = QmpSnapshotTag::from_checkpoint(&checkpoint);

    assert_eq!(tag.as_str(), HASH_AB_TAG);
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
        read_timeouts: Vec::new(),
        write_timeouts: Vec::new(),
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
    Checkpoint::new(
        content_hash_with_byte(byte),
        content_hash_with_byte(byte.wrapping_add(1)),
        CheckpointKind::Fat,
    )
}

fn content_hash_with_byte(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}

#[derive(Debug)]
struct ScriptedQmpStream {
    read: Cursor<Vec<u8>>,
    written: Vec<u8>,
    read_timeouts: Vec<Duration>,
    write_timeouts: Vec<Duration>,
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

impl QmpTimeoutStream for ScriptedQmpStream {
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.read_timeouts.push(timeout);
        Ok(())
    }

    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.write_timeouts.push(timeout);
        Ok(())
    }
}
