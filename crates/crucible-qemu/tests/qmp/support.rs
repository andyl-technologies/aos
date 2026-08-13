//! Scripted QMP stream and audit support for integration tests.

use super::*;

pub(super) fn loadvm_probe_authorization() -> crucible_qemu::QemuLoadvmCommandAuthorization {
    QemuSavevmCompletenessPolicy::phase0_fallback().authorize_loadvm_probe()
}

pub(super) fn scripted_qmp<const N: usize>(lines: [&str; N]) -> ScriptedQmpStream {
    let mut input = Vec::new();
    for line in lines {
        input.extend_from_slice(line.as_bytes());
        input.extend_from_slice(b"\r\n");
    }
    ScriptedQmpStream {
        read: Cursor::new(input),
        audit: Arc::new(Mutex::new(ScriptedQmpAudit::default())),
    }
}

pub(super) fn written_json_lines(
    audit: &ScriptedQmpAudit,
) -> Result<Vec<Value>, serde_json::Error> {
    String::from_utf8_lossy(&audit.written)
        .lines()
        .map(serde_json::from_str)
        .collect()
}

pub(super) fn audit_snapshot(handle: &Arc<Mutex<ScriptedQmpAudit>>) -> ScriptedQmpAudit {
    handle
        .lock()
        .expect("scripted QMP audit lock should remain available")
        .clone()
}

pub(super) fn json_line(lines: &[Value], index: usize) -> &Value {
    match lines.get(index) {
        Some(line) => line,
        None => panic!("missing written QMP line {index}"),
    }
}

pub(super) fn execute_name(value: &Value) -> Option<&str> {
    value.get("execute").and_then(Value::as_str)
}

pub(super) fn assert_timeout_budget(timeouts: &[Duration], budget: Duration) {
    assert!(!timeouts.is_empty());
    assert!(
        timeouts
            .iter()
            .all(|timeout| !timeout.is_zero() && *timeout <= budget)
    );
}

pub(super) fn checkpoint_with_hash_byte(byte: u8) -> Checkpoint {
    Checkpoint::new(
        content_hash_with_byte(byte),
        content_hash_with_byte(byte.wrapping_add(1)),
        CheckpointKind::Fat,
    )
}

pub(super) fn content_hash_with_byte(byte: u8) -> ContentHash {
    ContentHash { bytes: [byte; 32] }
}

#[derive(Debug)]
pub(super) struct ScriptedQmpStream {
    pub(super) read: Cursor<Vec<u8>>,
    pub(super) audit: Arc<Mutex<ScriptedQmpAudit>>,
}

impl ScriptedQmpStream {
    pub(super) fn audit_handle(&self) -> Arc<Mutex<ScriptedQmpAudit>> {
        Arc::clone(&self.audit)
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct ScriptedQmpAudit {
    pub(super) written: Vec<u8>,
    pub(super) read_timeouts: Vec<Duration>,
    pub(super) write_timeouts: Vec<Duration>,
}

impl Read for ScriptedQmpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read.read(buf)
    }
}

impl Write for ScriptedQmpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.audit
            .lock()
            .map_err(|_| io::Error::other("scripted QMP audit lock poisoned"))?
            .written
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for ScriptedQmpStream {
    fn set_qmp_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.audit
            .lock()
            .map_err(|_| io::Error::other("scripted QMP audit lock poisoned"))?
            .read_timeouts
            .push(timeout);
        Ok(())
    }

    fn set_qmp_write_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.audit
            .lock()
            .map_err(|_| io::Error::other("scripted QMP audit lock poisoned"))?
            .write_timeouts
            .push(timeout);
        Ok(())
    }
}
