//! Same-original query routing and cancellation on an actual component stream.

use super::*;
use crucible_host_resources::host_supervision::HostOperationBudgets;
use std::sync::{Arc, Mutex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

type RecordedWrites = Arc<Mutex<Vec<u8>>>;

#[derive(Debug)]
struct Stream {
    replies: io::Cursor<Vec<u8>>,
    writes: RecordedWrites,
    cancel_on_read: Option<HostOperationSupervisor>,
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some(original) = self.cancel_on_read.take() {
            original.cancel().map_err(io::Error::other)?;
        }
        let length = bytes.len().min(1);
        self.replies.read(&mut bytes[..length])
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes
            .lock()
            .map_err(|_| io::Error::other("component writes poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for Stream {
    fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
    fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
        Ok(())
    }
}

fn client(response: Value) -> Result<(QmpClient<Stream>, RecordedWrites), QmpError> {
    let writes = Arc::new(Mutex::new(Vec::new()));
    let replies = format!(
        "{}\n{}\n{}\n",
        json!({"QMP":{"version":{},"capabilities":[]}}),
        json!({"return":{}}),
        response
    );
    Ok((
        QmpClient::connect(Stream {
            replies: io::Cursor::new(replies.into_bytes()),
            writes: writes.clone(),
            cancel_on_read: None,
        })?,
        writes,
    ))
}

#[test]
fn receiving_runstate_requires_exact_typed_paused_status() -> TestResult {
    for (status, running, expected) in [
        ("paused", false, true),
        ("running", true, false),
        ("shutdown", false, false),
    ] {
        let (mut client, _) = client(json!({"return":{"status":status,"running":running}}))?;
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(300)),
        )?;
        let original = supervisor.begin(HostOperationClass::Transfer)?;
        assert_eq!(client.is_stopped_for_transfer(&original)?, expected);
        original.wait_slice()?;
    }
    let (mut client, _) = client(json!({"return":{"status":"paused","running":true}}))?;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(300)),
    )?;
    let original = supervisor.begin(HostOperationClass::Transfer)?;
    assert!(matches!(
        client.is_stopped_for_transfer(&original),
        Err(QmpError::MalformedTypedResponse { .. })
    ));
    Ok(())
}

#[test]
fn receiving_wrong_class_and_canceled_original_emit_no_status_request() -> TestResult {
    for class in [
        HostOperationClass::Setup,
        HostOperationClass::Cleanup,
        HostOperationClass::Transfer,
    ] {
        let (mut client, writes) = client(json!({"return":{"status":"paused","running":false}}))?;
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(300)),
        )?;
        let original = supervisor.begin(class)?;
        if class == HostOperationClass::Transfer {
            supervisor.cancel()?;
        }
        let before = writes.lock().map_err(|_| "write log poisoned")?.clone();
        assert!(matches!(
            client.is_stopped_for_transfer(&original),
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert_eq!(*writes.lock().map_err(|_| "write log poisoned")?, before);
    }
    Ok(())
}

#[test]
fn receiving_response_read_cancellation_refuses_and_preserves_stream_uncertainty() -> TestResult {
    let (mut client, writes) = client(json!({"return":{"status":"paused","running":false}}))?;
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(300)),
    )?;
    let original = supervisor.begin(HostOperationClass::Transfer)?;
    client.stream.get_mut().cancel_on_read = Some(supervisor.clone());
    assert!(client.is_stopped_for_transfer(&original).is_err());
    let sent = writes.lock().map_err(|_| "write log poisoned")?.clone();
    assert!(String::from_utf8(sent.clone())?.contains("query-status"));
    assert!(client.poisoned);
    assert!(client.is_stopped_for_transfer(&original).is_err());
    assert_eq!(*writes.lock().map_err(|_| "write log poisoned")?, sent);
    Ok(())
}
