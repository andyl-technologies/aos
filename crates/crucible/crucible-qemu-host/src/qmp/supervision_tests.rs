//! Checks actual QMP supervision refusals before command transport effects.

use super::*;
use crate::{QemuNodeChannelPlane, QemuNodeError};
use crucible_host_resources::host_supervision::{
    HostOperationBudgets, HostOperationState, HostSupervisionError,
};
use crucible_host_resources::test_support::TestAllocationObserver;
use std::error::Error;
use std::io::Cursor;

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Debug)]
struct Stream {
    replies: Cursor<&'static [u8]>,
    written: usize,
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.replies.read(bytes)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written += bytes.len();
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

#[test]
fn actual_canceled_qmp_command_keeps_cause_without_allocation_or_transport() -> TestResult {
    let mut client = QmpClient::connect(Stream {
        replies: Cursor::new(b"{\"QMP\":{\"version\":{},\"capabilities\":[]}}\n{\"return\":{}}\n"),
        written: 0,
    })?;
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    client.set_host_operation_supervisor(supervisor.clone());
    supervisor.cancel()?;
    let written = client.stream.get_ref().written;
    let expected = HostSupervisionError::Terminal {
        state: HostOperationState::Canceled,
    };

    let (result, counts) = TestAllocationObserver::count(|| {
        client
            .query_status()
            .map_err(QemuNodeChannelError::from)
            .map_err(|error| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, error)
            })
    });

    let error = result.expect_err("actual command admission is canceled");
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(client.stream.get_ref().written, written);
    assert_eq!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<HostSupervisionError>()),
        Some(&expected)
    );
    Ok(())
}

#[test]
fn actual_qmp_deadline_refusals_keep_typed_cause_without_allocating() -> TestResult {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
    let shared_guard = supervisor.begin(HostOperationClass::Preparation)?;
    let borrowed_guard = supervisor.begin(HostOperationClass::Preparation)?;
    let mut shared = QmpOperationDeadline::new(Duration::from_secs(1));
    shared.shared = Some(shared_guard);
    let mut borrowed = QmpOperationDeadline::new(Duration::from_secs(1));
    borrowed.borrowed = Some(&borrowed_guard);
    supervisor.cancel()?;
    let expected = HostSupervisionError::Terminal {
        state: HostOperationState::Canceled,
    };

    let (errors, counts) = TestAllocationObserver::count(|| {
        [
            shared.remaining("probe QMP original").map(|_| ()),
            borrowed.remaining("probe QMP original").map(|_| ()),
            shared.complete("probe QMP original"),
            borrowed.complete("probe QMP original"),
        ]
        .map(|result| {
            let qmp = result.expect_err("the same actual original is canceled");
            let channel = QemuNodeChannelError::from(qmp.clone());
            (
                qmp,
                QemuNodeError::from_channel(QemuNodeChannelPlane::QmpMachineControl, channel),
            )
        })
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    for (qmp, node) in errors {
        assert_eq!(
            qmp.source()
                .and_then(|source| source.downcast_ref::<HostSupervisionError>()),
            Some(&expected)
        );
        assert_eq!(
            qmp.to_string(),
            format!("probe QMP original host supervision failed: {expected}")
        );
        assert_eq!(
            node.source()
                .and_then(|source| source.downcast_ref::<HostSupervisionError>()),
            Some(&expected)
        );
    }
    Ok(())
}
