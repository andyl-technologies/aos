//! Real Unix QMP/private-stream failures with explicitly modeled child status.
//!
//! The native producer, fork identity, and terminal readiness are modeled. The
//! greeting parser, failed socket write, diagnostics drain and error retention
//! are production implementations. No native child or waitpid result is minted.

use std::error::Error;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

struct FailedQmpBackend {
    consumer: QemuHotForkChildDiagnosticConsumer,
    private_writer: UnixStream,
    qmp: Option<UnixStream>,
    order: Arc<AtomicUsize>,
}

impl QemuHotForkReconciliationBackend for FailedQmpBackend {
    type Error = LinuxQemuHotForkReconciliationError;

    fn child_basis(&self) -> QemuHotForkReconciliationChildBasis {
        QemuHotForkReconciliationChildBasis::new(13, 733)
    }

    fn admit_child_channel(&mut self) -> Result<(), Self::Error> {
        self.private_writer
            .write_all(b"child failed: step 11 detail 2 result -5\n")
            .map_err(|source| {
                QemuNodeChannelError::new("modeled private diagnostic writer", source.to_string())
            })?;
        let socket = self.qmp.take().ok_or(Self::Error::BasisMismatch)?;
        let source = match crucible_qemu::QmpClient::connect(socket) {
            Err(source) => source,
            Ok(_) => return Err(Self::Error::BasisMismatch),
        };
        assert!(matches!(
            source,
            crucible_qemu::QmpError::Io {
                kind: std::io::ErrorKind::BrokenPipe,
                ..
            }
        ));
        let report = capture(
            &mut self.consumer,
            modeled_basis(),
            &modeled_identity(),
            || Ok(true),
        );
        self.order.store(1, Ordering::SeqCst);
        Err(Self::Error::ChildAdmission {
            source: QemuNodeChannelError::new("private child QMP exchange", source.to_string()),
            report: Box::new(report),
        })
    }

    fn drain_child_diagnostics(&mut self) -> Result<(), Self::Error> {
        self.consumer.drain_available()?;
        Ok(())
    }

    fn quarantine(&mut self) {
        assert_eq!(self.order.swap(2, Ordering::SeqCst), 1);
        assert!(self.consumer.retained().starts_with(b"child failed:"));
    }

    fn terminate_child(&mut self) -> Result<(), Self::Error> {
        Err(Self::Error::BasisMismatch)
    }

    fn observe_child(&mut self) -> Result<QemuHotForkChildObservation, Self::Error> {
        Err(Self::Error::BasisMismatch)
    }

    fn release_next_child_resource(&mut self) -> Result<bool, Self::Error> {
        Err(Self::Error::BasisMismatch)
    }

    fn release_target(&mut self) -> Result<(), Self::Error> {
        Err(Self::Error::BasisMismatch)
    }

    fn release_source_status(
        &mut self,
        _terminal: QemuHotForkChildObservation,
    ) -> Result<(), Self::Error> {
        Err(Self::Error::BasisMismatch)
    }

    fn release_process_contract(&mut self) -> Result<(), Self::Error> {
        Err(Self::Error::BasisMismatch)
    }
}

fn modeled_identity() -> QemuProcessIdentity {
    QemuProcessIdentity {
        process_id: 733,
        start_time_ticks: 81234,
        executable: "/modeled/private-child-qemu".into(),
    }
}

fn modeled_basis() -> QemuHotForkChildProcessBasis {
    QemuHotForkChildProcessBasis::from_unvalidated_test_process_ids(611, 733)
}

fn private_stream() -> Result<(QemuHotForkChildDiagnosticConsumer, UnixStream), Box<dyn Error>> {
    let (reader, writer) = UnixStream::pair()?;
    let consumer = QemuHotForkChildDiagnosticConsumer::from_unvalidated_test_stream(
        reader,
        crucible_qemu::QmpDescriptorName::new("modeled-branch-private-stderr")?,
        0x1234,
        4,
    )?;
    Ok((consumer, writer))
}

#[test]
fn failed_qmp_greeting_preserves_private_evidence_before_quarantine() -> TestResult {
    let (consumer, mut writer) = private_stream()?;
    let (host_qmp, mut child_qmp) = UnixStream::pair()?;
    let (mut source_reader, mut source_writer) = UnixStream::pair()?;
    source_writer.write_all(b"source stderr sentinel")?;
    child_qmp.write_all(b"{\"QMP\":{\"version\":{},\"capabilities\":[\"oob\"]}}\r\n")?;
    child_qmp.shutdown(Shutdown::Both)?;
    drop(child_qmp);

    // The greeting is readable, but the original capabilities write fails.
    let order = Arc::new(AtomicUsize::new(0));
    let mut owner = QemuHotForkAttemptReconciliation::new(FailedQmpBackend {
        consumer,
        private_writer: writer.try_clone()?,
        qmp: Some(host_qmp),
        order: Arc::clone(&order),
    });
    let error = match owner.admit_child() {
        Err(error) => error,
        Ok(()) => return Err("closed child QMP unexpectedly negotiated".into()),
    };
    assert_eq!(owner.phase(), QemuHotForkReconciliationPhase::Quarantined);
    assert_eq!(order.load(Ordering::SeqCst), 2);
    let described = error.to_string();
    assert!(described.contains("BrokenPipe"));
    let QemuHotForkAttemptReconciliationError::Operation {
        source: LinuxQemuHotForkReconciliationError::ChildAdmission { source, .. },
        ..
    } = &error
    else {
        return Err("original typed admission cause was lost".into());
    };
    assert!(source.to_string().contains("BrokenPipe"));
    assert!(described.contains("source_pid=611 child_pid=733 process_start_ticks=81234"));
    assert!(described.contains("child failed: step 11 detail 2 result -5\\n"));
    assert!(described.contains("pidfd_terminal_readiness=Ok(true) exit_code=unobserved"));
    assert!(!described.contains("source stderr sentinel"));
    let mut source_bytes = [0_u8; 22];
    source_reader.read_exact(&mut source_bytes)?;
    assert_eq!(&source_bytes, b"source stderr sentinel");
    let backend = owner
        .backend
        .as_mut()
        .ok_or("failed owner lost its backend")?;
    assert_eq!(
        backend.consumer.retained(),
        b"child failed: step 11 detail 2 result -5\n"
    );

    // Capturing the report neither closes nor finalizes the owned stream.
    writer.write_all(b"still owned before quarantine\n")?;
    backend.consumer.drain_available()?;
    assert!(
        backend
            .consumer
            .retained()
            .ends_with(b"still owned before quarantine\n")
    );
    Ok(())
}

#[test]
fn admission_evidence_bounds_and_escapes_arbitrary_private_bytes() -> TestResult {
    let (mut consumer, mut writer) = private_stream()?;
    let prefix = vec![b'p'; MAX_REPORTED_STDERR_BYTES];
    writer.write_all(&prefix)?;
    consumer.drain_available()?;
    writer.write_all(b"\xff\0\n\"\\")?;
    let report = capture(&mut consumer, modeled_basis(), &modeled_identity(), || {
        Ok(false)
    });
    assert_eq!(report.retained_bytes, prefix.len() + 5);
    assert_eq!(report.stderr_tail.len(), MAX_REPORTED_STDERR_BYTES);
    let described = report.to_string();
    assert!(described.contains("omitted_prefix_bytes=5"));
    assert!(described.ends_with("\\xff\\x00\\n\\\"\\\\\""));
    assert!(!described.contains('\0'));
    assert!(described.len() < 4 * MAX_REPORTED_STDERR_BYTES + 8192);
    Ok(())
}

#[test]
fn drain_failure_keeps_retained_prefix_and_original_admission_cause() -> TestResult {
    let (mut consumer, mut writer) = private_stream()?;
    writer.write_all(b"private prefix before read loss\n")?;
    consumer.drain_available()?;
    // Reading after local shutdown deterministically yields EOF, not an I/O
    // error. Capacity loss instead uses the real cumulative production guard.
    let chunk = vec![b'x'; 64 * 1024];
    while consumer.retained().len() + chunk.len()
        <= crucible_qemu::MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES
    {
        writer.write_all(&chunk)?;
        consumer.drain_available()?;
    }
    let remaining =
        crucible_qemu::MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES - consumer.retained().len();
    writer.write_all(&vec![b'y'; remaining])?;
    consumer.drain_available()?;
    writer.write_all(b"one byte beyond the capture ceiling")?;
    let report = capture(&mut consumer, modeled_basis(), &modeled_identity(), || {
        Err(QemuVmRealizationError::ExecutorUnavailable {
            operation: "modeled interrupted pidfd observation",
            message: "interrupted".into(),
        })
    });
    assert!(report.drain.is_err());
    assert!(report.terminal_readiness.is_err());
    assert_eq!(
        report.retained_bytes,
        crucible_qemu::MAX_QEMU_HOT_FORK_CHILD_DIAGNOSTIC_BYTES
    );
    assert!(
        consumer
            .retained()
            .starts_with(b"private prefix before read loss\n")
    );
    let error = LinuxQemuHotForkReconciliationError::ChildAdmission {
        source: QemuNodeChannelError::new("original child QMP", "original broken pipe"),
        report: Box::new(report),
    };
    assert!(error.to_string().contains("original broken pipe"));
    assert!(error.to_string().contains("drain=Err("));
    Ok(())
}
