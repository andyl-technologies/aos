//! Lifecycle-aware plugin control channel adapters.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crucible_linux_resource::host_supervision::HostOperationGuard;

use crucible_protocol::ControlLifecycleStream;

use crate::{QemuNodeChannelError, QemuPluginIpcControlChannel};

impl<S> QemuPluginIpcControlChannel for ControlLifecycleStream<S>
where
    S: Write + Send + 'static,
{
    fn send_quit(&mut self) -> Result<(), QemuNodeChannelError> {
        self.host_send_quit().map_err(|source| {
            QemuNodeChannelError::new("send plugin control Quit", source.to_string())
        })
    }

    fn send_quit_supervised(
        &mut self,
        guard: &HostOperationGuard,
    ) -> Result<(), QemuNodeChannelError> {
        self.host_send_quit_with_writer(|stream, frame| {
            let writer = (stream as &mut dyn std::any::Any)
                .downcast_mut::<UnixStream>()
                .ok_or(crucible_protocol::FrameIoError::Io {
                    operation: "select bounded control writer",
                    kind: io::ErrorKind::Unsupported,
                })?;
            write_supervised_control_frame(writer, frame, guard)
        })
        .map_err(|source| {
            QemuNodeChannelError::new("send supervised plugin Quit", source.to_string())
        })
    }
}

pub(crate) fn write_supervised_control_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    guard: &HostOperationGuard,
) -> Result<(), crucible_protocol::FrameIoError> {
    let failure = |kind| crucible_protocol::FrameIoError::Io {
        operation: "write supervised control frame",
        kind,
    };
    let mut offset = 0;
    while offset < frame.len() {
        let slice = guard
            .wait_slice()
            .map_err(|_| failure(io::ErrorKind::TimedOut))?;
        stream
            .set_write_timeout(Some(slice.min(Duration::from_millis(10))))
            .map_err(|source| failure(source.kind()))?;
        match stream.write(&frame[offset..]) {
            Ok(0) => return Err(failure(io::ErrorKind::WriteZero)),
            Ok(written) => offset += written,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source)
                if matches!(
                    source.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                guard
                    .wait_for_change()
                    .map_err(|_| failure(io::ErrorKind::TimedOut))?;
            }
            Err(source) => return Err(failure(source.kind())),
        }
    }
    guard
        .wait_slice()
        .map_err(|_| failure(io::ErrorKind::TimedOut))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- control fixtures panic on failed framing, ownership or original-deadline assertions.
    #![allow(clippy::unwrap_used)]

    use std::io::Read;
    use std::sync::mpsc;

    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };
    use crucible_protocol::ControlLifecycleState;

    use super::*;

    #[test]
    fn supervised_control_write_preserves_the_complete_frame_cursor() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let frame = vec![0x73; 128 * 1024];
        let expected = frame.clone();
        let receiver = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut buffer = [0; 127];
            while bytes.len() < expected.len() {
                let count = reader.read(&mut buffer).unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&buffer[..count]);
            }
            assert_eq!(bytes, expected);
        });
        let owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let guard = owner.begin(HostOperationClass::Cleanup).unwrap();

        write_supervised_control_frame(&mut writer, &frame, &guard).unwrap();

        receiver.join().unwrap();
        guard.complete().unwrap();
    }

    #[test]
    fn blocked_quit_observes_budget_reduction_without_committing_lifecycle() {
        let (mut writer, _retained_reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let mut saturated = false;
        for _ in 0..4096 {
            match writer.write(&[0x34; 4096]) {
                Ok(_) => {}
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    saturated = true;
                    break;
                }
                Err(source) => panic!("fill control socket: {source}"),
            }
        }
        assert!(saturated);
        writer.set_nonblocking(false).unwrap();
        let owner = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        let guard = owner.begin(HostOperationClass::Cleanup).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut control = ControlLifecycleStream::restored_run_via_shared_memory(writer);
            started_tx.send(()).unwrap();
            let result = control.send_quit_supervised(&guard);
            finished_tx
                .send((result.is_err(), control.state()))
                .unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let (revision, mut budgets) = owner.budgets().unwrap();
        budgets.classes[HostOperationClass::Cleanup as usize].total_timeout =
            Some(Duration::from_nanos(1));

        owner.update_budgets(revision, budgets).unwrap();

        assert_eq!(
            finished_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            (true, ControlLifecycleState::RunningViaSharedMemory)
        );
        worker.join().unwrap();
    }
}
