//! Fixed retained native intake for the original internal IO relay connection.

use aos_sandbox_linux::seqpacket::{
    ReceivedRecord, RecordBindingError, RetainedSeqpacketReceiveErrorV1, SeqpacketSocket,
};

use super::{Error, InstalledScope, Ledger, MonitorCustody, RelayConnection};

pub(super) struct RelayIntakeOriginalV2 {
    socket: Option<SeqpacketSocket>,
    receive: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    binding: Option<Result<(), RecordBindingError>>,
    pending: Option<RelayConnection>,
    pub(super) body: Option<Result<(), Error>>,
}

impl RelayIntakeOriginalV2 {
    pub(super) fn new(socket: SeqpacketSocket) -> Self {
        Self {
            socket: Some(socket),
            receive: None,
            binding: None,
            pending: None,
            body: None,
        }
    }

    pub(super) fn enter(
        &mut self,
        installed: &InstalledScope,
        custody: &mut MonitorCustody,
        ledger: &Ledger,
    ) -> Result<(), Error> {
        super::refresh_relay(installed, custody, ledger)?;
        if custody.pending_io.is_some() {
            return Err(Error::LedgerConflict);
        }
        let deadline = std::time::Instant::now() + super::DEADLINE;
        let socket = self.socket.as_mut().ok_or(Error::LedgerConflict)?;
        loop {
            let _ = crate::process::poll_original_execution_timeouts_v1(ledger);
            if std::time::Instant::now() >= deadline {
                return Err(Error::InvalidRequest);
            }
            self.receive = Some(socket.receive_guest_monitor_request_retaining_v1(8));
            if self.receive.as_ref().is_some_and(|result| {
                result.as_ref().is_err_and(|cause| {
                    cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted()
                })
            }) {
                self.receive.take();
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            break;
        }
        let record = match self.receive.take() {
            Some(Ok(record)) => record,
            other => {
                self.receive = other;
                return Err(Error::AmbiguousEffect);
            }
        };
        let bound = match socket.bind_received_retaining(record) {
            Ok(bound) => {
                self.binding = Some(Ok(()));
                bound
            }
            Err((cause, record)) => {
                self.binding = Some(Err(cause));
                self.receive = Some(Ok(record));
                return Err(Error::AmbiguousEffect);
            }
        };
        let (payload, subject, _) = bound.into_parts();
        let socket = self.socket.take().ok_or(Error::LedgerConflict)?;
        self.pending = Some(RelayConnection {
            socket,
            subject,
            deadline,
            io_attempted: false,
        });
        if payload != b"AOSRIO03" {
            return Err(Error::InvalidRequest);
        }
        let pending = self.pending.as_ref().ok_or(Error::LedgerConflict)?;
        super::validate_relay(installed, custody, pending, ledger)
    }

    pub(super) fn take_completed(&mut self) -> Result<RelayConnection, Error> {
        if !matches!(self.body, Some(Ok(()))) {
            return Err(Error::AmbiguousEffect);
        }
        self.pending.take().ok_or(Error::LedgerConflict)
    }
}
