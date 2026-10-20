//! Retains the disconnected original monitor until its exact native pins exit.
//!
//! Socket shutdown forecloses further IO; it does not prove process death.
//! The same retained pidfds supply that separate evidence. No process is
//! adopted from a PID, and only the existing cancel-on-disconnect law cancels.

use super::{Error, Ledger, MonitorCustody, SessionLiveness};
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::SeqpacketOwnedShutdownOriginalV1;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

#[derive(Default)]
pub(super) struct OriginalMonitorRetirementV1 {
    entered: bool,
    body: Option<Result<bool, Error>>,
    root: SeqpacketOwnedShutdownOriginalV1,
    io: SeqpacketOwnedShutdownOriginalV1,
    io_present: bool,
    exited: [Option<Result<bool, Error>>; 6],
}

impl OriginalMonitorRetirementV1 {
    pub(super) fn entered(&self) -> bool {
        self.entered
    }

    pub(super) fn failed(&self) -> bool {
        self.body.as_ref().is_some_and(Result::is_err)
    }

    fn shutdown_once(
        &mut self,
        root: &mut SeqpacketSocket,
        io: Option<&mut SeqpacketSocket>,
    ) -> Result<(), Error> {
        if !self.entered {
            self.entered = true;
            self.io_present = io.is_some();
            let root = self.root.shutdown_once_v1(root);
            let io = io.map(|socket| self.io.shutdown_once_v1(socket));
            if root.is_err() || io.is_some_and(|result| result.is_err()) {
                return Err(Error::AmbiguousEffect);
            }
        }
        if !self.root.completed_v1() || (self.io_present && !self.io.completed_v1()) {
            return Err(Error::AmbiguousEffect);
        }
        Ok(())
    }

    fn observe_exits(&mut self, originals: &[&PidFd]) -> Result<bool, Error> {
        if originals.len() > self.exited.len() {
            return Err(Error::LedgerConflict);
        }
        for (index, original) in originals.iter().enumerate() {
            self.exited[index] = Some(
                original
                    .is_alive()
                    .map(|alive| !alive)
                    .map_err(Error::Confinement),
            );
            match self.exited[index].as_ref() {
                Some(Ok(true)) => {}
                Some(Ok(false)) => return Ok(false),
                _ => return Err(Error::AmbiguousEffect),
            }
        }
        Ok(true)
    }
}

/// Keeps an unconsumed original foreclosed until the same native pins exit.
/// Expiry/disconnect alone never cancels the Tenant or completes its Process.
pub(super) struct RetiringMonitorCustodyV1 {
    pub(super) execution: [u8; 16],
    pub(super) terminal_requested: bool,
    custody: MonitorCustody,
    original: OriginalMonitorRetirementV1,
    refusal: Option<Error>,
}

impl RetiringMonitorCustodyV1 {
    pub(super) fn new(
        execution: [u8; 16],
        custody: MonitorCustody,
        refusal: Option<Error>,
    ) -> Self {
        Self {
            execution,
            custody,
            refusal,
            terminal_requested: false,
            original: Default::default(),
        }
    }

    pub(super) fn progress(&mut self) -> Result<bool, Error> {
        if self.refusal.is_some() || self.original.failed() {
            return Err(Error::AmbiguousEffect);
        }
        let result = self.progress_inner();
        let completed = result.as_ref().copied().map_err(|_| Error::AmbiguousEffect);
        self.original.body = Some(result);
        completed
    }

    fn progress_inner(&mut self) -> Result<bool, Error> {
        self.original.shutdown_once(
            &mut self.custody.connection,
            self.custody.pending_io.as_mut().map(|io| &mut io.socket),
        )?;
        let custody = &self.custody;
        let mut originals = [&custody.child; 6];
        originals[0] = custody.subject.pidfd();
        originals[1] = custody.connection.peer().pidfd();
        let mut count = 3;
        if let Some(relay) = custody.relay.as_ref() {
            originals[count] = relay;
            count += 1;
        }
        if let Some(io) = custody.pending_io.as_ref() {
            if custody.relay.is_none() {
                return Err(Error::LedgerConflict);
            }
            originals[count] = io.subject.pidfd();
            originals[count + 1] = io.socket.peer().pidfd();
            count += 2;
        }
        // The private closed roster contains only handles already held by this
        // exact custody; absent optional IO adds no fabricated exit observation.
        self.original.observe_exits(&originals[..count])
    }
}

pub(super) fn retire_disconnected_original(
    session: &mut SessionLiveness,
    ledger: &Ledger,
) -> Result<bool, Error> {
    if session.retirement.failed() {
        return Err(Error::AmbiguousEffect);
    }
    let result = retire_inner(session, ledger);
    let completed = result.as_ref().copied().map_err(|_| Error::AmbiguousEffect);
    session.retirement.body = Some(result);
    completed
}

fn retire_inner(session: &mut SessionLiveness, ledger: &Ledger) -> Result<bool, Error> {
    if !session.retirement.entered {
        let process = ledger.read_process_bytes(session.execution)?;
        if process.cancel_on_disconnect == Some(true) && process.terminal.is_none() {
            crate::process::cancel_owned_execution(
                ledger,
                aos_sandbox_model::ExecutionId::from_bytes(session.execution),
                std::time::Instant::now() + super::DEADLINE,
            )?;
        }
    }
    session
        .retirement
        .shutdown_once(&mut session.connection, Some(&mut session.io.socket))?;
    let originals = [
        session.subject.pidfd(),
        session.connection.peer().pidfd(),
        &session.child,
        &session.relay,
        session.io.subject.pidfd(),
        session.io.socket.peer().pidfd(),
    ];
    session.retirement.observe_exits(&originals)
}
