//! Live original-ticket custody issued by the fixed privileged SSH monitor.
//!
//! This registry is deliberately in-memory. A protected ticket or callback
//! observation cannot reconstruct it after a crash. It owns the exact root
//! connection, kernel record subject, confined post-auth child and private relay
//! pidfds. A read-only observation is never authority. Only the existing typed
//! owner consume may borrow these handles through durable one-use I/O transfer.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aos_sandbox_guest_protocol::openssh_consume::{
    OriginalAttachActionV3, OriginalAttachObservationV3, OriginalAttachPhaseV3,
};
use crate::openssh_gate_linux::OpenSshMonitorRuntimeV2;
use aos_sandbox_guest_protocol::openssh_monitor::{
    OPENSSH_MONITOR_BINDING_ACK_V2, OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2,
    OpenSshMonitorWitnessV2,
};
use aos_sandbox_model::public_attach_ticket::PublicAttachTicketBindingV2;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::{
    KernelAuthorizedRecordSubject, SeqpacketError, SeqpacketSocket,
};
use sha2::{Digest as _, Sha256};

use crate::GuestProcessEffectErrorV1 as Error;
use crate::ledger::Ledger;

const DEADLINE: Duration = Duration::from_secs(5);

mod control;
mod terminal;
mod retirement;
mod registration;
mod relay_intake;

#[cfg(test)]
mod registration_tests;

#[derive(Clone, Default)]
pub(super) struct MonitorRegistry(Arc<Mutex<Registry>>);

#[derive(Default)]
struct Registry {
    installed: Option<InstalledScope>,
    owner: MonitorOwnerV4,
    refusal: Option<Error>,
    registration: Option<registration::MonitorRegistrationOriginalV2>,
    relay_intake: Option<relay_intake::RelayIntakeOriginalV2>,
}

// Registration, consumption and retirement move the same native custody.
// Their owning headers are mutually exclusive, including failed retirement;
// the enum prevents vacant inline destinations from multiplying the source.
#[derive(Default)]
enum MonitorOwnerV4 {
    #[default]
    Empty,
    Unconsumed(MonitorCustody),
    Session(SessionLiveness),
    Retiring(retirement::RetiringMonitorCustodyV1),
}

impl MonitorOwnerV4 {
    fn custody_mut(&mut self) -> Option<&mut MonitorCustody> {
        match self {
            Self::Unconsumed(owner) => Some(owner),
            _ => None,
        }
    }

    fn session_ref(&self) -> Option<&SessionLiveness> {
        match self {
            Self::Session(owner) => Some(owner),
            _ => None,
        }
    }

    fn session_mut(&mut self) -> Option<&mut SessionLiveness> {
        match self {
            Self::Session(owner) => Some(owner),
            _ => None,
        }
    }

    fn retiring_mut(&mut self) -> Option<&mut retirement::RetiringMonitorCustodyV1> {
        match self {
            Self::Retiring(owner) => Some(owner),
            _ => None,
        }
    }

    fn has_custody(&self) -> bool {
        matches!(self, Self::Unconsumed(_))
    }

    fn has_session(&self) -> bool {
        matches!(self, Self::Session(_))
    }

    fn has_retiring(&self) -> bool {
        matches!(self, Self::Retiring(_))
    }

    fn take_custody(&mut self) -> Option<MonitorCustody> {
        match std::mem::take(self) {
            Self::Unconsumed(owner) => Some(owner),
            other => {
                *self = other;
                None
            }
        }
    }

    fn clear_session(&mut self) {
        if self.has_session() {
            drop(std::mem::take(self));
        }
    }

    fn clear_retiring(&mut self) {
        if self.has_retiring() {
            drop(std::mem::take(self));
        }
    }
}

impl Registry {
    fn retain_unconsumed(&mut self, refusal: Option<Error>) -> Result<(), Error> {
        if self.owner.has_retiring() { return Err(Error::LedgerConflict); }
        let execution = self.installed.as_ref().ok_or(Error::LedgerConflict)?
            .runtime.claim().binding.execution_id;
        if let Some(custody) = self.owner.take_custody() {
            self.owner = MonitorOwnerV4::Retiring(retirement::RetiringMonitorCustodyV1::new(execution, custody, refusal));
        }
        Ok(())
    }
}

struct InstalledScope {
    runtime: OpenSshMonitorRuntimeV2,
    original_ticket: Vec<u8>,
}

struct MonitorCustody {
    connection: SeqpacketSocket,
    subject: KernelAuthorizedRecordSubject,
    child: PidFd,
    original_witness: Vec<u8>,
    original_expiry: u64,
    relay: Option<PidFd>,
    pending_io: Option<RelayConnection>,
    controls: control::OriginalSessionControlsV5,
    relay_registration: registration::RegistrationPacketV2,
    restriction: aos_sandbox_linux::seqpacket::SeqpacketRightsRestrictionOriginalV6,
    relay_ack: Option<Result<(), aos_sandbox_linux::seqpacket::RetainedSeqpacketSendErrorV1>>,
    relay_after: Option<Result<(), Error>>,
}

/// Holds original consumed-channel liveness and terminal data, never authority.
/// Certificate expiry or policy reads do not create or renew this record.
struct SessionLiveness {
    execution: [u8; 16],
    connection: SeqpacketSocket,
    subject: KernelAuthorizedRecordSubject,
    child: PidFd,
    relay: PidFd,
    io: RelayConnection,
    original_witness: Vec<u8>,
    original_expiry: u64,
    controls: control::OriginalSessionControlsV5,
    restriction: aos_sandbox_linux::seqpacket::SeqpacketRightsRestrictionOriginalV6,
    terminal_notified: bool,
    terminal_reply_sent: bool,
    refresh: terminal::TerminalRefreshOriginalV1,
    liveness: Option<Result<bool, Error>>,
    retirement: retirement::OriginalMonitorRetirementV1,
}

pub(crate) const fn original_terminal_control_header_bytes_v1() -> usize {
    // Registry contains both SessionLiveness and InstalledScope inline. Three
    // complete Registry planes cover its resident header and those same moved
    // constructor inputs; neither input is a separately archived owner.
    3 * std::mem::size_of::<Registry>()
}

pub(super) struct RelayConnection {
    pub(super) socket: SeqpacketSocket,
    pub(super) io_attempted: bool,
    subject: KernelAuthorizedRecordSubject,
    deadline: Instant,
}

impl MonitorRegistry {
    pub(super) fn close(&self) {
        // Poison recovery is permitted only to close handles, never to recover
        // authorization or continue a binding from partially mutated state.
        let mut registry = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.owner.take_custody();
        registry.owner.clear_session();
        registry.owner.clear_retiring();
        registry.installed.take();
        registry.registration.take();
        registry.relay_intake.take();
    }

    /// Samples the original session while the caller retains the effect
    /// barrier. A closed channel triggers the existing Owner cancellation, not
    /// an authorization decision, reconnect adoption, or a new monitor grant.
    pub(super) fn prune_closed(&self, ledger: &Ledger) -> Result<Option<[u8; 16]>, Error> {
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        if registry.refusal.is_some() || (registry.registration.is_some() || registry.relay_intake.is_some()) { return Err(Error::AmbiguousEffect); }
        if let Some(retiring) = registry.owner.retiring_mut() {
            let execution = retiring.execution;
            if retiring.progress()? && retiring.terminal_requested {
                registry.owner.clear_retiring();
                registry.installed.take();
                return Ok(Some(execution));
            }
            return Ok(None);
        }
        let original_session_is_valid = {
            let Registry {
                installed, owner, ..
            } = &mut *registry;
            match (installed.as_ref(), owner.session_mut()) {
                (Some(installed), Some(session)) => {
                    if session.refresh.failed() || session.retirement.failed()
                        || session.liveness.as_ref().is_some_and(Result::is_err)
                    {
                        return Err(Error::AmbiguousEffect);
                    }
                    if session.retirement.entered() {
                        false
                    } else {
                        session.liveness = Some(session.root_is_live());
                        let root_live = match session.liveness.as_ref() {
                            Some(Ok(live)) => *live,
                            _ => return Err(Error::AmbiguousEffect),
                        };
                        if root_live {
                            terminal::refresh_original_terminal(installed, session, ledger)?;
                            session.liveness = Some(if session.terminal_notified {
                                session.root_is_live()
                            } else {
                                session.is_live()
                            });
                            match session.liveness.as_ref() {
                                Some(Ok(live)) => *live,
                                _ => return Err(Error::AmbiguousEffect),
                            }
                        } else {
                            false
                        }
                    }
                }
                (_, None) => true,
                (None, Some(_)) => return Err(Error::InvalidRequest),
            }
        };
        if let Some(session) = registry.owner.session_mut() {
            if !original_session_is_valid {
                let execution = session.execution;
                if !retirement::retire_disconnected_original(session, ledger)? {
                    return Ok(None);
                }
                if registry.owner.has_custody() { return Err(Error::LedgerConflict); }
                registry.owner.clear_session();
                registry.installed.take();
                return Ok(Some(execution));
            }
        }
        let Registry {
            installed, owner, ..
        } = &mut *registry;
        let validity = match (installed.as_ref(), owner.custody_mut()) {
            (Some(installed), Some(custody)) => {
                custody.is_live_checked().and_then(|live| {
                    if live { refresh_relay(installed, custody, ledger).map(|_| true) }
                    else { Ok(false) }
                })
            }
            (_, None) => Ok(true),
            (None, Some(_)) => Err(Error::LedgerConflict),
        };
        match validity {
            Ok(true) => {}
            Ok(false) => registry.retain_unconsumed(None)?,
            Err(cause) => {
                registry.retain_unconsumed(Some(cause))?;
                return Err(Error::AmbiguousEffect);
            }
        }
        Ok(None)
    }

    /// Forecloses new consume and reports actual whole-registry retirement.
    ///
    /// An already consumed data channel stays owned until original terminal
    /// notification and disconnection. Foreign or incomplete original custody
    /// also keeps disposition pending; absence of one Session is insufficient.
    ///
    /// # Errors
    /// Rejects a poisoned monitor ownership lock.
    pub(super) fn finish_execution(&self, execution: [u8; 16]) -> Result<bool, Error> {
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        if registry.refusal.is_some() || (registry.registration.is_some() || registry.relay_intake.is_some()) { return Err(Error::AmbiguousEffect); }
        if registry.owner.session_ref().is_some_and(|session|
            session.refresh.failed() || session.retirement.failed()
                || session.liveness.as_ref().is_some_and(Result::is_err))
        {
            return Err(Error::AmbiguousEffect);
        }
        if registry
            .installed
            .as_ref()
            .is_some_and(|scope| scope.runtime.claim().binding.execution_id == execution)
        {
            if registry.owner.has_custody() { registry.retain_unconsumed(None)?; }
            if let Some(retiring) = registry.owner.retiring_mut() {
                if retiring.execution != execution { return Err(Error::LedgerConflict); }
                retiring.terminal_requested = true;
                if retiring.progress()? { registry.owner.clear_retiring(); }
            }
            if !registry.owner.has_session() && !registry.owner.has_retiring() {
                registry.installed.take();
            }
        }
        Ok(registry.installed.is_none() && !registry.owner.has_custody()
            && !registry.owner.has_session() && !registry.owner.has_retiring() && registry.registration.is_none() && registry.relay_intake.is_none())
    }

    pub(super) fn install(
        &self,
        runtime: OpenSshMonitorRuntimeV2,
        original_ticket: &[u8],
    ) -> Result<(), Error> {
        runtime
            .require_current()
            .map_err(|_| Error::InvalidRequest)?;
        let ticket = PublicAttachTicketBindingV2::decode(original_ticket)
            .map_err(|_| Error::InvalidRequest)?;
        aos_sandbox_guest_protocol::openssh_ticket::validate_ticket_profile_v2(
            runtime.claim(),
            &ticket,
            now()?,
        )
        .map_err(|_| Error::InvalidRequest)?;
        if read_ticket()? != original_ticket {
            return Err(Error::LedgerConflict);
        }

        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        if registry.owner.has_retiring() || registry.refusal.is_some() || (registry.registration.is_some() || registry.relay_intake.is_some()) { return Err(Error::LedgerConflict); }
        if let Some(installed) = &registry.installed {
            // Preserve the original owner anchor, never recompute/adopt one.
            installed
                .runtime
                .require_current()
                .map_err(|_| Error::InvalidRequest)?;
            if installed.runtime.claim() != runtime.claim()
                || installed.original_ticket != original_ticket
            {
                return Err(Error::LedgerConflict);
            }
            return Ok(());
        }
        registry.installed = Some(InstalledScope {
            runtime,
            original_ticket: original_ticket.to_vec(),
        });
        Ok(())
    }

    fn lock_with_original_deadlines<'registry>(&'registry self, ledger: &Ledger)
        -> Result<std::sync::MutexGuard<'registry, Registry>, Error>
    {
        loop {
            match self.0.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::LedgerConflict),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let _ = crate::process::poll_original_execution_timeouts_v1(ledger);
                    thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    pub(super) fn register(
        &self,
        connection: SeqpacketSocket,
        ledger: &Ledger,
    ) -> Result<(), Error> {
        let deadline = Instant::now() + DEADLINE;
        let mut registry = self.lock_with_original_deadlines(ledger)?;
        if registry.owner.has_session() || registry.owner.has_retiring() || registry.owner.has_custody()
            || (registry.registration.is_some() || registry.relay_intake.is_some()) || registry.refusal.is_some()
        {
            return Err(Error::LedgerConflict);
        }
        // Park the actual socket before policy, packet, pidfd or ACK gates.
        registry.registration = Some(registration::MonitorRegistrationOriginalV2::new(connection));
        let Registry { installed, registration, .. } = &mut *registry;
        let original = registration.as_mut().ok_or(Error::LedgerConflict)?;
        let result = match installed.as_ref() {
            Some(installed) => original.enter(installed, ledger, deadline),
            None => Err(Error::InvalidRequest),
        };
        let positive = result.is_ok();
        original.body = Some(result);
        if !positive { return Err(Error::AmbiguousEffect); }
        let custody = original.take_completed()?;
        registry.owner = MonitorOwnerV4::Unconsumed(custody);
        registry.registration.take();
        Ok(())
    }

    // A refused actual registration keeps its complete socket/native original.
    // The intake actor must stop before accepting another unbounded prefix.
    pub(super) fn registration_refused(&self) -> bool {
        self.0.lock().map_or(true, |registry| (registry.registration.is_some() || registry.relay_intake.is_some()))
    }

    pub(super) fn queue_relay(
        &self,
        socket: SeqpacketSocket,
        ledger: &Ledger,
    ) -> Result<(), Error> {
        let barrier = ledger.effect_barrier();
        let _current = crate::bridge::lock_effect_barrier_with_deadlines(&barrier, ledger)?;
        let mut registry = self.lock_with_original_deadlines(ledger)?;
        if registry.owner.has_retiring() || registry.refusal.is_some()
            || registry.registration.is_some() || registry.relay_intake.is_some()
        { return Err(Error::LedgerConflict); }
        registry.relay_intake = Some(relay_intake::RelayIntakeOriginalV2::new(socket));
        let Registry { installed, owner, relay_intake, .. } = &mut *registry;
        let original = relay_intake.as_mut().ok_or(Error::LedgerConflict)?;
        let result = match (installed.as_ref(), owner.custody_mut()) {
            (Some(installed), Some(custody)) => original.enter(installed, custody, ledger),
            _ => Err(Error::InvalidRequest),
        };
        let positive = result.is_ok();
        original.body = Some(result);
        if !positive { return Err(Error::AmbiguousEffect); }
        let pending = original.take_completed()?;
        let custody = owner.custody_mut().ok_or(Error::LedgerConflict)?;
        custody.pending_io = Some(pending);
        registry.relay_intake.take();
        Ok(())
    }

    /// Keeps kernel custody borrowed through the actual one-use I/O effect.
    pub(super) fn with_original_attach_v3(
        &self,
        action: OriginalAttachActionV3,
        expected_binding: [u8; 32],
        ticket: &[u8],
        ledger: &Ledger,
        transfer: impl FnOnce(
            &mut RelayConnection,
            &aos_sandbox_guest_protocol::openssh_gate::OpenSshGateClaimV1,
            &mut dyn FnMut(&RelayConnection) -> Result<(), Error>,
        ) -> Result<(), Error>,
    ) -> Result<OriginalAttachObservationV3, Error> {
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        if registry.owner.has_retiring() || registry.refusal.is_some() || (registry.registration.is_some() || registry.relay_intake.is_some()) { return Err(Error::LedgerConflict); }
        let Registry {
            installed, owner, ..
        } = &mut *registry;
        let installed = installed.as_ref().ok_or(Error::InvalidRequest)?;
        if installed.original_ticket != ticket || read_ticket()? != ticket {
            return Err(Error::LedgerConflict);
        }
        let Some(current) = owner.custody_mut() else {
            return if action == OriginalAttachActionV3::Poll {
                Ok(OriginalAttachObservationV3 {
                    binding: [0; 32],
                    phase: OriginalAttachPhaseV3::Pending,
                    witness: Vec::new(),
                })
            } else {
                Err(Error::InvalidRequest)
            };
        };
        let mut transferred_io = None;
        let result = (|| {
            validate_custody(
                installed,
                &current.connection,
                &current.subject,
                &current.child,
                &current.original_witness,
                ledger,
            )?;
            refresh_relay(installed, current, ledger)?;
            let Some(pending) = current.pending_io.as_ref() else {
                return if action == OriginalAttachActionV3::Poll {
                    Ok(OriginalAttachObservationV3 {
                        binding: [0; 32],
                        phase: OriginalAttachPhaseV3::Pending,
                        witness: Vec::new(),
                    })
                } else {
                    Err(Error::InvalidRequest)
                };
            };
            validate_relay(installed, current, pending, ledger)?;
            let binding = custody_binding(current, pending)?;
            let mut observation = OriginalAttachObservationV3 {
                binding,
                phase: OriginalAttachPhaseV3::Ready,
                witness: current.original_witness.clone(),
            };
            if action == OriginalAttachActionV3::Consume {
                if binding != expected_binding {
                    return Err(Error::InvalidRequest);
                }
                // The exact connection leaves the registry only after all live
                // checks. No callback-supplied PID or cached row can replace it.
                let mut pending = current.pending_io.take().ok_or(Error::LedgerConflict)?;
                // The effect producer keeps ledger.live borrowed through SCM.
                // This callback rechecks actual root/relay custody but does not
                // reacquire that same tree lock; the producer rechecks its tree.
                let mut recheck = |pending: &RelayConnection| {
                    validate_relay_custody(installed, current, pending, ledger)
                };
                let transferred = (|| {
                    validate_relay(installed, current, &pending, ledger)?;
                    transfer(&mut pending, installed.runtime.claim(), &mut recheck)?;
                    validate_custody(
                        installed,
                        &current.connection,
                        &current.subject,
                        &current.child,
                        &current.original_witness,
                        ledger,
                    )
                })();
                // An ambiguous SCM attempt may expose IO. Retain only its
                // original liveness handles, never retryable attach custody.
                if pending.io_attempted {
                    transferred_io = Some(pending);
                } else {
                    current.pending_io = Some(pending);
                }
                transferred?;
                observation.phase = OriginalAttachPhaseV3::Transferred;
            }
            Ok(observation)
        })();
        if let Some(io) = transferred_io {
            let mut original = registry.owner.take_custody().ok_or(Error::LedgerConflict)?;
            let execution = registry
                .installed
                .as_ref()
                .ok_or(Error::LedgerConflict)?
                .runtime
                .claim()
                .binding
                .execution_id;
            let Some(relay) = original.relay.take() else {
                original.pending_io = Some(io);
                registry.owner = MonitorOwnerV4::Unconsumed(original);
                registry.retain_unconsumed(Some(Error::LedgerConflict))?;
                return Err(Error::LedgerConflict);
            };
            registry.owner = MonitorOwnerV4::Session(SessionLiveness {
                execution,
                connection: original.connection,
                subject: original.subject,
                child: original.child,
                relay,
                io,
                original_witness: original.original_witness,
                original_expiry: original.original_expiry,
                controls: original.controls,
                restriction: original.restriction,
                terminal_notified: false,
                terminal_reply_sent: false,
                refresh: Default::default(), liveness: None,
                retirement: Default::default(),
            });
        } else if action == OriginalAttachActionV3::Consume || result.is_err() {
            registry.retain_unconsumed(None)?;
        }
        match result {
            Ok(observation) => Ok(observation),
            Err(cause) => {
                registry.refusal = Some(cause);
                Err(Error::AmbiguousEffect)
            }
        }
    }
}

impl SessionLiveness {
    fn root_is_live(&self) -> Result<bool, Error> {
        Ok(self.subject.is_alive()?
            && self.connection.peer().is_alive()?
            && self.child.is_alive()?
            && connected_checked(&self.connection)?)
    }

    fn is_live(&self) -> Result<bool, Error> {
        // These original handles were retained after the one-use SCM attempt.
        // No callback bytes, expiry refresh, scalar PID or session identifier
        // can recreate them. This method cannot release any descriptor.
        Ok(self.root_is_live()?
            && self.relay.is_alive()?
            && self.io.subject.is_alive()?
            && self.io.socket.peer().is_alive()?
            && connected_checked(&self.io.socket)?)
    }
}

impl MonitorCustody {
    fn is_live(&self) -> bool {
        self.is_live_checked().unwrap_or(false)
    }

    fn is_live_checked(&self) -> Result<bool, Error> {
        Ok(self.subject.is_alive()?
            && self.connection.peer().is_alive()?
            && self.child.is_alive()?
            && !self.original_witness.is_empty()
            && now()? < self.original_expiry
            && connected_checked(&self.connection)?
            && match self.relay.as_ref() {
                Some(relay) => relay.is_alive()?,
                None => true,
            })
    }
}

fn connected(connection: &SeqpacketSocket) -> bool {
    connected_checked(connection).unwrap_or(false)
}

fn connected_checked(connection: &SeqpacketSocket) -> Result<bool, Error> {
    let fd = connection.as_fd()?;
    let timeout = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut fds = [rustix::event::PollFd::new(
        &fd,
        rustix::event::PollFlags::empty(),
    )];
    // Incoming relay registrations are consumed by the exact typed branch.
    // This liveness sample only rejects a disconnected/error connection.
    if rustix::event::poll(&mut fds, Some(&timeout))? == 0 {
        return Ok(true);
    }
    let observed = fds[0].revents();
    if observed == rustix::event::PollFlags::HUP {
        Ok(false)
    } else {
        Err(Error::MonitorPoll(observed))
    }
}

fn require_root_monitor(
    connection: &SeqpacketSocket,
    runtime: &OpenSshMonitorRuntimeV2,
) -> Result<(), Error> {
    if connection.peer().credentials().uid() != 0 {
        return Err(Error::InvalidRequest);
    }
    runtime
        .require_original_control_monitor_v5(connection.peer().pidfd())
        .map_err(|_| Error::InvalidRequest)
}

fn validate_custody(
    installed: &InstalledScope,
    connection: &SeqpacketSocket,
    subject: &KernelAuthorizedRecordSubject,
    child: &PidFd,
    payload: &[u8],
    ledger: &Ledger,
) -> Result<(), Error> {
    let ticket = PublicAttachTicketBindingV2::decode(&installed.original_ticket)
        .map_err(|_| Error::InvalidRequest)?;
    control::require_control_custody(
        installed,
        connection,
        subject,
        child,
        payload,
        ticket.expires_at,
        ledger,
    )?;
    let process = ledger.read_process_bytes(installed.runtime.claim().binding.execution_id)?;
    ledger.require_active_original_tree_v5(&process)
}

fn refresh_relay(
    installed: &InstalledScope,
    custody: &mut MonitorCustody,
    ledger: &Ledger,
) -> Result<(), Error> {
    let mode = if custody.relay.is_some() { Some(&custody.restriction) } else { None };
    if !custody.relay_registration.receive(&mut custody.connection, false, mode)? {
        return Ok(());
    }
    custody.relay_registration.require_sender(&custody.connection)?;
    let record = custody.relay_registration.record()?;
    if record.payload().get(..8) == Some(b"AOSMCQ05".as_slice()) {
        if !record.descriptors().is_empty() { return Err(Error::InvalidRequest); }
        control::require_same_root_subject(record.subject(), &custody.subject)?;
        control::require_control_custody(installed, &custody.connection, &custody.subject,
            &custody.child, &custody.original_witness, custody.original_expiry, ledger)?;
        custody.controls.queue(record.payload())?;
        // Queue ownership is pure DATA. The actual receive/binding completed
        // before its packet/subject are retired at this old lexical boundary.
        custody.relay_registration = Default::default();
        return Ok(());
    }
    if record.payload() != b"AOSRLY03" || record.descriptors().len() != 1 || custody.relay.is_some() {
        return Err(Error::InvalidRequest);
    }
    installed.runtime.require_original_control_monitor_v5(record.subject().pidfd())
        .map_err(|_| Error::InvalidRequest)?;
    custody.relay_registration.admit_child()?;
    validate_custody(installed, &custody.connection, &custody.subject, &custody.child,
        &custody.original_witness, ledger)?;
    let witness = OpenSshMonitorWitnessV2::decode_confined_v3(&custody.original_witness)
        .map_err(|_| Error::InvalidRequest)?;
    let parent = custody.child.process_identity().map_err(|_| Error::InvalidRequest)?;
    installed.runtime.require_confined_child_v3(custody.relay_registration.child()?,
        parent.pid(), witness.uid, witness.gid).map_err(|_| Error::InvalidRequest)?;
    custody.relay = Some(custody.relay_registration.take_child()?);

    // Both real descriptor registrations are complete. Foreclose rights and
    // exclude pre-disable queued records before ACK permits terminal/control
    // traffic. A failed restriction stays with this exact socket and relay.
    custody.connection.restrict_incoming_rights_retaining_v6(&mut custody.restriction)?;
    custody.relay_ack = Some(custody.connection.send_retaining(b"AOSRAK03"));
    custody.relay_after = Some(validate_custody(installed, &custody.connection,
        &custody.subject, &custody.child, &custody.original_witness, ledger));
    if !matches!(custody.relay_ack, Some(Ok(()))) || !matches!(custody.relay_after, Some(Ok(()))) {
        return Err(Error::AmbiguousEffect);
    }
    custody.connection.require_rights_restriction_current_v6(&custody.restriction)?;
    custody.relay_registration = Default::default();
    Ok(())
}

fn read_ticket() -> Result<Vec<u8>, Error> {
    crate::openssh_gate_linux::load_original_ticket_claim_v2()
        .map_err(|_| Error::InvalidRequest)
}

fn validate_relay(
    installed: &InstalledScope,
    custody: &MonitorCustody,
    pending: &RelayConnection,
    ledger: &Ledger,
) -> Result<(), Error> {
    validate_relay_custody(installed, custody, pending, ledger)?;
    let process = ledger.read_process_bytes(installed.runtime.claim().binding.execution_id)?;
    ledger.require_active_original_tree_v5(&process)
}

// The SCM producer already holds the actual tree's live-map borrow. This
// current root/relay check deliberately does not reacquire that same mutex.
fn validate_relay_custody(
    installed: &InstalledScope,
    custody: &MonitorCustody,
    pending: &RelayConnection,
    ledger: &Ledger,
) -> Result<(), Error> {
    custody.connection.require_rights_restriction_current_v6(&custody.restriction)?;
    control::require_control_custody(
        installed,
        &custody.connection,
        &custody.subject,
        &custody.child,
        &custody.original_witness,
        custody.original_expiry,
        ledger,
    )?;
    let relay = custody.relay.as_ref().ok_or(Error::InvalidRequest)?;
    let expected = relay
        .process_identity()
        .map_err(|_| Error::InvalidRequest)?;
    let connector = pending.socket.peer().credentials();
    let sender = pending.subject.credentials();
    if Instant::now() >= pending.deadline
        || sender.pid() != connector.pid()
        || sender.uid() != connector.uid()
        || sender.gid() != connector.gid()
        || sender.pid().get() != expected.pid()
        || !pending
            .subject
            .is_alive()
            .map_err(|_| Error::InvalidRequest)?
        || !pending
            .socket
            .peer()
            .is_alive()
            .map_err(|_| Error::InvalidRequest)?
        || pending
            .subject
            .pidfd()
            .process_identity()
            .map_err(|_| Error::InvalidRequest)?
            != expected
        || pending
            .socket
            .peer()
            .pidfd()
            .process_identity()
            .map_err(|_| Error::InvalidRequest)?
            != expected
    {
        return Err(Error::InvalidRequest);
    }
    let witness = OpenSshMonitorWitnessV2::decode_confined_v3(&custody.original_witness)
        .map_err(|_| Error::InvalidRequest)?;
    let parent = custody
        .child
        .process_identity()
        .map_err(|_| Error::InvalidRequest)?;
    installed
        .runtime
        .require_confined_child_v3(relay, parent.pid(), witness.uid, witness.gid)
        .map_err(|_| Error::InvalidRequest)
}

fn custody_binding(custody: &MonitorCustody, pending: &RelayConnection) -> Result<[u8; 32], Error> {
    let relay = custody.relay.as_ref().ok_or(Error::InvalidRequest)?;
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.live-original-attach-custody.v3\0");
    digest.update(&custody.original_witness);
    digest.update(
        custody
            .connection
            .peer()
            .socket_cookie()
            .get()
            .to_be_bytes(),
    );
    digest.update(
        relay
            .process_identity()
            .map_err(|_| Error::InvalidRequest)?
            .pid()
            .to_be_bytes(),
    );
    digest.update(pending.socket.peer().socket_cookie().get().to_be_bytes());
    Ok(digest.finalize().into())
}

fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::InvalidRequest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;
    use std::os::fd::AsRawFd as _;

    #[test]
    fn cold_registry_never_reconstructs_monitor_custody() {
        let registry = MonitorRegistry::default();
        registry.finish_execution([1; 16]).unwrap();
        let cold = registry.0.lock().unwrap();
        assert!(cold.installed.is_none());
        assert!(!cold.owner.has_custody());
    }

    fn original_record_pair() -> (SeqpacketSocket, SeqpacketSocket, KernelAuthorizedRecordSubject) {
        let (receiver, sender) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX, rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC, None,
        ).unwrap();
        let mut receiver = SeqpacketSocket::from_owned(receiver).unwrap();
        let mut sender = SeqpacketSocket::from_owned(sender).unwrap();
        receiver.enable_record_subjects().unwrap();
        sender.send(b"x").unwrap();
        let record = receiver.receive(1).unwrap();
        let (_, subject, _) = receiver.bind_received(record).unwrap().into_parts();
        (receiver, sender, subject)
    }

    #[test]
    fn finish_keeps_consumed_original_fds_until_registry_physically_closes() {
        let registry = MonitorRegistry::default();
        let (connection, _root, subject) = original_record_pair();
        let (io, _relay, io_subject) = original_record_pair();
        let connection_path = format!("/proc/self/fd/{}", connection.as_fd().unwrap().as_raw_fd());
        let io_path = format!("/proc/self/fd/{}", io.as_fd().unwrap().as_raw_fd());
        let process = NonZeroU32::new(std::process::id()).unwrap();
        registry.0.lock().unwrap().owner = MonitorOwnerV4::Session(SessionLiveness {
            execution: [1; 16], connection, subject,
            child: PidFd::open(process).unwrap(), relay: PidFd::open(process).unwrap(),
            io: RelayConnection { socket: io, io_attempted: false, subject: io_subject,
                deadline: std::time::Instant::now() },
            original_witness: vec![1], original_expiry: 0,
            controls: control::OriginalSessionControlsV5::new(),
            restriction: aos_sandbox_linux::seqpacket::SeqpacketRightsRestrictionOriginalV6::new(), terminal_notified: true,
            terminal_reply_sent: false,
            refresh: Default::default(), liveness: None,
            retirement: Default::default(),
        });

        // A wrong-phase extraction keeps the same consumed native owners.
        assert!(registry.0.lock().unwrap().owner.take_custody().is_none());

        // This fixture exercises native custody only; it installs no runtime,
        // claim or mutation authority. Finish cannot erase consumed handles.
        assert!(!registry.finish_execution([1; 16]).unwrap());
        assert!(!registry.finish_execution([1; 16]).unwrap());
        assert!(registry.0.lock().unwrap().owner.has_session());
        assert!(std::fs::read_link(&connection_path).is_ok());
        assert!(std::fs::read_link(&io_path).is_ok());

        registry.close();
        assert!(registry.finish_execution([1; 16]).unwrap());
        assert!(std::fs::read_link(connection_path).is_err());
        assert!(std::fs::read_link(io_path).is_err());
    }

    #[test]
    fn closed_native_socket_is_uncertain_instead_of_a_positive_disconnect_sample() {
        let (mut socket, _peer, _subject) = original_record_pair();
        assert!(connected_checked(&socket).unwrap());

        socket.close();

        assert!(matches!(connected_checked(&socket), Err(Error::Bridge(SeqpacketError::Closed))));
    }

    fn unconsumed_original() -> (MonitorCustody, SeqpacketSocket) {
        let (connection, root, subject) = original_record_pair();
        let custody = MonitorCustody {
            connection, subject,
            child: PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap(),
            original_witness: vec![1], original_expiry: 0,
            relay: None, pending_io: None,
            relay_registration: Default::default(),
            restriction: aos_sandbox_linux::seqpacket::SeqpacketRightsRestrictionOriginalV6::new(),
            relay_ack: None, relay_after: None,
            controls: control::OriginalSessionControlsV5::new(),
        };
        (custody, root)
    }

    #[test]
    fn unconsumed_shutdown_keeps_original_fd_and_live_pins_pending() {
        let (custody, _root) = unconsumed_original();
        let path = format!("/proc/self/fd/{}", custody.connection.as_fd().unwrap().as_raw_fd());
        let mut retiring = retirement::RetiringMonitorCustodyV1::new([1; 16], custody, None);

        assert!(!retiring.progress().unwrap());
        assert!(!retiring.progress().unwrap());
        assert!(std::fs::read_link(&path).is_ok());
        let registry = MonitorRegistry::default();
        registry.0.lock().unwrap().owner = MonitorOwnerV4::Retiring(retiring);
        assert!(registry.0.lock().unwrap().owner.take_custody().is_none());
        registry.0.lock().unwrap().owner.clear_session();
        assert!(!registry.finish_execution([1; 16]).unwrap());
        assert!(registry.0.lock().unwrap().owner.has_retiring());
        assert!(std::fs::read_link(&path).is_ok());

        registry.close();
        assert!(std::fs::read_link(path).is_err());
    }

    #[test]
    fn unconsumed_failed_original_never_becomes_empty_registry_proof() {
        let (custody, _root) = unconsumed_original();
        let path = format!("/proc/self/fd/{}", custody.connection.as_fd().unwrap().as_raw_fd());
        let mut retiring = retirement::RetiringMonitorCustodyV1::new(
            [1; 16], custody, Some(Error::InvalidRequest),
        );

        assert!(retiring.progress().is_err());
        assert!(retiring.progress().is_err());
        assert!(std::fs::read_link(&path).is_ok());
        let registry = MonitorRegistry::default();
        registry.0.lock().unwrap().owner = MonitorOwnerV4::Retiring(retiring);
        assert!(!registry.finish_execution([1; 16]).unwrap());
        assert!(registry.0.lock().unwrap().owner.has_retiring());
    }
}
