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

use aos_sandbox_agent::openssh_consume::{
    OriginalAttachActionV3, OriginalAttachObservationV3, OriginalAttachPhaseV3,
};
use aos_sandbox_agent::openssh_gate_linux::OpenSshMonitorRuntimeV2;
use aos_sandbox_agent::openssh_monitor::{
    OPENSSH_MONITOR_BINDING_ACK_V2, OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2,
    OpenSshMonitorWitnessV2,
};
use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
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

#[derive(Clone, Default)]
pub(super) struct MonitorRegistry(Arc<Mutex<Registry>>);

#[derive(Default)]
struct Registry {
    installed: Option<InstalledScope>,
    custody: Option<MonitorCustody>,
    session: Option<SessionLiveness>,
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
    terminal_notified: bool,
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
        registry.custody.take();
        registry.session.take();
        registry.installed.take();
    }

    /// Samples the original session while the caller retains the effect
    /// barrier. A closed channel triggers the existing Owner cancellation, not
    /// an authorization decision, reconnect adoption, or a new monitor grant.
    pub(super) fn prune_closed(&self, ledger: &Ledger) -> Result<Option<[u8; 16]>, Error> {
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        let original_session_is_valid = {
            let Registry {
                installed, session, ..
            } = &mut *registry;
            match (installed.as_ref(), session.as_mut()) {
                (Some(installed), Some(session)) => {
                    terminal::refresh_original_terminal(installed, session, ledger).is_ok()
                        && if session.terminal_notified {
                            session.root_is_live()
                        } else {
                            session.is_live()
                        }
                }
                (_, None) => true,
                (None, Some(_)) => false,
            }
        };
        if let Some(session) = registry.session.as_ref() {
            if !original_session_is_valid {
                let execution = session.execution;
                let process = ledger.read_process_bytes(execution)?;
                if process.cancel_on_disconnect == Some(true) && process.terminal.is_none() {
                    crate::process::cancel_owned_execution(
                        ledger,
                        aos_sandbox_core::ExecutionId::from_bytes(execution),
                        Instant::now() + DEADLINE,
                    )?;
                }
                registry.session.take();
                registry.custody.take();
                registry.installed.take();
                return Ok(Some(execution));
            }
        }
        let Registry {
            installed, custody, ..
        } = &mut *registry;
        let valid = match (installed.as_ref(), custody.as_mut()) {
            (Some(installed), Some(custody)) => {
                custody.is_live() && refresh_relay(installed, custody, ledger).is_ok()
            }
            (_, None) => true,
            (None, Some(_)) => false,
        };
        if !valid {
            registry.custody.take();
        }
        Ok(None)
    }

    /// Forecloses new consume while retaining an already consumed data channel.
    ///
    /// # Errors
    /// Rejects a poisoned monitor ownership lock.
    pub(super) fn finish_execution(&self, execution: [u8; 16]) -> Result<(), Error> {
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        if registry
            .installed
            .as_ref()
            .is_some_and(|scope| scope.runtime.claim().binding.execution_id == execution)
        {
            registry.custody.take();
            if registry.session.is_none() {
                registry.installed.take();
            }
        }
        Ok(())
    }

    /// Reports original in-memory consumed-session ownership without recovery.
    ///
    /// # Errors
    /// Rejects a poisoned monitor ownership lock.
    pub(super) fn has_original_session(&self, execution: [u8; 16]) -> Result<bool, Error> {
        let registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        Ok(registry
            .session
            .as_ref()
            .is_some_and(|session| session.execution == execution))
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
        aos_sandbox_agent::openssh_ticket::validate_ticket_profile_v2(
            runtime.claim(),
            &ticket,
            now()?,
        )
        .map_err(|_| Error::InvalidRequest)?;
        if read_ticket()? != original_ticket {
            return Err(Error::LedgerConflict);
        }

        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
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

    pub(super) fn register(
        &self,
        mut connection: SeqpacketSocket,
        ledger: &Ledger,
    ) -> Result<(), Error> {
        let deadline = Instant::now() + DEADLINE;
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        if registry.session.is_some() {
            return Err(Error::LedgerConflict);
        }
        let installed = registry.installed.as_ref().ok_or(Error::InvalidRequest)?;
        let original_expiry = PublicAttachTicketBindingV2::decode(&installed.original_ticket)
            .map_err(|_| Error::InvalidRequest)?
            .expires_at;
        require_root_monitor(&connection, &installed.runtime)?;

        let received = loop {
            match connection.receive_with_descriptors(OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2, 1) {
                Ok(record) => break record,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                    if Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(error.into()),
            }
        };
        let (payload, subject, child) = {
            let bound = connection
                .bind_received_descriptors(received)
                .map_err(|_| Error::InvalidRequest)?;
            let (payload, subject, mut descriptors, peer) = bound.into_parts();
            let sender = subject.credentials();
            let connector = peer.credentials();
            if sender.pid() != connector.pid()
                || sender.uid() != connector.uid()
                || sender.gid() != connector.gid()
                || sender.uid() != 0
                || !subject.is_alive().map_err(|_| Error::InvalidRequest)?
            {
                return Err(Error::InvalidRequest);
            }
            let descriptor = descriptors.pop().ok_or(Error::InvalidRequest)?;
            if !descriptors.is_empty() {
                return Err(Error::InvalidRequest);
            }
            let child = PidFd::from_owned(descriptor).map_err(|_| Error::InvalidRequest)?;
            (payload, subject, child)
        };
        validate_custody(installed, &connection, &subject, &child, &payload, ledger)?;
        if registry
            .custody
            .as_ref()
            .is_some_and(|custody| custody.is_live())
        {
            return Err(Error::LedgerConflict);
        }
        // Dropping a dead record closes all its handles. No historical record
        // can nominate a new child or revive a root connection after a restart.
        registry.custody.take();
        let installed = registry.installed.as_ref().ok_or(Error::InvalidRequest)?;
        validate_custody(installed, &connection, &subject, &child, &payload, ledger)?;
        if Instant::now() >= deadline {
            return Err(Error::InvalidRequest);
        }
        registry.custody = Some(MonitorCustody {
            connection,
            subject,
            child,
            original_witness: payload,
            original_expiry,
            relay: None,
            pending_io: None,
            controls: control::OriginalSessionControlsV5::new(),
        });
        // Retention itself must not turn an earlier valid sample into an
        // unexpired/current record. This remains only a point-in-time check.
        let Registry {
            installed, custody, ..
        } = &mut *registry;
        let installed = installed.as_ref().ok_or(Error::LedgerConflict)?;
        let custody = custody.as_mut().ok_or(Error::LedgerConflict)?;
        if !custody.is_live()
            || validate_custody(
                installed,
                &custody.connection,
                &custody.subject,
                &custody.child,
                &custody.original_witness,
                ledger,
            )
            .is_err()
        {
            registry.custody.take();
            return Err(Error::InvalidRequest);
        }
        // The acknowledgement contains no descriptor and grants no I/O. An
        // ambiguous send drops custody instead of allowing cached adoption.
        if let Err(error) = custody.connection.send(OPENSSH_MONITOR_BINDING_ACK_V2) {
            registry.custody.take();
            return Err(error.into());
        }
        if validate_custody(
            installed,
            &custody.connection,
            &custody.subject,
            &custody.child,
            &custody.original_witness,
            ledger,
        )
        .is_err()
        {
            registry.custody.take();
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }

    pub(super) fn queue_relay(
        &self,
        mut socket: SeqpacketSocket,
        ledger: &Ledger,
    ) -> Result<(), Error> {
        let barrier = ledger.effect_barrier();
        let _current = barrier.lock().map_err(|_| Error::LedgerConflict)?;
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        let Registry {
            installed, custody, ..
        } = &mut *registry;
        let installed = installed.as_ref().ok_or(Error::InvalidRequest)?;
        let custody = custody.as_mut().ok_or(Error::InvalidRequest)?;
        refresh_relay(installed, custody, ledger)?;
        if custody.pending_io.is_some() {
            return Err(Error::LedgerConflict);
        }
        let deadline = Instant::now() + DEADLINE;
        let received = loop {
            match socket.receive(8) {
                Ok(record) => break record,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                    if Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(error) => return Err(error.into()),
            }
        };
        let received = socket
            .bind_received(received)
            .map_err(|_| Error::InvalidRequest)?;
        let (payload, subject, _) = received.into_parts();
        if payload != b"AOSRIO03" {
            return Err(Error::InvalidRequest);
        }
        let pending = RelayConnection {
            socket,
            subject,
            deadline,
            io_attempted: false,
        };
        validate_relay(installed, custody, &pending, ledger)?;
        custody.pending_io = Some(pending);
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
            &aos_sandbox_agent::openssh_gate::OpenSshGateClaimV1,
            &mut dyn FnMut(&RelayConnection) -> Result<(), Error>,
        ) -> Result<(), Error>,
    ) -> Result<OriginalAttachObservationV3, Error> {
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        let Registry {
            installed, custody, ..
        } = &mut *registry;
        let installed = installed.as_ref().ok_or(Error::InvalidRequest)?;
        if installed.original_ticket != ticket || read_ticket()? != ticket {
            return Err(Error::LedgerConflict);
        }
        let Some(current) = custody.as_mut() else {
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
                validate_relay(installed, current, &pending, ledger)?;
                // The effect producer keeps ledger.live borrowed through SCM.
                // This callback rechecks actual root/relay custody but does not
                // reacquire that same tree lock; the producer rechecks its tree.
                let mut recheck = |pending: &RelayConnection| {
                    validate_relay_custody(installed, current, pending, ledger)
                };
                let transferred = (|| {
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
                }
                transferred?;
                observation.phase = OriginalAttachPhaseV3::Transferred;
            }
            Ok(observation)
        })();
        if let Some(io) = transferred_io {
            let original = registry.custody.take().ok_or(Error::LedgerConflict)?;
            let execution = registry
                .installed
                .as_ref()
                .ok_or(Error::LedgerConflict)?
                .runtime
                .claim()
                .binding
                .execution_id;
            let relay = original.relay.ok_or(Error::LedgerConflict)?;
            registry.session = Some(SessionLiveness {
                execution,
                connection: original.connection,
                subject: original.subject,
                child: original.child,
                relay,
                io,
                original_witness: original.original_witness,
                original_expiry: original.original_expiry,
                controls: original.controls,
                terminal_notified: false,
            });
        } else if action == OriginalAttachActionV3::Consume || result.is_err() {
            registry.custody.take();
        }
        result
    }
}

impl SessionLiveness {
    fn root_is_live(&self) -> bool {
        self.subject.is_alive().unwrap_or(false)
            && self.connection.peer().is_alive().unwrap_or(false)
            && self.child.is_alive().unwrap_or(false)
            && connected(&self.connection)
    }

    fn is_live(&self) -> bool {
        // These original handles were retained after the one-use SCM attempt.
        // No callback bytes, expiry refresh, scalar PID or session identifier
        // can recreate them. This method cannot release any descriptor.
        self.root_is_live()
            && self.relay.is_alive().unwrap_or(false)
            && self.io.subject.is_alive().unwrap_or(false)
            && self.io.socket.peer().is_alive().unwrap_or(false)
            && connected(&self.io.socket)
    }
}

impl MonitorCustody {
    fn is_live(&self) -> bool {
        self.subject.is_alive().unwrap_or(false)
            && self.connection.peer().is_alive().unwrap_or(false)
            && self.child.is_alive().unwrap_or(false)
            && !self.original_witness.is_empty()
            && now().is_ok_and(|now| now < self.original_expiry)
            && connected(&self.connection)
            && self
                .relay
                .as_ref()
                .is_none_or(|relay| relay.is_alive().unwrap_or(false))
    }
}

fn connected(connection: &SeqpacketSocket) -> bool {
    let Ok(fd) = connection.as_fd() else {
        return false;
    };
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
    matches!(rustix::event::poll(&mut fds, Some(&timeout)), Ok(0))
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
    let record = match custody.connection.receive_with_descriptors(
        aos_sandbox_agent::openssh_control::OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5,
        1,
    ) {
        Ok(record) => record,
        Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let record = custody
        .connection
        .bind_received_descriptors(record)
        .map_err(|_| Error::InvalidRequest)?;
    let (payload, subject, mut descriptors, peer) = record.into_parts();
    let sender = subject.credentials();
    let connector = peer.credentials();
    if sender.pid() != connector.pid()
        || sender.uid() != connector.uid()
        || sender.gid() != connector.gid()
    {
        return Err(Error::InvalidRequest);
    }
    if payload.get(..8) == Some(b"AOSMCQ05".as_slice()) {
        if !descriptors.is_empty() {
            return Err(Error::InvalidRequest);
        }
        control::require_same_root_subject(&subject, &custody.subject)?;
        control::require_control_custody(
            installed,
            &custody.connection,
            &custody.subject,
            &custody.child,
            &custody.original_witness,
            custody.original_expiry,
            ledger,
        )?;
        return custody.controls.queue(&payload);
    }
    if payload != b"AOSRLY03" || descriptors.len() != 1 || custody.relay.is_some() {
        return Err(Error::InvalidRequest);
    }
    installed
        .runtime
        .require_original_control_monitor_v5(subject.pidfd())
        .map_err(|_| Error::InvalidRequest)?;
    let relay = PidFd::from_owned(descriptors.pop().ok_or(Error::InvalidRequest)?)
        .map_err(|_| Error::InvalidRequest)?;
    validate_custody(
        installed,
        &custody.connection,
        &custody.subject,
        &custody.child,
        &custody.original_witness,
        ledger,
    )?;
    let witness = OpenSshMonitorWitnessV2::decode_confined_v3(&custody.original_witness)
        .map_err(|_| Error::InvalidRequest)?;
    let parent = custody
        .child
        .process_identity()
        .map_err(|_| Error::InvalidRequest)?;
    installed
        .runtime
        .require_confined_child_v3(&relay, parent.pid(), witness.uid, witness.gid)
        .map_err(|_| Error::InvalidRequest)?;
    custody.relay = Some(relay);
    // No execution descriptor is sent here. An ambiguous registration ACK
    // causes the caller to drop custody; it cannot adopt another relay later.
    custody.connection.send(b"AOSRAK03")?;
    validate_custody(
        installed,
        &custody.connection,
        &custody.subject,
        &custody.child,
        &custody.original_witness,
        ledger,
    )
}

fn read_ticket() -> Result<Vec<u8>, Error> {
    aos_sandbox_agent::openssh_gate_linux::load_original_ticket_claim_v2()
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

    #[test]
    fn cold_registry_never_reconstructs_monitor_custody() {
        let registry = MonitorRegistry::default();
        registry.finish_execution([1; 16]).unwrap();
        let cold = registry.0.lock().unwrap();
        assert!(cold.installed.is_none());
        assert!(cold.custody.is_none());
    }
}
