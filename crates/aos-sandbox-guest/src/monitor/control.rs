//! Exact original root-monitor controls under the shared Guest effect barrier.
//!
//! Queue data is not permission. Only the existing authenticated Host effect
//! reaches application, joining immutable ticket/holder bytes, actual retained
//! root connection and child, current original expiry and the owned execution
//! subtree. A sequence leaves the queue before any effect or acknowledgement;
//! ambiguity drops custody and never adopts a persisted reservation.

use std::time::Instant;

use aos_sandbox_agent::openssh_control::OpenSshControlRequestV5;
use aos_sandbox_agent::openssh_control_channel::{
    OriginalControlActionV5, OriginalControlObservationV5, OriginalControlPhaseV5,
};
use aos_sandbox_agent::openssh_monitor::OpenSshMonitorWitnessV2;
use aos_sandbox_core::public_attach_ticket::PublicAttachTicketBindingV2;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, SeqpacketSocket};
use sha2::{Digest as _, Sha256};

use super::{Error, InstalledScope, Ledger, MonitorRegistry, Registry};

pub(super) struct OriginalSessionControlsV5 {
    pub(super) next_sequence: u64,
    pub(super) pending: Option<Vec<u8>>,
    pty_configured: bool,
}

impl OriginalSessionControlsV5 {
    pub(super) fn new() -> Self {
        Self {
            next_sequence: 1,
            pending: None,
            pty_configured: false,
        }
    }

    /// Retains one canonical request without reserving or authorizing an effect.
    ///
    /// # Errors
    /// Rejects malformed, duplicate, exhausted or out-of-order request data.
    pub(super) fn queue(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let request = OpenSshControlRequestV5::decode(bytes).map_err(|_| Error::InvalidRequest)?;
        if self.pending.is_some() || request.sequence != self.next_sequence {
            return Err(Error::LedgerConflict);
        }
        self.pending = Some(bytes.to_vec());
        Ok(())
    }
}

impl MonitorRegistry {
    /// Observes or applies a request while the caller retains the effect barrier.
    ///
    /// # Errors
    /// Rejects missing/currently foreign custody, expired authority, substitution,
    /// unsupported original topology, reused sequence or ambiguous effect/ACK.
    pub(crate) fn original_control_v5(
        &self,
        action: OriginalControlActionV5,
        expected_binding: [u8; 32],
        expected_request: &[u8],
        ticket: &[u8],
        ledger: &Ledger,
        deadline: Instant,
        authority_expires_at: i64,
        effect_deadline_boottime_nanoseconds: u64,
    ) -> Result<OriginalControlObservationV5, Error> {
        let mut registry = self.0.lock().map_err(|_| Error::LedgerConflict)?;
        let result = (|| {
            let Registry {
                installed,
                custody,
                session,
            } = &mut *registry;
            let installed = installed.as_ref().ok_or(Error::InvalidRequest)?;
            if installed.original_ticket != ticket || super::read_ticket()? != ticket {
                return Err(Error::LedgerConflict);
            }
            if let Some(session) = session.as_mut() {
                super::terminal::refresh_original_terminal(installed, session, ledger)?;
                apply_or_observe(
                    installed,
                    &mut session.connection,
                    &session.subject,
                    &session.child,
                    &session.original_witness,
                    session.original_expiry,
                    &mut session.controls,
                    true,
                    action,
                    expected_binding,
                    expected_request,
                    ledger,
                    deadline,
                    authority_expires_at,
                    effect_deadline_boottime_nanoseconds,
                )
            } else if let Some(custody) = custody.as_mut() {
                super::refresh_relay(installed, custody, ledger)?;
                apply_or_observe(
                    installed,
                    &mut custody.connection,
                    &custody.subject,
                    &custody.child,
                    &custody.original_witness,
                    custody.original_expiry,
                    &mut custody.controls,
                    false,
                    action,
                    expected_binding,
                    expected_request,
                    ledger,
                    deadline,
                    authority_expires_at,
                    effect_deadline_boottime_nanoseconds,
                )
            } else if action == OriginalControlActionV5::Poll {
                Ok(OriginalControlObservationV5 {
                    binding: [0; 32],
                    phase: OriginalControlPhaseV5::Idle,
                    transfer_attempted: false,
                    witness: Vec::new(),
                    request: Vec::new(),
                })
            } else {
                Err(Error::InvalidRequest)
            }
        })();
        if result.is_err() {
            // A failed effect/ACK may already have happened. Cold or equal-row
            // recovery cannot recreate this original private root connection.
            registry.custody.take();
            registry.session.take();
        }
        result
    }
}

fn apply_or_observe(
    installed: &InstalledScope,
    connection: &mut SeqpacketSocket,
    subject: &KernelAuthorizedRecordSubject,
    child: &PidFd,
    witness: &[u8],
    original_expiry: u64,
    controls: &mut OriginalSessionControlsV5,
    transfer_attempted: bool,
    action: OriginalControlActionV5,
    expected_binding: [u8; 32],
    expected_request: &[u8],
    ledger: &Ledger,
    deadline: Instant,
    authority_expires_at: i64,
    effect_deadline_boottime_nanoseconds: u64,
) -> Result<OriginalControlObservationV5, Error> {
    let recheck_root = |connection: &SeqpacketSocket| {
        require_control_custody(
            installed,
            connection,
            subject,
            child,
            witness,
            original_expiry,
            ledger,
        )
    };
    recheck_root(connection)?;
    let process = ledger.read_process_bytes(installed.runtime.claim().binding.execution_id)?;
    ledger.require_active_original_tree_v5(&process)?;
    let binding = control_binding(installed, connection, subject, child, witness)?;
    let queued = controls.pending.as_deref().unwrap_or(&[]);
    if action == OriginalControlActionV5::Poll {
        return Ok(OriginalControlObservationV5 {
            binding,
            transfer_attempted,
            phase: if queued.is_empty() {
                OriginalControlPhaseV5::Idle
            } else {
                OriginalControlPhaseV5::Queued
            },
            witness: witness.to_vec(),
            request: queued.to_vec(),
        });
    }
    if binding != expected_binding || queued != expected_request || queued.is_empty() {
        return Err(Error::InvalidRequest);
    }
    let request = OpenSshControlRequestV5::decode(queued).map_err(|_| Error::InvalidRequest)?;
    if request.sequence != controls.next_sequence {
        return Err(Error::LedgerConflict);
    }
    use aos_sandbox_agent::openssh_control::OpenSshControlActionV5;
    match &request.action {
        OpenSshControlActionV5::Pty { .. } if transfer_attempted || controls.pty_configured => {
            return Err(Error::InvalidRequest);
        }
        OpenSshControlActionV5::Resize(_) if !controls.pty_configured => {
            return Err(Error::InvalidRequest);
        }
        _ => {}
    }
    let exact_request = controls.pending.take().ok_or(Error::LedgerConflict)?;
    controls.next_sequence = controls
        .next_sequence
        .checked_add(1)
        .ok_or(Error::LedgerConflict)?;
    let ticket_digest =
        aos_sandbox_agent::openssh_ticket::ticket_digest_v2(&installed.original_ticket);
    let mut current_deadline = || {
        let fresh = crate::bridge::original_authority_deadline(
            authority_expires_at,
            effect_deadline_boottime_nanoseconds,
        )?;
        crate::process::check_deadline(deadline.min(fresh))
    };
    current_deadline()?;
    crate::process::apply_owned_original_control_v5(
        ledger,
        aos_sandbox_core::ExecutionId::from_bytes(process.execution),
        ticket_digest,
        binding,
        &request,
        deadline,
        &mut current_deadline,
        || {
            crate::process::check_deadline(deadline)?;
            // This deliberately does not reacquire ledger.live: the actual
            // tree/PTY owner holds that lock through every kernel effect.
            recheck_root(connection)
        },
    )?;
    current_deadline().map_err(|_| Error::AmbiguousEffect)?;
    recheck_root(connection).map_err(|_| Error::AmbiguousEffect)?;
    if matches!(request.action, OpenSshControlActionV5::Pty { .. }) {
        controls.pty_configured = true;
    }
    let mut ack = [0; 24];
    ack[..8].copy_from_slice(b"AOSMCA05");
    ack[8..16].copy_from_slice(&request.sequence.to_be_bytes());
    connection.send(&ack).map_err(|_| Error::AmbiguousEffect)?;
    current_deadline().map_err(|_| Error::AmbiguousEffect)?;
    recheck_root(connection).map_err(|_| Error::AmbiguousEffect)?;
    Ok(OriginalControlObservationV5 {
        binding,
        phase: OriginalControlPhaseV5::Applied,
        transfer_attempted,
        witness: witness.to_vec(),
        request: exact_request,
    })
}

/// Rechecks physical/root/ticket custody without locking the actual tree twice.
pub(super) fn require_control_custody(
    installed: &InstalledScope,
    connection: &SeqpacketSocket,
    subject: &KernelAuthorizedRecordSubject,
    child: &PidFd,
    witness_bytes: &[u8],
    original_expiry: u64,
    ledger: &Ledger,
) -> Result<(), Error> {
    if !super::connected(connection)
        || super::now()? >= original_expiry
        || !subject.is_alive().map_err(|_| Error::InvalidRequest)?
        || super::read_ticket()? != installed.original_ticket
    {
        return Err(Error::InvalidRequest);
    }
    installed
        .runtime
        .require_original_control_monitor_v5(connection.peer().pidfd())
        .map_err(|_| Error::InvalidRequest)?;
    installed
        .runtime
        .require_original_control_monitor_v5(subject.pidfd())
        .map_err(|_| Error::InvalidRequest)?;
    let witness = OpenSshMonitorWitnessV2::decode_confined_v3(witness_bytes)
        .map_err(|_| Error::InvalidRequest)?;
    let ticket = PublicAttachTicketBindingV2::decode(&installed.original_ticket)
        .map_err(|_| Error::InvalidRequest)?;
    let claim = installed.runtime.claim();
    witness
        .validate_original_holder(claim, &ticket, super::now()?)
        .map_err(|_| Error::InvalidRequest)?;
    installed
        .runtime
        .require_confined_child_v3(
            child,
            subject.credentials().pid().get(),
            witness.uid,
            witness.gid,
        )
        .map_err(|_| Error::InvalidRequest)?;
    let process = ledger.read_process_bytes(claim.binding.execution_id)?;
    let request = aos_sandbox_agent::openssh_gate::decode_openssh_gate_bridge_request_v1(
        &claim
            .encode_bridge_request()
            .map_err(|_| Error::InvalidRequest)?,
    )
    .map_err(|_| Error::InvalidRequest)?;
    if !crate::bridge::request_matches(&request, claim, &process)
        || crate::gate::static_login_identity(&claim.binding.user)? != (witness.uid, witness.gid)
        || process.canceled
        || process.terminal.is_some()
    {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}

pub(super) fn require_same_root_subject(
    subject: &KernelAuthorizedRecordSubject,
    original: &KernelAuthorizedRecordSubject,
) -> Result<(), Error> {
    let actual = subject.credentials();
    let expected = original.credentials();
    if actual.uid() != 0
        || actual.pid() != expected.pid()
        || actual.uid() != expected.uid()
        || actual.gid() != expected.gid()
        || subject
            .pidfd()
            .process_identity()
            .map_err(|_| Error::InvalidRequest)?
            != original
                .pidfd()
                .process_identity()
                .map_err(|_| Error::InvalidRequest)?
    {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}

fn control_binding(
    installed: &InstalledScope,
    connection: &SeqpacketSocket,
    subject: &KernelAuthorizedRecordSubject,
    child: &PidFd,
    witness: &[u8],
) -> Result<[u8; 32], Error> {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.live-original-monitor-controls.v5\0");
    digest.update(aos_sandbox_agent::openssh_ticket::ticket_digest_v2(
        &installed.original_ticket,
    ));
    digest.update(witness);
    digest.update(connection.peer().socket_cookie().get().to_be_bytes());
    for process in [subject.pidfd(), child] {
        let identity = process
            .process_identity()
            .map_err(|_| Error::InvalidRequest)?;
        digest.update(identity.pid().to_be_bytes());
        digest.update(identity.start_time_ticks().to_be_bytes());
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    //! Queue shape/sequence tests do not substitute for actual monitor custody.

    use super::*;
    use aos_sandbox_agent::openssh_control::OpenSshControlActionV5;

    #[test]
    fn queue_never_renews_or_replays_an_original_sequence() {
        let mut controls = OriginalSessionControlsV5::new();
        let bytes = OpenSshControlRequestV5 {
            sequence: 1,
            action: OpenSshControlActionV5::Signal(15),
        }
        .encode()
        .unwrap();
        controls.queue(&bytes).unwrap();
        assert!(controls.queue(&bytes).is_err());
        controls.pending.take();
        controls.next_sequence = 2;
        assert!(controls.queue(&bytes).is_err());
    }
}
