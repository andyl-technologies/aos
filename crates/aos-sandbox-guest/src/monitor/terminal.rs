//! Original-session terminal data from retained monitor and execution ownership.
//!
//! Terminal reads grant no mutation or I/O. They retain the already accepted
//! root connection and immutable witness, not callback bytes, relay exit or a
//! reconstructible PID. Certificate expiry does not refresh this custody or
//! permit a control: the only reply source is a validated original waitstatus
//! after the actual retained execution subtree became empty.

use aos_sandbox_agent::openssh_session::{
    OpenSshSessionActionV4, OpenSshSessionReplyV4, OpenSshSessionRequestV4, OpenSshSessionStateV4,
    OriginalExecutionWaitStatusV4,
};

use super::{
    Error, InstalledScope, Ledger, OpenSshMonitorWitnessV2, SeqpacketError, SessionLiveness,
};

/// Publishes only retained original terminal data under the caller's barrier.
///
/// # Errors
/// Rejects a changed installation, foreign/dead sender or child, invalid
/// sequence, ambiguous notification, or absent actual execution ownership.
pub(super) fn refresh_original_terminal(
    installed: &InstalledScope,
    session: &mut SessionLiveness,
    ledger: &Ledger,
) -> Result<(), Error> {
    // Idle polling has no publication or effect. The full measured physical
    // installation is reread at each outgoing data boundary, not hashed on
    // every empty poll while an execution is still running.
    if !session.root_is_live()
        || session.execution != installed.runtime.claim().binding.execution_id
        || session.original_witness.is_empty()
    {
        return Err(Error::InvalidRequest);
    }
    let execution = aos_sandbox_core::ExecutionId::from_bytes(session.execution);
    let terminal = crate::process::observe_owned_terminal(ledger, execution)?;
    let raw = if terminal.is_some() {
        let process = ledger.read_process_bytes(session.execution)?;
        Some(
            OriginalExecutionWaitStatusV4::new(
                process.terminal_waitstatus.ok_or(Error::LedgerConflict)?,
            )
            .map_err(|_| Error::LedgerConflict)?,
        )
    } else {
        None
    };
    if let Some(status) = raw {
        if !session.terminal_notified {
            // This is the original one-use IO connection, never a new stream
            // or retry of SCM. An ambiguous notification is not redispatched.
            require_original_terminal_session(installed, session, ledger)?;
            session.terminal_notified = true;
            session.io.socket.send(&status.encode_io_terminal())?;
            require_original_terminal_session(installed, session, ledger)?;
        }
    }

    let record = match session
        .connection
        .receive(aos_sandbox_agent::openssh_control::OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5)
    {
        Ok(record) => record,
        Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let bound = session
        .connection
        .bind_received(record)
        .map_err(|_| Error::InvalidRequest)?;
    let (payload, subject, _) = bound.into_parts();
    if payload.get(..8) == Some(b"AOSMCQ05".as_slice()) {
        super::control::require_same_root_subject(&subject, &session.subject)?;
        super::control::require_control_custody(
            installed,
            &session.connection,
            &session.subject,
            &session.child,
            &session.original_witness,
            session.original_expiry,
            ledger,
        )?;
        return session.controls.queue(&payload);
    }
    let sender = subject.credentials();
    let original = session.subject.credentials();
    if sender.pid() != original.pid()
        || sender.uid() != original.uid()
        || sender.gid() != original.gid()
        || subject
            .pidfd()
            .process_identity()
            .map_err(|_| Error::InvalidRequest)?
            != session
                .subject
                .pidfd()
                .process_identity()
                .map_err(|_| Error::InvalidRequest)?
    {
        return Err(Error::InvalidRequest);
    }
    let request = OpenSshSessionRequestV4::decode(&payload).map_err(|_| Error::InvalidRequest)?;
    if request.sequence != session.controls.next_sequence
        || request.action != OpenSshSessionActionV4::Terminal
    {
        return Err(Error::InvalidRequest);
    }
    // Correlation is session-private and cannot authorize a signal or resize.
    // Reserve before the reply: ambiguity closes custody, never replays it.
    if session.controls.pending.is_some() {
        return Err(Error::InvalidRequest);
    }
    session.controls.next_sequence = session
        .controls
        .next_sequence
        .checked_add(1)
        .ok_or(Error::LedgerConflict)?;
    require_original_terminal_session(installed, session, ledger)?;
    session.connection.send(
        &OpenSshSessionReplyV4 {
            sequence: request.sequence,
            state: raw
                .map(OpenSshSessionStateV4::Terminal)
                .unwrap_or(OpenSshSessionStateV4::Pending),
        }
        .encode()
        .map_err(|_| Error::InvalidRequest)?,
    )?;
    require_original_terminal_session(installed, session, ledger)
}

fn require_original_terminal_session(
    installed: &InstalledScope,
    session: &SessionLiveness,
    ledger: &Ledger,
) -> Result<(), Error> {
    installed
        .runtime
        .require_original_terminal_monitor_v4(session.connection.peer().pidfd())
        .map_err(|_| Error::InvalidRequest)?;
    installed
        .runtime
        .require_original_terminal_monitor_v4(session.subject.pidfd())
        .map_err(|_| Error::InvalidRequest)?;
    if !session.root_is_live() || super::read_ticket()? != installed.original_ticket {
        return Err(Error::InvalidRequest);
    }
    let witness = OpenSshMonitorWitnessV2::decode_confined_v3(&session.original_witness)
        .map_err(|_| Error::InvalidRequest)?;
    let claim = installed.runtime.claim();
    let process = ledger.read_process_bytes(session.execution)?;
    let request = aos_sandbox_agent::openssh_gate::decode_openssh_gate_bridge_request_v1(
        &claim
            .encode_bridge_request()
            .map_err(|_| Error::InvalidRequest)?,
    )
    .map_err(|_| Error::InvalidRequest)?;
    if !crate::bridge::request_matches(&request, claim, &process)
        || crate::gate::static_login_identity(&claim.binding.user)? != (witness.uid, witness.gid)
    {
        return Err(Error::InvalidRequest);
    }
    installed
        .runtime
        .require_confined_child_v3(
            &session.child,
            session.subject.credentials().pid().get(),
            witness.uid,
            witness.gid,
        )
        .map_err(|_| Error::InvalidRequest)
}
