//! Original-session terminal data from retained monitor and execution ownership.
//!
//! Terminal reads grant no mutation or I/O. They retain the already accepted
//! root connection and immutable witness, not callback bytes, relay exit or a
//! reconstructible PID. Certificate expiry does not refresh this custody or
//! permit a control: the only reply source is a validated original waitstatus
//! after the actual retained execution subtree became empty.

use aos_sandbox_guest_protocol::openssh_session::{
    OpenSshSessionActionV4, OpenSshSessionReplyV4, OpenSshSessionRequestV4, OpenSshSessionStateV4,
    OriginalExecutionWaitStatusV4,
};

use super::{
    Error, InstalledScope, Ledger, OpenSshMonitorWitnessV2, SessionLiveness,
};
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, ReceivedRecord,
    RecordBindingError, RetainedSeqpacketReceiveErrorV1, RetainedSeqpacketSendErrorV1};

#[derive(Default)]
pub(super) struct TerminalRefreshOriginalV1 {
    body: Option<Result<(), Error>>,
    notification_before: Option<Result<(), Error>>,
    notification_bytes: Option<[u8; 12]>,
    notification: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    notification_after: Option<Result<(), Error>>,
    notification_after_native: aos_sandbox_linux::seqpacket::SeqpacketSendAfterOriginalV1,
    notification_after_binding: Option<Result<(), RecordBindingError>>,
    receive: Option<Result<ReceivedRecord, RetainedSeqpacketReceiveErrorV1>>,
    receive_after: Option<Result<bool, Error>>,
    binding: Option<Result<(), RecordBindingError>>,
    received: Option<(Vec<u8>, KernelAuthorizedRecordSubject)>,
    response_before: Option<Result<(), Error>>,
    response_bytes: Option<[u8; aos_sandbox_guest_protocol::openssh_session::OPENSSH_SESSION_RECORD_BYTES_V4]>,
    response: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    response_after: Option<Result<(), Error>>,
    response_after_native: aos_sandbox_linux::seqpacket::SeqpacketSendAfterOriginalV1,
    response_after_binding: Option<Result<(), RecordBindingError>>,
}

impl TerminalRefreshOriginalV1 {
    pub(super) fn failed(&self) -> bool {
        self.body.as_ref().is_some_and(Result::is_err)
    }
}

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
    if session.refresh.failed() {
        return Err(Error::AmbiguousEffect);
    }
    if session.terminal_reply_sent {
        // The actual final reply already completed its independent after.
        // Poll the original disconnect; never receive another RPC after it.
        return Ok(());
    }
    // Only the preceding full-positive refresh may retire its native DATA.
    // A failed original is never overwritten, resampled or retried.
    session.refresh = TerminalRefreshOriginalV1::default();
    let result = refresh_original_terminal_inner(installed, session, ledger);
    let positive = result.is_ok();
    session.refresh.body = Some(result);
    if positive { Ok(()) } else { Err(Error::AmbiguousEffect) }
}

fn refresh_original_terminal_inner(
    installed: &InstalledScope,
    session: &mut SessionLiveness,
    ledger: &Ledger,
) -> Result<(), Error> {
    // Idle polling has no publication or effect. The full measured physical
    // installation is reread at each outgoing data boundary, not hashed on
    // every empty poll while an execution is still running.
    if !session.root_is_live()?
        || session.execution != installed.runtime.claim().binding.execution_id
        || session.original_witness.is_empty()
    {
        return Err(Error::InvalidRequest);
    }
    let execution = aos_sandbox_model::ExecutionId::from_bytes(session.execution);
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
            session.refresh.notification_before = Some(require_original_terminal_session(installed, session, ledger));
            if matches!(session.refresh.notification_before, Some(Ok(()))) {
                session.terminal_notified = true;
                session.refresh.notification_bytes = Some(status.encode_io_terminal());
                let bytes = session.refresh.notification_bytes.as_ref().ok_or(Error::AmbiguousEffect)?;
                session.refresh.notification = Some(session.io.socket.send_retaining(bytes));
            }
            // This actual after remains owed even when the native send fails.
            session.refresh.notification_after = Some(require_original_terminal_after(installed, session, ledger));
            let failure = session.refresh.notification.as_ref().and_then(|result| result.as_ref().err());
            session.refresh.notification_after_binding = Some(session.refresh.notification_after_native
                .observe_once_v1(&session.io.socket, failure));
            if !matches!(session.refresh.notification_before, Some(Ok(())))
                || !matches!(session.refresh.notification, Some(Ok(())))
                || !matches!(session.refresh.notification_after, Some(Ok(())))
                || !matches!(session.refresh.notification_after_binding, Some(Ok(())))
            {
                return Err(Error::AmbiguousEffect);
            }
        }
    }

    session.refresh.receive = Some(session.connection.receive_registered_guest_monitor_request_retaining_v2(
        aos_sandbox_guest_protocol::openssh_control::OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5,
        &session.restriction,
    ));
    // Keep the actual root liveness Result independently of native refusal.
    session.refresh.receive_after = Some(session.root_is_live());
    if !matches!(session.refresh.receive_after, Some(Ok(true))) {
        return Err(Error::AmbiguousEffect);
    }
    if session.refresh.receive.as_ref().is_some_and(|result| result.as_ref().is_err_and(|cause|
        cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted()))
    {
        return Ok(());
    }
    if !matches!(session.refresh.receive, Some(Ok(_))) {
        return Err(Error::AmbiguousEffect);
    }
    let Some(Ok(record)) = session.refresh.receive.take() else {
        return Err(Error::AmbiguousEffect);
    };
    match session.connection.bind_received_retaining(record) {
        Ok(bound) => {
            let (payload, subject, _) = bound.into_parts();
            session.refresh.received = Some((payload, subject));
            session.refresh.binding = Some(Ok(()));
        }
        Err((cause, record)) => {
            session.refresh.receive = Some(Ok(record));
            session.refresh.binding = Some(Err(cause));
            return Err(Error::AmbiguousEffect);
        }
    }
    let (payload, subject) = session.refresh.received.as_ref().ok_or(Error::AmbiguousEffect)?;
    if payload.get(..8) == Some(b"AOSMCQ05".as_slice()) {
        super::control::require_same_root_subject(subject, &session.subject)?;
        super::control::require_control_custody(
            installed,
            &session.connection,
            &session.subject,
            &session.child,
            &session.original_witness,
            session.original_expiry,
            ledger,
        )?;
        return session.controls.queue(payload);
    }
    let sender = subject.credentials();
    let original = session.subject.credentials();
    if sender.pid() != original.pid()
        || sender.uid() != original.uid()
        || sender.gid() != original.gid()
        || aos_sandbox_linux::pidfd::process_identity(&(subject
            .pidfd()))
            .map_err(Error::Confinement)?
            != aos_sandbox_linux::pidfd::process_identity(&(session
                .subject
                .pidfd()))
                .map_err(Error::Confinement)?
    {
        return Err(Error::InvalidRequest);
    }
    let request = OpenSshSessionRequestV4::decode(payload).map_err(|_| Error::InvalidRequest)?;
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
    session.refresh.response_bytes = Some(OpenSshSessionReplyV4 {
            sequence: request.sequence,
            state: raw
                .map(OpenSshSessionStateV4::Terminal)
                .unwrap_or(OpenSshSessionStateV4::Pending),
        }.encode().map_err(|_| Error::InvalidRequest)?);
    session.refresh.response_before = Some(require_original_terminal_session(installed, session, ledger));
    if matches!(session.refresh.response_before, Some(Ok(()))) {
        let bytes = session.refresh.response_bytes.as_ref().ok_or(Error::AmbiguousEffect)?;
        session.refresh.response = Some(session.connection.send_retaining(bytes));
    }
    session.refresh.response_after = Some(require_original_terminal_after(installed, session, ledger));
    let failure = session.refresh.response.as_ref().and_then(|result| result.as_ref().err());
    session.refresh.response_after_binding = Some(session.refresh.response_after_native
        .observe_once_v1(&session.connection, failure));
    if matches!(session.refresh.response_before, Some(Ok(())))
        && matches!(session.refresh.response, Some(Ok(())))
        && matches!(session.refresh.response_after, Some(Ok(())))
        && matches!(session.refresh.response_after_binding, Some(Ok(())))
    {
        if raw.is_some() { session.terminal_reply_sent = true; }
        Ok(())
    } else {
        Err(Error::AmbiguousEffect)
    }
}

fn require_original_terminal_session(
    installed: &InstalledScope,
    session: &SessionLiveness,
    ledger: &Ledger,
) -> Result<(), Error> {
    installed
        .runtime
        .require_original_terminal_monitor_v4(session.connection.peer().pidfd())
        .map_err(Error::OpenSshPhysical)?;
    installed
        .runtime
        .require_original_terminal_monitor_v4(session.subject.pidfd())
        .map_err(Error::OpenSshPhysical)?;
    if !session.root_is_live()? {
        return Err(Error::InvalidRequest);
    }
    let witness = require_original_terminal_binding(installed, session, ledger)?;
    installed
        .runtime
        .require_confined_child_v3(
            &session.child,
            session.subject.credentials().pid().get(),
            witness.uid,
            witness.gid,
        )
        .map_err(Error::OpenSshPhysical)
}

// Only the terminal send path calls this nonauthorizing after. The same
// private Session retains its actual before, native send, PIDFDs and cookie
// original. Receiver exit is expected after delivery and does not create a
// fresh control or descriptor-transfer permission.
fn require_original_terminal_after(
    installed: &InstalledScope,
    session: &SessionLiveness,
    ledger: &Ledger,
) -> Result<(), Error> {
    installed.runtime.require_original_terminal_after_installation_v1()
        .map_err(Error::OpenSshPhysical)?;
    require_original_terminal_binding(installed, session, ledger).map(|_| ())
}

fn require_original_terminal_binding<'session>(
    installed: &InstalledScope,
    session: &'session SessionLiveness,
    ledger: &Ledger,
) -> Result<OpenSshMonitorWitnessV2<'session>, Error> {
    if super::read_ticket()? != installed.original_ticket {
        return Err(Error::InvalidRequest);
    }
    let witness = OpenSshMonitorWitnessV2::decode_confined_v3(&session.original_witness)
        .map_err(|_| Error::InvalidRequest)?;
    let claim = installed.runtime.claim();
    let process = ledger.read_process_bytes(session.execution)?;
    let request = aos_sandbox_guest_protocol::openssh_gate::decode_openssh_gate_bridge_request_v1(
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
    Ok(witness)
}
