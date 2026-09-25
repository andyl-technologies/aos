//! Fixed-process transport for the native namespace-inspector manager query.
//!
//! The session gives the helper exactly three inherited roles: an already
//! connected manager stream at FD 3, a duplicate of the invoking inspector's
//! retained pidfd at FD 4, and a private authenticated control endpoint at FD
//! 5. The controller retains the other endpoint, authenticates every helper
//! record against the supervisor's live child, and implements the closed
//! START/A/CONTINUE/B/ACK/ABORT state machine.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::process::{
    ExchangeStep, FixedLiveChild, FixedProcessControlInterest, FixedProcessControlReadiness,
    FixedProcessRequest, FixedProcessSessionError, FixedProcessSessionExchange,
    FixedProcessSessionOutcome, FixedProcessSessionRequest,
    run_fixed_process_session_from_executable_descriptor,
};
use aos_sandbox_linux::seqpacket::{
    KernelAuthorizedRecordSubject, SeqpacketError, SeqpacketSocket,
};
use thiserror::Error;

use super::{
    INSPECTOR_CONTROL_GROUP_PREFIX, MANAGER_QUERY_SCHEMA_DIGEST_V1,
    MatchedNamespaceInspectorActivationSnapshotsV1, NamespaceInspectorManagerQueryError,
    NamespaceInspectorManagerQueryExpectedActivationV1,
    ObservedNamespaceInspectorActivationSnapshotV1, match_namespace_inspector_activation_snapshots,
};
use crate::namespace_inspector::launch_contract::{
    NamespaceInspectorArtifactRoleV1, ProtectedNamespaceInspectorDeploymentContractError,
    ProtectedNamespaceInspectorDeploymentContractV1,
};
use crate::systemd_socket_instance::SystemdSocketInstanceV1;

const CONTROL_MAGIC: &[u8; 8] = b"AOSNIMS1";
const CONTROL_VERSION: u16 = 1;
const CONTROL_HEADER_BYTES: usize = 16;
const START_PAYLOAD_BYTES: usize = 104;
const NONCE_PAYLOAD_BYTES: usize = 32;
const ABORT_PAYLOAD_BYTES: usize = 36;
const PHASE_BINDING_BYTES: usize = 84;
const MAXIMUM_SNAPSHOT_BYTES: usize = 128 * 1024;
const MAXIMUM_CONTROL_RECORD_BYTES: usize =
    CONTROL_HEADER_BYTES + PHASE_BINDING_BYTES + MAXIMUM_SNAPSHOT_BYTES;
const MANAGER_QUERY_TIMEOUT: Duration = Duration::from_secs(1);
const MAXIMUM_HELPER_OUTPUT_BYTES: usize = 4096;
const CONTROL_INTERRUPT_LIMIT: usize = 8;

/// Supplies retained descriptor custody and activation evidence to one query.
#[derive(Debug)]
pub(crate) struct NamespaceInspectorManagerQuerySessionRequest<'a> {
    pub(crate) protected_contract: &'a ProtectedNamespaceInspectorDeploymentContractV1,
    pub(crate) manager_stream: OwnedFd,
    pub(crate) parent_pidfd: &'a PidFd,
    pub(crate) activation: SystemdSocketInstanceV1,
    pub(crate) nonce: [u8; 32],
}

/// Reports failure of the complete manager-query process session.
#[derive(Debug, Error)]
pub(crate) enum NamespaceInspectorManagerQuerySessionError {
    /// Protected policy or retained activation evidence is inconsistent.
    #[error("invalid namespace-inspector manager-query session input: {0}")]
    InvalidInput(&'static str),
    /// Descriptor setup or retained kernel observation failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The authenticated control socket could not be created.
    #[error(transparent)]
    Seqpacket(#[from] SeqpacketError),
    /// Protected contract or snapshot model validation failed.
    #[error(transparent)]
    Model(#[from] NamespaceInspectorManagerQueryError),
    /// A pinned deployment artifact could not be duplicated or revalidated.
    #[error(transparent)]
    ProtectedDeployment(#[from] ProtectedNamespaceInspectorDeploymentContractError),
    /// The fixed-process supervisor or protocol exchange failed.
    #[error(transparent)]
    Session(#[from] FixedProcessSessionError<ManagerQueryExchangeError>),
    /// The helper exited before the authenticated exchange completed.
    #[error("namespace-inspector manager-query helper exited before completing its exchange")]
    ChildExitedBeforeExchange,
    /// The shared monotonic session deadline expired.
    #[error("namespace-inspector manager-query helper timed out")]
    TimedOut,
    /// Standard output or standard error crossed its configured ceiling.
    #[error("namespace-inspector manager-query helper exceeded an output ceiling")]
    OutputLimitExceeded,
    /// The helper did not exit normally with status zero.
    #[error("namespace-inspector manager-query helper exited unsuccessfully")]
    UnsuccessfulExit,
    /// A successful helper emitted unexpected output.
    #[error("namespace-inspector manager-query helper emitted output")]
    UnexpectedOutput,
}

/// Runs one native helper and returns only completely matched evidence.
///
/// The caller must retain the accepted socket from which `activation` was
/// derived and must have authenticated `manager_stream` as a fresh connection
/// to the protected systemd private-manager socket. The production inspector
/// composes both retained constructors before calling this session.
///
/// # Errors
///
/// Returns [`NamespaceInspectorManagerQuerySessionError`] for invalid retained
/// evidence, descriptor setup, process supervision, protocol, deadline,
/// output, exit-status, or snapshot-binding failures.
pub(crate) fn run_namespace_inspector_manager_query_session(
    request: NamespaceInspectorManagerQuerySessionRequest<'_>,
) -> Result<
    MatchedNamespaceInspectorActivationSnapshotsV1,
    NamespaceInspectorManagerQuerySessionError,
> {
    if request.nonce == [0; 32] {
        return Err(NamespaceInspectorManagerQuerySessionError::InvalidInput(
            "nonce must be nonzero",
        ));
    }
    let contract = request.protected_contract.contract();
    let helper = contract.manager_query_helper().ok_or(
        NamespaceInspectorManagerQuerySessionError::InvalidInput(
            "helper invocation must contain exactly one absolute executable path",
        ),
    )?;
    let helper_executable = request
        .protected_contract
        .duplicate_artifact(NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable)?;

    let parent_info = request.parent_pidfd.info()?;
    let parent_credentials = parent_info.credentials().ok_or(
        NamespaceInspectorManagerQuerySessionError::InvalidInput(
            "parent pidfd omitted credentials",
        ),
    )?;
    let parent_cgroup_id = parent_info.cgroup_id().filter(|value| *value != 0).ok_or(
        NamespaceInspectorManagerQuerySessionError::InvalidInput(
            "parent pidfd omitted its cgroup ID",
        ),
    )?;
    if parent_info.pid() != std::process::id()
        || parent_info.thread_group_id() != parent_info.pid()
        || parent_credentials.effective_user_id() != 0
        || parent_credentials.effective_group_id() != 0
    {
        return Err(NamespaceInspectorManagerQuerySessionError::InvalidInput(
            "parent pidfd must identify the root invoking process leader",
        ));
    }
    let parent_pidfd_inode = descriptor_inode(request.parent_pidfd.as_fd())?;
    if parent_info.pid() == request.activation.connecting_pid()
        && parent_pidfd_inode == request.activation.connecting_pidfd_inode()
    {
        return Err(NamespaceInspectorManagerQuerySessionError::InvalidInput(
            "connector and invoking parent must be independent processes",
        ));
    }

    let service_instance = request.activation.canonical_text();
    let service_unit = contract.service_unit_for_instance(&service_instance)?;
    let parent_control_group = format!("{INSPECTOR_CONTROL_GROUP_PREFIX}{service_unit}");
    let expected = NamespaceInspectorManagerQueryExpectedActivationV1 {
        service_unit_id: &service_unit,
        service_instance: &service_instance,
        parent_pid: parent_info.pid(),
        parent_pidfd_inode,
        parent_control_group: &parent_control_group,
        parent_control_group_id: parent_cgroup_id,
        accept_ordinal: request.activation.accept_ordinal(),
        accepted_socket_cookie: request.activation.socket_cookie(),
        connecting_pid: request.activation.connecting_pid(),
        connecting_pidfd_inode: request.activation.connecting_pidfd_inode(),
        connecting_uid: request.activation.connecting_uid(),
    };

    let (controller, helper_control) = SeqpacketSocket::pair_with_record_subjects()?;
    let control_poll = duplicate_descriptor(controller.as_fd()?)?;
    let helper_parent_pidfd = duplicate_descriptor(request.parent_pidfd.as_fd())?;
    let mut exchange = ManagerQueryExchange::new(
        controller,
        request.protected_contract,
        expected,
        request.nonce,
    );
    let arguments = [];
    let outcome = run_fixed_process_session_from_executable_descriptor(
        FixedProcessSessionRequest {
            process: FixedProcessRequest {
                executable: Path::new(helper),
                arguments: &arguments,
                timeout: MANAGER_QUERY_TIMEOUT,
                maximum_stdout_bytes: MAXIMUM_HELPER_OUTPUT_BYTES,
                maximum_stderr_bytes: MAXIMUM_HELPER_OUTPUT_BYTES,
            },
            stdin: None,
            inherited: vec![request.manager_stream, helper_parent_pidfd, helper_control],
            control: control_poll.as_fd(),
        },
        helper_executable,
        &mut exchange,
    )?;

    qualify_session_outcome(outcome)
}

fn qualify_session_outcome(
    outcome: FixedProcessSessionOutcome<MatchedNamespaceInspectorActivationSnapshotsV1>,
) -> Result<
    MatchedNamespaceInspectorActivationSnapshotsV1,
    NamespaceInspectorManagerQuerySessionError,
> {
    match outcome {
        FixedProcessSessionOutcome::Completed { process, exchange }
            if process.exit_code == Some(0)
                && process.signal.is_none()
                && process.stdout.is_empty()
                && process.stderr.is_empty() =>
        {
            Ok(exchange)
        }
        FixedProcessSessionOutcome::Completed { process, .. }
            if process.exit_code != Some(0) || process.signal.is_some() =>
        {
            Err(NamespaceInspectorManagerQuerySessionError::UnsuccessfulExit)
        }
        FixedProcessSessionOutcome::Completed { .. } => {
            Err(NamespaceInspectorManagerQuerySessionError::UnexpectedOutput)
        }
        FixedProcessSessionOutcome::ChildExitedBeforeExchange(_) => {
            Err(NamespaceInspectorManagerQuerySessionError::ChildExitedBeforeExchange)
        }
        FixedProcessSessionOutcome::TimedOut => {
            Err(NamespaceInspectorManagerQuerySessionError::TimedOut)
        }
        FixedProcessSessionOutcome::OutputLimitExceeded => {
            Err(NamespaceInspectorManagerQuerySessionError::OutputLimitExceeded)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
enum ControlPhase {
    Start = 1,
    SnapshotA = 2,
    Continue = 3,
    SnapshotB = 4,
    Ack = 5,
    Abort = 6,
}

impl ControlPhase {
    fn decode(value: u16) -> Result<Self, ManagerQueryExchangeError> {
        match value {
            1 => Ok(Self::Start),
            2 => Ok(Self::SnapshotA),
            3 => Ok(Self::Continue),
            4 => Ok(Self::SnapshotB),
            5 => Ok(Self::Ack),
            6 => Ok(Self::Abort),
            _ => Err(ManagerQueryExchangeError::InvalidRecord),
        }
    }
}

#[derive(Debug)]
enum ExchangeState {
    SendStart(Vec<u8>),
    AwaitA,
    SendContinue(Vec<u8>),
    AwaitB,
    SendAck {
        record: Vec<u8>,
        matched: Box<MatchedNamespaceInspectorActivationSnapshotsV1>,
    },
    Complete,
}

#[derive(Debug)]
struct ManagerQueryExchange<'a> {
    control: SeqpacketSocket,
    protected_contract: &'a ProtectedNamespaceInspectorDeploymentContractV1,
    expected: NamespaceInspectorManagerQueryExpectedActivationV1<'a>,
    nonce: [u8; 32],
    first: Option<ObservedNamespaceInspectorActivationSnapshotV1>,
    state: ExchangeState,
}

impl<'a> ManagerQueryExchange<'a> {
    fn new(
        control: SeqpacketSocket,
        protected_contract: &'a ProtectedNamespaceInspectorDeploymentContractV1,
        expected: NamespaceInspectorManagerQueryExpectedActivationV1<'a>,
        nonce: [u8; 32],
    ) -> Self {
        Self {
            control,
            protected_contract,
            expected,
            nonce,
            first: None,
            state: ExchangeState::SendStart(Vec::new()),
        }
    }

    fn send_pending(
        &mut self,
        child: &FixedLiveChild<'_>,
    ) -> Result<
        ExchangeStep<MatchedNamespaceInspectorActivationSnapshotsV1>,
        ManagerQueryExchangeError,
    > {
        validate_helper_executable(child, self.protected_contract)?;
        if matches!(self.state, ExchangeState::SendStart(_)) {
            let deadline_ns = u64::try_from(child.deadline().as_nanos())
                .map_err(|_| ManagerQueryExchangeError::InvalidDeadline)?;
            self.state =
                ExchangeState::SendStart(encode_start(self.nonce, deadline_ns, self.expected));
        }

        let record = match &self.state {
            ExchangeState::SendStart(record) | ExchangeState::SendContinue(record) => record,
            ExchangeState::SendAck { record, .. } => record,
            _ => return Err(ManagerQueryExchangeError::InvalidState),
        };
        match self.control.send(record) {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Writable));
            }
            Err(error) => return Err(error.into()),
        }

        match std::mem::replace(&mut self.state, ExchangeState::Complete) {
            ExchangeState::SendStart(_) => {
                self.state = ExchangeState::AwaitA;
                Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
            }
            ExchangeState::SendContinue(_) => {
                self.state = ExchangeState::AwaitB;
                Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
            }
            ExchangeState::SendAck { matched, .. } => Ok(ExchangeStep::Complete(*matched)),
            _ => Err(ManagerQueryExchangeError::InvalidState),
        }
    }

    fn receive_expected(
        &mut self,
        child: &FixedLiveChild<'_>,
        expected_phase: ControlPhase,
    ) -> Result<(), ManagerQueryExchangeError> {
        let record = match self.control.receive(MAXIMUM_CONTROL_RECORD_BYTES) {
            Ok(record) => record,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Err(ManagerQueryExchangeError::RetryRead);
            }
            Err(error) => return Err(error.into()),
        };
        validate_helper_subject(child, record.subject())?;
        let frame = decode_control_record(record.payload())?;
        if frame.phase == ControlPhase::Abort {
            return decode_abort(frame.payload, &self.nonce);
        }
        require_expected_phase(frame.phase, expected_phase)?;
        ensure_no_queued_record(&mut self.control)?;

        let snapshot = decode_snapshot_phase(frame.payload, self.nonce, self.expected)?;
        validate_helper_executable(child, self.protected_contract)?;
        match expected_phase {
            ControlPhase::SnapshotA => {
                self.first = Some(snapshot);
                self.state = ExchangeState::SendContinue(encode_nonce_record(
                    ControlPhase::Continue,
                    self.nonce,
                ));
            }
            ControlPhase::SnapshotB => {
                let first = self
                    .first
                    .take()
                    .ok_or(ManagerQueryExchangeError::InvalidState)?;
                let matched = match_namespace_inspector_activation_snapshots(
                    self.protected_contract,
                    self.expected,
                    first,
                    snapshot,
                )?;
                self.state = ExchangeState::SendAck {
                    record: encode_nonce_record(ControlPhase::Ack, self.nonce),
                    matched: Box::new(matched),
                };
            }
            _ => return Err(ManagerQueryExchangeError::InvalidState),
        }
        Ok(())
    }
}

impl FixedProcessSessionExchange for ManagerQueryExchange<'_> {
    type Output = MatchedNamespaceInspectorActivationSnapshotsV1;
    type Error = ManagerQueryExchangeError;

    fn start(
        &mut self,
        child: &FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
    ) -> Result<ExchangeStep<Self::Output>, Self::Error> {
        self.send_pending(child)
    }

    fn advance(
        &mut self,
        child: &FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
        readiness: FixedProcessControlReadiness,
    ) -> Result<ExchangeStep<Self::Output>, Self::Error> {
        if matches!(
            self.state,
            ExchangeState::SendStart(_)
                | ExchangeState::SendContinue(_)
                | ExchangeState::SendAck { .. }
        ) {
            if !readiness.is_writable() {
                return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Writable));
            }
            return self.send_pending(child);
        }

        if !readiness.is_readable() {
            return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable));
        }
        let phase = match self.state {
            ExchangeState::AwaitA => ControlPhase::SnapshotA,
            ExchangeState::AwaitB => ControlPhase::SnapshotB,
            _ => return Err(ManagerQueryExchangeError::InvalidState),
        };
        match self.receive_expected(child, phase) {
            Ok(()) => Ok(ExchangeStep::Pending(FixedProcessControlInterest::Writable)),
            Err(ManagerQueryExchangeError::RetryRead) => {
                Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
            }
            Err(error) => Err(error),
        }
    }
}

/// Reports one authenticated-control or snapshot-exchange failure.
#[derive(Debug, Error)]
pub(in crate::namespace_inspector) enum ManagerQueryExchangeError {
    #[error(transparent)]
    Seqpacket(#[from] SeqpacketError),
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    #[error(transparent)]
    Snapshot(#[from] NamespaceInspectorManagerQueryError),
    #[error(transparent)]
    ProtectedDeployment(#[from] ProtectedNamespaceInspectorDeploymentContractError),
    #[error("invalid manager-query control record")]
    InvalidRecord,
    #[error("manager-query control record used an unexpected phase")]
    UnexpectedPhase,
    #[error("manager-query exchange entered an invalid state")]
    InvalidState,
    #[error("manager-query helper record did not identify the supervised child")]
    HelperIdentityMismatch,
    #[error("manager-query helper reported ABORT reason {0}")]
    HelperAborted(u32),
    #[error("manager-query control channel queued an unexpected extra record")]
    ExtraRecord,
    #[error("fixed child deadline does not fit the manager-query wire")]
    InvalidDeadline,
    #[error("manager-query receive was interrupted or would block")]
    RetryRead,
}

struct DecodedControlRecord<'a> {
    phase: ControlPhase,
    payload: &'a [u8],
}

fn encode_start(
    nonce: [u8; 32],
    deadline_ns: u64,
    expected: NamespaceInspectorManagerQueryExpectedActivationV1<'_>,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(START_PAYLOAD_BYTES);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&deadline_ns.to_be_bytes());
    payload.extend_from_slice(MANAGER_QUERY_SCHEMA_DIGEST_V1.as_bytes());
    payload.extend_from_slice(&expected.accept_ordinal.to_be_bytes());
    payload.extend_from_slice(&expected.accepted_socket_cookie.to_be_bytes());
    payload.extend_from_slice(&expected.connecting_pid.to_be_bytes());
    payload.extend_from_slice(&expected.connecting_pidfd_inode.to_be_bytes());
    payload.extend_from_slice(&expected.connecting_uid.to_be_bytes());
    debug_assert_eq!(payload.len(), START_PAYLOAD_BYTES);
    encode_control_record(ControlPhase::Start, &payload)
}

fn encode_nonce_record(phase: ControlPhase, nonce: [u8; 32]) -> Vec<u8> {
    encode_control_record(phase, &nonce)
}

fn encode_control_record(phase: ControlPhase, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(CONTROL_HEADER_BYTES + payload.len());
    record.extend_from_slice(CONTROL_MAGIC);
    record.extend_from_slice(&CONTROL_VERSION.to_be_bytes());
    record.extend_from_slice(&(phase as u16).to_be_bytes());
    record.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn decode_control_record(
    record: &[u8],
) -> Result<DecodedControlRecord<'_>, ManagerQueryExchangeError> {
    if record.len() < CONTROL_HEADER_BYTES || &record[..8] != CONTROL_MAGIC {
        return Err(ManagerQueryExchangeError::InvalidRecord);
    }
    let version = u16::from_be_bytes(copy_array(&record[8..10])?);
    let phase = ControlPhase::decode(u16::from_be_bytes(copy_array(&record[10..12])?))?;
    let payload_length = usize::try_from(u32::from_be_bytes(copy_array(&record[12..16])?))
        .map_err(|_| ManagerQueryExchangeError::InvalidRecord)?;
    if version != CONTROL_VERSION
        || payload_length != record.len().saturating_sub(CONTROL_HEADER_BYTES)
    {
        return Err(ManagerQueryExchangeError::InvalidRecord);
    }
    Ok(DecodedControlRecord {
        phase,
        payload: &record[CONTROL_HEADER_BYTES..],
    })
}

fn decode_snapshot_phase(
    payload: &[u8],
    nonce: [u8; 32],
    expected: NamespaceInspectorManagerQueryExpectedActivationV1<'_>,
) -> Result<ObservedNamespaceInspectorActivationSnapshotV1, ManagerQueryExchangeError> {
    if payload.len() < PHASE_BINDING_BYTES
        || payload[..32] != nonce
        || payload[32..64] != *MANAGER_QUERY_SCHEMA_DIGEST_V1.as_bytes()
        || u64::from_be_bytes(copy_array(&payload[64..72])?) != expected.accept_ordinal
        || u64::from_be_bytes(copy_array(&payload[72..80])?) != expected.accepted_socket_cookie
    {
        return Err(ManagerQueryExchangeError::InvalidRecord);
    }
    let snapshot_length = usize::try_from(u32::from_be_bytes(copy_array(&payload[80..84])?))
        .map_err(|_| ManagerQueryExchangeError::InvalidRecord)?;
    if snapshot_length > MAXIMUM_SNAPSHOT_BYTES
        || snapshot_length != payload.len().saturating_sub(PHASE_BINDING_BYTES)
    {
        return Err(ManagerQueryExchangeError::InvalidRecord);
    }
    Ok(
        ObservedNamespaceInspectorActivationSnapshotV1::decode_untrusted(
            &payload[PHASE_BINDING_BYTES..],
        )?,
    )
}

fn decode_abort(payload: &[u8], nonce: &[u8; 32]) -> Result<(), ManagerQueryExchangeError> {
    if payload.len() != ABORT_PAYLOAD_BYTES || payload[..NONCE_PAYLOAD_BYTES] != *nonce {
        return Err(ManagerQueryExchangeError::InvalidRecord);
    }
    let reason = u32::from_be_bytes(copy_array(&payload[NONCE_PAYLOAD_BYTES..])?);
    if reason != 1 {
        return Err(ManagerQueryExchangeError::InvalidRecord);
    }
    Err(ManagerQueryExchangeError::HelperAborted(reason))
}

fn require_expected_phase(
    observed: ControlPhase,
    expected: ControlPhase,
) -> Result<(), ManagerQueryExchangeError> {
    if observed == expected {
        Ok(())
    } else {
        Err(ManagerQueryExchangeError::UnexpectedPhase)
    }
}

fn ensure_no_queued_record(control: &mut SeqpacketSocket) -> Result<(), ManagerQueryExchangeError> {
    for attempt in 0..CONTROL_INTERRUPT_LIMIT {
        match control.receive(MAXIMUM_CONTROL_RECORD_BYTES) {
            Err(SeqpacketError::WouldBlock) => return Ok(()),
            Err(SeqpacketError::Interrupted) if attempt + 1 < CONTROL_INTERRUPT_LIMIT => continue,
            Err(SeqpacketError::Interrupted) => return Err(ManagerQueryExchangeError::RetryRead),
            Ok(_) => return Err(ManagerQueryExchangeError::ExtraRecord),
            Err(error) => return Err(error.into()),
        }
    }
    Err(ManagerQueryExchangeError::RetryRead)
}

fn validate_helper_subject(
    child: &FixedLiveChild<'_>,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(), ManagerQueryExchangeError> {
    let child_info = child.initial_info();
    let subject_info = subject.initial_info();
    let credentials = subject.credentials();
    let Some(child_credentials) = child_info.credentials() else {
        return Err(ManagerQueryExchangeError::HelperIdentityMismatch);
    };
    if credentials.pid().get() != child_info.pid()
        || credentials.uid() != child_credentials.effective_user_id()
        || credentials.gid() != child_credentials.effective_group_id()
        || subject_info != child_info
        || subject.pidfd().info()? != child.pidfd().info()?
        || descriptor_inode(subject.pidfd().as_fd())? != descriptor_inode(child.pidfd().as_fd())?
        || !subject.pidfd().is_alive()?
    {
        return Err(ManagerQueryExchangeError::HelperIdentityMismatch);
    }
    Ok(())
}

fn validate_helper_executable(
    child: &FixedLiveChild<'_>,
    protected_contract: &ProtectedNamespaceInspectorDeploymentContractV1,
) -> Result<(), ManagerQueryExchangeError> {
    let initial = child.initial_info();
    let before = child.pidfd().info()?;
    if before != initial || !child.pidfd().is_alive()? {
        return Err(ManagerQueryExchangeError::HelperIdentityMismatch);
    }

    let first = open_process_executable(before.pid())?;
    protected_contract.verify_artifact_descriptor(
        NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable,
        first.as_fd(),
    )?;

    let middle = child.pidfd().info()?;
    if middle != before || !child.pidfd().is_alive()? {
        return Err(ManagerQueryExchangeError::HelperIdentityMismatch);
    }
    let second = open_process_executable(middle.pid())?;
    protected_contract.verify_artifact_descriptor(
        NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable,
        second.as_fd(),
    )?;

    let after = child.pidfd().info()?;
    if after != middle || !child.pidfd().is_alive()? {
        return Err(ManagerQueryExchangeError::HelperIdentityMismatch);
    }
    Ok(())
}

fn open_process_executable(pid: u32) -> Result<OwnedFd, aos_sandbox_linux::Error> {
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    rustix::fs::open(
        &path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| aos_sandbox_linux::Error::Syscall {
        operation: "open manager-query helper executable",
        source: source.into(),
    })
}

fn descriptor_inode(descriptor: BorrowedFd<'_>) -> Result<u64, aos_sandbox_linux::Error> {
    let status =
        rustix::fs::fstat(descriptor).map_err(|source| aos_sandbox_linux::Error::Syscall {
            operation: "inspect manager-query descriptor inode",
            source: source.into(),
        })?;
    Ok(status.st_ino)
}

fn duplicate_descriptor(descriptor: BorrowedFd<'_>) -> Result<OwnedFd, aos_sandbox_linux::Error> {
    rustix::io::fcntl_dupfd_cloexec(descriptor, 0).map_err(|source| {
        aos_sandbox_linux::Error::Syscall {
            operation: "duplicate manager-query descriptor",
            source: source.into(),
        }
    })
}

fn copy_array<const SIZE: usize>(bytes: &[u8]) -> Result<[u8; SIZE], ManagerQueryExchangeError> {
    bytes
        .try_into()
        .map_err(|_| ManagerQueryExchangeError::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_inspector::launch_contract::{
        ProtectedNamespaceInspectorDeploymentContractV1, tests::contract,
    };
    use crate::namespace_inspector::manager_query::codec::test_properties;
    use crate::namespace_inspector::manager_query::{
        CanonicalManagerPropertyValueV1, MANAGER_PROPERTY_TABLE_V1, ManagerPropertyObservationV1,
    };
    use aos_sandbox_linux::process::FixedProcessOutput;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn activation() -> NamespaceInspectorManagerQueryExpectedActivationV1<'static> {
        NamespaceInspectorManagerQueryExpectedActivationV1 {
            service_unit_id: "aos-sandbox-network-namespace-inspector@7-311-411_511-0.service",
            service_instance: "7-311-411_511-0",
            parent_pid: 113,
            parent_pidfd_inode: 613,
            parent_control_group: "/aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@7-311-411_511-0.service",
            parent_control_group_id: 211,
            accept_ordinal: 7,
            accepted_socket_cookie: 311,
            connecting_pid: 411,
            connecting_pidfd_inode: 511,
            connecting_uid: 0,
        }
    }

    fn snapshot_for(
        expected: NamespaceInspectorManagerQueryExpectedActivationV1<'_>,
    ) -> ObservedNamespaceInspectorActivationSnapshotV1 {
        let mut properties = test_properties(false);
        properties[1] = ManagerPropertyObservationV1 {
            descriptor_id: 1,
            value: CanonicalManagerPropertyValueV1::Scalar(
                expected.service_unit_id.as_bytes().to_vec(),
            ),
        };
        properties[17] = ManagerPropertyObservationV1 {
            descriptor_id: 17,
            value: CanonicalManagerPropertyValueV1::Scalar(
                expected.parent_control_group.as_bytes().to_vec(),
            ),
        };
        properties[18] = ManagerPropertyObservationV1 {
            descriptor_id: 18,
            value: CanonicalManagerPropertyValueV1::Scalar(
                expected.parent_control_group_id.to_le_bytes().to_vec(),
            ),
        };
        properties[24] = ManagerPropertyObservationV1 {
            descriptor_id: 24,
            value: CanonicalManagerPropertyValueV1::Scalar(
                expected.parent_pid.to_le_bytes().to_vec(),
            ),
        };
        ObservedNamespaceInspectorActivationSnapshotV1 {
            query_schema_digest: MANAGER_QUERY_SCHEMA_DIGEST_V1,
            service_unit_id: expected.service_unit_id.to_owned(),
            service_instance: expected.service_instance.to_owned(),
            invocation_id: [3; 16],
            main_pid: expected.parent_pid,
            control_group: expected.parent_control_group.to_owned(),
            control_group_id: expected.parent_control_group_id,
            accept_ordinal: expected.accept_ordinal,
            accepted_socket_cookie: expected.accepted_socket_cookie,
            connecting_pid: expected.connecting_pid,
            connecting_pidfd_inode: expected.connecting_pidfd_inode,
            connecting_uid: expected.connecting_uid,
            properties,
        }
    }

    fn snapshot() -> ObservedNamespaceInspectorActivationSnapshotV1 {
        snapshot_for(activation())
    }

    fn protected_contract() -> ProtectedNamespaceInspectorDeploymentContractV1 {
        ProtectedNamespaceInspectorDeploymentContractV1::for_test(contract()).unwrap()
    }

    #[test]
    fn helper_pathname_substitution_preserves_descriptor_but_fails_revalidation() {
        let directory = tempfile::tempdir().unwrap();
        let helper = directory.path().join("manager-query-helper");
        let substitute = directory.path().join("substitute-helper");
        let current_executable = std::env::current_exe().unwrap();
        std::fs::copy(&current_executable, &helper).unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o555)).unwrap();
        let protected = ProtectedNamespaceInspectorDeploymentContractV1::for_test_with_helper(
            contract(),
            &helper,
        )
        .unwrap();
        let retained = protected
            .duplicate_artifact(NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable)
            .unwrap();
        let retained_status = rustix::fs::fstat(retained.as_fd()).unwrap();

        std::fs::write(&substitute, b"hostile replacement").unwrap();
        std::fs::set_permissions(&substitute, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::rename(substitute, &helper).unwrap();
        let replacement_status = std::fs::metadata(&helper).unwrap();

        assert_ne!(
            (retained_status.st_dev, retained_status.st_ino),
            (replacement_status.dev(), replacement_status.ino())
        );
        assert!(matches!(
            protected.verify_artifact_descriptor(
                NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable,
                retained.as_fd(),
            ),
            Err(ProtectedNamespaceInspectorDeploymentContractError::Mismatch)
        ));
    }

    fn snapshot_phase(snapshot: &ObservedNamespaceInspectorActivationSnapshotV1) -> Vec<u8> {
        let expected = activation();
        let snapshot = snapshot.encode().unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&[7; 32]);
        payload.extend_from_slice(MANAGER_QUERY_SCHEMA_DIGEST_V1.as_bytes());
        payload.extend_from_slice(&expected.accept_ordinal.to_be_bytes());
        payload.extend_from_slice(&expected.accepted_socket_cookie.to_be_bytes());
        payload.extend_from_slice(&(snapshot.len() as u32).to_be_bytes());
        payload.extend_from_slice(&snapshot);
        payload
    }

    #[test]
    fn start_wire_is_exact_and_binds_connector_not_parent() {
        let expected = activation();
        let record = encode_start([7; 32], 0x0102_0304_0506_0708, expected);

        assert_eq!(&record[..8], CONTROL_MAGIC);
        assert_eq!(&record[8..10], &1_u16.to_be_bytes());
        assert_eq!(&record[10..12], &(ControlPhase::Start as u16).to_be_bytes());
        assert_eq!(&record[12..16], &(104_u32).to_be_bytes());
        assert_eq!(&record[16..48], &[7; 32]);
        assert_eq!(&record[48..56], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(&record[56..88], MANAGER_QUERY_SCHEMA_DIGEST_V1.as_bytes());
        assert_eq!(&record[88..96], &7_u64.to_be_bytes());
        assert_eq!(&record[96..104], &311_u64.to_be_bytes());
        assert_eq!(&record[104..108], &411_u32.to_be_bytes());
        assert_eq!(&record[108..116], &511_u64.to_be_bytes());
        assert_eq!(&record[116..120], &0_u32.to_be_bytes());
        assert_ne!(expected.parent_pid, expected.connecting_pid);
        assert_ne!(expected.parent_pidfd_inode, expected.connecting_pidfd_inode);
    }

    #[test]
    fn nonce_records_and_abort_are_exact() {
        for phase in [ControlPhase::Continue, ControlPhase::Ack] {
            let record = encode_nonce_record(phase, [9; 32]);
            assert_eq!(record.len(), CONTROL_HEADER_BYTES + NONCE_PAYLOAD_BYTES);
            assert_eq!(&record[16..], &[9; 32]);
        }

        let mut abort = [0_u8; ABORT_PAYLOAD_BYTES];
        abort[..32].copy_from_slice(&[9; 32]);
        abort[32..].copy_from_slice(&1_u32.to_be_bytes());
        assert!(matches!(
            decode_abort(&abort, &[9; 32]),
            Err(ManagerQueryExchangeError::HelperAborted(1))
        ));
        abort[0] ^= 1;
        assert!(matches!(
            decode_abort(&abort, &[9; 32]),
            Err(ManagerQueryExchangeError::InvalidRecord)
        ));
        abort[0] ^= 1;
        abort[35] = 2;
        assert!(matches!(
            decode_abort(&abort, &[9; 32]),
            Err(ManagerQueryExchangeError::InvalidRecord)
        ));
    }

    #[test]
    fn control_header_rejects_malformed_and_trailing_lengths() {
        let valid = encode_nonce_record(ControlPhase::Ack, [1; 32]);
        for mut invalid in [
            valid[..15].to_vec(),
            {
                let mut bytes = valid.clone();
                bytes[0] ^= 1;
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes[9] = 2;
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes[11] = 99;
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes[15] -= 1;
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes.push(0);
                bytes
            },
        ] {
            assert!(matches!(
                decode_control_record(&invalid),
                Err(ManagerQueryExchangeError::InvalidRecord)
            ));
            invalid.clear();
        }
    }

    #[test]
    fn early_snapshot_b_and_an_extra_record_are_rejected() {
        assert!(matches!(
            require_expected_phase(ControlPhase::SnapshotB, ControlPhase::SnapshotA),
            Err(ManagerQueryExchangeError::UnexpectedPhase)
        ));

        let (mut controller, peer) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let mut peer = SeqpacketSocket::from_owned(peer).unwrap();
        peer.send(b"extra").unwrap();

        assert!(matches!(
            ensure_no_queued_record(&mut controller),
            Err(ManagerQueryExchangeError::ExtraRecord)
        ));
    }

    #[test]
    fn snapshot_phase_rejects_wrong_binding_and_lengths() {
        let expected = activation();
        let valid = snapshot_phase(&snapshot());
        assert!(decode_snapshot_phase(&valid, [7; 32], expected).is_ok());

        for offset in [0, 32, 64, 72] {
            let mut invalid = valid.clone();
            invalid[offset] ^= 1;
            assert!(decode_snapshot_phase(&invalid, [7; 32], expected).is_err());
        }
        let mut invalid = valid.clone();
        invalid[83] = invalid[83].wrapping_sub(1);
        assert!(decode_snapshot_phase(&invalid, [7; 32], expected).is_err());
        let mut invalid = valid;
        invalid.push(0);
        assert!(decode_snapshot_phase(&invalid, [7; 32], expected).is_err());
    }

    #[test]
    fn matched_token_requires_distinct_parent_connector_and_exact_bindings() {
        let protected = protected_contract();
        let first = snapshot();
        assert_ne!(
            protected.digest().as_bytes(),
            MANAGER_QUERY_SCHEMA_DIGEST_V1.as_bytes()
        );
        let matched = match_namespace_inspector_activation_snapshots(
            &protected,
            activation(),
            first.clone(),
            first.clone(),
        )
        .unwrap();
        assert_eq!(matched.deployment_digest(), protected.digest());
        assert_eq!(matched.parent_pidfd_inode(), 613);
        assert_eq!(matched.snapshot(), &first);

        let mut cases = Vec::new();
        let mut equal_forged = activation();
        equal_forged.connecting_pid = equal_forged.parent_pid;
        equal_forged.connecting_pidfd_inode = equal_forged.parent_pidfd_inode;
        cases.push(equal_forged);

        let mut swapped = activation();
        std::mem::swap(&mut swapped.connecting_pid, &mut swapped.parent_pid);
        std::mem::swap(
            &mut swapped.connecting_pidfd_inode,
            &mut swapped.parent_pidfd_inode,
        );
        cases.push(swapped);

        let mut wrong_parent = activation();
        wrong_parent.parent_pid += 1;
        cases.push(wrong_parent);

        let mut wrong_connector = activation();
        wrong_connector.connecting_pid += 1;
        cases.push(wrong_connector);

        let mut wrong_connector_inode = activation();
        wrong_connector_inode.connecting_pidfd_inode += 1;
        cases.push(wrong_connector_inode);

        let mut wrong_service = activation();
        wrong_service.service_unit_id = "aos-sandbox-network-namespace-inspector@wrong.service";
        cases.push(wrong_service);

        let mut wrong_instance = activation();
        wrong_instance.service_instance = "07-311-411_511-0";
        cases.push(wrong_instance);

        let mut wrong_cgroup = activation();
        wrong_cgroup.parent_control_group = "/aos.slice/aos-control.slice/wrong.service";
        cases.push(wrong_cgroup);

        for expected in cases {
            assert_eq!(
                match_namespace_inspector_activation_snapshots(
                    &protected,
                    expected,
                    first.clone(),
                    first.clone(),
                ),
                Err(NamespaceInspectorManagerQueryError::ActivationBindingMismatch)
            );
        }

        for expected in [
            NamespaceInspectorManagerQueryExpectedActivationV1 {
                service_unit_id: "aos-sandbox-network-namespace-inspector@7-311-113_511-0.service",
                service_instance: "7-311-113_511-0",
                parent_control_group: "/aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@7-311-113_511-0.service",
                connecting_pid: 113,
                ..activation()
            },
            NamespaceInspectorManagerQueryExpectedActivationV1 {
                service_unit_id: "aos-sandbox-network-namespace-inspector@7-311-411_613-0.service",
                service_instance: "7-311-411_613-0",
                parent_control_group: "/aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@7-311-411_613-0.service",
                connecting_pidfd_inode: 613,
                ..activation()
            },
        ] {
            let observed = snapshot_for(expected);

            match_namespace_inspector_activation_snapshots(
                &protected,
                expected,
                observed.clone(),
                observed,
            )
            .unwrap();
        }
    }

    #[test]
    fn separate_queries_expose_changed_inspector_invocation_and_socket_state() {
        let protected = protected_contract();
        let original = snapshot();
        let before = match_namespace_inspector_activation_snapshots(
            &protected,
            activation(),
            original.clone(),
            original.clone(),
        )
        .unwrap();

        let mut restarted = original.clone();
        restarted.invocation_id = [4; 16];
        restarted.properties[14] = ManagerPropertyObservationV1 {
            descriptor_id: 14,
            value: CanonicalManagerPropertyValueV1::Scalar(restarted.invocation_id.to_vec()),
        };
        let after_restart = match_namespace_inspector_activation_snapshots(
            &protected,
            activation(),
            restarted.clone(),
            restarted,
        )
        .unwrap();
        assert_ne!(before, after_restart);

        let mut changed_socket = original;
        changed_socket.properties[121] = ManagerPropertyObservationV1 {
            descriptor_id: 121,
            value: CanonicalManagerPropertyValueV1::Scalar(1_u32.to_le_bytes().to_vec()),
        };
        let after_socket_change = match_namespace_inspector_activation_snapshots(
            &protected,
            activation(),
            changed_socket.clone(),
            changed_socket,
        )
        .unwrap();
        assert_ne!(before, after_socket_change);
    }

    #[test]
    fn snapshot_schema_digest_cannot_be_replaced_by_deployment_digest() {
        let protected = protected_contract();
        let mut observed = snapshot();
        observed.query_schema_digest =
            super::super::NamespaceInspectorManagerQuerySchemaDigestV1::from_bytes(
                *protected.digest().as_bytes(),
            );

        assert_eq!(
            observed.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidSnapshot)
        );
    }

    #[test]
    fn matcher_rejects_a_b_and_static_projection_drift() {
        let protected = protected_contract();
        let first = snapshot();
        let mut second = first.clone();
        second.invocation_id[0] ^= 1;
        second.properties[14].value =
            CanonicalManagerPropertyValueV1::Scalar(second.invocation_id.to_vec());
        assert_eq!(
            match_namespace_inspector_activation_snapshots(
                &protected,
                activation(),
                first.clone(),
                second,
            ),
            Err(NamespaceInspectorManagerQueryError::SnapshotMismatch)
        );

        let mut first = first;
        let static_index = MANAGER_PROPERTY_TABLE_V1
            .iter()
            .position(|descriptor| {
                descriptor.binding == super::super::ManagerPropertyBindingV1::StaticContract
            })
            .unwrap();
        first.properties[static_index].value =
            CanonicalManagerPropertyValueV1::Scalar(b"forged".to_vec());
        assert_eq!(
            match_namespace_inspector_activation_snapshots(
                &protected,
                activation(),
                first.clone(),
                first,
            ),
            Err(NamespaceInspectorManagerQueryError::StaticPropertyMismatch)
        );
    }

    #[test]
    fn matcher_rejects_manager_environment_outside_the_protected_allowlist() {
        let protected = protected_contract();
        let mut observed = snapshot();
        observed.properties[0].value =
            CanonicalManagerPropertyValueV1::UnorderedSet(vec![b"HOME=/root".to_vec()]);

        assert_eq!(
            match_namespace_inspector_activation_snapshots(
                &protected,
                activation(),
                observed.clone(),
                observed,
            ),
            Err(NamespaceInspectorManagerQueryError::StaticPropertyMismatch)
        );
    }

    #[test]
    fn outcome_adapter_rejects_every_incomplete_or_noisy_completion() {
        fn output(
            exit_code: Option<i32>,
            signal: Option<i32>,
            stdout: &[u8],
            stderr: &[u8],
        ) -> FixedProcessOutput {
            FixedProcessOutput {
                exit_code,
                signal,
                stdout: stdout.to_vec(),
                stderr: stderr.to_vec(),
            }
        }

        let token = || {
            let protected = protected_contract();
            let observed = snapshot();
            match_namespace_inspector_activation_snapshots(
                &protected,
                activation(),
                observed.clone(),
                observed,
            )
            .unwrap()
        };

        assert!(
            qualify_session_outcome(FixedProcessSessionOutcome::Completed {
                process: output(Some(0), None, &[], &[]),
                exchange: token(),
            })
            .is_ok()
        );
        for outcome in [
            FixedProcessSessionOutcome::ChildExitedBeforeExchange(output(Some(0), None, &[], &[])),
            FixedProcessSessionOutcome::TimedOut,
            FixedProcessSessionOutcome::OutputLimitExceeded,
        ] {
            assert!(qualify_session_outcome(outcome).is_err());
        }
        for process in [
            output(Some(1), None, &[], &[]),
            output(None, Some(9), &[], &[]),
            output(Some(0), None, b"stdout", &[]),
            output(Some(0), None, &[], b"stderr"),
        ] {
            assert!(
                qualify_session_outcome(FixedProcessSessionOutcome::Completed {
                    process,
                    exchange: token(),
                })
                .is_err()
            );
        }
    }
}
