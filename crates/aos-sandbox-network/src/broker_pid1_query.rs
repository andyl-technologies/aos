//! Bounded PID 1 readback for one retained Network service pidfd.
//!
//! This does not grant Apply authority. It observes a unit through a direct
//! authenticated PID 1 stream, then binds two identical observations to the
//! retained pidfd and, for an inspector, the kernel subject of an SCM record.
//! The namespace inspector reuses the worker exchange with its separately
//! pinned helper mode, which admits its exact CAP_SYS_PTRACE bounding set.
//! The V3 helper also rejects loader-input environment and noncanonical unit
//! definitions in each snapshot. The signed inventory and ELF closure still
//! need enforcing MAC and runtime binding before this can replace direct checks.
//!
//! ```text
//! AOSNIBQ3 frame = magic[8] || version:u16 || phase:u16 || length:u32 || payload
//! snapshot payload = V2 launch fields || loader-and-unit-gate:u8 (exactly 1)
//! ```

use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;
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
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use thiserror::Error;

use crate::inspector_deployment::{InspectorDeploymentErrorV2, ProtectedInspectorDeploymentV2};

const MAGIC: &[u8; 8] = b"AOSNIBQ3";
const VERSION: u16 = 3;
const HEADER: usize = 16;
const MAX_RECORD: usize = 8192;
/// Caps one signed PID 1 service query independently of its caller's attempt.
pub(crate) const PID1_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Selects the exact service role queried through PID 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BrokerPid1ServiceRoleV2 {
    /// Queries a socket-activated namespace inspector and requires SCM evidence.
    Inspector = 1,
    /// Queries a one-shot lifecycle worker whose launcher retains its pidfd.
    LifecycleWorker = 2,
}

/// Supplies a retained subject and the exact expected unit and invocation.
#[derive(Debug)]
pub struct BrokerPid1QueryRequestV2<'a> {
    /// Holds the broker's signed and pinned executable inventory.
    pub deployment: &'a ProtectedInspectorDeploymentV2,
    /// Pins the process handed to PID 1 through `GetUnitByPIDFD`.
    pub subject: &'a PidFd,
    /// Binds an inspector response to its kernel-checked SCM record subject.
    pub inspector_record_subject: Option<&'a KernelAuthorizedRecordSubject>,
    /// Selects the unit type and exact signed launch policy.
    pub role: BrokerPid1ServiceRoleV2,
    /// Names the exact `.service` instance expected from PID 1.
    pub unit: &'a str,
}

/// Retains a fully matched pair of fresh PID 1 observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerPid1ServiceObservationV2 {
    /// The exact service unit returned by `GetUnitByPIDFD` and `Unit.Id`.
    pub unit: String,
    /// The nonzero invocation ID returned by PID 1.
    pub invocation_id: [u8; 16],
    /// The PID 1 `Service.MainPID` bound to the retained pidfd.
    pub main_pid: u32,
    /// The PID 1 `Service.ControlGroupId` bound to the retained pidfd.
    pub control_group_id: u64,
    /// The exact PID 1 service cgroup path.
    pub control_group: String,
    /// The PID 1 unit fragment path matched to the signed, pinned fragment.
    pub fragment_path: String,
    /// The signed `ExecStart` executable path.
    pub executable: String,
    /// The complete signed `ExecStart` argument vector.
    pub arguments: Vec<String>,
}

/// Keeps one matched PID 1 readback attached to its exact retained subject.
#[derive(Debug)]
pub struct BrokerPid1ServiceReadbackV2 {
    observation: BrokerPid1ServiceObservationV2,
    subject: PidFd,
}

impl BrokerPid1ServiceReadbackV2 {
    /// Borrows the matched unit properties without granting effect authority.
    #[must_use]
    pub const fn observation(&self) -> &BrokerPid1ServiceObservationV2 {
        &self.observation
    }

    /// Borrows the same kernel process object queried by PID 1.
    #[must_use]
    pub const fn subject(&self) -> &PidFd {
        &self.subject
    }
}

/// Retains one service observation and its exact signed deployment for requery.
///
/// This is an observation owner, not an Apply authorization. A later effect
/// boundary must invoke [`Self::requery_at_effect_boundary`] immediately before
/// dispatch; the initial PID 1 result cannot be reused as a currentness proof.
#[derive(Debug)]
pub struct BrokerPid1ServiceBindingV3<'a> {
    deployment: &'a ProtectedInspectorDeploymentV2,
    role: BrokerPid1ServiceRoleV2,
    unit: String,
    initial: BrokerPid1ServiceReadbackV2,
}

/// Distinguishes a completed V3 readback from inventory-only startup.
///
/// `Unavailable` carries no observation and must never be accepted as an
/// effect-boundary proof. It exists only so inventory service can continue
/// while Network Apply remains independently closed.
#[must_use = "an unavailable PID 1 readback does not prove a service boundary"]
#[derive(Debug)]
pub enum BrokerPid1ServiceStateV3<'a> {
    /// No protected V3 deployment was installed, so no query was performed.
    Unavailable,
    /// PID 1 matched a live process and the signed V3 service payload.
    Observed(BrokerPid1ServiceBindingV3<'a>),
}

impl<'a> BrokerPid1ServiceStateV3<'a> {
    /// Observes a service only when a protected V3 deployment is present.
    ///
    /// # Errors
    ///
    /// Rejects a present but incomplete V2/V3 deployment or any failed PID 1
    /// query. Absence is represented only by [`Self::Unavailable`].
    pub fn observe_optional(
        deployment: Option<&'a ProtectedInspectorDeploymentV2>,
        subject: &PidFd,
        inspector_record_subject: Option<&KernelAuthorizedRecordSubject>,
        role: BrokerPid1ServiceRoleV2,
        unit: &str,
    ) -> Result<Self, BrokerPid1QueryErrorV2> {
        let Some(deployment) = deployment else {
            return Ok(Self::Unavailable);
        };
        BrokerPid1ServiceBindingV3::observe(
            deployment,
            subject,
            inspector_record_subject,
            role,
            unit,
        )
        .map(Self::Observed)
    }

    /// Requires an installed, observed V3 service before an effect is sent.
    ///
    /// # Errors
    ///
    /// Returns an unavailable error when startup had no protected V3
    /// deployment and therefore performed no PID 1 query.
    pub fn require_effect_readback(
        self,
    ) -> Result<BrokerPid1ServiceBindingV3<'a>, BrokerPid1QueryErrorV2> {
        match self {
            Self::Unavailable => Err(BrokerPid1QueryErrorV2::Unavailable),
            Self::Observed(binding) => Ok(binding),
        }
    }
}

impl<'a> BrokerPid1ServiceBindingV3<'a> {
    /// Observes one retained service through the broker's protected V3 policy.
    ///
    /// # Errors
    ///
    /// Rejects an absent or changed signed deployment, PID 1 mismatch, expired
    /// query, or record subject that does not name the queried inspector.
    pub fn observe(
        deployment: &'a ProtectedInspectorDeploymentV2,
        subject: &PidFd,
        inspector_record_subject: Option<&KernelAuthorizedRecordSubject>,
        role: BrokerPid1ServiceRoleV2,
        unit: &str,
    ) -> Result<Self, BrokerPid1QueryErrorV2> {
        let initial = query_broker_pid1_service(BrokerPid1QueryRequestV2 {
            deployment,
            subject,
            inspector_record_subject,
            role,
            unit,
        })?;
        Ok(Self {
            deployment,
            role,
            unit: unit.to_owned(),
            initial,
        })
    }

    /// Borrows the initial readback for correlation, without granting authority.
    #[must_use]
    pub const fn initial(&self) -> &BrokerPid1ServiceReadbackV2 {
        &self.initial
    }

    /// Requeries PID 1 with a fresh nonce and rejects any changed service.
    ///
    /// This reuses the same retained subject and protected signer generation.
    /// A new invocation, unit payload, pidfd identity, or failed deployment
    /// revalidation closes the boundary rather than updating the baseline.
    ///
    /// # Errors
    ///
    /// Rejects a changed or unavailable deployment, process, invocation,
    /// complete service payload, or inspector record subject.
    pub fn requery_at_effect_boundary(
        &self,
        inspector_record_subject: Option<&KernelAuthorizedRecordSubject>,
    ) -> Result<(), BrokerPid1QueryErrorV2> {
        let fresh = query_broker_pid1_service(BrokerPid1QueryRequestV2 {
            deployment: self.deployment,
            subject: self.initial.subject(),
            inspector_record_subject,
            role: self.role,
            unit: &self.unit,
        })?;
        require_same_readback(&self.initial, &fresh)
    }
}

/// Rejects any changed PID 1 payload or retained process identity.
///
/// # Errors
///
/// Returns an error when the observations or retained pidfds differ, or when
/// either pidfd can no longer be verified as live.
pub(crate) fn require_same_readback(
    initial: &BrokerPid1ServiceReadbackV2,
    fresh: &BrokerPid1ServiceReadbackV2,
) -> Result<(), BrokerPid1QueryErrorV2> {
    if initial.observation != fresh.observation
        || initial.subject.info()? != fresh.subject.info()?
        || descriptor_inode(initial.subject.as_fd())? != descriptor_inode(fresh.subject.as_fd())?
        || !initial.subject.is_alive()?
        || !fresh.subject.is_alive()?
    {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }
    Ok(())
}

/// Reports a closed broker-to-PID-1 query failure.
#[derive(Debug, Error)]
pub enum BrokerPid1QueryErrorV2 {
    /// No protected V3 deployment was installed for an effect-boundary query.
    #[error("broker PID 1 service readback is unavailable")]
    Unavailable,
    /// An input, record, or observed role binding did not match.
    #[error("broker PID 1 query binding is invalid")]
    Invalid,
    /// The signed inventory failed revalidation.
    #[error(transparent)]
    Deployment(#[from] InspectorDeploymentErrorV2),
    /// The retained Linux descriptor operation failed.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// The authenticated record transport failed.
    #[error(transparent)]
    Seqpacket(#[from] SeqpacketError),
    /// The supervised fixed-process session failed.
    #[error(transparent)]
    Session(#[from] FixedProcessSessionError<QueryExchangeError>),
}

/// Queries PID 1 twice, accepting only an exact, live pidfd-bound match.
///
/// The returned observation is not permission to enable Apply. In particular,
/// the worker caller must independently bind `subject` to its fixed child,
/// and a later namespace-effect boundary must make a fresh currentness check.
/// A V2-only deployment without the separately signed V3 launch policy is
/// rejected before opening the PID 1 stream.
///
/// # Errors
///
/// Returns an error for missing SCM identity, PID 1 authentication failure,
/// changed deployment, malformed or contradictory observations, helper failure,
/// or expiration of the shared deadline.
pub fn query_broker_pid1_service(
    request: BrokerPid1QueryRequestV2<'_>,
) -> Result<BrokerPid1ServiceReadbackV2, BrokerPid1QueryErrorV2> {
    let (helper_path, helper_executable) = request.deployment.broker_query_helper()?;
    query_pid1_service_with_helper(request, &helper_path, helper_executable, PID1_QUERY_TIMEOUT)
}

/// Runs the same signed PID 1 query with a separately pinned helper binary.
///
/// The namespace inspector uses its V1 protected helper executable in worker
/// mode because its CAP_SYS_PTRACE bounding set differs from the broker's.
/// The caller must derive both arguments from one retained protected contract.
/// Its timeout may only shorten the helper's fixed two-second maximum.
///
/// # Errors
///
/// Rejects an invalid signed launch, helper session, PID 1 response, or live
/// process identity.
pub(crate) fn query_pid1_service_with_helper(
    request: BrokerPid1QueryRequestV2<'_>,
    helper_path: &str,
    helper_executable: OwnedFd,
    timeout: Duration,
) -> Result<BrokerPid1ServiceReadbackV2, BrokerPid1QueryErrorV2> {
    if timeout.is_zero() || timeout > PID1_QUERY_TIMEOUT {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }
    let inspector = request.role == BrokerPid1ServiceRoleV2::Inspector;
    let launch = request.deployment.service_launch(inspector)?;
    let prefix = launch
        .unit_template()
        .strip_suffix(".service")
        .ok_or(BrokerPid1QueryErrorV2::Invalid)?;
    if !request.unit.starts_with(prefix)
        || !request.unit.ends_with(".service")
        || request.unit.len() <= prefix.len() + ".service".len()
        || request.unit.len() > 192
    {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }

    let executable = request.deployment.service_executable(inspector)?;
    if launch.arguments().first().map(String::as_str) != Some(executable) {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }
    if inspector != request.inspector_record_subject.is_some() {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }

    let subject_info = request.subject.info()?;
    let credentials = subject_info
        .credentials()
        .ok_or(BrokerPid1QueryErrorV2::Invalid)?;
    let cgroup_id = subject_info
        .cgroup_id()
        .filter(|id| *id != 0)
        .ok_or(BrokerPid1QueryErrorV2::Invalid)?;
    let subject_inode = descriptor_inode(request.subject.as_fd())?;
    if subject_info.pid() == 0
        || subject_info.pid() != subject_info.thread_group_id()
        || credentials.effective_user_id() != 0
        || !request.subject.is_alive()?
    {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }
    if let Some(record) = request.inspector_record_subject {
        if record.initial_info() != subject_info
            || record.pidfd().info()? != subject_info
            || descriptor_inode(record.pidfd().as_fd())? != subject_inode
            || record.credentials().pid().get() != subject_info.pid()
            || record.credentials().uid() != credentials.effective_user_id()
            || record.credentials().gid() != credentials.effective_group_id()
            || !record.pidfd().is_alive()?
        {
            return Err(BrokerPid1QueryErrorV2::Invalid);
        }
    }

    let manager = RetainedUnixStream::connect(Path::new("/run/systemd/private"))?;
    let peer = manager.peer();
    if peer.credentials().pid().get() != 1
        || peer.credentials().uid() != 0
        || peer.credentials().gid() != 0
        || peer.initial_info().pid() != 1
        || !peer.is_alive()?
    {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }

    let manager_fd = duplicate(manager.as_fd())?;
    let self_pid = NonZeroU32::new(std::process::id()).ok_or(BrokerPid1QueryErrorV2::Invalid)?;
    let parent = PidFd::open(self_pid)?;
    let parent_fd = duplicate(parent.as_fd())?;
    let target_fd = duplicate(request.subject.as_fd())?;
    let (control, child_control) = SeqpacketSocket::pair_with_record_subjects()?;
    let control_poll = duplicate(control.as_fd()?)?;
    let mut exchange = QueryExchange {
        control,
        nonce: random_nonce()?,
        subject_pid: subject_info.pid(),
        subject_inode,
        cgroup_id,
        role: request.role,
        unit: request.unit,
        executable,
        expected_fragment_path: launch.fragment_path(),
        expected_arguments: launch.arguments(),
        state: ExchangeState::Start,
        first: None,
    };
    let outcome = run_fixed_process_session_from_executable_descriptor(
        FixedProcessSessionRequest {
            process: FixedProcessRequest {
                executable: Path::new(helper_path),
                arguments: &[],
                timeout,
                maximum_stdout_bytes: 4096,
                maximum_stderr_bytes: 4096,
            },
            stdin: None,
            inherited: vec![manager_fd, parent_fd, child_control, target_fd],
            control: control_poll.as_fd(),
        },
        helper_executable,
        &mut exchange,
    )?;
    let observation = match outcome {
        FixedProcessSessionOutcome::Completed { process, exchange }
            if process.exit_code == Some(0)
                && process.signal.is_none()
                && process.stdout.is_empty()
                && process.stderr.is_empty() =>
        {
            exchange
        }
        _ => return Err(BrokerPid1QueryErrorV2::Invalid),
    };
    if request.subject.info()? != subject_info || !request.subject.is_alive()? {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }
    if let Some(record) = request.inspector_record_subject {
        if record.pidfd().info()? != subject_info || !record.pidfd().is_alive()? {
            return Err(BrokerPid1QueryErrorV2::Invalid);
        }
    }
    request.deployment.service_launch(inspector)?;
    let retained_subject = PidFd::from_owned(duplicate(request.subject.as_fd())?)?;
    if retained_subject.info()? != subject_info
        || descriptor_inode(retained_subject.as_fd())? != subject_inode
    {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }
    Ok(BrokerPid1ServiceReadbackV2 {
        observation,
        subject: retained_subject,
    })
}

#[derive(Debug, Error)]
#[error("invalid authenticated broker query exchange")]
pub struct QueryExchangeError;

#[derive(Debug)]
enum ExchangeState {
    Start,
    AwaitA,
    Continue,
    AwaitB,
    Ack(BrokerPid1ServiceObservationV2),
    Done,
}

struct QueryExchange<'a> {
    control: SeqpacketSocket,
    nonce: [u8; 32],
    subject_pid: u32,
    subject_inode: u64,
    cgroup_id: u64,
    role: BrokerPid1ServiceRoleV2,
    unit: &'a str,
    executable: &'a str,
    expected_fragment_path: &'a str,
    expected_arguments: &'a [String],
    state: ExchangeState,
    first: Option<BrokerPid1ServiceObservationV2>,
}

impl QueryExchange<'_> {
    fn send(
        &mut self,
        child: &FixedLiveChild<'_>,
    ) -> Result<ExchangeStep<BrokerPid1ServiceObservationV2>, QueryExchangeError> {
        let (phase, payload) = match &self.state {
            ExchangeState::Start => {
                let deadline =
                    u64::try_from(child.deadline().as_nanos()).map_err(|_| QueryExchangeError)?;
                let mut payload = Vec::with_capacity(66 + self.unit.len() + self.executable.len());
                payload.extend_from_slice(&self.nonce);
                payload.extend_from_slice(&deadline.to_be_bytes());
                payload.extend_from_slice(&self.subject_pid.to_be_bytes());
                payload.extend_from_slice(&self.subject_inode.to_be_bytes());
                payload.extend_from_slice(&self.cgroup_id.to_be_bytes());
                payload.push(self.role as u8);
                payload.push(0);
                payload.extend_from_slice(
                    &u16::try_from(self.unit.len())
                        .map_err(|_| QueryExchangeError)?
                        .to_be_bytes(),
                );
                payload.extend_from_slice(
                    &u16::try_from(self.executable.len())
                        .map_err(|_| QueryExchangeError)?
                        .to_be_bytes(),
                );
                payload.extend_from_slice(self.unit.as_bytes());
                payload.extend_from_slice(self.executable.as_bytes());
                (1, payload)
            }
            ExchangeState::Continue => (3, self.nonce.to_vec()),
            ExchangeState::Ack(_) => (5, self.nonce.to_vec()),
            _ => return Err(QueryExchangeError),
        };
        let frame = frame(phase, &payload);
        match self.control.send(&frame) {
            Ok(()) => {}
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Writable));
            }
            Err(_) => return Err(QueryExchangeError),
        }
        match std::mem::replace(&mut self.state, ExchangeState::Done) {
            ExchangeState::Start => {
                self.state = ExchangeState::AwaitA;
                Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
            }
            ExchangeState::Continue => {
                self.state = ExchangeState::AwaitB;
                Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable))
            }
            ExchangeState::Ack(observation) => Ok(ExchangeStep::Complete(observation)),
            _ => Err(QueryExchangeError),
        }
    }

    fn receive(
        &mut self,
        child: &FixedLiveChild<'_>,
    ) -> Result<ExchangeStep<BrokerPid1ServiceObservationV2>, QueryExchangeError> {
        let record = match self.control.receive(MAX_RECORD) {
            Ok(record) => record,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable));
            }
            Err(_) => return Err(QueryExchangeError),
        };
        let helper = record.subject();
        let child_credentials = child
            .initial_info()
            .credentials()
            .ok_or(QueryExchangeError)?;
        if helper.credentials().pid().get() != child.initial_info().pid()
            || helper.credentials().uid() != child_credentials.effective_user_id()
            || helper.credentials().gid() != child_credentials.effective_group_id()
            || helper.initial_info() != child.initial_info()
            || helper.pidfd().info().map_err(|_| QueryExchangeError)?
                != child.pidfd().info().map_err(|_| QueryExchangeError)?
            || descriptor_inode(helper.pidfd().as_fd()).map_err(|_| QueryExchangeError)?
                != descriptor_inode(child.pidfd().as_fd()).map_err(|_| QueryExchangeError)?
            || !helper.pidfd().is_alive().map_err(|_| QueryExchangeError)?
        {
            return Err(QueryExchangeError);
        }
        let expected_phase = if matches!(self.state, ExchangeState::AwaitA) {
            2
        } else {
            4
        };
        let payload = unframe(record.payload(), expected_phase)?;
        let observation = decode_snapshot(payload, self)?;
        match self.control.receive(MAX_RECORD) {
            Err(SeqpacketError::WouldBlock) => {}
            _ => return Err(QueryExchangeError),
        }
        match std::mem::replace(&mut self.state, ExchangeState::Done) {
            ExchangeState::AwaitA => {
                self.first = Some(observation);
                self.state = ExchangeState::Continue;
            }
            ExchangeState::AwaitB => {
                if self.first.as_ref() != Some(&observation) {
                    return Err(QueryExchangeError);
                }
                self.state = ExchangeState::Ack(observation);
            }
            _ => return Err(QueryExchangeError),
        }
        Ok(ExchangeStep::Pending(FixedProcessControlInterest::Writable))
    }
}

impl FixedProcessSessionExchange for QueryExchange<'_> {
    type Output = BrokerPid1ServiceObservationV2;
    type Error = QueryExchangeError;

    fn start(
        &mut self,
        child: &FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
    ) -> Result<ExchangeStep<Self::Output>, Self::Error> {
        self.send(child)
    }

    fn advance(
        &mut self,
        child: &FixedLiveChild<'_>,
        _control: BorrowedFd<'_>,
        readiness: FixedProcessControlReadiness,
    ) -> Result<ExchangeStep<Self::Output>, Self::Error> {
        if matches!(
            self.state,
            ExchangeState::Start | ExchangeState::Continue | ExchangeState::Ack(_)
        ) {
            if !readiness.is_writable() {
                return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Writable));
            }
            return self.send(child);
        }
        if !readiness.is_readable() {
            return Ok(ExchangeStep::Pending(FixedProcessControlInterest::Readable));
        }
        self.receive(child)
    }
}

fn frame(phase: u16, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(HEADER + payload.len());
    record.extend_from_slice(MAGIC);
    record.extend_from_slice(&VERSION.to_be_bytes());
    record.extend_from_slice(&phase.to_be_bytes());
    record.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn unframe(record: &[u8], phase: u16) -> Result<&[u8], QueryExchangeError> {
    if record.len() < HEADER
        || &record[..8] != MAGIC
        || u16::from_be_bytes(record[8..10].try_into().map_err(|_| QueryExchangeError)?) != VERSION
        || u16::from_be_bytes(record[10..12].try_into().map_err(|_| QueryExchangeError)?) != phase
        || u32::from_be_bytes(record[12..16].try_into().map_err(|_| QueryExchangeError)?) as usize
            != record.len() - HEADER
    {
        return Err(QueryExchangeError);
    }
    Ok(&record[HEADER..])
}

fn decode_snapshot(
    payload: &[u8],
    expected: &QueryExchange<'_>,
) -> Result<BrokerPid1ServiceObservationV2, QueryExchangeError> {
    let mut cursor = Cursor::new(payload);
    if cursor.take(32)? != expected.nonce
        || cursor.u8()? != expected.role as u8
        || cursor.u32()? != expected.subject_pid
        || cursor.u64()? != expected.subject_inode
        || cursor.u64()? != expected.cgroup_id
        || cursor.text(192)? != expected.unit
    {
        return Err(QueryExchangeError);
    }
    let invocation_id: [u8; 16] = cursor
        .take(16)?
        .try_into()
        .map_err(|_| QueryExchangeError)?;
    if invocation_id == [0; 16] {
        return Err(QueryExchangeError);
    }
    let control_group = cursor.text(512)?.to_owned();
    let fragment_path = cursor.text(512)?.to_owned();
    let executable = cursor.text(512)?.to_owned();
    let count = cursor.u8()? as usize;
    if count != expected.expected_arguments.len()
        || control_group != format!("/aos.slice/aos-control.slice/{}", expected.unit)
        || fragment_path != expected.expected_fragment_path
        || executable != expected.executable
    {
        return Err(QueryExchangeError);
    }
    let mut arguments = Vec::with_capacity(count);
    for argument in expected.expected_arguments {
        let observed = cursor.text(512)?;
        if observed != argument {
            return Err(QueryExchangeError);
        }
        arguments.push(observed.to_owned());
    }
    // The V3 helper emits this only after querying the manager and service
    // environment sources in the same PID 1 snapshot as the launch fields.
    if cursor.u8()? != 1 || !cursor.remaining().is_empty() {
        return Err(QueryExchangeError);
    }
    Ok(BrokerPid1ServiceObservationV2 {
        unit: expected.unit.to_owned(),
        invocation_id,
        main_pid: expected.subject_pid,
        control_group_id: expected.cgroup_id,
        control_group,
        fragment_path,
        executable,
        arguments,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    fn remaining(&self) -> &'a [u8] {
        self.bytes
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], QueryExchangeError> {
        if count > self.bytes.len() {
            return Err(QueryExchangeError);
        }
        let (value, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, QueryExchangeError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, QueryExchangeError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| QueryExchangeError)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, QueryExchangeError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| QueryExchangeError)?,
        ))
    }
    fn text(&mut self, max: usize) -> Result<&'a str, QueryExchangeError> {
        let count =
            u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| QueryExchangeError)?) as usize;
        if count == 0 || count > max {
            return Err(QueryExchangeError);
        }
        let text = self.take(count)?;
        if text.contains(&0) {
            return Err(QueryExchangeError);
        }
        std::str::from_utf8(text).map_err(|_| QueryExchangeError)
    }
}

fn descriptor_inode(fd: BorrowedFd<'_>) -> Result<u64, aos_sandbox_linux::Error> {
    rustix::fs::fstat(fd)
        .map(|status| status.st_ino)
        .map_err(|source| aos_sandbox_linux::Error::Syscall {
            operation: "inspect broker query descriptor",
            source: source.into(),
        })
}

fn duplicate(fd: BorrowedFd<'_>) -> Result<OwnedFd, aos_sandbox_linux::Error> {
    rustix::io::fcntl_dupfd_cloexec(fd, 0).map_err(|source| aos_sandbox_linux::Error::Syscall {
        operation: "duplicate broker query descriptor",
        source: source.into(),
    })
}

fn random_nonce() -> Result<[u8; 32], BrokerPid1QueryErrorV2> {
    let mut nonce = [0; 32];
    let mut filled = 0;
    while filled < nonce.len() {
        let count =
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(|source| aos_sandbox_linux::Error::Syscall {
                    operation: "generate broker query nonce",
                    source: source.into(),
                })?;
        if count == 0 {
            return Err(BrokerPid1QueryErrorV2::Invalid);
        }
        filled += count;
    }
    if nonce == [0; 32] {
        return Err(BrokerPid1QueryErrorV2::Invalid);
    }
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_frame_rejects_wrong_phase_and_length() {
        let good = frame(2, &[7; 4]);
        assert_eq!(unframe(&good, 2).unwrap(), &[7; 4]);
        assert!(unframe(&good, 4).is_err());
        assert!(unframe(&good[..good.len() - 1], 2).is_err());

        let mut legacy = good.clone();
        legacy[..8].copy_from_slice(b"AOSNIBQ2");
        assert!(unframe(&legacy, 2).is_err());

        legacy = good;
        legacy[9] = 2;
        assert!(unframe(&legacy, 2).is_err());
    }

    #[test]
    fn snapshot_requires_exact_pid1_subject_and_invocation_fields() {
        let (control, _) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        let arguments = vec!["/nix/store/example/bin/inspector".to_owned()];
        let expected = QueryExchange {
            control,
            nonce: [7; 32],
            subject_pid: 31,
            subject_inode: 41,
            cgroup_id: 51,
            role: BrokerPid1ServiceRoleV2::Inspector,
            unit: "aos-sandbox-network-namespace-inspector@one.service",
            executable: &arguments[0],
            expected_fragment_path: "/nix/store/example/unit.service",
            expected_arguments: &arguments,
            state: ExchangeState::AwaitA,
            first: None,
        };
        let mut snapshot = Vec::new();
        snapshot.extend_from_slice(&expected.nonce);
        snapshot.push(expected.role as u8);
        snapshot.extend_from_slice(&expected.subject_pid.to_be_bytes());
        snapshot.extend_from_slice(&expected.subject_inode.to_be_bytes());
        snapshot.extend_from_slice(&expected.cgroup_id.to_be_bytes());
        for text in [expected.unit] {
            snapshot.extend_from_slice(&(text.len() as u16).to_be_bytes());
            snapshot.extend_from_slice(text.as_bytes());
        }
        snapshot.extend_from_slice(&[3; 16]);
        for text in [
            format!("/aos.slice/aos-control.slice/{}", expected.unit),
            "/nix/store/example/unit.service".to_owned(),
            expected.executable.to_owned(),
        ] {
            snapshot.extend_from_slice(&(text.len() as u16).to_be_bytes());
            snapshot.extend_from_slice(text.as_bytes());
        }
        snapshot.push(1);
        snapshot.extend_from_slice(&(arguments[0].len() as u16).to_be_bytes());
        snapshot.extend_from_slice(arguments[0].as_bytes());
        snapshot.push(1);

        let observation = decode_snapshot(&snapshot, &expected).unwrap();
        assert_eq!(observation.main_pid, 31);
        assert_eq!(observation.control_group_id, 51);
        assert_eq!(observation.invocation_id, [3; 16]);
        assert!(decode_snapshot(&snapshot[..snapshot.len() - 1], &expected).is_err());

        let mut replayed_nonce = snapshot.clone();
        replayed_nonce[..32].fill(8);
        assert!(decode_snapshot(&replayed_nonce, &expected).is_err());

        let mut wrong_cgroup_id = snapshot.clone();
        wrong_cgroup_id[52] ^= 1;
        assert!(decode_snapshot(&wrong_cgroup_id, &expected).is_err());

        let mut wrong_invocation = snapshot.clone();
        let invocation_offset = 53 + 2 + expected.unit.len();
        wrong_invocation[invocation_offset..invocation_offset + 16].fill(0);
        assert!(decode_snapshot(&wrong_invocation, &expected).is_err());

        let mut wrong_fragment = snapshot.clone();
        let fragment = expected.expected_fragment_path.as_bytes();
        let offset = wrong_fragment
            .windows(fragment.len())
            .position(|window| window == fragment)
            .unwrap();
        wrong_fragment[offset] = b'!';
        assert!(decode_snapshot(&wrong_fragment, &expected).is_err());

        let mut no_loader_gate = snapshot.clone();
        *no_loader_gate.last_mut().unwrap() = 0;
        assert!(decode_snapshot(&no_loader_gate, &expected).is_err());

        let mut appended = snapshot;
        appended.push(0);
        assert!(decode_snapshot(&appended, &expected).is_err());

        let mut missing_loader_gate = appended.clone();
        missing_loader_gate.truncate(missing_loader_gate.len() - 2);
        assert!(decode_snapshot(&missing_loader_gate, &expected).is_err());

        let worker_arguments = vec!["/nix/store/example/bin/worker".to_owned(); 8];
        let worker = QueryExchange {
            control: SeqpacketSocket::pair_with_record_subjects().unwrap().0,
            nonce: [7; 32],
            subject_pid: 31,
            subject_inode: 41,
            cgroup_id: 51,
            role: BrokerPid1ServiceRoleV2::LifecycleWorker,
            unit: "aos-sandbox-network-lifecycle-worker@one.service",
            executable: &worker_arguments[0],
            expected_fragment_path: "/nix/store/example/worker.service",
            expected_arguments: &worker_arguments,
            state: ExchangeState::AwaitA,
            first: None,
        };
        assert!(decode_snapshot(&appended, &worker).is_err());
    }

    #[test]
    fn effect_boundary_rejects_changed_invocation_or_signed_unit_payload() {
        let observation = BrokerPid1ServiceObservationV2 {
            unit: "aos-sandbox-network-lifecycle-worker@one.service".to_owned(),
            invocation_id: [3; 16],
            main_pid: std::process::id(),
            control_group_id: 51,
            control_group:
                "/aos.slice/aos-control.slice/aos-sandbox-network-lifecycle-worker@one.service"
                    .to_owned(),
            fragment_path: "/nix/store/example/worker.service".to_owned(),
            executable: "/nix/store/example/bin/worker".to_owned(),
            arguments: vec!["/nix/store/example/bin/worker".to_owned()],
        };
        let subject_pid = NonZeroU32::new(std::process::id()).unwrap();
        let readback = |observation| BrokerPid1ServiceReadbackV2 {
            observation,
            subject: PidFd::open(subject_pid).unwrap(),
        };
        let initial = readback(observation.clone());
        assert!(require_same_readback(&initial, &readback(observation.clone())).is_ok());

        let mut changed = observation.clone();
        changed.invocation_id = [4; 16];
        assert!(require_same_readback(&initial, &readback(changed)).is_err());

        let mut changed = observation.clone();
        changed.unit.push('x');
        assert!(require_same_readback(&initial, &readback(changed)).is_err());

        let mut changed = observation.clone();
        changed.control_group_id += 1;
        assert!(require_same_readback(&initial, &readback(changed)).is_err());

        let mut changed = observation.clone();
        changed.fragment_path.push('x');
        assert!(require_same_readback(&initial, &readback(changed)).is_err());

        let mut changed = observation.clone();
        changed.executable.push('x');
        assert!(require_same_readback(&initial, &readback(changed)).is_err());

        let mut changed = observation;
        changed.arguments.push("--extra".to_owned());
        assert!(require_same_readback(&initial, &readback(changed)).is_err());
    }

    #[test]
    fn absent_v3_deployment_is_explicitly_unavailable() {
        let subject = PidFd::open(NonZeroU32::new(std::process::id()).unwrap()).unwrap();
        let state = BrokerPid1ServiceStateV3::observe_optional(
            None,
            &subject,
            None,
            BrokerPid1ServiceRoleV2::LifecycleWorker,
            "aos-sandbox-network-lifecycle-worker@one.service",
        )
        .unwrap();
        assert!(matches!(&state, BrokerPid1ServiceStateV3::Unavailable));
        assert!(matches!(
            state.require_effect_readback(),
            Err(BrokerPid1QueryErrorV2::Unavailable)
        ));
    }
}
