//! Authenticated one-transaction OpenZFS process worker.
//!
//! A broker sends canonical resolved-catalog bytes and one closed
//! [`StorageOperation`]. The independently packaged worker reconstructs the
//! catalog, recompiles [`ZfsTransaction`], and invokes only its configured
//! immutable AOS-store executable. Raw argv never crosses the socket.
//!
//! The version-two bounded wire sequence is:
//!
//! ```text
//! worker -> broker: READY  = magic | version | cgroup-length | cgroup
//! broker -> worker: REQUEST = magic | version | verb | executable-check | operation | catalog
//! worker -> broker: MUTATION = magic | version | success | timeout | stdout | stderr
//! worker -> broker: OBSERVE  = magic | version | state | captured-guid | evidence-digest
//! broker -> worker: ACK = magic | version
//! ```
//!
//! The closed request verb selects mutation, precondition observation, or
//! postcondition observation. Observation output is parsed inside the worker;
//! raw command output never crosses the socket. A failed observation command
//! is an error, not evidence of absence.
//!
//! Every record carries kernel-generated credentials and a pidfd. The ACK
//! keeps a fast-success worker alive while the broker verifies that READY and
//! RESPONSE came from the same still-live service execution.

use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aos_sandbox_linux::cgroup::CgroupV2Root;
use aos_sandbox_linux::process::{FixedProcessOutcome, FixedProcessRequest, run_fixed_process};
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketError, SeqpacketSocket,
};

use crate::observation::{ZfsObservationPlan, ZfsObservationResult};
use crate::{
    ResolvedCatalogCommitmentV1, StorageOperation, ZfsHelperContract, ZfsTransaction,
    ZfsTransactionError,
};

mod wire;

use wire::{
    MAXIMUM_OBSERVATION_RESPONSE_BYTES, MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES,
    WIRE_VERSION, WorkerRequestVerb, decode_mutation_response, decode_observation_response,
    decode_request, encode_mutation_response, encode_observation_response, encode_request,
};

const READY_MAGIC: &[u8; 8] = b"AOSZRDY2";
const ACK_MAGIC: &[u8; 8] = b"AOSZACK2";
const MAXIMUM_READY_BYTES: usize = 4096;
const MAXIMUM_ACK_BYTES: usize = 10;
const MAXIMUM_CGROUP_TEXT_BYTES: usize = 4096;
const MAXIMUM_STDOUT_BYTES: usize = 64 * 1024;
const MAXIMUM_STDERR_BYTES: usize = 64 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(35);
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const STORAGED_CGROUP: &str = "aos-control.slice/aos-storaged.service";
const WORKER_CGROUP_PREFIX: &str = "aos-control.slice/aos-sandbox-zfs-worker@";
const WORKER_CGROUP_SUFFIX: &str = ".service";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Reports a fixed-worker setup, authentication, protocol, or execution error.
#[derive(Debug, thiserror::Error)]
pub enum ZfsWorkerError {
    /// The configured executable contract is invalid.
    #[error("invalid fixed ZFS executable: {0}")]
    Executable(String),
    /// A local worker packet is malformed, oversized, or semantically invalid.
    #[error("invalid fixed ZFS worker protocol: {0}")]
    Protocol(&'static str),
    /// The connected process does not belong to the configured service role.
    #[error("fixed ZFS worker peer provenance did not match")]
    PeerMismatch,
    /// The transport could not exchange one complete bounded transaction.
    #[error("fixed ZFS worker transport failed: {0}")]
    Transport(#[from] SeqpacketError),
    /// A local filesystem or descriptor operation failed.
    #[error("fixed ZFS worker I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Linux process or identity enforcement failed.
    #[error("fixed ZFS worker Linux boundary failed: {0}")]
    Linux(#[from] aos_sandbox_linux::Error),
    /// A safe rustix operation failed.
    #[error("fixed ZFS worker kernel operation failed: {0}")]
    Kernel(#[from] rustix::io::Errno),
    /// The independently reconstructed catalog and operation do not agree.
    #[error("fixed ZFS worker transaction compilation failed: {0}")]
    Transaction(#[from] ZfsTransactionError),
    /// The local worker preserved this exact child-side executable error.
    #[error("local fixed ZFS exec failed: {0}")]
    Exec(std::io::Error),
}

/// Returns the fixed internal process timeout enforced by every worker.
#[must_use]
pub const fn process_timeout() -> Duration {
    PROCESS_TIMEOUT
}

/// Executes typed storage transactions through systemd-created one-shot workers.
#[derive(Debug)]
pub struct SystemdZfsExecutor {
    socket_path: PathBuf,
    systemd_manager_cgroup: aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    worker_parent_cgroup: aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
}

impl SystemdZfsExecutor {
    /// Opens the fixed worker-service cgroup and validates the socket path.
    ///
    /// # Errors
    ///
    /// Returns an error unless the socket is a normalized absolute path and
    /// the fixed `aos-control.slice` cgroup can be retained.
    pub fn new(socket_path: PathBuf, cgroup_root: CgroupV2Root) -> Result<Self, ZfsWorkerError> {
        let normalized = socket_path.is_absolute()
            && socket_path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)));
        if !normalized || socket_path.as_os_str().len() > 4096 {
            return Err(ZfsWorkerError::Protocol("unsafe worker socket path"));
        }
        let systemd_manager_cgroup = cgroup_root.resolve(Path::new(SYSTEMD_MANAGER_CGROUP))?;
        let worker_parent_cgroup = cgroup_root.resolve(Path::new("aos-control.slice"))?;
        Ok(Self {
            socket_path,
            systemd_manager_cgroup,
            worker_parent_cgroup,
        })
    }

    /// Sends one typed transaction and waits for its size-bounded result exactly once.
    ///
    /// No transport failure is retried. Once the request packet is sent, every
    /// error is an ambiguous mutation outcome for the durable caller.
    ///
    /// # Errors
    ///
    /// Returns an error for worker activation, peer/cgroup mismatch, malformed
    /// framing, executable mismatch, transport failure, or deadline expiry.
    /// A disconnect after request transmission is ambiguous and is never
    /// retried; child-side `execve` errno is retained only in worker logging.
    pub fn execute_once(
        &self,
        contract: &ZfsHelperContract,
        operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<WorkerProcessOutput, ZfsWorkerError> {
        let request = encode_request(WorkerRequestVerb::Mutate, contract, operation, catalog)?;
        let response = self.exchange(request, MAXIMUM_RESPONSE_BYTES)?;
        decode_mutation_response(&response)
    }

    /// Revalidates the transaction's exact physical preconditions without mutation.
    ///
    /// The protected caller remains responsible for the catalog-binding check;
    /// the worker reports only physical ZFS facts. Failed commands, output
    /// truncation, and permission errors are returned as errors and never as
    /// successful absence observations.
    ///
    /// # Errors
    ///
    /// Returns an error for worker activation, authentication, framing,
    /// execution, parsing, or deadline failure.
    pub fn observe_preconditions(
        &self,
        contract: &ZfsHelperContract,
        operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<WorkerObservationOutcome, ZfsWorkerError> {
        self.observe(
            WorkerRequestVerb::ObservePreconditions,
            contract,
            operation,
            catalog,
        )
    }

    /// Observes the transaction's exact physical postcondition without mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for worker activation, authentication, framing,
    /// execution, parsing, or deadline failure. A successful parent inventory
    /// is required before an absent object can produce a matched result.
    pub fn observe_postcondition(
        &self,
        contract: &ZfsHelperContract,
        operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<WorkerObservationOutcome, ZfsWorkerError> {
        self.observe(
            WorkerRequestVerb::ObservePostcondition,
            contract,
            operation,
            catalog,
        )
    }

    fn observe(
        &self,
        verb: WorkerRequestVerb,
        contract: &ZfsHelperContract,
        operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<WorkerObservationOutcome, ZfsWorkerError> {
        let request = encode_request(verb, contract, operation, catalog)?;
        let response = self.exchange(request, MAXIMUM_OBSERVATION_RESPONSE_BYTES)?;
        decode_observation_response(&response)
    }

    fn exchange(
        &self,
        request: Vec<u8>,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ZfsWorkerError> {
        let deadline = Deadline::after(CONNECTION_TIMEOUT);
        let mut socket = SeqpacketSocket::connect(&self.socket_path)?;
        verify_systemd_activation_peer(socket.peer(), &self.systemd_manager_cgroup)?;

        let ready = receive_before(&mut socket, MAXIMUM_READY_BYTES, deadline)?;
        let (ready_payload, worker_subject) = ready.into_parts();
        let worker_cgroup = decode_ready(&ready_payload)?;
        verify_worker_peer(
            &worker_subject,
            &self.worker_parent_cgroup,
            Path::new(worker_cgroup),
        )?;

        send_before(&mut socket, &request, deadline)?;
        let response = receive_before(&mut socket, maximum_response_bytes, deadline)?;
        verify_same_live_subject(&worker_subject, response.subject())?;
        let payload = response.payload().to_vec();
        send_before(&mut socket, &encode_ack(), deadline)?;
        Ok(payload)
    }
}

/// Reports the bounded child result returned by a one-shot worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerProcessOutput {
    /// Complete standard output within the fixed ceiling.
    pub stdout: Vec<u8>,
    /// Complete standard error within the fixed ceiling.
    pub stderr: Vec<u8>,
    /// Whether every compiled ZFS command exited successfully.
    pub success: bool,
    /// Whether the worker's process deadline elapsed.
    pub timed_out: bool,
}

/// Classifies one authoritative, non-mutating worker observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerObservationOutcome {
    /// Every physical fact matched the closed plan.
    Matched {
        /// Newly captured object GUID for create/snapshot, when applicable.
        object_guid: Option<u64>,
        /// Domain-separated digest of exact command argv and machine output.
        observation_digest: aos_sandbox_core::ObjectDigest,
    },
    /// The postcondition has not reached its complete expected state.
    Incomplete,
    /// A physical name, kind, or GUID conflicts with the catalogued identity.
    Mismatch,
}

/// Runs one inherited systemd socket worker transaction.
///
/// PID 1 must supply the same connected `SOCK_SEQPACKET` as standard input and
/// standard output. The configured ZFS executable comes only from the fixed
/// service unit and is never selected by the request.
///
/// # Errors
///
/// Returns an error for an invalid executable, inherited socket, storaged peer,
/// request, transaction compilation, process launch, or response write.
pub fn run_inherited_worker(configured_zfs: PathBuf) -> Result<(), ZfsWorkerError> {
    let contract = ZfsHelperContract::new(configured_zfs)
        .map_err(|error| ZfsWorkerError::Executable(error.to_string()))?;
    let _executable_pin = PinnedExecutable::open(&contract)?;
    let cgroup_root = open_cgroup_root()?;
    let storaged_cgroup = cgroup_root.resolve(Path::new(STORAGED_CGROUP))?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = SeqpacketSocket::from_owned(descriptor)?;
    verify_storaged_peer(socket.peer(), &storaged_cgroup)?;
    socket.enable_record_subjects()?;

    let deadline = Deadline::after(PROCESS_TIMEOUT);
    let ready = encode_ready(&current_cgroup()?)?;
    send_before(&mut socket, &ready, deadline)?;
    let request = receive_before(&mut socket, MAXIMUM_REQUEST_BYTES, deadline)?;
    verify_same_subject(socket.peer(), request.subject())?;
    storaged_cgroup.verify_exact_membership(request.subject().pidfd())?;
    let request = decode_request(request.payload())?;
    let expected_executable = &request.executable;
    if expected_executable != contract.executable() {
        return Err(ZfsWorkerError::Executable(
            "broker and worker executable contracts differ".to_owned(),
        ));
    }
    _executable_pin.validate_current(&contract)?;

    let transaction = ZfsTransaction::from_catalog(request.operation, &request.catalog)?;
    let response = match request.verb {
        WorkerRequestVerb::Mutate => {
            let output = execute_transaction(&contract, &transaction, deadline)?;
            encode_mutation_response(&output)?
        }
        WorkerRequestVerb::ObservePreconditions => {
            let plan = ZfsObservationPlan::preconditions(&transaction)
                .map_err(|_| ZfsWorkerError::Protocol("invalid ZFS observation plan"))?;
            let observation = execute_observation(&contract, &plan, deadline)?;
            encode_observation_response(observation)?
        }
        WorkerRequestVerb::ObservePostcondition => {
            let plan = ZfsObservationPlan::postcondition(&transaction)
                .map_err(|_| ZfsWorkerError::Protocol("invalid ZFS observation plan"))?;
            let observation = execute_observation(&contract, &plan, deadline)?;
            encode_observation_response(observation)?
        }
    };
    _executable_pin.validate_current(&contract)?;
    send_before(&mut socket, &response, deadline)?;
    let acknowledgement = receive_before(&mut socket, MAXIMUM_ACK_BYTES, deadline)?;
    verify_same_subject(socket.peer(), acknowledgement.subject())?;
    storaged_cgroup.verify_exact_membership(acknowledgement.subject().pidfd())?;
    decode_ack(acknowledgement.payload())?;
    Ok(())
}

fn execute_transaction(
    contract: &ZfsHelperContract,
    transaction: &ZfsTransaction,
    deadline: Deadline,
) -> Result<WorkerProcessOutput, ZfsWorkerError> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut commands = Vec::with_capacity(2);
    if let Some(ancestor) = transaction.ancestor_transaction() {
        commands.push(ancestor.mutation_arguments());
    }
    commands.push(transaction.mutation_arguments());

    for arguments in commands {
        let Some(timeout) = deadline.remaining() else {
            return Ok(WorkerProcessOutput {
                stdout,
                stderr,
                success: false,
                timed_out: true,
            });
        };
        let outcome = run_fixed_process(FixedProcessRequest {
            executable: contract.executable(),
            arguments,
            timeout,
            maximum_stdout_bytes: MAXIMUM_STDOUT_BYTES.saturating_sub(stdout.len()),
            maximum_stderr_bytes: MAXIMUM_STDERR_BYTES.saturating_sub(stderr.len()),
        });
        match outcome {
            Ok(FixedProcessOutcome::Completed(output)) => {
                stdout.extend(output.stdout);
                stderr.extend(output.stderr);
                if output.exit_code != Some(0) || output.signal.is_some() {
                    return Ok(WorkerProcessOutput {
                        stdout,
                        stderr,
                        success: false,
                        timed_out: false,
                    });
                }
            }
            Ok(FixedProcessOutcome::TimedOut) => {
                return Ok(WorkerProcessOutput {
                    stdout,
                    stderr,
                    success: false,
                    timed_out: true,
                });
            }
            Ok(FixedProcessOutcome::OutputLimitExceeded) => {
                return Err(ZfsWorkerError::Protocol("ZFS output exceeded its ceiling"));
            }
            Err(aos_sandbox_linux::Error::Syscall {
                operation: "spawn fixed process",
                source,
            }) if source.raw_os_error().is_some() => {
                return Err(ZfsWorkerError::Exec(source));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(WorkerProcessOutput {
        stdout,
        stderr,
        success: true,
        timed_out: false,
    })
}

fn execute_observation(
    contract: &ZfsHelperContract,
    plan: &ZfsObservationPlan,
    deadline: Deadline,
) -> Result<ZfsObservationResult, ZfsWorkerError> {
    let mut evaluation = plan.evaluation();
    let mut output_bytes = 0_usize;

    for command in plan.commands() {
        let Some(timeout) = deadline.remaining() else {
            return Err(ZfsWorkerError::Protocol("ZFS observation timed out"));
        };
        let outcome = run_fixed_process(FixedProcessRequest {
            executable: contract.executable(),
            arguments: command.arguments(),
            timeout,
            maximum_stdout_bytes: MAXIMUM_STDOUT_BYTES.saturating_sub(output_bytes),
            maximum_stderr_bytes: MAXIMUM_STDERR_BYTES,
        });
        let output = match outcome {
            Ok(FixedProcessOutcome::Completed(output))
                if output.exit_code == Some(0)
                    && output.signal.is_none()
                    && output.stderr.is_empty() =>
            {
                output.stdout
            }
            Ok(FixedProcessOutcome::Completed(_)) => {
                // A failed direct command is never evidence that an object is absent.
                return Err(ZfsWorkerError::Protocol("ZFS observation command failed"));
            }
            Ok(FixedProcessOutcome::TimedOut) => {
                return Err(ZfsWorkerError::Protocol("ZFS observation timed out"));
            }
            Ok(FixedProcessOutcome::OutputLimitExceeded) => {
                return Err(ZfsWorkerError::Protocol(
                    "ZFS observation output exceeded its ceiling",
                ));
            }
            Err(aos_sandbox_linux::Error::Syscall {
                operation: "spawn fixed process",
                source,
            }) if source.raw_os_error().is_some() => return Err(ZfsWorkerError::Exec(source)),
            Err(error) => return Err(error.into()),
        };
        output_bytes = output_bytes
            .checked_add(output.len())
            .filter(|bytes| *bytes <= MAXIMUM_STDOUT_BYTES)
            .ok_or(ZfsWorkerError::Protocol(
                "ZFS observation output exceeded its ceiling",
            ))?;
        if let Some(result) = evaluation
            .accept(output)
            .map_err(|_| ZfsWorkerError::Protocol("invalid ZFS observation output"))?
        {
            return Ok(result);
        }
    }
    Err(ZfsWorkerError::Protocol(
        "ZFS observation plan did not produce a result",
    ))
}

struct PinnedExecutable {
    _file: File,
    device: u64,
    inode: u64,
}

impl PinnedExecutable {
    fn open(contract: &ZfsHelperContract) -> Result<Self, ZfsWorkerError> {
        let metadata = std::fs::symlink_metadata(contract.executable())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o222 != 0
        {
            return Err(ZfsWorkerError::Executable(
                "must be a root-owned, non-writable regular store file".to_owned(),
            ));
        }
        let file = File::open(contract.executable())?;
        let opened = file.metadata()?;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(ZfsWorkerError::Executable(
                "changed while its identity was pinned".to_owned(),
            ));
        }
        Ok(Self {
            _file: file,
            device: opened.dev(),
            inode: opened.ino(),
        })
    }

    fn validate_current(&self, contract: &ZfsHelperContract) -> Result<(), ZfsWorkerError> {
        let metadata = std::fs::symlink_metadata(contract.executable())?;
        if !metadata.file_type().is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o222 != 0
        {
            return Err(ZfsWorkerError::Executable(
                "configured store executable identity changed".to_owned(),
            ));
        }
        Ok(())
    }
}

fn encode_ack() -> [u8; MAXIMUM_ACK_BYTES] {
    let mut bytes = [0_u8; MAXIMUM_ACK_BYTES];
    bytes[..8].copy_from_slice(ACK_MAGIC);
    bytes[8..].copy_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes
}

fn decode_ack(bytes: &[u8]) -> Result<(), ZfsWorkerError> {
    if bytes == encode_ack() {
        Ok(())
    } else {
        Err(ZfsWorkerError::Protocol("acknowledgement is invalid"))
    }
}

fn encode_ready(cgroup: &str) -> Result<Vec<u8>, ZfsWorkerError> {
    let cgroup = cgroup.as_bytes();
    let length = u16::try_from(cgroup.len())
        .map_err(|_| ZfsWorkerError::Protocol("worker cgroup is too long"))?;
    let mut bytes = Vec::with_capacity(12 + cgroup.len());
    bytes.extend_from_slice(READY_MAGIC);
    bytes.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(cgroup);
    Ok(bytes)
}

fn decode_ready(bytes: &[u8]) -> Result<&str, ZfsWorkerError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.take(8)? != READY_MAGIC || decoder.u16()? != WIRE_VERSION {
        return Err(ZfsWorkerError::Protocol("ready magic or version mismatch"));
    }
    let length = usize::from(decoder.u16()?);
    let cgroup = std::str::from_utf8(decoder.take(length)?)
        .map_err(|_| ZfsWorkerError::Protocol("worker cgroup is not UTF-8"))?;
    decoder.finish()?;
    validate_worker_cgroup(cgroup)?;
    Ok(cgroup)
}

fn current_cgroup() -> Result<String, ZfsWorkerError> {
    let mut file = File::open("/proc/self/cgroup")?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(u64::try_from(MAXIMUM_CGROUP_TEXT_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM_CGROUP_TEXT_BYTES {
        return Err(ZfsWorkerError::Protocol("worker cgroup text is oversized"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ZfsWorkerError::Protocol("worker cgroup text is not UTF-8"))?;
    let path = text
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .ok_or(ZfsWorkerError::Protocol("unified worker cgroup is absent"))?;
    validate_worker_cgroup(path)?;
    Ok(path.to_owned())
}

fn validate_worker_cgroup(path: &str) -> Result<(), ZfsWorkerError> {
    let Some(instance) = path
        .strip_prefix(WORKER_CGROUP_PREFIX)
        .and_then(|value| value.strip_suffix(WORKER_CGROUP_SUFFIX))
    else {
        return Err(ZfsWorkerError::PeerMismatch);
    };
    if instance.is_empty() || instance.len() > 255 || instance.contains('/') {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn verify_worker_peer(
    subject: &KernelAuthorizedRecordSubject,
    parent: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
    path: &Path,
) -> Result<(), ZfsWorkerError> {
    let credentials = subject.credentials();
    if credentials.uid() == 0 || credentials.gid() == 0 {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    let relative = path
        .strip_prefix("aos-control.slice")
        .map_err(|_| ZfsWorkerError::PeerMismatch)?;
    let info = parent.verify_descendant_membership(subject.pidfd(), relative)?;
    if info.pid() != credentials.pid().get() || info.thread_group_id() != credentials.pid().get() {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn verify_systemd_activation_peer(
    peer: &ConnectionPeerIdentity,
    expected: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
) -> Result<(), ZfsWorkerError> {
    let credentials = peer.credentials();
    if credentials.pid().get() != 1 || credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    let info = expected.verify_exact_membership(peer.pidfd())?;
    if info.pid() != 1 || info.thread_group_id() != 1 {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn verify_storaged_peer(
    peer: &ConnectionPeerIdentity,
    expected: &aos_sandbox_linux::cgroup::RetainedCgroupAnchor,
) -> Result<(), ZfsWorkerError> {
    let credentials = peer.credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    let info = expected.verify_exact_membership(peer.pidfd())?;
    if info.pid() != credentials.pid().get() || info.thread_group_id() != credentials.pid().get() {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn verify_same_subject(
    peer: &ConnectionPeerIdentity,
    subject: &KernelAuthorizedRecordSubject,
) -> Result<(), ZfsWorkerError> {
    let peer_credentials = peer.credentials();
    let record_credentials = subject.credentials();
    if record_credentials.pid() != peer_credentials.pid()
        || record_credentials.uid() != peer_credentials.uid()
        || record_credentials.gid() != peer_credentials.gid()
        || subject.initial_info().pid() != peer.initial_info().pid()
        || subject.initial_info().thread_group_id() != peer.initial_info().thread_group_id()
    {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn verify_same_live_subject(
    expected: &KernelAuthorizedRecordSubject,
    actual: &KernelAuthorizedRecordSubject,
) -> Result<(), ZfsWorkerError> {
    if !expected.is_alive()? || !actual.is_alive()? {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    if expected.credentials() != actual.credentials()
        || expected.initial_info().pid() != actual.initial_info().pid()
        || expected.initial_info().thread_group_id() != actual.initial_info().thread_group_id()
        || expected.initial_info().cgroup_id() != actual.initial_info().cgroup_id()
    {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn send_before(
    socket: &mut SeqpacketSocket,
    bytes: &[u8],
    deadline: Deadline,
) -> Result<(), ZfsWorkerError> {
    loop {
        deadline.ensure_pending()?;
        match socket.send(bytes) {
            Ok(()) => return deadline.ensure_pending(),
            Err(SeqpacketError::WouldBlock) | Err(SeqpacketError::Interrupted) => {
                wait_socket(socket, rustix::event::PollFlags::OUT, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_before(
    socket: &mut SeqpacketSocket,
    maximum: usize,
    deadline: Deadline,
) -> Result<aos_sandbox_linux::seqpacket::ReceivedRecord, ZfsWorkerError> {
    loop {
        deadline.ensure_pending()?;
        match socket.receive(maximum) {
            Ok(record) => {
                deadline.ensure_pending()?;
                return Ok(record);
            }
            Err(SeqpacketError::WouldBlock) | Err(SeqpacketError::Interrupted) => {
                wait_socket(socket, rustix::event::PollFlags::IN, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait_socket(
    socket: &SeqpacketSocket,
    events: rustix::event::PollFlags,
    deadline: Deadline,
) -> Result<(), ZfsWorkerError> {
    let remaining = deadline.remaining().ok_or(ZfsWorkerError::Protocol(
        "worker connection deadline elapsed",
    ))?;
    let timeout = rustix::event::Timespec::try_from(remaining)
        .map_err(|_| ZfsWorkerError::Protocol("worker deadline is invalid"))?;
    let descriptor = socket.as_fd()?;
    let mut descriptors = [rustix::event::PollFd::new(&descriptor, events)];
    if rustix::event::poll(&mut descriptors, Some(&timeout))? == 0 {
        return Err(ZfsWorkerError::Protocol(
            "worker connection deadline elapsed",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Deadline(Duration);

impl Deadline {
    fn after(duration: Duration) -> Self {
        Self(
            monotonic_now()
                .checked_add(duration)
                .unwrap_or(Duration::MAX),
        )
    }

    fn remaining(self) -> Option<Duration> {
        self.0
            .checked_sub(monotonic_now())
            .filter(|remaining| !remaining.is_zero())
    }

    fn ensure_pending(self) -> Result<(), ZfsWorkerError> {
        self.remaining().map(|_| ()).ok_or(ZfsWorkerError::Protocol(
            "worker connection deadline elapsed",
        ))
    }
}

fn monotonic_now() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

fn open_cgroup_root() -> Result<CgroupV2Root, ZfsWorkerError> {
    let descriptor: OwnedFd = rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    Ok(CgroupV2Root::from_owned(descriptor)?)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ZfsWorkerError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ZfsWorkerError::Protocol("wire length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ZfsWorkerError::Protocol("truncated worker packet"))?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, ZfsWorkerError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(ZfsWorkerError::Protocol("missing worker byte"))
    }

    fn u16(&mut self) -> Result<u16, ZfsWorkerError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| ZfsWorkerError::Protocol("invalid worker u16"),
        )?))
    }

    fn u32(&mut self) -> Result<u32, ZfsWorkerError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| ZfsWorkerError::Protocol("invalid worker u32"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, ZfsWorkerError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| ZfsWorkerError::Protocol("invalid worker u64"),
        )?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZfsWorkerError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ZfsWorkerError::Protocol("invalid fixed worker field"))
    }

    fn finish(self) -> Result<(), ZfsWorkerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ZfsWorkerError::Protocol("trailing worker packet bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::ObjectDigest;

    use super::*;
    use crate::observation::ZfsObservationState;
    use crate::{
        ActiveHoldEvidence, CatalogPlanV1, HoldId, ManagedDatasetRoot, PlannedDataset,
        PlannedSnapshot, ProjectAncestorPolicyV1, ReservationPolicy, ResolvedDataset,
        ResolvedSnapshot, StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

    fn socket_pair() -> (SeqpacketSocket, SeqpacketSocket) {
        let (left, right) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        (left, SeqpacketSocket::from_owned(right).unwrap())
    }

    fn assert_deadline_elapsed(error: ZfsWorkerError) {
        match error {
            ZfsWorkerError::Protocol(message) => {
                assert_eq!(message, "worker connection deadline elapsed");
            }
            other => panic!("unexpected deadline error: {other:?}"),
        }
    }

    fn fixture() -> (ResolvedCatalogCommitmentV1, StorageOperation) {
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root = ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap();
        let ancestor_dataset =
            ResolvedDataset::from_catalog(root.clone(), "tank/aos/project", 15, [1; 32], domains)
                .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 65_536, 8, 16).unwrap();
        let destination =
            PlannedDataset::from_catalog(root, "tank/aos/project/work", domains).unwrap();
        let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
        (
            ResolvedCatalogCommitmentV1::new(
                7,
                domains,
                CatalogPlanV1::CreateWorkspace {
                    destination,
                    space,
                    ancestor,
                },
            )
            .unwrap(),
            StorageOperation::CreateWorkspace { quota_bytes: 4096 },
        )
    }

    #[test]
    fn request_round_trip_reconstructs_typed_inputs() {
        let (catalog, operation) = fixture();
        let contract = ZfsHelperContract::new("/nix/store/hash-zfs/sbin/zfs".into()).unwrap();
        let bytes =
            encode_request(WorkerRequestVerb::Mutate, &contract, operation, &catalog).unwrap();
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.verb, WorkerRequestVerb::Mutate);
        assert_eq!(decoded.executable, contract.executable());
        assert_eq!(decoded.operation, operation);
        assert_eq!(decoded.catalog, catalog);
        assert_eq!(
            ZfsTransaction::from_catalog(decoded.operation, &decoded.catalog).unwrap(),
            ZfsTransaction::from_catalog(operation, &catalog).unwrap()
        );

        for verb in [
            WorkerRequestVerb::ObservePreconditions,
            WorkerRequestVerb::ObservePostcondition,
        ] {
            let decoded =
                decode_request(&encode_request(verb, &contract, operation, &catalog).unwrap())
                    .unwrap();
            assert_eq!(decoded.verb, verb);
            assert_eq!(decoded.operation, operation);
            assert_eq!(decoded.catalog, catalog);
        }
    }

    #[test]
    fn request_rejects_operation_substitution_and_trailing_bytes() {
        let (catalog, operation) = fixture();
        let contract = ZfsHelperContract::new("/nix/store/hash-zfs/sbin/zfs".into()).unwrap();
        let mut bytes =
            encode_request(WorkerRequestVerb::Mutate, &contract, operation, &catalog).unwrap();
        let operation_offset = 13 + contract.executable().as_os_str().len();
        bytes[operation_offset] = 2;
        assert!(decode_request(&bytes).is_err());

        let mut bytes =
            encode_request(WorkerRequestVerb::Mutate, &contract, operation, &catalog).unwrap();
        bytes.push(0);
        assert!(decode_request(&bytes).is_err());

        let mut bytes =
            encode_request(WorkerRequestVerb::Mutate, &contract, operation, &catalog).unwrap();
        bytes[10] = 0;
        assert!(decode_request(&bytes).is_err());
    }

    #[test]
    fn response_round_trip_enforces_output_and_state_shape() {
        let output = WorkerProcessOutput {
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            success: false,
            timed_out: true,
        };
        assert_eq!(
            decode_mutation_response(&encode_mutation_response(&output).unwrap()).unwrap(),
            output
        );

        let mut invalid = encode_mutation_response(&WorkerProcessOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            success: true,
            timed_out: false,
        })
        .unwrap();
        invalid[11] = 1;
        assert!(decode_mutation_response(&invalid).is_err());
    }

    #[test]
    fn observation_response_round_trip_rejects_inconsistent_evidence() {
        let digest = aos_sandbox_core::ObjectDigest::from_bytes([9; 32]);
        let matched = ZfsObservationResult {
            state: ZfsObservationState::Matched,
            object_guid: Some(44),
            digest: Some(digest),
        };
        assert_eq!(
            decode_observation_response(&encode_observation_response(matched).unwrap()).unwrap(),
            WorkerObservationOutcome::Matched {
                object_guid: Some(44),
                observation_digest: digest,
            }
        );

        let mut inconsistent = encode_observation_response(ZfsObservationResult {
            state: ZfsObservationState::Incomplete,
            object_guid: None,
            digest: None,
        })
        .unwrap();
        *inconsistent.last_mut().unwrap() = 1;
        assert!(decode_observation_response(&inconsistent).is_err());
    }

    #[test]
    fn acknowledgement_is_exact_and_versioned() {
        let acknowledgement = encode_ack();
        decode_ack(&acknowledgement).unwrap();

        let mut wrong_version = acknowledgement;
        wrong_version[9] ^= 1;
        assert!(decode_ack(&wrong_version).is_err());
        assert!(decode_ack(&acknowledgement[..9]).is_err());
    }

    #[test]
    fn expired_deadline_does_not_send_on_a_writable_socket() {
        let (mut sender, mut receiver) = socket_pair();

        let error = send_before(&mut sender, b"late", Deadline(Duration::ZERO)).unwrap_err();

        assert_deadline_elapsed(error);
        assert!(matches!(
            receiver.receive(4),
            Err(SeqpacketError::WouldBlock)
        ));
    }

    #[test]
    fn expired_deadline_does_not_consume_a_queued_record() {
        let (mut receiver, mut sender) = socket_pair();
        sender.send(b"queued").unwrap();

        let error = receive_before(&mut receiver, 6, Deadline(Duration::ZERO)).unwrap_err();

        assert_deadline_elapsed(error);
        assert_eq!(receiver.receive(6).unwrap().payload(), b"queued");
    }

    #[test]
    #[ignore = "requires the real systemd Accept=yes worker and cgroup-v2 service layout"]
    fn systemd_worker_vm_client() {
        let executable = std::env::var_os("AOS_ZFS_EXECUTABLE")
            .map(PathBuf::from)
            .unwrap();
        let case = std::env::var("AOS_ZFS_WORKER_CASE").unwrap();
        let fields = case.split(':').collect::<Vec<_>>();
        let action = fields[0];
        let domains = StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap();
        let root_guid = fields.get(1).map_or(10, |value| value.parse().unwrap());
        let root = ManagedDatasetRoot::from_catalog("aosproof", "aosproof/aos", root_guid).unwrap();
        let ancestor_guid = fields.get(2).map_or(15, |value| value.parse().unwrap());
        let ancestor_dataset = ResolvedDataset::from_catalog(
            root.clone(),
            "aosproof/aos/project",
            ancestor_guid,
            [1; 32],
            domains,
        )
        .unwrap();
        let ancestor = ProjectAncestorPolicyV1::new(ancestor_dataset, 268_435_456, 8, 16).unwrap();
        let contract = ZfsHelperContract::new(executable).unwrap();
        let executor = SystemdZfsExecutor::new(
            PathBuf::from("/run/aos/sandbox-zfs-worker/control.sock"),
            open_cgroup_root().unwrap(),
        )
        .unwrap();

        if action == "fast" || action == "timeout" {
            let dataset = ResolvedDataset::from_catalog(
                root,
                &format!("aosproof/aos/project/{action}"),
                91,
                [2; 32],
                domains,
            )
            .unwrap();
            let space = WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap();
            let catalog = ResolvedCatalogCommitmentV1::new(
                7,
                domains,
                CatalogPlanV1::SetQuota {
                    dataset,
                    space,
                    ancestor,
                },
            )
            .unwrap();
            let operation = StorageOperation::SetQuota {
                storage_handle: [2; 32],
                quota_bytes: 4096,
            };

            if action == "timeout" {
                assert!(
                    executor
                        .execute_once(&contract, operation, &catalog)
                        .is_err()
                );
                return;
            }

            for _ in 0..8 {
                let output = executor
                    .execute_once(&contract, operation, &catalog)
                    .unwrap();
                assert!(output.success);
                assert!(!output.timed_out);
            }
            return;
        }

        let workspace_guid = fields.get(3).map(|value| value.parse().unwrap());
        let snapshot_guid = fields.get(4).map(|value| value.parse().unwrap());
        let workspace = workspace_guid.map(|guid| {
            ResolvedDataset::from_catalog(
                root.clone(),
                "aosproof/aos/project/workspace",
                guid,
                [2; 32],
                domains,
            )
            .unwrap()
        });
        let snapshot = snapshot_guid.map(|guid| {
            ResolvedSnapshot::from_catalog(workspace.clone().unwrap(), "revision-1", guid, [4; 32])
                .unwrap()
        });
        let clone_guid = fields.get(5).map(|value| value.parse().unwrap());
        let clone = clone_guid.map(|guid| {
            ResolvedDataset::from_catalog(
                root.clone(),
                "aosproof/aos/project/clone",
                guid,
                [3; 32],
                domains,
            )
            .unwrap()
        });
        let hold_id = HoldId::from_bytes([0xab; 16]).unwrap();
        let initial_space =
            WorkspaceSpacePolicyV1::new(67_108_864, ReservationPolicy::Exact(1_048_576)).unwrap();
        let enlarged_space =
            WorkspaceSpacePolicyV1::new(100_663_296, ReservationPolicy::None).unwrap();

        let (operation, plan) = match action {
            "create" => (
                StorageOperation::CreateWorkspace {
                    quota_bytes: initial_space.refquota_bytes(),
                },
                CatalogPlanV1::CreateWorkspace {
                    destination: PlannedDataset::from_catalog(
                        root,
                        "aosproof/aos/project/workspace",
                        domains,
                    )
                    .unwrap(),
                    space: initial_space,
                    ancestor,
                },
            ),
            "snapshot" => (
                StorageOperation::Snapshot {
                    storage_handle: [2; 32],
                },
                CatalogPlanV1::Snapshot {
                    source: workspace.clone().unwrap(),
                    destination: PlannedSnapshot::from_catalog(
                        workspace.clone().unwrap(),
                        "revision-1",
                    )
                    .unwrap(),
                },
            ),
            "hold" => (
                StorageOperation::HoldSnapshot {
                    storage_handle: [2; 32],
                    version_handle: [4; 32],
                },
                CatalogPlanV1::HoldSnapshot {
                    snapshot: snapshot.clone().unwrap(),
                    hold_id,
                },
            ),
            "clone" => (
                StorageOperation::Clone {
                    storage_handle: [2; 32],
                    version_handle: [4; 32],
                    quota_bytes: initial_space.refquota_bytes(),
                },
                CatalogPlanV1::Clone {
                    source: Box::new(snapshot.clone().unwrap()),
                    origin_hold: ActiveHoldEvidence::from_catalog(
                        snapshot.as_ref().unwrap().guid(),
                        hold_id,
                    )
                    .unwrap(),
                    destination: PlannedDataset::from_catalog(
                        root,
                        "aosproof/aos/project/clone",
                        domains,
                    )
                    .unwrap(),
                    space: initial_space,
                    ancestor,
                },
            ),
            "quota" => (
                StorageOperation::SetQuota {
                    storage_handle: [3; 32],
                    quota_bytes: enlarged_space.refquota_bytes(),
                },
                CatalogPlanV1::SetQuota {
                    dataset: clone.clone().unwrap(),
                    space: enlarged_space,
                    ancestor,
                },
            ),
            "release" => (
                StorageOperation::ReleaseHold {
                    storage_handle: [2; 32],
                    version_handle: [4; 32],
                },
                CatalogPlanV1::ReleaseHold {
                    snapshot: snapshot.clone().unwrap(),
                    hold_id,
                },
            ),
            "destroy-clone" => (
                StorageOperation::Destroy {
                    storage_handle: [3; 32],
                    version_handle: None,
                },
                CatalogPlanV1::DestroyDataset {
                    dataset: clone.unwrap(),
                },
            ),
            "destroy-snapshot" => (
                StorageOperation::Destroy {
                    storage_handle: [2; 32],
                    version_handle: Some([4; 32]),
                },
                CatalogPlanV1::DestroySnapshot {
                    snapshot: snapshot.unwrap(),
                },
            ),
            "destroy-workspace" => (
                StorageOperation::Destroy {
                    storage_handle: [2; 32],
                    version_handle: None,
                },
                CatalogPlanV1::DestroyDataset {
                    dataset: workspace.unwrap(),
                },
            ),
            _ => panic!("unknown worker VM case"),
        };
        let catalog = ResolvedCatalogCommitmentV1::new(7, domains, plan).unwrap();
        let preconditions = executor
            .observe_preconditions(&contract, operation, &catalog)
            .unwrap();
        assert!(matches!(
            preconditions,
            WorkerObservationOutcome::Matched {
                object_guid: None,
                ..
            }
        ));

        let output = executor
            .execute_once(&contract, operation, &catalog)
            .unwrap();
        assert!(
            output.success,
            "ZFS stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.timed_out);

        let postcondition = executor
            .observe_postcondition(&contract, operation, &catalog)
            .unwrap();
        let captures_guid = matches!(action, "create" | "snapshot" | "clone");
        assert!(matches!(
            postcondition,
            WorkerObservationOutcome::Matched { object_guid, .. }
                if object_guid.is_some() == captures_guid
        ));
    }
}
