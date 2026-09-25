//! Authenticated one-transaction OpenZFS process worker.
//!
//! A broker sends canonical resolved-catalog bytes and one closed
//! [`StorageOperation`]. The independently packaged worker reconstructs the
//! catalog, recompiles [`ZfsTransaction`], and invokes only its configured
//! immutable AOS-store executable. Raw argv never crosses the socket.
//!
//! The sole version-one bounded wire sequence is:
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
//! A separate AOSZHS01 request observes a catalogued held snapshot and pool
//! GUID without admitting a mutation or producing a signed SourceRoot receipt.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor,
};
use aos_sandbox_linux::process::{FixedProcessOutcome, FixedProcessRequest, run_fixed_process};
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketError, SeqpacketSocket,
};
use sha2::{Digest as _, Sha256};

use crate::catalog_transition::execution_capture::readback::{
    CaptureZfsPreflightPlanV1, CaptureZfsPreflightV1, CaptureZfsReadbackCommandV1,
    CaptureZfsReadbackPlanV1, CaptureZfsReadbackV1, CaptureZfsToolV1, MAXIMUM_MACHINE_OUTPUT_BYTES,
};
use crate::observation::{
    MAXIMUM_CATALOG_ZFS_STDOUT_BYTES, ZfsObservationPlan, ZfsObservationResult,
    evaluate_workspace_catalog_zfs, workspace_catalog_zfs_arguments,
};
use crate::observation_protocol::WorkspaceCatalogObservationRequestV1;
use crate::{
    ResolvedCatalogCommitmentV1, StorageOperation, ZfsHelperContract, ZfsTransaction,
    ZfsTransactionError,
};

mod held_snapshot;
mod held_snapshot_reader;
mod wire;

pub(crate) use held_snapshot::{HeldSnapshotPhysicalObservationV1, HeldSnapshotWorkerBindingV1};
pub use held_snapshot_reader::run_inherited_held_snapshot_reader;
pub(crate) use held_snapshot_reader::{
    HeldSnapshotReaderObservationV1, SystemdHeldSnapshotReaderV1,
};

use wire::{
    AtomicSnapshotRequestVerbV1, AtomicSnapshotWorkerRequestV1, MAXIMUM_OBSERVATION_RESPONSE_BYTES,
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, WIRE_VERSION, WorkerRequestVerb,
    decode_atomic_snapshot_request, decode_mutation_response, decode_observation_response,
    decode_request, encode_atomic_snapshot_request, encode_mutation_response,
    encode_observation_response, encode_request, is_atomic_snapshot_request,
};

const READY_MAGIC: &[u8; 8] = b"AOSZRDY1";
const ACK_MAGIC: &[u8; 8] = b"AOSZACK1";
const MAXIMUM_READY_BYTES: usize = 4096;
const MAXIMUM_ACK_BYTES: usize = 10;
const MAXIMUM_CGROUP_TEXT_BYTES: usize = 4096;
const MAXIMUM_STDOUT_BYTES: usize = 64 * 1024;
const MAXIMUM_STDERR_BYTES: usize = 64 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(35);
const NATURAL_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(5);
const QUIESCENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const STORAGED_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const WORKER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-zfs-worker@";
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
    /// Protected durable authority did not authorize the requested worker effect.
    #[error("fixed ZFS worker protected authority was rejected")]
    Authority,
    /// A dispatched worker unit could not be proved completely quiescent.
    #[error("fixed ZFS worker whole-unit quiescence failed: {0}")]
    Quiescence(String),
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

/// Runs the capture readback contract with two pinned executables in one deadline.
///
/// This is deliberately not wired to a broker request or physical binding.
/// Only a future dedicated Storage worker may call it after authenticating a
/// Controller create grant and protecting the effect barrier. The pool probe
/// itself cannot prevent a checkpoint from being created after observation.
pub(crate) fn observe_capture_zfs_for(
    zfs: &ZfsHelperContract,
    plan: &CaptureZfsReadbackPlanV1,
) -> Result<CaptureZfsReadbackV1, ZfsWorkerError> {
    let [pool, root, dataset] = run_capture_zfs_observation_commands(zfs, plan.commands())?;
    plan.evaluate([&pool, &root, &dataset])
        .map_err(|_| ZfsWorkerError::Protocol("capture ZFS readback mismatch"))
}

/// Observes checkpoint-free capacity without creating or mounting a dataset.
///
/// This read-only probe is a candidate input, never a Storage grant or a
/// promise that pool state remains unchanged after the result is returned.
pub(crate) fn observe_capture_zfs_preflight_for(
    zfs: &ZfsHelperContract,
    plan: &CaptureZfsPreflightPlanV1,
) -> Result<CaptureZfsPreflightV1, ZfsWorkerError> {
    let [pool, root] = run_capture_zfs_observation_commands(zfs, plan.commands())?;
    plan.evaluate([&pool, &root])
        .map_err(|_| ZfsWorkerError::Protocol("capture ZFS preflight mismatch"))
}

fn run_capture_zfs_observation_commands<const N: usize>(
    zfs: &ZfsHelperContract,
    commands: &[CaptureZfsReadbackCommandV1; N],
) -> Result<[Vec<u8>; N], ZfsWorkerError> {
    let tools = PinnedCaptureZfsTools::new(
        zfs,
        "capture readback requires the fixed AOS zfs executable",
    )?;
    let deadline = Deadline::after(PROCESS_TIMEOUT);
    let mut outputs = Vec::with_capacity(commands.len());

    for command in commands {
        let (contract, pin) = tools.for_tool(command.tool);
        pin.validate_current(contract)?;
        let timeout = deadline.remaining().ok_or(ZfsWorkerError::Protocol(
            "capture readback deadline elapsed",
        ))?;
        let arguments: Vec<OsString> = command.arguments.iter().map(OsString::from).collect();
        let output = run_fixed_process(FixedProcessRequest {
            executable: contract.executable(),
            arguments: &arguments,
            timeout,
            maximum_stdout_bytes: MAXIMUM_MACHINE_OUTPUT_BYTES,
            maximum_stderr_bytes: MAXIMUM_STDERR_BYTES,
        })?;
        match output {
            FixedProcessOutcome::Completed(output)
                if output.exit_code == Some(0)
                    && output.signal.is_none()
                    && output.stderr.is_empty() =>
            {
                outputs.push(output.stdout);
            }
            _ => return Err(ZfsWorkerError::Protocol("capture ZFS readback failed")),
        }
    }

    tools.validate_current()?;
    outputs
        .try_into()
        .map_err(|_| ZfsWorkerError::Protocol("capture ZFS observation is incomplete"))
}

/// Runs one complete host-wide ZFS catalog observation before an absolute deadline.
///
/// This separate path raises only the catalog-observation stdout ceiling. The
/// ordinary transaction observer remains capped at 64 KiB. Only a plan with no
/// authenticated protected roots skips the process; initialized-empty
/// workspace catalogs still observe configured roots and infrastructure.
pub(crate) fn observe_workspace_catalog_zfs_for(
    contract: &ZfsHelperContract,
    request: &WorkspaceCatalogObservationRequestV1,
    deadline_boottime_nanoseconds: u64,
) -> Result<aos_sandbox_core::ObjectDigest, ZfsWorkerError> {
    if request.roots().is_empty() {
        return evaluate_workspace_catalog_zfs(request, &[])
            .map_err(|_| ZfsWorkerError::Protocol("invalid catalog ZFS observation"));
    }
    let timeout = remaining_boottime(deadline_boottime_nanoseconds)?;
    let arguments = workspace_catalog_zfs_arguments();
    let outcome = run_fixed_process(FixedProcessRequest {
        executable: contract.executable(),
        arguments: &arguments,
        timeout,
        maximum_stdout_bytes: MAXIMUM_CATALOG_ZFS_STDOUT_BYTES,
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
            return Err(ZfsWorkerError::Protocol(
                "global catalog ZFS observation command failed",
            ));
        }
        Ok(FixedProcessOutcome::TimedOut) => {
            return Err(ZfsWorkerError::Protocol(
                "global catalog ZFS observation timed out",
            ));
        }
        Ok(FixedProcessOutcome::OutputLimitExceeded) => {
            return Err(ZfsWorkerError::Protocol(
                "global catalog ZFS observation exceeded its ceiling",
            ));
        }
        Err(aos_sandbox_linux::Error::Syscall {
            operation: "spawn fixed process",
            source,
        }) if source.raw_os_error().is_some() => return Err(ZfsWorkerError::Exec(source)),
        Err(error) => return Err(error.into()),
    };
    evaluate_workspace_catalog_zfs(request, &output)
        .map_err(|_| ZfsWorkerError::Protocol("invalid catalog ZFS observation"))
}

fn remaining_boottime(deadline_boottime_nanoseconds: u64) -> Result<Duration, ZfsWorkerError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| ZfsWorkerError::Protocol("CLOCK_BOOTTIME seconds are invalid"))?;
    let nanoseconds = u64::try_from(now.tv_nsec)
        .map_err(|_| ZfsWorkerError::Protocol("CLOCK_BOOTTIME nanoseconds are invalid"))?;
    let now = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(ZfsWorkerError::Protocol("CLOCK_BOOTTIME overflowed"))?;
    deadline_boottime_nanoseconds
        .checked_sub(now)
        .filter(|remaining| *remaining != 0)
        .map(Duration::from_nanos)
        .ok_or(ZfsWorkerError::Protocol(
            "catalog observation deadline elapsed",
        ))
}

/// Executes typed storage transactions through systemd-created one-shot workers.
#[derive(Debug)]
pub struct SystemdZfsExecutor {
    socket_path: PathBuf,
    systemd_manager_cgroup: RetainedCgroupAnchor,
    worker_parent_cgroup: RetainedCgroupAnchor,
    fail_stopped: bool,
}

impl SystemdZfsExecutor {
    /// Reobserves one protected held snapshot through the fixed read-only worker.
    ///
    /// The caller must keep its protected catalog lock across this exchange and
    /// compare the same catalog and authority heads after whole-unit quiescence.
    /// The nonce prevents a reply to an earlier request from being accepted.
    ///
    /// # Errors
    ///
    /// Rejects worker activation, peer or cgroup provenance, malformed or
    /// replayed framing, failed physical readback, and uncertain quiescence.
    pub(crate) fn observe_held_snapshot(
        &mut self,
        contract: &ZfsHelperContract,
        snapshot: &crate::ResolvedSnapshot,
        hold_id: crate::HoldId,
        binding: HeldSnapshotWorkerBindingV1,
    ) -> Result<HeldSnapshotPhysicalObservationV1, ZfsWorkerError> {
        let request = held_snapshot::encode_request(contract, snapshot, hold_id, binding)?;
        let digest = held_snapshot::request_digest(&request);
        let response = self.exchange(request, held_snapshot::RESPONSE_BYTES)?;
        held_snapshot::decode_response(&response, digest)
    }

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
        let worker_parent_cgroup = cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?;
        Ok(Self {
            socket_path,
            systemd_manager_cgroup,
            worker_parent_cgroup,
            fail_stopped: false,
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
        &mut self,
        contract: &ZfsHelperContract,
        operation: StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<WorkerProcessOutput, ZfsWorkerError> {
        let request = encode_request(WorkerRequestVerb::Mutate, contract, operation, catalog)?;
        let response = self.exchange(request, MAXIMUM_RESPONSE_BYTES)?;
        decode_mutation_response(&response)
    }

    /// Executes or observes one exact coordinated multi-dataset snapshot group.
    ///
    /// The mutation form invokes one bounded `zfs snapshot` command containing
    /// every destination. The observation form never mutates and is suitable
    /// only for recovery after durable ambiguous custody.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid protected group, worker authentication,
    /// transport failure, or a failed whole-group GUID readback.
    pub(crate) fn atomic_snapshot_once(
        &mut self,
        contract: &ZfsHelperContract,
        program: &crate::DormantAtomicDatasetSnapshotV1,
        mutate: bool,
    ) -> Result<WorkerProcessOutput, ZfsWorkerError> {
        let verb = if mutate {
            AtomicSnapshotRequestVerbV1::Mutate
        } else {
            AtomicSnapshotRequestVerbV1::Observe
        };
        let request = encode_atomic_snapshot_request(verb, contract, program)?;
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
        &mut self,
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
        &mut self,
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
        &mut self,
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
        &mut self,
        request: Vec<u8>,
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Quiescence(
                "fixed ZFS executor is fail-stopped".to_owned(),
            ));
        }
        let deadline = Deadline::after(CONNECTION_TIMEOUT);
        let mut socket = SeqpacketSocket::connect(&self.socket_path)?;
        verify_systemd_activation_peer(socket.peer(), &self.systemd_manager_cgroup)?;

        let ready = receive_before(&mut socket, MAXIMUM_READY_BYTES, deadline)?;
        let (ready_payload, worker_subject) = ready.into_parts();
        let worker_cgroup = decode_ready(&ready_payload)?;
        let worker_cgroup = verify_worker_peer(
            &worker_subject,
            &self.worker_parent_cgroup,
            Path::new(worker_cgroup),
        )?;
        let population = worker_cgroup.population_monitor()?;
        let exchange = (|| {
            send_before(&mut socket, &request, deadline)?;
            let response = receive_before(&mut socket, maximum_response_bytes, deadline)?;
            verify_same_live_subject(&worker_subject, response.subject())?;
            worker_cgroup.verify_exact_membership(response.subject().pidfd())?;
            let payload = response.payload().to_vec();
            send_before(&mut socket, &encode_ack(), deadline)?;
            Ok(payload)
        })();

        match exchange {
            Ok(payload) => {
                let natural_exit =
                    wait_for_worker_quiescence(&worker_subject, &population, NATURAL_EXIT_TIMEOUT);
                let Err(natural_exit_error) = natural_exit else {
                    return Ok(payload);
                };
                if let Err(cancellation_error) =
                    quiesce_worker(&worker_subject, &worker_cgroup, &population)
                {
                    self.fail_stopped = true;
                    return Err(ZfsWorkerError::Quiescence(format!(
                        "a successful fixed ZFS worker remained live and cancellation was not proved; natural exit: {natural_exit_error}; cancellation: {cancellation_error}"
                    )));
                }
                Err(ZfsWorkerError::Quiescence(format!(
                    "a successful fixed ZFS worker did not terminate cleanly; natural exit: {natural_exit_error}"
                )))
            }
            Err(error) => {
                if let Err(cancellation_error) =
                    quiesce_worker(&worker_subject, &worker_cgroup, &population)
                {
                    self.fail_stopped = true;
                    return Err(ZfsWorkerError::Quiescence(format!(
                        "failed fixed ZFS worker cancellation was not proved; exchange: {error}; cancellation: {cancellation_error}"
                    )));
                }
                Err(error)
            }
        }
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
    // A stable service UID is required because systemd's DynamicUser path
    // forces a seccomp rule incompatible with mandatory openat2 resolution.
    // Disable dumpability before opening or parsing any privileged state so
    // the serialized UID cannot become a ptrace or core-file authority path.
    aos_sandbox_linux::process::disable_core_dumps()?;

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
    if is_atomic_snapshot_request(request.payload()) {
        let request = decode_atomic_snapshot_request(request.payload())?;
        if request.executable != *contract.executable() {
            return Err(ZfsWorkerError::Executable(
                "broker and worker executable contracts differ".to_owned(),
            ));
        }
        _executable_pin.validate_current(&contract)?;
        let output = execute_atomic_snapshot(&contract, &request, deadline)?;
        _executable_pin.validate_current(&contract)?;
        send_before(&mut socket, &encode_mutation_response(&output)?, deadline)?;
        let acknowledgement = receive_before(&mut socket, MAXIMUM_ACK_BYTES, deadline)?;
        verify_same_subject(socket.peer(), acknowledgement.subject())?;
        storaged_cgroup.verify_exact_membership(acknowledgement.subject().pidfd())?;
        decode_ack(acknowledgement.payload())?;
        return Ok(());
    }
    if held_snapshot::is_request(request.payload()) {
        let request = held_snapshot::decode_request(request.payload())?;
        if request.executable != contract {
            return Err(ZfsWorkerError::Executable(
                "broker and worker executable contracts differ".to_owned(),
            ));
        }
        _executable_pin.validate_current(&contract)?;
        let observation = held_snapshot::execute_request(&request, deadline)?;
        _executable_pin.validate_current(&contract)?;
        let response = held_snapshot::encode_response(request.digest, observation);
        send_before(&mut socket, &response, deadline)?;
        let acknowledgement = receive_before(&mut socket, MAXIMUM_ACK_BYTES, deadline)?;
        verify_same_subject(socket.peer(), acknowledgement.subject())?;
        storaged_cgroup.verify_exact_membership(acknowledgement.subject().pidfd())?;
        decode_ack(acknowledgement.payload())?;
        return Ok(());
    }
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

fn execute_atomic_snapshot(
    contract: &ZfsHelperContract,
    request: &AtomicSnapshotWorkerRequestV1,
    deadline: Deadline,
) -> Result<WorkerProcessOutput, ZfsWorkerError> {
    if request.operation == [0; 16]
        || request.snapshot == [0; 16]
        || request.program.as_bytes() == &[0; 32]
    {
        return Err(ZfsWorkerError::Protocol(
            "atomic snapshot program identity is invalid",
        ));
    }
    if request.verb == AtomicSnapshotRequestVerbV1::Mutate {
        require_atomic_snapshot_sources(contract, request, deadline)?;
        let mut arguments = Vec::with_capacity(request.members.len() + 1);
        arguments.push("snapshot".into());
        arguments.extend(
            request
                .members
                .iter()
                .map(|member| OsString::from(&member.destination_name)),
        );
        let output = execute_fixed_arguments(contract, &arguments, deadline)?;
        if !output.success || output.timed_out {
            return Ok(output);
        }
    }
    observe_atomic_snapshot_group(contract, request, deadline)
}

fn require_atomic_snapshot_sources(
    contract: &ZfsHelperContract,
    request: &AtomicSnapshotWorkerRequestV1,
    deadline: Deadline,
) -> Result<(), ZfsWorkerError> {
    let mut arguments = vec![
        "list".into(),
        "-H".into(),
        "-p".into(),
        "-o".into(),
        "name,guid".into(),
    ];
    arguments.extend(
        request
            .members
            .iter()
            .map(|member| OsString::from(&member.source_name)),
    );
    let output = execute_fixed_arguments(contract, &arguments, deadline)?;
    if !output.success || output.timed_out || !output.stderr.is_empty() {
        return Err(ZfsWorkerError::Protocol(
            "atomic snapshot source observation failed",
        ));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| ZfsWorkerError::Protocol("atomic snapshot source rows are not UTF-8"))?;
    let mut observed = text
        .lines()
        .map(|line| {
            let (name, guid) = line.split_once('\t').ok_or(ZfsWorkerError::Protocol(
                "atomic snapshot source row is invalid",
            ))?;
            let guid = guid.parse::<u64>().ok().filter(|guid| *guid != 0).ok_or(
                ZfsWorkerError::Protocol("atomic snapshot source GUID is invalid"),
            )?;
            Ok((name, guid))
        })
        .collect::<Result<Vec<_>, ZfsWorkerError>>()?;
    observed.sort_unstable();
    let mut expected = request
        .members
        .iter()
        .map(|member| (member.source_name.as_str(), member.source_guid))
        .collect::<Vec<_>>();
    expected.sort_unstable();
    if observed != expected {
        return Err(ZfsWorkerError::Protocol(
            "atomic snapshot source GUID set changed",
        ));
    }
    Ok(())
}

fn observe_atomic_snapshot_group(
    contract: &ZfsHelperContract,
    request: &AtomicSnapshotWorkerRequestV1,
    deadline: Deadline,
) -> Result<WorkerProcessOutput, ZfsWorkerError> {
    let mut arguments = vec![
        "list".into(),
        "-H".into(),
        "-p".into(),
        "-o".into(),
        "name,guid".into(),
    ];
    arguments.extend(
        request
            .members
            .iter()
            .map(|member| OsString::from(&member.destination_name)),
    );
    let output = execute_fixed_arguments(contract, &arguments, deadline)?;
    if !output.success || output.timed_out || !output.stderr.is_empty() {
        return Ok(output);
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| ZfsWorkerError::Protocol("atomic snapshot observation is not UTF-8"))?;
    let mut observed = text.lines().collect::<Vec<_>>();
    observed.sort_unstable();
    let mut expected = request
        .members
        .iter()
        .map(|member| member.destination_name.as_str())
        .collect::<Vec<_>>();
    expected.sort_unstable();
    if observed.len() != expected.len() {
        return Err(ZfsWorkerError::Protocol(
            "atomic snapshot observation is incomplete",
        ));
    }
    let mut digest = Sha256::new()
        .chain_update(b"aos.sandbox.storage.atomic-snapshot-observation.v1\0")
        .chain_update(request.program.as_bytes())
        .chain_update((observed.len() as u32).to_be_bytes());
    let mut guids = BTreeMap::new();
    for (line, expected_name) in observed.into_iter().zip(expected) {
        let (name, guid) = line.split_once('\t').ok_or(ZfsWorkerError::Protocol(
            "atomic snapshot observation row is invalid",
        ))?;
        let guid = guid
            .parse::<u64>()
            .ok()
            .filter(|guid| *guid != 0)
            .ok_or(ZfsWorkerError::Protocol("atomic snapshot GUID is invalid"))?;
        if name != expected_name {
            return Err(ZfsWorkerError::Protocol(
                "atomic snapshot observation names a foreign object",
            ));
        }
        digest = digest
            .chain_update(name.as_bytes())
            .chain_update([0])
            .chain_update(guid.to_be_bytes());
        if guids.insert(name, guid).is_some() {
            return Err(ZfsWorkerError::Protocol("atomic snapshot names repeat"));
        }
    }
    let count = u16::try_from(request.members.len())
        .map_err(|_| ZfsWorkerError::Protocol("atomic snapshot group is too large"))?;
    let mut evidence = Vec::with_capacity(42 + request.members.len() * 8);
    evidence.extend_from_slice(b"AOSASO02");
    evidence.extend_from_slice(&digest.finalize());
    evidence.extend_from_slice(&count.to_be_bytes());
    for member in &request.members {
        let guid = guids
            .get(member.destination_name.as_str())
            .ok_or(ZfsWorkerError::Protocol(
                "atomic snapshot member observation is missing",
            ))?;
        evidence.extend_from_slice(&guid.to_be_bytes());
    }
    Ok(WorkerProcessOutput {
        stdout: evidence,
        stderr: Vec::new(),
        success: true,
        timed_out: false,
    })
}

fn execute_fixed_arguments(
    contract: &ZfsHelperContract,
    arguments: &[OsString],
    deadline: Deadline,
) -> Result<WorkerProcessOutput, ZfsWorkerError> {
    let Some(timeout) = deadline.remaining() else {
        return Ok(WorkerProcessOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            success: false,
            timed_out: true,
        });
    };
    match run_fixed_process(FixedProcessRequest {
        executable: contract.executable(),
        arguments,
        timeout,
        maximum_stdout_bytes: MAXIMUM_STDOUT_BYTES,
        maximum_stderr_bytes: MAXIMUM_STDERR_BYTES,
    }) {
        Ok(FixedProcessOutcome::Completed(output)) => Ok(WorkerProcessOutput {
            success: output.exit_code == Some(0) && output.signal.is_none(),
            timed_out: false,
            stdout: output.stdout,
            stderr: output.stderr,
        }),
        Ok(FixedProcessOutcome::TimedOut) => Ok(WorkerProcessOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            success: false,
            timed_out: true,
        }),
        Ok(FixedProcessOutcome::OutputLimitExceeded) => {
            Err(ZfsWorkerError::Protocol("ZFS output exceeded its ceiling"))
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn execute_transaction_for(
    contract: &ZfsHelperContract,
    transaction: &ZfsTransaction,
    timeout: Duration,
) -> Result<WorkerProcessOutput, ZfsWorkerError> {
    execute_transaction(contract, transaction, Deadline::after(timeout))
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

pub(crate) fn observe_transaction_for(
    contract: &ZfsHelperContract,
    transaction: &ZfsTransaction,
    postcondition: bool,
    timeout: Duration,
) -> Result<ZfsObservationResult, ZfsWorkerError> {
    let plan = if postcondition {
        ZfsObservationPlan::postcondition(transaction)
    } else {
        ZfsObservationPlan::preconditions(transaction)
    }
    .map_err(|_| ZfsWorkerError::Protocol("invalid ZFS observation plan"))?;
    execute_observation(contract, &plan, Deadline::after(timeout))
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

pub(crate) struct PinnedExecutable {
    _file: File,
    device: u64,
    inode: u64,
}

/// Retains both fixed capture tools across observation and effect boundaries.
///
/// The caller still selects its own deadline and output policy. Neither tool
/// may be replaced between the first probe and the final identity check.
pub(crate) struct PinnedCaptureZfsTools<'a> {
    zfs: &'a ZfsHelperContract,
    zpool: ZfsHelperContract,
    zfs_pin: PinnedExecutable,
    zpool_pin: PinnedExecutable,
}

impl<'a> PinnedCaptureZfsTools<'a> {
    pub(crate) fn new(
        zfs: &'a ZfsHelperContract,
        invalid_executable: &'static str,
    ) -> Result<Self, ZfsWorkerError> {
        if zfs
            .executable()
            .file_name()
            .is_none_or(|name| name != "zfs")
        {
            return Err(ZfsWorkerError::Executable(invalid_executable.to_owned()));
        }
        let zpool = ZfsHelperContract::new(zfs.executable().with_file_name("zpool"))?;
        let zfs_pin = PinnedExecutable::open(zfs)?;
        let zpool_pin = PinnedExecutable::open(&zpool)?;
        Ok(Self {
            zfs,
            zpool,
            zfs_pin,
            zpool_pin,
        })
    }

    pub(crate) fn for_tool(
        &self,
        tool: CaptureZfsToolV1,
    ) -> (&ZfsHelperContract, &PinnedExecutable) {
        match tool {
            CaptureZfsToolV1::Zpool => (&self.zpool, &self.zpool_pin),
            CaptureZfsToolV1::Zfs => (self.zfs, &self.zfs_pin),
        }
    }

    pub(crate) fn validate_current(&self) -> Result<(), ZfsWorkerError> {
        self.zfs_pin.validate_current(self.zfs)?;
        self.zpool_pin.validate_current(&self.zpool)
    }
}

impl PinnedExecutable {
    pub(crate) fn open(contract: &ZfsHelperContract) -> Result<Self, ZfsWorkerError> {
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

    pub(crate) fn validate_current(
        &self,
        contract: &ZfsHelperContract,
    ) -> Result<(), ZfsWorkerError> {
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
    let path = current_cgroup_path()?;
    validate_worker_cgroup(&path)?;
    Ok(path)
}

fn current_cgroup_path() -> Result<String, ZfsWorkerError> {
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
    parent: &RetainedCgroupAnchor,
    path: &Path,
) -> Result<RetainedCgroupAnchor, ZfsWorkerError> {
    let credentials = subject.credentials();
    if credentials.uid() == 0 || credentials.gid() == 0 {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    let relative = path
        .strip_prefix(CONTROL_SLICE_CGROUP)
        .map_err(|_| ZfsWorkerError::PeerMismatch)?;
    let worker_cgroup = parent.resolve_descendant(relative)?;
    let info = worker_cgroup.verify_exact_membership(subject.pidfd())?;
    if info.pid() != credentials.pid().get() || info.thread_group_id() != credentials.pid().get() {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    parent.validate_current()?;
    Ok(worker_cgroup)
}

fn quiesce_worker(
    subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
    population: &CgroupPopulationMonitor,
) -> Result<(), ZfsWorkerError> {
    if worker_is_quiescent(subject, population)? {
        return Ok(());
    }
    if let Err(kill_error) = worker_cgroup.kill_all() {
        // Systemd can empty or remove the unit cgroup before this write.
        // Accept that race only when exact pidfd death plus the retained
        // monitor proves either an empty active subtree or its retirement.
        return match worker_is_quiescent(subject, population) {
            Ok(true) => Ok(()),
            Ok(false) => Err(kill_error.into()),
            Err(proof_error) => Err(ZfsWorkerError::Quiescence(format!(
                "cgroup kill failed and the quiescence recheck also failed; kill: {kill_error}; recheck: {proof_error}"
            ))),
        };
    }

    wait_for_worker_quiescence(subject, population, QUIESCENCE_TIMEOUT)
}

fn worker_is_quiescent(
    subject: &KernelAuthorizedRecordSubject,
    population: &CgroupPopulationMonitor,
) -> Result<bool, ZfsWorkerError> {
    if subject.pidfd().is_alive()? {
        return Ok(false);
    }
    match population.state()? {
        CgroupPopulationState::Empty | CgroupPopulationState::Retired => Ok(true),
        CgroupPopulationState::Populated => Ok(false),
    }
}

fn wait_for_worker_quiescence(
    subject: &KernelAuthorizedRecordSubject,
    population: &CgroupPopulationMonitor,
    timeout: Duration,
) -> Result<(), ZfsWorkerError> {
    let deadline = Deadline::after(timeout);

    loop {
        if worker_is_quiescent(subject, population)? {
            return Ok(());
        }
        let remaining = deadline.remaining().ok_or(ZfsWorkerError::Quiescence(
            "fixed ZFS worker quiescence deadline elapsed".to_owned(),
        ))?;
        std::thread::sleep(remaining.min(QUIESCENCE_POLL_INTERVAL));
    }
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
            boottime_now()
                .checked_add(duration)
                .unwrap_or(Duration::MAX),
        )
    }

    fn remaining(self) -> Option<Duration> {
        self.0
            .checked_sub(boottime_now())
            .filter(|remaining| !remaining.is_zero())
    }

    fn ensure_pending(self) -> Result<(), ZfsWorkerError> {
        self.remaining().map(|_| ()).ok_or(ZfsWorkerError::Protocol(
            "worker connection deadline elapsed",
        ))
    }
}

fn boottime_now() -> Duration {
    // CLOCK_BOOTTIME includes suspend. A relative poll may wake late after a
    // resume, but the mandatory before/after checks reject that record instead
    // of extending the authorization acceptance window.
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

pub(crate) fn open_cgroup_root() -> Result<CgroupV2Root, ZfsWorkerError> {
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
    use aos_sandbox_protocol::semantics::CatalogBindingV1;

    use super::*;

    use crate::observation::ZfsObservationState;
    use crate::observation_protocol::{
        WorkspaceCatalogCustodyBindingV1, WorkspaceCatalogObservationBindingsV1,
        WorkspaceCatalogObservationRootV1,
    };
    use crate::{
        ActiveHoldEvidence, CatalogPlanV1, HoldId, ManagedDatasetRoot, PlannedDataset,
        PlannedSnapshot, ProjectAncestorPolicyV1, ReservationPolicy, ResolvedDataset,
        ResolvedSnapshot, StorageDomainsV1, WorkspaceSpacePolicyV1,
    };

    #[test]
    fn capture_tools_reject_wrong_leaf_before_opening_store_files() {
        let invalid = ZfsHelperContract::new("/nix/store/hash-zfs/sbin/zpool".into()).unwrap();
        let error = PinnedCaptureZfsTools::new(&invalid, "wrong capture tool")
            .err()
            .unwrap();
        assert!(
            matches!(error, ZfsWorkerError::Executable(message) if message == "wrong capture tool")
        );

        let missing = ZfsHelperContract::new("/nix/store/hash-zfs/sbin/zfs".into()).unwrap();
        assert!(matches!(
            PinnedCaptureZfsTools::new(&missing, "wrong capture tool"),
            Err(ZfsWorkerError::Io(_))
        ));
    }

    fn socket_pair() -> (SeqpacketSocket, SeqpacketSocket) {
        let (left, right) = SeqpacketSocket::pair_with_record_subjects().unwrap();
        (left, SeqpacketSocket::from_owned(right).unwrap())
    }

    fn catalog_observation_request(
        roots: Vec<WorkspaceCatalogObservationRootV1>,
    ) -> WorkspaceCatalogObservationRequestV1 {
        WorkspaceCatalogObservationRequestV1::new(
            [1; 32],
            1,
            WorkspaceCatalogObservationBindingsV1::new(
                ObjectDigest::from_bytes([2; 32]),
                [3; 16],
                4,
                ObjectDigest::from_bytes([5; 32]),
                ObjectDigest::from_bytes([6; 32]),
                7,
                ObjectDigest::from_bytes([8; 32]),
                9,
                ObjectDigest::from_bytes([10; 32]),
                11,
                65_536,
                65_536,
            )
            .unwrap(),
            WorkspaceCatalogCustodyBindingV1::new([12; 16], 13, 14, 15, 16, 17).unwrap(),
            roots,
            Vec::new(),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn only_a_plan_without_protected_roots_skips_global_zfs() {
        let contract = ZfsHelperContract::new(PathBuf::from(
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-zfs/bin/zfs",
        ))
        .unwrap();
        let unconfigured = catalog_observation_request(Vec::new());
        let configured_empty = catalog_observation_request(vec![
            WorkspaceCatalogObservationRootV1::new("tank/aos".to_owned(), 18).unwrap(),
        ]);

        assert!(observe_workspace_catalog_zfs_for(&contract, &unconfigured, 1).is_ok());
        assert!(matches!(
            observe_workspace_catalog_zfs_for(&contract, &configured_empty, 1),
            Err(ZfsWorkerError::Protocol(
                "catalog observation deadline elapsed"
            ))
        ));
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
            ResolvedCatalogCommitmentV1::new_for_test(
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
    fn worker_cgroup_requires_the_exact_systemd_slice_hierarchy() {
        let expected = "aos.slice/aos-control.slice/aos-sandbox-zfs-worker@trusted.service";
        validate_worker_cgroup(expected).unwrap();

        for substituted in [
            "aos-control.slice/aos-sandbox-zfs-worker@trusted.service",
            "aos.slice/alternate.slice/aos-sandbox-zfs-worker@trusted.service",
            "aos.slice/aos-control.slice/alternate/aos-sandbox-zfs-worker@trusted.service",
        ] {
            assert!(matches!(
                validate_worker_cgroup(substituted),
                Err(ZfsWorkerError::PeerMismatch)
            ));
        }
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
        let mut executor = SystemdZfsExecutor::new(
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
            let catalog = ResolvedCatalogCommitmentV1::new_for_test(
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
        if action == "held" {
            let variant = *fields.get(6).unwrap();
            let expected_pool_guid = fields.get(5).unwrap().parse::<u64>().unwrap();
            let nonce_byte = fields.get(7).unwrap().parse::<u8>().unwrap();
            let selected_snapshot = match variant {
                "wrong-snapshot" => ResolvedSnapshot::from_catalog(
                    workspace.clone().unwrap(),
                    "revision-1",
                    snapshot_guid.unwrap().checked_add(1).unwrap_or(1),
                    [4; 32],
                )
                .unwrap(),
                _ => snapshot.unwrap(),
            };
            let selected_hold = if variant == "wrong-hold" {
                HoldId::from_bytes([0xcd; 16]).unwrap()
            } else {
                HoldId::from_bytes([0xab; 16]).unwrap()
            };
            let binding = HeldSnapshotWorkerBindingV1 {
                pool_guid: if variant == "wrong-pool" {
                    expected_pool_guid.checked_add(1).unwrap_or(1)
                } else {
                    expected_pool_guid
                },
                catalog: CatalogBindingV1::from_publisher(17, ObjectDigest::from_bytes([8; 32]))
                    .unwrap(),
                authority_sequence: 23,
                nonce: [nonce_byte; 16],
            };
            let observation = executor.observe_held_snapshot(
                &contract,
                &selected_snapshot,
                selected_hold,
                binding,
            );
            match variant {
                "matched" => assert!(matches!(
                    observation,
                    Ok(HeldSnapshotPhysicalObservationV1::Matched { pool_guid, digest })
                        if pool_guid == expected_pool_guid && digest.as_bytes() != &[0; 32]
                )),
                "wrong-pool" | "wrong-snapshot" | "wrong-hold" | "missing-hold" | "gone" => {
                    assert_eq!(
                        observation.unwrap(),
                        HeldSnapshotPhysicalObservationV1::Mismatch
                    );
                }
                _ => panic!("unknown held-snapshot VM case"),
            }
            return;
        }
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
        let catalog = ResolvedCatalogCommitmentV1::new_for_test(7, domains, plan).unwrap();
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
