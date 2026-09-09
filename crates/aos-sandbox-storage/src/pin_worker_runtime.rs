//! Fixed privileged execution for authenticated workspace root-pin attempts.
//!
//! The broker retains serialization while this one-shot service independently
//! authenticates protected records, enters the transferred initial mount
//! namespace, verifies the exact transferred pin root, and performs at most one
//! attempt. A root-owned replay claim is durable before the first target
//! mutation. Any failure thereafter remains observation-only.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aos_sandbox_core::{ObjectDigest, RawClockProvenance, RawPairedClockSample};
use aos_sandbox_linux::cgroup::{
    CgroupPopulationMonitor, CgroupPopulationState, CgroupV2Root, RetainedCgroupAnchor,
};
use aos_sandbox_linux::mount::{FileSystemContext, MountAttributes, unmount_child};
use aos_sandbox_linux::path::{BeneathRoot, ResolveOptions, ResolvedPath};
use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, SingleThreadedProcess};
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, KernelAuthorizedRecordSubject, SeqpacketError,
};
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};

use crate::authorization::StorageProtectedConfigurationV1;
use crate::observation::ZfsObservationState;
use crate::pin_observer::{
    WorkspacePinHostCustody, WorkspacePinObserverError, current_host_scope, observe_workspace_pin,
    observe_workspace_pin_repair, open_workspace_slot, validate_host_scope,
};
use crate::pin_worker::{
    AuthenticatedWorkspacePinWorkerRequestV1, MAXIMUM_PIN_WORKER_RESULT_BYTES,
    WorkspacePinWorkerResultV1, boottime_now_nanoseconds, decode_request, decode_result,
    encode_result, ensure_before_deadline, receive_request_before, send_request_before,
    verify_same_live_subject, wait_before,
};
use crate::process::{
    PinnedExecutable, execute_transaction_for, observe_transaction_for, open_cgroup_root,
};
use crate::workspace_pin::{
    WorkspaceDatasetObservationV1, WorkspacePinActionV1, WorkspacePinObservationV1,
    workspace_pin_path,
};
use crate::workspace_repair::WorkspacePinRepairProbeV1;
use crate::workspace_repair_observer::{
    WorkspacePinRepairObserverResultV1, decode_request as decode_repair_observer_request,
    decode_result as decode_repair_observer_result, encode_result as encode_repair_observer_result,
    is_repair_request,
};
use crate::{StorageAdmissionError, ZfsHelperContract, ZfsTransaction, ZfsWorkerError};

const READY_MAGIC: &[u8; 8] = b"AOSZPRD1";
const ACK: &[u8; 10] = b"AOSZPACK\0\x01";
const MAXIMUM_READY_BYTES: usize = 4096;
const MAXIMUM_CGROUP_BYTES: usize = 4096;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);
const QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(5);
const NATURAL_EXIT_TIMEOUT: Duration = Duration::from_secs(1);
const QUIESCENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAXIMUM_RECOVERED_WORKER_CGROUPS: usize = 128;
const EFFECT_PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const OBSERVATION_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(35);
const SYSTEMD_MANAGER_CGROUP: &str = "init.scope";
const CONTROL_SLICE_CGROUP: &str = "aos.slice/aos-control.slice";
const STORAGED_CGROUP: &str = "aos.slice/aos-control.slice/aos-storaged.service";
const WORKER_CGROUP_PREFIX: &str = "aos.slice/aos-control.slice/aos-sandbox-workspace-pin-worker@";
const OBSERVER_CGROUP_PREFIX: &str =
    "aos.slice/aos-control.slice/aos-sandbox-workspace-pin-observer@";
const WORKER_CGROUP_SUFFIX: &str = ".service";
const WORKER_CGROUP_BASENAME_PREFIX: &str = "aos-sandbox-workspace-pin-worker@";
const OBSERVER_CGROUP_BASENAME_PREFIX: &str = "aos-sandbox-workspace-pin-observer@";
const GENERIC_WORKER_CGROUP_BASENAME_PREFIX: &str = "aos-sandbox-zfs-worker@";
const SERIALIZATION_LOCK: &str = "serialization.lock";

#[derive(Clone, Copy)]
enum WorkspacePinServiceRole {
    Effect,
    Observer,
}

impl WorkspacePinServiceRole {
    const fn cgroup_prefix(self) -> &'static str {
        match self {
            Self::Effect => WORKER_CGROUP_PREFIX,
            Self::Observer => OBSERVER_CGROUP_PREFIX,
        }
    }
}

/// Executes authenticated pin attempts through root-owned systemd workers.
pub(crate) struct SystemdWorkspacePinExecutor {
    socket_path: PathBuf,
    systemd_manager_cgroup: RetainedCgroupAnchor,
    worker_parent_cgroup: RetainedCgroupAnchor,
    role: WorkspacePinServiceRole,
    fail_stopped: bool,
}

impl SystemdWorkspacePinExecutor {
    pub(crate) fn new(
        socket_path: PathBuf,
        cgroup_root: CgroupV2Root,
    ) -> Result<Self, ZfsWorkerError> {
        Self::new_for_role(socket_path, cgroup_root, WorkspacePinServiceRole::Effect)
    }

    fn new_for_role(
        socket_path: PathBuf,
        cgroup_root: CgroupV2Root,
        role: WorkspacePinServiceRole,
    ) -> Result<Self, ZfsWorkerError> {
        if !normalized_absolute_path(&socket_path) {
            return Err(ZfsWorkerError::Protocol(
                "unsafe workspace pin worker socket path",
            ));
        }
        Ok(Self {
            socket_path,
            systemd_manager_cgroup: cgroup_root.resolve(Path::new(SYSTEMD_MANAGER_CGROUP))?,
            worker_parent_cgroup: cgroup_root.resolve(Path::new(CONTROL_SLICE_CGROUP))?,
            role,
            fail_stopped: false,
        })
    }

    pub(crate) fn execute(
        &mut self,
        request: &[u8],
        attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
        custody: &WorkspacePinHostCustody,
    ) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
        self.exchange(
            request,
            attempt,
            custody,
            attempt.effect_deadline_boottime_nanoseconds(),
        )
    }

    fn exchange(
        &mut self,
        request: &[u8],
        attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
        custody: &WorkspacePinHostCustody,
        exchange_deadline: u64,
    ) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin executor is fail-stopped",
            ));
        }
        let mut socket = DescriptorSubjectSocket::connect(&self.socket_path)?;
        verify_systemd_peer(socket.peer(), &self.systemd_manager_cgroup)?;
        let ready_deadline = transfer_deadline()?;
        let ready = receive_packet_before(&mut socket, MAXIMUM_READY_BYTES, ready_deadline)?;
        let worker_path = decode_ready(ready.payload(), self.role)?;
        let worker_cgroup = verify_worker_subject(
            ready.subject(),
            &self.worker_parent_cgroup,
            Path::new(worker_path),
            self.role,
        )?;
        let population = worker_cgroup.population_monitor()?;

        let exchange = exchange_after_ready(
            &mut socket,
            request,
            attempt,
            custody,
            ready.subject(),
            &worker_cgroup,
            exchange_deadline,
        );
        self.finish_exchange(exchange, ready.subject(), &worker_cgroup, &population)
    }

    fn exchange_repair(
        &mut self,
        request: &[u8],
        attempt_id: [u8; 16],
        probe_digest: ObjectDigest,
        custody: &WorkspacePinHostCustody,
        exchange_deadline: u64,
    ) -> Result<WorkspacePinRepairObserverResultV1, ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Protocol(
                "workspace pin executor is fail-stopped",
            ));
        }
        let mut socket = DescriptorSubjectSocket::connect(&self.socket_path)?;
        verify_systemd_peer(socket.peer(), &self.systemd_manager_cgroup)?;
        let ready_deadline = transfer_deadline()?;
        let ready = receive_packet_before(&mut socket, MAXIMUM_READY_BYTES, ready_deadline)?;
        let worker_path = decode_ready(ready.payload(), self.role)?;
        let worker_cgroup = verify_worker_subject(
            ready.subject(),
            &self.worker_parent_cgroup,
            Path::new(worker_path),
            self.role,
        )?;
        let population = worker_cgroup.population_monitor()?;
        let exchange = exchange_repair_after_ready(
            &mut socket,
            request,
            attempt_id,
            probe_digest,
            custody,
            ready.subject(),
            &worker_cgroup,
            exchange_deadline,
        );
        self.finish_exchange(exchange, ready.subject(), &worker_cgroup, &population)
    }

    fn finish_exchange<T>(
        &mut self,
        exchange: Result<T, ZfsWorkerError>,
        subject: &KernelAuthorizedRecordSubject,
        worker_cgroup: &RetainedCgroupAnchor,
        population: &CgroupPopulationMonitor,
    ) -> Result<T, ZfsWorkerError> {
        match exchange {
            Ok(result) => {
                let natural_exit =
                    wait_for_worker_quiescence(subject, population, NATURAL_EXIT_TIMEOUT);
                let Err(natural_exit_error) = natural_exit else {
                    return Ok(result);
                };
                if let Err(cancellation_error) = quiesce_worker(subject, worker_cgroup, population)
                {
                    self.fail_stopped = true;
                    return Err(ZfsWorkerError::Quiescence(format!(
                        "a successful worker result remained live and cancellation was not proved; natural exit: {natural_exit_error}; cancellation: {cancellation_error}"
                    )));
                }
                Err(ZfsWorkerError::Quiescence(format!(
                    "a successful worker result did not terminate cleanly; natural exit: {natural_exit_error}"
                )))
            }
            Err(error) => {
                if let Err(cancellation_error) = quiesce_worker(subject, worker_cgroup, population)
                {
                    // Releasing broker serialization without whole-unit
                    // quiescence could overlap a still-running ZFS child with
                    // a later attempt.
                    self.fail_stopped = true;
                    return Err(ZfsWorkerError::Quiescence(format!(
                        "failed worker cancellation was not proved; exchange: {error}; cancellation: {cancellation_error}"
                    )));
                }
                Err(error)
            }
        }
    }

    /// Cancels every recovered Storage-worker cgroup before any state observation.
    ///
    /// The caller already owns the exclusive Storage journal lock, so no
    /// admitted request can create a new worker. A systemd socket activation
    /// may create a cgroup before READY, but that worker has no authenticated
    /// request and therefore cannot mutate. Two bounded scans cancel populated
    /// root-pin and generic ZFS remnants, and a final scan proves both reserved
    /// worker scopes empty. Any error permanently fail-stops this executor.
    pub(crate) fn recover_quiescence(&mut self) -> Result<(), ZfsWorkerError> {
        if self.fail_stopped {
            return Err(ZfsWorkerError::Quiescence(
                "workspace pin executor is fail-stopped".to_owned(),
            ));
        }
        let recovery = (|| {
            for _ in 0..2 {
                let workers = enumerate_worker_cgroups(&self.worker_parent_cgroup)?;
                for worker in workers {
                    let population = worker.population_monitor()?;
                    if population.state()? == CgroupPopulationState::Populated {
                        quiesce_cgroup(&worker, &population)?;
                    }
                }
            }
            if enumerate_worker_cgroups(&self.worker_parent_cgroup)?
                .into_iter()
                .map(|worker| {
                    let population = worker.population_monitor()?;
                    population.state()
                })
                .collect::<Result<Vec<_>, aos_sandbox_linux::Error>>()?
                .into_iter()
                .any(|state| state == CgroupPopulationState::Populated)
            {
                return Err(ZfsWorkerError::Quiescence(
                    "a recovered workspace pin worker cgroup remained populated".to_owned(),
                ));
            }
            Ok(())
        })();
        if recovery.is_err() {
            self.fail_stopped = true;
        }
        recovery
    }
}

/// Executes only authenticated, descriptor-backed pin observations.
pub(crate) struct SystemdWorkspacePinObserver {
    client: SystemdWorkspacePinExecutor,
}

impl SystemdWorkspacePinObserver {
    pub(crate) fn new(
        socket_path: PathBuf,
        cgroup_root: CgroupV2Root,
    ) -> Result<Self, ZfsWorkerError> {
        Ok(Self {
            client: SystemdWorkspacePinExecutor::new_for_role(
                socket_path,
                cgroup_root,
                WorkspacePinServiceRole::Observer,
            )?,
        })
    }

    pub(crate) fn observe(
        &mut self,
        request: &[u8],
        attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
        custody: &WorkspacePinHostCustody,
    ) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
        let deadline = quiescence_deadline(OBSERVATION_TRANSACTION_TIMEOUT)?;
        self.client.exchange(request, attempt, custody, deadline)
    }

    pub(crate) fn observe_repair(
        &mut self,
        request: &[u8],
        attempt_id: [u8; 16],
        probe_digest: ObjectDigest,
        custody: &WorkspacePinHostCustody,
    ) -> Result<WorkspacePinRepairObserverResultV1, ZfsWorkerError> {
        let deadline = quiescence_deadline(OBSERVATION_TRANSACTION_TIMEOUT)?;
        self.client
            .exchange_repair(request, attempt_id, probe_digest, custody, deadline)
    }
}

fn exchange_after_ready(
    socket: &mut DescriptorSubjectSocket,
    request: &[u8],
    attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
    custody: &WorkspacePinHostCustody,
    ready_subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
    exchange_deadline: u64,
) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
    send_request_before(
        socket,
        request,
        [
            custody.mount_namespace().as_fd(),
            custody.pin_root().as_fd(),
        ],
        exchange_deadline,
    )?;
    let response =
        receive_packet_before(socket, MAXIMUM_PIN_WORKER_RESULT_BYTES, exchange_deadline)?;
    verify_same_live_subject(ready_subject, response.subject())?;
    verify_exact_worker_subject(response.subject(), worker_cgroup)?;
    let result = decode_result(response.payload())?;
    if result.attempt_id() != attempt.attempt_id() {
        return Err(ZfsWorkerError::Authority);
    }
    send_packet_before(socket, ACK, exchange_deadline)?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn exchange_repair_after_ready(
    socket: &mut DescriptorSubjectSocket,
    request: &[u8],
    attempt_id: [u8; 16],
    probe_digest: ObjectDigest,
    custody: &WorkspacePinHostCustody,
    ready_subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
    exchange_deadline: u64,
) -> Result<WorkspacePinRepairObserverResultV1, ZfsWorkerError> {
    send_request_before(
        socket,
        request,
        [
            custody.mount_namespace().as_fd(),
            custody.pin_root().as_fd(),
        ],
        exchange_deadline,
    )?;
    let response =
        receive_packet_before(socket, MAXIMUM_PIN_WORKER_RESULT_BYTES, exchange_deadline)?;
    verify_same_live_subject(ready_subject, response.subject())?;
    verify_exact_worker_subject(response.subject(), worker_cgroup)?;
    let result = decode_repair_observer_result(response.payload())?;
    if result.observation().attempt_id() != attempt_id || result.probe_digest() != probe_digest {
        return Err(ZfsWorkerError::Authority);
    }
    send_packet_before(socket, ACK, exchange_deadline)?;
    Ok(result)
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
    let deadline = quiescence_deadline(timeout)?;

    loop {
        let worker_alive = subject.pidfd().is_alive()?;
        let population_state = population.state()?;
        if !worker_alive
            && matches!(
                population_state,
                CgroupPopulationState::Empty | CgroupPopulationState::Retired
            )
        {
            return Ok(());
        }

        let remaining = deadline
            .checked_sub(boottime_now_nanoseconds()?)
            .filter(|remaining| *remaining != 0)
            .ok_or(ZfsWorkerError::Protocol(
                "workspace pin worker quiescence deadline elapsed",
            ))?;
        if worker_alive {
            wait_before(
                subject.pidfd().as_fd(),
                rustix::event::PollFlags::IN | rustix::event::PollFlags::RDNORM,
                deadline,
            )?;
        } else {
            std::thread::sleep(Duration::from_nanos(remaining).min(QUIESCENCE_POLL_INTERVAL));
        }
    }
}

fn quiesce_cgroup(
    worker_cgroup: &RetainedCgroupAnchor,
    population: &CgroupPopulationMonitor,
) -> Result<(), ZfsWorkerError> {
    if population.state()? != CgroupPopulationState::Populated {
        return Ok(());
    }
    worker_cgroup.kill_all()?;
    let deadline = quiescence_deadline(QUIESCENCE_TIMEOUT)?;
    while population.state()? == CgroupPopulationState::Populated {
        let remaining = deadline
            .checked_sub(boottime_now_nanoseconds()?)
            .filter(|remaining| *remaining != 0)
            .ok_or(ZfsWorkerError::Quiescence(
                "recovered worker cgroup cancellation timed out".to_owned(),
            ))?;
        std::thread::sleep(Duration::from_nanos(remaining).min(QUIESCENCE_POLL_INTERVAL));
    }
    Ok(())
}

fn quiescence_deadline(timeout: Duration) -> Result<u64, ZfsWorkerError> {
    boottime_now_nanoseconds()?
        .checked_add(timeout.as_nanos() as u64)
        .ok_or(ZfsWorkerError::Protocol(
            "workspace pin quiescence deadline overflowed",
        ))
}

fn enumerate_worker_cgroups(
    parent: &RetainedCgroupAnchor,
) -> Result<Vec<RetainedCgroupAnchor>, ZfsWorkerError> {
    let directory = PathBuf::from(format!("/proc/self/fd/{}", parent.as_fd().as_raw_fd()));
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| ZfsWorkerError::PeerMismatch)?;
        if (name.starts_with(WORKER_CGROUP_BASENAME_PREFIX)
            || name.starts_with(OBSERVER_CGROUP_BASENAME_PREFIX)
            || name.starts_with(GENERIC_WORKER_CGROUP_BASENAME_PREFIX))
            && name.ends_with(WORKER_CGROUP_SUFFIX)
        {
            let full = format!("{CONTROL_SLICE_CGROUP}/{name}");
            validate_recovered_worker_cgroup(&full)?;
            names.push(name);
            if names.len() > MAXIMUM_RECOVERED_WORKER_CGROUPS {
                return Err(ZfsWorkerError::Quiescence(
                    "recovered workspace pin worker cgroup count exceeded its ceiling".to_owned(),
                ));
            }
        }
    }
    names.sort_unstable();
    names
        .into_iter()
        .map(|name| {
            parent
                .resolve_descendant(Path::new(&name))
                .map_err(Into::into)
        })
        .collect()
}

fn validate_recovered_worker_cgroup(path: &str) -> Result<(), ZfsWorkerError> {
    if path.starts_with(WORKER_CGROUP_PREFIX) {
        return validate_worker_cgroup(path, WorkspacePinServiceRole::Effect);
    }
    if path.starts_with(OBSERVER_CGROUP_PREFIX) {
        return validate_worker_cgroup(path, WorkspacePinServiceRole::Observer);
    }
    let instance = path
        .strip_prefix("aos.slice/aos-control.slice/aos-sandbox-zfs-worker@")
        .and_then(|path| path.strip_suffix(WORKER_CGROUP_SUFFIX))
        .filter(|instance| !instance.is_empty() && instance.len() <= 255 && !instance.contains('/'))
        .ok_or(ZfsWorkerError::PeerMismatch)?;
    if instance == "." || instance == ".." {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

/// Runs one inherited, root-privileged workspace pin worker transaction.
///
/// # Errors
///
/// Returns an error unless protected configuration, sender identity, every
/// authority record, both descriptor roles, the replay ledger, ZFS identity,
/// and the exact mount effect all validate.
pub fn run_inherited_workspace_pin_worker(
    configured_zfs: PathBuf,
    authority_directory: &Path,
    replay_directory: &Path,
) -> Result<(), ZfsWorkerError> {
    let contract = ZfsHelperContract::new(configured_zfs)
        .map_err(|error| ZfsWorkerError::Executable(error.to_string()))?;
    let executable_pin = PinnedExecutable::open(&contract)?;
    let protected = StorageProtectedConfigurationV1::from_protected_directory(authority_directory)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let cgroup_root = open_cgroup_root()?;
    let storaged_cgroup = cgroup_root.resolve(Path::new(STORAGED_CGROUP))?;
    let replay = ReplayLedger::open(replay_directory)?;
    let single_threaded = SingleThreadedProcess::verify()?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;

    let ready_deadline = transfer_deadline()?;
    send_packet_before(
        &mut socket,
        &encode_ready(&current_cgroup()?, WorkspacePinServiceRole::Effect)?,
        ready_deadline,
    )?;
    let received = receive_request_before(&mut socket, ready_deadline)?;
    verify_storaged_subject(&received.subject, &storaged_cgroup)?;
    let request = decode_request(&received.bytes)?;
    let authenticated = protected.authenticate_workspace_pin_worker_request(&contract, request)?;
    let [mount_namespace, pin_root]: [OwnedFd; 2] = received
        .descriptors
        .try_into()
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin descriptor roles are invalid"))?;
    let mount_namespace = NamespaceFd::from_owned(mount_namespace, NamespaceKind::Mount)?;
    let pin_root = ResolvedPath::from_inherited(pin_root)?;

    mount_namespace.enter(&single_threaded)?;
    validate_host_scope(authenticated.attempt(), &mount_namespace, &pin_root)
        .map_err(map_observer_error)?;
    executable_pin.validate_current(&contract)?;
    let _serialization = replay.lock(authenticated.effect_deadline_boottime_nanoseconds())?;
    let result = execute_authenticated(
        &protected,
        &contract,
        &executable_pin,
        &replay,
        authenticated,
        &mount_namespace,
        &pin_root,
        &single_threaded,
    )?;
    executable_pin.validate_current(&contract)?;

    let response_deadline = transfer_deadline()?;
    send_packet_before(&mut socket, &encode_result(&result)?, response_deadline)?;
    let acknowledgement = receive_packet_before(&mut socket, ACK.len(), response_deadline)?;
    verify_same_live_subject(&received.subject, acknowledgement.subject())?;
    verify_storaged_subject(acknowledgement.subject(), &storaged_cgroup)?;
    if acknowledgement.payload() != ACK {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin acknowledgement is invalid",
        ));
    }
    Ok(())
}

/// Runs one independently authenticated observation-only pin helper.
///
/// The helper has no replay ledger, no protected-clock effect gate, and no
/// call path to mount or ZFS mutation. It enters only the transferred retained
/// host mount namespace and returns typed read-only ZFS and mount evidence.
///
/// # Errors
///
/// Returns an error unless the historical receipt/effect/catalog links,
/// sender identity, descriptor roles, fixed ZFS executable, host scope, and
/// complete observations all validate within one bounded transaction.
pub fn run_inherited_workspace_pin_observer(
    configured_zfs: PathBuf,
    authority_directory: &Path,
) -> Result<(), ZfsWorkerError> {
    let contract = ZfsHelperContract::new(configured_zfs)
        .map_err(|error| ZfsWorkerError::Executable(error.to_string()))?;
    let executable_pin = PinnedExecutable::open(&contract)?;
    let protected = StorageProtectedConfigurationV1::from_protected_directory(authority_directory)
        .map_err(|_| ZfsWorkerError::Authority)?;
    let cgroup_root = open_cgroup_root()?;
    let storaged_cgroup = cgroup_root.resolve(Path::new(STORAGED_CGROUP))?;
    let single_threaded = SingleThreadedProcess::verify()?;
    let descriptor: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())?;
    let mut socket = DescriptorSubjectSocket::from_owned(descriptor)?;
    let transaction_deadline = quiescence_deadline(OBSERVATION_TRANSACTION_TIMEOUT)?;

    send_packet_before(
        &mut socket,
        &encode_ready(&current_cgroup()?, WorkspacePinServiceRole::Observer)?,
        transaction_deadline,
    )?;
    let received = receive_request_before(&mut socket, transaction_deadline)?;
    verify_storaged_subject(&received.subject, &storaged_cgroup)?;
    let repair_request = if is_repair_request(&received.bytes) {
        Some(decode_repair_observer_request(&received.bytes)?)
    } else {
        None
    };
    let ordinary_request = if repair_request.is_none() {
        Some(protected.authenticate_workspace_pin_observation_request(
            &contract,
            decode_request(&received.bytes)?,
        )?)
    } else {
        None
    };
    let [mount_namespace, pin_root]: [OwnedFd; 2] = received
        .descriptors
        .try_into()
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin descriptor roles are invalid"))?;
    let mount_namespace = NamespaceFd::from_owned(mount_namespace, NamespaceKind::Mount)?;
    let pin_root = ResolvedPath::from_inherited(pin_root)?;

    mount_namespace.enter(&single_threaded)?;
    executable_pin.validate_current(&contract)?;
    let encoded_result = if let Some(request) = repair_request {
        let current_scope =
            current_host_scope(&mount_namespace, &pin_root).map_err(map_observer_error)?;
        let authenticated = protected.authenticate_workspace_pin_repair_observation_request(
            &contract,
            request,
            current_scope,
        )?;
        let transaction = ZfsTransaction::from_catalog(
            authenticated.catalog().plan().operation(),
            authenticated.catalog(),
        )?;
        let (dataset, observation_digest) = observe_repair_dataset_until(
            &contract,
            &transaction,
            authenticated.probe(),
            transaction_deadline,
        )?;
        let pin = observe_workspace_pin_repair(
            authenticated.probe(),
            &dataset,
            &mount_namespace,
            &pin_root,
        )
        .map_err(map_observer_error)?;
        executable_pin.validate_current(&contract)?;
        let observation = WorkspacePinWorkerResultV1::new(
            authenticated.attempt().attempt_id(),
            dataset,
            pin,
            required_observation_digest(observation_digest)?,
        );
        encode_repair_observer_result(&WorkspacePinRepairObserverResultV1::new(
            authenticated.probe().digest(),
            observation,
        ))?
    } else {
        let authenticated = ordinary_request.ok_or(ZfsWorkerError::Protocol(
            "workspace pin observer request classification was lost",
        ))?;
        validate_host_scope(authenticated.attempt(), &mount_namespace, &pin_root)
            .map_err(map_observer_error)?;
        let transaction = ZfsTransaction::from_catalog(
            authenticated.request().catalog.plan().operation(),
            &authenticated.request().catalog,
        )?;
        let (dataset, observation_digest) = observe_dataset_until(
            &contract,
            &transaction,
            authenticated.attempt(),
            true,
            transaction_deadline,
        )?;
        let pin = observe_workspace_pin(
            authenticated.attempt(),
            &dataset,
            &mount_namespace,
            &pin_root,
        )
        .map_err(map_observer_error)?;
        executable_pin.validate_current(&contract)?;
        encode_result(&WorkspacePinWorkerResultV1::new(
            authenticated.attempt().attempt_id(),
            dataset,
            pin,
            required_observation_digest(observation_digest)?,
        ))?
    };

    send_packet_before(&mut socket, &encoded_result, transaction_deadline)?;
    let acknowledgement = receive_packet_before(&mut socket, ACK.len(), transaction_deadline)?;
    verify_same_live_subject(&received.subject, acknowledgement.subject())?;
    verify_storaged_subject(acknowledgement.subject(), &storaged_cgroup)?;
    if acknowledgement.payload() != ACK {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin acknowledgement is invalid",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_authenticated(
    protected: &StorageProtectedConfigurationV1,
    contract: &ZfsHelperContract,
    executable_pin: &PinnedExecutable,
    replay: &ReplayLedger,
    request: AuthenticatedWorkspacePinWorkerRequestV1,
    mount_namespace: &NamespaceFd,
    pin_root: &ResolvedPath,
    single_threaded: &SingleThreadedProcess,
) -> Result<WorkspacePinWorkerResultV1, ZfsWorkerError> {
    let attempt = request.attempt();
    let transaction = ZfsTransaction::from_catalog(
        request.request().catalog.plan().operation(),
        &request.request().catalog,
    )?;
    let (dataset_before, observation_before) = observe_dataset_until(
        contract,
        &transaction,
        attempt,
        false,
        attempt.effect_deadline_boottime_nanoseconds(),
    )?;
    let pin_before = observe_workspace_pin(attempt, &dataset_before, mount_namespace, pin_root)
        .map_err(map_observer_error)?;

    match attempt.action() {
        WorkspacePinActionV1::Ensure => {
            if matches!(
                (&dataset_before, &pin_before),
                (
                    WorkspaceDatasetObservationV1::Exact { .. },
                    WorkspacePinObservationV1::Present(_)
                )
            ) {
                return Ok(WorkspacePinWorkerResultV1::new(
                    attempt.attempt_id(),
                    dataset_before,
                    pin_before,
                    required_observation_digest(observation_before)?,
                ));
            }
            if !matches!(dataset_before, WorkspaceDatasetObservationV1::Exact { .. })
                || pin_before != WorkspacePinObservationV1::Absent
            {
                return Err(ZfsWorkerError::Authority);
            }

            check_immediately_before_effect(protected, &request)?;
            let _claim = replay.claim(attempt.attempt_id())?;
            check_immediately_before_effect(protected, &request)?;
            ensure_before_deadline(attempt.effect_deadline_boottime_nanoseconds())?;
            materialize_pin(attempt, pin_root)?;
        }
        WorkspacePinActionV1::RemoveAndDestroy => {
            if !matches!(dataset_before, WorkspaceDatasetObservationV1::Exact { .. })
                || !matches!(pin_before, WorkspacePinObservationV1::Present(_))
            {
                return Err(ZfsWorkerError::Authority);
            }

            check_immediately_before_effect(protected, &request)?;
            let _claim = replay.claim(attempt.attempt_id())?;
            check_immediately_before_effect(protected, &request)?;
            ensure_before_deadline(attempt.effect_deadline_boottime_nanoseconds())?;

            // RemoveAndDestroy is one replay-consumed compound effect, like a
            // generic ZFS transaction containing an ancestor mutation and its
            // dataset mutation. Broker serialization admits no intermediate
            // authority snapshot; the same absolute deadline remains checked
            // at every later blocking boundary inside this attempt.
            remove_pin_and_dataset(
                contract,
                executable_pin,
                &transaction,
                attempt,
                mount_namespace,
                pin_root,
                single_threaded,
            )?;
        }
    }

    let (dataset_after, observation_after) = observe_dataset_until(
        contract,
        &transaction,
        attempt,
        true,
        attempt.effect_deadline_boottime_nanoseconds(),
    )?;
    let pin_after = observe_workspace_pin(attempt, &dataset_after, mount_namespace, pin_root)
        .map_err(map_observer_error)?;
    Ok(WorkspacePinWorkerResultV1::new(
        attempt.attempt_id(),
        dataset_after,
        pin_after,
        required_observation_digest(observation_after)?,
    ))
}

fn required_observation_digest(
    digest: Option<ObjectDigest>,
) -> Result<ObjectDigest, ZfsWorkerError> {
    digest
        .filter(|digest| digest.as_bytes() != &[0; 32])
        .ok_or(ZfsWorkerError::Protocol(
            "workspace pin terminal ZFS observation has no digest",
        ))
}

fn check_immediately_before_effect(
    protected: &StorageProtectedConfigurationV1,
    request: &AuthenticatedWorkspacePinWorkerRequestV1,
) -> Result<(), ZfsWorkerError> {
    protected.check_workspace_pin_worker_before_effect(request, &mut protected_clock)
}

fn protected_clock() -> Result<RawPairedClockSample, StorageAdmissionError> {
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let wall_seconds = realtime.tv_sec;
    let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock")
        .map_err(|_| StorageAdmissionError::FenceRejected)?;
    RawPairedClockSample::new_untrusted(
        provenance,
        aos_sandbox_linux::boot::KernelBootId::current()
            .map_err(|_| StorageAdmissionError::FenceRejected)?
            .into_bytes(),
        wall_seconds,
        boottime_now_nanoseconds().map_err(|_| StorageAdmissionError::FenceRejected)?,
    )
    .map_err(|_| StorageAdmissionError::FenceRejected)
}

fn materialize_pin(
    attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
    pin_root: &ResolvedPath,
) -> Result<(), ZfsWorkerError> {
    let component = workspace_component(&attempt.workspace_handle())?;
    match rustix::fs::mkdirat(
        pin_root.as_fd(),
        component.as_str(),
        Mode::from_raw_mode(0o700),
    ) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let slot = open_workspace_slot(pin_root, &attempt.workspace_handle())
        .map_err(map_observer_error)?
        .ok_or(ZfsWorkerError::Protocol(
            "workspace pin slot is absent after creation",
        ))?;
    validate_controlled_slot(&slot)?;
    let mut filesystem = FileSystemContext::open("zfs")?;
    filesystem.set_string("source", attempt.dataset_name())?;
    let detached = filesystem.create()?.mount()?;
    detached.set_attributes(false, MountAttributes::secure_writable(), None)?;
    detached.attach(&slot)?;
    Ok(())
}

fn remove_pin_and_dataset(
    contract: &ZfsHelperContract,
    executable_pin: &PinnedExecutable,
    transaction: &ZfsTransaction,
    attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
    mount_namespace: &NamespaceFd,
    pin_root: &ResolvedPath,
    single_threaded: &SingleThreadedProcess,
) -> Result<(), ZfsWorkerError> {
    let component = workspace_component(&attempt.workspace_handle())?;
    let root = BeneathRoot::from_owned(rustix::io::dup(pin_root.as_fd())?)?;
    unmount_child(&root, Path::new(&component), single_threaded)?;
    let pin_after_unmount = observe_workspace_pin(
        attempt,
        &WorkspaceDatasetObservationV1::Exact {
            name: attempt.dataset_name().to_owned(),
            guid: attempt.dataset_guid(),
        },
        mount_namespace,
        pin_root,
    )
    .map_err(map_observer_error)?;
    if pin_after_unmount != WorkspacePinObservationV1::Absent {
        return Err(ZfsWorkerError::Authority);
    }

    executable_pin.validate_current(contract)?;
    let output = execute_transaction_for(
        contract,
        transaction,
        remaining_effect_time(attempt.effect_deadline_boottime_nanoseconds())?,
    )?;
    if !output.success || output.timed_out {
        return Err(ZfsWorkerError::Protocol(
            "workspace dataset destruction did not complete",
        ));
    }
    executable_pin.validate_current(contract)?;
    rustix::fs::unlinkat(pin_root.as_fd(), component.as_str(), AtFlags::REMOVEDIR)?;
    Ok(())
}

fn observe_dataset_until(
    contract: &ZfsHelperContract,
    transaction: &ZfsTransaction,
    attempt: &crate::workspace_pin::WorkspacePinAttemptV1,
    after_effect: bool,
    deadline_boottime_nanoseconds: u64,
) -> Result<(WorkspaceDatasetObservationV1, Option<ObjectDigest>), ZfsWorkerError> {
    let postcondition = match attempt.action() {
        WorkspacePinActionV1::Ensure => true,
        WorkspacePinActionV1::RemoveAndDestroy => after_effect,
    };
    let observation = observe_transaction_for(
        contract,
        transaction,
        postcondition,
        remaining_effect_time(deadline_boottime_nanoseconds)?,
    )?;
    match (attempt.action(), postcondition, observation.state) {
        (WorkspacePinActionV1::Ensure, true, ZfsObservationState::Matched) => {
            let dataset = match observation.object_guid {
                Some(guid) if guid == attempt.dataset_guid() => {
                    WorkspaceDatasetObservationV1::Exact {
                        name: attempt.dataset_name().to_owned(),
                        guid,
                    }
                }
                _ => WorkspaceDatasetObservationV1::Mismatch,
            };
            Ok((dataset, observation.digest))
        }
        (WorkspacePinActionV1::RemoveAndDestroy, false, ZfsObservationState::Matched) => Ok((
            WorkspaceDatasetObservationV1::Exact {
                name: attempt.dataset_name().to_owned(),
                guid: attempt.dataset_guid(),
            },
            observation.digest,
        )),
        (WorkspacePinActionV1::RemoveAndDestroy, true, ZfsObservationState::Matched)
            if observation.object_guid.is_none() =>
        {
            Ok((WorkspaceDatasetObservationV1::Absent, observation.digest))
        }
        (_, _, ZfsObservationState::Mismatch) => {
            Ok((WorkspaceDatasetObservationV1::Mismatch, None))
        }
        (_, _, ZfsObservationState::Incomplete) if postcondition => {
            // A missing create target and a still-present destroy target both
            // make the postcondition incomplete. Re-evaluate the complete
            // precondition plan to distinguish those two terminal identities
            // without introducing an ad-hoc ZFS query.
            let before = observe_transaction_for(
                contract,
                transaction,
                false,
                remaining_effect_time(deadline_boottime_nanoseconds)?,
            )?;
            match (attempt.action(), before.state) {
                (WorkspacePinActionV1::Ensure, ZfsObservationState::Matched) => {
                    Ok((WorkspaceDatasetObservationV1::Absent, before.digest))
                }
                (WorkspacePinActionV1::RemoveAndDestroy, ZfsObservationState::Matched) => Ok((
                    WorkspaceDatasetObservationV1::Exact {
                        name: attempt.dataset_name().to_owned(),
                        guid: attempt.dataset_guid(),
                    },
                    before.digest,
                )),
                _ => Ok((WorkspaceDatasetObservationV1::Mismatch, None)),
            }
        }
        _ => Ok((WorkspaceDatasetObservationV1::Mismatch, None)),
    }
}

fn observe_repair_dataset_until(
    contract: &ZfsHelperContract,
    transaction: &ZfsTransaction,
    probe: &WorkspacePinRepairProbeV1,
    deadline_boottime_nanoseconds: u64,
) -> Result<(WorkspaceDatasetObservationV1, Option<ObjectDigest>), ZfsWorkerError> {
    let observation = observe_transaction_for(
        contract,
        transaction,
        true,
        remaining_effect_time(deadline_boottime_nanoseconds)?,
    )?;
    match observation.state {
        ZfsObservationState::Matched => {
            let dataset = match observation.object_guid {
                Some(guid) if guid == probe.dataset_guid() => {
                    WorkspaceDatasetObservationV1::Exact {
                        name: probe.dataset_name().to_owned(),
                        guid,
                    }
                }
                _ => WorkspaceDatasetObservationV1::Mismatch,
            };
            Ok((dataset, observation.digest))
        }
        ZfsObservationState::Mismatch => Ok((WorkspaceDatasetObservationV1::Mismatch, None)),
        ZfsObservationState::Incomplete => {
            let before = observe_transaction_for(
                contract,
                transaction,
                false,
                remaining_effect_time(deadline_boottime_nanoseconds)?,
            )?;
            if before.state == ZfsObservationState::Matched {
                Ok((WorkspaceDatasetObservationV1::Absent, before.digest))
            } else {
                Ok((WorkspaceDatasetObservationV1::Mismatch, None))
            }
        }
    }
}

fn remaining_effect_time(deadline: u64) -> Result<Duration, ZfsWorkerError> {
    let remaining = deadline
        .checked_sub(boottime_now_nanoseconds()?)
        .filter(|remaining| *remaining != 0)
        .ok_or(ZfsWorkerError::Protocol(
            "workspace pin effect deadline elapsed",
        ))?;
    Ok(Duration::from_nanos(remaining).min(EFFECT_PROCESS_TIMEOUT))
}

fn validate_controlled_slot(slot: &ResolvedPath) -> Result<(), ZfsWorkerError> {
    let metadata = rustix::fs::fstat(slot.as_fd())?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != 0
        || metadata.st_mode & 0o022 != 0
        || metadata.st_dev == 0
        || metadata.st_ino == 0
    {
        return Err(ZfsWorkerError::Authority);
    }
    Ok(())
}

fn workspace_component(handle: &[u8; 32]) -> Result<String, ZfsWorkerError> {
    let path = workspace_pin_path(handle);
    path.rsplit_once('/')
        .map(|(_, component)| component.to_owned())
        .filter(|component| component.len() == 64)
        .ok_or(ZfsWorkerError::Protocol(
            "workspace pin component is invalid",
        ))
}

struct ReplayLedger {
    directory: OwnedFd,
}

impl ReplayLedger {
    fn open(path: &Path) -> Result<Self, ZfsWorkerError> {
        if !normalized_absolute_path(path) {
            return Err(ZfsWorkerError::Protocol(
                "unsafe workspace pin replay directory",
            ));
        }
        let system_root = rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        validate_root_owned_directory(system_root.as_fd())?;
        let system_root = BeneathRoot::from_owned(system_root)?;
        let relative = path
            .strip_prefix("/")
            .map_err(|_| ZfsWorkerError::Protocol("unsafe workspace pin replay directory"))?;
        let mut current = PathBuf::new();
        let mut directory_anchor = None;
        for component in relative.components() {
            let std::path::Component::Normal(component) = component else {
                return Err(ZfsWorkerError::Protocol(
                    "unsafe workspace pin replay directory",
                ));
            };
            current.push(component);
            let resolved = system_root.resolve(
                &current,
                ResolveOptions {
                    no_mount_crossing: false,
                    require_directory: true,
                },
            )?;
            validate_root_owned_directory(resolved.as_fd())?;
            directory_anchor = Some(resolved);
        }
        let directory_anchor = directory_anchor.ok_or(ZfsWorkerError::Protocol(
            "unsafe workspace pin replay directory",
        ))?;
        let directory = reopen_replay_directory(&directory_anchor, 0)?;
        Ok(Self { directory })
    }

    fn lock(&self, deadline: u64) -> Result<File, ZfsWorkerError> {
        ensure_before_deadline(deadline)?;
        let descriptor = rustix::fs::openat(
            self.directory.as_fd(),
            SERIALIZATION_LOCK,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        validate_root_owned_file(descriptor.as_fd())?;
        let file = File::from(descriptor);
        rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive)?;
        ensure_before_deadline(deadline)?;
        Ok(file)
    }

    fn claim(&self, attempt_id: [u8; 16]) -> Result<File, ZfsWorkerError> {
        claim_replay_attempt(&self.directory, attempt_id, 0)
    }
}

fn reopen_replay_directory(
    anchor: &ResolvedPath,
    owner_uid: u32,
) -> Result<OwnedFd, ZfsWorkerError> {
    // Resolution intentionally yields O_PATH, which cannot provide the
    // directory fsync required after a durable replay claim.
    let directory = rustix::fs::openat(
        anchor.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let metadata = rustix::fs::fstat(directory.as_fd())?;
    if metadata.st_dev != anchor.identity().device || metadata.st_ino != anchor.identity().inode {
        return Err(ZfsWorkerError::Authority);
    }
    validate_owned_directory(directory.as_fd(), owner_uid)?;
    Ok(directory)
}

fn claim_replay_attempt(
    directory: &OwnedFd,
    attempt_id: [u8; 16],
    owner_uid: u32,
) -> Result<File, ZfsWorkerError> {
    let mut name = String::with_capacity(38);
    name.push_str("attempt-");
    for byte in attempt_id {
        write!(name, "{byte:02x}")
            .map_err(|_| ZfsWorkerError::Protocol("workspace pin claim is invalid"))?;
    }
    let descriptor = rustix::fs::openat(
        directory.as_fd(),
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            ZfsWorkerError::Authority
        } else {
            error.into()
        }
    })?;
    validate_owned_file(descriptor.as_fd(), owner_uid)?;
    rustix::fs::fsync(&descriptor)?;
    rustix::fs::fsync(directory)?;
    Ok(File::from(descriptor))
}

fn validate_root_owned_directory(
    descriptor: std::os::fd::BorrowedFd<'_>,
) -> Result<(), ZfsWorkerError> {
    validate_owned_directory(descriptor, 0)
}

fn validate_owned_directory(
    descriptor: std::os::fd::BorrowedFd<'_>,
    owner_uid: u32,
) -> Result<(), ZfsWorkerError> {
    let metadata = rustix::fs::fstat(descriptor)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != owner_uid
        || metadata.st_mode & 0o022 != 0
        || metadata.st_dev == 0
        || metadata.st_ino == 0
    {
        return Err(ZfsWorkerError::Authority);
    }
    Ok(())
}

fn validate_root_owned_file(descriptor: std::os::fd::BorrowedFd<'_>) -> Result<(), ZfsWorkerError> {
    validate_owned_file(descriptor, 0)
}

fn validate_owned_file(
    descriptor: std::os::fd::BorrowedFd<'_>,
    owner_uid: u32,
) -> Result<(), ZfsWorkerError> {
    let metadata = rustix::fs::fstat(descriptor)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != owner_uid
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_dev == 0
        || metadata.st_ino == 0
    {
        return Err(ZfsWorkerError::Authority);
    }
    Ok(())
}

fn verify_systemd_peer(
    peer: &ConnectionPeerIdentity,
    manager: &RetainedCgroupAnchor,
) -> Result<(), ZfsWorkerError> {
    let credentials = peer.credentials();
    let info = manager.verify_exact_membership(peer.pidfd())?;
    if credentials.pid().get() != 1
        || credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != 1
        || info.thread_group_id() != 1
    {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn verify_storaged_subject(
    subject: &KernelAuthorizedRecordSubject,
    storaged: &RetainedCgroupAnchor,
) -> Result<(), ZfsWorkerError> {
    let credentials = subject.credentials();
    let info = storaged.verify_exact_membership(subject.pidfd())?;
    if credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != credentials.pid().get()
        || info.thread_group_id() != credentials.pid().get()
    {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn verify_worker_subject(
    subject: &KernelAuthorizedRecordSubject,
    parent: &RetainedCgroupAnchor,
    path: &Path,
    role: WorkspacePinServiceRole,
) -> Result<RetainedCgroupAnchor, ZfsWorkerError> {
    let credentials = subject.credentials();
    validate_worker_cgroup(path.to_str().ok_or(ZfsWorkerError::PeerMismatch)?, role)?;
    let relative = path
        .strip_prefix(CONTROL_SLICE_CGROUP)
        .map_err(|_| ZfsWorkerError::PeerMismatch)?;
    let worker_cgroup = parent.resolve_descendant(relative)?;
    let info = worker_cgroup.verify_exact_membership(subject.pidfd())?;
    if credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != credentials.pid().get()
        || info.thread_group_id() != credentials.pid().get()
    {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    parent.validate_current()?;
    Ok(worker_cgroup)
}

fn verify_exact_worker_subject(
    subject: &KernelAuthorizedRecordSubject,
    worker_cgroup: &RetainedCgroupAnchor,
) -> Result<(), ZfsWorkerError> {
    let credentials = subject.credentials();
    let info = worker_cgroup.verify_exact_membership(subject.pidfd())?;
    if credentials.uid() != 0
        || credentials.gid() != 0
        || info.pid() != credentials.pid().get()
        || info.thread_group_id() != credentials.pid().get()
    {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn encode_ready(cgroup: &str, role: WorkspacePinServiceRole) -> Result<Vec<u8>, ZfsWorkerError> {
    validate_worker_cgroup(cgroup, role)?;
    let length = u16::try_from(cgroup.len())
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin cgroup is too long"))?;
    let mut bytes = Vec::with_capacity(12 + cgroup.len());
    bytes.extend_from_slice(READY_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(cgroup.as_bytes());
    Ok(bytes)
}

fn decode_ready(bytes: &[u8], role: WorkspacePinServiceRole) -> Result<&str, ZfsWorkerError> {
    if bytes.len() < 12 || &bytes[..8] != READY_MAGIC || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin ready header is invalid",
        ));
    }
    let length = usize::from(u16::from_be_bytes(bytes[10..12].try_into().map_err(
        |_| ZfsWorkerError::Protocol("workspace pin ready length is invalid"),
    )?));
    if length == 0 || length > MAXIMUM_CGROUP_BYTES || bytes.len() != 12 + length {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin ready length is invalid",
        ));
    }
    let cgroup = std::str::from_utf8(&bytes[12..])
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin cgroup is not UTF-8"))?;
    validate_worker_cgroup(cgroup, role)?;
    Ok(cgroup)
}

fn validate_worker_cgroup(path: &str, role: WorkspacePinServiceRole) -> Result<(), ZfsWorkerError> {
    let instance = path
        .strip_prefix(role.cgroup_prefix())
        .and_then(|path| path.strip_suffix(WORKER_CGROUP_SUFFIX))
        .filter(|instance| !instance.is_empty() && instance.len() <= 255 && !instance.contains('/'))
        .ok_or(ZfsWorkerError::PeerMismatch)?;
    if instance == "." || instance == ".." {
        return Err(ZfsWorkerError::PeerMismatch);
    }
    Ok(())
}

fn current_cgroup() -> Result<String, ZfsWorkerError> {
    let mut bytes = Vec::new();
    File::open("/proc/self/cgroup")?
        .take((MAXIMUM_CGROUP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAXIMUM_CGROUP_BYTES {
        return Err(ZfsWorkerError::Protocol(
            "workspace pin cgroup text is too long",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ZfsWorkerError::Protocol("workspace pin cgroup is not UTF-8"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .map(str::to_owned)
        .ok_or(ZfsWorkerError::PeerMismatch)
}

fn send_packet_before(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    deadline: u64,
) -> Result<(), ZfsWorkerError> {
    socket.provision_packet_capacity(payload.len())?;
    loop {
        ensure_before_deadline(deadline)?;
        match socket.send(payload) {
            Ok(()) => return ensure_before_deadline(deadline),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_before(socket.as_fd()?, rustix::event::PollFlags::OUT, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_packet_before(
    socket: &mut DescriptorSubjectSocket,
    maximum: usize,
    deadline: u64,
) -> Result<
    aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    ZfsWorkerError,
> {
    socket.provision_packet_capacity(maximum)?;
    loop {
        ensure_before_deadline(deadline)?;
        match socket.receive(maximum, 0) {
            Ok(record) => {
                ensure_before_deadline(deadline)?;
                return Ok(record);
            }
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_before(socket.as_fd()?, rustix::event::PollFlags::IN, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn transfer_deadline() -> Result<u64, ZfsWorkerError> {
    boottime_now_nanoseconds()?
        .checked_add(TRANSFER_TIMEOUT.as_nanos() as u64)
        .ok_or(ZfsWorkerError::Protocol(
            "workspace pin transfer deadline overflowed",
        ))
}

fn normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && path.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn map_observer_error(error: WorkspacePinObserverError) -> ZfsWorkerError {
    match error {
        WorkspacePinObserverError::Linux(error) => error.into(),
        WorkspacePinObserverError::Kernel(error) => error.into(),
        WorkspacePinObserverError::HostScopeMismatch | WorkspacePinObserverError::State(_) => {
            ZfsWorkerError::Authority
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn replay_claim_fsyncs_a_readable_reopened_directory() {
        let temporary = TempDir::new().unwrap();
        let anchor = rustix::fs::open(
            temporary.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let anchor = ResolvedPath::from_inherited(anchor).unwrap();
        let owner_uid = rustix::fs::fstat(anchor.as_fd()).unwrap().st_uid;
        assert_eq!(
            rustix::fs::fsync(anchor.as_fd()),
            Err(rustix::io::Errno::BADF)
        );
        let directory = reopen_replay_directory(&anchor, owner_uid).unwrap();
        let attempt_id = [7; 16];

        drop(claim_replay_attempt(&directory, attempt_id, owner_uid).unwrap());

        assert!(
            temporary
                .path()
                .join(format!("attempt-{}", "07".repeat(16)))
                .is_file()
        );
        assert!(matches!(
            claim_replay_attempt(&directory, attempt_id, owner_uid),
            Err(ZfsWorkerError::Authority)
        ));
    }

    #[test]
    fn workspace_worker_cgroups_require_the_exact_systemd_slice_hierarchy() {
        for (role, basename) in [
            (
                WorkspacePinServiceRole::Effect,
                "aos-sandbox-workspace-pin-worker@trusted.service",
            ),
            (
                WorkspacePinServiceRole::Observer,
                "aos-sandbox-workspace-pin-observer@trusted.service",
            ),
        ] {
            let expected = format!("{CONTROL_SLICE_CGROUP}/{basename}");
            validate_worker_cgroup(&expected, role).unwrap();

            for substituted in [
                format!("aos-control.slice/{basename}"),
                format!("aos.slice/alternate.slice/{basename}"),
                format!("{CONTROL_SLICE_CGROUP}/alternate/{basename}"),
            ] {
                assert!(matches!(
                    validate_worker_cgroup(&substituted, role),
                    Err(ZfsWorkerError::PeerMismatch)
                ));
            }
        }
    }

    #[test]
    fn recovered_generic_workers_require_the_exact_control_slice() {
        validate_recovered_worker_cgroup(
            "aos.slice/aos-control.slice/aos-sandbox-zfs-worker@trusted.service",
        )
        .unwrap();

        for substituted in [
            "aos-control.slice/aos-sandbox-zfs-worker@trusted.service",
            "aos.slice/alternate.slice/aos-sandbox-zfs-worker@trusted.service",
        ] {
            assert!(matches!(
                validate_recovered_worker_cgroup(substituted),
                Err(ZfsWorkerError::PeerMismatch)
            ));
        }
    }
}
