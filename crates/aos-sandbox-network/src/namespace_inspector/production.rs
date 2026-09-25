//! Deployment composition precursor for one systemd-activated inspection.
//!
//! The entrypoint reconstructs the complete `Accept=yes` instance from the
//! accepted socket and its pinned connector. Raw cgroup text supplies only the
//! accept ordinal; every security-relevant subject field must match retained
//! kernel evidence before the native manager query is allowed to run.
//!
//! The inherited path now requires the broker's signed V2/V3 inventory for
//! inspector and lifecycle-worker ELF closures. The corresponding system module
//! still fails evaluation until the remaining executable closures and live
//! enforcing host-MAC behavior have been qualified. Executing the retained V1
//! helper ELF does not by itself authenticate its loader or shared libraries.
//! A fresh native query before the response must reproduce the complete
//! manager, service, and socket activation snapshot observed before the request.
//! The signed V3 worker launch is also queried through PID 1 against the
//! retained worker pidfd at admission and immediately before the response.
//! This path does not advertise Network Apply, readiness, or authority minting.

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::no_setid::require_guarded_startup;
use aos_sandbox_linux::pidfd::{NamespaceKind, PidFd, SingleThreadedProcess};
use aos_sandbox_linux::process::disable_core_dumps;
use aos_sandbox_linux::seqpacket::{SeqpacketError, descriptor_subject::DescriptorSubjectSocket};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use thiserror::Error;

use super::launch_contract::{
    NamespaceInspectorArtifactRoleV1, ProtectedNamespaceInspectorDeploymentContractError,
    ProtectedNamespaceInspectorDeploymentContractV1,
};
use super::manager_query::MatchedNamespaceInspectorActivationSnapshotsV1;
use super::manager_query::session::{
    NamespaceInspectorManagerQuerySessionError, NamespaceInspectorManagerQuerySessionRequest,
    run_namespace_inspector_manager_query_session,
};
use super::runtime::{
    NamespaceInspectorKernelAuthenticationError, NamespaceInspectorKernelVerifierV1,
    require_current_inspector_mac_context,
};
use super::store::{InspectorProtectedRootError, InspectorProtectedStoreAccess};
use super::{
    AuthenticatedLifecycleWorkerLaunchObservationV1, InspectorDescriptorEnvelopeV1,
    InspectorProcessIdentityV1, InspectorTrustedClockV1, InspectorTrustedTimeV1,
    NetworkNamespaceInspectionRequestV1, NetworkNamespaceInspectorAdmissionError,
    NetworkNamespaceInspectorAdmissionV1, NetworkNamespaceInspectorError,
    NetworkNamespaceInspectorPeerRoleV1, ProvisionedInspectorPeerRoleV1,
    ProvisionedNetworkNamespaceInspectorV1,
};
use crate::broker_pid1_query::{
    BrokerPid1QueryErrorV2, BrokerPid1QueryRequestV2, BrokerPid1ServiceObservationV2,
    BrokerPid1ServiceReadbackV2, BrokerPid1ServiceRoleV2, query_pid1_service_with_helper,
    require_same_readback,
};
use crate::inspector_deployment::ProtectedInspectorDeploymentV2;
use crate::systemd_socket_instance::SystemdSocketInstanceV1;

const CONTRACT_CREDENTIAL: &str = "deployment-contract";
const LIFECYCLE_DIGEST_CREDENTIAL: &str = "lifecycle-worker-launch-digest";
const DEPLOYMENT_VERIFIER_CREDENTIAL: &str = "inspector-deployment-verifier-v2";
const DEPLOYMENT_CONTRACT_CREDENTIAL: &str = "inspector-deployment-contract-v2";
const LAUNCH_POLICY_CREDENTIAL: &str = "inspector-launch-policy-v3";
const CREDENTIAL_HANDLES: [&str; 5] = [
    CONTRACT_CREDENTIAL,
    LIFECYCLE_DIGEST_CREDENTIAL,
    DEPLOYMENT_VERIFIER_CREDENTIAL,
    DEPLOYMENT_CONTRACT_CREDENTIAL,
    LAUNCH_POLICY_CREDENTIAL,
];
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
const EXPECTED_FINAL: &str = "/var/lib/aos/sandbox-network/namespace-inspector/expected-final";
const SPENT_STAGING: &str = "/var/lib/aos/sandbox-network/namespace-inspector/spent-staging";
const SPENT_FINAL: &str = "/var/lib/aos/sandbox-network/namespace-inspector/spent-final";
const INSPECTOR_CGROUP_PREFIX: &str =
    "aos.slice/aos-control.slice/aos-sandbox-network-namespace-inspector@";
const INSPECTOR_CGROUP_SUFFIX: &str = ".service";
const MAXIMUM_CGROUP_FILE_BYTES: usize = 1024;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(2);

/// Reports a fail-closed production namespace-inspector failure.
#[derive(Debug, Error)]
pub enum NamespaceInspectorProductionError {
    /// The process was not launched with the fixed root authority contract.
    #[error("namespace inspector requires fixed root systemd activation")]
    Authority,
    /// Fixed environment, pathname, cgroup, or activation syntax was invalid.
    #[error("namespace inspector production contract is invalid: {0}")]
    Contract(&'static str),
    /// A fixed local file operation failed.
    #[error("namespace inspector failed during {operation}: {source}")]
    Io {
        /// Names the bounded operation which failed.
        operation: &'static str,
        /// Preserves the operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// The audited Linux descriptor boundary rejected an operation.
    #[error(transparent)]
    Linux(#[from] aos_sandbox_linux::Error),
    /// Sequenced-packet framing or ancillary validation failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// Protected deployment loading or revalidation failed.
    #[error("namespace-inspector protected deployment failed: {0}")]
    ProtectedDeployment(String),
    /// Signed V2/V3 deployment or executable closure admission failed.
    #[error("namespace-inspector signed deployment failed: {0}")]
    SignedDeployment(String),
    /// Fixed kernel role authentication failed.
    #[error("namespace-inspector kernel authentication failed: {0}")]
    Authentication(String),
    /// The native, authenticated systemd manager query failed.
    #[error("namespace-inspector manager query failed: {0}")]
    ManagerQuery(String),
    /// PID 1 did not confirm the exact signed, live lifecycle-worker launch.
    #[error("namespace-inspector worker PID 1 query failed: {0}")]
    WorkerPid1(String),
    /// Protected store roots failed admission.
    #[error("namespace-inspector protected store failed: {0}")]
    ProtectedStore(String),
    /// Pure inspector admission or response validation failed.
    #[error("namespace-inspector model rejected the transaction: {0}")]
    Model(String),
    /// A spent-nonce publication failed while retaining no retry authority.
    #[error("namespace-inspector spent-nonce claim failed: {0}")]
    SpentClaim(String),
}

/// Runs one inherited, authenticated namespace-inspector transaction.
///
/// The function accepts no caller configuration. PID 1 provides the connected
/// descriptor on standard input and five fixed credentials. The inspector
/// authenticates the broker connection and record independently, validates
/// its own `Accept=yes` activation with the native manager-query helper, claims
/// immutable expected policy exactly once, and returns one type-checked Network
/// namespace descriptor.
///
/// # Errors
///
/// Returns [`NamespaceInspectorProductionError`] for every activation,
/// provisioning, identity, manager-query, policy, replay, kernel observation,
/// deadline, or transport failure. No failure is retryable in-process.
pub fn run_inherited_network_namespace_inspector() -> Result<(), NamespaceInspectorProductionError>
{
    require_guarded_startup()?;
    let _single_threaded = SingleThreadedProcess::verify()?;
    validate_initial_descriptor_table()?;
    require_root()?;
    require_selinux_enforcing()?;
    require_current_inspector_mac_context().map_err(authentication)?;
    disable_core_dumps()?;

    let accepted: OwnedFd = rustix::io::dup(std::io::stdin().as_fd())
        .map_err(|source| io("duplicate accepted socket", source.into()))?;
    let mut socket = DescriptorSubjectSocket::from_owned(accepted)?;
    let activation = reconstruct_activation(socket.peer(), &current_cgroup()?)?;

    let credentials_directory = credentials_directory(activation)?;
    let protected_contract = ProtectedNamespaceInspectorDeploymentContractV1::load(
        &credentials_directory.join(CONTRACT_CREDENTIAL),
    )
    .map_err(protected_deployment)?;
    let signed_deployment = ProtectedInspectorDeploymentV2::load_required_for_inspector(
        &credentials_directory,
        *protected_contract.digest().as_bytes(),
    )
    .map_err(|error| NamespaceInspectorProductionError::SignedDeployment(error.to_string()))?;
    socket.require_local_filesystem_path(Path::new(
        protected_contract.contract().control_socket_path(),
    ))?;
    let lifecycle_digest =
        read_protected_digest(&credentials_directory.join(LIFECYCLE_DIGEST_CREDENTIAL))?;

    let self_pidfd = PidFd::open(NonZeroU32::new(std::process::id()).ok_or(
        NamespaceInspectorProductionError::Contract("process ID is zero"),
    )?)?;
    let verifier = kernel_verifier(&protected_contract)?;
    let inspector = verifier
        .authenticate_inspector_pidfd(&self_pidfd, &activation.canonical_text())
        .map_err(authentication)?;
    inspector
        .authenticated_inspector()
        .map_err(authentication)?;

    let manager_stream = RetainedUnixStream::connect(Path::new(
        protected_contract.contract().manager_socket_path(),
    ))?;
    let manager = verifier
        .authenticate_manager_stream(manager_stream.peer())
        .map_err(authentication)?;
    let manager_identity = manager.authenticated_manager().map_err(authentication)?;

    protected_contract
        .revalidate()
        .map_err(protected_deployment)?;
    validate_inspector_invocation(&protected_contract)?;
    let matched_activation = query_manager_activation(
        &protected_contract,
        &manager_stream,
        &self_pidfd,
        activation,
    )?;
    if matched_activation.deployment_digest() != protected_contract.digest()
        || matched_activation.parent_pidfd_inode() != descriptor_inode(self_pidfd.as_fd())?
    {
        return Err(NamespaceInspectorProductionError::Contract(
            "manager-query evidence lost its protected binding",
        ));
    }

    let initial_broker_identity = {
        let broker = verifier
            .authenticate_broker_connection(socket.peer())
            .map_err(authentication)?;
        broker.authenticated_peer().map_err(authentication)?
    };
    let deadline = deadline_after(TRANSFER_TIMEOUT)?;
    let received = receive_before(&mut socket, deadline)?;
    let (request_bytes, subject, mut descriptors) = received.into_parts();
    let request =
        NetworkNamespaceInspectionRequestV1::decode(&request_bytes).map_err(model_error)?;
    let worker_descriptor =
        descriptors
            .pop()
            .ok_or(NamespaceInspectorProductionError::Contract(
                "request omitted worker pidfd",
            ))?;
    if !descriptors.is_empty() {
        return Err(NamespaceInspectorProductionError::Contract(
            "request carried extra descriptors",
        ));
    }

    let broker_record = verifier
        .authenticate_broker_record(subject)
        .map_err(authentication)?;
    let broker_record_identity = broker_record.authenticated_peer().map_err(authentication)?;
    {
        let broker = verifier
            .authenticate_broker_connection(socket.peer())
            .map_err(authentication)?;
        if !broker
            .same_execution(&broker_record)
            .map_err(authentication)?
        {
            return Err(NamespaceInspectorProductionError::Contract(
                "broker connection and record executions differ",
            ));
        }
    }
    if initial_broker_identity != broker_record_identity {
        return Err(NamespaceInspectorProductionError::Contract(
            "broker identity changed before request admission",
        ));
    }

    let worker_pidfd = PidFd::from_owned(worker_descriptor)?;
    let worker = verifier
        .authenticate_lifecycle_worker_pidfd(&worker_pidfd, &request.expected.cgroup)
        .map_err(authentication)?;
    let worker_identity = worker.process().map_err(authentication)?;
    let initial_worker_pid1 = query_inspector_worker_pid1(
        &protected_contract,
        &signed_deployment,
        &worker_pidfd,
        &request.expected.unit_name,
    )?;
    require_worker_pid1_match(
        initial_worker_pid1.observation(),
        &request.expected.unit_name,
        &request.expected.cgroup,
        worker_identity,
    )?;
    let launch = AuthenticatedLifecycleWorkerLaunchObservationV1 {
        manager: manager_identity,
        unit_name: request.expected.unit_name.clone(),
        cgroup: request.expected.cgroup.clone(),
        process: worker_identity,
        launch_contract_digest: lifecycle_digest,
    };
    let deployment = ProvisionedNetworkNamespaceInspectorV1 {
        boot_id: KernelBootId::current()?.into_bytes(),
        broker: ProvisionedInspectorPeerRoleV1 {
            role: NetworkNamespaceInspectorPeerRoleV1::Broker,
            uid: 0,
            gid: 0,
        },
        inspector: ProvisionedInspectorPeerRoleV1 {
            role: NetworkNamespaceInspectorPeerRoleV1::Inspector,
            uid: 0,
            gid: 0,
        },
        systemd_manager: manager_identity,
        launch_contract_digest: lifecycle_digest,
    };

    let mut stores = protected_stores()?;
    let mut clock = KernelInspectorClock;
    let mut admission = NetworkNamespaceInspectorAdmissionV1::default();
    let (expected, spent) = stores.split();
    let authorization = match admission.authenticate_and_claim(
        &deployment,
        initial_broker_identity,
        broker_record_identity,
        &launch,
        expected,
        spent,
        &mut clock,
        request,
        InspectorDescriptorEnvelopeV1 {
            count: 1,
            ancillary_is_canonical: true,
        },
        worker_identity,
    ) {
        Ok(authorization) => authorization,
        Err(NetworkNamespaceInspectorAdmissionError::Model(error)) => {
            return Err(model_error(error));
        }
        Err(NetworkNamespaceInspectorAdmissionError::Spent(error)) => {
            return Err(NamespaceInspectorProductionError::SpentClaim(
                error.to_string(),
            ));
        }
    };

    let namespace = worker_pidfd.namespace(NamespaceKind::Network)?;
    let process_after_inspection = worker.process().map_err(authentication)?;
    let response = authorization
        .respond(&mut clock, process_after_inspection, namespace.identity())
        .map_err(model_error)?;

    protected_contract
        .revalidate()
        .map_err(protected_deployment)?;
    signed_deployment
        .service_launch(true)
        .map_err(|error| NamespaceInspectorProductionError::SignedDeployment(error.to_string()))?;
    inspector.revalidate_retained().map_err(authentication)?;
    manager.revalidate_retained().map_err(authentication)?;
    // The matched snapshot includes all 126 manager, service, and socket
    // properties, including invocation, cgroup, executable, unit fragment,
    // capabilities, environment, listener, and accepted-connection settings.
    // A new D-Bus connection is necessary: reusing the first stream would
    // replay authentication on a connection whose protocol state has advanced.
    let refreshed_stream = RetainedUnixStream::connect(Path::new(
        protected_contract.contract().manager_socket_path(),
    ))?;
    let refreshed_manager = verifier
        .authenticate_manager_stream(refreshed_stream.peer())
        .map_err(authentication)?;
    let current_manager = refreshed_manager
        .authenticated_manager()
        .map_err(authentication)?;
    if current_manager != manager_identity {
        return Err(NamespaceInspectorProductionError::Contract(
            "systemd manager changed during the request",
        ));
    }
    let refreshed_activation = query_manager_activation(
        &protected_contract,
        &refreshed_stream,
        &self_pidfd,
        activation,
    )?;
    refreshed_manager
        .revalidate_retained()
        .map_err(authentication)?;
    if refreshed_activation != matched_activation {
        return Err(NamespaceInspectorProductionError::Contract(
            "inspector activation changed during the request",
        ));
    }
    protected_contract
        .revalidate()
        .map_err(protected_deployment)?;
    signed_deployment
        .service_launch(true)
        .map_err(|error| NamespaceInspectorProductionError::SignedDeployment(error.to_string()))?;
    inspector.revalidate_retained().map_err(authentication)?;
    broker_record
        .revalidate_retained()
        .map_err(authentication)?;
    {
        let broker = verifier
            .authenticate_broker_connection(socket.peer())
            .map_err(authentication)?;
        if !broker
            .same_execution(&broker_record)
            .map_err(authentication)?
        {
            return Err(NamespaceInspectorProductionError::Contract(
                "broker execution changed before response",
            ));
        }
    }
    let final_worker_pid1 = query_inspector_worker_pid1(
        &protected_contract,
        &signed_deployment,
        &worker_pidfd,
        &launch.unit_name,
    )?;
    require_same_readback(&initial_worker_pid1, &final_worker_pid1)
        .map_err(map_worker_pid1_error)?;
    let final_worker = worker.process().map_err(authentication)?;
    if final_worker != worker_identity {
        return Err(NamespaceInspectorProductionError::Contract(
            "lifecycle-worker identity changed before response",
        ));
    }
    send_before(&mut socket, &response.encode(), namespace.as_fd(), deadline)?;
    socket.close();
    Ok(())
}

fn query_inspector_worker_pid1(
    protected_contract: &ProtectedNamespaceInspectorDeploymentContractV1,
    signed_deployment: &ProtectedInspectorDeploymentV2,
    worker_pidfd: &PidFd,
    unit: &str,
) -> Result<BrokerPid1ServiceReadbackV2, NamespaceInspectorProductionError> {
    let helper_path = protected_contract.contract().manager_query_helper().ok_or(
        NamespaceInspectorProductionError::Contract(
            "inspector manager-query helper path is absent",
        ),
    )?;
    let helper_executable = protected_contract
        .duplicate_artifact(NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable)
        .map_err(protected_deployment)?;

    query_pid1_service_with_helper(
        BrokerPid1QueryRequestV2 {
            deployment: signed_deployment,
            subject: worker_pidfd,
            inspector_record_subject: None,
            role: BrokerPid1ServiceRoleV2::LifecycleWorker,
            unit,
        },
        helper_path,
        helper_executable,
    )
    .map_err(map_worker_pid1_error)
}

fn require_worker_pid1_match(
    observed: &BrokerPid1ServiceObservationV2,
    unit: &str,
    cgroup: &str,
    worker: InspectorProcessIdentityV1,
) -> Result<(), NamespaceInspectorProductionError> {
    if observed.unit != unit
        || observed.control_group != format!("/{cgroup}")
        || observed.main_pid != worker.pid
        || observed.control_group_id != worker.cgroup_id
        || observed.invocation_id == [0; 16]
    {
        return Err(NamespaceInspectorProductionError::Contract(
            "PID 1 worker observation differs from authenticated worker",
        ));
    }
    Ok(())
}

fn query_manager_activation(
    protected_contract: &ProtectedNamespaceInspectorDeploymentContractV1,
    manager_stream: &RetainedUnixStream,
    self_pidfd: &PidFd,
    activation: SystemdSocketInstanceV1,
) -> Result<MatchedNamespaceInspectorActivationSnapshotsV1, NamespaceInspectorProductionError> {
    let manager_descriptor = manager_stream
        .duplicate()?
        .as_fd()
        .try_clone_to_owned()
        .map_err(|source| io("duplicate manager stream", source))?;
    run_namespace_inspector_manager_query_session(NamespaceInspectorManagerQuerySessionRequest {
        protected_contract,
        manager_stream: manager_descriptor,
        parent_pidfd: self_pidfd,
        activation,
        nonce: random_nonce()?,
    })
    .map_err(manager_query)
}

fn validate_initial_descriptor_table() -> Result<(), NamespaceInspectorProductionError> {
    let mut descriptors = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")
        .map_err(|source| io("open initial descriptor table", source))?
    {
        let name = entry
            .map_err(|source| io("read initial descriptor table", source))?
            .file_name();
        let descriptor = name
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(NamespaceInspectorProductionError::Contract(
                "initial descriptor table contains a noncanonical entry",
            ))?;
        descriptors.push(descriptor);
    }
    descriptors.sort_unstable();
    validate_initial_descriptor_numbers(&descriptors)?;
    validate_inherited_standard_streams(
        std::io::stdin().as_fd(),
        std::io::stdout().as_fd(),
        std::io::stderr().as_fd(),
    )
}

fn validate_initial_descriptor_numbers(
    descriptors: &[u32],
) -> Result<(), NamespaceInspectorProductionError> {
    // Opening /proc/self/fd temporarily occupies descriptor 3. PID 1 must
    // otherwise provide only the accepted socket on stdin/stdout and the
    // configured journal stream on stderr.
    if descriptors != [0, 1, 2, 3] {
        return Err(NamespaceInspectorProductionError::Contract(
            "namespace inspector inherited an unexpected descriptor",
        ));
    }
    Ok(())
}

fn validate_inherited_standard_streams(
    stdin: BorrowedFd<'_>,
    stdout: BorrowedFd<'_>,
    stderr: BorrowedFd<'_>,
) -> Result<(), NamespaceInspectorProductionError> {
    let input =
        rustix::fs::fstat(stdin).map_err(|source| io("inspect inherited stdin", source.into()))?;
    let output = rustix::fs::fstat(stdout)
        .map_err(|source| io("inspect inherited stdout", source.into()))?;
    let error = rustix::fs::fstat(stderr)
        .map_err(|source| io("inspect inherited stderr", source.into()))?;

    // Both socket-directed streams must refer to the same accepted endpoint.
    // The journal stream must not become a competing protocol writer.
    let accepted_socket = (input.st_dev, input.st_ino);
    if rustix::fs::FileType::from_raw_mode(input.st_mode) != rustix::fs::FileType::Socket
        || rustix::fs::FileType::from_raw_mode(output.st_mode) != rustix::fs::FileType::Socket
        || accepted_socket != (output.st_dev, output.st_ino)
        || accepted_socket == (error.st_dev, error.st_ino)
    {
        return Err(NamespaceInspectorProductionError::Contract(
            "inherited standard streams differ from the accepted socket contract",
        ));
    }
    Ok(())
}

struct KernelInspectorClock;

impl InspectorTrustedClockV1 for KernelInspectorClock {
    fn observe(&mut self) -> Result<InspectorTrustedTimeV1, NetworkNamespaceInspectorError> {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let seconds = u64::try_from(now.tv_sec).map_err(|_| {
            NetworkNamespaceInspectorError::Protocol("CLOCK_BOOTTIME seconds are invalid")
        })?;
        let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| {
            NetworkNamespaceInspectorError::Protocol("CLOCK_BOOTTIME nanoseconds are invalid")
        })?;
        let boottime_ns = seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or(NetworkNamespaceInspectorError::Protocol(
                "CLOCK_BOOTTIME overflowed",
            ))?;
        let boot_id = KernelBootId::current()
            .map_err(|_| NetworkNamespaceInspectorError::ObservationMismatch)?
            .into_bytes();
        Ok(InspectorTrustedTimeV1 {
            boot_id,
            boottime_ns,
        })
    }
}

fn require_root() -> Result<(), NamespaceInspectorProductionError> {
    if rustix::process::getuid().is_root()
        && rustix::process::geteuid().is_root()
        && rustix::process::getgid().is_root()
        && rustix::process::getegid().is_root()
    {
        Ok(())
    } else {
        Err(NamespaceInspectorProductionError::Authority)
    }
}

fn require_selinux_enforcing() -> Result<(), NamespaceInspectorProductionError> {
    let state = std::fs::read(SELINUX_ENFORCE)
        .map_err(|source| io("read SELinux enforcement state", source))?;
    validate_selinux_enforcing_state(&state)
}

fn validate_selinux_enforcing_state(state: &[u8]) -> Result<(), NamespaceInspectorProductionError> {
    if state == b"1\n" {
        Ok(())
    } else {
        Err(NamespaceInspectorProductionError::Authority)
    }
}

fn credentials_directory(
    activation: SystemdSocketInstanceV1,
) -> Result<PathBuf, NamespaceInspectorProductionError> {
    let path = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .ok_or(NamespaceInspectorProductionError::Contract(
            "CREDENTIALS_DIRECTORY is absent",
        ))?;
    let expected = PathBuf::from(format!(
        "/run/credentials/aos-sandbox-network-namespace-inspector@{}.service",
        activation.canonical_text()
    ));
    if !normalized_absolute_path(&path) || path != expected {
        return Err(NamespaceInspectorProductionError::Contract(
            "CREDENTIALS_DIRECTORY differs from the authenticated service instance",
        ));
    }
    validate_credential_handles(&path)?;
    Ok(path)
}

fn validate_credential_handles(path: &Path) -> Result<(), NamespaceInspectorProductionError> {
    let mut seen = [false; CREDENTIAL_HANDLES.len()];
    let entries =
        std::fs::read_dir(path).map_err(|source| io("open credentials directory", source))?;
    for entry in entries {
        let entry = entry.map_err(|source| io("read credentials directory", source))?;
        let name = entry.file_name();
        let Some(index) = CREDENTIAL_HANDLES
            .iter()
            .position(|expected| name == OsStr::new(expected))
        else {
            return Err(NamespaceInspectorProductionError::Contract(
                "credentials directory contains an unexpected handle",
            ));
        };
        if std::mem::replace(&mut seen[index], true) {
            return Err(NamespaceInspectorProductionError::Contract(
                "credentials directory repeats a handle",
            ));
        }
    }
    if seen.iter().all(|present| *present) {
        Ok(())
    } else {
        Err(NamespaceInspectorProductionError::Contract(
            "credentials directory omits a required handle",
        ))
    }
}

fn read_protected_digest(path: &Path) -> Result<ObjectDigest, NamespaceInspectorProductionError> {
    let file = open_regular(path, rustix::fs::OFlags::RDONLY, "open launch digest")?;
    let metadata = file
        .metadata()
        .map_err(|source| io("inspect launch digest", source))?;
    if metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() != 32
    {
        return Err(NamespaceInspectorProductionError::Contract(
            "launch digest credential metadata is invalid",
        ));
    }
    let mut bytes = [0; 32];
    file.take(33)
        .read_exact(&mut bytes)
        .map_err(|source| io("read launch digest", source))?;
    if bytes == [0; 32] {
        return Err(NamespaceInspectorProductionError::Contract(
            "launch digest is zero",
        ));
    }
    Ok(ObjectDigest::from_bytes(bytes))
}

fn kernel_verifier(
    contract: &ProtectedNamespaceInspectorDeploymentContractV1,
) -> Result<NamespaceInspectorKernelVerifierV1, NamespaceInspectorProductionError> {
    let current_executable = std::fs::read_link("/proc/self/exe")
        .map_err(|source| io("resolve current executable", source))?;
    if !normalized_absolute_path(&current_executable) {
        return Err(NamespaceInspectorProductionError::Contract(
            "current executable path is not canonical",
        ));
    }
    let parent = current_executable
        .parent()
        .ok_or(NamespaceInspectorProductionError::Contract(
            "current executable has no parent",
        ))?;
    let broker = open_executable(&parent.join("aos-netd"))?;
    let lifecycle_worker = open_executable(&parent.join("aos-sandbox-network-lifecycle-worker"))?;
    let inspector = contract
        .duplicate_artifact(NamespaceInspectorArtifactRoleV1::InspectorExecutable)
        .map_err(protected_deployment)?;
    let manager = rustix::fs::open(
        "/proc/1/exe",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| io("open manager executable", source.into()))?;
    let cgroup_root = open_directory(Path::new(CGROUP_ROOT))?;

    NamespaceInspectorKernelVerifierV1::from_owned(
        cgroup_root,
        broker,
        inspector,
        lifecycle_worker,
        manager,
    )
    .map_err(authentication)
}

fn validate_inspector_invocation(
    protected: &ProtectedNamespaceInspectorDeploymentContractV1,
) -> Result<(), NamespaceInspectorProductionError> {
    let executable = std::fs::read_link("/proc/self/exe")
        .map_err(|source| io("resolve inspector invocation", source))?;
    let Some(executable) = executable.to_str() else {
        return Err(NamespaceInspectorProductionError::Contract(
            "inspector executable path is not UTF-8",
        ));
    };
    if protected.contract().inspector_arguments() != [executable] {
        return Err(NamespaceInspectorProductionError::Contract(
            "running inspector arguments differ from protected policy",
        ));
    }
    Ok(())
}

fn protected_stores() -> Result<InspectorProtectedStoreAccess, NamespaceInspectorProductionError> {
    InspectorProtectedStoreAccess::from_owned(
        open_directory(Path::new(EXPECTED_FINAL))?,
        open_directory(Path::new(SPENT_STAGING))?,
        open_directory(Path::new(SPENT_FINAL))?,
    )
    .map_err(protected_store)
}

fn reconstruct_activation(
    peer: &aos_sandbox_linux::seqpacket::ConnectionPeerIdentity,
    cgroup: &str,
) -> Result<SystemdSocketInstanceV1, NamespaceInspectorProductionError> {
    let instance = instance_from_cgroup(cgroup)?;
    let untrusted = SystemdSocketInstanceV1::parse(instance).map_err(|_| {
        NamespaceInspectorProductionError::Contract("inspector instance is noncanonical")
    })?;
    let credentials = peer.credentials();
    reconstruct_instance_from_evidence(
        instance,
        untrusted.accept_ordinal(),
        peer.socket_cookie().get(),
        credentials.pid().get(),
        descriptor_inode(peer.pidfd().as_fd())?,
        credentials.uid(),
    )
}

fn instance_from_cgroup(cgroup: &str) -> Result<&str, NamespaceInspectorProductionError> {
    cgroup
        .strip_prefix(INSPECTOR_CGROUP_PREFIX)
        .and_then(|value| value.strip_suffix(INSPECTOR_CGROUP_SUFFIX))
        .ok_or(NamespaceInspectorProductionError::Contract(
            "inspector cgroup does not name the fixed service template",
        ))
}

fn reconstruct_instance_from_evidence(
    raw_instance: &str,
    raw_accept_ordinal: u64,
    socket_cookie: u64,
    connecting_pid: u32,
    connecting_pidfd_inode: u64,
    connecting_uid: u32,
) -> Result<SystemdSocketInstanceV1, NamespaceInspectorProductionError> {
    let reconstructed = SystemdSocketInstanceV1::new(
        raw_accept_ordinal,
        socket_cookie,
        connecting_pid,
        connecting_pidfd_inode,
        connecting_uid,
    )
    .map_err(|_| NamespaceInspectorProductionError::Contract("activation fields are invalid"))?;
    if reconstructed.canonical_text() != raw_instance {
        return Err(NamespaceInspectorProductionError::Contract(
            "raw service instance differs from accepted socket evidence",
        ));
    }
    Ok(reconstructed)
}

fn current_cgroup() -> Result<String, NamespaceInspectorProductionError> {
    let mut bytes = Vec::new();
    File::open("/proc/self/cgroup")
        .map_err(|source| io("open current cgroup", source))?
        .take((MAXIMUM_CGROUP_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| io("read current cgroup", source))?;
    if bytes.len() > MAXIMUM_CGROUP_FILE_BYTES {
        return Err(NamespaceInspectorProductionError::Contract(
            "current cgroup file exceeds its bound",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        NamespaceInspectorProductionError::Contract("current cgroup file is not UTF-8")
    })?;
    let cgroup = text
        .strip_prefix("0::/")
        .and_then(|value| value.strip_suffix('\n'))
        .ok_or(NamespaceInspectorProductionError::Contract(
            "current process does not have one canonical cgroup-v2 entry",
        ))?;
    if cgroup.is_empty() || cgroup.contains('\n') {
        return Err(NamespaceInspectorProductionError::Contract(
            "current cgroup entry is invalid",
        ));
    }
    Ok(cgroup.to_owned())
}

fn random_nonce() -> Result<[u8; 32], NamespaceInspectorProductionError> {
    let mut nonce = [0; 32];
    let mut filled = 0;
    while filled < nonce.len() {
        let count =
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())
                .map_err(|source| io("read kernel random source", source.into()))?;
        if count == 0 {
            return Err(NamespaceInspectorProductionError::Contract(
                "kernel random source returned no bytes",
            ));
        }
        filled += count;
    }
    if nonce == [0; 32] {
        return Err(NamespaceInspectorProductionError::Contract(
            "kernel random source returned reserved nonce",
        ));
    }
    Ok(nonce)
}

fn receive_before(
    socket: &mut DescriptorSubjectSocket,
    deadline: u64,
) -> Result<
    aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord,
    NamespaceInspectorProductionError,
> {
    socket.provision_packet_capacity(super::MAXIMUM_REQUEST_BYTES)?;
    loop {
        ensure_before(deadline)?;
        match socket.receive(super::MAXIMUM_REQUEST_BYTES, 1) {
            Ok(record) => return Ok(record),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_before(socket.as_fd()?, rustix::event::PollFlags::IN, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn send_before(
    socket: &mut DescriptorSubjectSocket,
    payload: &[u8],
    descriptor: BorrowedFd<'_>,
    deadline: u64,
) -> Result<(), NamespaceInspectorProductionError> {
    socket.provision_packet_capacity(payload.len())?;
    loop {
        ensure_before(deadline)?;
        match socket.send_with_descriptors(payload, &[descriptor]) {
            Ok(()) => return ensure_before(deadline),
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                wait_before(socket.as_fd()?, rustix::event::PollFlags::OUT, deadline)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait_before(
    descriptor: BorrowedFd<'_>,
    events: rustix::event::PollFlags,
    deadline: u64,
) -> Result<(), NamespaceInspectorProductionError> {
    loop {
        let remaining = deadline.checked_sub(boottime_now()?).ok_or(
            NamespaceInspectorProductionError::Contract("transport deadline elapsed"),
        )?;
        let timeout = rustix::event::Timespec {
            tv_sec: i64::try_from(remaining / 1_000_000_000).map_err(|_| {
                NamespaceInspectorProductionError::Contract("poll timeout seconds overflowed")
            })?,
            tv_nsec: i64::try_from(remaining % 1_000_000_000).map_err(|_| {
                NamespaceInspectorProductionError::Contract("poll timeout nanoseconds overflowed")
            })?,
        };
        let mut descriptors = [rustix::event::PollFd::new(&descriptor, events)];
        match rustix::event::poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => {
                return Err(NamespaceInspectorProductionError::Contract(
                    "transport deadline elapsed",
                ));
            }
            Ok(_) => return ensure_before(deadline),
            Err(rustix::io::Errno::INTR) => continue,
            Err(source) => return Err(io("poll inspector transport", source.into())),
        }
    }
}

fn deadline_after(duration: Duration) -> Result<u64, NamespaceInspectorProductionError> {
    boottime_now()?
        .checked_add(duration.as_nanos() as u64)
        .ok_or(NamespaceInspectorProductionError::Contract(
            "transport deadline overflowed",
        ))
}

fn ensure_before(deadline: u64) -> Result<(), NamespaceInspectorProductionError> {
    if boottime_now()? < deadline {
        Ok(())
    } else {
        Err(NamespaceInspectorProductionError::Contract(
            "transport deadline elapsed",
        ))
    }
}

fn boottime_now() -> Result<u64, NamespaceInspectorProductionError> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| {
        NamespaceInspectorProductionError::Contract("CLOCK_BOOTTIME seconds are invalid")
    })?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| {
        NamespaceInspectorProductionError::Contract("CLOCK_BOOTTIME nanoseconds are invalid")
    })?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(NamespaceInspectorProductionError::Contract(
            "CLOCK_BOOTTIME overflowed",
        ))
}

fn open_directory(path: &Path) -> Result<OwnedFd, NamespaceInspectorProductionError> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| io("open protected directory", source.into()))
}

fn open_executable(path: &Path) -> Result<OwnedFd, NamespaceInspectorProductionError> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| io("open fixed executable", source.into()))
}

fn open_regular(
    path: &Path,
    access: rustix::fs::OFlags,
    operation: &'static str,
) -> Result<File, NamespaceInspectorProductionError> {
    let descriptor = rustix::fs::open(
        path,
        access
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|source| io(operation, source.into()))?;
    let file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|source| io(operation, source))?
        .is_file()
    {
        return Err(NamespaceInspectorProductionError::Contract(
            "protected credential is not a regular file",
        ));
    }
    Ok(file)
}

fn descriptor_inode(descriptor: BorrowedFd<'_>) -> Result<u64, NamespaceInspectorProductionError> {
    let metadata =
        rustix::fs::fstat(descriptor).map_err(|source| io("inspect pidfd inode", source.into()))?;
    let inode = metadata.st_ino as u64;
    if inode == 0 {
        return Err(NamespaceInspectorProductionError::Contract(
            "pidfd inode is zero",
        ));
    }
    Ok(inode)
}

fn normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && path.file_name().is_some_and(|name| name != OsStr::new(""))
}

fn io(operation: &'static str, source: std::io::Error) -> NamespaceInspectorProductionError {
    NamespaceInspectorProductionError::Io { operation, source }
}

fn protected_deployment(
    error: ProtectedNamespaceInspectorDeploymentContractError,
) -> NamespaceInspectorProductionError {
    NamespaceInspectorProductionError::ProtectedDeployment(error.to_string())
}

fn map_worker_pid1_error(error: BrokerPid1QueryErrorV2) -> NamespaceInspectorProductionError {
    NamespaceInspectorProductionError::WorkerPid1(error.to_string())
}

fn authentication(
    error: NamespaceInspectorKernelAuthenticationError,
) -> NamespaceInspectorProductionError {
    NamespaceInspectorProductionError::Authentication(error.to_string())
}

fn manager_query(
    error: NamespaceInspectorManagerQuerySessionError,
) -> NamespaceInspectorProductionError {
    NamespaceInspectorProductionError::ManagerQuery(error.to_string())
}

fn protected_store(error: InspectorProtectedRootError) -> NamespaceInspectorProductionError {
    NamespaceInspectorProductionError::ProtectedStore(error.to_string())
}

fn model_error(error: NetworkNamespaceInspectorError) -> NamespaceInspectorProductionError {
    NamespaceInspectorProductionError::Model(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn exact_initial_descriptor_contract_rejects_an_extra_descriptor() {
        assert!(validate_initial_descriptor_numbers(&[0, 1, 2, 3]).is_ok());
        assert!(validate_initial_descriptor_numbers(&[0, 1, 2, 3, 4]).is_err());
        assert!(validate_initial_descriptor_numbers(&[0, 1, 3]).is_err());
    }

    #[test]
    fn inherited_standard_streams_bind_one_accepted_socket() {
        let (accepted, other_endpoint) = UnixStream::pair().unwrap();
        let output = accepted.try_clone().unwrap();
        let journal = tempfile::tempfile().unwrap();

        assert!(
            validate_inherited_standard_streams(accepted.as_fd(), output.as_fd(), journal.as_fd())
                .is_ok()
        );
        assert!(
            validate_inherited_standard_streams(
                accepted.as_fd(),
                other_endpoint.as_fd(),
                journal.as_fd(),
            )
            .is_err()
        );
        assert!(
            validate_inherited_standard_streams(
                accepted.as_fd(),
                output.as_fd(),
                accepted.as_fd(),
            )
            .is_err()
        );
        assert!(
            validate_inherited_standard_streams(
                journal.as_fd(),
                journal.as_fd(),
                other_endpoint.as_fd(),
            )
            .is_err()
        );
    }

    #[test]
    fn inspector_entry_rejects_an_extra_task() {
        let rendezvous = Arc::new(Barrier::new(2));
        let child_rendezvous = Arc::clone(&rendezvous);
        let task = std::thread::spawn(move || {
            child_rendezvous.wait();
            child_rendezvous.wait();
        });

        rendezvous.wait();
        assert!(SingleThreadedProcess::verify().is_err());
        rendezvous.wait();
        assert!(task.join().is_ok());
    }

    #[test]
    fn selinux_must_report_the_exact_enforcing_state() {
        assert!(validate_selinux_enforcing_state(b"1\n").is_ok());
        for rejected in [b"0\n".as_slice(), b"1", b"1\nextra", b""] {
            assert!(validate_selinux_enforcing_state(rejected).is_err());
        }
    }

    #[test]
    fn credentials_directory_has_exactly_five_fixed_handles() {
        let directory = tempfile::tempdir().unwrap();
        for name in CREDENTIAL_HANDLES {
            std::fs::write(directory.path().join(name), b"credential").unwrap();
        }

        assert!(validate_credential_handles(directory.path()).is_ok());

        std::fs::write(directory.path().join("unexpected"), b"extra").unwrap();
        assert!(validate_credential_handles(directory.path()).is_err());

        std::fs::remove_file(directory.path().join("unexpected")).unwrap();
        std::fs::remove_file(directory.path().join(LAUNCH_POLICY_CREDENTIAL)).unwrap();
        assert!(validate_credential_handles(directory.path()).is_err());
    }

    #[test]
    fn worker_pid1_readback_must_match_the_authenticated_worker() {
        let unit = "aos-sandbox-network-lifecycle-worker@7.service";
        let cgroup = format!("aos.slice/aos-control.slice/{unit}");
        let worker = InspectorProcessIdentityV1 {
            pid: 37,
            thread_group_id: 37,
            parent_pid: 1,
            cgroup_id: 71,
        };
        let observed = BrokerPid1ServiceObservationV2 {
            unit: unit.to_owned(),
            invocation_id: [5; 16],
            main_pid: worker.pid,
            control_group_id: worker.cgroup_id,
            control_group: format!("/{cgroup}"),
            fragment_path: "/nix/store/example/worker.service".to_owned(),
            executable: "/nix/store/example/worker".to_owned(),
            arguments: vec!["/nix/store/example/worker".to_owned()],
        };

        assert!(require_worker_pid1_match(&observed, unit, &cgroup, worker).is_ok());

        let mut changed = observed.clone();
        changed.unit.push('x');
        assert!(require_worker_pid1_match(&changed, unit, &cgroup, worker).is_err());

        let mut changed = observed.clone();
        changed.control_group.push('x');
        assert!(require_worker_pid1_match(&changed, unit, &cgroup, worker).is_err());

        let mut changed = observed.clone();
        changed.main_pid += 1;
        assert!(require_worker_pid1_match(&changed, unit, &cgroup, worker).is_err());

        let mut changed = observed.clone();
        changed.control_group_id += 1;
        assert!(require_worker_pid1_match(&changed, unit, &cgroup, worker).is_err());

        let mut changed = observed;
        changed.invocation_id = [0; 16];
        assert!(require_worker_pid1_match(&changed, unit, &cgroup, worker).is_err());
    }

    #[test]
    fn raw_instance_can_supply_only_the_accept_ordinal() {
        let instance =
            reconstruct_instance_from_evidence("7-11-13_17-19", 7, 11, 13, 17, 19).unwrap();

        assert_eq!(instance.canonical_text(), "7-11-13_17-19");
        assert!(reconstruct_instance_from_evidence("7-23-13_17-19", 7, 11, 13, 17, 19).is_err());
        assert!(reconstruct_instance_from_evidence("9-11-13_17-19", 7, 11, 13, 17, 19).is_err());
    }

    #[test]
    fn cgroup_locator_accepts_only_the_fixed_control_slice_template() {
        let cgroup = concat!(
            "aos.slice/aos-control.slice/",
            "aos-sandbox-network-namespace-inspector@7-11-13_17-19.service"
        );

        assert_eq!(instance_from_cgroup(cgroup).unwrap(), "7-11-13_17-19");
        assert!(
            instance_from_cgroup(
                "aos.slice/aos-foreign.slice/aos-sandbox-network-namespace-inspector@7-11-13_17-19.service"
            )
            .is_err()
        );
        assert!(
            instance_from_cgroup("aos.slice/aos-control.slice/aos-netd@7-11-13_17-19.service")
                .is_err()
        );
    }
}
