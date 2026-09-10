//! Production runtime for the unprivileged node controller.
//!
//! The service is the sole writer of its protected journal. On every restart it
//! replays any durable pending Host catalog before acquiring new authenticated
//! Storage, Network, Mount, or destination-slot observations. Only a complete
//! mutually current inventory projection and authenticated Host confirmation
//! opens the systemd readiness gate.
//!
//! The first production tranche deliberately exposes only the read-only
//! `GetNodeCapabilities` diagnostic RPC to root on a local Unix socket.
//! UID 0 is trusted here as the local administrator, not as another node
//! service role; the response contains no catalog rows, resources, credentials,
//! operation state, or mutation surface.
//! Assignment compilation, Guardian plan signing, and every broker Apply path
//! return explicit unavailable results; their absence can never be mistaken
//! for mutation authority.

use std::io::IoSlice;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use aos_proto::aos::sandbox::v1::{
    CancelOperationRequestView, CancelOperationResponse, Event, GetNodeCapabilitiesRequestView,
    GetNodeCapabilitiesResponse, GetOperationRequestView, GetOperationResponse, NodeCapabilities,
    OperationService, OperationServiceExt, Timestamp, WatchRequestView,
};
use aos_sandbox_core::{NodeId, ObjectDigest, OperationId};
use aos_sandbox_linux::Error as LinuxError;
use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use buffa::view::OwnedView;
use connectrpc::{ConnectError, Context, ErrorCode};
use futures::Stream;
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    sendmsg_addr, socket_with,
};
use sha2::{Digest as _, Sha256};

use crate::host_catalog_publication::{
    HostCatalogPublicationClient, HostCatalogPublicationError, HostCatalogServiceIdentity,
};
use crate::mount_preparation::{MountCatalogPreparationError, MountServiceIdentity};
use crate::{
    ActivatedOperationCompiler, ControllerRequestScopeV1, ControllerServiceError,
    DestinationSlotInventoryClient, EffectFailure, EffectObservation, EffectPlan, EffectReceipt,
    HostCatalogReconciliationError, HostCatalogReconciliationV1, Journal, JournalError,
    JournalLimits, JournalRecord, JournalTransaction, MountAttemptError, MountInventoryClient,
    NetworkResourceInventoryClient, NodeController, NodeControllerLimits,
    OperationCompilationError, OperationPlan, Reconciler, RecordNamespace, ResourceInventoryError,
    ResourceInventoryServiceIdentity, SingleNodeEffectExecutor, StorageResourceInventoryClient,
};

const STATE_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const JOURNAL_NAME: &str = "controller.journal";
const DIAGNOSTIC_SOCKET: &str = "/run/aos/sandboxd/diagnostics.sock";
const HOST_SOCKET: &str = "/run/aos/sandbox-host/control.sock";
const STORAGE_SOCKET: &str = "/run/aos/sandbox-storage/control.sock";
const MOUNT_SOCKET: &str = "/run/aos/sandbox-mount/control.sock";
const NETWORK_SOCKET: &str = "/run/aos/sandbox-network/control.sock";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CONTROL_SLICE: &str = "aos.slice/aos-control.slice";
const HOST_SLICE: &str = "system.slice";
const HOST_SERVICE: &str = "aos-sandbox-hostd.service";
const STORAGE_CGROUP: &str = "aos-storaged.service";
const MOUNT_CGROUP: &str = "aos-sandbox-mountd.service";
const NETWORK_CGROUP: &str = "aos-netd.service";
const NODE_ID_CREDENTIAL: &str = "node-id";
const CONTROLLER_IDENTITY_KEY: &[u8] = b"node";
const CONTROLLER_IDENTITY_MAGIC: &[u8; 8] = b"AOSCNI01";
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const HOST_PUBLICATION_WINDOW_NANOSECONDS: u64 = 10_000_000_000;
const REQUEST_SCOPE: [u8; 32] = [0x43; 32];
const UNAVAILABLE_REASON: &str = "production mutation authority is not installed";
const MEBIBYTE: usize = 1024 * 1024;
const PRODUCTION_MAXIMUM_JOURNAL_BYTES: u64 = 256 * 1024 * 1024;
const PRODUCTION_MAXIMUM_MATERIALIZED_BYTES: usize = 128 * MEBIBYTE;
const PRODUCTION_MAXIMUM_TRANSACTIONS: usize = 65_536;
const PRODUCTION_MAXIMUM_MATERIALIZED_RECORDS: usize = 131_072;

type ProductionController = NodeController<UnavailableCompiler, UnavailableExecutor>;

/// Runs the controller from systemd's protected runtime environment.
///
/// Positional arguments are the fixed decimal controller UID and GID. The node
/// identity is read from `CREDENTIALS_DIRECTORY/node-id`; broker endpoints,
/// cgroups, journal location, and root-only diagnostic socket are fixed
/// production paths.
///
/// # Errors
///
/// Returns an error for invalid activation, unsafe state or socket paths,
/// corrupt durable state, failure of the initial authenticated catalog cycle,
/// systemd notification failure, or diagnostic-server termination.
pub fn run_from_environment() -> Result<(), ControllerRuntimeError> {
    let configuration = RuntimeConfiguration::from_process()?;
    configuration.validate_process_identity()?;
    let node_id = read_node_id()?;
    let listener = bind_diagnostic_socket(&configuration)?;
    let controller = open_controller(&configuration, node_id)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ControllerRuntimeError::Runtime)?;
    let listener = runtime.block_on(into_async_diagnostic_listener(listener))?;
    let capabilities = Arc::new(Mutex::new(CapabilityState::starting(node_id)));
    let (events_tx, events_rx) = mpsc::channel();
    let worker_capabilities = Arc::clone(&capabilities);

    std::thread::Builder::new()
        .name("aos-sandboxd-reconciler".to_owned())
        .spawn(move || controller_worker(controller, worker_capabilities, events_tx))
        .map_err(ControllerRuntimeError::WorkerSpawn)?;

    wait_for_initial_readiness(&events_rx)?;
    SystemdReadyNotifier::from_environment()?.notify_ready()?;

    let service = Arc::new(CapabilityService { capabilities });
    let connect = service
        .register(connectrpc::Router::new())
        .into_axum_service();
    let application = axum::Router::new().fallback_service(connect);
    let result = runtime.block_on(serve_until_worker_failure(listener, application, events_rx));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

async fn serve_until_worker_failure(
    listener: AuthenticatedDiagnosticListener,
    application: axum::Router,
    events: mpsc::Receiver<WorkerEvent>,
) -> Result<(), ControllerRuntimeError> {
    let worker = tokio::task::spawn_blocking(move || events.recv());
    tokio::select! {
        result = axum::serve(listener, application) => {
            result.map_err(ControllerRuntimeError::DiagnosticServer)
        }
        result = worker => {
            match result.map_err(ControllerRuntimeError::WorkerJoin)? {
                Ok(WorkerEvent::Fatal(message)) => Err(ControllerRuntimeError::Worker(message)),
                Ok(WorkerEvent::Ready) => Err(ControllerRuntimeError::Worker(
                    "controller worker emitted duplicate readiness".to_owned(),
                )),
                Err(_) => Err(ControllerRuntimeError::Worker(
                    "controller worker exited without a terminal status".to_owned(),
                )),
            }
        }
    }
}

async fn into_async_diagnostic_listener(
    listener: std::os::unix::net::UnixListener,
) -> Result<AuthenticatedDiagnosticListener, ControllerRuntimeError> {
    into_async_authenticated_listener(listener, 0).await
}

async fn into_async_authenticated_listener(
    listener: std::os::unix::net::UnixListener,
    expected_uid: u32,
) -> Result<AuthenticatedDiagnosticListener, ControllerRuntimeError> {
    let listener = tokio::net::UnixListener::from_std(listener)
        .map_err(ControllerRuntimeError::DiagnosticSocketRuntime)?;
    Ok(AuthenticatedDiagnosticListener::new(listener, expected_uid))
}

struct AuthenticatedDiagnosticListener {
    listener: tokio::net::UnixListener,
    expected_uid: u32,
}

impl AuthenticatedDiagnosticListener {
    const fn new(listener: tokio::net::UnixListener, expected_uid: u32) -> Self {
        Self {
            listener,
            expected_uid,
        }
    }
}

impl axum::serve::Listener for AuthenticatedDiagnosticListener {
    type Io = tokio::net::UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.listener.accept().await {
                Ok((stream, address)) => match stream.peer_cred() {
                    Ok(credentials) if credentials.uid() == self.expected_uid => {
                        return (stream, address);
                    }
                    Ok(credentials) => {
                        eprintln!(
                            "aos-sandboxd: rejected diagnostic connection from UID {}",
                            credentials.uid()
                        );
                    }
                    Err(error) => {
                        eprintln!(
                            "aos-sandboxd: rejected diagnostic connection without peer credentials: {error}"
                        );
                    }
                },
                Err(error) => {
                    eprintln!("aos-sandboxd: diagnostic socket accept failed: {error}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

fn controller_worker(
    mut controller: ProductionController,
    capabilities: Arc<Mutex<CapabilityState>>,
    events: mpsc::Sender<WorkerEvent>,
) {
    let mut ready = false;
    loop {
        match run_controller_cycle(&mut controller) {
            Ok(catalog) => {
                let update = capabilities
                    .lock()
                    .map_err(|_| "capability status lock is poisoned".to_owned())
                    .map(|mut state| state.record_success(catalog.generation, catalog.digest));
                if let Err(message) = update {
                    let _ = events.send(WorkerEvent::Fatal(message));
                    return;
                }
                if !ready {
                    if events.send(WorkerEvent::Ready).is_err() {
                        return;
                    }
                    ready = true;
                }
            }
            Err(CycleFailure::Retryable(message)) => {
                if let Ok(mut state) = capabilities.lock() {
                    state.record_retryable_failure(message.clone());
                } else {
                    let _ = events.send(WorkerEvent::Fatal(
                        "capability status lock is poisoned".to_owned(),
                    ));
                    return;
                }
                eprintln!("aos-sandboxd: reconciliation pending: {message}");
            }
            Err(CycleFailure::Fatal(message)) => {
                let _ = events.send(WorkerEvent::Fatal(message));
                return;
            }
        }
        std::thread::sleep(RECONCILIATION_INTERVAL);
    }
}

fn wait_for_initial_readiness(
    events: &mpsc::Receiver<WorkerEvent>,
) -> Result<(), ControllerRuntimeError> {
    match events.recv() {
        Ok(WorkerEvent::Ready) => Ok(()),
        Ok(WorkerEvent::Fatal(message)) => Err(ControllerRuntimeError::Worker(message)),
        Err(_) => Err(ControllerRuntimeError::Worker(
            "controller worker exited before readiness".to_owned(),
        )),
    }
}

fn run_controller_cycle(
    controller: &mut ProductionController,
) -> Result<CatalogStatus, CycleFailure> {
    pending_first_read_only_cycle(
        controller,
        |controller| {
            controller
                .pending_host_catalog()
                .map_err(|error| CycleFailure::Fatal(error.to_string()))
        },
        |controller, pending| publish_pending(controller, pending).map(|_| ()),
        validate_read_only_ledger,
        refresh_catalog,
    )
}

fn pending_first_read_only_cycle<State, Pending, Status, Error>(
    state: &mut State,
    recover: impl FnOnce(&mut State) -> Result<Option<Pending>, Error>,
    publish: impl FnOnce(&mut State, Pending) -> Result<(), Error>,
    validate_idle: impl FnOnce(&mut State) -> Result<(), Error>,
    continue_cycle: impl FnOnce(&mut State) -> Result<Status, Error>,
) -> Result<Status, Error> {
    if let Some(pending) = recover(state)? {
        publish(state, pending)?;
    }

    validate_idle(state)?;
    continue_cycle(state)
}

fn validate_read_only_ledger(controller: &mut ProductionController) -> Result<(), CycleFailure> {
    let unfinished = controller
        .validated_unfinished_operation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    if unfinished.is_some() {
        return Err(CycleFailure::Fatal(
            "durable operation ledger contains unfinished mutation work".to_owned(),
        ));
    }

    Ok(())
}

fn refresh_catalog(controller: &mut ProductionController) -> Result<CatalogStatus, CycleFailure> {
    // Mount and destination state participate in the controller-state digest
    // captured by Storage and Network, so acquire them first.
    let mounts = controller
        .record_mount_inventory(mount_inventory_client()?)
        .map_err(classify_mount_error)?;
    let destinations = controller
        .record_destination_slot_inventory(destination_inventory_client()?)
        .map_err(classify_mount_error)?;
    let storage = controller
        .record_storage_resource_inventory(storage_inventory_client()?)
        .map_err(classify_resource_error)?;
    let network = controller
        .record_network_resource_inventory(network_inventory_client()?)
        .map_err(classify_resource_error)?;

    match controller
        .prepare_host_catalog(storage, network, mounts, destinations)
        .map_err(classify_catalog_error)?
    {
        HostCatalogReconciliationV1::Current(current) => Ok(CatalogStatus {
            generation: current.generation(),
            digest: current.catalog_digest(),
        }),
        HostCatalogReconciliationV1::Publish(pending) => publish_pending(controller, pending),
    }
}

fn publish_pending(
    controller: &mut ProductionController,
    pending: crate::DurablePendingHostCatalogV1,
) -> Result<CatalogStatus, CycleFailure> {
    let client = host_publication_client()?;
    let deadline = boottime_nanoseconds()?
        .checked_add(HOST_PUBLICATION_WINDOW_NANOSECONDS)
        .ok_or_else(|| CycleFailure::Retryable("Host publication deadline overflow".to_owned()))?;
    let current = controller
        .dispatch_host_catalog(pending, client, deadline)
        .map_err(classify_catalog_error)?;
    Ok(CatalogStatus {
        generation: current.generation(),
        digest: current.catalog_digest(),
    })
}

fn mount_inventory_client() -> Result<MountInventoryClient, CycleFailure> {
    let identity = MountServiceIdentity {
        uid: 0,
        gid: 0,
        cgroup: service_cgroup(CONTROL_SLICE, MOUNT_CGROUP)?,
    };
    MountInventoryClient::connect(Path::new(MOUNT_SOCKET), identity).map_err(classify_mount_error)
}

fn destination_inventory_client() -> Result<DestinationSlotInventoryClient, CycleFailure> {
    let identity = MountServiceIdentity {
        uid: 0,
        gid: 0,
        cgroup: service_cgroup(CONTROL_SLICE, MOUNT_CGROUP)?,
    };
    DestinationSlotInventoryClient::connect(Path::new(MOUNT_SOCKET), identity)
        .map_err(classify_mount_error)
}

fn storage_inventory_client() -> Result<StorageResourceInventoryClient, CycleFailure> {
    let identity = ResourceInventoryServiceIdentity {
        uid: 0,
        gid: 0,
        cgroup: service_cgroup(CONTROL_SLICE, STORAGE_CGROUP)?,
    };
    StorageResourceInventoryClient::connect(Path::new(STORAGE_SOCKET), identity)
        .map_err(classify_resource_error)
}

fn network_inventory_client() -> Result<NetworkResourceInventoryClient, CycleFailure> {
    let identity = ResourceInventoryServiceIdentity {
        uid: 0,
        gid: 0,
        cgroup: service_cgroup(CONTROL_SLICE, NETWORK_CGROUP)?,
    };
    NetworkResourceInventoryClient::connect(Path::new(NETWORK_SOCKET), identity)
        .map_err(classify_resource_error)
}

fn host_publication_client() -> Result<HostCatalogPublicationClient, CycleFailure> {
    let identity = HostCatalogServiceIdentity {
        uid: 0,
        gid: 0,
        cgroup: service_cgroup(HOST_SLICE, HOST_SERVICE)?,
    };
    HostCatalogPublicationClient::connect(Path::new(HOST_SOCKET), identity)
        .map_err(classify_publication_error)
}

fn service_cgroup(slice: &str, unit: &str) -> Result<RetainedCgroupAnchor, CycleFailure> {
    let descriptor = rustix::fs::open(
        CGROUP_ROOT,
        rustix::fs::OFlags::PATH
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| CycleFailure::Retryable(error.to_string()))?;
    let root = CgroupV2Root::from_owned(descriptor)
        .map_err(|error| CycleFailure::Retryable(error.to_string()))?;
    root.resolve(service_cgroup_path(slice, unit).as_path())
        .map_err(|error| CycleFailure::Retryable(error.to_string()))
}

fn service_cgroup_path(slice: &str, unit: &str) -> PathBuf {
    Path::new(slice).join(unit)
}

fn classify_mount_error(error: MountAttemptError) -> CycleFailure {
    let retryable = match &error {
        MountAttemptError::BrokerRejected { retryable, .. } => *retryable,
        MountAttemptError::Preparation(preparation) => retryable_mount_preparation(preparation),
        MountAttemptError::Transport(transport) => retryable_transport(transport),
        MountAttemptError::Kernel(kernel) => retryable_kernel(kernel),
        MountAttemptError::CorruptState
        | MountAttemptError::Conflict
        | MountAttemptError::Capacity
        | MountAttemptError::Deadline
        | MountAttemptError::MountIdentity
        | MountAttemptError::Protocol(_)
        | MountAttemptError::Current(_)
        | MountAttemptError::NamespaceTarget(_)
        | MountAttemptError::Journal(_) => false,
    };

    classified_failure(retryable, error)
}

fn classify_resource_error(error: ResourceInventoryError) -> CycleFailure {
    let retryable = match &error {
        ResourceInventoryError::Deadline => true,
        ResourceInventoryError::Kernel(kernel) => retryable_kernel(kernel),
        ResourceInventoryError::BrokerRejected { retryable, .. } => *retryable,
        ResourceInventoryError::Transport(transport) => retryable_transport(transport),
        ResourceInventoryError::CorruptState
        | ResourceInventoryError::Conflict
        | ResourceInventoryError::Capacity
        | ResourceInventoryError::EntropyUnavailable
        | ResourceInventoryError::ServiceIdentity
        | ResourceInventoryError::Protocol(_)
        | ResourceInventoryError::Journal(_)
        | ResourceInventoryError::Io(_) => false,
    };

    classified_failure(retryable, error)
}

fn classify_catalog_error(error: HostCatalogReconciliationError) -> CycleFailure {
    if let HostCatalogReconciliationError::Publication(publication) = error {
        return classify_publication_error(publication);
    }

    let retryable = matches!(
        error,
        HostCatalogReconciliationError::InventoryConflict
            | HostCatalogReconciliationError::IncompleteResources
    );
    classified_failure(retryable, error)
}

fn classify_publication_error(error: HostCatalogPublicationError) -> CycleFailure {
    let retryable = match &error {
        HostCatalogPublicationError::Deadline => true,
        HostCatalogPublicationError::Kernel(kernel) => retryable_kernel(kernel),
        HostCatalogPublicationError::BrokerRejected { retryable, .. } => *retryable,
        HostCatalogPublicationError::Transport(transport) => retryable_transport(transport),
        HostCatalogPublicationError::InvalidDraft
        | HostCatalogPublicationError::EntropyUnavailable
        | HostCatalogPublicationError::HostIdentity
        | HostCatalogPublicationError::ReceiptMismatch
        | HostCatalogPublicationError::Protocol(_)
        | HostCatalogPublicationError::CatalogFile(_)
        | HostCatalogPublicationError::Io(_) => false,
    };

    classified_failure(retryable, error)
}

fn retryable_mount_preparation(error: &MountCatalogPreparationError) -> bool {
    match error {
        MountCatalogPreparationError::Deadline => true,
        MountCatalogPreparationError::Kernel(kernel) => retryable_kernel(kernel),
        MountCatalogPreparationError::Transport(transport) => retryable_transport(transport),
        MountCatalogPreparationError::InvalidIntent
        | MountCatalogPreparationError::EntropyUnavailable
        | MountCatalogPreparationError::MountIdentity
        | MountCatalogPreparationError::ReplayMismatch
        | MountCatalogPreparationError::HostAuthority(_)
        | MountCatalogPreparationError::CurrentTarget(_)
        | MountCatalogPreparationError::Semantics(_)
        | MountCatalogPreparationError::DispatchTemplate(_)
        | MountCatalogPreparationError::Protocol(_)
        | MountCatalogPreparationError::Io(_) => false,
    }
}

fn retryable_transport(error: &SeqpacketError) -> bool {
    matches!(
        error,
        SeqpacketError::WouldBlock | SeqpacketError::Interrupted | SeqpacketError::Closed
    ) || matches!(error, SeqpacketError::Kernel(kernel) if retryable_kernel(kernel))
}

fn retryable_kernel(error: &LinuxError) -> bool {
    matches!(
        error,
        LinuxError::Syscall { .. } | LinuxError::DeadlineExceeded { .. }
    )
}

fn classified_failure(error_is_retryable: bool, error: impl ToString) -> CycleFailure {
    if error_is_retryable {
        CycleFailure::Retryable(error.to_string())
    } else {
        CycleFailure::Fatal(error.to_string())
    }
}

fn boottime_nanoseconds() -> Result<u64, CycleFailure> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec)
        .map_err(|_| CycleFailure::Retryable("CLOCK_BOOTTIME is negative".to_owned()))?;
    let nanoseconds = u64::try_from(now.tv_nsec)
        .map_err(|_| CycleFailure::Retryable("CLOCK_BOOTTIME is invalid".to_owned()))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| CycleFailure::Retryable("CLOCK_BOOTTIME overflow".to_owned()))
}

fn open_controller(
    configuration: &RuntimeConfiguration,
    node_id: [u8; 16],
) -> Result<ProductionController, ControllerRuntimeError> {
    let (journal, _) = Journal::open_protected_at_for_uid(
        &configuration.state_directory,
        JOURNAL_NAME,
        production_journal_limits(),
        configuration.uid,
    )?;

    controller_from_journal(journal, node_id)
}

fn controller_from_journal(
    mut journal: Journal,
    node_id: [u8; 16],
) -> Result<ProductionController, ControllerRuntimeError> {
    bind_controller_identity(&mut journal, node_id)?;
    crate::runtime_authority::RuntimeAuthorityStore::load(
        &mut journal,
        crate::runtime_authority::RuntimeAuthorityLimits::default(),
    )?
    .validate_current_node(NodeId::from_bytes(node_id))?;
    let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes(REQUEST_SCOPE))?;
    let limits = NodeControllerLimits::new(1024 * 1024, 65_536, 1)?;
    Ok(NodeController::new(
        scope,
        limits,
        UnavailableCompiler,
        Reconciler::new(journal, UnavailableExecutor),
    ))
}

fn bind_controller_identity(
    journal: &mut Journal,
    node_id: [u8; 16],
) -> Result<(), ControllerRuntimeError> {
    let records = journal
        .records(RecordNamespace::ControllerIdentity)
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    match records.as_slice() {
        [] => {
            if journal.all_records().next().is_some() {
                return Err(ControllerRuntimeError::UnboundControllerIdentity);
            }
            let mut value = Vec::with_capacity(CONTROLLER_IDENTITY_MAGIC.len() + node_id.len());
            value.extend_from_slice(CONTROLLER_IDENTITY_MAGIC);
            value.extend_from_slice(&node_id);
            let record = JournalRecord::put(
                RecordNamespace::ControllerIdentity,
                CONTROLLER_IDENTITY_KEY.to_vec(),
                value,
            );
            let transaction =
                JournalTransaction::new(OperationId::new().into_bytes(), vec![record])?;
            journal.commit(&transaction)?;
            Ok(())
        }
        [(key, value)]
            if key.as_slice() == CONTROLLER_IDENTITY_KEY
                && value.len() == CONTROLLER_IDENTITY_MAGIC.len() + node_id.len()
                && value.starts_with(CONTROLLER_IDENTITY_MAGIC) =>
        {
            if value[CONTROLLER_IDENTITY_MAGIC.len()..] != node_id {
                return Err(ControllerRuntimeError::ControllerIdentityMismatch);
            }
            Ok(())
        }
        _ => Err(ControllerRuntimeError::InvalidControllerIdentity),
    }
}

fn production_journal_limits() -> JournalLimits {
    JournalLimits {
        maximum_journal_bytes: PRODUCTION_MAXIMUM_JOURNAL_BYTES,
        maximum_record_bytes: 16 * MEBIBYTE,
        maximum_key_bytes: 1024,
        maximum_records_per_transaction: 4096,
        maximum_transaction_bytes: 64 * MEBIBYTE,
        maximum_transactions: PRODUCTION_MAXIMUM_TRANSACTIONS,
        maximum_materialized_bytes: PRODUCTION_MAXIMUM_MATERIALIZED_BYTES,
        maximum_materialized_records: PRODUCTION_MAXIMUM_MATERIALIZED_RECORDS,
    }
}

fn read_node_id() -> Result<[u8; 16], ControllerRuntimeError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or(ControllerRuntimeError::InvalidCredential)?;
    let bytes = std::fs::read(Path::new(&directory).join(NODE_ID_CREDENTIAL))
        .map_err(ControllerRuntimeError::CredentialRead)?;
    let node_id: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ControllerRuntimeError::InvalidCredential)?;
    if node_id == [0; 16] {
        return Err(ControllerRuntimeError::InvalidCredential);
    }
    Ok(node_id)
}

fn bind_diagnostic_socket(
    configuration: &RuntimeConfiguration,
) -> Result<std::os::unix::net::UnixListener, ControllerRuntimeError> {
    let parent = configuration
        .diagnostic_socket
        .parent()
        .ok_or(ControllerRuntimeError::UnsafeDiagnosticSocket)?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != configuration.uid
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ControllerRuntimeError::UnsafeDiagnosticSocket);
    }
    match std::fs::symlink_metadata(&configuration.diagnostic_socket) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == configuration.uid => {
            std::fs::remove_file(&configuration.diagnostic_socket)
                .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
        }
        Ok(_) => return Err(ControllerRuntimeError::UnsafeDiagnosticSocket),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ControllerRuntimeError::DiagnosticSocketFilesystem(error)),
    }
    let listener = std::os::unix::net::UnixListener::bind(&configuration.diagnostic_socket)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    listener
        .set_nonblocking(true)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    std::fs::set_permissions(
        &configuration.diagnostic_socket,
        std::fs::Permissions::from_mode(0o660),
    )
    .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    Ok(listener)
}

#[derive(Clone, Debug)]
struct RuntimeConfiguration {
    uid: u32,
    gid: u32,
    state_directory: PathBuf,
    diagnostic_socket: PathBuf,
}

impl RuntimeConfiguration {
    fn from_process() -> Result<Self, ControllerRuntimeError> {
        let mut arguments = std::env::args();
        let _program = arguments.next();
        let uid = parse_identity(arguments.next(), "controller UID")?;
        let gid = parse_identity(arguments.next(), "controller GID")?;
        if arguments.next().is_some() {
            return Err(ControllerRuntimeError::InvalidArguments(
                "usage: aos-sandboxd CONTROLLER_UID CONTROLLER_GID",
            ));
        }
        Ok(Self {
            uid,
            gid,
            state_directory: PathBuf::from(STATE_DIRECTORY),
            diagnostic_socket: PathBuf::from(DIAGNOSTIC_SOCKET),
        })
    }

    fn validate_process_identity(&self) -> Result<(), ControllerRuntimeError> {
        if self.uid == 0
            || self.gid == 0
            || rustix::process::getuid().as_raw() != self.uid
            || rustix::process::geteuid().as_raw() != self.uid
            || rustix::process::getgid().as_raw() != self.gid
            || rustix::process::getegid().as_raw() != self.gid
        {
            return Err(ControllerRuntimeError::InvalidProcessIdentity);
        }
        Ok(())
    }
}

fn parse_identity(
    value: Option<String>,
    label: &'static str,
) -> Result<u32, ControllerRuntimeError> {
    value
        .ok_or(ControllerRuntimeError::InvalidArguments(label))?
        .parse()
        .map_err(|_| ControllerRuntimeError::InvalidArguments(label))
}

struct UnavailableCompiler;

impl ActivatedOperationCompiler for UnavailableCompiler {
    fn compile(
        &mut self,
        _canonical_request: &[u8],
        _request_digest: [u8; 32],
    ) -> Result<OperationPlan, OperationCompilationError> {
        Err(OperationCompilationError::Rejected)
    }
}

struct UnavailableExecutor;

impl SingleNodeEffectExecutor for UnavailableExecutor {
    fn observe(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _plan: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        Err(EffectFailure::Retryable(UNAVAILABLE_REASON.to_owned()))
    }

    fn apply(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        _plan: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        Err(EffectFailure::Retryable(UNAVAILABLE_REASON.to_owned()))
    }
}

#[derive(Clone, Copy)]
struct CatalogStatus {
    generation: u64,
    digest: ObjectDigest,
}

enum CycleFailure {
    Retryable(String),
    Fatal(String),
}

enum WorkerEvent {
    Ready,
    Fatal(String),
}

struct CapabilityState {
    node_id: [u8; 16],
    capability_generation: u64,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    observation_available: bool,
    retryable_failure: Option<String>,
    observed_at: rustix::time::Timespec,
}

impl CapabilityState {
    fn starting(node_id: [u8; 16]) -> Self {
        Self {
            node_id,
            capability_generation: 1,
            catalog_generation: 0,
            catalog_digest: ObjectDigest::from_bytes([0; 32]),
            observation_available: false,
            retryable_failure: Some("initial authenticated inventory is pending".to_owned()),
            observed_at: diagnostic_wall_time(),
        }
    }

    fn record_success(&mut self, generation: u64, digest: ObjectDigest) {
        let changed = !self.observation_available
            || self.catalog_generation != generation
            || self.catalog_digest != digest;
        self.catalog_generation = generation;
        self.catalog_digest = digest;
        self.observation_available = true;
        self.retryable_failure = None;
        self.observed_at = diagnostic_wall_time();
        if changed {
            self.capability_generation = self.capability_generation.saturating_add(1);
        }
    }

    fn record_retryable_failure(&mut self, message: String) {
        let changed = self.observation_available
            || self.retryable_failure.as_deref() != Some(message.as_str());
        self.observation_available = false;
        self.retryable_failure = Some(message);
        self.observed_at = diagnostic_wall_time();
        if changed {
            self.capability_generation = self.capability_generation.saturating_add(1);
        }
    }

    #[allow(
        clippy::result_large_err,
        reason = "ConnectRPC fixes the service error type and this is not a hot path."
    )]
    fn response(&self) -> Result<GetNodeCapabilitiesResponse, ConnectError> {
        let observed_at = timestamp(self.observed_at)?;
        let resource_version = capability_resource_version(
            self.node_id,
            self.capability_generation,
            self.catalog_generation,
            self.catalog_digest,
            self.observation_available,
        );
        Ok(GetNodeCapabilitiesResponse {
            capabilities: Some(NodeCapabilities {
                node_id: self.node_id.to_vec(),
                resource_version: resource_version.to_vec(),
                capability_generation: self.capability_generation,
                // No ownership-namespaced feature with a checked-in
                // conformance fixture is implemented by this read-only tranche.
                capabilities: Vec::new(),
                observed_at: Some(observed_at).into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
    }
}

fn capability_resource_version(
    node_id: [u8; 16],
    capability_generation: u64,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
    available: bool,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos.sandbox.controller-capabilities.v1\0");
    digest.update(node_id);
    digest.update(capability_generation.to_be_bytes());
    digest.update(catalog_generation.to_be_bytes());
    digest.update(catalog_digest.as_bytes());
    digest.update([u8::from(available)]);
    digest.finalize().into()
}

fn diagnostic_wall_time() -> rustix::time::Timespec {
    // This display-only sample never enters durable state, authority,
    // deadlines, inventory continuity, or readiness decisions.
    rustix::time::clock_gettime(rustix::time::ClockId::Realtime)
}

#[allow(
    clippy::result_large_err,
    reason = "ConnectRPC fixes the service error type and this is not a hot path."
)]
fn timestamp(value: rustix::time::Timespec) -> Result<Timestamp, ConnectError> {
    let error = if value.tv_sec < 0 {
        ConnectError::new(
            ErrorCode::Internal,
            "controller wall clock precedes the Unix epoch",
        )
    } else if !(0..1_000_000_000).contains(&value.tv_nsec) {
        ConnectError::new(ErrorCode::Internal, "controller wall clock is out of range")
    } else {
        return Ok(Timestamp {
            seconds: value.tv_sec,
            nanoseconds: u32::try_from(value.tv_nsec).map_err(|_| {
                ConnectError::new(ErrorCode::Internal, "controller wall clock is out of range")
            })?,
            ..Default::default()
        });
    };

    Err(error)
}

struct CapabilityService {
    capabilities: Arc<Mutex<CapabilityState>>,
}

impl OperationService for CapabilityService {
    async fn get_operation(
        &self,
        _context: Context,
        _request: OwnedView<GetOperationRequestView<'static>>,
    ) -> Result<(GetOperationResponse, Context), ConnectError> {
        Err(mutation_unavailable())
    }

    async fn cancel_operation(
        &self,
        _context: Context,
        _request: OwnedView<CancelOperationRequestView<'static>>,
    ) -> Result<(CancelOperationResponse, Context), ConnectError> {
        Err(mutation_unavailable())
    }

    async fn watch(
        &self,
        _context: Context,
        _request: OwnedView<WatchRequestView<'static>>,
    ) -> Result<
        (
            Pin<Box<dyn Stream<Item = Result<Event, ConnectError>> + Send>>,
            Context,
        ),
        ConnectError,
    > {
        Err(mutation_unavailable())
    }

    async fn get_node_capabilities(
        &self,
        context: Context,
        request: OwnedView<GetNodeCapabilitiesRequestView<'static>>,
    ) -> Result<(GetNodeCapabilitiesResponse, Context), ConnectError> {
        let capabilities = self.capabilities.lock().map_err(|_| {
            ConnectError::new(
                ErrorCode::Internal,
                "controller capability state is unavailable",
            )
        })?;
        if request.node_id != capabilities.node_id {
            return Err(ConnectError::new(
                ErrorCode::NotFound,
                "requested node does not match this controller",
            ));
        }
        Ok((capabilities.response()?, context))
    }
}

fn mutation_unavailable() -> ConnectError {
    ConnectError::new(ErrorCode::Unimplemented, UNAVAILABLE_REASON)
}

struct SystemdReadyNotifier {
    socket: std::os::fd::OwnedFd,
    address: SocketAddrUnix,
}

impl SystemdReadyNotifier {
    fn from_environment() -> Result<Self, ControllerRuntimeError> {
        let value =
            std::env::var_os("NOTIFY_SOCKET").ok_or(ControllerRuntimeError::InvalidNotifySocket)?;
        let value = value
            .to_str()
            .filter(|value| !value.is_empty())
            .ok_or(ControllerRuntimeError::InvalidNotifySocket)?;
        let address = if let Some(name) = value.strip_prefix('@') {
            if name.is_empty() {
                return Err(ControllerRuntimeError::InvalidNotifySocket);
            }
            SocketAddrUnix::new_abstract_name(name.as_bytes())
        } else {
            SocketAddrUnix::new(Path::new(value))
        }
        .map_err(ControllerRuntimeError::Notify)?;
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(ControllerRuntimeError::Notify)?;
        Ok(Self { socket, address })
    }

    fn notify_ready(&self) -> Result<(), ControllerRuntimeError> {
        let payload = b"READY=1";
        let written = sendmsg_addr(
            &self.socket,
            &self.address,
            &[IoSlice::new(payload)],
            &mut SendAncillaryBuffer::default(),
            SendFlags::NOSIGNAL,
        )
        .map_err(ControllerRuntimeError::Notify)?;
        if written != payload.len() {
            return Err(ControllerRuntimeError::PartialNotification);
        }
        Ok(())
    }
}

/// Reports activation, recovery, reconciliation, or serving failure.
#[derive(Debug, thiserror::Error)]
pub enum ControllerRuntimeError {
    /// Positional activation arguments are absent or invalid.
    #[error("invalid controller arguments: {0}")]
    InvalidArguments(&'static str),
    /// Real/effective UID or GID differs from the configured fixed identity.
    #[error("controller process identity does not match its configured UID/GID")]
    InvalidProcessIdentity,
    /// The protected node identity credential is absent or malformed.
    #[error("protected controller node identity is invalid")]
    InvalidCredential,
    /// The protected node identity credential could not be read.
    #[error("protected controller node identity could not be read: {0}")]
    CredentialRead(std::io::Error),
    /// Existing state predates a trustworthy durable node-identity binding.
    #[error("nonempty controller state has no durable node identity")]
    UnboundControllerIdentity,
    /// The durable controller node identity record is malformed or duplicated.
    #[error("durable controller node identity is invalid")]
    InvalidControllerIdentity,
    /// The configured node identity differs from the state-directory binding.
    #[error("configured node identity does not match durable controller state")]
    ControllerIdentityMismatch,
    /// The diagnostic socket parent or stale entry violates ownership and type rules.
    #[error("controller diagnostic socket path is unsafe")]
    UnsafeDiagnosticSocket,
    /// The diagnostic socket could not be inspected, replaced, bound, or permissioned.
    #[error("controller diagnostic socket failed: {0}")]
    DiagnosticSocketFilesystem(std::io::Error),
    /// The diagnostic socket could not be registered with the asynchronous runtime.
    #[error("controller diagnostic socket runtime registration failed: {0}")]
    DiagnosticSocketRuntime(std::io::Error),
    /// The protected journal failed to open or recover.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// Fixed controller configuration is invalid.
    #[error(transparent)]
    Controller(#[from] ControllerServiceError),
    /// Protected current runtime assignments do not belong to this node.
    #[error(transparent)]
    RuntimeAuthority(#[from] crate::runtime_authority::RuntimeAuthorityError),
    /// The reconciliation worker thread could not be created.
    #[error("controller worker could not start: {0}")]
    WorkerSpawn(std::io::Error),
    /// The reconciliation worker stopped before or after readiness.
    #[error("controller worker failed: {0}")]
    Worker(String),
    /// The asynchronous runtime could not start.
    #[error("controller async runtime failed: {0}")]
    Runtime(std::io::Error),
    /// The asynchronous worker monitor failed.
    #[error("controller worker monitor failed: {0}")]
    WorkerJoin(tokio::task::JoinError),
    /// The root-only local diagnostic ConnectRPC server terminated.
    #[error("controller diagnostic server failed: {0}")]
    DiagnosticServer(std::io::Error),
    /// The systemd notification address is absent or malformed.
    #[error("controller systemd notification socket is invalid")]
    InvalidNotifySocket,
    /// A systemd notification socket operation failed.
    #[error("controller systemd notification failed: {0}")]
    Notify(rustix::io::Errno),
    /// systemd accepted only part of the atomic readiness datagram.
    #[error("controller systemd readiness notification was partial")]
    PartialNotification,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "Fixture construction and regression assertions intentionally panic."
    )]

    use super::*;
    use axum::serve::Listener as _;

    fn diagnostic_configuration(directory: &tempfile::TempDir) -> RuntimeConfiguration {
        RuntimeConfiguration {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            state_directory: directory.path().join("state"),
            diagnostic_socket: directory.path().join("diagnostics.sock"),
        }
    }

    fn protected_test_journal(directory: &tempfile::TempDir, limits: JournalLimits) -> Journal {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Journal::open_protected_at_uid(
            directory.path(),
            JOURNAL_NAME,
            limits,
            rustix::process::getuid().as_raw(),
        )
        .unwrap()
        .0
    }

    #[test]
    fn readiness_changes_only_after_a_confirmed_catalog() {
        let mut state = CapabilityState::starting([7; 16]);
        let starting = state.response().unwrap();
        let starting = starting.capabilities.as_option().unwrap();
        assert!(starting.capabilities.is_empty());
        assert_eq!(starting.capability_generation, 1);
        let starting_version = starting.resource_version.clone();

        state.record_success(9, ObjectDigest::from_bytes([8; 32]));
        let ready = state.response().unwrap();
        let ready = ready.capabilities.as_option().unwrap();
        assert!(ready.capabilities.is_empty());
        assert_eq!(ready.capability_generation, 2);
        assert_ne!(ready.resource_version, starting_version);
    }

    #[test]
    fn unregistered_semantic_capabilities_are_not_advertised() {
        let mut state = CapabilityState::starting([7; 16]);
        state.record_success(1, ObjectDigest::from_bytes([8; 32]));
        let response = state.response().unwrap();
        let capabilities = response.capabilities.as_option().unwrap();
        let mutation = mutation_unavailable();

        assert!(capabilities.capabilities.is_empty());
        assert_eq!(mutation.code, ErrorCode::Unimplemented);
        assert_eq!(mutation.message.as_deref(), Some(UNAVAILABLE_REASON));
    }

    #[test]
    fn root_diagnostic_response_discloses_no_catalog_or_resource_detail() {
        let mut state = CapabilityState::starting([7; 16]);
        state.record_success(9, ObjectDigest::from_bytes([8; 32]));
        let response = state.response().unwrap();
        let capabilities = response.capabilities.as_option().unwrap();

        assert_eq!(capabilities.node_id, [7; 16]);
        assert_eq!(capabilities.resource_version.len(), 32);
        assert_eq!(capabilities.capability_generation, 2);
        assert!(capabilities.capabilities.is_empty());
        assert!(capabilities.observed_at.as_option().is_some());
    }

    #[test]
    fn retryable_inventory_loss_closes_observation_status() {
        let mut state = CapabilityState::starting([7; 16]);
        state.record_success(1, ObjectDigest::from_bytes([8; 32]));
        state.record_retryable_failure("Storage inventory is unavailable".to_owned());
        let response = state.response().unwrap();
        let capabilities = response.capabilities.as_option().unwrap();

        assert!(capabilities.capabilities.is_empty());
        assert_eq!(capabilities.capability_generation, 3);
    }

    #[test]
    fn recovered_pending_catalog_is_published_before_a_fresh_readiness_cycle() {
        #[derive(Default)]
        struct Calls {
            order: Vec<&'static str>,
        }

        let mut calls = Calls::default();
        let status = pending_first_read_only_cycle(
            &mut calls,
            |calls| {
                calls.order.push("recovery");
                Ok::<_, ()>(Some("durable pending catalog"))
            },
            |calls, pending| {
                calls.order.push("pending publication");
                assert_eq!(pending, "durable pending catalog");
                Ok::<_, ()>(())
            },
            |calls| {
                calls.order.push("read-only ledger audit");
                Ok::<_, ()>(())
            },
            |calls| {
                calls.order.push("fresh broker inventories");
                Ok::<_, ()>("fresh confirmed catalog")
            },
        )
        .unwrap();

        assert_eq!(status, "fresh confirmed catalog");
        assert_eq!(
            calls.order,
            [
                "recovery",
                "pending publication",
                "read-only ledger audit",
                "fresh broker inventories",
            ]
        );
    }

    #[test]
    fn successful_pending_publication_does_not_satisfy_readiness() {
        #[derive(Default)]
        struct Calls {
            publication: usize,
            fresh_inventory: usize,
        }

        let mut calls = Calls::default();
        let result: Result<&str, &str> = pending_first_read_only_cycle(
            &mut calls,
            |_| Ok::<_, &'static str>(Some("durable pending catalog")),
            |calls, _| {
                calls.publication += 1;
                Ok(())
            },
            |_| Ok(()),
            |calls| {
                calls.fresh_inventory += 1;
                Err("fresh inventory unavailable")
            },
        );

        assert!(matches!(result, Err("fresh inventory unavailable")));
        assert_eq!(calls.publication, 1);
        assert_eq!(calls.fresh_inventory, 1);
        assert!(result.is_err(), "publication alone must not open readiness");
    }

    #[test]
    fn unfinished_operation_closes_readiness_before_active_or_broker_work() {
        #[derive(Default)]
        struct Calls {
            compiler: usize,
            executor: usize,
            reconciliation: usize,
            broker_inventory: usize,
        }

        let mut calls = Calls::default();
        let result = pending_first_read_only_cycle(
            &mut calls,
            |_| Ok::<_, &'static str>(None::<()>),
            |_, _| Ok(()),
            |_| Err("unfinished operation"),
            |calls| {
                calls.compiler += 1;
                calls.executor += 1;
                calls.reconciliation += 1;
                calls.broker_inventory += 1;
                Ok("ready")
            },
        );

        assert!(matches!(result, Err("unfinished operation")));
        assert_eq!(calls.compiler, 0);
        assert_eq!(calls.executor, 0);
        assert_eq!(calls.reconciliation, 0);
        assert_eq!(calls.broker_inventory, 0);
        assert!(result.is_err(), "unfinished work must not open readiness");
    }

    #[test]
    fn broker_service_cgroup_paths_match_systemd_slice_placement() {
        assert_eq!(
            service_cgroup_path(HOST_SLICE, HOST_SERVICE),
            Path::new("system.slice/aos-sandbox-hostd.service")
        );
        assert_eq!(
            service_cgroup_path(CONTROL_SLICE, STORAGE_CGROUP),
            Path::new("aos.slice/aos-control.slice/aos-storaged.service")
        );
    }

    #[test]
    fn diagnostic_listener_is_registered_inside_the_async_runtime_with_root_policy() {
        let directory = tempfile::tempdir().unwrap();
        let configuration = diagnostic_configuration(&directory);
        let listener = bind_diagnostic_socket(&configuration).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let listener = runtime
            .block_on(into_async_diagnostic_listener(listener))
            .unwrap();

        assert_eq!(listener.expected_uid, 0);
        assert_eq!(
            listener.local_addr().unwrap().as_pathname(),
            Some(configuration.diagnostic_socket.as_path())
        );
    }

    #[test]
    fn diagnostic_listener_accepts_the_exact_authenticated_uid() {
        let directory = tempfile::tempdir().unwrap();
        let configuration = diagnostic_configuration(&directory);
        let listener = bind_diagnostic_socket(&configuration).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut listener = runtime
            .block_on(into_async_authenticated_listener(
                listener,
                configuration.uid,
            ))
            .unwrap();

        runtime.block_on(async {
            let _client = tokio::net::UnixStream::connect(&configuration.diagnostic_socket)
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .unwrap();
        });
    }

    #[test]
    fn diagnostic_listener_rejects_every_other_uid() {
        let directory = tempfile::tempdir().unwrap();
        let configuration = diagnostic_configuration(&directory);
        let listener = bind_diagnostic_socket(&configuration).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let unexpected_uid = if configuration.uid == u32::MAX {
            configuration.uid - 1
        } else {
            configuration.uid + 1
        };
        let mut listener = runtime
            .block_on(into_async_authenticated_listener(listener, unexpected_uid))
            .unwrap();

        runtime.block_on(async {
            let _client = tokio::net::UnixStream::connect(&configuration.diagnostic_socket)
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn protected_controller_recovery_retains_its_node_binding() {
        let directory = tempfile::tempdir().unwrap();
        let journal = protected_test_journal(&directory, production_journal_limits());
        let controller = controller_from_journal(journal, [7; 16]).unwrap();
        drop(controller);
        let before = std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap();

        let journal = protected_test_journal(&directory, production_journal_limits());
        let controller = controller_from_journal(journal, [7; 16]).unwrap();
        drop(controller);

        assert_eq!(
            std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
            before
        );
    }

    #[test]
    fn durable_first_bind_is_idempotent_after_an_ambiguous_process_exit() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_test_journal(&directory, production_journal_limits());
        bind_controller_identity(&mut journal, [7; 16]).unwrap();
        let before = std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap();
        drop(journal);

        let mut journal = protected_test_journal(&directory, production_journal_limits());
        bind_controller_identity(&mut journal, [7; 16]).unwrap();

        assert_eq!(
            journal.records(RecordNamespace::ControllerIdentity).count(),
            1
        );
        assert_eq!(
            std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
            before
        );
    }

    #[test]
    fn unbound_preexisting_state_has_no_automatic_identity_migration() {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = protected_test_journal(&directory, production_journal_limits());
        let transaction = JournalTransaction::new(
            OperationId::from_bytes([9; 16]).into_bytes(),
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                vec![1],
                vec![2],
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        let before = std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap();
        drop(journal);

        let journal = protected_test_journal(&directory, production_journal_limits());
        assert!(matches!(
            controller_from_journal(journal, [7; 16]),
            Err(ControllerRuntimeError::UnboundControllerIdentity)
        ));

        assert_eq!(
            std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
            before
        );
    }

    #[test]
    fn protected_controller_rejects_a_different_node_without_changing_state() {
        let directory = tempfile::tempdir().unwrap();
        let journal = protected_test_journal(&directory, production_journal_limits());
        let controller = controller_from_journal(journal, [7; 16]).unwrap();
        drop(controller);
        let before = std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap();

        let journal = protected_test_journal(&directory, production_journal_limits());
        assert!(matches!(
            controller_from_journal(journal, [8; 16]),
            Err(ControllerRuntimeError::ControllerIdentityMismatch)
        ));

        assert_eq!(
            std::fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
            before
        );
    }

    #[test]
    fn production_journal_limits_fit_the_service_memory_budget() {
        let limits = production_journal_limits();

        assert_eq!(limits.maximum_journal_bytes, 256 * 1024 * 1024);
        assert_eq!(limits.maximum_materialized_bytes, 128 * MEBIBYTE);
        assert!(
            limits.maximum_journal_bytes
                + u64::try_from(limits.maximum_materialized_bytes).unwrap()
                < 512 * 1024 * 1024
        );
        assert_eq!(limits.maximum_transactions, 65_536);
        assert_eq!(limits.maximum_materialized_records, 131_072);
    }

    #[test]
    fn broker_retryability_is_preserved_across_inventory_classification() {
        use aos_proto::aos::sandbox::local::v1::BrokerErrorCode;

        let code = BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE;
        assert!(matches!(
            classify_mount_error(MountAttemptError::BrokerRejected {
                code,
                retryable: false,
            }),
            CycleFailure::Fatal(_)
        ));
        assert!(matches!(
            classify_mount_error(MountAttemptError::BrokerRejected {
                code,
                retryable: true,
            }),
            CycleFailure::Retryable(_)
        ));
        assert!(matches!(
            classify_resource_error(ResourceInventoryError::BrokerRejected {
                code,
                retryable: false,
            }),
            CycleFailure::Fatal(_)
        ));
        assert!(matches!(
            classify_resource_error(ResourceInventoryError::BrokerRejected {
                code,
                retryable: true,
            }),
            CycleFailure::Retryable(_)
        ));
    }

    #[test]
    fn host_publication_retryability_is_preserved_through_reconciliation() {
        use aos_proto::aos::sandbox::local::v1::BrokerErrorCode;

        let rejected = |retryable| {
            HostCatalogReconciliationError::Publication(
                HostCatalogPublicationError::BrokerRejected {
                    code: BrokerErrorCode::BROKER_ERROR_CODE_BACKEND_FAILURE,
                    retryable,
                },
            )
        };

        assert!(matches!(
            classify_catalog_error(rejected(false)),
            CycleFailure::Fatal(_)
        ));
        assert!(matches!(
            classify_catalog_error(rejected(true)),
            CycleFailure::Retryable(_)
        ));
    }

    #[test]
    fn hostile_publication_and_transport_failures_are_terminal() {
        assert!(matches!(
            classify_publication_error(HostCatalogPublicationError::HostIdentity),
            CycleFailure::Fatal(_)
        ));
        assert!(matches!(
            classify_publication_error(HostCatalogPublicationError::ReceiptMismatch),
            CycleFailure::Fatal(_)
        ));
        assert!(matches!(
            classify_publication_error(HostCatalogPublicationError::Protocol(
                aos_sandbox_protocol::ProtocolValidationError::DescriptorTableMismatch,
            )),
            CycleFailure::Fatal(_)
        ));
        assert!(matches!(
            classify_resource_error(ResourceInventoryError::Transport(
                SeqpacketError::EmptyRecord,
            )),
            CycleFailure::Fatal(_)
        ));
        assert!(matches!(
            classify_resource_error(ResourceInventoryError::Kernel(LinuxError::InvalidInput {
                field: "service cgroup",
                message: "invalid deployment contract".to_owned(),
            })),
            CycleFailure::Fatal(_)
        ));
    }

    #[test]
    fn bounded_service_loss_remains_retryable() {
        assert!(matches!(
            classify_resource_error(ResourceInventoryError::Deadline),
            CycleFailure::Retryable(_)
        ));
        assert!(matches!(
            classify_publication_error(HostCatalogPublicationError::Transport(
                SeqpacketError::Closed,
            )),
            CycleFailure::Retryable(_)
        ));
        assert!(matches!(
            classify_mount_error(MountAttemptError::Preparation(
                MountCatalogPreparationError::Deadline,
            )),
            CycleFailure::Retryable(_)
        ));
    }

    #[test]
    fn production_journal_rejects_a_sparse_file_above_its_limit() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join(JOURNAL_NAME);
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(PRODUCTION_MAXIMUM_JOURNAL_BYTES + 1).unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            Journal::open_protected_at_uid(
                directory.path(),
                JOURNAL_NAME,
                production_journal_limits(),
                rustix::process::getuid().as_raw(),
            ),
            Err(JournalError::JournalTooLarge)
        ));
    }
}
