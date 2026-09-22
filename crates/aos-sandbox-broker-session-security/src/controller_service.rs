//! Production runtime for the unprivileged node controller.
//!
//! The service is the sole writer of its protected journal. On every restart it
//! resolves any durable pending Host catalog before acquiring new authenticated
//! Storage, Network, Mount, or destination-slot observations. Only a complete
//! mutually current inventory projection and authenticated Host confirmation
//! opens the systemd readiness gate.
//! Unresolved prior-process session history remains fail-closed; a new request
//! identity is not a substitute for exact transport recovery.
//!
//! The root-only local socket exposes the read-only public feature registry,
//! `GetNodeCapabilities`, and restart-stable `GetOperation` observations. The
//! operation query crosses a bounded command channel to the sole journal owner;
//! the asynchronous server never opens or shares the journal. An opt-in public
//! Unix endpoint offers discovery and capability-authorized operation reads to
//! explicitly registered mutually authenticated TLS clients; socket credentials
//! or request headers do not identify those clients or grant authority. UID 0
//! is trusted here as the local administrator, not as another node service
//! role. Discovery responses contain no catalog rows, credentials, operation
//! state, or mutation surface. The feature
//! registry describes the closed public protocol vocabulary; the node-capability
//! response advertises none of those features until their production
//! implementations are active.
//! Controller-local capability revocation is compiled and committed atomically.
//! Assignment-bound mutations still require the separately protected assignment
//! compiler and Guardian signer; authority-bound effects already present in the
//! durable controller journal execute through their exact authenticated broker
//! sessions without manufacturing replacement identity.

use std::io::IoSlice;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, RuntimeAction};
use aos_proto::aos::sandbox::v1::{
    CacheServiceExt, CancelOperationRequest, CancelOperationResponse, CapabilityServiceExt,
    DiscoveryService, DiscoveryServiceExt, Event, ExecutionServiceExt, FilesystemViewServiceExt,
    GetNodeCapabilitiesRequest, GetNodeCapabilitiesRequestView, GetNodeCapabilitiesResponse,
    GetOperationRequest, GetOperationResponse, GetPublicFeatureRegistryRequest,
    GetPublicFeatureRegistryResponse, NodeCapabilities, Operation, OperationPhase,
    OperationService, OperationServiceExt, OperatorServiceExt, PolicyPlan, SandboxServiceExt,
    SnapshotServiceExt, Timestamp, WatchRequest,
};
use aos_sandbox_core::{
    CapabilityId, NodeId, ObjectDigest, Operation as CapabilityOperation, OperationId,
    RawClockProvenance, RawPairedClockSample, ResourceId,
};
use aos_sandbox_core::{ResourceKind, Selector};
use aos_sandbox_linux::Error as LinuxError;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use connectrpc::{
    ConnectError, Encodable, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use futures::Stream;
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    sendmsg_addr, socket_with,
};
use sha2::{Digest as _, Sha256};

use crate::controller_publication::{ControllerHostPublication, ControllerHostPublicationError};
use aos_sandbox::cli_model::{
    AuditAuthorizationV1, DormantSandboxRequestKindV1, PublicApiAuditMethodV1,
};
use aos_sandbox::controller::DormantControllerCompositionV1;
use aos_sandbox::controller_service::journal::{
    production_journal_limits, validate_controller_journal,
};
use aos_sandbox::controller_service::public_projection::{
    AuthorizedPublicProjectionReadV1, PublicProjectionQueryV1, PublicProjectionRecordV1,
};
use aos_sandbox::host_catalog_publication::{
    HostCatalogPublicationDraftV1, HostCatalogPublicationError,
};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::lifecycle::{
    LifecycleCancelIdempotencyDigestV1, LifecycleCurrentAuxiliaryPublicationV1,
    LifecycleOperationAdmissionV1, LifecycleOperationV1, LifecycleProgressCommitOutcomeV1,
    LifecycleProgressOutcomeUnknownV1, LifecycleProgressRecoveryV1,
    LifecycleProtectedCancellationAdmissionV1, LifecycleProtectedCancellationResolutionV1,
    LifecycleProtectedRecordKindV1, LifecycleSnapshotBarrierV1, LifecycleSuspensionPlanV1,
    LifecycleTimeV1, lifecycle_operation_from_public_mutation_v1, lifecycle_protected_key_v1,
    lifecycle_public_mutation_admission_v1,
};
use aos_sandbox::mount_preparation::MountCatalogPreparationError;
use aos_sandbox::production_operation_compiler::ProductionOperationCompilerV1;
use aos_sandbox::public_policy_planner::PublicPolicyPlanningErrorV1;
use aos_sandbox::{
    AcceptOutcome, ActivatedOperationCompiler, AuthorityEffectAttemptTimingV1,
    AuthorityEffectObservationV1, ControllerRequestScopeV1, ControllerServiceError, EffectFailure,
    EffectObservation, EffectPlan, EffectReceipt, HostCatalogReconciliationError,
    HostCatalogReconciliationV1, Journal, JournalError, MountAttemptError, NodeController,
    NodeControllerLimits, OperationCompilationError, PreparedAuthorityEffectV1,
    PublicMutationEffectV1, Reconciler, ResourceInventoryError, SingleNodeEffectExecutor,
    ValidatedAuthorityEffectReceiptV1, prepare_runtime_lifecycle_authority_effect_v1,
    public_operation_resource_from_journal_v1,
};

mod public_api;
mod public_hierarchy;
mod public_services;
mod public_watch;

const STATE_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const JOURNAL_NAME: &str = "controller.journal";
const DIAGNOSTIC_SOCKET: &str = "/run/aos/sandboxd/diagnostics.sock";
const NODE_ID_CREDENTIAL: &str = "node-id";
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const CONTROLLER_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROLLER_COMMAND_CAPACITY: usize = 64;
const PUBLIC_CAPABILITY_HEADER: &str = "aos-capability-id";
const REQUEST_SCOPE: [u8; 32] = [0x43; 32];
const UNAVAILABLE_REASON: &str = "production mutation authority is not installed";
const CONTROLLER_ORCHESTRATION_PENDING: &str =
    "controller mutation is awaiting production orchestration lowering";

type ProductionController = NodeController<ProductionOperationCompilerV1, ProductionEffectExecutor>;
type SharedControllerBrokerSessions = Arc<Mutex<ControllerBrokerSessions>>;

/// Retains authenticated transports and their durable sequence owners across cycles.
#[derive(Default)]
struct ControllerBrokerSessions {
    host: Option<ControllerHostPublication>,
    mount: Option<crate::DormantMountLifecycleInventoryOwnerV1>,
    storage: Option<crate::DormantStorageLifecycleInventoryOwnerV1>,
    network: Option<crate::DormantNetworkLifecycleInventoryOwnerV1>,
}

enum ControllerCommand {
    GetOperation {
        operation_id: OperationId,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Option<Operation>>>,
    },
    GetAuthorizedOperation {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        operation_id: OperationId,
        protobuf_body: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Option<Operation>>>,
    },
    AuthorizePublicRead {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: ResourceKind,
        operation: CapabilityOperation,
        selector: Selector,
        protobuf_body: Vec<u8>,
        expires_at: Instant,
        reply:
            tokio::sync::oneshot::Sender<ControllerCommandResponse<Option<AuditAuthorizationV1>>>,
    },
    ReadPublicProjection {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        method: PublicApiAuditMethodV1,
        resource_kind: ResourceKind,
        operation: CapabilityOperation,
        selector: Selector,
        protobuf_body: Vec<u8>,
        query: PublicProjectionQueryV1,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<
            ControllerCommandResponse<Option<AuthorizedPublicProjectionReadV1>>,
        >,
    },
    PlanPublicPolicy {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        method: PublicApiAuditMethodV1,
        protobuf_body: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<PolicyPlan>>,
    },
    AdmitPublicOperatorRecovery {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Operation>>,
    },
    AdmitPublicMutation {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        canonical_request: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<AdmittedPublicMutationV1>>,
    },
}

struct AdmittedPublicMutationV1 {
    operation: Operation,
    projections: Vec<PublicProjectionRecordV1>,
}

type ControllerCommandResponse<T> = Result<T, ControllerCommandFailure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControllerCommandFailure {
    DeadlineExceeded,
    ControllerUnavailable,
    InvalidRequest,
    Rejected,
}

/// Composes explicitly supplied controller and public-client dependencies without activation.
///
/// This factory does not register a service, bind a socket, start a worker, or
/// alter [`run_from_environment`]. Production therefore retains its fail-closed
/// unavailable compiler and executor until a separately qualified activation
/// change selects concrete dependencies.
#[must_use]
pub fn dormant_controller_composition<C, E, T>(
    scope: ControllerRequestScopeV1,
    limits: NodeControllerLimits,
    journal: Journal,
    compiler: C,
    executor: E,
    public_api_transport: T,
) -> DormantControllerCompositionV1<C, E, T>
where
    C: ActivatedOperationCompiler,
    E: SingleNodeEffectExecutor,
{
    DormantControllerCompositionV1::new(
        scope,
        limits,
        journal,
        compiler,
        executor,
        public_api_transport,
    )
}

/// Runs the controller from systemd's protected runtime environment.
///
/// Positional arguments are the fixed decimal controller UID and GID. The
/// optional `--public-api` flag requires all four protected public TLS credentials
/// and enables registered-client discovery and authorized operation reads at the
/// fixed public socket. The node identity is read from
/// `CREDENTIALS_DIRECTORY/node-id`; broker endpoints,
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
    let sessions = Arc::new(Mutex::new(ControllerBrokerSessions::default()));
    let controller = open_controller(&configuration, node_id, Arc::clone(&sessions))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ControllerRuntimeError::Runtime)?;
    let listener = runtime.block_on(into_async_diagnostic_listener(listener))?;
    let public_listener = if configuration.public_api {
        Some(runtime.block_on(public_api::bind(configuration.uid))?)
    } else {
        None
    };
    let capabilities = Arc::new(Mutex::new(CapabilityState::starting(node_id)));
    let (events_tx, events_rx) = mpsc::channel();
    let (commands_tx, commands_rx) = mpsc::sync_channel(CONTROLLER_COMMAND_CAPACITY);
    let worker_capabilities = Arc::clone(&capabilities);

    std::thread::Builder::new()
        .name("aos-sandboxd-reconciler".to_owned())
        .spawn(move || {
            controller_worker(
                controller,
                node_id,
                worker_capabilities,
                sessions,
                commands_rx,
                events_tx,
            )
        })
        .map_err(ControllerRuntimeError::WorkerSpawn)?;

    wait_for_initial_readiness(&events_rx)?;
    SystemdReadyNotifier::from_environment()?.notify_ready()?;

    let public_service = Arc::new(CapabilityService {
        capabilities: Arc::clone(&capabilities),
        commands: commands_tx.clone(),
        endpoint: ControllerEndpoint::RegisteredPublic,
    });
    let diagnostic_service = Arc::new(CapabilityService {
        capabilities,
        commands: commands_tx,
        endpoint: ControllerEndpoint::RootDiagnostic,
    });
    let public_connect =
        DiscoveryServiceExt::register(Arc::clone(&public_service), connectrpc::Router::new());
    let public_connect = SandboxServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect = ExecutionServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect =
        FilesystemViewServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect = SnapshotServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect =
        CapabilityServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect = CacheServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect = OperatorServiceExt::register(Arc::clone(&public_service), public_connect);
    let public_connect =
        OperationServiceExt::register(public_service, public_connect).into_axum_service();
    let public_application = axum::Router::new().fallback_service(public_connect);
    let connect =
        DiscoveryServiceExt::register(Arc::clone(&diagnostic_service), connectrpc::Router::new());
    let connect = OperationServiceExt::register(diagnostic_service, connect).into_axum_service();
    let application = axum::Router::new().fallback_service(connect);
    let result = runtime.block_on(serve_until_worker_failure(
        listener,
        application,
        public_listener,
        public_application,
        events_rx,
    ));
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

async fn serve_until_worker_failure(
    listener: AuthenticatedDiagnosticListener,
    application: axum::Router,
    public_listener: Option<public_api::PublicListener>,
    public_application: axum::Router,
    events: mpsc::Receiver<WorkerEvent>,
) -> Result<(), ControllerRuntimeError> {
    let worker = tokio::task::spawn_blocking(move || events.recv());
    tokio::select! {
        result = public_api::serve(public_listener, public_application) => result,
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
    node_id: [u8; 16],
    capabilities: Arc<Mutex<CapabilityState>>,
    sessions: SharedControllerBrokerSessions,
    commands: mpsc::Receiver<ControllerCommand>,
    events: mpsc::Sender<WorkerEvent>,
) {
    let mut ready = false;
    let mut next_cycle = Instant::now();
    loop {
        if Instant::now() >= next_cycle {
            match run_controller_cycle(&mut controller, node_id, &sessions) {
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
            next_cycle = Instant::now() + RECONCILIATION_INTERVAL;
        }

        let wait = next_cycle.saturating_duration_since(Instant::now());
        match commands.recv_timeout(wait) {
            Ok(command) => {
                if let Err(message) = handle_controller_command(&mut controller, command) {
                    let _ = events.send(WorkerEvent::Fatal(message));
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = events.send(WorkerEvent::Fatal(
                    "controller command channel disconnected".to_owned(),
                ));
                return;
            }
        }
    }
}

fn handle_controller_command(
    controller: &mut ProductionController,
    command: ControllerCommand,
) -> Result<(), String> {
    match command {
        ControllerCommand::GetOperation {
            operation_id,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            match controller.public_operation(operation_id) {
                Ok(operation) => {
                    let _ = reply.send(Ok(operation));
                    Ok(())
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
            }
        }
        ControllerCommand::GetAuthorizedOperation {
            peer,
            capability_id,
            operation_id,
            protobuf_body,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            match controller.authorized_public_operation(
                &peer,
                capability_id,
                operation_id,
                &protobuf_body,
            ) {
                Ok(operation) => {
                    let _ = reply.send(Ok(operation));
                    Ok(())
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
            }
        }
        ControllerCommand::AuthorizePublicRead {
            peer,
            capability_id,
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            match controller.authorize_public_read(
                &peer,
                capability_id,
                method,
                resource_kind,
                operation,
                selector,
                &protobuf_body,
            ) {
                Ok(authorization) => {
                    let _ = reply.send(Ok(authorization));
                    Ok(())
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
            }
        }
        ControllerCommand::ReadPublicProjection {
            peer,
            capability_id,
            method,
            resource_kind,
            operation,
            selector,
            protobuf_body,
            query,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            match controller.authorized_public_projection_read(
                &peer,
                capability_id,
                method,
                resource_kind,
                operation,
                selector,
                &protobuf_body,
                query,
            ) {
                Ok(read) => {
                    let _ = reply.send(Ok(read));
                    Ok(())
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
            }
        }
        ControllerCommand::PlanPublicPolicy {
            peer,
            capability_id,
            method,
            protobuf_body,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            match controller.plan_public_policy(&peer, capability_id, method, &protobuf_body) {
                Ok(plan) => {
                    let _ = reply.send(Ok(plan));
                    Ok(())
                }
                Err(PublicPolicyPlanningErrorV1::Malformed) => {
                    let _ = reply.send(Err(ControllerCommandFailure::InvalidRequest));
                    Ok(())
                }
                Err(PublicPolicyPlanningErrorV1::Rejected) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                    Ok(())
                }
                Err(PublicPolicyPlanningErrorV1::Unavailable) => {
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Ok(())
                }
                Err(PublicPolicyPlanningErrorV1::InvalidPlan) => {
                    let message = "public policy planner returned an invalid plan".to_owned();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
            }
        }
        ControllerCommand::AdmitPublicOperatorRecovery {
            peer,
            capability_id,
            canonical_request,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            let operation_id = match controller.admit_public_operator_recovery(
                &peer,
                capability_id,
                &canonical_request,
            ) {
                Ok(AcceptOutcome::Accepted(operation) | AcceptOutcome::Replay(operation)) => {
                    operation
                }
                Err(
                    ControllerServiceError::EmptyRequest
                    | ControllerServiceError::RequestTooLarge
                    | ControllerServiceError::Compilation(OperationCompilationError::Malformed),
                ) => {
                    let _ = reply.send(Err(ControllerCommandFailure::InvalidRequest));
                    return Ok(());
                }
                Err(ControllerServiceError::Compilation(OperationCompilationError::Rejected)) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                    return Ok(());
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            };
            match controller.public_operation(operation_id) {
                Ok(Some(operation)) => {
                    let _ = reply.send(Ok(operation));
                    Ok(())
                }
                Ok(None) => {
                    let message = "accepted operator recovery has no public operation".to_owned();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    Err(message)
                }
            }
        }
        ControllerCommand::AdmitPublicMutation {
            peer,
            capability_id,
            canonical_request,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            let operation_id =
                match controller.admit_public(&peer, capability_id, &canonical_request) {
                    Ok(AcceptOutcome::Accepted(operation) | AcceptOutcome::Replay(operation)) => {
                        operation
                    }
                    Err(
                        ControllerServiceError::EmptyRequest
                        | ControllerServiceError::RequestTooLarge
                        | ControllerServiceError::Compilation(OperationCompilationError::Malformed),
                    ) => {
                        let _ = reply.send(Err(ControllerCommandFailure::InvalidRequest));
                        return Ok(());
                    }
                    Err(ControllerServiceError::Compilation(
                        OperationCompilationError::Rejected,
                    )) => {
                        let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                        return Ok(());
                    }
                    Err(error) => {
                        let message = error.to_string();
                        let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                        return Err(message);
                    }
                };
            let operation = match controller.public_operation(operation_id) {
                Ok(Some(operation)) => operation,
                Ok(None) => {
                    let message = "accepted public mutation has no public operation".to_owned();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            };
            let projections = match controller.public_operation_projections(operation_id) {
                Ok(projections) => projections,
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            };
            let _ = reply.send(Ok(AdmittedPublicMutationV1 {
                operation,
                projections,
            }));
            Ok(())
        }
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
    node_id: [u8; 16],
    sessions: &SharedControllerBrokerSessions,
) -> Result<CatalogStatus, CycleFailure> {
    {
        let mut sessions = sessions
            .lock()
            .map_err(|_| CycleFailure::Fatal("broker session lock is poisoned".to_owned()))?;
        ensure_controller_broker_sessions(node_id, &mut sessions)?;
    }
    let mut state = (controller, sessions);
    pending_first_reconciliation_cycle(
        &mut state,
        |(controller, _)| {
            controller
                .pending_host_catalog()
                .map_err(|error| CycleFailure::Fatal(error.to_string()))
        },
        |(controller, sessions), pending| {
            let mut sessions = sessions
                .lock()
                .map_err(|_| CycleFailure::Fatal("broker session lock is poisoned".to_owned()))?;
            publish_pending(controller, pending, node_id, &mut sessions).map(|_| ())
        },
        |(controller, _)| {
            controller
                .reconcile_quantum()
                .map(|_| ())
                .map_err(|error| CycleFailure::Fatal(error.to_string()))
        },
        |(controller, sessions)| {
            let mut sessions = sessions
                .lock()
                .map_err(|_| CycleFailure::Fatal("broker session lock is poisoned".to_owned()))?;
            refresh_catalog(controller, node_id, &mut sessions)
        },
    )
}

fn pending_first_reconciliation_cycle<State, Pending, Status, Error>(
    state: &mut State,
    recover: impl FnOnce(&mut State) -> Result<Option<Pending>, Error>,
    publish: impl FnOnce(&mut State, Pending) -> Result<(), Error>,
    reconcile: impl FnOnce(&mut State) -> Result<(), Error>,
    continue_cycle: impl FnOnce(&mut State) -> Result<Status, Error>,
) -> Result<Status, Error> {
    if let Some(pending) = recover(state)? {
        publish(state, pending)?;
    }

    reconcile(state)?;
    continue_cycle(state)
}

fn ensure_controller_broker_sessions(
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<(), CycleFailure> {
    if sessions
        .host
        .as_ref()
        .is_some_and(ControllerHostPublication::requires_reconnect)
    {
        sessions.host = None;
    }
    if sessions.host.is_none() {
        sessions.host = Some(ControllerHostPublication::new(connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
            node_id,
        )?));
    }
    if sessions.mount.is_none() {
        sessions.mount = Some(
            crate::DormantMountLifecycleInventoryOwnerV1::from_protected_session(
                connect_controller_session(
                    crate::ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
                    node_id,
                )?,
            ),
        );
    }
    if sessions.storage.is_none() {
        sessions.storage = Some(
            crate::DormantStorageLifecycleInventoryOwnerV1::from_protected_session(
                connect_controller_session(
                    crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
                    node_id,
                )?,
            ),
        );
    }
    if sessions.network.is_none() {
        sessions.network = Some(
            crate::DormantNetworkLifecycleInventoryOwnerV1::from_protected_session(
                connect_controller_session(
                    crate::ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
                    node_id,
                )?,
            ),
        );
    }
    Ok(())
}

fn connect_controller_session(
    endpoint: crate::ProtectedBrokerSessionFixedEndpointV1,
    node_id: [u8; 16],
) -> Result<crate::DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(endpoint)
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let deadline = crate::production_deadline_after(Duration::from_secs(10))
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let mut session = custody
        .connect_production_client_session(deadline)
        .map_err(classify_protected_handshake_error)?;
    session
        .require_current_node(node_id)
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    Ok(session)
}

fn refresh_catalog(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<CatalogStatus, CycleFailure> {
    // Mount and destination state participate in the controller-state digest
    // captured by Storage and Network, so acquire them first.
    let (mounts, destinations) = authenticated_mount_inventories(controller, node_id, sessions)?;
    let storage = authenticated_storage_inventory(controller, node_id, sessions)?;
    let network = authenticated_network_inventory(controller, node_id, sessions)?;

    match controller
        .prepare_host_catalog(storage, network, mounts, destinations)
        .map_err(classify_catalog_error)?
    {
        HostCatalogReconciliationV1::Current(current) => Ok(CatalogStatus {
            generation: current.generation(),
            digest: current.catalog_digest(),
        }),
        HostCatalogReconciliationV1::Publish(pending) => {
            publish_pending(controller, pending, node_id, sessions)
        }
    }
}

fn publish_pending(
    controller: &mut ProductionController,
    pending: aos_sandbox::DurablePendingHostCatalogV1,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<CatalogStatus, CycleFailure> {
    if sessions.host.is_none() {
        let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
        )
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        let deadline = crate::production_deadline_after(Duration::from_secs(10))
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        let mut session = custody
            .connect_production_client_session(deadline)
            .map_err(classify_protected_handshake_error)?;
        session
            .require_current_node(node_id)
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        sessions.host = Some(ControllerHostPublication::new(session));
    }
    let publisher = sessions
        .host
        .as_mut()
        .ok_or_else(|| CycleFailure::Fatal("protected Host session was not retained".to_owned()))?;
    let draft = HostCatalogPublicationDraftV1::new(
        pending.canonical_catalog().to_vec(),
        pending.generation(),
    )
    .map_err(classify_publication_error)?;
    let outcome = publisher
        .publish(&draft)
        .map_err(classify_protected_publication_error)?;
    let current = controller
        .complete_authenticated_host_catalog_publication(pending, &outcome)
        .map_err(classify_catalog_error)?;
    Ok(CatalogStatus {
        generation: current.generation(),
        digest: current.catalog_digest(),
    })
}

fn authenticated_mount_inventories(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<
    (
        aos_sandbox::DurableMountInventorySnapshotV1,
        aos_sandbox::DurableDestinationSlotInventorySnapshotV1,
    ),
    CycleFailure,
> {
    if sessions.mount.is_none() {
        let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
        )
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        let deadline = crate::production_deadline_after(Duration::from_secs(10))
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        let mut session = custody
            .connect_production_client_session(deadline)
            .map_err(classify_protected_handshake_error)?;
        session
            .require_current_node(node_id)
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        sessions.mount =
            Some(crate::DormantMountLifecycleInventoryOwnerV1::from_protected_session(session));
    }
    let inventory = sessions.mount.as_mut().ok_or_else(|| {
        CycleFailure::Fatal("protected Mount session was not retained".to_owned())
    })?;
    let mount_fence = controller
        .begin_authenticated_mount_inventory()
        .map_err(classify_mount_error)?;
    let mounts = inventory
        .current_inventory_observation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let mounts = controller
        .complete_authenticated_mount_inventory(mount_fence, &mounts)
        .map_err(classify_mount_error)?;

    // The Mount snapshot commit precedes the destination observation's fence.
    let destination_fence = controller
        .begin_authenticated_destination_slot_inventory()
        .map_err(classify_mount_error)?;
    let destinations = inventory
        .current_destination_slot_observation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let destinations = controller
        .complete_authenticated_destination_slot_inventory(destination_fence, &destinations)
        .map_err(classify_mount_error)?;
    Ok((mounts, destinations))
}

fn authenticated_storage_inventory(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<aos_sandbox::DurableStorageResourceInventorySnapshotV1, CycleFailure> {
    if sessions.storage.is_none() {
        let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
        )
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        let deadline = crate::production_deadline_after(Duration::from_secs(10))
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        let mut session = custody
            .connect_production_client_session(deadline)
            .map_err(classify_protected_handshake_error)?;
        session
            .require_current_node(node_id)
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        sessions.storage =
            Some(crate::DormantStorageLifecycleInventoryOwnerV1::from_protected_session(session));
    }
    let inventory = sessions.storage.as_mut().ok_or_else(|| {
        CycleFailure::Fatal("protected Storage session was not retained".to_owned())
    })?;
    let fence = controller
        .begin_authenticated_storage_inventory()
        .map_err(classify_resource_error)?;
    let outcome = inventory
        .current_inventory_observation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;

    controller
        .complete_authenticated_storage_inventory(fence, &outcome)
        .map_err(classify_resource_error)
}

fn authenticated_network_inventory(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<aos_sandbox::DurableNetworkResourceInventorySnapshotV1, CycleFailure> {
    if sessions.network.is_none() {
        let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
        )
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        let deadline = crate::production_deadline_after(Duration::from_secs(10))
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        let mut session = custody
            .connect_production_client_session(deadline)
            .map_err(classify_protected_handshake_error)?;
        session
            .require_current_node(node_id)
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        sessions.network =
            Some(crate::DormantNetworkLifecycleInventoryOwnerV1::from_protected_session(session));
    }
    let inventory = sessions.network.as_mut().ok_or_else(|| {
        CycleFailure::Fatal("protected Network session was not retained".to_owned())
    })?;
    let fence = controller
        .begin_authenticated_network_inventory()
        .map_err(classify_resource_error)?;
    let outcome = inventory
        .current_inventory_observation()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;

    controller
        .complete_authenticated_network_inventory(fence, &outcome)
        .map_err(classify_resource_error)
}

fn classify_protected_publication_error(error: ControllerHostPublicationError) -> CycleFailure {
    // Only explicit retained recovery permits another cycle. A deadline or
    // protocol failure must not become permission to mint a new request.
    classified_failure(
        matches!(error, ControllerHostPublicationError::RecoveryPending),
        error,
    )
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

fn classify_protected_handshake_error(
    error: crate::DormantBrokerSessionHandshakeErrorV1,
) -> CycleFailure {
    use crate::DormantBrokerSessionHandshakeErrorV1 as HandshakeError;

    let retryable = match &error {
        HandshakeError::Transport | HandshakeError::Deadline => true,
        HandshakeError::EndpointRole
        | HandshakeError::Protected(_)
        | HandshakeError::RemoteInvalid
        | HandshakeError::KernelEvidence => false,
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

fn open_controller(
    configuration: &RuntimeConfiguration,
    node_id: [u8; 16],
    sessions: SharedControllerBrokerSessions,
) -> Result<ProductionController, ControllerRuntimeError> {
    let (journal, _) = Journal::open_protected_at_for_uid(
        &configuration.state_directory,
        JOURNAL_NAME,
        production_journal_limits(),
        configuration.uid,
    )?;

    controller_from_journal(journal, node_id, sessions, configuration.uid)
}

fn controller_from_journal(
    mut journal: Journal,
    node_id: [u8; 16],
    sessions: SharedControllerBrokerSessions,
    controller_uid: u32,
) -> Result<ProductionController, ControllerRuntimeError> {
    validate_controller_journal(&mut journal, node_id)?;
    let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes(REQUEST_SCOPE))?;
    let limits = NodeControllerLimits::new(1024 * 1024, 65_536, 1)?;
    Ok(NodeController::new(
        scope,
        limits,
        ProductionOperationCompilerV1,
        Reconciler::new(
            journal,
            ProductionEffectExecutor::open(sessions, controller_uid, NodeId::from_bytes(node_id))?,
        ),
    ))
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
    bind_controller_socket(&configuration.diagnostic_socket, configuration.uid, 0o660)
}

fn bind_controller_socket(
    path: &Path,
    uid: u32,
    mode: u32,
) -> Result<std::os::unix::net::UnixListener, ControllerRuntimeError> {
    let parent = path
        .parent()
        .ok_or(ControllerRuntimeError::UnsafeDiagnosticSocket)?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != uid
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ControllerRuntimeError::UnsafeDiagnosticSocket);
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == uid => {
            std::fs::remove_file(path)
                .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
        }
        Ok(_) => return Err(ControllerRuntimeError::UnsafeDiagnosticSocket),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ControllerRuntimeError::DiagnosticSocketFilesystem(error)),
    }
    let listener = std::os::unix::net::UnixListener::bind(path)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    listener
        .set_nonblocking(true)
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(ControllerRuntimeError::DiagnosticSocketFilesystem)?;
    Ok(listener)
}

#[derive(Clone, Debug)]
struct RuntimeConfiguration {
    uid: u32,
    gid: u32,
    state_directory: PathBuf,
    diagnostic_socket: PathBuf,
    public_api: bool,
}

impl RuntimeConfiguration {
    fn from_process() -> Result<Self, ControllerRuntimeError> {
        let mut arguments = std::env::args();
        let _program = arguments.next();
        let uid = parse_identity(arguments.next(), "controller UID")?;
        let gid = parse_identity(arguments.next(), "controller GID")?;
        let public_api = match arguments.next().as_deref() {
            None => false,
            Some("--public-api") => true,
            Some(_) => {
                return Err(ControllerRuntimeError::InvalidArguments(
                    "invalid public API activation",
                ));
            }
        };
        if arguments.next().is_some() {
            return Err(ControllerRuntimeError::InvalidArguments(
                "usage: aos-sandboxd CONTROLLER_UID CONTROLLER_GID [--public-api]",
            ));
        }
        Ok(Self {
            uid,
            gid,
            state_directory: PathBuf::from(STATE_DIRECTORY),
            diagnostic_socket: PathBuf::from(DIAGNOSTIC_SOCKET),
            public_api,
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

struct ProductionEffectExecutor {
    sessions: SharedControllerBrokerSessions,
    source_domains: ProtectedSourceDomainJournalOwnerV1,
    cache_inventory: Option<aos_sandbox::cache_residency::CacheResidencyProtectedOwnerV1>,
    transfer_inventory: Option<aos_sandbox::multi_node::ProtectedMultiNodeAuthorityOwnerV1>,
    node: NodeId,
    process_start: Option<([u8; 16], u64)>,
    pending_source_commit: Option<PendingSourceCommit>,
}

struct PendingSourceCommit {
    operation_id: OperationId,
    receipt: Option<EffectReceipt>,
    pending: LifecycleProgressOutcomeUnknownV1,
}

enum AuxiliaryPublicationDisposition {
    Current,
    OutcomeUnknown(LifecycleProgressOutcomeUnknownV1),
    Diverged(LifecycleProgressOutcomeUnknownV1),
}

struct ProductionCancellationRequest {
    target_operation: OperationId,
    idempotency: LifecycleCancelIdempotencyDigestV1,
    requested_at: LifecycleTimeV1,
}

impl ProductionEffectExecutor {
    fn open(
        sessions: SharedControllerBrokerSessions,
        controller_uid: u32,
        node: NodeId,
    ) -> Result<Self, ControllerRuntimeError> {
        let (mut source_domains, _) =
            ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(controller_uid)?;
        aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(&mut source_domains)?
            .replay()?;

        Ok(Self {
            sessions,
            source_domains,
            cache_inventory: None,
            transfer_inventory: None,
            node,
            process_start: current_boot_and_boottime(),
            pending_source_commit: None,
        })
    }

    fn public_mutation_context(
        &mut self,
        plan: &EffectPlan,
    ) -> Result<PublicMutationEffectV1, EffectFailure> {
        aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(&mut self.source_domains)
            .and_then(|owner| owner.replay())
            .map_err(|error| {
                EffectFailure::Permanent(format!("protected source-domain replay failed: {error}"))
            })?;
        plan.public_mutation_context()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .ok_or_else(|| {
                EffectFailure::Permanent(
                    "controller effect lacks authenticated admission context".to_owned(),
                )
            })
    }

    fn cancellation_request(
        context: &PublicMutationEffectV1,
    ) -> Result<ProductionCancellationRequest, EffectFailure> {
        let DormantSandboxRequestKindV1::CancelOperation(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Err(EffectFailure::Permanent(
                "controller cancellation effect has the wrong public method".to_owned(),
            ));
        };
        let target: [u8; 16] = request.operation_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent(
                "controller cancellation target identity is invalid".to_owned(),
            )
        })?;
        let mutation = request.mutation.as_option().ok_or_else(|| {
            EffectFailure::Permanent("controller cancellation has no mutation context".to_owned())
        })?;
        let accepted_seconds = u64::try_from(context.accepted_wall_seconds()).map_err(|_| {
            EffectFailure::Permanent("controller cancellation time is invalid".to_owned())
        })?;
        let accepted_nanoseconds =
            accepted_seconds.checked_mul(1_000_000_000).ok_or_else(|| {
                EffectFailure::Permanent("controller cancellation time overflows".to_owned())
            })?;

        Ok(ProductionCancellationRequest {
            target_operation: OperationId::from_bytes(target),
            idempotency: LifecycleCancelIdempotencyDigestV1::commit(&mutation.idempotency_key),
            requested_at: LifecycleTimeV1::new(accepted_nanoseconds).map_err(|_| {
                EffectFailure::Permanent("controller cancellation time is invalid".to_owned())
            })?,
        })
    }

    fn cancellation_receipt(
        resolution: &LifecycleProtectedCancellationResolutionV1,
    ) -> Result<EffectReceipt, EffectFailure> {
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(b"AOSCAN01");
        bytes.extend_from_slice(resolution.receipt().as_bytes());
        EffectReceipt::new(bytes).map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    fn terminal_public_operation_receipt(
        journal: &Journal,
        target: OperationId,
    ) -> Result<Option<EffectReceipt>, EffectFailure> {
        let operation = public_operation_resource_from_journal_v1(journal, target)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .ok_or_else(|| {
                EffectFailure::Permanent("controller cancellation target is unknown".to_owned())
            })?;
        if !matches!(
            operation.phase.as_known(),
            Some(
                OperationPhase::OPERATION_PHASE_SUCCEEDED
                    | OperationPhase::OPERATION_PHASE_FAILED_BEFORE_COMMIT
                    | OperationPhase::OPERATION_PHASE_CANCELED_BEFORE_COMMIT
                    | OperationPhase::OPERATION_PHASE_COMMITTED_WITH_RESIDUAL_CLEANUP
                    | OperationPhase::OPERATION_PHASE_PERMANENTLY_BLOCKED
            )
        ) {
            return Ok(None);
        }
        let receipt: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.controller.cancel-terminal-operation.v1\0")
            .chain_update(target.as_bytes())
            .chain_update((operation.resource_version.len() as u64).to_be_bytes())
            .chain_update(&operation.resource_version)
            .finalize()
            .into();
        EffectReceipt::new([b"AOSCAT01".as_slice(), receipt.as_slice()].concat())
            .map(Some)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    fn recover_pending_source_commit(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<EffectObservation>, EffectFailure> {
        let Some(pending) = self.pending_source_commit.take() else {
            return Ok(None);
        };
        if pending.operation_id != operation_id {
            self.pending_source_commit = Some(pending);
            return Err(EffectFailure::Retryable(
                "another protected source commit still requires recovery".to_owned(),
            ));
        }

        let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
            &mut self.source_domains,
        )
        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        match owner
            .recover_effect_progress(pending.pending)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        {
            LifecycleProgressRecoveryV1::Applied(_) => {
                Ok(pending.receipt.map(EffectObservation::Applied))
            }
            LifecycleProgressRecoveryV1::Retry(prepared) => {
                match owner
                    .commit_effect_progress(prepared)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                {
                    LifecycleProgressCommitOutcomeV1::Applied(_) => {
                        Ok(pending.receipt.map(EffectObservation::Applied))
                    }
                    LifecycleProgressCommitOutcomeV1::OutcomeUnknown {
                        pending: retained, ..
                    } => {
                        self.pending_source_commit = Some(PendingSourceCommit {
                            pending: retained,
                            ..pending
                        });
                        Err(EffectFailure::Retryable(
                            "protected cancellation durability is still unknown".to_owned(),
                        ))
                    }
                }
            }
            LifecycleProgressRecoveryV1::Diverged(retained) => {
                self.pending_source_commit = Some(PendingSourceCommit {
                    pending: retained,
                    ..pending
                });
                Err(EffectFailure::Permanent(
                    "protected cancellation commit diverged".to_owned(),
                ))
            }
        }
    }

    fn settle_cancellation_admission(
        &mut self,
        operation_id: OperationId,
        admission: LifecycleProtectedCancellationAdmissionV1,
    ) -> Result<EffectReceipt, EffectFailure> {
        match admission {
            LifecycleProtectedCancellationAdmissionV1::Existing(resolution) => {
                Self::cancellation_receipt(&resolution)
            }
            LifecycleProtectedCancellationAdmissionV1::Admitted { resolution, commit } => {
                let receipt = Self::cancellation_receipt(&resolution)?;
                match commit {
                    LifecycleProgressCommitOutcomeV1::Applied(_) => Ok(receipt),
                    LifecycleProgressCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                        self.pending_source_commit = Some(PendingSourceCommit {
                            operation_id,
                            receipt: Some(receipt),
                            pending,
                        });
                        Err(EffectFailure::Retryable(
                            "protected cancellation durability is unknown".to_owned(),
                        ))
                    }
                }
            }
        }
    }

    fn prepared_in_this_process(&self, prepared: &PreparedAuthorityEffectV1) -> bool {
        self.process_start
            .is_some_and(|(host_boot_id, started_at)| {
                prepared.preparation_host_boot_id() == host_boot_id
                    && prepared.preparation_boottime_nanoseconds() >= started_at
            })
    }

    fn validate_lifecycle_admission(
        &self,
        operation: OperationId,
        context: &PublicMutationEffectV1,
        request: &DormantSandboxRequestKindV1,
        journal: &mut Journal,
    ) -> Result<LifecycleOperationV1, EffectFailure> {
        if !is_lifecycle_mutation(request) {
            return Err(EffectFailure::Permanent(
                "public mutation does not use lifecycle admission".to_owned(),
            ));
        }

        let admission = lifecycle_public_mutation_admission_v1(
            journal,
            operation,
            context.project(),
            self.node,
            request,
        )
        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        lifecycle_operation_from_public_mutation_v1(
            operation,
            context.caller(),
            context.project(),
            context.accepted_wall_seconds(),
            context.canonical_request(),
            request,
            admission,
        )
        .map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    fn settle_lifecycle_admission(
        &mut self,
        operation_id: OperationId,
        admission: LifecycleOperationAdmissionV1,
    ) -> Result<(), EffectFailure> {
        match admission {
            LifecycleOperationAdmissionV1::Replay(_) => Ok(()),
            LifecycleOperationAdmissionV1::Admitted { outcome, .. } => match outcome {
                LifecycleProgressCommitOutcomeV1::Applied(_) => Ok(()),
                LifecycleProgressCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                    self.pending_source_commit = Some(PendingSourceCommit {
                        operation_id,
                        receipt: None,
                        pending,
                    });
                    Err(EffectFailure::Retryable(
                        "protected lifecycle admission durability is unknown".to_owned(),
                    ))
                }
            },
        }
    }

    fn ensure_snapshot_retention_ledger(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        let disposition = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (operation_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "snapshot operation is absent from protected custody".to_owned(),
                    )
                })?;
            let project = current.operation().project();
            let operation_lineage = lifecycle_plan_resource_id(operation_id, b"operation-lineage");
            let retention_lineage = lifecycle_plan_resource_id(operation_id, b"retention-lineage");
            let retention_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                retention_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if owner
                .current_retention_ledger(&retention_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_some()
            {
                AuxiliaryPublicationDisposition::Current
            } else {
                drop(current);
                let publication = owner
                    .publish_initial_retention_ledger(
                        &operation_key,
                        &retention_key,
                        lifecycle_plan_transaction_id(operation_id, b"retention-publication"),
                        lifecycle_plan_resource_id(operation_id, b"retention-atomic-join"),
                        operation_lineage,
                        retention_lineage,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                auxiliary_publication_disposition(publication)
            }
        };

        self.settle_auxiliary_publication(operation_id, disposition, "retention ledger")
    }

    fn ensure_snapshot_coordination(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        let disposition = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (operation_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "snapshot operation is absent from protected custody".to_owned(),
                    )
                })?;
            let project = current.operation().project();
            let operation_lineage = lifecycle_plan_resource_id(operation_id, b"operation-lineage");
            let retention_lineage = lifecycle_plan_resource_id(operation_id, b"retention-lineage");
            let coordination_lineage =
                lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
            let retention_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                retention_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let coordination_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                coordination_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if owner
                .current_coordination(&coordination_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_some()
            {
                AuxiliaryPublicationDisposition::Current
            } else {
                drop(current);
                let publication = owner
                    .publish_coordination_admission(
                        &operation_key,
                        &retention_key,
                        &coordination_key,
                        lifecycle_plan_transaction_id(operation_id, b"coordination-publication"),
                        lifecycle_plan_resource_id(operation_id, b"coordination-atomic-join"),
                        operation_lineage,
                        coordination_lineage,
                        lifecycle_plan_resource_id(operation_id, b"coordination-transaction"),
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                auxiliary_publication_disposition(publication)
            }
        };

        self.settle_auxiliary_publication(operation_id, disposition, "snapshot coordination")
    }

    fn settle_auxiliary_publication(
        &mut self,
        operation_id: OperationId,
        disposition: AuxiliaryPublicationDisposition,
        subject: &str,
    ) -> Result<(), EffectFailure> {
        match disposition {
            AuxiliaryPublicationDisposition::Current => Ok(()),
            AuxiliaryPublicationDisposition::OutcomeUnknown(pending) => {
                self.pending_source_commit = Some(PendingSourceCommit {
                    operation_id,
                    receipt: None,
                    pending,
                });
                Err(EffectFailure::Retryable(format!(
                    "protected {subject} durability is unknown"
                )))
            }
            AuxiliaryPublicationDisposition::Diverged(pending) => {
                self.pending_source_commit = Some(PendingSourceCommit {
                    operation_id,
                    receipt: None,
                    pending,
                });
                Err(EffectFailure::Permanent(format!(
                    "protected {subject} publication diverged"
                )))
            }
        }
    }

    fn bind_lifecycle_plan(&mut self, operation_id: OperationId) -> Result<(), EffectFailure> {
        let coordinated_snapshot = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (_, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "admitted lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            matches!(
                current.operation().intent(),
                aos_sandbox::lifecycle::LifecycleIntentV1::Snapshot { .. }
                    | aos_sandbox::lifecycle::LifecycleIntentV1::Hibernate { .. }
            ) && current.operation().plan_is_unbound()
        };
        if coordinated_snapshot {
            self.ensure_snapshot_retention_ledger(operation_id)?;
            self.ensure_snapshot_coordination(operation_id)?;
        }

        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "admitted lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if !current.operation().plan_is_unbound() {
                return Ok(());
            }

            let steps = match current.operation().intent() {
                aos_sandbox::lifecycle::LifecycleIntentV1::Stop { .. } => {
                    LifecycleSuspensionPlanV1::planned_stop_steps(&current)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                }
                aos_sandbox::lifecycle::LifecycleIntentV1::SuspendMemory { .. } => {
                    LifecycleSuspensionPlanV1::planned_memory_suspend_steps(&current)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                }
                aos_sandbox::lifecycle::LifecycleIntentV1::Snapshot { .. }
                | aos_sandbox::lifecycle::LifecycleIntentV1::Hibernate { .. } => {
                    let project = current.operation().project();
                    let coordination_lineage =
                        lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
                    let coordination_key = lifecycle_protected_key_v1(
                        LifecycleProtectedRecordKindV1::Auxiliary,
                        project,
                        coordination_lineage,
                        operation_id,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let coordination = owner
                        .current_coordination(&coordination_key)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "snapshot coordination is absent after protected publication"
                                    .to_owned(),
                            )
                        })?;
                    if matches!(
                        current.operation().intent(),
                        aos_sandbox::lifecycle::LifecycleIntentV1::Snapshot { .. }
                    ) {
                        LifecycleSnapshotBarrierV1::planned_snapshot_steps(&current, &coordination)
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    } else {
                        LifecycleSuspensionPlanV1::planned_hibernate_steps(&current, &coordination)
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    }
                }
                _ => return Ok(()),
            };
            let transaction_id =
                lifecycle_plan_binding_transaction_id(operation_id, current.record().digest());
            let prepared = owner
                .prepare_plan_binding(&current_key, transaction_id, steps)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };

        self.settle_lifecycle_progress(operation_id, outcome)
    }

    fn ensure_initial_lifecycle_reservation(
        &mut self,
        operation_id: OperationId,
    ) -> Result<(), EffectFailure> {
        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "bound lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if current.operation().phase() != aos_sandbox::lifecycle::LifecyclePhaseV1::Accepted
                || current.operation().plan_is_unbound()
            {
                return Ok(());
            }
            let current_record = current.record();
            drop(current);
            let started_at = current_lifecycle_time()?;
            let transaction_id =
                lifecycle_initial_reservation_transaction_id(operation_id, current_record.digest());
            let prepared = owner
                .prepare_initial_lifecycle_progress(&current_key, transaction_id, started_at)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };

        self.settle_lifecycle_progress(operation_id, outcome)
    }

    fn advance_controller_lifecycle_effect(
        &mut self,
        operation_id: OperationId,
    ) -> Result<bool, EffectFailure> {
        let (current_key, current_record, observation, observed_at) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if !matches!(
                current.operation().phase(),
                aos_sandbox::lifecycle::LifecyclePhaseV1::Preparing
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Completing
            ) {
                return Ok(false);
            }

            let effect = match current.operation().intent().method() {
                aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory => {
                    LifecycleSuspensionPlanV1::suspend(&current, None)
                        .and_then(|plan| plan.next_effect(&current))
                }
                aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot
                | aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate => {
                    let coordination_lineage =
                        lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
                    let coordination_key = lifecycle_protected_key_v1(
                        LifecycleProtectedRecordKindV1::Auxiliary,
                        current.operation().project(),
                        coordination_lineage,
                        operation_id,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let coordination = owner
                        .current_coordination(&coordination_key)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "snapshot coordination is absent during effect dispatch".to_owned(),
                            )
                        })?;
                    let barrier = LifecycleSnapshotBarrierV1::from_current_transaction(
                        &current,
                        &coordination,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    if current.operation().intent().method()
                        == aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot
                    {
                        barrier.next_effect(&current)
                    } else {
                        LifecycleSuspensionPlanV1::suspend(&current, Some(barrier))
                            .and_then(|plan| plan.next_effect(&current))
                    }
                }
                _ => return Ok(false),
            }
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if effect.domain() != aos_sandbox::lifecycle::LifecycleEffectDomainV1::Controller {
                return Ok(false);
            }
            let result = ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(b"aos.sandbox.lifecycle.controller-effect-result.v1\0")
                    .chain_update(effect.canonical_body())
                    .chain_update(current.record().digest().as_bytes())
                    .finalize()
                    .into(),
            );
            let inventory = current.projection_root();
            let observation = effect
                .observe_controller_readback(result, inventory)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            (
                current_key,
                current.record(),
                observation,
                current_lifecycle_time()?,
            )
        };

        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let transaction_id = lifecycle_progress_transaction_id(
                operation_id,
                current_record.digest(),
                b"controller-effect-success",
            );
            let prepared = owner
                .prepare_successful_effect_progress(
                    &current_key,
                    transaction_id,
                    observation,
                    observed_at,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };
        self.settle_lifecycle_progress(operation_id, outcome)?;
        Ok(true)
    }

    fn advance_runtime_lifecycle_effect(
        &mut self,
        operation_id: OperationId,
        journal: &mut Journal,
    ) -> Result<bool, EffectFailure> {
        let (current_key, current_record, observation, observed_at, publish_coordination) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if !matches!(
                current.operation().phase(),
                aos_sandbox::lifecycle::LifecyclePhaseV1::Preparing
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Completing
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Compensating
            ) {
                return Ok(false);
            }

            let method = current.operation().intent().method();
            let (effect, fence) = match method {
                aos_sandbox::lifecycle::LifecycleMethodV1::Stop => {
                    let fence = match current.operation().intent() {
                        aos_sandbox::lifecycle::LifecycleIntentV1::Stop { fence, .. } => *fence,
                        _ => {
                            return Err(EffectFailure::Permanent(
                                "stop method has a different intent".to_owned(),
                            ));
                        }
                    };
                    let effect = LifecycleSuspensionPlanV1::stop(&current)
                        .and_then(|plan| plan.next_effect(&current))
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    (effect, fence)
                }
                aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory => {
                    let fence = match current.operation().intent() {
                        aos_sandbox::lifecycle::LifecycleIntentV1::SuspendMemory {
                            fence, ..
                        } => *fence,
                        _ => {
                            return Err(EffectFailure::Permanent(
                                "memory-suspend method has a different intent".to_owned(),
                            ));
                        }
                    };
                    let effect = LifecycleSuspensionPlanV1::suspend(&current, None)
                        .and_then(|plan| plan.next_effect(&current))
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    (effect, fence)
                }
                aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot
                | aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate => {
                    let coordination_lineage =
                        lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
                    let coordination_key = lifecycle_protected_key_v1(
                        LifecycleProtectedRecordKindV1::Auxiliary,
                        current.operation().project(),
                        coordination_lineage,
                        operation_id,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let coordination = owner
                        .current_coordination(&coordination_key)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "snapshot coordination is absent during runtime dispatch"
                                    .to_owned(),
                            )
                        })?;
                    let fence = coordination.coordination().transaction().live_fence();
                    let barrier = LifecycleSnapshotBarrierV1::from_current_transaction(
                        &current,
                        &coordination,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let effect = if method == aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot {
                        barrier.next_effect(&current)
                    } else {
                        LifecycleSuspensionPlanV1::suspend(&current, Some(barrier))
                            .and_then(|plan| plan.next_effect(&current))
                    }
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    (effect, fence)
                }
                _ => return Ok(false),
            };
            if effect.domain() != aos_sandbox::lifecycle::LifecycleEffectDomainV1::Runtime {
                return Ok(false);
            }
            let runtime_action = match (method, effect.step(), effect.ordinal()) {
                (aos_sandbox::lifecycle::LifecycleMethodV1::Stop, 0, 6) => {
                    RuntimeAction::RUNTIME_ACTION_STOP
                }
                (aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory, 2, 3)
                | (aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot, 2, 3)
                | (aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate, 2 | 5, 3) => {
                    RuntimeAction::RUNTIME_ACTION_FREEZE
                }
                (aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot, 5, 6)
                | (aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate, 5, 6) => {
                    RuntimeAction::RUNTIME_ACTION_THAW
                }
                (aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate, 8, 6) => {
                    RuntimeAction::RUNTIME_ACTION_STOP
                }
                _ => {
                    return Err(EffectFailure::Permanent(
                        "runtime lifecycle cursor has no broker action".to_owned(),
                    ));
                }
            };
            let publish_coordination = method
                == aos_sandbox::lifecycle::LifecycleMethodV1::Snapshot
                || (method == aos_sandbox::lifecycle::LifecycleMethodV1::Hibernate
                    && effect.step() == 5);
            let inventory_lineage =
                lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage");
            let boot_inventory_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                current.operation().project(),
                inventory_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let challenge = owner
                .begin_boot_inventory_bootstrap(&current_key, &boot_inventory_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let timing = production_authority_effect_timing().ok_or_else(|| {
                EffectFailure::Retryable(
                    "current clock cannot safely attenuate lifecycle authority".to_owned(),
                )
            })?;
            let authority = prepare_runtime_lifecycle_authority_effect_v1(
                journal,
                self.node,
                fence,
                runtime_action,
                timing,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            let host = sessions.host.as_mut().ok_or_else(missing_broker_session)?;
            if !host.lifecycle_runtime_ready() {
                return Err(EffectFailure::Retryable(
                    "protected Host session is completing earlier work".to_owned(),
                ));
            }
            let observation = host
                .apply_lifecycle_runtime(challenge, effect, fence, runtime_action, &authority)
                .map_err(|error| {
                    // Once request custody begins, retrying from the lifecycle
                    // cursor could mint a different authenticated identity.
                    // Fail this outer operation closed instead.
                    EffectFailure::Permanent(format!(
                        "authenticated Host runtime lifecycle effect did not settle: {error}"
                    ))
                })?;
            drop(sessions);
            (
                current_key,
                current.record(),
                observation,
                current_lifecycle_time()?,
                publish_coordination,
            )
        };

        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let transaction_id = lifecycle_progress_transaction_id(
                operation_id,
                current_record.digest(),
                b"runtime-effect-success",
            );
            let prepared = owner
                .prepare_successful_effect_progress(
                    &current_key,
                    transaction_id,
                    observation,
                    observed_at,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };
        self.settle_lifecycle_progress(operation_id, outcome)?;
        if publish_coordination {
            self.publish_snapshot_coordination_observation(
                operation_id,
                current_record,
                observation,
            )?;
        }
        Ok(true)
    }

    fn publish_snapshot_coordination_observation(
        &mut self,
        operation_id: OperationId,
        predecessor: aos_sandbox::lifecycle::LifecycleRecordDigestV1,
        observation: aos_sandbox::lifecycle::LifecycleEffectObservationV1,
    ) -> Result<(), EffectFailure> {
        let disposition = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (operation_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "snapshot operation is absent during coordination publication".to_owned(),
                    )
                })?;
            let operation_lineage = lifecycle_plan_resource_id(operation_id, b"operation-lineage");
            let coordination_lineage =
                lifecycle_plan_resource_id(operation_id, b"coordination-lineage");
            let coordination_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                current.operation().project(),
                coordination_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            drop(current);
            let publication = owner
                .publish_coordination_observation(
                    &operation_key,
                    &coordination_key,
                    lifecycle_progress_transaction_id(
                        operation_id,
                        predecessor.digest(),
                        b"coordination-observation",
                    ),
                    lifecycle_progress_resource_id(
                        operation_id,
                        predecessor.digest(),
                        b"coordination-observation",
                    ),
                    operation_lineage,
                    coordination_lineage,
                    observation,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            auxiliary_publication_disposition(publication)
        };
        self.settle_auxiliary_publication(operation_id, disposition, "snapshot coordination")
    }

    fn ensure_lifecycle_inventory_owners(&mut self) -> Result<(), EffectFailure> {
        if self.cache_inventory.is_none() {
            let (owner, _) =
                aos_sandbox::cache_residency::CacheResidencyProtectedOwnerV1::open_fixed_protected(
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            self.cache_inventory = Some(owner);
        }
        if self.transfer_inventory.is_none() {
            let (mut owner, _, initial) =
                aos_sandbox::multi_node::ProtectedMultiNodeAuthorityOwnerV1::open_fixed_protected()
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if let Some(initial) = initial {
                match initial {
                    aos_sandbox::multi_node::ProtectedRecordCommitOutcomeV1::Committed(_) => {}
                    aos_sandbox::multi_node::ProtectedRecordCommitOutcomeV1::RecoveryRequired(
                        recovery,
                    ) => match owner.resolve_store_write(recovery) {
                        aos_sandbox::multi_node::ProtectedStoreRecoveryOutcomeV1::RecordCommitted(
                            _,
                        ) => {}
                        aos_sandbox::multi_node::ProtectedStoreRecoveryOutcomeV1::CheckpointCommitted(
                            _,
                        )
                        | aos_sandbox::multi_node::ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
                            ..
                        } => {
                            return Err(EffectFailure::Permanent(
                                "protected Transfer bootstrap durability is unresolved".to_owned(),
                            ));
                        }
                    },
                }
            }
            self.transfer_inventory = Some(owner);
        }
        Ok(())
    }

    fn advance_suspend_terminal_publication(
        &mut self,
        operation_id: OperationId,
        journal: &mut Journal,
    ) -> Result<bool, EffectFailure> {
        let (
            current_key,
            boot_inventory_key,
            observation_key,
            boot_is_current,
            observation_is_current,
        ) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            if current.operation().terminal_result()
                != Some(aos_sandbox::lifecycle::LifecycleTerminalResultV1::Succeeded)
                || current.operation().intent().method()
                    != aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
            {
                return Ok(false);
            }
            let project = current.operation().project();
            let inventory_lineage =
                lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage");
            let observation_lineage =
                lifecycle_plan_resource_id(operation_id, b"suspend-observation-lineage");
            let boot_inventory_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                inventory_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let observation_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                project,
                observation_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let boot_is_current = owner
                .current_boot_inventory(&boot_inventory_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_some();
            let observation_is_current = owner
                .current_suspend_observation(&observation_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_some();
            (
                current_key,
                boot_inventory_key,
                observation_key,
                boot_is_current,
                observation_is_current,
            )
        };
        if observation_is_current {
            return Ok(false);
        }

        let operation_lineage = lifecycle_plan_resource_id(operation_id, b"operation-lineage");
        if !boot_is_current {
            self.ensure_lifecycle_inventory_owners()?;
            let challenge = {
                let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                    &mut self.source_domains,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                owner
                    .begin_boot_inventory_bootstrap(&current_key, &boot_inventory_key)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            };
            let storage_fence = aos_sandbox::begin_authenticated_storage_inventory_v1(journal)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (runtime, mounts, storage_outcome, storage_inventory, network) = {
                let mut sessions = self.sessions.lock().map_err(|_| {
                    EffectFailure::Retryable("broker session lock is poisoned".to_owned())
                })?;
                if sessions.host.is_none()
                    || sessions.mount.is_none()
                    || sessions.storage.is_none()
                    || sessions.network.is_none()
                {
                    return Err(EffectFailure::Retryable(
                        "lifecycle inventory sessions are not connected".to_owned(),
                    ));
                }
                let host = sessions.host.as_mut().ok_or_else(missing_broker_session)?;
                if !host.lifecycle_runtime_ready() {
                    return Err(EffectFailure::Retryable(
                        "protected Host session is completing earlier work".to_owned(),
                    ));
                }
                let runtime = host
                    .bootstrap_runtime_inventory(&challenge)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                let mounts = sessions
                    .mount
                    .as_mut()
                    .ok_or_else(missing_broker_session)?
                    .bootstrap_inventory_pair(&challenge)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                let storage_owner = sessions
                    .storage
                    .as_mut()
                    .ok_or_else(missing_broker_session)?;
                let storage_outcome = storage_owner
                    .current_inventory_observation()
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                let storage_inventory = storage_owner
                    .bootstrap_inventory_pair(&challenge)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                let network = sessions
                    .network
                    .as_mut()
                    .ok_or_else(missing_broker_session)?
                    .bootstrap_inventory_pair(&challenge)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                (runtime, mounts, storage_outcome, storage_inventory, network)
            };
            let storage = aos_sandbox::complete_authenticated_storage_inventory_v1(
                journal,
                storage_fence,
                &storage_outcome,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let transfer_inventory = self
                .transfer_inventory
                .as_mut()
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "protected Transfer inventory owner is unavailable".to_owned(),
                    )
                })?
                .lifecycle_transfer_inventory()
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let outcome = {
                let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                    &mut self.source_domains,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                owner
                    .publish_boot_inventory_bootstrap_from_protected_owners(
                        journal,
                        &current_key,
                        &boot_inventory_key,
                        challenge,
                        &runtime,
                        &mounts,
                        &storage,
                        &storage_inventory,
                        &network,
                        self.cache_inventory.as_mut().ok_or_else(|| {
                            EffectFailure::Permanent(
                                "protected Cache inventory owner is unavailable".to_owned(),
                            )
                        })?,
                        self.transfer_inventory.as_mut().ok_or_else(|| {
                            EffectFailure::Permanent(
                                "protected Transfer inventory owner is unavailable".to_owned(),
                            )
                        })?,
                        &transfer_inventory,
                        lifecycle_plan_transaction_id(operation_id, b"boot-inventory-publication"),
                        lifecycle_plan_resource_id(operation_id, b"boot-inventory-atomic-join"),
                        operation_lineage,
                        lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage"),
                        current_lifecycle_time()?,
                    )
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            };
            self.settle_lifecycle_progress(operation_id, outcome)?;
            return Ok(true);
        }

        let disposition = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let publication = owner
                .publish_suspend_observation(
                    &current_key,
                    &boot_inventory_key,
                    &observation_key,
                    lifecycle_plan_transaction_id(operation_id, b"suspend-observation-publication"),
                    lifecycle_plan_resource_id(operation_id, b"suspend-observation-atomic-join"),
                    operation_lineage,
                    lifecycle_plan_resource_id(operation_id, b"suspend-observation-lineage"),
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            auxiliary_publication_disposition(publication)
        };
        self.settle_auxiliary_publication(operation_id, disposition, "suspend observation")?;
        Ok(true)
    }

    fn advance_lifecycle_semantic_commit(
        &mut self,
        operation_id: OperationId,
        journal: &Journal,
    ) -> Result<bool, EffectFailure> {
        let (current_key, current_record, phase, semantic_commit) = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let (current_key, current) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            let phase = current.operation().phase();
            if !matches!(
                phase,
                aos_sandbox::lifecycle::LifecyclePhaseV1::Prepared
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::ReadyToCommit
                    | aos_sandbox::lifecycle::LifecyclePhaseV1::Committed
            ) {
                return Ok(false);
            }
            if !matches!(
                current.operation().intent().method(),
                aos_sandbox::lifecycle::LifecycleMethodV1::Stop
                    | aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
            ) {
                return Ok(false);
            }
            let semantic_commit =
                if phase == aos_sandbox::lifecycle::LifecyclePhaseV1::ReadyToCommit {
                    Some(
                        aos_sandbox::lifecycle::lifecycle_desired_state_semantic_commit_v1(
                            journal,
                            current.operation(),
                            current_lifecycle_time()?,
                        )
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?,
                    )
                } else {
                    None
                };
            (current_key, current.record(), phase, semantic_commit)
        };

        let outcome = {
            let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let transaction_id = lifecycle_progress_transaction_id(
                operation_id,
                current_record.digest(),
                match phase {
                    aos_sandbox::lifecycle::LifecyclePhaseV1::Prepared => b"commit-readiness",
                    aos_sandbox::lifecycle::LifecyclePhaseV1::ReadyToCommit => b"semantic-commit",
                    aos_sandbox::lifecycle::LifecyclePhaseV1::Committed => b"postcommit-progress",
                    _ => {
                        return Err(EffectFailure::Permanent(
                            "invalid lifecycle semantic phase".to_owned(),
                        ));
                    }
                },
            );
            let prepared = match phase {
                aos_sandbox::lifecycle::LifecyclePhaseV1::Prepared => {
                    owner.prepare_semantic_commit_readiness(&current_key, transaction_id)
                }
                aos_sandbox::lifecycle::LifecyclePhaseV1::ReadyToCommit => owner
                    .prepare_semantic_commit(
                        &current_key,
                        transaction_id,
                        semantic_commit.ok_or_else(|| {
                            EffectFailure::Permanent(
                                "lifecycle semantic witness is absent".to_owned(),
                            )
                        })?,
                    ),
                aos_sandbox::lifecycle::LifecyclePhaseV1::Committed => owner
                    .prepare_postcommit_progress(
                        &current_key,
                        transaction_id,
                        current_lifecycle_time()?,
                    ),
                _ => {
                    return Err(EffectFailure::Permanent(
                        "invalid lifecycle semantic phase".to_owned(),
                    ));
                }
            }
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            owner
                .commit_effect_progress(prepared)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        };
        self.settle_lifecycle_progress(operation_id, outcome)?;
        Ok(true)
    }

    fn lifecycle_terminal_receipt(
        &mut self,
        operation_id: OperationId,
    ) -> Result<Option<EffectReceipt>, EffectFailure> {
        let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
            &mut self.source_domains,
        )
        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        let Some((_, current)) = owner
            .current_operation_by_id(operation_id)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Ok(None);
        };
        if current.operation().terminal_result()
            != Some(aos_sandbox::lifecycle::LifecycleTerminalResultV1::Succeeded)
        {
            return Ok(None);
        }
        if current.operation().intent().method()
            == aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
        {
            let observation_lineage =
                lifecycle_plan_resource_id(operation_id, b"suspend-observation-lineage");
            let observation_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                current.operation().project(),
                observation_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if owner
                .current_suspend_observation(&observation_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_none()
            {
                return Ok(None);
            }
        }
        let bytes = [
            b"AOSLIF01".as_slice(),
            operation_id.as_bytes(),
            current.record().digest().as_bytes(),
        ]
        .concat();
        EffectReceipt::new(bytes)
            .map(Some)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))
    }

    fn settle_lifecycle_progress(
        &mut self,
        operation_id: OperationId,
        outcome: LifecycleProgressCommitOutcomeV1,
    ) -> Result<(), EffectFailure> {
        match outcome {
            LifecycleProgressCommitOutcomeV1::Applied(_) => Ok(()),
            LifecycleProgressCommitOutcomeV1::OutcomeUnknown { pending, .. } => {
                self.pending_source_commit = Some(PendingSourceCommit {
                    operation_id,
                    receipt: None,
                    pending,
                });
                Err(EffectFailure::Retryable(
                    "protected lifecycle progress durability is unknown".to_owned(),
                ))
            }
        }
    }
}

fn auxiliary_publication_disposition<Current>(
    publication: LifecycleCurrentAuxiliaryPublicationV1<Current>,
) -> AuxiliaryPublicationDisposition {
    match publication {
        LifecycleCurrentAuxiliaryPublicationV1::Current(_) => {
            AuxiliaryPublicationDisposition::Current
        }
        LifecycleCurrentAuxiliaryPublicationV1::OutcomeUnknown { pending, .. } => {
            AuxiliaryPublicationDisposition::OutcomeUnknown(pending)
        }
        LifecycleCurrentAuxiliaryPublicationV1::Diverged(pending) => {
            AuxiliaryPublicationDisposition::Diverged(pending)
        }
    }
}

fn lifecycle_plan_resource_id(operation: OperationId, purpose: &[u8]) -> ResourceId {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-resource.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    ResourceId::from_bytes(identity)
}

fn lifecycle_progress_resource_id(
    operation: OperationId,
    current_record: ObjectDigest,
    purpose: &[u8],
) -> ResourceId {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.progress-resource.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    ResourceId::from_bytes(identity)
}

fn lifecycle_plan_transaction_id(operation: OperationId, purpose: &[u8]) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(&digest[..16]);
    if transaction == [0; 16] {
        transaction[15] = 1;
    }
    transaction
}

fn lifecycle_plan_binding_transaction_id(
    operation: OperationId,
    current_record: ObjectDigest,
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-binding-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .finalize()
        .into();
    let mut transaction = [0_u8; 16];
    transaction.copy_from_slice(&digest[..16]);
    if transaction == [0; 16] {
        transaction[15] = 1;
    }
    transaction
}

fn lifecycle_initial_reservation_transaction_id(
    operation: OperationId,
    current_record: ObjectDigest,
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.initial-reservation-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .finalize()
        .into();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(&digest[..16]);
    if transaction == [0; 16] {
        transaction[15] = 1;
    }
    transaction
}

fn lifecycle_progress_transaction_id(
    operation: OperationId,
    current_record: ObjectDigest,
    purpose: &[u8],
) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.progress-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update(current_record.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    let mut transaction = [0; 16];
    transaction.copy_from_slice(&digest[..16]);
    if transaction == [0; 16] {
        transaction[15] = 1;
    }
    transaction
}

const fn is_lifecycle_mutation(request: &DormantSandboxRequestKindV1) -> bool {
    use DormantSandboxRequestKindV1 as Request;

    matches!(
        request,
        Request::Create(_)
            | Request::UpdatePolicy(_)
            | Request::Start(_)
            | Request::Stop(_)
            | Request::Suspend(_)
            | Request::Resume(_)
            | Request::Delete(_)
            | Request::Exec(_)
            | Request::CancelExec(_)
            | Request::ViewCreate(_)
            | Request::ViewAttach(_)
            | Request::ViewReplace(_)
            | Request::ViewDetach(_)
            | Request::ViewRelease(_)
            | Request::Snapshot(_)
            | Request::Restore(_)
            | Request::Fork(_)
            | Request::DeleteSnapshot(_)
    )
}

impl SingleNodeEffectExecutor for ProductionEffectExecutor {
    fn authority_effect_timing(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
    ) -> Option<AuthorityEffectAttemptTimingV1> {
        production_authority_effect_timing()
    }

    fn observe(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        plan: &EffectPlan,
    ) -> Result<EffectObservation, EffectFailure> {
        if plan.public_mutation_method().is_some() {
            return Err(EffectFailure::Permanent(
                "controller mutation bypassed its journal-custody hook".to_owned(),
            ));
        }
        Err(EffectFailure::Retryable(UNAVAILABLE_REASON.to_owned()))
    }

    fn apply(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        plan: &EffectPlan,
    ) -> Result<EffectReceipt, EffectFailure> {
        if plan.public_mutation_method().is_some() {
            return Err(EffectFailure::Permanent(
                "controller mutation bypassed its journal-custody hook".to_owned(),
            ));
        }
        Err(EffectFailure::Retryable(UNAVAILABLE_REASON.to_owned()))
    }

    fn observe_controller(
        &mut self,
        operation_id: OperationId,
        _step: u32,
        plan: &EffectPlan,
        journal: &mut Journal,
    ) -> Result<EffectObservation, EffectFailure> {
        if let Some(observation) = self.recover_pending_source_commit(operation_id)? {
            return Ok(observation);
        }
        let context = self.public_mutation_context(plan)?;
        if plan.public_mutation_method()
            != Some(aos_sandbox::controller_query::PublicOperationMethodV1::CancelOperation)
        {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if let Some((_, current)) = owner
                .current_operation_by_id(operation_id)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            {
                if current.operation().terminal_result()
                    == Some(aos_sandbox::lifecycle::LifecycleTerminalResultV1::CanceledBeforeCommit)
                {
                    return Ok(EffectObservation::Applied(
                        EffectReceipt::canceled_before_commit(current.record().digest()),
                    ));
                }
            }
            drop(owner);
            if let Some(receipt) = self.lifecycle_terminal_receipt(operation_id)? {
                return Ok(EffectObservation::Applied(receipt));
            }
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox::controller_query::PublicOperationMethodV1::CancelOperation)
        {
            let cancellation = Self::cancellation_request(&context)?;
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if let Some(resolution) = owner
                .cancellation_resolution(
                    context.caller(),
                    context.project(),
                    cancellation.target_operation,
                    cancellation.idempotency,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            {
                return Self::cancellation_receipt(&resolution).map(EffectObservation::Applied);
            }
            drop(owner);
            if let Some(receipt) =
                Self::terminal_public_operation_receipt(journal, cancellation.target_operation)?
            {
                return Ok(EffectObservation::Applied(receipt));
            }
        }
        Ok(EffectObservation::Absent)
    }

    fn apply_controller(
        &mut self,
        operation_id: OperationId,
        _step: u32,
        plan: &EffectPlan,
        journal: &mut Journal,
    ) -> Result<EffectReceipt, EffectFailure> {
        if let Some(observation) = self.recover_pending_source_commit(operation_id)? {
            return match observation {
                EffectObservation::Applied(receipt) => Ok(receipt),
                EffectObservation::Absent => Err(EffectFailure::Retryable(
                    "protected source commit recovery is incomplete".to_owned(),
                )),
            };
        }
        let context = self.public_mutation_context(plan)?;
        if plan.public_mutation_method()
            == Some(aos_sandbox::controller_query::PublicOperationMethodV1::CancelOperation)
        {
            let cancellation = Self::cancellation_request(&context)?;
            let admission = {
                let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                    &mut self.source_domains,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                if owner
                    .current_operation_by_id(cancellation.target_operation)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    .is_none()
                {
                    None
                } else {
                    Some(
                        owner
                            .admit_cancellation(
                                operation_id,
                                context.caller(),
                                context.project(),
                                cancellation.target_operation,
                                cancellation.idempotency,
                                cancellation.requested_at,
                            )
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?,
                    )
                }
            };
            if let Some(admission) = admission {
                return self.settle_cancellation_admission(operation_id, admission);
            }
            if let Some(receipt) =
                Self::terminal_public_operation_receipt(journal, cancellation.target_operation)?
            {
                return Ok(receipt);
            }
            return Err(EffectFailure::Retryable(
                "cancellation target is awaiting protected lifecycle admission".to_owned(),
            ));
        }
        let request = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        if is_lifecycle_mutation(&request) {
            let operation =
                self.validate_lifecycle_admission(operation_id, &context, &request, journal)?;
            let admission = {
                let mut owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                    &mut self.source_domains,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                owner
                    .admit_operation(operation)
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            };
            self.settle_lifecycle_admission(operation_id, admission)?;
            self.bind_lifecycle_plan(operation_id)?;
            self.ensure_initial_lifecycle_reservation(operation_id)?;
            if self.advance_suspend_terminal_publication(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if let Some(receipt) = self.lifecycle_terminal_receipt(operation_id)? {
                return Ok(receipt);
            }
            if self.advance_controller_lifecycle_effect(operation_id)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_runtime_lifecycle_effect(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_lifecycle_semantic_commit(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_suspend_terminal_publication(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if let Some(receipt) = self.lifecycle_terminal_receipt(operation_id)? {
                return Ok(receipt);
            }
        }
        Err(EffectFailure::Retryable(
            CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
        ))
    }

    fn observe_authority(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<AuthorityEffectObservationV1, EffectFailure> {
        let method = prepared
            .broker_request()
            .map_err(|_| {
                EffectFailure::Permanent("durable authority effect is malformed".to_owned())
            })?
            .method();
        if self.prepared_in_this_process(prepared) {
            let retained = {
                let mut sessions = self.sessions.lock().map_err(|_| {
                    EffectFailure::Retryable("broker session lock is poisoned".to_owned())
                })?;
                resume_controller_authority_effect(&mut sessions, method, prepared)?
            };
            return match retained {
                Some(receipt) => Ok(AuthorityEffectObservationV1::Applied(receipt)),
                None => Ok(AuthorityEffectObservationV1::Absent),
            };
        }
        let recovered = {
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            recover_controller_terminal_authority_effect(&mut sessions, method, prepared)?
        };
        if let Some(receipt) = recovered {
            return Ok(AuthorityEffectObservationV1::Applied(receipt));
        }
        if method == BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME {
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            return sessions
                .host
                .as_mut()
                .ok_or_else(missing_broker_session)?
                .query_authority_effect(prepared);
        }
        let retained = {
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            resume_controller_authority_effect(&mut sessions, method, prepared)?
        };
        if let Some(receipt) = retained {
            return Ok(AuthorityEffectObservationV1::Applied(receipt));
        }
        Err(EffectFailure::Retryable(
            "durable authority effect requires authenticated restart observation".to_owned(),
        ))
    }

    fn apply_authority(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        prepared: &PreparedAuthorityEffectV1,
    ) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
        let method = prepared
            .broker_request()
            .map_err(|_| {
                EffectFailure::Permanent("durable authority effect is malformed".to_owned())
            })?
            .method();
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| EffectFailure::Retryable("broker session lock is poisoned".to_owned()))?;
        apply_controller_authority_effect(&mut sessions, method, prepared)
    }
}

fn production_authority_effect_timing() -> Option<AuthorityEffectAttemptTimingV1> {
    let (host_boot_id, boottime_nanoseconds) = current_boot_and_boottime()?;
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let deadline = boottime_nanoseconds.checked_add(5_000_000_000)?;
    let provenance = RawClockProvenance::new_untrusted(*b"aos-kernel-clock").ok()?;
    let clock = RawPairedClockSample::new_untrusted(
        provenance,
        host_boot_id,
        realtime.tv_sec,
        boottime_nanoseconds,
    )
    .ok()?;
    Some(AuthorityEffectAttemptTimingV1::new(clock, deadline))
}

fn current_lifecycle_time() -> Result<LifecycleTimeV1, EffectFailure> {
    let realtime = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    let seconds = u64::try_from(realtime.tv_sec).map_err(|_| {
        EffectFailure::Retryable("system realtime is outside the lifecycle range".to_owned())
    })?;
    let nanoseconds = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(u64::try_from(realtime.tv_nsec).ok()?))
        .ok_or_else(|| {
            EffectFailure::Retryable("system realtime is outside the lifecycle range".to_owned())
        })?;
    LifecycleTimeV1::new(nanoseconds).map_err(|_| {
        EffectFailure::Retryable("system realtime is outside the lifecycle range".to_owned())
    })
}

fn current_boot_and_boottime() -> Option<([u8; 16], u64)> {
    let boot_before = KernelBootId::current().ok()?.into_bytes();
    let boottime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let boot_after = KernelBootId::current().ok()?.into_bytes();
    if boot_before != boot_after {
        return None;
    }
    let boottime_nanoseconds = u64::try_from(boottime.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(boottime.tv_nsec).ok()?)?;

    Some((boot_before, boottime_nanoseconds))
}

fn apply_controller_authority_effect(
    sessions: &mut ControllerBrokerSessions,
    method: BrokerMethod,
    prepared: &PreparedAuthorityEffectV1,
) -> Result<ValidatedAuthorityEffectReceiptV1, EffectFailure> {
    match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => sessions
            .host
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .apply_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => sessions
            .storage
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .apply_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => sessions
            .mount
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .apply_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => sessions
            .network
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .apply_authority_effect(prepared),
        _ => Err(EffectFailure::Permanent(
            "durable authority effect selected a non-Apply method".to_owned(),
        )),
    }
}

fn resume_controller_authority_effect(
    sessions: &mut ControllerBrokerSessions,
    method: BrokerMethod,
    prepared: &PreparedAuthorityEffectV1,
) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
    let retained = match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => sessions
            .host
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .resume_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => sessions
            .storage
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .resume_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => sessions
            .mount
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .resume_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => sessions
            .network
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .resume_authority_effect(prepared),
        _ => {
            return Err(EffectFailure::Permanent(
                "durable authority effect selected a non-Apply method".to_owned(),
            ));
        }
    };
    retained.transpose()
}

fn recover_controller_terminal_authority_effect(
    sessions: &mut ControllerBrokerSessions,
    method: BrokerMethod,
    prepared: &PreparedAuthorityEffectV1,
) -> Result<Option<ValidatedAuthorityEffectReceiptV1>, EffectFailure> {
    match method {
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME => sessions
            .host
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .recover_terminal_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_STORAGE_APPLY => sessions
            .storage
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .recover_terminal_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_MOUNT_APPLY => sessions
            .mount
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .recover_terminal_authority_effect(prepared),
        BrokerMethod::BROKER_METHOD_NETWORK_APPLY => sessions
            .network
            .as_mut()
            .ok_or_else(missing_broker_session)?
            .recover_terminal_authority_effect(prepared),
        _ => Err(EffectFailure::Permanent(
            "durable authority effect selected a non-Apply method".to_owned(),
        )),
    }
}

fn missing_broker_session() -> EffectFailure {
    EffectFailure::Retryable("authenticated broker session is unavailable".to_owned())
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
    commands: mpsc::SyncSender<ControllerCommand>,
    endpoint: ControllerEndpoint,
}

#[derive(Clone, Copy)]
enum ControllerEndpoint {
    RootDiagnostic,
    RegisteredPublic,
}

/// Carries the generated service's owned server-streaming responses.
type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, ConnectError>> + Send>>;

impl DiscoveryService for CapabilityService {
    async fn get_public_feature_registry<'a>(
        &'a self,
        _context: RequestContext,
        _request: ServiceRequest<'_, GetPublicFeatureRegistryRequest>,
    ) -> ServiceResult<impl Encodable<GetPublicFeatureRegistryResponse> + Send + use<'a>> {
        Response::ok(GetPublicFeatureRegistryResponse {
            registry: Some(aos_sandbox::controller_query::public_feature_registry_v1()).into(),
            ..Default::default()
        })
    }

    async fn get_node_capabilities<'a>(
        &'a self,
        _context: RequestContext,
        request: ServiceRequest<'_, GetNodeCapabilitiesRequest>,
    ) -> ServiceResult<impl Encodable<GetNodeCapabilitiesResponse> + Send + use<'a>> {
        Response::ok(self.node_capabilities(request.view())?)
    }
}

impl CapabilityService {
    #[allow(clippy::too_many_arguments)]
    async fn read_public_projection(
        &self,
        context: &RequestContext,
        method: PublicApiAuditMethodV1,
        resource_kind: ResourceKind,
        operation: CapabilityOperation,
        selector: Selector,
        protobuf_body: &[u8],
        query: PublicProjectionQueryV1,
    ) -> Result<AuthorizedPublicProjectionReadV1, ConnectError> {
        if !matches!(self.endpoint, ControllerEndpoint::RegisteredPublic) {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public resource reads are unavailable on the diagnostic endpoint",
            ));
        }
        let peer = context
            .extensions()
            .get::<aos_sandbox::public_api_session::PublicApiPeer>()
            .ok_or_else(|| {
                ConnectError::new(
                    ErrorCode::Unauthenticated,
                    "public resource read requires registered TLS peer evidence",
                )
            })?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::ReadPublicProjection {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                method,
                resource_kind,
                operation,
                selector,
                protobuf_body: protobuf_body.to_vec(),
                query,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = tokio::time::timeout(CONTROLLER_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "controller public resource read timed out",
                )
            })?
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::Unavailable,
                    "controller worker ended before replying",
                )
            })?;

        match result {
            Ok(Some(read)) => Ok(read),
            Ok(None) => Err(ConnectError::new(
                ErrorCode::NotFound,
                "authorized resource was not found",
            )),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "controller public resource read expired",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "controller public resource state is unavailable",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "public resource request is invalid",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public resource read was rejected",
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorize_public_read(
        &self,
        context: &RequestContext,
        method: PublicApiAuditMethodV1,
        resource_kind: ResourceKind,
        operation: CapabilityOperation,
        selector: Selector,
        protobuf_body: &[u8],
    ) -> Result<AuditAuthorizationV1, ConnectError> {
        if !matches!(self.endpoint, ControllerEndpoint::RegisteredPublic) {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public read authorization is unavailable on the diagnostic endpoint",
            ));
        }
        let peer = context
            .extensions()
            .get::<aos_sandbox::public_api_session::PublicApiPeer>()
            .ok_or_else(|| {
                ConnectError::new(
                    ErrorCode::Unauthenticated,
                    "public read requires registered TLS peer evidence",
                )
            })?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AuthorizePublicRead {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                method,
                resource_kind,
                operation,
                selector,
                protobuf_body: protobuf_body.to_vec(),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = tokio::time::timeout(CONTROLLER_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "controller public-read authorization timed out",
                )
            })?
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::Unavailable,
                    "controller worker ended before replying",
                )
            })?;

        match result {
            Ok(Some(authorization)) => Ok(authorization),
            Ok(None) => Err(ConnectError::new(
                ErrorCode::NotFound,
                "authorized resource was not found",
            )),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "controller public-read authorization expired",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "controller authorization state is unavailable",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "public read request is invalid",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public read was rejected",
            )),
        }
    }

    async fn plan_public_policy(
        &self,
        context: &RequestContext,
        method: PublicApiAuditMethodV1,
        protobuf_body: &[u8],
    ) -> Result<PolicyPlan, ConnectError> {
        if !matches!(self.endpoint, ControllerEndpoint::RegisteredPublic) {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public policy planning is unavailable on the diagnostic endpoint",
            ));
        }
        let peer = context
            .extensions()
            .get::<aos_sandbox::public_api_session::PublicApiPeer>()
            .ok_or_else(|| {
                ConnectError::new(
                    ErrorCode::Unauthenticated,
                    "public policy planning requires registered TLS peer evidence",
                )
            })?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::PlanPublicPolicy {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                method,
                protobuf_body: protobuf_body.to_vec(),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = tokio::time::timeout(CONTROLLER_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "controller public policy planning timed out",
                )
            })?
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::Unavailable,
                    "controller worker ended before replying",
                )
            })?;

        match result {
            Ok(plan) => Ok(plan),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "controller public policy planning expired",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "public policy-planning request is invalid",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public policy-planning request was rejected",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "controller public policy planner is unavailable",
            )),
        }
    }

    async fn admit_public_operator_recovery(
        &self,
        context: &RequestContext,
        canonical_request: Vec<u8>,
    ) -> Result<Operation, ConnectError> {
        if !matches!(self.endpoint, ControllerEndpoint::RegisteredPublic) {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "operator recovery is unavailable on the diagnostic endpoint",
            ));
        }
        let peer = context
            .extensions()
            .get::<aos_sandbox::public_api_session::PublicApiPeer>()
            .ok_or_else(|| {
                ConnectError::new(
                    ErrorCode::Unauthenticated,
                    "operator recovery requires registered TLS peer evidence",
                )
            })?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AdmitPublicOperatorRecovery {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                canonical_request,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = tokio::time::timeout(CONTROLLER_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "controller operator-recovery admission timed out",
                )
            })?
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::Unavailable,
                    "controller worker ended before replying",
                )
            })?;

        match result {
            Ok(operation) => Ok(operation),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "controller operator-recovery admission expired",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "operator-recovery request is invalid",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "operator-recovery request was rejected",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "controller operator-recovery state is unavailable",
            )),
        }
    }

    async fn admit_public_mutation(
        &self,
        context: &RequestContext,
        canonical_request: Vec<u8>,
    ) -> Result<AdmittedPublicMutationV1, ConnectError> {
        if !matches!(self.endpoint, ControllerEndpoint::RegisteredPublic) {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public mutations are unavailable on the diagnostic endpoint",
            ));
        }
        let peer = context
            .extensions()
            .get::<aos_sandbox::public_api_session::PublicApiPeer>()
            .ok_or_else(|| {
                ConnectError::new(
                    ErrorCode::Unauthenticated,
                    "public mutation requires registered TLS peer evidence",
                )
            })?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AdmitPublicMutation {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                canonical_request,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = tokio::time::timeout(CONTROLLER_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "controller public mutation admission timed out",
                )
            })?
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::Unavailable,
                    "controller worker ended before replying",
                )
            })?;

        match result {
            Ok(admitted) => Ok(admitted),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "controller public mutation admission expired",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "public mutation request is invalid",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public mutation was rejected",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "controller public mutation state is unavailable",
            )),
        }
    }

    fn node_capabilities(
        &self,
        request: &GetNodeCapabilitiesRequestView<'_>,
    ) -> Result<GetNodeCapabilitiesResponse, ConnectError> {
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
        capabilities.response()
    }

    async fn operation(
        &self,
        context: &RequestContext,
        operation_identity: &[u8],
        protobuf_body: &[u8],
    ) -> Result<GetOperationResponse, ConnectError> {
        let operation_id: [u8; 16] = operation_identity.try_into().map_err(|_| {
            ConnectError::new(
                ErrorCode::InvalidArgument,
                "operation identity must contain exactly 16 bytes",
            )
        })?;
        if operation_id == [0; 16] {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "operation identity must be nonzero",
            ));
        }

        let (reply, response) = tokio::sync::oneshot::channel();
        let operation_id = OperationId::from_bytes(operation_id);
        let expires_at = Instant::now() + CONTROLLER_COMMAND_TIMEOUT;
        let command = match self.endpoint {
            ControllerEndpoint::RootDiagnostic => ControllerCommand::GetOperation {
                operation_id,
                expires_at,
                reply,
            },
            ControllerEndpoint::RegisteredPublic => {
                let peer = context
                    .extensions()
                    .get::<aos_sandbox::public_api_session::PublicApiPeer>()
                    .ok_or_else(|| {
                        ConnectError::new(
                            ErrorCode::Unauthenticated,
                            "public operation lookup requires registered TLS peer evidence",
                        )
                    })?;
                ControllerCommand::GetAuthorizedOperation {
                    peer: peer.clone(),
                    capability_id: public_capability_id(context)?,
                    operation_id,
                    protobuf_body: protobuf_body.to_vec(),
                    expires_at,
                    reply,
                }
            }
        };
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => ConnectError::new(
                    ErrorCode::ResourceExhausted,
                    "controller command capacity is exhausted",
                ),
                mpsc::TrySendError::Disconnected(_) => {
                    ConnectError::new(ErrorCode::Unavailable, "controller worker is unavailable")
                }
            })?;
        let result = tokio::time::timeout(CONTROLLER_COMMAND_TIMEOUT, response)
            .await
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "controller operation lookup timed out",
                )
            })?
            .map_err(|_| {
                ConnectError::new(
                    ErrorCode::Unavailable,
                    "controller worker ended before replying",
                )
            })?;
        let operation = match result {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                return Err(ConnectError::new(
                    ErrorCode::NotFound,
                    "operation was not found",
                ));
            }
            Err(ControllerCommandFailure::DeadlineExceeded) => {
                return Err(ConnectError::new(
                    ErrorCode::DeadlineExceeded,
                    "controller operation lookup expired",
                ));
            }
            Err(ControllerCommandFailure::ControllerUnavailable) => {
                return Err(ConnectError::new(
                    ErrorCode::Unavailable,
                    "controller operation state is unavailable",
                ));
            }
            Err(ControllerCommandFailure::InvalidRequest) => {
                return Err(ConnectError::new(
                    ErrorCode::InvalidArgument,
                    "operation lookup request is invalid",
                ));
            }
            Err(ControllerCommandFailure::Rejected) => {
                return Err(ConnectError::new(
                    ErrorCode::PermissionDenied,
                    "operation lookup was rejected",
                ));
            }
        };

        Ok(GetOperationResponse {
            operation: Some(operation).into(),
            ..Default::default()
        })
    }
}

fn controller_command_send_error<T>(error: mpsc::TrySendError<T>) -> ConnectError {
    match error {
        mpsc::TrySendError::Full(_) => ConnectError::new(
            ErrorCode::ResourceExhausted,
            "controller command capacity is exhausted",
        ),
        mpsc::TrySendError::Disconnected(_) => {
            ConnectError::new(ErrorCode::Unavailable, "controller worker is unavailable")
        }
    }
}

impl OperationService for CapabilityService {
    async fn get_operation<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, GetOperationRequest>,
    ) -> ServiceResult<impl Encodable<GetOperationResponse> + Send + use<'a>> {
        Response::ok(
            self.operation(&context, request.view().operation_id, request.bytes())
                .await?,
        )
    }

    async fn cancel_operation<'a>(
        &'a self,
        context: RequestContext,
        request: ServiceRequest<'_, CancelOperationRequest>,
    ) -> ServiceResult<impl Encodable<CancelOperationResponse> + Send + use<'a>> {
        let admitted = self
            .admit_public_command(
                &context,
                PublicApiAuditMethodV1::CancelOperation,
                request.bytes(),
            )
            .await?;

        Response::ok(CancelOperationResponse {
            operation: Some(admitted.operation).into(),
            ..Default::default()
        })
    }

    async fn watch(
        &self,
        context: RequestContext,
        request: ServiceRequest<'_, WatchRequest>,
    ) -> ServiceResult<ResponseStream<impl Encodable<Event> + Send + use<>>> {
        self.watch_response(&context, request).await
    }

    async fn get_node_capabilities<'a>(
        &'a self,
        _context: RequestContext,
        request: ServiceRequest<'_, GetNodeCapabilitiesRequest>,
    ) -> ServiceResult<impl Encodable<GetNodeCapabilitiesResponse> + Send + use<'a>> {
        Response::ok(self.node_capabilities(request.view())?)
    }
}

fn public_capability_id(context: &RequestContext) -> Result<CapabilityId, ConnectError> {
    let mut values = context.headers().get_all(PUBLIC_CAPABILITY_HEADER).iter();
    let value = values.next().ok_or_else(|| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public operation lookup requires a capability identity",
        )
    })?;
    if values.next().is_some() {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public operation lookup requires exactly one capability identity",
        ));
    }
    let value = value.to_str().map_err(|_| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability identity is not valid text",
        )
    })?;
    let capability_id: CapabilityId = value.parse().map_err(|_| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability identity is not canonical",
        )
    })?;
    if capability_id.as_bytes() == &[0; 16] {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability identity must be nonzero",
        ));
    }

    Ok(capability_id)
}

#[cfg(test)]
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
    /// Protected public TLS credentials are missing, unsafe, or invalid.
    #[error(transparent)]
    PublicSession(#[from] aos_sandbox::public_api_session::PublicApiSessionError),
    /// The authenticated public server could not bind or serve.
    #[error("controller public API failed: {0}")]
    PublicServer(std::io::Error),
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
    /// Controller journal identity or assignment validation failed.
    #[error(transparent)]
    ControllerJournal(#[from] aos_sandbox::controller_service::journal::ControllerJournalError),
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
    /// The protected lifecycle source-domain projection failed cold replay.
    #[error(transparent)]
    LifecycleJournal(#[from] aos_sandbox::lifecycle::LifecycleProtectedJournalErrorV1),
    /// Fixed controller configuration is invalid.
    #[error(transparent)]
    Controller(#[from] ControllerServiceError),
    /// Protected current runtime assignments do not belong to this node.
    #[error(transparent)]
    RuntimeAuthority(#[from] aos_sandbox::runtime_authority::RuntimeAuthorityError),
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
            public_api: false,
        }
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

    #[tokio::test]
    async fn canonical_discovery_service_exposes_only_checked_diagnostics() {
        use aos_proto::aos::sandbox::v1::{
            GetNodeCapabilitiesRequest, GetPublicFeatureRegistryRequest,
        };
        use buffa::{Message, view::HasMessageView};
        use connectrpc::CodecFormat;

        let mut state = CapabilityState::starting([7; 16]);
        state.record_success(9, ObjectDigest::from_bytes([8; 32]));
        let (commands, _command_receiver) = mpsc::sync_channel(1);
        let service = CapabilityService {
            capabilities: Arc::new(Mutex::new(state)),
            commands,
            endpoint: ControllerEndpoint::RootDiagnostic,
        };

        let registry_body: axum::body::Bytes = GetPublicFeatureRegistryRequest::default()
            .encode_to_vec()
            .into();
        let registry_view = GetPublicFeatureRegistryRequest::decode_view(&registry_body).unwrap();
        let registry_response = DiscoveryService::get_public_feature_registry(
            &service,
            RequestContext::new(Default::default()),
            ServiceRequest::from_parts(&registry_view, &registry_body),
        )
        .await
        .unwrap();
        let registry_response = GetPublicFeatureRegistryResponse::decode_from_slice(
            registry_response
                .body
                .encode(CodecFormat::Proto)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let expected_registry = aos_sandbox::controller_query::public_feature_registry_v1();
        assert_eq!(
            registry_response.registry.as_option(),
            Some(&expected_registry)
        );

        let capabilities_body: axum::body::Bytes = GetNodeCapabilitiesRequest {
            node_id: vec![7; 16],
            ..Default::default()
        }
        .encode_to_vec()
        .into();
        let capabilities_view =
            GetNodeCapabilitiesRequest::decode_view(&capabilities_body).unwrap();
        let capabilities_response = DiscoveryService::get_node_capabilities(
            &service,
            RequestContext::new(Default::default()),
            ServiceRequest::from_parts(&capabilities_view, &capabilities_body),
        )
        .await
        .unwrap();
        let capabilities_response = GetNodeCapabilitiesResponse::decode_from_slice(
            capabilities_response
                .body
                .encode(CodecFormat::Proto)
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let capabilities = capabilities_response.capabilities.as_option().unwrap();
        assert_eq!(capabilities.node_id, [7; 16]);
        assert!(capabilities.capabilities.is_empty());
    }

    #[tokio::test]
    async fn operation_lookup_crosses_the_bounded_worker_channel() {
        let (commands, receiver) = mpsc::sync_channel(1);
        let service = CapabilityService {
            capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
            commands,
            endpoint: ControllerEndpoint::RootDiagnostic,
        };
        let operation_id = [0x42; 16];
        let worker = std::thread::spawn(move || {
            let (operation_id, expires_at, reply) = match receiver.recv().unwrap() {
                ControllerCommand::GetOperation {
                    operation_id,
                    expires_at,
                    reply,
                } => (operation_id, expires_at, reply),
                ControllerCommand::GetAuthorizedOperation { .. } => {
                    panic!("root diagnostics must not enter public authorization")
                }
                ControllerCommand::AuthorizePublicRead { .. } => {
                    panic!("root diagnostics must not enter public read authorization")
                }
                ControllerCommand::ReadPublicProjection { .. } => {
                    panic!("root diagnostics must not enter public projection reads")
                }
                ControllerCommand::PlanPublicPolicy { .. }
                | ControllerCommand::AdmitPublicOperatorRecovery { .. }
                | ControllerCommand::AdmitPublicMutation { .. } => {
                    panic!("root diagnostics must not enter public mutation services")
                }
            };
            assert_eq!(operation_id.as_bytes(), &[0x42; 16]);
            assert!(expires_at > Instant::now());
            reply
                .send(Ok(Some(Operation {
                    operation_id: operation_id.into_bytes().to_vec(),
                    ..Default::default()
                })))
                .unwrap();
        });

        let response = service
            .operation(&RequestContext::default(), &operation_id, &[])
            .await
            .unwrap();
        assert_eq!(
            response.operation.as_option().unwrap().operation_id,
            operation_id
        );
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn operation_lookup_rejects_invalid_identity_and_channel_saturation() {
        let (commands, receiver) = mpsc::sync_channel(1);
        let service = CapabilityService {
            capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
            commands: commands.clone(),
            endpoint: ControllerEndpoint::RootDiagnostic,
        };

        let invalid = service
            .operation(&RequestContext::default(), &[1; 15], &[])
            .await
            .unwrap_err();
        assert_eq!(invalid.code, ErrorCode::InvalidArgument);
        let zero = service
            .operation(&RequestContext::default(), &[0; 16], &[])
            .await
            .unwrap_err();
        assert_eq!(zero.code, ErrorCode::InvalidArgument);

        let (reply, _response) = tokio::sync::oneshot::channel();
        commands
            .try_send(ControllerCommand::GetOperation {
                operation_id: OperationId::from_bytes([0x43; 16]),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .unwrap();
        let saturated = service
            .operation(&RequestContext::default(), &[0x44; 16], &[])
            .await
            .unwrap_err();
        assert_eq!(saturated.code, ErrorCode::ResourceExhausted);

        drop(receiver);
    }

    #[test]
    fn public_capability_header_requires_one_canonical_nonzero_identity() {
        let missing = public_capability_id(&RequestContext::default()).unwrap_err();
        assert_eq!(missing.code, ErrorCode::Unauthenticated);

        for invalid in [
            "NOT-A-UUID",
            "00112233-4455-6677-8899-AABBCCDDEEFF",
            "00000000-0000-0000-0000-000000000000",
        ] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(PUBLIC_CAPABILITY_HEADER, invalid.parse().unwrap());
            let error = public_capability_id(&RequestContext::new(headers)).unwrap_err();
            assert_eq!(error.code, ErrorCode::Unauthenticated);
        }

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            PUBLIC_CAPABILITY_HEADER,
            "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap(),
        );
        let capability_id = public_capability_id(&RequestContext::new(headers)).unwrap();
        assert_eq!(
            capability_id.to_string(),
            "00112233-4455-6677-8899-aabbccddeeff"
        );

        let mut duplicate_headers = axum::http::HeaderMap::new();
        duplicate_headers.append(
            PUBLIC_CAPABILITY_HEADER,
            "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap(),
        );
        duplicate_headers.append(
            PUBLIC_CAPABILITY_HEADER,
            "11112233-4455-6677-8899-aabbccddeeff".parse().unwrap(),
        );
        let duplicate = public_capability_id(&RequestContext::new(duplicate_headers)).unwrap_err();
        assert_eq!(duplicate.code, ErrorCode::Unauthenticated);
    }

    #[tokio::test]
    async fn public_operation_lookup_never_falls_back_to_root_diagnostics() {
        let (commands, _receiver) = mpsc::sync_channel(1);
        let service = CapabilityService {
            capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
            commands,
            endpoint: ControllerEndpoint::RegisteredPublic,
        };

        let error = service
            .operation(&RequestContext::default(), &[0x42; 16], &[0x0a, 0x10])
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unauthenticated);
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
        let status = pending_first_reconciliation_cycle(
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
                calls.order.push("bounded reconciliation");
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
                "bounded reconciliation",
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
        let result: Result<&str, &str> = pending_first_reconciliation_cycle(
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
    fn reconciliation_failure_closes_readiness_before_broker_inventory() {
        #[derive(Default)]
        struct Calls {
            reconciliation: usize,
            broker_inventory: usize,
        }

        let mut calls = Calls::default();
        let result = pending_first_reconciliation_cycle(
            &mut calls,
            |_| Ok::<_, &'static str>(None::<()>),
            |_, _| Ok(()),
            |calls| {
                calls.reconciliation += 1;
                Err("reconciliation failed")
            },
            |calls| {
                calls.broker_inventory += 1;
                Ok("ready")
            },
        );

        assert!(matches!(result, Err("reconciliation failed")));
        assert_eq!(calls.reconciliation, 1);
        assert_eq!(calls.broker_inventory, 0);
        assert!(
            result.is_err(),
            "failed reconciliation must not open readiness"
        );
    }

    #[test]
    fn protected_publication_retries_only_retained_recovery() {
        assert!(matches!(
            classify_protected_publication_error(ControllerHostPublicationError::RecoveryPending),
            CycleFailure::Retryable(_)
        ));
        assert!(matches!(
            classify_protected_publication_error(ControllerHostPublicationError::Conflict),
            CycleFailure::Fatal(_)
        ));
        assert!(matches!(
            classify_protected_publication_error(ControllerHostPublicationError::Session(
                crate::DormantBrokerSessionHandshakeErrorV1::Deadline
            )),
            CycleFailure::Fatal(_)
        ));
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
    fn protected_handshake_authentication_failures_are_terminal() {
        use crate::DormantBrokerSessionHandshakeErrorV1 as HandshakeError;

        for error in [
            HandshakeError::EndpointRole,
            HandshakeError::RemoteInvalid,
            HandshakeError::KernelEvidence,
        ] {
            assert!(matches!(
                classify_protected_handshake_error(error),
                CycleFailure::Fatal(_)
            ));
        }
        for error in [HandshakeError::Transport, HandshakeError::Deadline] {
            assert!(matches!(
                classify_protected_handshake_error(error),
                CycleFailure::Retryable(_)
            ));
        }
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
}
