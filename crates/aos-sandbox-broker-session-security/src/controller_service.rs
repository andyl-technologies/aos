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
//! Unix endpoint offers discovery, capability-authorized operation reads, and
//! explicitly admitted mutations to registered mutually authenticated TLS
//! clients; socket credentials or request headers do not identify those clients
//! or grant authority. UID 0
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

use std::fs::File;
use std::io::{IoSlice, Read};
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
    GetPublicFeatureRegistryResponse, NodeCapabilities, OpenSshAccessEndpoint, Operation,
    OperationPhase, OperationService, OperationServiceExt, OperatorRecoveryAction,
    OperatorServiceExt, PolicyPlan, SandboxServiceExt, SnapshotServiceExt, Timestamp, WatchRequest,
};
use aos_sandbox_core::{
    AttachmentId, CapabilityId, NodeId, ObjectDigest, Operation as CapabilityOperation,
    OperationId, RawClockProvenance, RawPairedClockSample, ResourceId,
};
use aos_sandbox_core::{ResourceKind, Selector};
use aos_sandbox_linux::Error as LinuxError;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use connectrpc::{
    ConnectError, Encodable, ErrorCode, RequestContext, Response, ServiceRequest, ServiceResult,
};
use futures::Stream;
use rustix::fs::{Mode, OFlags, open};
use rustix::net::{
    AddressFamily, SendAncillaryBuffer, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
    sendmsg_addr, socket_with,
};
use sha2::{Digest as _, Sha256};

use crate::controller_attach_credentials::ControllerAttachCredentialsV1;
use crate::controller_cache_readback_credential::validate_process_cache_readback_credentials_v1;
use crate::controller_guest_root_credentials::load_guest_root_template_pins_optional;
use crate::controller_ownership::{ControllerOwnershipConfigurationV1, sample_ownership_clock};
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::controller_publication::{ControllerHostPublication, ControllerHostPublicationError};
use aos_sandbox::cache_residency::{
    CacheOwnerLimitsV1, CacheReplayControllerBootstrapOwnerV1, CacheResidencyProtectedOwnerV1,
    DormantCacheOwnerV1,
};
use aos_sandbox::cli_model::{
    AuditAuthorizationV1, DormantSandboxRequestKindV1, PublicApiAuditMethodV1,
    PublicMutationRequestV1,
};
use aos_sandbox::controller::DormantControllerCompositionV1;
use aos_sandbox::controller_service::journal::{
    production_journal_limits, validate_controller_journal,
};
use aos_sandbox::controller_service::public_projection::{
    AuthorizedPublicProjectionReadV1, PublicProjectionKindV1, PublicProjectionQueryV1,
    PublicProjectionRecordV1,
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
    EffectObservation, EffectPlan, EffectReceipt, GuardianPlanRequestV1,
    HostCatalogReconciliationError, HostCatalogReconciliationV1, Journal, JournalError,
    MountAttemptError, NodeController, NodeControllerLimits, OperationCompilationError,
    OwnershipGateStatusV1, OwnershipResumeOutcomeV1, PreparedAuthorityEffectV1,
    PublicMutationEffectV1, Reconciler, ResourceInventoryError, SignedBrokerPlan,
    SingleNodeEffectExecutor, ValidatedAuthorityEffectReceiptV1,
    activated_ownership_gate_digest_from_journal_v1, prepare_runtime_lifecycle_authority_effect_v1,
    public_operation_resource_from_journal_v1,
};

mod attachment_desired;
mod attachment_physical;
mod attachment_slot_effect;
mod attachment_target;
mod cache_pin;
mod cache_unpin;
pub(crate) mod execution;
pub(crate) mod execution_argument_observe;
pub(crate) mod execution_capture_candidate;
pub(crate) mod execution_output_reserve;
mod guest_root;
mod public_api;
mod public_attach;
mod public_hierarchy;
mod public_services;
mod public_watch;
mod publisher_credential;
mod publisher_ingress;
mod publisher_policy_source;
mod storage_snapshot;
mod view_mutations;

const STATE_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const JOURNAL_NAME: &str = "controller.journal";
const DIAGNOSTIC_SOCKET: &str = "/run/aos/sandboxd/diagnostics.sock";
const NODE_ID_CREDENTIAL: &str = "node-id";
const CACHE_REPLAY_BUNDLE_CREDENTIAL: &str = "cache-replay-bundle";
const MAXIMUM_CACHE_REPLAY_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const CACHE_OWNER_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const CONTROLLER_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROLLER_COMMAND_CAPACITY: usize = 64;
const PUBLIC_CAPABILITY_HEADER: &str = "aos-capability-id";
const PUBLIC_CAPABILITY_HANDLE_HEADER: &str = "aos-capability-handle";
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
    storage_root: guest_root::ControllerGuestRootExchangeV1,
    network: Option<crate::DormantNetworkLifecycleInventoryOwnerV1>,
}

enum ControllerCommand {
    BootstrapPublicCapability {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        idempotency_key: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<(CapabilityId, [u8; 32])>>,
    },
    GetOperation {
        operation_id: OperationId,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Option<Operation>>>,
    },
    GetAuthorizedOperation {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: aos_sandbox_core::CapabilityId,
        capability_handle: [u8; 32],
        operation_id: OperationId,
        protobuf_body: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Option<Operation>>>,
    },
    AuthorizePublicRead {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
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
        capability_handle: [u8; 32],
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
        capability_handle: [u8; 32],
        method: PublicApiAuditMethodV1,
        protobuf_body: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<PolicyPlan>>,
    },
    AdmitPublicOperatorRecovery {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        canonical_request: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<Operation>>,
    },
    AdmitPublicMutation {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        canonical_request: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<AdmittedPublicMutationV1>>,
    },
    AdmitPublicAttach {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        capability_id: CapabilityId,
        capability_handle: [u8; 32],
        canonical_request: Vec<u8>,
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<AdmittedPublicAttachV1>>,
    },
    ResolvePublicCapabilityTarget {
        peer: aos_sandbox::public_api_session::PublicApiPeer,
        handle: [u8; 32],
        expires_at: Instant,
        reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<CapabilityId>>,
    },
}

struct AdmittedPublicMutationV1 {
    operation: Operation,
    projections: Vec<PublicProjectionRecordV1>,
    holder_handle: Option<[u8; 32]>,
}

struct AdmittedPublicAttachV1 {
    operation: Operation,
    access: OpenSshAccessEndpoint,
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
/// alter [`run_from_environment`]. Production selects its concrete compiler
/// and executor separately; constructing this dormant composition cannot
/// activate them or bypass the installed service's authority checks.
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
/// and enables the registered-client public endpoint at the fixed socket.
/// `--publisher-ingress` requires one protected service-scope credential and
/// PID 1's exact record-subject listener; it registers an execution only.
/// The node identity is read from
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
    let publisher_listener = if configuration.publisher_ingress {
        Some(
            publisher_ingress::adopt_listener()
                .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?,
        )
    } else {
        None
    };
    let node_id = read_node_id()?;
    let publisher_registration = if let Some(listener) = publisher_listener {
        let scope = publisher_ingress::PublisherServiceScopeV1::from_process_credential(
            NodeId::from_bytes(node_id),
        )
        .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?;
        Some(
            publisher_ingress::PublisherRegistrationOwnerV1::new(listener, scope)
                .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?,
        )
    } else {
        None
    };
    if let Some(bundle) = read_cache_replay_bundle()? {
        CacheReplayControllerBootstrapOwnerV1::import_fixed_bundle_for_uid(
            configuration.uid,
            &bundle,
        )
        .map_err(ControllerRuntimeError::CacheReplaySource)?;
    }
    let ownership = ControllerOwnershipConfigurationV1::from_process_credentials_optional()
        .map_err(|_| ControllerRuntimeError::InvalidOwnershipCredential)?;
    let attach_credentials = ControllerAttachCredentialsV1::from_process_credentials_optional()
        .map_err(|_| ControllerRuntimeError::InvalidAttachCredential)?;
    let attach_plan_signer = ControllerBrokerPlanSignerV1::from_process_credentials_optional()
        .map_err(|_| ControllerRuntimeError::InvalidBrokerPlanCredential)?;
    let guest_root_pins = load_guest_root_template_pins_optional()
        .map_err(|_| ControllerRuntimeError::InvalidGuestRootCredential)?;
    let listener = bind_diagnostic_socket(&configuration)?;
    let sessions = Arc::new(Mutex::new(ControllerBrokerSessions::default()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ControllerRuntimeError::Runtime)?;
    let attachment_host = match runtime.block_on(attachment_target::observe_host_service_identity())
    {
        Ok(identity) => Some(identity),
        Err(error) => {
            // Unrelated controller work continues; attachment effects retain no target.
            eprintln!("aos-sandboxd: Host attachment identity unavailable: {error}");
            None
        }
    };
    let attachment_mount =
        match runtime.block_on(attachment_target::observe_mount_service_identity()) {
            Ok(identity) => Some(identity),
            Err(error) => {
                eprintln!("aos-sandboxd: Mount attachment identity unavailable: {error}");
                None
            }
        };
    let mut controller = open_controller(
        &configuration,
        node_id,
        Arc::clone(&sessions),
        attachment_host,
        attachment_mount,
    )?;
    if let Some(scope) = publisher_registration
        .as_ref()
        .map(|owner| owner.service_scope())
    {
        publisher_policy_source::install_from_process_credentials(&mut controller, scope)
            .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?;
    }
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
                ownership,
                attach_credentials,
                attach_plan_signer,
                guest_root_pins,
                publisher_registration,
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
    ownership: Option<ControllerOwnershipConfigurationV1>,
    attach_credentials: Option<ControllerAttachCredentialsV1>,
    attach_plan_signer: Option<ControllerBrokerPlanSignerV1>,
    guest_root_pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    mut publisher_registration: Option<publisher_ingress::PublisherRegistrationOwnerV1>,
    capabilities: Arc<Mutex<CapabilityState>>,
    sessions: SharedControllerBrokerSessions,
    commands: mpsc::Receiver<ControllerCommand>,
    events: mpsc::Sender<WorkerEvent>,
) {
    let mut ready = false;
    let mut next_cycle = Instant::now();
    loop {
        if Instant::now() >= next_cycle {
            match run_controller_cycle(
                &mut controller,
                node_id,
                &sessions,
                !ready,
                guest_root_pins,
                attach_plan_signer.as_ref(),
            ) {
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

        if let Some(owner) = publisher_registration.as_mut() {
            if let Err(message) = owner.try_register(&mut controller) {
                let _ = events.send(WorkerEvent::Fatal(message));
                return;
            }
        }

        let mut wait = next_cycle.saturating_duration_since(Instant::now());
        if publisher_registration
            .as_ref()
            .is_some_and(|owner| owner.needs_registration())
        {
            wait = wait.min(Duration::from_millis(250));
        }
        match commands.recv_timeout(wait) {
            Ok(command) => {
                if let Err(message) = handle_controller_command(
                    &mut controller,
                    ownership.as_ref(),
                    attach_credentials.as_ref(),
                    attach_plan_signer.as_ref(),
                    NodeId::from_bytes(node_id),
                    &sessions,
                    command,
                ) {
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

fn reply_read_only_controller_result<T>(
    reply: tokio::sync::oneshot::Sender<ControllerCommandResponse<T>>,
    result: Result<T, ControllerServiceError>,
) -> Result<(), String> {
    match result {
        Ok(value) => {
            let _ = reply.send(Ok(value));
            Ok(())
        }
        Err(error) => {
            let message = error.to_string();
            let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
            Err(message)
        }
    }
}

fn handle_controller_command(
    controller: &mut ProductionController,
    ownership: Option<&ControllerOwnershipConfigurationV1>,
    attach_credentials: Option<&ControllerAttachCredentialsV1>,
    attach_plan_signer: Option<&ControllerBrokerPlanSignerV1>,
    node: NodeId,
    sessions: &SharedControllerBrokerSessions,
    command: ControllerCommand,
) -> Result<(), String> {
    macro_rules! require_holder_handle {
        ($peer:expr, $id:expr, $handle:expr, $reply:expr) => {
            if controller
                .resolve_public_capability_handle(&$peer, $id, &$handle)
                .is_err()
            {
                let _ = $reply.send(Err(ControllerCommandFailure::Rejected));
                return Ok(());
            }
        };
    }

    let effect_command = matches!(
        &command,
        ControllerCommand::AdmitPublicMutation { .. }
            | ControllerCommand::AdmitPublicAttach { .. }
            | ControllerCommand::AdmitPublicOperatorRecovery { .. }
    );
    if effect_command
        && sessions
            .lock()
            .map_err(|_| "broker session lock is poisoned".to_owned())?
            .storage_root
            .has_pending()
    {
        // A retained method-31 packet owns the sole Storage session until the
        // next cycle recovers it and completes a fresh physical readback.
        match command {
            ControllerCommand::AdmitPublicMutation { reply, .. } => {
                let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
            }
            ControllerCommand::AdmitPublicAttach { reply, .. } => {
                let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
            }
            ControllerCommand::AdmitPublicOperatorRecovery { reply, .. } => {
                let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
            }
            _ => return Err("guest-root command guard lost its method".to_owned()),
        }
        return Ok(());
    }
    match command {
        ControllerCommand::BootstrapPublicCapability {
            peer,
            idempotency_key,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            let result = controller.bootstrap_initial_public_capability(&peer, &idempotency_key);
            match result {
                Ok(issued) => {
                    let _ = reply.send(Ok((issued.id(), *issued.holder_handle())));
                }
                Err(aos_sandbox::public_capability_issuance::InitialPublicCapabilityErrorV1::Rejected) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err(message);
                }
            }
            Ok(())
        }
        ControllerCommand::GetOperation {
            operation_id,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            reply_read_only_controller_result(reply, controller.public_operation(operation_id))
        }
        ControllerCommand::GetAuthorizedOperation {
            peer,
            capability_id,
            capability_handle,
            operation_id,
            protobuf_body,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            reply_read_only_controller_result(
                reply,
                controller.authorized_public_operation(
                    &peer,
                    capability_id,
                    operation_id,
                    &protobuf_body,
                ),
            )
        }
        ControllerCommand::AuthorizePublicRead {
            peer,
            capability_id,
            capability_handle,
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
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            reply_read_only_controller_result(
                reply,
                controller.authorize_public_read(
                    &peer,
                    capability_id,
                    method,
                    resource_kind,
                    operation,
                    selector,
                    &protobuf_body,
                ),
            )
        }
        ControllerCommand::ReadPublicProjection {
            peer,
            capability_id,
            capability_handle,
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
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            reply_read_only_controller_result(
                reply,
                controller.authorized_public_projection_read(
                    &peer,
                    capability_id,
                    method,
                    resource_kind,
                    operation,
                    selector,
                    &protobuf_body,
                    query,
                ),
            )
        }
        ControllerCommand::PlanPublicPolicy {
            peer,
            capability_id,
            capability_handle,
            method,
            protobuf_body,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
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
            capability_handle,
            canonical_request,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
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
                    resume_operator_ownership(controller, ownership, &canonical_request)
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
            capability_handle,
            canonical_request,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            let admission = if controller
                .resolve_public_capability_handle(&peer, capability_id, &capability_handle)
                .is_ok()
            {
                controller.admit_public(&peer, capability_id, &canonical_request)
            } else {
                // Renewal atomically retires its invoking handle. Only the
                // controller's exact committed-renewal proof may replay it.
                controller.replay_committed_public_capability_renewal(
                    &peer,
                    capability_id,
                    &capability_handle,
                    &canonical_request,
                )
            };
            let operation_id = match admission {
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
            let returns_capability_handle = matches!(
                PublicMutationRequestV1::decode(&canonical_request).map(|request| request.method()),
                Ok(PublicApiAuditMethodV1::AttenuateCapability
                    | PublicApiAuditMethodV1::RenewCapability)
            );
            let holder_handle = if returns_capability_handle {
                let Some(record) = projections.first() else {
                    let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                    return Err("capability mutation has no public projection".to_owned());
                };
                let resource = record.resource();
                let id: [u8; 16] = match resource.resource_id().try_into() {
                    Ok(id)
                        if projections.len() == 1
                            && resource.kind() == PublicProjectionKindV1::Capability =>
                    {
                        id
                    }
                    _ => {
                        let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                        return Err("capability mutation has invalid public projection".to_owned());
                    }
                };
                match controller.public_holder_handle(&peer, CapabilityId::from_bytes(id)) {
                    Ok(handle) => Some(handle),
                    Err(error) => {
                        let message = error.to_string();
                        let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                        return Err(message);
                    }
                }
            } else {
                None
            };
            let _ = reply.send(Ok(AdmittedPublicMutationV1 {
                operation,
                projections,
                holder_handle,
            }));
            Ok(())
        }
        ControllerCommand::AdmitPublicAttach {
            peer,
            capability_id,
            capability_handle,
            canonical_request,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            require_holder_handle!(peer, capability_id, capability_handle, reply);
            let result = sessions
                .lock()
                .map_err(|_| ControllerCommandFailure::ControllerUnavailable)
                .and_then(|mut sessions| {
                    let host = sessions
                        .host
                        .as_mut()
                        .ok_or(ControllerCommandFailure::ControllerUnavailable)?;
                    public_attach::admit_public_attach(
                        controller,
                        attach_credentials,
                        attach_plan_signer,
                        node,
                        host,
                        &peer,
                        capability_id,
                        &canonical_request,
                    )
                });
            let _ = reply.send(result);
            Ok(())
        }
        ControllerCommand::ResolvePublicCapabilityTarget {
            peer,
            handle,
            expires_at,
            reply,
        } => {
            if Instant::now() >= expires_at {
                let _ = reply.send(Err(ControllerCommandFailure::DeadlineExceeded));
                return Ok(());
            }
            match controller.resolve_public_capability_target(&peer, &handle) {
                Ok(id) => {
                    let _ = reply.send(Ok(id));
                }
                Err(_) => {
                    let _ = reply.send(Err(ControllerCommandFailure::Rejected));
                }
            }
            Ok(())
        }
    }
}

fn resume_operator_ownership(
    controller: &mut ProductionController,
    ownership: Option<&ControllerOwnershipConfigurationV1>,
    canonical_request: &[u8],
) -> Result<(), String> {
    let envelope = PublicMutationRequestV1::decode(canonical_request)
        .map_err(|error| format!("admitted ownership recovery envelope is invalid: {error}"))?;
    let DormantSandboxRequestKindV1::OperatorRecover(request) = envelope
        .decode_validated_kind()
        .map_err(|error| format!("admitted ownership recovery request is invalid: {error}"))?
    else {
        return Err("admitted ownership recovery has the wrong method".to_owned());
    };
    if request.action.as_known() != Some(OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY) {
        return Ok(());
    }
    let target_bytes: [u8; 16] = request
        .resource_id
        .as_slice()
        .try_into()
        .map_err(|_| "admitted ownership recovery target is invalid".to_owned())?;
    let target = OperationId::from_bytes(target_bytes);
    if controller
        .public_operation(target)
        .map_err(|error| error.to_string())?
        .is_none()
    {
        return Ok(());
    }
    let Some(gate) = controller
        .ownership_gate(target)
        .map_err(|error| error.to_string())?
    else {
        return Ok(());
    };
    let OwnershipGateStatusV1::Pending(plan) = gate else {
        return Ok(());
    };
    let Some(ownership) = ownership else {
        eprintln!("aos-sandboxd: explicit ownership retry is pending protected configuration");
        return Ok(());
    };
    if plan.expected_authority() != ownership.verifier().authority() {
        return Err("ownership retry authority differs from the admitted gate".to_owned());
    }
    let mut client = match ownership.connect() {
        Ok(client) => client,
        Err(aos_sandbox::OwnershipSessionTransportError::Unavailable) => {
            eprintln!("aos-sandboxd: explicit ownership retry could not reach the authority");
            return Ok(());
        }
        Err(error) => return Err(error.to_string()),
    };
    let outcome = controller
        .resume_ownership(
            target,
            &mut client,
            ownership.verifier(),
            &mut sample_ownership_clock,
        )
        .map_err(|error| error.to_string())?;
    if !matches!(
        outcome,
        OwnershipResumeOutcomeV1::Activated | OwnershipResumeOutcomeV1::Replay
    ) {
        eprintln!("aos-sandboxd: explicit ownership retry remains pending: {outcome:?}");
    }
    Ok(())
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
    cold_start: bool,
    guest_root_pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    guest_root_signer: Option<&ControllerBrokerPlanSignerV1>,
) -> Result<CatalogStatus, CycleFailure> {
    let pending_snapshot = {
        let mut sessions = sessions
            .lock()
            .map_err(|_| CycleFailure::Fatal("broker session lock is poisoned".to_owned()))?;
        ensure_controller_broker_sessions(node_id, &mut sessions)?;
        if let Some(reservation) = resume_pending_guest_root(&mut sessions)? {
            let storage = authenticated_storage_inventory(controller, node_id, &mut sessions)?;
            if !controller
                .verify_guest_root_publication_readback(&storage, &reservation)
                .map_err(classify_guest_root_publication)?
            {
                return Err(CycleFailure::Retryable(
                    "Storage guest-root effect lacks fresh physical readback".to_owned(),
                ));
            }
        }
        if cold_start {
            audit_pending_atomic_snapshot_sources(controller, &mut sessions, true)?;
            let pending = controller
                .pending_atomic_snapshot_sources()
                .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
            if pending.len() > 1 {
                return Err(CycleFailure::Fatal(
                    "multiple Storage snapshot sources are pending".to_owned(),
                ));
            }
            pending.first().map(|(operation, _)| *operation)
        } else {
            None
        }
    };
    if let Some(operation) = pending_snapshot {
        controller
            .reconcile_operation_once(operation)
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
        if !controller
            .pending_atomic_snapshot_sources()
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?
            .is_empty()
        {
            return Err(CycleFailure::Retryable(
                "original Storage snapshot source awaits terminal recovery".to_owned(),
            ));
        }
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
            audit_pending_atomic_snapshot_sources(controller, &mut sessions, false)?;
            refresh_catalog(
                controller,
                node_id,
                &mut sessions,
                guest_root_pins,
                guest_root_signer,
            )
        },
    )
}

fn audit_pending_atomic_snapshot_sources(
    controller: &mut ProductionController,
    sessions: &mut ControllerBrokerSessions,
    before_reconciliation: bool,
) -> Result<(), CycleFailure> {
    // Historical group success may recover from a fresh read-only status only
    // when Storage attests the original protected post-head is still current.
    // An absent or incomplete group has no such authority.
    let completed = if before_reconciliation {
        controller
            .completed_atomic_snapshot_source_request_ids()
            .map_err(|error| CycleFailure::Fatal(error.to_string()))?
    } else {
        Vec::new()
    };
    let pending = controller
        .pending_atomic_snapshot_sources()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    if pending.is_empty() && completed.is_empty() {
        return Ok(());
    }
    let storage = sessions.storage.as_mut().ok_or_else(|| {
        CycleFailure::Retryable("protected Storage session is unavailable".to_owned())
    })?;
    for request_id in completed {
        storage
            .retire_atomic_snapshot_archive(request_id)
            .map_err(|error| CycleFailure::Retryable(format!("{error:?}")))?;
    }
    for (_, source) in pending {
        let aos_sandbox::lifecycle::LifecycleAtomicSnapshotSourceRecoveryV1::Pending {
            request_id,
            request_packet,
            predecessor_packet,
            session,
            checkpoint,
        } = source
        else {
            return Err(CycleFailure::Fatal(
                "pending Storage source scan returned a terminal record".to_owned(),
            ));
        };
        let history = storage
            .recover_verified_atomic_snapshot_history(
                request_id,
                request_packet,
                predecessor_packet,
                session,
                checkpoint,
            )
            .map_err(|error| CycleFailure::Retryable(format!("{error:?}")))?;
        if !matches!(
            history,
            crate::recovery::ProtectedVerifiedAtomicStorageHistoryV1::Complete { .. }
                | crate::recovery::ProtectedVerifiedAtomicStorageHistoryV1::GroupCommitted { .. }
        ) {
            return Err(CycleFailure::Retryable(
                "pending Storage source lacks a verified group result".to_owned(),
            ));
        }
        storage
            .archive_verified_atomic_snapshot_history(
                request_id,
                request_packet,
                predecessor_packet,
                session,
                checkpoint,
            )
            .map_err(|error| CycleFailure::Retryable(format!("{error:?}")))?;
        if !before_reconciliation {
            return Err(CycleFailure::Retryable(
                "verified Storage source awaits lifecycle completion".to_owned(),
            ));
        }
    }
    // Reconciliation completes the source before catalog refresh can install
    // a new Storage request and roll this old terminal history forward.
    Ok(())
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
    if sessions.storage_root.requires_reconnect() {
        sessions.storage = None;
        sessions.storage_root = guest_root::ControllerGuestRootExchangeV1::default();
    }
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
    guest_root_pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    guest_root_signer: Option<&ControllerBrokerPlanSignerV1>,
) -> Result<CatalogStatus, CycleFailure> {
    // Mount and destination state participate in the controller-state digest
    // captured by Storage and Network, so acquire them first.
    let (mounts, destinations) = authenticated_mount_inventories(controller, node_id, sessions)?;
    let storage = authenticated_storage_inventory(controller, node_id, sessions)?;
    let storage = publish_guest_roots(
        controller,
        node_id,
        sessions,
        storage,
        guest_root_pins,
        guest_root_signer,
    )?;
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

fn resume_pending_guest_root(
    sessions: &mut ControllerBrokerSessions,
) -> Result<
    Option<aos_sandbox::guest_root_publication::GuestRootPublicationReservationV1>,
    CycleFailure,
> {
    let Some(reservation) = sessions.storage_root.pending_reservation() else {
        return Ok(None);
    };
    let owner = sessions.storage.as_mut().ok_or_else(|| {
        CycleFailure::Retryable("retained Storage session is unavailable".to_owned())
    })?;
    let session = owner
        .guest_root_session()
        .map_err(classify_guest_root_effect)?;
    sessions
        .storage_root
        .resume(session)
        .map_err(classify_guest_root_effect)?
        .ok_or_else(|| {
            CycleFailure::Fatal("guest-root exchange lost retained effect".to_owned())
        })?;
    Ok(Some(reservation))
}

fn publish_guest_roots(
    controller: &mut ProductionController,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
    storage: aos_sandbox::DurableStorageResourceInventorySnapshotV1,
    pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    signer: Option<&ControllerBrokerPlanSignerV1>,
) -> Result<aos_sandbox::DurableStorageResourceInventorySnapshotV1, CycleFailure> {
    let Some(pins) = pins else {
        if storage.inventory().workspaces().is_empty() {
            return Ok(storage);
        }
        return Err(CycleFailure::Retryable(
            "pinned guest-root template credentials are unavailable".to_owned(),
        ));
    };
    let Some(reservation) = controller
        .reserve_guest_root_publication(&storage, NodeId::from_bytes(node_id), pins)
        .map_err(classify_guest_root_publication)?
    else {
        return Ok(storage);
    };
    let signer = signer.ok_or_else(|| {
        CycleFailure::Retryable("Storage guest-root plan signer is unavailable".to_owned())
    })?;
    let now = sample_ownership_clock()
        .map_err(|_| CycleFailure::Retryable("guest-root clock is unavailable".to_owned()))?
        .wall_seconds();
    let (plan, lease, lease_signature) = controller
        .prepare_guest_root_publication_plan(&reservation, NodeId::from_bytes(node_id), now)
        .map_err(classify_guest_root_publication)?
        .into_parts();
    let signed_plan = signer.sign_plan(plan, now).map_err(|_| {
        CycleFailure::Retryable("fresh Storage guest-root plan could not be signed".to_owned())
    })?;
    let owner = sessions.storage.as_mut().ok_or_else(|| {
        CycleFailure::Retryable("retained Storage session is unavailable".to_owned())
    })?;
    let session = owner
        .guest_root_session()
        .map_err(classify_guest_root_effect)?;
    sessions
        .storage_root
        .apply(session, reservation, &signed_plan, lease, lease_signature)
        .map_err(classify_guest_root_effect)?;

    // The response is not a readiness claim. Storage must independently
    // read back its workspace and report the exact physical proof again.
    let observed = authenticated_storage_inventory(controller, node_id, sessions)?;
    if !controller
        .verify_guest_root_publication_readback(&observed, &reservation)
        .map_err(classify_guest_root_publication)?
    {
        return Err(CycleFailure::Retryable(
            "Storage guest-root effect lacks fresh physical readback".to_owned(),
        ));
    }
    if controller
        .reserve_guest_root_publication(&observed, NodeId::from_bytes(node_id), pins)
        .map_err(classify_guest_root_publication)?
        .is_some()
    {
        return Err(CycleFailure::Retryable(
            "another workspace still needs guest-root publication".to_owned(),
        ));
    }
    Ok(observed)
}

fn classify_guest_root_effect(error: EffectFailure) -> CycleFailure {
    match error {
        EffectFailure::Retryable(message) => CycleFailure::Retryable(message),
        EffectFailure::Permanent(message) => CycleFailure::Fatal(message),
    }
}

fn classify_guest_root_publication(
    error: aos_sandbox::guest_root_publication::GuestRootPublicationErrorV1,
) -> CycleFailure {
    match error {
        aos_sandbox::guest_root_publication::GuestRootPublicationErrorV1::Unavailable => {
            CycleFailure::Retryable(error.to_string())
        }
        _ => CycleFailure::Fatal(error.to_string()),
    }
}

fn publish_pending(
    controller: &mut ProductionController,
    pending: aos_sandbox::DurablePendingHostCatalogV1,
    node_id: [u8; 16],
    sessions: &mut ControllerBrokerSessions,
) -> Result<CatalogStatus, CycleFailure> {
    if sessions.host.is_none() {
        let session = connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
            node_id,
        )?;
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
        let session = connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
            node_id,
        )?;
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
        let session = connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            node_id,
        )?;
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
        let session = connect_controller_session(
            crate::ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
            node_id,
        )?;
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
    attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
    attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
) -> Result<ProductionController, ControllerRuntimeError> {
    let (journal, _) = Journal::open_protected_at_for_uid(
        &configuration.state_directory,
        JOURNAL_NAME,
        production_journal_limits(),
        configuration.uid,
    )?;

    controller_from_journal(
        journal,
        node_id,
        sessions,
        configuration.uid,
        attachment_host,
        attachment_mount,
    )
}

fn controller_from_journal(
    mut journal: Journal,
    node_id: [u8; 16],
    sessions: SharedControllerBrokerSessions,
    controller_uid: u32,
    attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
    attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
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
            ProductionEffectExecutor::open(
                sessions,
                controller_uid,
                NodeId::from_bytes(node_id),
                attachment_host,
                attachment_mount,
            )?,
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

fn read_cache_replay_bundle() -> Result<Option<Vec<u8>>, ControllerRuntimeError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
        .ok_or(ControllerRuntimeError::InvalidCacheReplayBundle)?;
    let path = Path::new(&directory).join(CACHE_REPLAY_BUNDLE_CREDENTIAL);
    let descriptor = match open(
        &path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(ControllerRuntimeError::InvalidCacheReplayBundle),
    };
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|_| ControllerRuntimeError::InvalidCacheReplayBundle)?;
    let size = usize::try_from(metadata.len())
        .map_err(|_| ControllerRuntimeError::InvalidCacheReplayBundle)?;
    let current_uid = rustix::process::geteuid().as_raw();
    if !metadata.is_file()
        || (metadata.uid() != 0 && metadata.uid() != current_uid)
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || size == 0
        || size > MAXIMUM_CACHE_REPLAY_BUNDLE_BYTES
    {
        return Err(ControllerRuntimeError::InvalidCacheReplayBundle);
    }
    let mut bytes = vec![0; size];
    file.read_exact(&mut bytes)
        .map_err(|_| ControllerRuntimeError::InvalidCacheReplayBundle)?;
    let mut trailing = [0];
    if file
        .read(&mut trailing)
        .map_err(|_| ControllerRuntimeError::InvalidCacheReplayBundle)?
        != 0
    {
        return Err(ControllerRuntimeError::InvalidCacheReplayBundle);
    }
    Ok(Some(bytes))
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
    publisher_ingress: bool,
}

impl RuntimeConfiguration {
    fn from_process() -> Result<Self, ControllerRuntimeError> {
        let mut arguments = std::env::args();
        let _program = arguments.next();
        let uid = parse_identity(arguments.next(), "controller UID")?;
        let gid = parse_identity(arguments.next(), "controller GID")?;
        let mut public_api = false;
        let mut publisher_ingress = false;
        for argument in arguments {
            match argument.as_str() {
                "--public-api" if !public_api => public_api = true,
                "--publisher-ingress" if !publisher_ingress => publisher_ingress = true,
                _ => {
                    return Err(ControllerRuntimeError::InvalidArguments(
                        "unknown or duplicate activation flag",
                    ));
                }
            }
        }
        if !publisher_ingress && std::env::var_os("LISTEN_FDS").is_some() {
            return Err(ControllerRuntimeError::InvalidArguments(
                "unexpected controller socket activation",
            ));
        }
        Ok(Self {
            uid,
            gid,
            state_directory: PathBuf::from(STATE_DIRECTORY),
            diagnostic_socket: PathBuf::from(DIAGNOSTIC_SOCKET),
            public_api,
            publisher_ingress,
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
    broker_plan_signer: Option<ControllerBrokerPlanSignerV1>,
    attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
    attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
    pending_attachment_slot_attempt:
        Option<aos_sandbox::destination_slot_effect::DurableCurrentDestinationSlotAttemptV1>,
    pending_attachment_catalog_query: Option<attachment_physical::PendingAttachmentCatalogQueryV1>,
    pending_attachment_mount_attempt:
        Option<aos_sandbox::attachment_mount::DurableCurrentAttachmentMountAttemptV1>,
    pending_attachment_source_attempt:
        Option<aos_sandbox::attachment_source::DurableCurrentAttachmentSourceDispatchV1>,
    pending_attachment_source_consume:
        Option<aos_sandbox::attachment_mount::CompletedCurrentAttachmentMountAttemptV1>,
    source_domains: ProtectedSourceDomainJournalOwnerV1,
    cache_inventory: Option<CacheResidencyProtectedOwnerV1>,
    cache_physical: Option<DormantCacheOwnerV1>,
    cache_physical_limits: Option<CacheOwnerLimitsV1>,
    pending_cache_pin: Option<cache_pin::PendingControllerCachePinV1>,
    pending_cache_unpin: Option<cache_unpin::PendingControllerCacheUnpinV1>,
    controller_uid: u32,
    transfer_inventory: Option<aos_sandbox::multi_node::ProtectedMultiNodeAuthorityOwnerV1>,
    node: NodeId,
    process_start: Option<([u8; 16], u64)>,
    pending_source_commit: Option<PendingSourceCommit>,
    pending_atomic_snapshot: Option<storage_snapshot::PendingAtomicSnapshotV1>,
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
        attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
        attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
    ) -> Result<Self, ControllerRuntimeError> {
        let broker_plan_signer = ControllerBrokerPlanSignerV1::from_process_credentials_optional()
            .map_err(|_| ControllerRuntimeError::InvalidBrokerPlanCredential)?;
        validate_process_cache_readback_credentials_v1(
            broker_plan_signer
                .as_ref()
                .map(ControllerBrokerPlanSignerV1::verifying_key_bytes),
        )
        .map_err(|_| ControllerRuntimeError::InvalidCacheReadbackCredential)?;
        let (mut source_domains, _) =
            ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(controller_uid)?;
        aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(&mut source_domains)?
            .replay()?;

        Ok(Self {
            sessions,
            broker_plan_signer,
            attachment_host,
            attachment_mount,
            pending_attachment_slot_attempt: None,
            pending_attachment_catalog_query: None,
            pending_attachment_mount_attempt: None,
            pending_attachment_source_attempt: None,
            pending_attachment_source_consume: None,
            source_domains,
            cache_inventory: None,
            cache_physical: None,
            cache_physical_limits: None,
            pending_cache_pin: None,
            pending_cache_unpin: None,
            controller_uid,
            transfer_inventory: None,
            node,
            process_start: current_boot_and_boottime(),
            pending_source_commit: None,
            pending_atomic_snapshot: None,
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

    fn ownership_recovery_receipt(
        recovery_operation: OperationId,
        context: &PublicMutationEffectV1,
        journal: &Journal,
    ) -> Result<Option<EffectReceipt>, EffectFailure> {
        let DormantSandboxRequestKindV1::OperatorRecover(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Err(EffectFailure::Permanent(
                "operator recovery effect has the wrong request method".to_owned(),
            ));
        };
        if request.action.as_known() != Some(OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY)
        {
            return Ok(None);
        }
        let target_bytes: [u8; 16] = request.resource_id.as_slice().try_into().map_err(|_| {
            EffectFailure::Permanent("operator recovery target is invalid".to_owned())
        })?;
        let target = OperationId::from_bytes(target_bytes);
        if public_operation_resource_from_journal_v1(journal, target)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .is_none()
        {
            return Ok(None);
        }
        let Some(publication_digest) =
            activated_ownership_gate_digest_from_journal_v1(journal, target)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        else {
            return Ok(None);
        };
        let receipt = [
            b"AOSORE01".as_slice(),
            recovery_operation.as_bytes(),
            target.as_bytes(),
            publication_digest.as_bytes(),
        ]
        .concat();
        EffectReceipt::new(receipt)
            .map(Some)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))
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
                aos_sandbox::lifecycle::LifecycleIntentV1::Resume {
                    source: aos_sandbox::lifecycle::LifecycleResumeSourceV1::Memory { fence },
                    ..
                } => {
                    let observation = owner
                        .current_suspend_observation_for_fence(
                            current.operation().project(),
                            *fence,
                        )
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "protected suspension observation is absent".to_owned(),
                            )
                        })?;
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
                    let runtime = {
                        let mut sessions = self.sessions.lock().map_err(|_| {
                            EffectFailure::Retryable("broker session lock is poisoned".to_owned())
                        })?;
                        let host = sessions.host.as_mut().ok_or_else(missing_broker_session)?;
                        host.bootstrap_runtime_inventory(&challenge)
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    };
                    let liveness = owner
                        .bind_authenticated_runtime_liveness(&current_key, &runtime)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    LifecycleSuspensionPlanV1::planned_memory_resume_steps(
                        &current,
                        &observation,
                        &liveness,
                    )
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
                aos_sandbox::lifecycle::LifecycleMethodV1::Resume => {
                    let fence = match current.operation().intent() {
                        aos_sandbox::lifecycle::LifecycleIntentV1::Resume {
                            source:
                                aos_sandbox::lifecycle::LifecycleResumeSourceV1::Memory { fence },
                            ..
                        } => *fence,
                        _ => return Ok(false),
                    };
                    let observation = owner
                        .current_suspend_observation_for_fence(current.operation().project(), fence)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                        .ok_or_else(|| {
                            EffectFailure::Permanent(
                                "protected suspension observation is absent".to_owned(),
                            )
                        })?;
                    let runtime = {
                        let mut sessions = self.sessions.lock().map_err(|_| {
                            EffectFailure::Retryable("broker session lock is poisoned".to_owned())
                        })?;
                        let host = sessions.host.as_mut().ok_or_else(missing_broker_session)?;
                        host.bootstrap_runtime_inventory(&challenge)
                            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                    };
                    let liveness = owner
                        .bind_authenticated_runtime_liveness(&current_key, &runtime)
                        .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
                    let effect =
                        LifecycleSuspensionPlanV1::resume_memory(&current, &observation, &liveness)
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
                (aos_sandbox::lifecycle::LifecycleMethodV1::Resume, 0, 9) => {
                    RuntimeAction::RUNTIME_ACTION_THAW
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

    fn ensure_cache_inventory_owner(&mut self) -> Result<(), EffectFailure> {
        let (mut cache_source, _) =
            CacheReplayControllerBootstrapOwnerV1::open_fixed_protected_for_uid(
                self.controller_uid,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        if self.cache_inventory.is_none() {
            let owner = match CacheResidencyProtectedOwnerV1::open_fixed_protected_for_uid(
                self.controller_uid,
            ) {
                Ok((owner, _)) => owner,
                Err(open_error) => {
                    let first = cache_source.partitions().next().ok_or_else(|| {
                        EffectFailure::Permanent(
                            "controller Cache bootstrap source has no partitions".to_owned(),
                        )
                    })?;
                    let (owner, _) = cache_source
                        .bootstrap_fixed_cache(first)
                        .map_err(|error| {
                            EffectFailure::Permanent(format!(
                                "protected Cache replay failed: {open_error}; clean bootstrap failed: {error}"
                            ))
                        })?;
                    owner
                }
            };
            self.cache_inventory = Some(owner);
        }
        let cache = self.cache_inventory.as_mut().ok_or_else(|| {
            EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
        })?;
        cache_source
            .reconcile_fixed_cache(cache)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        Ok(())
    }

    fn ensure_cache_physical_owner(&mut self) -> Result<(), EffectFailure> {
        self.ensure_cache_inventory_owner()?;
        let quotas = self
            .cache_inventory
            .as_mut()
            .ok_or_else(|| {
                EffectFailure::Permanent("protected Cache inventory is unavailable".to_owned())
            })?
            .reconstructed_node_quotas()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        if quotas
            .iter()
            .any(|quota| quota.partition.node().as_bytes() != self.node.as_bytes())
        {
            return Err(EffectFailure::Permanent(
                "protected Cache partition belongs to another controller node".to_owned(),
            ));
        }
        let limits = CacheOwnerLimitsV1::from_node_quotas(CACHE_OWNER_MEMORY_BYTES, quotas)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        if self.cache_physical_limits == Some(limits) && self.cache_physical.is_some() {
            return Ok(());
        }

        // A changed protected partition set changes the owner-wide envelope.
        // Release the old lock before reopening and validating that manifest.
        self.cache_physical = None;
        self.cache_physical_limits = None;
        let physical = DormantCacheOwnerV1::open_fixed(limits)
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
        self.cache_physical = Some(physical);
        self.cache_physical_limits = Some(limits);
        Ok(())
    }

    fn ensure_lifecycle_inventory_owners(&mut self) -> Result<(), EffectFailure> {
        self.ensure_cache_inventory_owner()?;

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

    fn advance_terminal_lifecycle_publication(
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
            let is_memory_resume = matches!(
                current.operation().intent(),
                aos_sandbox::lifecycle::LifecycleIntentV1::Resume {
                    source: aos_sandbox::lifecycle::LifecycleResumeSourceV1::Memory { .. },
                    ..
                }
            );
            let method = current.operation().intent().method();
            if current.operation().terminal_result()
                != Some(aos_sandbox::lifecycle::LifecycleTerminalResultV1::Succeeded)
                || (method != aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
                    && !is_memory_resume)
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
            let observation_is_current = method
                == aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
                && owner
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
            // Another lifecycle bootstrap must not roll the Storage session
            // while an exact grouped request still owns its signed history.
            if self.pending_atomic_snapshot.is_some() {
                return Err(EffectFailure::Retryable(
                    "Storage session is reserved for an atomic snapshot".to_owned(),
                ));
            }
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

        let is_memory_resume = {
            let owner = aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(
                &mut self.source_domains,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            let current = owner
                .current_operation(&current_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .ok_or_else(|| {
                    EffectFailure::Permanent(
                        "terminal lifecycle operation is absent from protected custody".to_owned(),
                    )
                })?;
            matches!(
                current.operation().intent(),
                aos_sandbox::lifecycle::LifecycleIntentV1::Resume {
                    source: aos_sandbox::lifecycle::LifecycleResumeSourceV1::Memory { .. },
                    ..
                }
            )
        };
        if is_memory_resume {
            return Ok(false);
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
                    | aos_sandbox::lifecycle::LifecycleMethodV1::Resume
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
        if matches!(
            current.operation().intent().method(),
            aos_sandbox::lifecycle::LifecycleMethodV1::SuspendMemory
                | aos_sandbox::lifecycle::LifecycleMethodV1::Resume
        ) {
            let boot_inventory_lineage =
                lifecycle_plan_resource_id(operation_id, b"boot-inventory-lineage");
            let boot_inventory_key = lifecycle_protected_key_v1(
                LifecycleProtectedRecordKindV1::Auxiliary,
                current.operation().project(),
                boot_inventory_lineage,
                operation_id,
            )
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if owner
                .current_boot_inventory(&boot_inventory_key)
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?
                .is_none()
            {
                return Ok(None);
            }
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
    ResourceId::from_bytes(nonzero_lifecycle_id_from_digest(digest))
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
    ResourceId::from_bytes(nonzero_lifecycle_id_from_digest(digest))
}

fn lifecycle_plan_transaction_id(operation: OperationId, purpose: &[u8]) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.plan-transaction.v1\0")
        .chain_update(operation.as_bytes())
        .chain_update((purpose.len() as u64).to_be_bytes())
        .chain_update(purpose)
        .finalize()
        .into();
    nonzero_lifecycle_id_from_digest(digest)
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
    nonzero_lifecycle_id_from_digest(digest)
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
    nonzero_lifecycle_id_from_digest(digest)
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
    nonzero_lifecycle_id_from_digest(digest)
}

fn nonzero_lifecycle_id_from_digest(digest: [u8; 32]) -> [u8; 16] {
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    identity
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

fn require_execution_create_handoff_ready(
    method: Option<aos_sandbox::controller_query::PublicOperationMethodV1>,
) -> Result<(), EffectFailure> {
    if method == Some(aos_sandbox::controller_query::PublicOperationMethodV1::CreateExecution) {
        // Generic lifecycle settlement has no authenticated Host execution
        // result or physical output backing and cannot finish Create.
        return Err(EffectFailure::Retryable(
            "execution Create awaits protected cross-owner effect handoff".to_owned(),
        ));
    }
    Ok(())
}

impl SingleNodeEffectExecutor for ProductionEffectExecutor {
    fn prepare_guardian_plan(
        &mut self,
        _operation_id: OperationId,
        _step: u32,
        request: &GuardianPlanRequestV1,
    ) -> Option<SignedBrokerPlan> {
        let signer = self.broker_plan_signer.as_ref()?;
        let now_seconds = rustix::time::clock_gettime(rustix::time::ClockId::Realtime).tv_sec;
        let plan = request.plan_at(now_seconds).ok()?;
        signer.sign_plan(plan, now_seconds).ok()
    }

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
        require_execution_create_handoff_ready(plan.public_mutation_method())?;
        if let Some(observation) = self.recover_pending_source_commit(operation_id)? {
            return Ok(observation);
        }
        let context = self.public_mutation_context(plan)?;
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox::controller_query::PublicOperationMethodV1::ControlExecution
                    | aos_sandbox::controller_query::PublicOperationMethodV1::CancelExecution
            )
        ) {
            let intent =
                execution::ControllerExecutionIntentV1::from_request(operation_id, &context)?;
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            let host = sessions.host.as_mut().ok_or_else(|| {
                EffectFailure::Retryable("Host session is unavailable".to_owned())
            })?;
            let authorization = host
                .needs_fresh_execution_authorization()
                .then(|| {
                    intent.prepare_authorization(
                        execution::ExecutionAuthorizationKindV1::Query,
                        context.project(),
                        self.node,
                        journal,
                        self.broker_plan_signer.as_ref(),
                    )
                })
                .transpose()?;
            let observation = host.query_execution(&intent, authorization.as_ref())?;
            drop(sessions);
            return match observation {
                execution::ControllerExecutionObservationV1::Absent => {
                    Ok(EffectObservation::Absent)
                }
                execution::ControllerExecutionObservationV1::Applied(completion) => {
                    intent.commit_control_projection(context.project(), journal, &completion)?;
                    Ok(EffectObservation::Applied(completion.receipt))
                }
            };
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox::controller_query::PublicOperationMethodV1::OperatorRecover)
        {
            return Self::ownership_recovery_receipt(operation_id, &context, journal).map(
                |receipt| receipt.map_or(EffectObservation::Absent, EffectObservation::Applied),
            );
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox::controller_query::PublicOperationMethodV1::AttachView
                    | aos_sandbox::controller_query::PublicOperationMethodV1::ReplaceAttachment
                    | aos_sandbox::controller_query::PublicOperationMethodV1::DetachView
            )
        ) {
            // Generic lifecycle receipts do not prove an attachment or Mount effect.
            return Ok(EffectObservation::Absent);
        }
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
        if let DormantSandboxRequestKindV1::ViewCreate(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        {
            return view_mutations::observe_create_view(operation_id, &context, &request, journal);
        }
        if let DormantSandboxRequestKindV1::ViewRelease(request) = context
            .validated_request()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
        {
            return view_mutations::observe_release_view(operation_id, &context, &request, journal);
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
        require_execution_create_handoff_ready(plan.public_mutation_method())?;
        if let Some(observation) = self.recover_pending_source_commit(operation_id)? {
            return match observation {
                EffectObservation::Applied(receipt) => Ok(receipt),
                EffectObservation::Absent => Err(EffectFailure::Retryable(
                    "protected source commit recovery is incomplete".to_owned(),
                )),
            };
        }
        if self.pending_cache_unpin.is_some() {
            self.ensure_cache_physical_owner()?;
            self.recover_pending_cache_unpin(operation_id)?;
        }
        if self.pending_cache_pin.is_some() {
            self.ensure_cache_physical_owner()?;
            self.recover_pending_cache_pin(operation_id)?;
        }
        let context = self.public_mutation_context(plan)?;
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox::controller_query::PublicOperationMethodV1::ControlExecution
                    | aos_sandbox::controller_query::PublicOperationMethodV1::CancelExecution
            )
        ) {
            let intent =
                execution::ControllerExecutionIntentV1::from_request(operation_id, &context)?;
            let mut sessions = self.sessions.lock().map_err(|_| {
                EffectFailure::Retryable("broker session lock is poisoned".to_owned())
            })?;
            let host = sessions.host.as_mut().ok_or_else(|| {
                EffectFailure::Retryable("Host session is unavailable".to_owned())
            })?;
            let authorization = host
                .needs_fresh_execution_authorization()
                .then(|| {
                    intent.prepare_authorization(
                        execution::ExecutionAuthorizationKindV1::Apply,
                        context.project(),
                        self.node,
                        journal,
                        self.broker_plan_signer.as_ref(),
                    )
                })
                .transpose()?;
            let completion = host.apply_execution(&intent, authorization.as_ref())?;
            drop(sessions);
            intent.commit_control_projection(context.project(), journal, &completion)?;
            return Ok(completion.receipt);
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox::controller_query::PublicOperationMethodV1::OperatorRecover)
        {
            return Self::ownership_recovery_receipt(operation_id, &context, journal)?.ok_or_else(
                || {
                    EffectFailure::Retryable(
                        "operator recovery is awaiting explicit ownership activation".to_owned(),
                    )
                },
            );
        }
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
        if let DormantSandboxRequestKindV1::ViewCreate(create) = &request {
            return view_mutations::apply_create_view(operation_id, &context, create, journal);
        }
        if let DormantSandboxRequestKindV1::ViewRelease(release) = &request {
            return view_mutations::apply_release_view(operation_id, &context, release, journal);
        }
        if matches!(
            &request,
            DormantSandboxRequestKindV1::ViewAttach(_)
                | DormantSandboxRequestKindV1::ViewReplace(_)
                | DormantSandboxRequestKindV1::ViewDetach(_)
        ) {
            let (sandbox, slot, attachment) = attachment_target::admitted_attachment(
                journal,
                operation_id,
                context.project(),
                &request,
            )?;
            if attachment_physical::drain_pending_before_slot(self, journal)? {
                return Err(EffectFailure::Retryable(
                    "fresh authenticated Mount inventory is pending".to_owned(),
                ));
            }
            attachment_slot_effect::advance(
                self,
                operation_id,
                &context,
                &request,
                sandbox,
                slot,
                journal,
            )?;
            if let DormantSandboxRequestKindV1::ViewAttach(attach) = &request {
                attachment_desired::advance_immutable_attach(
                    self,
                    operation_id,
                    &context,
                    attach,
                    &attachment,
                    sandbox,
                    slot,
                    journal,
                )?;
            } else {
                attachment_desired::advance_existing(
                    self,
                    operation_id,
                    &context,
                    &request,
                    &attachment,
                    sandbox,
                    slot,
                    journal,
                )?;
            }
            let attachment_id: [u8; 16] =
                attachment
                    .attachment_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| {
                        EffectFailure::Permanent(
                            "admitted attachment identity is invalid".to_owned(),
                        )
                    })?;
            let verified = attachment_physical::observe(
                self,
                operation_id,
                AttachmentId::from_bytes(attachment_id),
                sandbox,
                journal,
            )?;
            return verified.receipt(operation_id);
        }
        let cache_consumer = if matches!(
            &request,
            DormantSandboxRequestKindV1::CachePin(_) | DormantSandboxRequestKindV1::CacheUnpin(_)
        ) {
            Some(
                aos_sandbox::production_operation_compiler::recheck_cache_consumer_projection_v1(
                    journal,
                    context.project(),
                    &request,
                )
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?,
            )
        } else {
            None
        };
        if matches!(&request, DormantSandboxRequestKindV1::CachePin(_)) {
            let consumer = cache_consumer.as_ref().ok_or_else(|| {
                EffectFailure::Permanent("cache pin consumer is unavailable".to_owned())
            })?;
            return self.apply_public_cache_pin(operation_id, consumer, journal, &request);
        }
        if matches!(&request, DormantSandboxRequestKindV1::CacheUnpin(_)) {
            let consumer = cache_consumer.as_ref().ok_or_else(|| {
                EffectFailure::Permanent("cache unpin consumer is unavailable".to_owned())
            })?;
            return self.apply_public_cache_unpin(operation_id, consumer, journal, &request);
        }
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
            if self.advance_terminal_lifecycle_publication(operation_id, journal)? {
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
            if self.advance_storage_lifecycle_effect(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_lifecycle_semantic_commit(operation_id, journal)? {
                return Err(EffectFailure::Retryable(
                    CONTROLLER_ORCHESTRATION_PENDING.to_owned(),
                ));
            }
            if self.advance_terminal_lifecycle_publication(operation_id, journal)? {
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
        if method == BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            && self.pending_atomic_snapshot.is_some()
        {
            return Err(EffectFailure::Retryable(
                "Storage session is reserved for an atomic snapshot".to_owned(),
            ));
        }
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
    async fn bootstrap_public_capability(
        &self,
        context: &RequestContext,
        idempotency_key: &[u8],
    ) -> Result<(CapabilityId, [u8; 32]), ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "capability bootstrap is unavailable on the diagnostic endpoint",
            "capability bootstrap requires registered TLS peer evidence",
        )?;
        if !(16..=128).contains(&idempotency_key.len()) {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "capability bootstrap idempotency key must contain 16..=128 bytes",
            ));
        }
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::BootstrapPublicCapability {
                peer: peer.clone(),
                idempotency_key: idempotency_key.to_vec(),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "capability bootstrap timed out").await?;
        match result {
            Ok(issued) => {
                peer.recheck().map_err(|_| {
                    ConnectError::new(
                        ErrorCode::PermissionDenied,
                        "capability bootstrap peer is no longer current",
                    )
                })?;
                Ok(issued)
            }
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "capability bootstrap expired",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "capability bootstrap rejected",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "capability bootstrap request is invalid",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "capability bootstrap authority is unavailable",
            )),
        }
    }

    fn registered_public_peer<'a>(
        &self,
        context: &'a RequestContext,
        diagnostic_message: &'static str,
        unauthenticated_message: &'static str,
    ) -> Result<&'a aos_sandbox::public_api_session::PublicApiPeer, ConnectError> {
        if !matches!(self.endpoint, ControllerEndpoint::RegisteredPublic) {
            return Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                diagnostic_message,
            ));
        }
        context
            .extensions()
            .get::<aos_sandbox::public_api_session::PublicApiPeer>()
            .ok_or_else(|| ConnectError::new(ErrorCode::Unauthenticated, unauthenticated_message))
    }

    async fn resolve_public_capability_target(
        &self,
        context: &RequestContext,
        handle: &[u8],
    ) -> Result<CapabilityId, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "capability inspection is unavailable on the diagnostic endpoint",
            "capability inspection requires registered TLS peer evidence",
        )?;
        let handle: [u8; 32] = handle.try_into().map_err(|_| {
            ConnectError::new(
                ErrorCode::InvalidArgument,
                "capability handle must contain exactly 32 bytes",
            )
        })?;
        if handle == [0; 32] {
            return Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "capability handle must be nonzero",
            ));
        }

        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::ResolvePublicCapabilityTarget {
                peer: peer.clone(),
                handle,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "capability handle lookup timed out").await?;
        match result {
            Ok(id) => Ok(id),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "capability handle lookup expired",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "capability handle was rejected",
            )),
            Err(_) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "capability handle lookup is unavailable",
            )),
        }
    }

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
        let peer = self.registered_public_peer(
            context,
            "public resource reads are unavailable on the diagnostic endpoint",
            "public resource read requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::ReadPublicProjection {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
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
        let result =
            await_public_controller_reply(response, "controller public resource read timed out")
                .await?;

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
        let peer = self.registered_public_peer(
            context,
            "public read authorization is unavailable on the diagnostic endpoint",
            "public read requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AuthorizePublicRead {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                method,
                resource_kind,
                operation,
                selector,
                protobuf_body: protobuf_body.to_vec(),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = await_public_controller_reply(
            response,
            "controller public-read authorization timed out",
        )
        .await?;

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
        let peer = self.registered_public_peer(
            context,
            "public policy planning is unavailable on the diagnostic endpoint",
            "public policy planning requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::PlanPublicPolicy {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                method,
                protobuf_body: protobuf_body.to_vec(),
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "controller public policy planning timed out")
                .await?;

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
        let peer = self.registered_public_peer(
            context,
            "operator recovery is unavailable on the diagnostic endpoint",
            "operator recovery requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AdmitPublicOperatorRecovery {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                canonical_request,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = await_public_controller_reply(
            response,
            "controller operator-recovery admission timed out",
        )
        .await?;

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
        let peer = self.registered_public_peer(
            context,
            "public mutations are unavailable on the diagnostic endpoint",
            "public mutation requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AdmitPublicMutation {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                canonical_request,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result = await_public_controller_reply(
            response,
            "controller public mutation admission timed out",
        )
        .await?;

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

    async fn admit_public_attach(
        &self,
        context: &RequestContext,
        canonical_request: Vec<u8>,
    ) -> Result<AdmittedPublicAttachV1, ConnectError> {
        let peer = self.registered_public_peer(
            context,
            "public attachment is unavailable on the diagnostic endpoint",
            "public attachment requires registered TLS peer evidence",
        )?;
        let (reply, response) = tokio::sync::oneshot::channel();
        self.commands
            .try_send(ControllerCommand::AdmitPublicAttach {
                peer: peer.clone(),
                capability_id: public_capability_id(context)?,
                capability_handle: public_capability_handle(context)?,
                canonical_request,
                expires_at: Instant::now() + CONTROLLER_COMMAND_TIMEOUT,
                reply,
            })
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "controller attachment admission timed out")
                .await?;

        match result {
            Ok(admitted) => Ok(admitted),
            Err(ControllerCommandFailure::DeadlineExceeded) => Err(ConnectError::new(
                ErrorCode::DeadlineExceeded,
                "controller attachment admission expired",
            )),
            Err(ControllerCommandFailure::InvalidRequest) => Err(ConnectError::new(
                ErrorCode::InvalidArgument,
                "public attachment request is invalid",
            )),
            Err(ControllerCommandFailure::Rejected) => Err(ConnectError::new(
                ErrorCode::PermissionDenied,
                "public attachment was rejected",
            )),
            Err(ControllerCommandFailure::ControllerUnavailable) => Err(ConnectError::new(
                ErrorCode::Unavailable,
                "authenticated Host attachment route is unavailable",
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
                    capability_handle: public_capability_handle(context)?,
                    operation_id,
                    protobuf_body: protobuf_body.to_vec(),
                    expires_at,
                    reply,
                }
            }
        };
        self.commands
            .try_send(command)
            .map_err(controller_command_send_error)?;
        let result =
            await_public_controller_reply(response, "controller operation lookup timed out")
                .await?;
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

async fn await_public_controller_reply<T>(
    response: tokio::sync::oneshot::Receiver<ControllerCommandResponse<T>>,
    timeout_message: &'static str,
) -> Result<ControllerCommandResponse<T>, ConnectError> {
    tokio::time::timeout(CONTROLLER_COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| ConnectError::new(ErrorCode::DeadlineExceeded, timeout_message))?
        .map_err(|_| {
            ConnectError::new(
                ErrorCode::Unavailable,
                "controller worker ended before replying",
            )
        })
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

fn public_capability_handle(context: &RequestContext) -> Result<[u8; 32], ConnectError> {
    let mut values = context
        .headers()
        .get_all(PUBLIC_CAPABILITY_HANDLE_HEADER)
        .iter();
    let value = values.next().ok_or_else(|| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public request requires a capability handle",
        )
    })?;
    if values.next().is_some() {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public request requires exactly one capability handle",
        ));
    }
    let value = value.to_str().map_err(|_| {
        ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability handle is not valid text",
        )
    })?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability handle is not canonical",
        ));
    }
    let mut handle = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        };
        handle[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    if handle == [0; 32] {
        return Err(ConnectError::new(
            ErrorCode::Unauthenticated,
            "public capability handle must be nonzero",
        ));
    }
    Ok(handle)
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
    /// The optional cache Replay credential is unsafe or malformed.
    #[error("protected controller cache Replay bundle is invalid")]
    InvalidCacheReplayBundle,
    /// The optional Cache readback seed and role pin are unsafe or inconsistent.
    #[error("protected Controller Cache readback credentials are invalid")]
    InvalidCacheReadbackCredential,
    /// Protected cache Replay source import failed.
    #[error("protected controller cache Replay source failed: {0}")]
    CacheReplaySource(aos_sandbox::cache_residency::CacheReplayControllerBootstrapErrorV1),
    /// The optional protected broker-plan signing credential is unsafe or malformed.
    #[error("protected controller broker-plan signing credential is invalid")]
    InvalidBrokerPlanCredential,
    /// The optional ownership credential set is partial, unsafe, or inconsistent.
    #[error("protected controller ownership credentials are invalid")]
    InvalidOwnershipCredential,
    /// The optional dedicated OpenSSH attach credential set is invalid.
    #[error("protected controller OpenSSH attach credentials are invalid")]
    InvalidAttachCredential,
    /// The optional guest-root template pin set is partial or malformed.
    #[error("protected controller guest-root template credentials are invalid")]
    InvalidGuestRootCredential,
    /// The protected publisher scope or exact listener activation is invalid.
    #[error("controller publisher ingress failed: {0}")]
    PublisherIngress(String),
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

    #[test]
    fn lifecycle_digest_id_uses_a_nonzero_prefix() {
        let mut digest = [0; 32];
        digest[31] = 7;
        let mut expected = [0; 16];
        expected[15] = 1;
        assert_eq!(nonzero_lifecycle_id_from_digest(digest), expected);

        digest[0] = 9;
        let mut expected = [0; 16];
        expected[0] = 9;
        assert_eq!(nonzero_lifecycle_id_from_digest(digest), expected);
    }

    #[test]
    fn create_execution_cannot_settle_through_generic_lifecycle() {
        use aos_sandbox::controller_query::PublicOperationMethodV1;

        assert!(matches!(
            require_execution_create_handoff_ready(Some(PublicOperationMethodV1::CreateExecution)),
            Err(EffectFailure::Retryable(message))
                if message == "execution Create awaits protected cross-owner effect handoff"
        ));
        assert!(
            require_execution_create_handoff_ready(Some(PublicOperationMethodV1::StartSandbox))
                .is_ok()
        );
    }

    fn diagnostic_configuration(directory: &tempfile::TempDir) -> RuntimeConfiguration {
        RuntimeConfiguration {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            state_directory: directory.path().join("state"),
            diagnostic_socket: directory.path().join("diagnostics.sock"),
            public_api: false,
            publisher_ingress: false,
        }
    }

    #[tokio::test]
    async fn first_capability_bootstrap_requires_registered_public_peer() {
        let (commands, receiver) = mpsc::sync_channel(1);
        let diagnostic = CapabilityService {
            capabilities: Arc::new(Mutex::new(CapabilityState::starting([7; 16]))),
            commands: commands.clone(),
            endpoint: ControllerEndpoint::RootDiagnostic,
        };
        let context = RequestContext::new(Default::default());
        let error = diagnostic
            .bootstrap_public_capability(&context, &[1; 16])
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::PermissionDenied);

        let public = CapabilityService {
            endpoint: ControllerEndpoint::RegisteredPublic,
            ..diagnostic
        };
        let error = public
            .bootstrap_public_capability(&context, &[1; 16])
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unauthenticated);
        assert!(receiver.try_recv().is_err());
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
                ControllerCommand::BootstrapPublicCapability { .. }
                | ControllerCommand::PlanPublicPolicy { .. }
                | ControllerCommand::AdmitPublicOperatorRecovery { .. }
                | ControllerCommand::AdmitPublicMutation { .. }
                | ControllerCommand::AdmitPublicAttach { .. }
                | ControllerCommand::ResolvePublicCapabilityTarget { .. } => {
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

    #[test]
    fn public_handle_header_requires_one_canonical_nonzero_secret() {
        let missing = public_capability_handle(&RequestContext::default()).unwrap_err();
        assert_eq!(missing.code, ErrorCode::Unauthenticated);

        for invalid in [
            "00".repeat(32),
            "ab".repeat(31),
            "AB".repeat(32),
            "gg".repeat(32),
        ] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(PUBLIC_CAPABILITY_HANDLE_HEADER, invalid.parse().unwrap());
            let error = public_capability_handle(&RequestContext::new(headers)).unwrap_err();
            assert_eq!(error.code, ErrorCode::Unauthenticated);
        }

        let encoded = "ab".repeat(32);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(PUBLIC_CAPABILITY_HANDLE_HEADER, encoded.parse().unwrap());
        assert_eq!(
            public_capability_handle(&RequestContext::new(headers)).unwrap(),
            [0xab; 32]
        );

        let mut headers = axum::http::HeaderMap::new();
        headers.append(PUBLIC_CAPABILITY_HANDLE_HEADER, encoded.parse().unwrap());
        headers.append(
            PUBLIC_CAPABILITY_HANDLE_HEADER,
            "cd".repeat(32).parse().unwrap(),
        );
        let duplicate = public_capability_handle(&RequestContext::new(headers)).unwrap_err();
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

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification_mount_inventory;
