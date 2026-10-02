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
//!
//! Selected original startup uses one partial parent/worker custody graph;
//! the empty ordinary route keeps its original consuming locals. Both borrow
//! the sole reconciliation loop. The private slots and parent-frame server
//! pins belong here with the installed startup recipe, its terminal ordering
//! and worker/server handoff, rather than a generic owner framework. This does
//! not retain callee-local failed constructors, task populations or provider
//! prefixes, nor establish funding, drain or readiness for those missing paths.

use std::io::IoSlice;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
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
    OperationId, ProjectId, RawClockProvenance, RawPairedClockSample, ResourceId,
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

use crate::controller_attach_credentials::ControllerAttachCredentialsV1;
use crate::controller_cache_readback_credential::validate_process_cache_readback_credentials_v1;
use crate::controller_guest_root_credentials::load_guest_root_template_pins_optional;
use crate::controller_hold_credential::{
    validate_process_controller_hold_credentials_v1, with_process_controller_hold_signer_v1,
};
use crate::controller_ownership::{ControllerOwnershipConfigurationV1, sample_ownership_clock};
use crate::controller_plan_signer::ControllerBrokerPlanSignerV1;
use crate::controller_publication::{ControllerHostPublication, ControllerHostPublicationError};
use crate::fixed_role_credential::{
    CredentialOwnerPolicyV1, read_optional_bounded_role_credential_v1,
};
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
use aos_sandbox::hierarchy::controller_genesis_input::{
    ControllerSourceGenesisInputErrorV1, ProvisionedControllerSourceGenesisInputV1,
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
use aos_sandbox::production_operation_compiler::{
    ControllerNixStartRecipeSelectorV2, NixStartAdmissionErrorV2, ProductionOperationCompilerV1,
};
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
#[allow(
    dead_code,
    reason = "PRE-ROOT client awaits genuine later kernel-request/Ready-worker ingress"
)]
mod consumer_read;
pub(crate) mod execution;
pub(crate) mod execution_argument_observe;
pub(crate) mod execution_capture_candidate;
mod execution_output_effect;
pub(crate) mod execution_output_reserve;
#[allow(
    dead_code,
    reason = "Storage output reserve is signed but awaits same-session Host proof and closed dispatch"
)]
mod execution_output_storage_reserve;
mod guest_root;
mod git_read_inspection;
#[allow(
    dead_code,
    reason = "Local Nix input custody awaits genuine configured worker and independently floored session ingress"
)]
mod nix_inputs;
mod original_attach;
mod operator_repair;
mod public_api;
mod public_attach;
mod public_hierarchy;
mod public_services;
mod public_watch;
mod publisher_credential;
mod publisher_ingress;
mod publisher_policy_source;
mod cache_usage;
mod cache_mutation;
mod storage_snapshot;
mod source_successor_issuance;
mod view_mutations;

const STATE_DIRECTORY: &str = "/var/lib/aos/sandboxd";
const JOURNAL_NAME: &str = "controller.journal";
const DIAGNOSTIC_SOCKET: &str = "/run/aos/sandboxd/diagnostics.sock";
const NODE_ID_CREDENTIAL: &str = "node-id";
const CACHE_REPLAY_BUNDLE_CREDENTIAL: &str = "cache-replay-bundle";
const MAXIMUM_CACHE_REPLAY_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const CACHE_OWNER_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const ORIGINAL_ATTACH_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CONTROLLER_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROLLER_COMMAND_CAPACITY: usize = 64;
const PUBLIC_CAPABILITY_HEADER: &str = "aos-capability-id";
const PUBLIC_CAPABILITY_HANDLE_HEADER: &str = "aos-capability-handle";
const REQUEST_SCOPE: [u8; 32] = [0x43; 32];
const UNAVAILABLE_REASON: &str = "production mutation authority is not installed";
const CONTROLLER_ORCHESTRATION_PENDING: &str =
    "controller mutation is awaiting production orchestration lowering";
const CREATE_Q04_AUTHORITY_PENDING: &str =
    "Create awaits authenticated Q04 compiler input and held owner custody";

type ProductionController = NodeController<ProductionOperationCompilerV1, ProductionEffectExecutor>;
type SharedControllerBrokerSessions = Arc<Mutex<ControllerBrokerSessions>>;

/// Retains authenticated transports and their durable sequence owners across cycles.
#[derive(Default)]
struct ControllerBrokerSessions {
    launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    host: Option<ControllerHostPublication>,
    mount: Option<crate::DormantMountLifecycleInventoryOwnerV1>,
    storage: Option<crate::DormantStorageLifecycleInventoryOwnerV1>,
    storage_cold: Option<crate::handshake::RetainedStorageColdOpenV1>,
    storage_terminal: Option<std::sync::Weak<ControllerWorkerCustodyV1>>,
    storage_root: guest_root::ControllerGuestRootExchangeV1,
    network: Option<crate::DormantNetworkLifecycleInventoryOwnerV1>,
}

enum ControllerCommand {
    InspectGitRead {
        original: Box<Option<aos_sandbox::git::delegated_read::GitReadRequestOwnerV1>>,
        index: usize,
        reply: tokio::sync::oneshot::Sender<()>,
    },
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
/// `--nix-start-admission` requires the original paired Nix startup capture and
/// twelve fixed public credentials. It admits pending Start operations only;
/// it does not enable a Nix worker, effect success, or readiness.
/// The exclusive `--issue-source-successor` mode derives and durably delivers
/// one fixed administrative approval from real completed generation-one owners.
/// It starts no listener or worker and sends no READY notification. After its
/// original resources are acquired, failure terminates with custody resident
/// instead of returning an ordinary runtime error.
/// The node identity is read from
/// `CREDENTIALS_DIRECTORY/node-id`; broker endpoints,
/// cgroups, journal location, and root-only diagnostic socket are fixed
/// production paths.
///
/// # Errors
///
/// Returns configuration or process-identity errors. A genuinely empty
/// NoRoot/NoNix continuation also returns ordinary state, socket, journal,
/// catalog, notification or server errors.
///
/// Original capture, selected Root/Nix startup and recipe admission failures
/// intentionally terminate instead of returning an error. Later ordinary
/// failures also terminate while the continuation remains armed or retains
/// Root, Nix selector or launch-image custody. Selected Publisher and partial
/// worker startup also retain returned originals through intentional
/// termination. Issue-only failures retain their original invocation.
pub fn run_from_environment() -> Result<(), ControllerRuntimeError> {
    let configuration = RuntimeConfiguration::from_process()?;
    configuration.validate_process_identity()?;
    let mut startup = crate::production_startup::ControllerStartupContinuationV1::new(
        configuration.publisher_ingress,
        configuration.nix_start_admission,
        configuration.issue_source_successor,
    );
    if !startup.capture_once() {
        startup.terminate_failed();
    }
    if configuration.issue_source_successor {
        return source_successor_issuance::run(&configuration, &mut startup);
    }

    match run_ordinary_controller(configuration, &mut startup) {
        Err(cause) if startup.must_retain_failure() => startup.fail_runtime(cause),
        result => result,
    }
}

fn run_ordinary_controller(
    configuration: RuntimeConfiguration,
    startup: &mut crate::production_startup::ControllerStartupContinuationV1,
) -> Result<(), ControllerRuntimeError> {
    // This independently selected profile is retained before opening any
    // journal. Root's concurrent startup is joined only on the original flight.
    if !startup.admit_root_once(configuration.uid, configuration.gid) {
        startup.terminate_failed();
    }
    let normal_root_profile = startup.profile_share();
    if !startup.require_source_delivery_absent() {
        if startup.must_retain_failure() {
            startup.terminate_failed();
        }
        // Genuine empty NoRoot/NoNix retains the old ordinary error exit.
        return Err(ControllerRuntimeError::InvalidCredential);
    }
    if !startup.bind_launch_in_place() {
        startup.terminate_failed();
    }
    let launch_image = startup.image_share();
    if startup.must_retain_failure() {
        return run_retained_controller(
            configuration,
            startup,
            normal_root_profile,
            launch_image,
        );
    }
    let publisher_descriptor = startup.take_publisher();
    let publisher_listener = publisher_descriptor
        .map(publisher_ingress::adopt_observed_listener)
        .transpose()
        .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?;
    let node_id = read_node_id()?;
    // Admission consumes the genuine original capture before any Controller
    // journal opens. The selected credentials grant no worker or floor owner.
    let nix_start = if configuration.nix_start_admission {
        if !startup.admit_nix_once(
            configuration.uid,
            configuration.gid,
            NodeId::from_bytes(node_id),
        ) {
            startup.terminate_failed();
        }
        startup.selector_share()
    } else {
        None
    };
    let source_genesis_input =
        ProvisionedControllerSourceGenesisInputV1::from_systemd_credentials_optional()?;
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
    let sessions = Arc::new(Mutex::new(ControllerBrokerSessions {
        launch_image,
        ..ControllerBrokerSessions::default()
    }));
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
        nix_start,
    )?;
    let replay_genesis = source_genesis_input
        .as_ref()
        .map(|input| controller.has_retained_provisioned_source_genesis_v1(input))
        .transpose()?
        .unwrap_or(false);
    if replay_genesis {
        // Historical owner recovery must not wait behind an expired or updated
        // unrelated publisher bootstrap credential. This selector grants no
        // authority: the coordinator still rejoins the actual original attempt.
        complete_configured_source_genesis(
            &mut controller,
            source_genesis_input.as_ref(),
            normal_root_profile.as_deref(),
        )?;
    }
    if let Some(scope) = publisher_registration
        .as_ref()
        .map(|owner| owner.service_scope())
    {
        publisher_policy_source::install_from_process_credentials(&mut controller, scope)
            .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))?;
    }
    if !replay_genesis {
        complete_configured_source_genesis(
            &mut controller,
            source_genesis_input.as_ref(),
            normal_root_profile.as_deref(),
        )?;
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
    let worker_normal_root_profile = normal_root_profile.clone();

    std::thread::Builder::new()
        .name("aos-sandboxd-reconciler".to_owned())
        .spawn(move || {
            controller_worker(
                controller,
                worker_normal_root_profile,
                node_id,
                ownership,
                attach_credentials,
                attach_plan_signer,
                guest_root_pins,
                source_genesis_input,
                publisher_registration,
                worker_capabilities,
                sessions,
                commands_rx,
                events_tx,
            )
        })
        .map_err(ControllerRuntimeError::WorkerSpawn)?;

    startup.complete_worker_handoff();

    wait_for_initial_readiness(&events_rx)?;
    if let Some(profile) = &normal_root_profile {
        profile
            .recheck()
            .map_err(ControllerRuntimeError::NormalRootProfile)?;
    }
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
    let (public_application, application) =
        controller_applications(public_service, diagnostic_service);
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

// Keeps the complete fixed public-first/diagnostic-second owning recipe together.
fn controller_applications(
    public_service: Arc<CapabilityService>,
    diagnostic_service: Arc<CapabilityService>,
) -> (axum::Router, axum::Router) {
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

    (public_application, application)
}

fn run_retained_controller(
    configuration: RuntimeConfiguration,
    startup: &mut crate::production_startup::ControllerStartupContinuationV1,
    profile: Option<Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>>,
    launch: Option<crate::production_startup::Pid1LaunchImageV1>,
) -> ! {
    let mut parent = ControllerParentCustodyV1::new(profile, launch);
    let worker = Arc::clone(&parent.worker);
    let Ok(mut originals) = worker.originals.lock() else {
        worker.terminate(ControllerResidentCauseV1::Closed("Controller owner lock poisoned"));
    };
    let _unwind = AbortControllerCustodyUnwindV1;

    // Local propagation only: success is assigned immediately into an already
    // prepared field. No helper consumes an original or supplies authority.
    macro_rules! checked {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(cause) => worker.terminate(ControllerResidentCauseV1::Runtime(cause)),
            }
        };
    }

    macro_rules! required {
        ($value:expr) => {
            match $value {
                Some(value) => value,
                None => worker.terminate(ControllerResidentCauseV1::Closed(
                    "Controller partial destination unavailable",
                )),
            }
        };
    }

    macro_rules! begin {
        ($step:ident) => {
            if worker.ended.load(Ordering::Acquire)
                || !parent.stage.begin(ControllerParentStepV1::$step)
            {
                worker.terminate(ControllerResidentCauseV1::Closed("Controller step reentered"));
            }
        };
    }

    macro_rules! complete {
        ($step:ident) => {
            if worker.ended.load(Ordering::Acquire)
                || !parent.stage.complete(ControllerParentStepV1::$step)
            {
                worker.terminate(ControllerResidentCauseV1::Closed("Controller step incomplete"));
            }
        };
    }

    begin!(Publisher);
    // Prepare the destination before the same actual FIRST6 role handoff.
    originals.publisher_attempt = startup
        .take_publisher()
        .map(publisher_ingress::PublisherStartupAttemptV1::from_original_listener);
    if let Some(attempt) = &mut originals.publisher_attempt {
        if attempt.admit_listener_once().is_err() {
            worker.terminate(ControllerResidentCauseV1::Publisher);
        }
    }
    complete!(Publisher);

    begin!(Node);
    originals.node = Some(checked!(read_node_id()));
    let node_id = required!(originals.node);
    complete!(Node);

    begin!(Nix);
    if configuration.nix_start_admission {
        if !startup.admit_nix_once(
            configuration.uid,
            configuration.gid,
            NodeId::from_bytes(node_id),
        ) {
            worker.close(ControllerResidentCauseV1::Closed(
                "resident original Nix admission failed",
            ));
            startup.terminate_failed();
        }
        originals.nix_selector = Some(startup.selector_share());
    } else {
        originals.nix_selector = Some(None);
    }
    complete!(Nix);

    begin!(GenesisInput);
    originals.genesis = Some(checked!(
        ProvisionedControllerSourceGenesisInputV1::from_systemd_credentials_optional()
            .map_err(ControllerRuntimeError::from)
    ));
    complete!(GenesisInput);

    begin!(PublisherRegistration);
    originals.publisher_registration = Some(None);
    if let Some(attempt) = &mut originals.publisher_attempt {
        if attempt
            .construct_registration_once(NodeId::from_bytes(node_id))
            .is_err()
        {
            worker.terminate(ControllerResidentCauseV1::Publisher);
        }
        originals.publisher_registration = Some(Some(required!(
            attempt.take_completed_registration()
        )));
    }
    complete!(PublisherRegistration);

    begin!(Cache);
    if configuration.git_upload_bootstrap {
        // ExistingResident never imports or creates its own Source authority.
        originals.cache_bundle = Some(None);
    } else {
        originals.cache_bundle = Some(checked!(read_cache_replay_bundle()));
        if let Some(bundle) = required!(originals.cache_bundle.as_ref()) {
            checked!(
                CacheReplayControllerBootstrapOwnerV1::import_fixed_bundle_for_uid(
                    configuration.uid,
                    bundle,
                )
                .map_err(ControllerRuntimeError::CacheReplaySource)
            );
        }
    }
    complete!(Cache);

    begin!(Ownership);
    originals.ownership = Some(checked!(
        ControllerOwnershipConfigurationV1::from_process_credentials_optional()
            .map_err(|_| ControllerRuntimeError::InvalidOwnershipCredential)
    ));
    complete!(Ownership);

    begin!(Attach);
    originals.attach = Some(checked!(
        ControllerAttachCredentialsV1::from_process_credentials_optional()
            .map_err(|_| ControllerRuntimeError::InvalidAttachCredential)
    ));
    complete!(Attach);

    begin!(Signer);
    originals.signer = Some(checked!(
        ControllerBrokerPlanSignerV1::from_process_credentials_optional()
            .map_err(|_| ControllerRuntimeError::InvalidBrokerPlanCredential)
    ));
    complete!(Signer);

    begin!(Pins);
    originals.pins = Some(checked!(
        load_guest_root_template_pins_optional()
            .map_err(|_| ControllerRuntimeError::InvalidGuestRootCredential)
    ));
    complete!(Pins);

    begin!(Diagnostic);
    parent.diagnostic_registration = Some(tokio::net::UnixListenerRegistrationAttempt::new(
        checked!(bind_diagnostic_socket(&configuration)),
    ));
    complete!(Diagnostic);

    begin!(Sessions);
    originals.sessions = Some(Arc::new(Mutex::new(ControllerBrokerSessions {
        launch_image: required!(parent.launch.take()),
        storage_terminal: Some(Arc::downgrade(&worker)),
        ..ControllerBrokerSessions::default()
    })));
    complete!(Sessions);

    begin!(Runtime);
    parent.runtime = Some(checked!(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(ControllerRuntimeError::Runtime)
    ));
    complete!(Runtime);

    begin!(Host);
    parent.host = Some(match required!(parent.runtime.as_ref())
        .block_on(attachment_target::observe_host_service_identity())
    {
        Ok(identity) => Some(identity),
        Err(error) => {
            eprintln!("aos-sandboxd: Host attachment identity unavailable: {error}");
            None
        }
    });
    complete!(Host);

    begin!(Mount);
    parent.mount = Some(match required!(parent.runtime.as_ref())
        .block_on(attachment_target::observe_mount_service_identity())
    {
        Ok(identity) => Some(identity),
        Err(error) => {
            eprintln!("aos-sandboxd: Mount attachment identity unavailable: {error}");
            None
        }
    });
    complete!(Mount);

    begin!(Controller);
    // The unchanged consuming constructor still has a pre-return custody gap
    // for these attachment inputs and its own Journal/executor locals.
    originals.controller = Some(checked!(open_controller(
        &configuration,
        node_id,
        Arc::clone(required!(originals.sessions.as_ref())),
        required!(parent.host.take()),
        required!(parent.mount.take()),
        required!(originals.nix_selector.as_ref()).clone(),
    )));
    complete!(Controller);

    begin!(ControllerStartup);
    {
        let ControllerWorkerOriginalsV1 {
            controller,
            genesis,
            profile,
            publisher_registration,
            publisher_policy_bootstrap,
            ..
        } = &mut *originals;
        let controller = required!(controller.as_mut());
        let genesis = required!(genesis.as_ref()).as_ref();
        let profile = required!(profile.as_ref()).as_deref();
        let replay_genesis = checked!(
            genesis
                .map(|input| controller.has_retained_provisioned_source_genesis_v1(input))
                .transpose()
                .map_err(ControllerRuntimeError::from)
        )
        .unwrap_or(false);
        if replay_genesis {
            checked!(
                complete_configured_source_genesis(controller, genesis, profile)
                    .map_err(ControllerRuntimeError::from)
            );
        }
        if configuration.git_upload_bootstrap
            && required!(publisher_registration.as_ref()).is_none()
        {
            worker.terminate(ControllerResidentCauseV1::Closed(
                "Git bootstrap original publisher registration is absent",
            ));
        }
        if let Some(scope) = required!(publisher_registration.as_ref())
            .as_ref()
            .map(|owner| owner.service_scope())
        {
            if configuration.git_upload_bootstrap {
                // Park the empty fixed destination before capture or parsing.
                *publisher_policy_bootstrap = Some(
                    publisher_policy_source::PublisherPolicyBootstrapAttemptV1::new(),
                );
                let attempt = required!(publisher_policy_bootstrap.as_mut());
                if attempt.install_bootstrap_once(controller, scope).is_err() {
                    worker.terminate(ControllerResidentCauseV1::PublisherPolicyBootstrap);
                }
            } else {
                checked!(
                    publisher_policy_source::install_from_process_credentials(controller, scope)
                        .map_err(|error| ControllerRuntimeError::PublisherIngress(error.to_string()))
                );
            }
        }
        if !replay_genesis {
            checked!(
                complete_configured_source_genesis(controller, genesis, profile)
                    .map_err(ControllerRuntimeError::from)
            );
        }
        if let Some(bootstrap) = publisher_policy_bootstrap.as_mut() {
            if cache_usage::selected_bookend(controller, bootstrap).is_err() {
                worker.terminate(ControllerResidentCauseV1::CacheUsage);
            }
        }
    }
    complete!(ControllerStartup);

    begin!(AsyncDiagnostic);
    {
        let ControllerParentCustodyV1 {
            runtime,
            diagnostic_registration,
            diagnostic,
            ..
        } = &mut parent;
        let runtime = required!(runtime.as_ref());
        let attempt = required!(diagnostic_registration.as_mut());
        runtime.block_on(async {
            register_retained_diagnostic(attempt, diagnostic, worker.as_ref());
        });
    }
    complete!(AsyncDiagnostic);

    begin!(Public);
    if configuration.public_api {
        let ControllerParentCustodyV1 {
            runtime,
            public_startup,
            public,
            ..
        } = &mut parent;
        required!(runtime.as_ref()).block_on(async {
            public_api::bind_retained(
                configuration.uid,
                public_startup,
                public,
                worker.as_ref(),
            );
        });
    } else {
        parent.public = Some(None);
    }
    complete!(Public);

    if let Some(gateway) = configuration.git_read_inspection {
        parent.git_read.bind(configuration.uid, configuration.gid, gateway, &worker);
        let Some(Some(public)) = parent.public.as_ref() else {
            worker.terminate(ControllerResidentCauseV1::GitRead);
        };
        originals.git_read = Some(git_read_inspection::GitReadWorkerInputsV1::new(
            public.git_read_acceptor(),
            required!(parent.runtime.as_ref()).handle().clone(),
        ));
    }

    begin!(Capabilities);
    originals.capabilities = Some(Arc::new(Mutex::new(CapabilityState::starting(node_id))));
    complete!(Capabilities);

    begin!(Events);
    // Both target guards are acquired BEFORE the tuple producer returns either
    // original end. The receiver never enters a consuming monitor closure.
    {
        let Ok(mut receiver) = worker.receiver.lock() else {
            worker.terminate(ControllerResidentCauseV1::Closed("Controller receiver lock poisoned"));
        };
        if receiver.is_some() || originals.events.is_some() {
            worker.terminate(ControllerResidentCauseV1::Closed("Controller event targets occupied"));
        }
        let (sender, received) = mpsc::channel();
        originals.events = Some(sender);
        *receiver = Some(received);
    }
    complete!(Events);

    begin!(Commands);
    let (commands_tx, commands_rx) = mpsc::sync_channel(CONTROLLER_COMMAND_CAPACITY);
    parent.commands = Some(commands_tx);
    if configuration.git_read_inspection.is_some() {
        parent.git_read_commands = Some(required!(parent.commands.as_ref()).clone());
    }
    originals.commands = Some(commands_rx);
    complete!(Commands);
    if !originals.complete_worker_inputs(&parent.stage) {
        worker.terminate(ControllerResidentCauseV1::Closed("Controller worker fields incomplete"));
    }
    let capabilities = Arc::clone(required!(originals.capabilities.as_ref()));

    begin!(Spawn);
    drop(originals);
    let thread_worker = Arc::clone(&worker);
    parent.thread = Some(checked!(
        std::thread::Builder::new()
            .name("aos-sandboxd-reconciler".to_owned())
            .spawn(move || retained_controller_worker(&thread_worker))
            .map_err(ControllerRuntimeError::WorkerSpawn)
    ));
    complete!(Spawn);
    // No acquisition of the long owner loan after a successful spawn.
    startup.complete_worker_handoff();

    begin!(Readiness);
    match worker.receive() {
        ControllerMonitorOutcomeV1::Event(WorkerEvent::Ready)
            if !worker.ended.load(Ordering::Acquire) => {}
        ControllerMonitorOutcomeV1::Event(WorkerEvent::Fatal(message)) => {
            worker.terminate(ControllerResidentCauseV1::Worker(message))
        }
        _ => worker.terminate(ControllerResidentCauseV1::Closed(
            "resident Controller worker stopped before readiness",
        )),
    }
    complete!(Readiness);
    begin!(Profile);
    if let Some(profile) = startup.profile() {
        checked!(profile.recheck().map_err(ControllerRuntimeError::NormalRootProfile));
    }
    complete!(Profile);
    begin!(Notifier);
    parent.notifier = Some(checked!(SystemdReadyNotifier::from_environment()));
    complete!(Notifier);
    begin!(Notify);
    checked!(required!(parent.notifier.as_ref()).notify_ready());
    complete!(Notify);

    // These are the same routers and service sharing points as Legacy.
    begin!(Applications);
    let public_service = Arc::new(CapabilityService {
        capabilities: Arc::clone(&capabilities),
        commands: required!(parent.commands.as_ref()).clone(),
        endpoint: ControllerEndpoint::RegisteredPublic,
    });
    let diagnostic_service = Arc::new(CapabilityService {
        capabilities,
        commands: required!(parent.commands.take()),
        endpoint: ControllerEndpoint::RootDiagnostic,
    });
    let (public_application, application) =
        controller_applications(public_service, diagnostic_service);
    complete!(Applications);

    // Future construction is an infallible ownership park. Axum's unchanged
    // IntoFuture boxing happens during poll, an excluded provider boundary.
    let public = std::pin::pin!(public_api::serve(
        required!(parent.public.take()),
        public_application,
    ));
    let _public_unwind = AbortControllerCustodyUnwindV1;
    let diagnostic_listener = required!(parent.diagnostic.take());
    let _diagnostic_input_unwind = AbortControllerCustodyUnwindV1;
    let diagnostic = std::pin::pin!(async move {
        axum::serve(diagnostic_listener, application)
            .await
            .map_err(ControllerRuntimeError::DiagnosticServer)
    });
    let _diagnostic_unwind = AbortControllerCustodyUnwindV1;

    let git_read = std::pin::pin!(parent.git_read.serve(
        parent.git_read_commands.as_ref(),
        worker.as_ref(),
    ));
    let _git_read_unwind = AbortControllerCustodyUnwindV1;

    // Only the concrete listener/router enters that future. Runtime remains
    // in the parent, and the receiver stays in its independent original slot.
    begin!(Monitor);
    let monitor_worker = Arc::clone(&worker);
    parent.monitor = Some(
        required!(parent.runtime.as_ref()).spawn_blocking(move || monitor_worker.receive()),
    );
    complete!(Monitor);
    let _serve_unwind = AbortControllerCustodyUnwindV1;
    let runtime = required!(parent.runtime.as_ref());
    let monitor = required!(parent.monitor.as_mut());
    let _stopped: () = runtime.block_on(async {
        let mut public = public;
        let mut diagnostic = diagnostic;
        let mut git_read = git_read;
        tokio::select! {
            () = &mut git_read => worker.terminate(ControllerResidentCauseV1::GitRead),
            result = &mut public => {
                let cause = match result {
                    Err(cause) => ControllerResidentCauseV1::Runtime(cause),
                    Ok(()) => ControllerResidentCauseV1::Closed("Controller public server completed"),
                };
                worker.terminate(cause)
            }
            result = &mut diagnostic => {
                let cause = match result {
                    Err(cause) => ControllerResidentCauseV1::Runtime(cause),
                    Ok(()) => ControllerResidentCauseV1::Closed("Controller diagnostic server completed"),
                };
                worker.terminate(cause)
            }
            result = monitor => {
                let cause = match result {
                    Err(cause) => ControllerResidentCauseV1::Runtime(
                        ControllerRuntimeError::WorkerJoin(cause),
                    ),
                    Ok(ControllerMonitorOutcomeV1::Event(WorkerEvent::Fatal(message))) => {
                        ControllerResidentCauseV1::Worker(message)
                    }
                    Ok(_) => ControllerResidentCauseV1::Closed("Controller worker monitor ended"),
                };
                worker.terminate(cause)
            }
        }
    });
    worker.terminate(ControllerResidentCauseV1::Closed(
        "Controller server monitor returned unexpectedly",
    ))
}

// These slots are a fixed destination for actual returned startup inputs, not
// an authority tuple. Outer None is unobserved; Some(None) is the same producer's
// observed optional absence. The worker only borrows a completed destination.
#[derive(Default)]
struct ControllerWorkerOriginalsV1 {
    git_read: Option<git_read_inspection::GitReadWorkerInputsV1>,
    publisher_attempt: Option<publisher_ingress::PublisherStartupAttemptV1>,
    publisher_registration: Option<Option<publisher_ingress::PublisherRegistrationOwnerV1>>,
    publisher_policy_bootstrap: Option<publisher_policy_source::PublisherPolicyBootstrapAttemptV1>,
    node: Option<[u8; 16]>,
    profile: Option<
        Option<Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>>,
    >,
    nix_selector: Option<Option<Arc<ControllerNixStartRecipeSelectorV2>>>,
    genesis: Option<Option<ProvisionedControllerSourceGenesisInputV1>>,
    cache_bundle: Option<Option<Vec<u8>>>,
    ownership: Option<Option<ControllerOwnershipConfigurationV1>>,
    attach: Option<Option<ControllerAttachCredentialsV1>>,
    signer: Option<Option<ControllerBrokerPlanSignerV1>>,
    pins: Option<Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>>,
    sessions: Option<SharedControllerBrokerSessions>,
    controller: Option<ProductionController>,
    capabilities: Option<Arc<Mutex<CapabilityState>>>,
    commands: Option<mpsc::Receiver<ControllerCommand>>,
    events: Option<mpsc::Sender<WorkerEvent>>,
    worker_stage: ControllerWorkerStageV1,
}

// Consecutive values constrain this private, single execution recipe. They are
// negative bookkeeping, never a currentness, floor, or detached Ready witness.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
enum ControllerParentStepV1 {
    Publisher = 1,
    Node,
    Nix,
    GenesisInput,
    PublisherRegistration,
    Cache,
    Ownership,
    Attach,
    Signer,
    Pins,
    Diagnostic,
    Sessions,
    Runtime,
    Host,
    Mount,
    Controller,
    ControllerStartup,
    AsyncDiagnostic,
    Public,
    Capabilities,
    Events,
    Commands,
    Spawn,
    Readiness,
    Profile,
    Notifier,
    Notify,
    Applications,
    Monitor,
}

#[derive(Default)]
enum ControllerParentStageV1 {
    #[default]
    Prepared,
    Checking(ControllerParentStepV1),
    Completed(ControllerParentStepV1),
    Ended,
}

impl ControllerParentStageV1 {
    fn begin(&mut self, step: ControllerParentStepV1) -> bool {
        let previous = match *self {
            ControllerParentStageV1::Prepared => 0,
            ControllerParentStageV1::Completed(previous) => previous as u8,
            ControllerParentStageV1::Checking(_) | ControllerParentStageV1::Ended => {
                *self = ControllerParentStageV1::Ended;
                return false;
            }
        };
        if previous.checked_add(1) != Some(step as u8) {
            *self = ControllerParentStageV1::Ended;
            return false;
        }
        *self = ControllerParentStageV1::Checking(step);
        true
    }

    fn complete(&mut self, step: ControllerParentStepV1) -> bool {
        if !matches!(*self, ControllerParentStageV1::Checking(actual) if actual == step) {
            *self = ControllerParentStageV1::Ended;
            return false;
        }
        *self = ControllerParentStageV1::Completed(step);
        true
    }
}

#[derive(Default)]
enum ControllerWorkerStageV1 {
    #[default]
    Building,
    Ready,
    Ended,
}

impl ControllerWorkerOriginalsV1 {
    fn complete_worker_inputs(&mut self, stage: &ControllerParentStageV1) -> bool {
        if !matches!(self.worker_stage, ControllerWorkerStageV1::Building)
            || !matches!(
                stage,
                ControllerParentStageV1::Completed(ControllerParentStepV1::Commands)
            )
        {
            self.worker_stage = ControllerWorkerStageV1::Ended;
            return false;
        }
        self.worker_stage = ControllerWorkerStageV1::Ready;
        if self.ready_loan().is_none() {
            self.worker_stage = ControllerWorkerStageV1::Ended;
            return false;
        }
        true
    }

    fn ready_loan(&mut self) -> Option<ControllerWorkerLoanV1<'_>> {
        if !matches!(self.worker_stage, ControllerWorkerStageV1::Ready)
            || self.nix_selector.is_none()
            || self.cache_bundle.is_none()
            || self.publisher_registration.is_none()
        {
            return None;
        }
        Some(ControllerWorkerLoanV1 {
            controller: self.controller.as_mut()?,
            profile: self.profile.as_ref()?.as_deref(),
            node: self.node?,
            ownership: self.ownership.as_ref()?.as_ref(),
            attach: self.attach.as_ref()?.as_ref(),
            signer: self.signer.as_ref()?.as_ref(),
            pins: *self.pins.as_ref()?,
            genesis: self.genesis.as_ref()?.as_ref(),
            publisher: self.publisher_registration.as_mut()?.as_mut(),
            cache_bootstrap: self.publisher_policy_bootstrap.as_mut(),
            git_read: self.git_read.as_mut(),
            capabilities: self.capabilities.as_ref()?,
            sessions: self.sessions.as_ref()?,
            commands: self.commands.as_ref()?,
            events: self.events.as_ref()?,
        })
    }
}

/// Borrows the actual stored fields for the sole reconciliation loop.
struct ControllerWorkerLoanV1<'owner> {
    controller: &'owner mut ProductionController,
    profile: Option<&'owner aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
    node: [u8; 16],
    ownership: Option<&'owner ControllerOwnershipConfigurationV1>,
    attach: Option<&'owner ControllerAttachCredentialsV1>,
    signer: Option<&'owner ControllerBrokerPlanSignerV1>,
    pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    genesis: Option<&'owner ProvisionedControllerSourceGenesisInputV1>,
    publisher: Option<&'owner mut publisher_ingress::PublisherRegistrationOwnerV1>,
    cache_bootstrap: Option<&'owner mut publisher_policy_source::PublisherPolicyBootstrapAttemptV1>,
    git_read: Option<&'owner mut git_read_inspection::GitReadWorkerInputsV1>,
    capabilities: &'owner Arc<Mutex<CapabilityState>>,
    sessions: &'owner SharedControllerBrokerSessions,
    commands: &'owner mpsc::Receiver<ControllerCommand>,
    events: &'owner mpsc::Sender<WorkerEvent>,
}

enum ControllerResidentCauseV1 {
    // The real native cause and channel/Journal outcomes remain in fixed slots.
    GitRead,
    Runtime(ControllerRuntimeError),
    Worker(String),
    ReadySend(mpsc::SendError<WorkerEvent>),
    Receive(mpsc::RecvError),
    // The actual typed cause remains in SAME pending Publisher attempt.
    Publisher,
    // Actual original lower/verification/Journal cause stays in the SAME slot.
    PublisherPolicyBootstrap,
    // Actual Cache initialization/replay causes stay in the SAME Controller.
    CacheUsage,
    // Typed cause and every partial owner remain in SAME sessions' cold slot.
    StorageCold,
    Closed(&'static str),
}

impl ControllerResidentCauseV1 {
    fn diagnostic(&self) -> &'static str {
        match self {
            Self::GitRead => "resident original Git read inspection failure",
            Self::Runtime(_) => "resident Controller startup/server failure",
            Self::Worker(_) => "resident Controller worker failure",
            Self::ReadySend(_) => "resident Controller readiness delivery failure",
            Self::Receive(_) => "resident Controller event receiver disconnected",
            Self::Publisher => "resident original Publisher startup failure",
            Self::PublisherPolicyBootstrap => "resident original Publisher policy bootstrap failure",
            Self::CacheUsage => "resident original Cache project observation failure",
            Self::StorageCold => "resident original Storage cold admission failure",
            Self::Closed(label) => label,
        }
    }
}

// Neither terminal handling nor event reception needs the worker's long owner
// loan. In particular diagnostics must never wait on owner under terminal.
struct ControllerWorkerCustodyV1 {
    originals: Mutex<ControllerWorkerOriginalsV1>,
    terminal: Mutex<Option<ControllerResidentCauseV1>>,
    receiver: Mutex<Option<mpsc::Receiver<WorkerEvent>>>,
    ended: AtomicBool,
}

impl ControllerWorkerCustodyV1 {
    fn close(&self, cause: ControllerResidentCauseV1) {
        self.ended.store(true, Ordering::Release);
        let Ok(mut terminal) = self.terminal.lock() else {
            std::process::abort();
        };
        if terminal.is_none() {
            *terminal = Some(cause);
        }
    }

    fn terminate(&self, cause: ControllerResidentCauseV1) -> ! {
        self.close(cause);
        let Ok(terminal) = self.terminal.lock() else {
            std::process::abort();
        };
        let label = terminal.as_ref().map(ControllerResidentCauseV1::diagnostic);
        eprintln!("aos-sandboxd: {}", label.unwrap_or("resident Controller closed"));
        std::process::exit(1)
    }

    fn receive(&self) -> ControllerMonitorOutcomeV1 {
        let Ok(receiver) = self.receiver.lock() else {
            self.close(ControllerResidentCauseV1::Closed("Controller receiver lock poisoned"));
            return ControllerMonitorOutcomeV1::Ended;
        };
        let Some(receiver) = receiver.as_ref() else {
            self.close(ControllerResidentCauseV1::Closed("Controller receiver unavailable"));
            return ControllerMonitorOutcomeV1::Ended;
        };
        match receiver.recv() {
            Ok(event) => ControllerMonitorOutcomeV1::Event(event),
            Err(cause) => {
                self.close(ControllerResidentCauseV1::Receive(cause));
                ControllerMonitorOutcomeV1::Ended
            }
        }
    }
}

enum ControllerMonitorOutcomeV1 {
    Event(WorkerEvent),
    Ended,
}

// Same parent frame owns these partial I/O returns independently of the worker
// mutex. Selected termination intentionally precedes every normal field Drop.
struct ControllerParentCustodyV1 {
    worker: Arc<ControllerWorkerCustodyV1>,
    stage: ControllerParentStageV1,
    launch: Option<Option<crate::production_startup::Pid1LaunchImageV1>>,
    runtime: Option<tokio::runtime::Runtime>,
    diagnostic_registration: Option<tokio::net::UnixListenerRegistrationAttempt>,
    diagnostic: Option<AuthenticatedDiagnosticListener>,
    public_startup: public_api::PublicListenerStartupV1,
    public: Option<Option<public_api::PublicListener>>,
    host: Option<Option<aos_sandbox::runtime_scope::HostServiceIdentity>>,
    mount: Option<Option<aos_sandbox::mount_preparation::MountServiceIdentity>>,
    notifier: Option<SystemdReadyNotifier>,
    thread: Option<std::thread::JoinHandle<()>>,
    monitor: Option<tokio::task::JoinHandle<ControllerMonitorOutcomeV1>>,
    commands: Option<mpsc::SyncSender<ControllerCommand>>,
    git_read_commands: Option<mpsc::SyncSender<ControllerCommand>>,
    git_read: git_read_inspection::GitReadIngressV1,
}

impl ControllerParentCustodyV1 {
    fn new(
        profile: Option<Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>>,
        launch: Option<crate::production_startup::Pid1LaunchImageV1>,
    ) -> Self {
        Self {
            worker: Arc::new(ControllerWorkerCustodyV1 {
                originals: Mutex::new(ControllerWorkerOriginalsV1 {
                    profile: Some(profile),
                    ..ControllerWorkerOriginalsV1::default()
                }),
                terminal: Mutex::new(None),
                receiver: Mutex::new(None),
                ended: AtomicBool::new(false),
            }),
            stage: ControllerParentStageV1::Prepared,
            launch: Some(launch),
            runtime: None,
            diagnostic_registration: None,
            diagnostic: None,
            public_startup: public_api::PublicListenerStartupV1::new(),
            public: None,
            host: None,
            mount: None,
            notifier: None,
            thread: None,
            monitor: None,
            commands: None,
            git_read_commands: None,
            git_read: git_read_inspection::GitReadIngressV1::new(),
        }
    }
}

impl Drop for ControllerParentCustodyV1 {
    fn drop(&mut self) {
        self.worker.ended.store(true, Ordering::Release);
        std::process::abort();
    }
}

// This fence is placed AFTER newly pinned futures or a worker owner loan so it
// fires before their Drop. It cannot rescue already-unwound callee-local frames.
struct AbortControllerCustodyUnwindV1;

impl Drop for AbortControllerCustodyUnwindV1 {
    fn drop(&mut self) {
        if std::thread::panicking() {
            std::process::abort();
        }
    }
}

fn complete_configured_source_genesis(
    controller: &mut ProductionController,
    input: Option<&ProvisionedControllerSourceGenesisInputV1>,
    profile: Option<&aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
) -> Result<(), ControllerSourceGenesisInputErrorV1> {
    let Some(input) = input else {
        return Ok(());
    };
    let profile = profile.ok_or(ControllerSourceGenesisInputErrorV1::Owner(
        aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1::AdmissionClosed,
    ))?;
    // Configured genesis is a real startup obligation, not an advisory
    // inspection. Failure keeps readiness closed; restarting rejoins the
    // exact original pair and protected rows through final Root Finish.
    controller.coordinate_provisioned_source_genesis_v1(input, profile)?;
    Ok(())
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
                Ok(WorkerEvent::ResidentFailure) => Err(ControllerRuntimeError::Worker(
                    "controller worker retained its original failure".to_owned(),
                )),
                Err(_) => Err(ControllerRuntimeError::Worker(
                    "controller worker exited without a terminal status".to_owned(),
                )),
            }
        }
    }
}

// Called inside the existing runtime with only loans of the parent's fields.
// Neither a returned error nor a registered listener crosses that runtime
// return boundary before entering the same parent's resident destination.
fn register_retained_diagnostic(
    attempt: &mut tokio::net::UnixListenerRegistrationAttempt,
    destination: &mut Option<AuthenticatedDiagnosticListener>,
    terminal: &ControllerWorkerCustodyV1,
) {
    if destination.is_some() {
        terminal.terminate(ControllerResidentCauseV1::Closed(
            "Controller diagnostic destination occupied",
        ));
    }

    let listener = match attempt.register() {
        Ok(listener) => listener,
        Err(cause) => terminal.terminate(ControllerResidentCauseV1::Runtime(
            ControllerRuntimeError::DiagnosticSocketRuntime(cause),
        )),
    };
    *destination = Some(AuthenticatedDiagnosticListener::new(listener, 0));
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
    normal_root_profile: Option<
        Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
    >,
    node_id: [u8; 16],
    ownership: Option<ControllerOwnershipConfigurationV1>,
    attach_credentials: Option<ControllerAttachCredentialsV1>,
    attach_plan_signer: Option<ControllerBrokerPlanSignerV1>,
    guest_root_pins: Option<aos_sandbox::guest_root_publication::GuestRootTemplatePinsV1>,
    source_genesis_input: Option<ProvisionedControllerSourceGenesisInputV1>,
    mut publisher_registration: Option<publisher_ingress::PublisherRegistrationOwnerV1>,
    capabilities: Arc<Mutex<CapabilityState>>,
    sessions: SharedControllerBrokerSessions,
    commands: mpsc::Receiver<ControllerCommand>,
    events: mpsc::Sender<WorkerEvent>,
) {
    controller_worker_loop(
        ControllerWorkerLoanV1 {
            controller: &mut controller,
            profile: normal_root_profile.as_deref(),
            node: node_id,
            ownership: ownership.as_ref(),
            attach: attach_credentials.as_ref(),
            signer: attach_plan_signer.as_ref(),
            pins: guest_root_pins,
            genesis: source_genesis_input.as_ref(),
            publisher: publisher_registration.as_mut(),
            cache_bootstrap: None,
            git_read: None,
            capabilities: &capabilities,
            sessions: &sessions,
            commands: &commands,
            events: &events,
        },
        None,
    );
}

fn retained_controller_worker(worker: &ControllerWorkerCustodyV1) {
    let Ok(mut originals) = worker.originals.lock() else {
        worker.terminate(ControllerResidentCauseV1::Closed("Controller owner lock poisoned"));
    };
    let _unwind = AbortControllerCustodyUnwindV1;
    if worker.ended.load(Ordering::Acquire) {
        return;
    }
    let Some(loan) = originals.ready_loan() else {
        worker.terminate(ControllerResidentCauseV1::Closed("Controller worker fields incomplete"));
    };
    controller_worker_loop(loan, Some(worker));
}

// The only loop is borrowed by both the literal consuming Legacy wrapper and
// the selected resident owner. No stored reference or duplicate reducer exists.
fn controller_worker_loop(
    loan: ControllerWorkerLoanV1<'_>,
    custody: Option<&ControllerWorkerCustodyV1>,
) {
    let ControllerWorkerLoanV1 {
        controller,
        profile: normal_root_profile,
        node: node_id,
        ownership,
        attach: attach_credentials,
        signer: attach_plan_signer,
        pins: guest_root_pins,
        genesis: source_genesis_input,
        publisher: mut publisher_registration,
        mut cache_bootstrap,
        mut git_read,
        capabilities,
        sessions,
        commands,
        events,
    } = loan;
    let mut ready = false;
    let mut next_cycle = Instant::now();
    let mut next_attach_poll = Instant::now();
    let mut attach_poll_cursor = 0;
    loop {
        if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
            return;
        }
        if Instant::now() >= next_cycle {
            if let Some(input) = &source_genesis_input {
                if let Err(error) = input.recheck() {
                    report_controller_worker_failure(
                        events,
                        custody,
                        ControllerResidentCauseV1::Runtime(
                            ControllerRuntimeError::SourceGenesisInput(error),
                        ),
                    );
                    return;
                }
            }

            // Retain this same original profile in the actual worker lifecycle;
            // no Root readiness or genesis authority follows from this check.
            if let Some(profile) = &normal_root_profile {
                if let Err(error) = profile.recheck() {
                    report_controller_worker_failure(
                        events,
                        custody,
                        ControllerResidentCauseV1::Runtime(
                            ControllerRuntimeError::NormalRootProfile(error),
                        ),
                    );
                    return;
                }
            }
            if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
                return;
            }
            if let Some(bootstrap) = cache_bootstrap.as_mut() {
                if cache_usage::selected_bookend(controller, bootstrap).is_err() {
                    report_controller_worker_failure(events, custody, ControllerResidentCauseV1::CacheUsage);
                    return;
                }
            }
            match run_controller_cycle(
                controller,
                node_id,
                sessions,
                !ready,
                guest_root_pins,
                attach_plan_signer,
            ) {
                Ok(catalog) => {
                    if let Some(bootstrap) = cache_bootstrap.as_mut() {
                        if cache_usage::selected_bookend(controller, bootstrap).is_err() {
                            report_controller_worker_failure(events, custody, ControllerResidentCauseV1::CacheUsage);
                            return;
                        }
                    }
                    if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
                        return;
                    }
                    let update = capabilities
                        .lock()
                        .map_err(|_| "capability status lock is poisoned".to_owned())
                        .map(|mut state| state.record_success(catalog.generation, catalog.digest));
                    if let Err(message) = update {
                        report_controller_worker_failure(
                            events,
                            custody,
                            ControllerResidentCauseV1::Worker(message),
                        );
                        return;
                    }
                    if !ready {
                        if let Err(cause) = events.send(WorkerEvent::Ready) {
                            if let Some(owner) = custody {
                                owner.close(ControllerResidentCauseV1::ReadySend(cause));
                            }
                            return;
                        }
                        ready = true;
                    }
                }
                Err(CycleFailure::Retryable(message)) => {
                    if let Ok(mut state) = capabilities.lock() {
                        state.record_retryable_failure(message.clone());
                    } else {
                        report_controller_worker_failure(
                            events,
                            custody,
                            ControllerResidentCauseV1::Worker(
                                "capability status lock is poisoned".to_owned(),
                            ),
                        );
                        return;
                    }
                    eprintln!("aos-sandboxd: reconciliation pending: {message}");
                }
                Err(CycleFailure::Fatal(message)) => {
                    report_controller_worker_failure(
                        events,
                        custody,
                        ControllerResidentCauseV1::Worker(message),
                    );
                    return;
                }
            }
            next_cycle = Instant::now() + RECONCILIATION_INTERVAL;
        }

        if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
            return;
        }
        if Instant::now() >= next_attach_poll {
            original_attach::poll_one(
                controller,
                NodeId::from_bytes(node_id),
                sessions,
                attach_plan_signer,
                &mut attach_poll_cursor,
            );
            next_attach_poll = Instant::now() + ORIGINAL_ATTACH_POLL_INTERVAL;
        }

        if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
            return;
        }
        if let Some(owner) = publisher_registration.as_mut() {
            if let Err(message) = owner.try_register(controller) {
                report_controller_worker_failure(
                    events,
                    custody,
                    ControllerResidentCauseV1::Worker(message),
                );
                return;
            }
        }

        if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
            return;
        }
        let mut wait = next_cycle
            .min(next_attach_poll)
            .saturating_duration_since(Instant::now());
        if publisher_registration
            .as_ref()
            .is_some_and(|owner| owner.needs_registration())
        {
            wait = wait.min(Duration::from_millis(250));
        }
        match commands.recv_timeout(wait) {
            Ok(ControllerCommand::InspectGitRead { original, index, reply }) => {
                // Move the genuine returned owner into its destination before
                // any ended check, currentness gate or evaluator can fail.
                let (Some(inputs), Some(bootstrap), Some(terminal)) =
                    (git_read.as_mut(), cache_bootstrap.as_mut(), custody)
                else {
                    std::process::abort();
                };
                inputs.inspect(controller, bootstrap, original, index, reply, terminal);
            }
            Ok(command) => {
                if custody.is_some_and(|owner| owner.ended.load(Ordering::Acquire)) {
                    return;
                }
                if let Err(message) = handle_controller_command(
                    controller,
                    ownership,
                    attach_credentials,
                    attach_plan_signer,
                    NodeId::from_bytes(node_id),
                    sessions,
                    command,
                ) {
                    report_controller_worker_failure(
                        events,
                        custody,
                        ControllerResidentCauseV1::Worker(message),
                    );
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                report_controller_worker_failure(
                    events,
                    custody,
                    ControllerResidentCauseV1::Worker(
                        "controller command channel disconnected".to_owned(),
                    ),
                );
                return;
            }
        }
    }
}

fn report_controller_worker_failure(
    events: &mpsc::Sender<WorkerEvent>,
    custody: Option<&ControllerWorkerCustodyV1>,
    cause: ControllerResidentCauseV1,
) {
    if let Some(owner) = custody {
        // Store the actual cause before allocating diagnostics or notifying.
        // The parent resolves a fixed marker without waiting on this owner loan.
        owner.close(cause);
        if let Err(cause) = events.send(WorkerEvent::ResidentFailure) {
            owner.close(ControllerResidentCauseV1::ReadySend(cause));
        }
    } else {
        let message = match cause {
            ControllerResidentCauseV1::Worker(message) => message,
            ControllerResidentCauseV1::Runtime(ControllerRuntimeError::SourceGenesisInput(cause)) => {
                cause.to_string()
            }
            ControllerResidentCauseV1::Runtime(ControllerRuntimeError::NormalRootProfile(cause)) => {
                cause.to_string()
            }
            _ => "controller worker closed".to_owned(),
        };
        let _ = events.send(WorkerEvent::Fatal(message));
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
        ControllerCommand::InspectGitRead { .. } => std::process::abort(),
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
            let repair = operator_repair::is_repair(&canonical_request);
            if matches!(repair, Ok(true)) && !operator_repair::QUALIFIED {
                let _ = reply.send(Err(ControllerCommandFailure::ControllerUnavailable));
                return Ok(());
            }
            let admitted = match repair {
                Ok(true) => operator_repair::admit(
                    controller, &peer, capability_id, &canonical_request,
                    attach_plan_signer, node, sessions,
                ),
                Ok(false) => controller.admit_public_operator_recovery(
                    &peer, capability_id, &canonical_request,
                ),
                Err(error) => Err(error),
            };
            let operation_id = match admitted {
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
        Ok(WorkerEvent::ResidentFailure) => Err(ControllerRuntimeError::Worker(
            "controller worker retained its original failure".to_owned(),
        )),
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
    // Required failure closes before reconnect can release either the old
    // Storage session or the original guest-root exchange. No replacement
    // owner may overtake a failed/unfinished verified cold flight.
    if sessions
        .storage_cold
        .as_ref()
        .is_some_and(crate::handshake::RetainedStorageColdOpenV1::is_failed)
    {
        if let Some(worker) = sessions
            .storage_terminal
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            worker.close(ControllerResidentCauseV1::StorageCold);
        }
        return Err(CycleFailure::Fatal(
            "resident Storage cold admission is closed".to_owned(),
        ));
    }
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
        if let Some(image) = sessions.launch_image.as_ref() {
            // A genuine Required image selects the SAME parent-held worker
            // destination, including when no Publisher was supplied.
            let worker = sessions
                .storage_terminal
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .ok_or_else(|| {
                    CycleFailure::Fatal(
                        "Required Storage has no resident Controller destination".to_owned(),
                    )
                })?;
            let session = connect_retained_controller_storage(
                node_id,
                image,
                &mut sessions.storage_cold,
                &worker,
            )?;
            sessions.storage = Some(
                crate::DormantStorageLifecycleInventoryOwnerV1::from_protected_session(session),
            );
        } else {
            sessions.storage = Some(
                crate::DormantStorageLifecycleInventoryOwnerV1::from_protected_session(
                    connect_controller_storage_session(
                        crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
                        node_id,
                        sessions.launch_image.as_ref(),
                    )?,
                ),
            );
        }
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

/// Borrows the actual fixed image and resident destination for one cold flight.
fn connect_retained_controller_storage(
    node_id: [u8; 16],
    image: &crate::production_startup::Pid1LaunchImageV1,
    cold: &mut Option<crate::handshake::RetainedStorageColdOpenV1>,
    worker: &ControllerWorkerCustodyV1,
) -> Result<crate::DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(
        crate::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
    )
    .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let custody = custody
        .retain_launch_image(Some(image.clone()))
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let deadline = crate::handshake::OriginalBrokerColdDeadlineV1::controller()
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;

    match custody.connect_retained_storage_session(deadline, cold, node_id) {
        Ok(session) => Ok(session),
        Err(error) if cold.is_some() => {
            worker.close(ControllerResidentCauseV1::StorageCold);
            // Diagnostic projection only: the typed cause, packets, writers,
            // physical owners and debt remain in the SAME cold slot.
            Err(CycleFailure::Fatal(error.to_string()))
        }
        Err(error) => Err(classify_protected_handshake_error(error)),
    }
}

fn connect_controller_session(
    endpoint: crate::ProtectedBrokerSessionFixedEndpointV1,
    node_id: [u8; 16],
) -> Result<crate::DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    connect_controller_storage_session(endpoint, node_id, None)
}

fn connect_controller_storage_session(
    endpoint: crate::ProtectedBrokerSessionFixedEndpointV1,
    node_id: [u8; 16],
    launch_image: Option<&crate::production_startup::Pid1LaunchImageV1>,
) -> Result<crate::DormantAuthenticatedBrokerSessionV1, CycleFailure> {
    let custody = crate::ProtectedBrokerSessionFixedCustodyV1::open_fixed_protected(endpoint)
        .map_err(|error| CycleFailure::Fatal(error.to_string()))?;
    let custody = custody
        .retain_launch_image(launch_image.cloned())
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
    nix_start: Option<Arc<ControllerNixStartRecipeSelectorV2>>,
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
        nix_start,
    )
}

fn controller_from_journal(
    mut journal: Journal,
    node_id: [u8; 16],
    sessions: SharedControllerBrokerSessions,
    controller_uid: u32,
    attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
    attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
    nix_start: Option<Arc<ControllerNixStartRecipeSelectorV2>>,
) -> Result<ProductionController, ControllerRuntimeError> {
    validate_controller_journal(&mut journal, node_id)?;
    let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes(REQUEST_SCOPE))?;
    let limits = NodeControllerLimits::new(1024 * 1024, 65_536, 1)?;
    let executor = ProductionEffectExecutor::open(
        &mut journal,
        sessions,
        scope,
        controller_uid,
        NodeId::from_bytes(node_id),
        attachment_host,
        attachment_mount,
    )?;
    let compiler = match nix_start {
        Some(selector) => ProductionOperationCompilerV1::with_nix_start(selector),
        None => ProductionOperationCompilerV1::new(),
    };
    Ok(NodeController::new(
        scope,
        limits,
        compiler,
        Reconciler::new(journal, executor),
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
    read_optional_bounded_role_credential_v1(
        Path::new(&directory),
        CACHE_REPLAY_BUNDLE_CREDENTIAL,
        1,
        MAXIMUM_CACHE_REPLAY_BUNDLE_BYTES,
        true,
        CredentialOwnerPolicyV1::RootOrCurrent,
    )
    .map_err(|_| ControllerRuntimeError::InvalidCacheReplayBundle)
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
    git_upload_bootstrap: bool,
    git_read_inspection: Option<(u32, u32)>,
    nix_start_admission: bool,
    issue_source_successor: bool,
}

impl RuntimeConfiguration {
    fn from_process() -> Result<Self, ControllerRuntimeError> {
        Self::from_arguments(std::env::args())
    }

    fn from_arguments(
        mut arguments: impl Iterator<Item = String>,
    ) -> Result<Self, ControllerRuntimeError> {
        let _program = arguments.next();
        let uid = parse_identity(arguments.next(), "controller UID")?;
        let gid = parse_identity(arguments.next(), "controller GID")?;
        let mut public_api = false;
        let mut publisher_ingress = false;
        let mut git_upload_bootstrap = false;
        let mut git_read_inspection = None;
        let mut nix_start_admission = false;
        let mut issue_source_successor = false;
        for argument in arguments {
            match argument.as_str() {
                "--public-api" if !public_api => public_api = true,
                "--publisher-ingress" if !publisher_ingress => publisher_ingress = true,
                "--git-upload-bootstrap" if !git_upload_bootstrap => git_upload_bootstrap = true,
                "--nix-start-admission" if !nix_start_admission => nix_start_admission = true,
                "--issue-source-successor" if !issue_source_successor => {
                    issue_source_successor = true;
                }
                value if value.starts_with("--git-read-inspection=")
                    && git_read_inspection.is_none() => {
                    let pair = &value["--git-read-inspection=".len()..];
                    let Some((gateway_uid, gateway_gid)) = pair.split_once(':') else {
                        return Err(ControllerRuntimeError::InvalidArguments("Git role tuple"));
                    };
                    let parse = |value: &str| -> Result<u32, ControllerRuntimeError> {
                        let parsed = value.parse::<u32>().map_err(|_| {
                            ControllerRuntimeError::InvalidArguments("Git role identity")
                        })?;
                        if parsed == 0 || parsed >= 65_536 || parsed.to_string() != value {
                            return Err(ControllerRuntimeError::InvalidArguments("Git role identity"));
                        }
                        Ok(parsed)
                    };
                    let gateway = (parse(gateway_uid)?, parse(gateway_gid)?);
                    if gateway.0 == uid || gateway.1 == gid {
                        return Err(ControllerRuntimeError::InvalidArguments("Git roles overlap"));
                    }
                    git_read_inspection = Some(gateway);
                }
                _ => {
                    return Err(ControllerRuntimeError::InvalidArguments(
                        "unknown or duplicate activation flag",
                    ));
                }
            }
        }
        if issue_source_successor
            && (public_api || publisher_ingress || nix_start_admission || git_upload_bootstrap
                || git_read_inspection.is_some())
        {
            return Err(ControllerRuntimeError::InvalidArguments(
                "issue mode is exclusive",
            ));
        }
        if git_upload_bootstrap && !publisher_ingress {
            return Err(ControllerRuntimeError::InvalidArguments(
                "Git bootstrap requires original publisher ingress",
            ));
        }
        if git_read_inspection.is_some() && !(public_api && publisher_ingress && git_upload_bootstrap) {
            return Err(ControllerRuntimeError::InvalidArguments(
                "Git inspection requires public credentials and original Cache bootstrap",
            ));
        }
        Ok(Self {
            uid,
            gid,
            state_directory: PathBuf::from(STATE_DIRECTORY),
            diagnostic_socket: PathBuf::from(DIAGNOSTIC_SOCKET),
            public_api,
            publisher_ingress,
            git_upload_bootstrap,
            git_read_inspection,
            nix_start_admission,
            issue_source_successor,
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
    request_scope: ControllerRequestScopeV1,
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
    cache_resident_usage: aos_sandbox::cache_residency::CacheResidentInitializationV1,
    cache_mutation: cache_mutation::ControllerCacheMutationV1,
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
        journal: &mut Journal,
        sessions: SharedControllerBrokerSessions,
        request_scope: ControllerRequestScopeV1,
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
        validate_process_controller_hold_credentials_v1(
            broker_plan_signer
                .as_ref()
                .map(ControllerBrokerPlanSignerV1::verifying_key_bytes),
        )
        .map_err(|_| ControllerRuntimeError::InvalidControllerHoldCredential)?;
        let (mut source_domains, _) =
            ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(controller_uid)?;
        aos_sandbox::lifecycle::LifecycleProtectedJournalOwnerV1::claim(&mut source_domains)?
            .replay()?;
        crate::project_admission_coordinator::recover_source_project_admission_v1(
            journal,
            &mut source_domains,
            request_scope,
        )
        .map_err(ControllerRuntimeError::ProjectAdmissionRecovery)?;

        Ok(Self::from_retained_source(
            sessions,
            request_scope,
            broker_plan_signer,
            attachment_host,
            attachment_mount,
            source_domains,
            controller_uid,
            node,
            current_boot_and_boottime(),
        ))
    }

    // All fallible admission precedes this infallible move. Ordinary opening
    // retains its old checks/order; issue mode supplies its parked SAME owner.
    fn from_retained_source(
        sessions: SharedControllerBrokerSessions,
        request_scope: ControllerRequestScopeV1,
        broker_plan_signer: Option<ControllerBrokerPlanSignerV1>,
        attachment_host: Option<aos_sandbox::runtime_scope::HostServiceIdentity>,
        attachment_mount: Option<aos_sandbox::mount_preparation::MountServiceIdentity>,
        source_domains: ProtectedSourceDomainJournalOwnerV1,
        controller_uid: u32,
        node: NodeId,
        process_start: Option<([u8; 16], u64)>,
    ) -> Self {
        Self {
            sessions,
            request_scope,
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
            cache_resident_usage: aos_sandbox::cache_residency::CacheResidentInitializationV1::new(),
            cache_mutation: cache_mutation::ControllerCacheMutationV1::default(),
            cache_physical: None,
            cache_physical_limits: None,
            pending_cache_pin: None,
            pending_cache_unpin: None,
            controller_uid,
            transfer_inventory: None,
            node,
            process_start,
            pending_source_commit: None,
            pending_atomic_snapshot: None,
        }
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

    fn require_current_create_effect(
        &mut self,
        operation_id: OperationId,
        plan: &EffectPlan,
        journal: &mut Journal,
    ) -> Result<aos_sandbox::policy_compiler::CurrentCreateProjectPolicySourceV1, EffectFailure>
    {
        // A generic lifecycle recovery must never become a Create receipt.
        if self.pending_source_commit.is_some() {
            return Err(EffectFailure::Retryable(
                "protected source commit recovery is pending".to_owned(),
            ));
        }
        let context = self.public_mutation_context(plan)?;
        if !matches!(
            context
                .validated_request()
                .map_err(|error| EffectFailure::Permanent(error.to_string()))?,
            DormantSandboxRequestKindV1::Create(_)
        ) {
            return Err(EffectFailure::Permanent(
                "Create effect has the wrong admitted request".to_owned(),
            ));
        }
        require_current_parentless_create_source(
            operation_id,
            context.project(),
            self.request_scope,
            plan,
            journal,
        )
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
        if self.cache_resident_usage.started() {
            self.cache_resident_usage.fence_unsupported_transition();
            return Err(EffectFailure::Permanent(
                "legacy Cache transition is unsupported under resident custody".to_owned(),
            ));
        }
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
        if self.cache_resident_usage.started() {
            let protected = self.cache_inventory.as_mut().ok_or_else(|| {
                EffectFailure::Permanent("resident protected Cache inventory is unavailable".to_owned())
            })?;
            return self.cache_resident_usage.prepare_existing_physical_owner(
                protected, &mut self.cache_physical, self.node, CACHE_OWNER_MEMORY_BYTES,
            ).map_err(|_| self.resident_cache_failure());
        }
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

fn require_current_parentless_create_source(
    operation: OperationId,
    project: ProjectId,
    scope: ControllerRequestScopeV1,
    effect_plan: &EffectPlan,
    journal: &mut Journal,
) -> Result<aos_sandbox::policy_compiler::CurrentCreateProjectPolicySourceV1, EffectFailure> {
    aos_sandbox::policy_compiler::current_parentless_create_project_source_for_operation_v1(
        journal,
        operation,
        project,
        scope,
        effect_plan,
    )
    .map_err(|error| {
        EffectFailure::Retryable(format!("admitted Create source is not current: {error}"))
    })
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

fn reject_unqualified_delete_effect(plan: &EffectPlan) -> Result<(), EffectFailure> {
    if plan.public_mutation_method()
        == Some(aos_sandbox::controller_query::PublicOperationMethodV1::DeleteSandbox)
    {
        // Retained operations cannot run until the protected dependency plan exists.
        return Err(EffectFailure::Permanent(
            "sandbox deletion awaits a protected dependency plan".to_owned(),
        ));
    }

    Ok(())
}

impl SingleNodeEffectExecutor for ProductionEffectExecutor {
    fn existing_cache_project_usage_v1(
        &mut self,
        project: aos_sandbox_core::ProjectId,
    ) -> Result<aos_sandbox::cache_residency::CacheProjectUsageLoanV1<'_>, aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.observe_existing_cache_usage(project)
    }

    fn recheck_existing_cache_project_usage_v1(
        &mut self,
    ) -> Result<(), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.cache_mutation.require_completed_or_empty()?;
        let owner = self.cache_inventory.as_mut()
            .ok_or(aos_sandbox::cache_residency::CacheResidentUnavailableV1)?;
        self.cache_resident_usage.recheck(owner)
    }

    fn reconcile_operator_storage_repair(
        &mut self,
        operation_id: OperationId,
        step: u32,
        plan: &EffectPlan,
        journal: &mut Journal,
        completion_wall_seconds: i64,
    ) -> Result<aos_sandbox::OperatorStorageRepairReconcileV1, EffectFailure> {
        operator_repair::reconcile(self, operation_id, step, plan, journal, completion_wall_seconds)
    }

    fn coordinate_provisioned_source_genesis_v1(
        &mut self,
        journal: &mut Journal,
        input: &ProvisionedControllerSourceGenesisInputV1,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, ControllerSourceGenesisInputErrorV1> {
        // This is the existing fixed Controller-purpose role, independently
        // pinned by Root. It supplies no administrative seed or Root authority.
        with_process_controller_hold_signer_v1(|generation, signer| {
            Ok(
                aos_sandbox::policy_compiler::coordinate_provisioned_source_genesis_v1(
                    journal,
                    &mut self.source_domains,
                    input,
                    profile,
                    generation,
                    signer,
                ),
            )
        })
        .map_err(aos_sandbox::hierarchy::genesis_profile::SourceGenesisErrorV1::from)?
    }

    fn issue_source_successor_v2<'writers, 'profile, 'credentials>(
        &'writers mut self,
        journal: &'writers mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut aos_sandbox::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<
        aos_sandbox::hierarchy::source_successor::SourceSuccessorApprovalDataV2,
        aos_sandbox::policy_compiler::FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
    > {
        let mut original = aos_sandbox::policy_compiler::OriginalSourceSuccessorInvocationV2::park(
            journal, &mut self.source_domains, profile, credentials,
        );
        if let Err(cause) = with_process_controller_hold_signer_v1(|generation, signer| {
            original.run_with_controller_signer(generation, signer);
            Ok(())
        }) {
            original.fail_controller_signer_admission(cause);
        }
        original.into_outcome()
    }

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
        reject_unqualified_delete_effect(plan)?;

        if plan.public_mutation_context()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .is_some_and(|context| context.has_retained_nix_start())
        {
            // Admission is real, but no namespace47 floor/archive/publication
            // owner exists in this slice. Generic lifecycle cannot stand in.
            return Ok(EffectObservation::Absent);
        }

        if plan.public_mutation_method()
            == Some(aos_sandbox::controller_query::PublicOperationMethodV1::CreateSandbox)
        {
            self.require_current_create_effect(operation_id, plan, journal)?;
            return Ok(EffectObservation::Absent);
        }

        if let Some(observation) = self.recover_pending_source_commit(operation_id)? {
            return Ok(observation);
        }
        let context = self.public_mutation_context(plan)?;
        if plan.public_mutation_method()
            == Some(aos_sandbox::controller_query::PublicOperationMethodV1::CreateExecution)
        {
            execution_output_effect::observe(self, operation_id, &context, journal)?;
            return Ok(EffectObservation::Absent);
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox::controller_query::PublicOperationMethodV1::ControlExecution
                    | aos_sandbox::controller_query::PublicOperationMethodV1::CancelExecution
            )
        ) {
            let intent = execution::ControllerExecutionIntentV1::from_request(
                operation_id,
                &context,
                journal,
            )?;
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
        reject_unqualified_delete_effect(plan)?;

        if plan.public_mutation_context()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .is_some_and(|context| context.has_retained_nix_start())
        {
            return Err(EffectFailure::Retryable(
                "retained Nix Start awaits genuine session floor and recipe publication owners".to_owned(),
            ));
        }

        if plan.public_mutation_method()
            == Some(aos_sandbox::controller_query::PublicOperationMethodV1::CreateSandbox)
        {
            let source = self.require_current_create_effect(operation_id, plan, journal)?;
            let progress =
                crate::project_admission_coordinator::advance_create_project_admission_v1(
                    journal,
                    &mut self.source_domains,
                    &source,
                    self.request_scope,
                    plan,
                )
                .map_err(|error| {
                    EffectFailure::Retryable(format!(
                        "protected project admission is pending: {error}"
                    ))
                })?;
            if matches!(
                progress,
                crate::project_admission_coordinator::ProjectAdmissionProgressV1::RetiredPrior
            ) {
                return Err(EffectFailure::Retryable(
                    "prior project admission was retired; retry exact Create".to_owned(),
                ));
            }
            // V2 source admission is a prerequisite, not the held four-owner
            // compiler publication or a public Create completion.
            return Err(EffectFailure::Retryable(
                CREATE_Q04_AUTHORITY_PENDING.to_owned(),
            ));
        }

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
        if plan.public_mutation_method()
            == Some(aos_sandbox::controller_query::PublicOperationMethodV1::CreateExecution)
        {
            execution_output_effect::apply(self, operation_id, &context, journal)?;
            return Err(EffectFailure::Retryable(
                "execution Create awaits physical Storage backing and Host launch".to_owned(),
            ));
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox::controller_query::PublicOperationMethodV1::ControlExecution
                    | aos_sandbox::controller_query::PublicOperationMethodV1::CancelExecution
            )
        ) {
            let intent = execution::ControllerExecutionIntentV1::from_request(
                operation_id,
                &context,
                journal,
            )?;
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
    ResidentFailure,
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
    /// The selected original Nix startup or fixed recipe credentials failed admission.
    #[error(transparent)]
    NixStartAdmission(#[from] NixStartAdmissionErrorV2),
    /// Pre-Q04 project admission could not be replayed to an exact Root outcome.
    #[error("controller project-admission recovery failed: {0}")]
    ProjectAdmissionRecovery(std::io::Error),
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
    /// The optional Controller hold seed and role pin are unsafe or inconsistent.
    #[error("protected Controller hold readback credentials are invalid")]
    InvalidControllerHoldCredential,
    /// Protected Source genesis delivery or read-only current-cut validation failed.
    #[error(transparent)]
    SourceGenesisInput(#[from] ControllerSourceGenesisInputErrorV1),
    /// The original image-selected normal-Root comparison inputs differ.
    #[error("normal Root selected-profile custody failed: {0}")]
    NormalRootProfile(#[source] aos_sandbox::normal_root::NormalRootStartupErrorV1),
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
    use buffa::Message as _;

    // These vectors exercise DATA/negative bookkeeping and actual std channel
    // errors only. They do not construct a positive original startup owner.
    #[test]
    fn partial_controller_stage_cannot_skip_or_repeat_a_crossing() {
        let mut skipped = ControllerParentStageV1::Prepared;
        let mut repeated = ControllerParentStageV1::Prepared;
        let mut mismatched = ControllerParentStageV1::Prepared;
        let mut completed = ControllerParentStageV1::Prepared;

        assert!(!skipped.begin(ControllerParentStepV1::Node));
        assert!(!skipped.begin(ControllerParentStepV1::Publisher));

        assert!(repeated.begin(ControllerParentStepV1::Publisher));
        assert!(!repeated.begin(ControllerParentStepV1::Publisher));
        assert!(!repeated.complete(ControllerParentStepV1::Publisher));

        assert!(mismatched.begin(ControllerParentStepV1::Publisher));
        assert!(!mismatched.complete(ControllerParentStepV1::Node));
        assert!(!mismatched.complete(ControllerParentStepV1::Publisher));

        assert!(completed.begin(ControllerParentStepV1::Publisher));
        assert!(completed.complete(ControllerParentStepV1::Publisher));
        assert!(completed.begin(ControllerParentStepV1::Node));
        assert!(completed.complete(ControllerParentStepV1::Node));
        assert!(!completed.complete(ControllerParentStepV1::Node));
    }

    #[test]
    fn partial_optional_absence_does_not_create_a_worker_loan() {
        let mut originals = ControllerWorkerOriginalsV1::default();
        assert!(originals.genesis.is_none());

        originals.genesis = Some(None);
        originals.nix_selector = Some(None);
        originals.cache_bundle = Some(None);
        originals.publisher_registration = Some(None);

        assert!(matches!(originals.genesis, Some(None)));
        assert!(originals.ready_loan().is_none());
        assert!(!originals.complete_worker_inputs(&ControllerParentStageV1::Prepared));
        assert!(!originals.complete_worker_inputs(&ControllerParentStageV1::Completed(
            ControllerParentStepV1::Commands,
        )));
    }

    fn empty_controller_test_custody() -> ControllerWorkerCustodyV1 {
        ControllerWorkerCustodyV1 {
            originals: Mutex::new(ControllerWorkerOriginalsV1::default()),
            terminal: Mutex::new(None),
            receiver: Mutex::new(None),
            ended: AtomicBool::new(false),
        }
    }

    #[test]
    fn terminal_close_does_not_wait_on_the_worker_owner_loan() {
        let custody = empty_controller_test_custody();
        let _owner_loan = custody.originals.lock().unwrap();
        let message = "original worker cause".to_owned();
        let original_buffer = message.as_ptr();

        custody.close(ControllerResidentCauseV1::Worker(message));
        custody.close(ControllerResidentCauseV1::Closed("later failure"));

        assert!(custody.ended.load(Ordering::Acquire));
        let terminal = custody.terminal.lock().unwrap();
        assert!(matches!(
            terminal.as_ref(),
            Some(ControllerResidentCauseV1::Worker(message))
                if message.as_ptr() == original_buffer && message == "original worker cause"
        ));
    }

    #[test]
    fn ready_send_failure_retains_the_actual_returned_send_error() {
        let custody = empty_controller_test_custody();
        let (sender, receiver) = mpsc::channel();
        drop(receiver);
        let cause = match sender.send(WorkerEvent::Ready) {
            Err(cause) => cause,
            Ok(()) => panic!("disconnected actual channel unexpectedly accepted readiness"),
        };

        custody.close(ControllerResidentCauseV1::ReadySend(cause));

        let terminal = custody.terminal.lock().unwrap();
        assert!(matches!(
            terminal.as_ref(),
            Some(ControllerResidentCauseV1::ReadySend(mpsc::SendError(WorkerEvent::Ready)))
        ));
    }

    #[test]
    fn original_event_receiver_stays_in_its_slot_after_reception() {
        let custody = empty_controller_test_custody();
        let (sender, receiver) = mpsc::channel();
        *custody.receiver.lock().unwrap() = Some(receiver);
        assert!(sender.send(WorkerEvent::Ready).is_ok());

        let observed = custody.receive();

        assert!(matches!(
            observed,
            ControllerMonitorOutcomeV1::Event(WorkerEvent::Ready)
        ));
        assert!(custody.receiver.lock().unwrap().is_some());
        assert!(!custody.ended.load(Ordering::Acquire));
    }

    #[test]
    fn selected_worker_failure_parks_cause_before_marker_notification() {
        let custody = empty_controller_test_custody();
        let (sender, receiver) = mpsc::channel();
        let original = "original returned worker failure".to_owned();
        let original_buffer = original.as_ptr();

        report_controller_worker_failure(
            &sender,
            Some(&custody),
            ControllerResidentCauseV1::Worker(original),
        );

        assert!(matches!(receiver.recv(), Ok(WorkerEvent::ResidentFailure)));
        let terminal = custody.terminal.lock().unwrap();
        assert!(matches!(
            terminal.as_ref(),
            Some(ControllerResidentCauseV1::Worker(cause)) if cause.as_ptr() == original_buffer
        ));
        assert!(custody.ended.load(Ordering::Acquire));
    }

    #[test]
    fn actual_partial_destination_types_are_send_and_shared_holder_is_sync() {
        fn require_send<T: Send>() {}
        fn require_sync<T: Sync>() {}

        require_send::<ControllerWorkerOriginalsV1>();
        require_send::<ControllerResidentCauseV1>();
        require_sync::<ControllerWorkerCustodyV1>();
    }

    #[test]
    fn source_successor_issue_mode_is_exclusive_and_keeps_fixed_paths() {
        let configuration = RuntimeConfiguration::from_arguments(
            ["aos-sandboxd", "1001", "1002", "--issue-source-successor"]
                .map(str::to_owned).into_iter(),
        ).unwrap();

        assert!(configuration.issue_source_successor);
        assert!(!configuration.public_api);
        assert!(!configuration.publisher_ingress);
        assert!(!configuration.nix_start_admission);
        assert_eq!(configuration.state_directory, PathBuf::from(STATE_DIRECTORY));
        assert_eq!(configuration.diagnostic_socket, PathBuf::from(DIAGNOSTIC_SOCKET));

        for other in ["--public-api", "--publisher-ingress", "--nix-start-admission"] {
            for flags in [["--issue-source-successor", other], [other, "--issue-source-successor"]] {
                let arguments = ["aos-sandboxd", "1001", "1002"]
                    .into_iter().chain(flags).map(str::to_owned);
                assert!(matches!(
                    RuntimeConfiguration::from_arguments(arguments),
                    Err(ControllerRuntimeError::InvalidArguments("issue mode is exclusive")),
                ));
            }
        }
    }

    #[test]
    fn source_successor_issue_mode_defaults_absent_and_rejects_aliases_or_duplicates() {
        let normal = RuntimeConfiguration::from_arguments(
            ["aos-sandboxd", "1001", "1002"].map(str::to_owned).into_iter(),
        ).unwrap();

        assert!(!normal.issue_source_successor);
        for flags in [
            vec!["--issue-source-successor", "--issue-source-successor"],
            vec!["--issue-source-successor=true"],
            vec!["--source-successor"],
        ] {
            let arguments = ["aos-sandboxd", "1001", "1002"]
                .into_iter().chain(flags).map(str::to_owned);
            assert!(matches!(
                RuntimeConfiguration::from_arguments(arguments),
                Err(ControllerRuntimeError::InvalidArguments("unknown or duplicate activation flag")),
            ));
        }
    }

    #[test]
    fn nix_start_admission_defaults_closed_without_changing_fixed_paths() {
        let configuration = RuntimeConfiguration::from_arguments(
            ["aos-sandboxd", "1001", "1002"].map(str::to_owned).into_iter(),
        )
        .unwrap();

        assert_eq!(configuration.uid, 1001);
        assert_eq!(configuration.gid, 1002);
        assert_eq!(
            configuration.state_directory,
            PathBuf::from(STATE_DIRECTORY)
        );
        assert_eq!(
            configuration.diagnostic_socket,
            PathBuf::from(DIAGNOSTIC_SOCKET)
        );
        assert!(!configuration.public_api);
        assert!(!configuration.publisher_ingress);
        assert!(!configuration.nix_start_admission);
    }

    #[test]
    fn legacy_activation_flags_do_not_select_nix_admission() {
        for flags in [
            vec!["--public-api"],
            vec!["--publisher-ingress"],
            vec!["--public-api", "--publisher-ingress"],
            vec!["--publisher-ingress", "--public-api"],
        ] {
            let arguments = ["aos-sandboxd", "1001", "1002"]
                .into_iter()
                .chain(flags)
                .map(str::to_owned);
            let configuration = RuntimeConfiguration::from_arguments(arguments).unwrap();

            assert_eq!(configuration.uid, 1001);
            assert_eq!(configuration.gid, 1002);
            assert!(!configuration.nix_start_admission);
        }
    }

    #[test]
    fn nix_start_admission_flag_composes_with_each_existing_flag_order() {
        for flags in [
            ["--nix-start-admission", "--public-api", "--publisher-ingress"],
            ["--nix-start-admission", "--publisher-ingress", "--public-api"],
            ["--public-api", "--nix-start-admission", "--publisher-ingress"],
            ["--public-api", "--publisher-ingress", "--nix-start-admission"],
            ["--publisher-ingress", "--nix-start-admission", "--public-api"],
            ["--publisher-ingress", "--public-api", "--nix-start-admission"],
        ] {
            let arguments = ["aos-sandboxd", "1001", "1002"]
                .into_iter()
                .chain(flags)
                .map(str::to_owned);
            let configuration = RuntimeConfiguration::from_arguments(arguments).unwrap();

            assert!(configuration.public_api);
            assert!(configuration.publisher_ingress);
            assert!(configuration.nix_start_admission);
        }
    }

    #[test]
    fn activation_flags_reject_duplicates_and_unknown_nix_spellings() {
        for flags in [
            vec!["--nix-start-admission", "--nix-start-admission"],
            vec!["--public-api", "--public-api"],
            vec!["--publisher-ingress", "--publisher-ingress"],
            vec!["--nix-start-admission=true"],
            vec!["--nix-build"],
            vec!["--unknown"],
        ] {
            let arguments = ["aos-sandboxd", "1001", "1002"]
                .into_iter()
                .chain(flags)
                .map(str::to_owned);
            let error = RuntimeConfiguration::from_arguments(arguments).unwrap_err();

            assert!(matches!(
                error,
                ControllerRuntimeError::InvalidArguments("unknown or duplicate activation flag")
            ));
        }
    }

    #[test]
    fn activation_identity_errors_keep_their_original_precedence() {
        for (arguments, expected) in [
            (vec!["aos-sandboxd"], "controller UID"),
            (
                vec!["aos-sandboxd", "bad", "--nix-start-admission"],
                "controller UID",
            ),
            (vec!["aos-sandboxd", "1001"], "controller GID"),
            (
                vec!["aos-sandboxd", "1001", "bad", "--unknown"],
                "controller GID",
            ),
        ] {
            let error = RuntimeConfiguration::from_arguments(
                arguments.into_iter().map(str::to_owned),
            )
            .unwrap_err();

            assert!(matches!(
                error,
                ControllerRuntimeError::InvalidArguments(label) if label == expected
            ));
        }
    }

    #[test]
    fn nix_admission_error_is_retained_without_a_success_label() {
        let error = ControllerRuntimeError::from(NixStartAdmissionErrorV2::Invalid);

        assert!(matches!(
            error,
            ControllerRuntimeError::NixStartAdmission(NixStartAdmissionErrorV2::Invalid)
        ));
    }

    #[test]
    fn retained_public_delete_effect_is_permanently_blocked() {
        let request = aos_proto::aos::sandbox::v1::DeleteSandboxRequest {
            sandbox_id: vec![0x11; 16],
            expected_plan_digest: vec![0x22; 32],
            mutation: Some(aos_proto::aos::sandbox::v1::MutationContext {
                idempotency_key: vec![0x33; 16],
                expected_resource_version: vec![0x44; 32],
                operation_timeout: Some(aos_proto::aos::sandbox::v1::Duration {
                    nanoseconds: 1,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let envelope = aos_sandbox::cli_model::PublicMutationRequestV1::new(
            aos_sandbox::cli_model::PublicApiAuditMethodV1::DeleteSandbox,
            &request.encode_to_vec(),
        )
        .unwrap()
        .encode();
        let effect = EffectPlan::authorized_public_mutation(
            aos_sandbox::controller_query::PublicOperationMethodV1::DeleteSandbox,
            PublicMutationEffectV1::new(
                aos_sandbox_core::PrincipalId::from_bytes([0x55; 16]),
                aos_sandbox_core::ProjectId::from_bytes([0x66; 16]),
                1,
                envelope,
            )
            .unwrap(),
        )
        .unwrap();

        assert!(matches!(
            reject_unqualified_delete_effect(&effect),
            Err(EffectFailure::Permanent(_))
        ));
    }

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

    fn diagnostic_configuration(directory: &tempfile::TempDir) -> RuntimeConfiguration {
        RuntimeConfiguration {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            state_directory: directory.path().join("state"),
            diagnostic_socket: directory.path().join("diagnostics.sock"),
            public_api: false,
            publisher_ingress: false,
            git_upload_bootstrap: false,
            git_read_inspection: None,
            nix_start_admission: false,
            issue_source_successor: false,
        }
    }

    #[test]
    fn git_bootstrap_is_default_off_and_requires_original_publisher_ingress() {
        let parse = |flags: &[&str]| RuntimeConfiguration::from_arguments(
            ["sandboxd", "1000", "1000"].into_iter()
                .chain(flags.iter().copied()).map(str::to_owned),
        );

        assert!(!parse(&[]).unwrap().git_upload_bootstrap);
        assert!(parse(&["--git-upload-bootstrap"]).is_err());
        assert!(parse(&["--publisher-ingress", "--git-upload-bootstrap"]).unwrap().git_upload_bootstrap);
        assert!(parse(&["--publisher-ingress", "--git-upload-bootstrap", "--issue-source-successor"]).is_err());
        assert!(parse(&["--publisher-ingress", "--git-upload-bootstrap", "--git-upload-bootstrap"]).is_err());
    }

    #[test]
    fn git_inspection_requires_closed_roles_and_existing_producers() {
        let parse = |flags: &[&str]| RuntimeConfiguration::from_arguments(
            ["sandboxd", "979", "979"].into_iter()
                .chain(flags.iter().copied()).map(str::to_owned),
        );
        let flags = ["--public-api", "--publisher-ingress", "--git-upload-bootstrap",
            "--git-read-inspection=980:980"];
        assert_eq!(parse(&flags).unwrap().git_read_inspection, Some((980, 980)));
        assert!(parse(&flags[3..]).is_err());
        for value in ["--git-read-inspection=979:980", "--git-read-inspection=0:980",
            "--git-read-inspection=0980:980", "--git-read-inspection=980:65536"]
        {
            assert!(parse(&[flags[0], flags[1], flags[2], value]).is_err());
        }
        assert!(parse(&[flags[0], flags[1], flags[2], flags[3], flags[3]]).is_err());
        assert!(parse(&[]).unwrap().git_read_inspection.is_none());
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

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification_host_inventory;
