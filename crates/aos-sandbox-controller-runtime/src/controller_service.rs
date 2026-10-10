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
//! pins are orchestrated by private activation with the installed startup recipe,
//! its terminal ordering and worker/server handoff, rather than a generic owner
//! framework. This does not retain callee-local failed constructors, task
//! populations or provider prefixes, nor establish funding, drain or readiness
//! for those missing paths.

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, RuntimeAction};
use aos_proto::aos::sandbox::v1::{Operation, OperationPhase, OperatorRecoveryAction};
use aos_sandbox_core::{
    AttachmentId, CapabilityId, NodeId, ObjectDigest, OperationId, ProjectId,
    RawClockProvenance, RawPairedClockSample, ResourceId,
};
use aos_sandbox_linux::boot::KernelBootId;
use sha2::{Digest as _, Sha256};

use crate::controller_service::attach_credentials::ControllerAttachCredentialsV1;
use crate::controller_service::cache_readback_credential::validate_process_cache_readback_credentials_v1;
use crate::controller_service::guest_root_credentials::load_guest_root_template_pins_optional;
use crate::controller_service::hold_credential::{
    validate_process_controller_hold_credentials_v1, with_process_controller_hold_signer_v1,
};
use crate::controller_service::ownership::ControllerOwnershipConfigurationV1;
use aos_sandbox_broker_session_security::controller_composition::sample_ownership_clock;
use crate::controller_service::plan_signer::ControllerBrokerPlanSignerV1;
use crate::controller_service::publication::ControllerHostPublication;
use aos_sandbox::cache_residency::{
    CacheOwnerLimitsV1, CacheReplayControllerBootstrapOwnerV1, CacheResidencyProtectedOwnerV1,
    DormantCacheOwnerV1,
};
use aos_sandbox::cli_model::PublicMutationRequestV1;
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
use aos_sandbox::controller::DormantControllerCompositionV1;
use aos_sandbox::journal::controller::{
    production_journal_limits, validate_controller_journal,
};
use aos_sandbox::hierarchy::controller_genesis_input::{
    ControllerSourceGenesisInputErrorV1, ProvisionedControllerSourceGenesisInputV1,
};
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::lifecycle::{
    LifecycleCancelIdempotencyDigestV1, LifecycleCurrentAuxiliaryPublicationV1,
    LifecycleIntentV1, LifecycleOperationAdmissionV1, LifecycleOperationV1,
    LifecycleProgressCommitOutcomeV1,
    LifecycleProgressOutcomeUnknownV1, LifecycleProgressRecoveryV1,
    LifecycleProtectedCancellationAdmissionV1, LifecycleProtectedCancellationResolutionV1,
    LifecycleProtectedJournalErrorV1,
    LifecycleProtectedRecordKindV1, LifecycleSnapshotBarrierV1, LifecycleSuspensionPlanV1,
    LifecycleTimeV1, lifecycle_operation_from_public_mutation_v1, lifecycle_protected_key_v1,
    lifecycle_public_mutation_admission_v1,
};
use aos_sandbox::production_operation_compiler::{
    ControllerNixStartRecipeSelectorV2, NixStartAdmissionErrorV2, ProductionOperationCompilerV1,
};
use aos_sandbox::{
    AcceptOutcome, ActivatedOperationCompiler, AuthorityEffectAttemptTimingV1,
    AuthorityEffectObservationV1, ControllerRequestScopeV1, ControllerServiceError, EffectFailure,
    EffectObservation, EffectPlan, EffectReceipt, GuardianPlanRequestV1,
    Journal, JournalError, NodeController, NodeControllerLimits, OperationCompilationError,
    PreparedAuthorityEffectV1,
    PublicMutationEffectV1, Reconciler, SingleNodeEffectExecutor,
    ValidatedAuthorityEffectReceiptV1, activated_ownership_gate_digest_from_journal_v1,
    prepare_runtime_lifecycle_authority_effect_v1, public_operation_resource_from_journal_v1,
};
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;

use resident_custody::{
    AbortControllerCustodyUnwindV1, ControllerMonitorOutcomeV1, ControllerParentCustodyV1,
    ControllerParentStepV1, ControllerResidentCauseV1, ControllerWorkerCustodyV1,
    ControllerWorkerOriginalsV1,
};

mod activation;
mod effects;
mod worker;
mod argument_exchange;
mod attach_credentials;
mod attach_exchange;
mod authority_effect;
mod cache_directory_source;
mod cache_index_buffer;
mod cache_public_pin;
mod cache_readback_credential;
mod cache_source_membership;
mod capture_candidate_exchange;
mod guest_root_credentials;
mod hold_credential;
pub(crate) mod inventory;
mod lifecycle_runtime_effect;
mod no_apply_exchange;
mod output_exchange;
mod ownership;
mod plan_signer;
mod project_admission;
mod publication;
mod resident_custody;

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
pub(crate) mod execution_output_storage_registration;
mod guest_root;
#[cfg(target_os = "linux")]
mod git_coverage;
mod git_read_inspection;
#[allow(
    dead_code,
    reason = "The default binary leaves local Nix input custody dormant; only the selected online Resolve caller consumes it"
)]
pub(crate) mod nix_inputs;
#[cfg(feature = "online-nix")]
mod nix_environment;
#[cfg(feature = "online-nix")]
pub(crate) mod nix_generation;
mod original_attach;
mod operator_repair;
mod create_q04;
pub mod assembly;
mod startup;

use assembly::{ControllerServerAssembly, ControllerServerTerminal};
mod commands;
mod public_attach;
mod public_rpc;

pub use activation::run_from_environment;
pub use public_rpc::CapabilityService;
use public_rpc::{CapabilityState, ControllerEndpoint};
use commands::{
    AdmittedPublicAttachV1, AdmittedPublicMutationV1, ControllerCommand,
    ControllerCommandFailure, ControllerCommandResponse, handle_controller_command,
};
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
const CACHE_OWNER_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const RECONCILIATION_INTERVAL: Duration = Duration::from_secs(5);
const ORIGINAL_ATTACH_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CONTROLLER_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROLLER_COMMAND_CAPACITY: usize = 64;
const REQUEST_SCOPE: [u8; 32] = [0x43; 32];
const UNAVAILABLE_REASON: &str = "production mutation authority is not installed";
const CONTROLLER_ORCHESTRATION_PENDING: &str =
    "controller mutation is awaiting production orchestration lowering";
const CREATE_Q04_AUTHORITY_PENDING: &str =
    "Create awaits authenticated Q04 compiler input and held owner custody";

use effects::{
    ProductionEffectExecutor, current_boot_and_boottime, current_lifecycle_time,
    lifecycle_plan_resource_id, lifecycle_progress_transaction_id, missing_broker_session,
    production_authority_effect_timing,
};

type ProductionController = NodeController<ProductionOperationCompilerV1, ProductionEffectExecutor>;
type SharedControllerBrokerSessions = Arc<Mutex<ControllerBrokerSessions>>;
type SnapshotOwnershipDonationV3 = Arc<OnceLock<ControllerOwnershipConfigurationV1>>;

/// Retains authenticated transports and their durable sequence owners across cycles.
#[derive(Default)]
struct ControllerBrokerSessions {
    nix_generation_enabled: bool,
    #[cfg(feature = "online-nix")]
    nix_resolve: Option<nix_environment::NixResolveAttemptV1>,
    #[cfg(feature = "online-nix")]
    nix_existing_outputs: bool,
    #[cfg(feature = "online-nix")]
    nix_input_source: Option<cache_directory_source::ProjectSealedViewObjectSourceV1>,
    launch_image: Option<aos_sandbox_broker_session_security::controller_composition::Pid1LaunchImageV1>,
    host: Option<ControllerHostPublication>,
    mount: Option<crate::DormantMountLifecycleInventoryOwnerV1>,
    storage: Option<crate::DormantStorageLifecycleInventoryOwnerV1>,
    storage_cold: Option<aos_sandbox_broker_session_security::controller_composition::RetainedStorageColdOpenV1>,
    storage_terminal: Option<std::sync::Weak<ControllerWorkerCustodyV1>>,
    storage_root: guest_root::ControllerGuestRootExchangeV1,
    network: Option<crate::DormantNetworkLifecycleInventoryOwnerV1>,
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
    ControllerJournal(#[from] aos_sandbox::journal::controller::ControllerJournalError),
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

    #[test]
    fn nix_admission_error_is_retained_without_a_success_label() {
        let error = ControllerRuntimeError::from(NixStartAdmissionErrorV2::Invalid);

        assert!(matches!(
            error,
            ControllerRuntimeError::NixStartAdmission(NixStartAdmissionErrorV2::Invalid)
        ));
    }
}

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification_mount_inventory;

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification_host_inventory;
