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
use aos_sandbox_linux::Error as LinuxError;
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_broker_session_security::controller_composition::HistoricalAtomicStorageHistoryDataV1;
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
use crate::controller_service::publication::{ControllerHostPublication, ControllerHostPublicationError};
use aos_sandbox::cache_residency::{
    CacheOwnerLimitsV1, CacheReplayControllerBootstrapOwnerV1, CacheResidencyProtectedOwnerV1,
    DormantCacheOwnerV1,
};
use aos_sandbox::cli_model::PublicMutationRequestV1;
use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
use aos_sandbox::controller::DormantControllerCompositionV1;
use aos_sandbox::controller_service::journal::{
    production_journal_limits, validate_controller_journal,
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
    LifecycleIntentV1, LifecycleOperationAdmissionV1, LifecycleOperationV1,
    LifecycleProgressCommitOutcomeV1,
    LifecycleProgressOutcomeUnknownV1, LifecycleProgressRecoveryV1,
    LifecycleProtectedCancellationAdmissionV1, LifecycleProtectedCancellationResolutionV1,
    LifecycleProtectedJournalErrorV1,
    LifecycleProtectedRecordKindV1, LifecycleSnapshotBarrierV1, LifecycleSuspensionPlanV1,
    LifecycleTimeV1, lifecycle_operation_from_public_mutation_v1, lifecycle_protected_key_v1,
    lifecycle_public_mutation_admission_v1,
};
use aos_sandbox::mount_preparation::MountCatalogPreparationError;
use aos_sandbox::production_operation_compiler::{
    ControllerNixStartRecipeSelectorV2, NixStartAdmissionErrorV2, ProductionOperationCompilerV1,
};
use aos_sandbox::{
    AcceptOutcome, ActivatedOperationCompiler, AuthorityEffectAttemptTimingV1,
    AuthorityEffectObservationV1, ControllerRequestScopeV1, ControllerServiceError, EffectFailure,
    EffectObservation, EffectPlan, EffectReceipt, GuardianPlanRequestV1,
    HostCatalogReconciliationError, HostCatalogReconciliationV1, Journal, JournalError,
    MountAttemptError, NodeController, NodeControllerLimits, OperationCompilationError,
    PreparedAuthorityEffectV1,
    PublicMutationEffectV1, Reconciler, ResourceInventoryError, SingleNodeEffectExecutor,
    ValidatedAuthorityEffectReceiptV1, activated_ownership_gate_digest_from_journal_v1,
    prepare_runtime_lifecycle_authority_effect_v1, public_operation_resource_from_journal_v1,
};
use aos_sandbox_protocol::authorization_artifact::SignedBrokerPlan;

use resident_custody::{
    AbortControllerCustodyUnwindV1, ControllerMonitorOutcomeV1, ControllerParentCustodyV1,
    ControllerParentStepV1, ControllerResidentCauseV1, ControllerWorkerCustodyV1,
    ControllerWorkerLoanV1, ControllerWorkerOriginalsV1, report_controller_worker_failure,
};

mod activation;
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

struct ProductionEffectExecutor {
    resource_bank: Option<Arc<Mutex<aos_sandbox::ControllerResourceBankOpeningV1>>>,
    first_global_prefix: Option<aos_sandbox::ControllerFirstGlobalPrefixAttemptV1>,

    snapshot_ownership: Option<SnapshotOwnershipDonationV3>,
    pending_snapshot_derivative: Option<storage_snapshot::authorization::SnapshotDerivativeAttemptV3>,
    #[cfg(feature = "online-nix")]
    nix_start: Option<Arc<ControllerNixStartRecipeSelectorV2>>,
    #[cfg(feature = "online-nix")]
    nix_generation_enabled: bool,
    #[cfg(feature = "online-nix")]
    nix_generation_profile: Option<Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>>,
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
    transfer_inventory: Option<aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1>,
    node: NodeId,
    process_start: Option<([u8; 16], u64)>,
    pending_source_commit: Option<PendingSourceCommit>,
    pending_snapshot_coordination: Option<PendingSnapshotCoordinationV2>,
    pending_atomic_snapshot: Option<storage_snapshot::PendingAtomicSnapshotV1>,
    q04: Option<create_q04::OriginalQ04ControllerSelectionV1>,
}

struct PendingSourceCommit {
    operation_id: OperationId,
    receipt: Option<EffectReceipt>,
    pending: LifecycleProgressOutcomeUnknownV1,
}

/// Retains the actual selected result; legacy retry custody is independent.
struct PendingSnapshotCoordinationV2 {
    operation_id: OperationId,
    outcome: Result<LifecycleProgressCommitOutcomeV1, LifecycleProtectedJournalErrorV1>,
    readback_debt: Option<LifecycleProtectedJournalErrorV1>,
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
        crate::controller_service::project_admission::recover_source_project_admission_v1(
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
            resource_bank: None,
            first_global_prefix: None,
            snapshot_ownership: None,
            pending_snapshot_derivative: None,
            #[cfg(feature = "online-nix")]
            nix_start: None,
            #[cfg(feature = "online-nix")]
            nix_generation_enabled: false,
            #[cfg(feature = "online-nix")]
            nix_generation_profile: None,
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
            pending_snapshot_coordination: None,
            pending_atomic_snapshot: None,
            q04: None,
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
        if self.pending_snapshot_coordination.is_some() {
            return Err(self.retained_snapshot_coordination_failure());
        }

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
                Some(AuxiliaryPublicationDisposition::Current)
            } else {
                let selected_snapshot = matches!(
                    current.operation().intent(), LifecycleIntentV1::Snapshot { .. }
                );
                drop(current);
                if selected_snapshot {
                    let publication = owner.publish_snapshot_coordination_admission_v2(
                        &operation_key,
                        &retention_key,
                        &coordination_key,
                        lifecycle_plan_transaction_id(operation_id, b"coordination-publication"),
                        lifecycle_plan_resource_id(operation_id, b"coordination-atomic-join"),
                        operation_lineage,
                        coordination_lineage,
                        lifecycle_plan_resource_id(operation_id, b"coordination-transaction"),
                    );
                    match publication {
                        Err(error) => {
                            self.pending_snapshot_coordination =
                                Some(PendingSnapshotCoordinationV2 {
                                    operation_id,
                                    outcome: Err(error),
                                    readback_debt: None,
                                });
                        }
                        Ok((outcome, readback)) => {
                            let retained = self.pending_snapshot_coordination.insert(
                                PendingSnapshotCoordinationV2 {
                                    operation_id,
                                    outcome: Ok(outcome),
                                    readback_debt: None,
                                },
                            );
                            // Park native success/ambiguity first. The current handle
                            // remains local to this SAME Source owner loan.
                            match readback {
                                Ok(Some(current)) => drop(current),
                                Ok(None) => {
                                    if matches!(
                                        &retained.outcome,
                                        Ok(LifecycleProgressCommitOutcomeV1::Applied(_))
                                    ) {
                                        retained.readback_debt = Some(
                                            LifecycleProtectedJournalErrorV1::NonCanonicalRecord,
                                        );
                                    }
                                }
                                Err(error) => retained.readback_debt = Some(error),
                            }
                        }
                    }
                    None
                } else {
                    let publication = owner.publish_coordination_admission(
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
                    Some(auxiliary_publication_disposition(publication))
                }
            }
        };

        if let Some(retained) = &self.pending_snapshot_coordination {
            if matches!(
                &retained.outcome,
                Ok(LifecycleProgressCommitOutcomeV1::Applied(_))
            ) && retained.readback_debt.is_none()
            {
                // Every selected readback has succeeded and the owner loan ended.
                // Only this completed success retires its native result.
                self.pending_snapshot_coordination = None;
                return Ok(());
            }
            return Err(self.retained_snapshot_coordination_failure());
        }

        match disposition {
            Some(disposition) => {
                self.settle_auxiliary_publication(operation_id, disposition, "snapshot coordination")
            }
            None => Err(EffectFailure::Permanent(
                "snapshot coordination result is absent".to_owned(),
            )),
        }
    }

    fn retained_snapshot_coordination_failure(&self) -> EffectFailure {
        let Some(retained) = &self.pending_snapshot_coordination else {
            return EffectFailure::Permanent(
                "snapshot coordination custody is absent".to_owned(),
            );
        };
        match &retained.outcome {
            Err(error) => EffectFailure::Permanent(format!(
                "protected snapshot coordination {} failed: {error}",
                retained.operation_id,
            )),
            Ok(LifecycleProgressCommitOutcomeV1::OutcomeUnknown { cause, .. }) => {
                EffectFailure::Retryable(format!(
                    "protected snapshot coordination {} durability is unknown: {cause}",
                    retained.operation_id,
                ))
            }
            Ok(LifecycleProgressCommitOutcomeV1::Applied(_)) => match &retained.readback_debt {
                Some(error) => EffectFailure::Permanent(format!(
                    "protected snapshot coordination {} readback failed: {error}",
                    retained.operation_id,
                )),
                None => EffectFailure::Permanent(
                    "snapshot coordination result is already resident".to_owned(),
                ),
            },
        }
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
        if self.q04.is_some() {
            return Err(EffectFailure::Permanent(
                "original Q04 Cache writers cannot be reopened or used by ordinary mutation".to_owned(),
            ));
        }
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
                aos_sandbox::local_inventory::ProtectedMultiNodeAuthorityOwnerV1::open_fixed_protected()
                    .map_err(|error| EffectFailure::Permanent(error.to_string()))?;
            if let Some(initial) = initial {
                match initial {
                    aos_sandbox::local_inventory::ProtectedRecordCommitOutcomeV1::Committed(_) => {}
                    aos_sandbox::local_inventory::ProtectedRecordCommitOutcomeV1::RecoveryRequired(
                        recovery,
                    ) => match owner.resolve_store_write(recovery) {
                        aos_sandbox::local_inventory::ProtectedStoreRecoveryOutcomeV1::RecordCommitted(
                            _,
                        ) => {}
                        aos_sandbox::local_inventory::ProtectedStoreRecoveryOutcomeV1::CheckpointCommitted(
                            _,
                        )
                        | aos_sandbox::local_inventory::ProtectedStoreRecoveryOutcomeV1::RecoveryRequired {
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
        == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::DeleteSandbox)
    {
        // Retained operations cannot run until the protected dependency plan exists.
        return Err(EffectFailure::Permanent(
            "sandbox deletion awaits a protected dependency plan".to_owned(),
        ));
    }

    Ok(())
}

impl SingleNodeEffectExecutor for ProductionEffectExecutor {
    #[cfg(target_os = "linux")]
    fn run_existing_git_coverage_read_metadata_v1(
        &mut self,
        journal: &mut Journal,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        operation: &mut aos_sandbox::reconciler::GitCoverageReadMetadataOperationV1<'_, '_>,
    ) -> Result<(), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        use aos_sandbox::cache_residency::CacheResidentUnavailableV1;

        self.cache_mutation.require_completed_or_empty()?;
        let protected = self.cache_inventory.as_mut().ok_or(CacheResidentUnavailableV1)?;
        let physical = self.cache_physical.as_ref().ok_or(CacheResidentUnavailableV1)?;
        self.cache_resident_usage.run_existing_git_coverage_read_metadata_v1(
            protected, physical, &mut self.source_domains, journal,
            original_inputs, operation,
        )
    }

    #[cfg(target_os = "linux")]
    fn capture_existing_git_coverage_account_cut_v1(
        &mut self,
        journal: &mut Journal,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &aos_sandbox::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &aos_sandbox::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut aos_sandbox::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.capture_existing_git_coverage_account_cut(
            journal, original_inputs, original_bootstrap, original_source,
            original_capacity, original_bootstrap_credentials, attempt,
        )
    }

    #[cfg(target_os = "linux")]
    fn commit_existing_git_coverage_account_v1(
        &mut self,
        journal: &mut Journal,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        original_bootstrap: &aos_sandbox::publisher_policy::GitUploadBootstrapAppendV1,
        original_source: &aos_sandbox::publisher_policy::VerifiedPublisherPolicySourceV1,
        original_capacity: &aos_sandbox_core::GitUploadCapacityV1,
        original_bootstrap_credentials: &mut aos_sandbox::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1,
        attempt: &mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>,
    ) -> Result<(), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.commit_existing_git_coverage_account(
            journal, original_inputs, original_bootstrap, original_source,
            original_capacity, original_bootstrap_credentials, attempt,
        )
    }

    #[cfg(target_os = "linux")]
    fn compare_existing_cache_git_coverage_v1(
        &mut self,
        original_inputs: &mut aos_sandbox::public_api_session::GitCoverageCredentialCustodyV1,
        flight: aos_sandbox_core::format::git_upload_enrollment::GitCoverageFlightV1,
        original_nonce: [u8; 16],
        original_account: Option<&mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'_>>,
    ) -> Result<(
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageBirthFieldsV1,
        aos_sandbox_core::format::git_upload_enrollment::GitCoverageFenceFieldsV1,
        [u8; 32],
        u64,
    ), aos_sandbox::cache_residency::CacheResidentUnavailableV1> {
        self.compare_existing_cache_git_coverage(original_inputs, flight, original_nonce, original_account)
    }

    fn select_original_create_q04_policy_subgate_v1(
        &mut self,
        profile: Arc<aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1>,
    ) -> Result<(), EffectFailure> {
        create_q04::select(self, profile)
    }

    fn reconcile_original_create_q04_policy_subgate_v1(
        &mut self,
        operation: OperationId,
        step: u32,
        effect_count: u32,
        plan: &EffectPlan,
        dispatch: Option<&PreparedAuthorityEffectV1>,
        authority_gate: Option<(aos_sandbox_core::SandboxId, ObjectDigest)>,
        journal: &mut Journal,
    ) -> Option<Result<(), EffectFailure>> {
        create_q04::reconcile(
            self, operation, step, effect_count, plan, dispatch, authority_gate, journal,
        )
    }

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

    fn coordinate_configured_project_genesis_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<ObjectDigest, aos_sandbox::policy_compiler::FailedConfiguredProjectGenesisInvocationV3<'writers, 'profile>> {
        let mut original = aos_sandbox::policy_compiler::OriginalConfiguredProjectGenesisInvocationV3::park(
            journal, &mut self.source_domains, input, profile,
        );
        if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
            original.run_with_signer(generation, signer);
            Ok(())
        }) { original.fail_signer_admission(error); }
        original.into_outcome()
    }

    fn prepare_first_global_prefix_v1(
        &mut self,
        journal: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<(), aos_sandbox::ResourceReservationErrorV1> {
        let bank = self.resource_bank.as_ref()
            .ok_or(aos_sandbox::ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if self.first_global_prefix.is_some() {
            return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
        }
        self.first_global_prefix = Some(
            aos_sandbox::ControllerFirstGlobalPrefixAttemptV1::new(Arc::clone(bank)),
        );
        // These are actual resident original representations, not deployment
        // flags or a new default Session masquerading as an unused owner.
        let shape = (|| {
            let sessions = self.sessions.lock()
                .map_err(|_| aos_sandbox::ResourceReservationErrorV1::Conflict)?;
            if sessions.host.is_some()
                || sessions.mount.is_some()
                || sessions.storage.is_some()
                || sessions.storage_cold.is_some()
                || sessions.network.is_some()
                || sessions.storage_root.has_pending()
                || sessions.storage_root.requires_reconnect()
                || self.pending_attachment_slot_attempt.is_some()
                || self.pending_attachment_catalog_query.is_some()
                || self.pending_attachment_mount_attempt.is_some()
                || self.pending_attachment_source_attempt.is_some()
                || self.pending_attachment_source_consume.is_some()
                || self.pending_cache_pin.is_some()
                || self.pending_cache_unpin.is_some()
                || self.pending_source_commit.is_some()
                || self.pending_snapshot_coordination.is_some()
                || self.pending_atomic_snapshot.is_some()
                || self.pending_snapshot_derivative.is_some()
                || self.q04.is_some()
            {
                return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
            }
            #[cfg(feature = "online-nix")]
            if sessions.nix_resolve.is_some() || sessions.nix_input_source.is_some() {
                return Err(aos_sandbox::ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })();
        self.first_global_prefix.as_mut()
            .ok_or(aos_sandbox::ResourceReservationErrorV1::Conflict)?
            .prepare_once(journal, &mut self.source_domains, profile, shape)
    }

    fn coordinate_configured_global_genesis_v2<'writers, 'profile>(
        &'writers mut self,
        journal: &'writers mut Journal,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<
        ObjectDigest,
        aos_sandbox::policy_compiler::FailedConfiguredGlobalGenesisInvocationV2<'writers, 'profile>,
    > {
        let mut original = aos_sandbox::policy_compiler::OriginalConfiguredGlobalGenesisInvocationV2::park_with_resource_bank(
            journal,
            &mut self.source_domains,
            input,
            profile,
            self.resource_bank.clone(),
        );
        if let Some(prefix) = self.first_global_prefix.as_ref() {
            if original.attach_first_global_prefix(prefix).is_err() {
                // The whole attachment failure and independent posts/LAST
                // precede fixed credential loading or SigningKey creation.
                return original.into_outcome();
            }
        }

        if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
            original.run_with_signer(generation, signer);
            Ok(())
        }) {
            original.fail_signer_admission(error);
        }

        original.into_outcome()
    }

    fn issue_project_source_successor_v3<'writers, 'profile, 'credentials>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut aos_sandbox::normal_root::SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Result<aos_sandbox::hierarchy::source_successor::SourceSuccessorApprovalDataV2, aos_sandbox::policy_compiler::FailedSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials>> {
        let mut original = aos_sandbox::policy_compiler::OriginalSourceProjectSuccessorInvocationV3::park(
            journal, &mut self.source_domains, profile, credentials,
        );
        if let Err(cause) = with_process_controller_hold_signer_v1(|generation, signer| {
            original.run_with_controller_signer(generation, signer);
            Ok(())
        }) { original.fail_controller_signer_admission(cause); }
        original.into_outcome()
    }

    fn coordinate_retained_first_source_successor_v2<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, aos_sandbox::policy_compiler::FailedOriginalFirstSourceSuccessorV2<'writers, 'profile>> {
        let mut original = aos_sandbox::policy_compiler::OriginalFirstSourceSuccessorInvocationV2::park(
            journal, &mut self.source_domains, profile,
        );
        if original.select_retained_before_signer() == aos_sandbox::policy_compiler::FirstSourceSuccessorSelectionV2::Selected {
            // The invocation predates the selected signer/catch boundary. Its
            // whole returned failure retains both writers through termination.
            if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
                original.run_with_controller_signer(generation, signer);
                Ok(())
            }) {
                original.fail_controller_signer_admission(error);
            }
        }
        original.into_outcome()
    }

    fn coordinate_project_successor_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        project: aos_sandbox_core::ProjectId,
    ) -> Result<Option<ObjectDigest>, aos_sandbox::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        let mut original = aos_sandbox::policy_compiler::OriginalProjectSuccessorInvocationV3::park(
            journal, &mut self.source_domains, profile, project,
        );
        if original.select_retained_before_signer() == aos_sandbox::policy_compiler::FirstSourceSuccessorSelectionV2::Selected {
            if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
                original.run_with_controller_signer(generation, signer);
                Ok(())
            }) { original.fail_controller_signer_admission(error); }
        }
        original.into_outcome()
    }

    fn coordinate_predecessor_successor_v3<'writers, 'profile>(
        &'writers mut self, journal: &'writers mut Journal,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
    ) -> Result<Option<ObjectDigest>, aos_sandbox::policy_compiler::FailedProjectSuccessorInvocationV3<'writers, 'profile>> {
        let mut original = aos_sandbox::policy_compiler::OriginalProjectSuccessorInvocationV3::park_predecessor(
            journal, &mut self.source_domains, profile, input,
        );
        if original.select_retained_before_signer() == aos_sandbox::policy_compiler::FirstSourceSuccessorSelectionV2::Selected {
            if let Err(error) = with_process_controller_hold_signer_v1(|generation, signer| {
                original.run_with_controller_signer(generation, signer);
                Ok(())
            }) { original.fail_controller_signer_admission(error); }
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
        step: u32,
        plan: &EffectPlan,
        journal: &mut Journal,
    ) -> Result<EffectObservation, EffectFailure> {
        reject_unqualified_delete_effect(plan)?;

        if plan.public_mutation_context()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .is_some_and(|context| context.has_retained_nix_start())
        {
            #[cfg(feature = "online-nix")]
            if self.nix_generation_enabled {
                return nix_generation::observe(self, operation_id, step);
            }
            #[cfg(feature = "online-nix")]
            return nix_environment::observe(self, operation_id, step);
            #[cfg(not(feature = "online-nix"))]
            // Admission is real, but no namespace47 floor/archive/publication
            // owner exists in this slice. Generic lifecycle cannot stand in.
            return Ok(EffectObservation::Absent);
        }

        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
        {
            self.require_current_create_effect(operation_id, plan, journal)?;
            return Ok(EffectObservation::Absent);
        }

        if let Some(observation) = self.recover_pending_source_commit(operation_id)? {
            return Ok(observation);
        }
        let context = self.public_mutation_context(plan)?;
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateExecution)
        {
            execution_output_effect::observe(self, operation_id, &context, journal)?;
            return Ok(EffectObservation::Absent);
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox_protocol::public_api::PublicOperationMethodV1::ControlExecution
                    | aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelExecution
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
            let observation = host.query_execution(&intent, authorization.as_ref(), context.project(), journal)?;
            return match observation {
                execution::ControllerExecutionObservationV1::Absent => {
                    Ok(EffectObservation::Absent)
                }
                execution::ControllerExecutionObservationV1::Applied(completion) => {
                    Ok(EffectObservation::Applied(completion.receipt))
                }
            };
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover)
        {
            return Self::ownership_recovery_receipt(operation_id, &context, journal).map(
                |receipt| receipt.map_or(EffectObservation::Absent, EffectObservation::Applied),
            );
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox_protocol::public_api::PublicOperationMethodV1::AttachView
                    | aos_sandbox_protocol::public_api::PublicOperationMethodV1::ReplaceAttachment
                    | aos_sandbox_protocol::public_api::PublicOperationMethodV1::DetachView
            )
        ) {
            // Generic lifecycle receipts do not prove an attachment or Mount effect.
            return Ok(EffectObservation::Absent);
        }
        if plan.public_mutation_method()
            != Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelOperation)
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
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelOperation)
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
        step: u32,
        plan: &EffectPlan,
        journal: &mut Journal,
    ) -> Result<EffectReceipt, EffectFailure> {
        reject_unqualified_delete_effect(plan)?;

        if plan.public_mutation_context()
            .map_err(|error| EffectFailure::Permanent(error.to_string()))?
            .is_some_and(|context| context.has_retained_nix_start())
        {
            #[cfg(feature = "online-nix")]
            if self.nix_generation_enabled {
                return nix_generation::prepare(self, operation_id, step, plan, journal);
            }
            #[cfg(feature = "online-nix")]
            return nix_environment::resolve(self, operation_id, step, plan, journal);
            #[cfg(not(feature = "online-nix"))]
            return Err(EffectFailure::Retryable(
                "retained Nix Start awaits genuine session floor and recipe publication owners".to_owned(),
            ));
        }

        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateSandbox)
        {
            let source = self.require_current_create_effect(operation_id, plan, journal)?;
            let progress =
                crate::controller_service::project_admission::advance_create_project_admission_v1(
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
                crate::controller_service::project_admission::ProjectAdmissionProgressV1::RetiredPrior
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
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CreateExecution)
        {
            execution_output_effect::apply(self, operation_id, &context, journal)?;
            return Err(EffectFailure::Retryable(
                "execution Create awaits physical Storage backing and Host launch".to_owned(),
            ));
        }
        if matches!(
            plan.public_mutation_method(),
            Some(
                aos_sandbox_protocol::public_api::PublicOperationMethodV1::ControlExecution
                    | aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelExecution
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
            let completion = host.apply_execution(&intent, authorization.as_ref(), context.project(), journal)?;
            return Ok(completion.receipt);
        }
        if plan.public_mutation_method()
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::OperatorRecover)
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
            == Some(aos_sandbox_protocol::public_api::PublicOperationMethodV1::CancelOperation)
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
            && (self.pending_atomic_snapshot.is_some() || self.pending_snapshot_derivative.is_some())
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
    use buffa::Message as _;

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
            aos_sandbox_protocol::public_api::PublicOperationMethodV1::DeleteSandbox,
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

}

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification_mount_inventory;

#[cfg(all(test, feature = "kernel-tests"))]
mod qualification_host_inventory;
