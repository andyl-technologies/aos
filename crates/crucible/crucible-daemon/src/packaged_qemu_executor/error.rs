//! Typed failures for packaged executor construction and native catalog recovery.

use super::*;

/// Failure to acquire or compose one packaged local QEMU executor.
#[derive(Debug, thiserror::Error)]
pub enum PackagedQemuExecutorError {
    /// Normal production entry lacks its authenticated same-main executor debit.
    #[error("normal production executor requires its original process owner")]
    MissingNormalProcessOwner,
    /// The same normal process purpose retains its concrete first refusal.
    #[error(transparent)]
    NormalProcessPurpose(#[from] crucible_host_resources::host_services::process_birth::ServiceBirthError),
    /// The permanent same Main retains the complete failed constructor.
    #[error("normal executor constructor remains retained: {0}")]
    RetainedConstructor(#[source] &'static crucible_host_resources::host_services::process_birth::ServiceBirthError),
    /// Custody publication refused and returns the same complete owner.
    #[error(transparent)]
    ConstructorCustody(#[from] crate::campaign_process::ExecutorConstructionCustodyFailure),
    /// The actual common native subdivision refused its original account.
    #[error("normal native account refused: {0}")]
    NormalNativeAccount(#[source] crucible_qemu_host::OriginalActorAccountError),
    /// A bound original factory cannot be prepared without its same guard.
    #[cfg(feature = "private-measurement-domain")]
    #[error("original factory preparation custody is absent")]
    MissingOriginalFactoryPreparation,
    /// The factory roster and preparation do not retain the same actual guard.
    #[cfg(feature = "private-measurement-domain")]
    #[error("original factory binding refused: {0}")]
    OriginalFactoryBinding(#[source] crucible_qemu_host::OriginalActorAccountError),
    /// Preserves the actual account binding refusal and original postcut.
    #[cfg(feature = "private-measurement-domain")]
    #[error("original factory bind failed: {source}; original: {original_after:?}")]
    OriginalFactoryBind {
        /// Actual first account binding refusal.
        #[source]
        source: crucible_qemu_host::OriginalActorAccountError,
        /// Separate same-original refusal after the binding attempt.
        original_after: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    },
    /// Preserves the concrete factory refusal and independent original cut.
    #[cfg(feature = "private-measurement-domain")]
    #[error("original factory open failed: {source}; original: {original_after:?}")]
    OriginalFactoryOpen {
        /// Actual first host namespace refusal.
        #[source]
        source: QemuVmRealizationError,
        /// Same original's separate postcheck.
        original_after: Option<crucible_host_resources::host_supervision::HostSupervisionError>,
    },

    /// Original provider-service bootstrap refused before error erasure.
    #[error(transparent)]
    ProviderServiceAdmission(#[from] crate::ProviderServiceAdmissionError),
    /// A required mutable lifecycle copy lacks its original allocation custody.
    #[error(transparent)]
    LifecycleConfiguration(#[from] crate::vm_lifecycle::ProductionVmLifecycleConfigCloneError),
    /// The original catalog refused lifecycle metadata allocation.
    #[error(transparent)]
    DecodedMetadata(#[from] crucible_engine::owned_decode::DecodeAdmissionError),
    /// The original registry namespace lacks its exact physical quota authority.
    #[error("operational registry physical quota admission failed: {0}")]
    RegistryQuota(#[from] crucible_host_resources::SupervisedProjectQuotaError),
    /// Persistent native RAM catalog containment or admission failed.
    #[error(transparent)]
    RamCatalog(#[from] crucible_store::content_store::StoreError),
    /// Durable host operational authority could not be acquired safely.
    #[error(transparent)]
    HostOperational(#[from] crucible_control_api::host_operational::HostOperationalError),
    /// The complete retained world cannot satisfy its actual RAM launch contract.
    #[error("host RAM launch admission failed: {0}")]
    HostRamAdmission(#[from] crucible_control_api::host_operational::HostRamAdmissionError),
    /// Private preparation refused its same original derivation boundary.
    #[cfg(feature = "private-measurement-domain")]
    #[error(transparent)]
    OriginalPreparationScope(
        #[from] crucible_host_resources::host_supervision::OriginalCaptureSupervisionError,
    ),
    /// Retains a private startup cut's actual original supervision refusal.
    #[cfg(feature = "private-measurement-domain")]
    #[error("private original preparation boundary refused: {0}")]
    OriginalPreparationBoundary(#[source] crucible_host_resources::host_supervision::HostSupervisionError),
    /// Private capture preserves its actual work and completion failures.
    #[cfg(feature = "private-measurement-domain")]
    #[error(transparent)]
    OriginalPreparationCapture(#[from] preparation::OriginalCaptureFailure),
    /// Preparation could not start its separately charged watchdog or namespace.
    #[error("packaged preparation supervision failed: {0}")]
    PreparationSupervisor(#[source] std::io::Error),
    /// Preparation could not prove that its complete physical service was cleaned.
    #[error("packaged preparation cleanup remains uncertain: {source}")]
    PreparationCleanup {
        /// Physical authority that refused a capacity discharge.
        #[source]
        source: crucible_control_api::host_operational::HostOperationalError,
        /// Original preparation failure retained for containment diagnostics.
        preparation: Option<Box<PackagedQemuExecutorError>>,
    },
    /// Preparation expired before its cleaned native candidate could be accepted.
    #[error("packaged preparation host allowance expired")]
    PreparationExpired {
        /// Failure returned by the canceled capture, when one was available.
        #[source]
        source: Option<PreparationExpiredCause>,
    },
    /// The internal deployment contract named no campaign.
    #[error("packaged QEMU executor has no campaign")]
    NoCampaigns,
    /// The lineage requests a closure format this concrete executor cannot emit.
    #[error("packaged QEMU executor supports exact closure schema {supported}, not {actual}")]
    UnsupportedExactClosureSchema {
        /// Requested lineage compatibility version.
        actual: u32,
        /// Concrete checkpoint writer's version.
        supported: u32,
    },
    /// A configured campaign does not share the pool's exact compatibility basis.
    #[error(
        "campaign `{}` is incompatible with the packaged QEMU executor pool",
        campaign.as_str()
    )]
    CampaignCompatibilityMismatch {
        /// Incompatible configured campaign.
        campaign: CampaignName,
    },
    /// The selected immutable QEMU artifacts do not match the lineage build.
    #[error("selected QEMU build `{actual}` differs from campaign lineage build `{expected}`")]
    QemuBuildMismatch {
        /// Build identity authenticated by the campaign lineage.
        expected: String,
        /// Build identity authenticated from the selected QEMU and plugin artifacts.
        actual: String,
    },
    /// The authenticated launch receipt names different lifecycle artifacts.
    #[error("packaged hot-fork launch receipt differs from lifecycle QEMU or plugin path")]
    HotForkLaunchPathMismatch,
    /// Initial-runner construction disagreed with the configured hot-fork policy.
    #[error("packaged hot-fork policy and constructed source owner disagree")]
    HotForkCompositionMismatch,
    /// Campaign or lineage authentication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// A retained-source basis failed closed authentication.
    #[error(transparent)]
    HotForkSourceBasis(#[from] AuthenticatedQemuHotForkSourceBasisError),
    /// The retained Crucible scenario artifact failed semantic authentication.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The complete native scenario catalog exceeds its startup work bound.
    #[error("packaged QEMU scenario catalog exceeds {maximum} canonical bytes")]
    ScenarioCatalogBytesExceeded {
        /// Maximum admitted aggregate canonical record-body bytes.
        maximum: usize,
    },
    /// Exact baked-genesis capture or complete native admission failed.
    #[error("packaged QEMU baked-genesis capture failed for scenario {scenario:?}")]
    BakedGenesis {
        /// Exact scenario whose native capture failed.
        scenario: ScenarioArtifactId,
        /// Guarded capture or native admission failure.
        #[source]
        source: Box<ProductionBakedGenesisCaptureError<QemuAttemptProductionVmLifecycleError>>,
    },
    /// The durable retained-source fallback catalog could not be opened.
    #[error(transparent)]
    HotForkRetention(#[from] HotCheckpointFallbackRetentionError),
    /// Existing retained-source fallback records could not be authenticated.
    #[error(transparent)]
    HotForkPool(#[from] ManagedQemuHotForkSourceWorldPoolConstructionError),
    /// A canonical source world could not be launched and prepared.
    #[error("capture packaged hot-fork source for lineage {lineage}")]
    HotForkSourceCapture {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Guarded launch or source-world preparation failure.
        #[source]
        source: hot_fork::RetainedSourceCaptureFailure<ProductionQemuHotForkSourceCaptureError>,
    },
    /// A prepared source world failed managed admission and entered quarantine.
    #[error("admit packaged hot-fork source for lineage {lineage}")]
    HotForkSourceAdmission {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Source-free admission diagnostic after quarantine.
        #[source]
        source:
            Box<ManagedQemuHotForkAuthenticatedAdmissionError<PackagedQemuHotForkDemotionError>>,
    },
    /// A binding-rejected source could not attest complete process/resource cleanup.
    #[error("clean up binding-rejected packaged hot-fork source for lineage {lineage}: {binding}")]
    HotForkSourceBindingCleanup {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Original source binding rejection.
        binding: Box<
            crate::managed_qemu_hot_fork_source_world_pool::ManagedQemuHotForkSourceWorldBindingError,
        >,
        /// Complete source-world retirement failure. Its retained lifecycle has
        /// already entered the production quarantine path.
        #[source]
        retirement: Box<crucible_control_api::LifecycleApiError>,
    },
    /// Cold-fallback retention failed while the declined source was also cleaned up.
    #[error("retain fallback and clean up policy-declined hot-fork source for lineage {lineage}")]
    HotForkRejectedSourceCleanup {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Durable fallback retention failure.
        #[source]
        retention:
            Box<ManagedQemuHotForkSourceWorldAdmissionError<PackagedQemuHotForkDemotionError>>,
        /// Source retirement failure, when retirement was attempted but did not complete.
        retirement: Option<Box<crucible_control_api::LifecycleApiError>>,
        /// Whether an unavailable managed candidate was retained for the process lifetime.
        candidate_quarantined: bool,
    },
    /// A policy-declined source could not be safely retired after fallback retention.
    #[error("retire policy-declined packaged hot-fork source for lineage {lineage}")]
    HotForkRejectedSourceRetirement {
        /// Authenticated source lineage.
        lineage: CampaignLineageId,
        /// Complete source-world retirement failure.
        #[source]
        source: crucible_control_api::LifecycleApiError,
    },
    /// A fixed worker could not acquire an independent shared-pool session.
    #[error(transparent)]
    HotForkProvider(#[from] SharedQemuHotForkSourceWorldProviderConstructionError),
    /// Source capture failed and one or more earlier sources also failed cleanup.
    #[error("packaged hot-fork startup and retained-source cleanup both failed")]
    HotForkStartupCleanup {
        /// Primary startup failure.
        #[source]
        source: Box<PackagedQemuExecutorError>,
        /// Complete keyed cleanup failure report.
        cleanup: Box<PackagedQemuHotForkSourceShutdownError>,
    },
    /// The complete native scenario catalog was empty or ambiguous.
    #[error(transparent)]
    BakedGenesisCatalog(#[from] ProductionBakedGenesisReplayCatalogError),
    /// Durable assignment-ledger acquisition failed.
    #[error(transparent)]
    Ledger(#[from] AssignmentLedgerError),
    /// Durable prepared-result journal namespace acquisition failed.
    #[error(transparent)]
    PreparedResults(#[from] PreparedResultJournalError),
    /// Pending finding incorporation could not be resumed safely.
    #[error("reconcile pending finding candidates after packaged executor restart")]
    FindingRestart(#[source] crate::FindingCandidateRestartError<AssignmentLedgerError>),
    /// A bounded restart pass left work without releasing any matching root.
    #[error(
        "campaign `{}` finding restart made no progress with {remaining} roots remaining",
        campaign.as_str()
    )]
    FindingRestartNoProgress {
        /// Campaign whose pending finding roots could not advance.
        campaign: CampaignName,
        /// Roots deferred after the stalled pass.
        remaining: usize,
    },
    /// Abandoned attempt-local native checkpoint state could not be reconciled.
    #[error(transparent)]
    NativeCatalogRecovery(#[from] PackagedNativeCatalogRecoveryError),
    /// Durable exact-checkpoint store construction failed.
    #[error(transparent)]
    Checkpoints(#[from] ExactCheckpointStoreError),
    /// Exact-pin journal acquisition or startup reconciliation failed.
    #[error(transparent)]
    ExactPinMaterializer(Box<PackagedExactPinMaterializerError>),
    /// Linux process/storage resource ownership could not be acquired.
    #[error(transparent)]
    Host(#[from] QemuVmRealizationError),
    /// An immutable executor capability or resource bound was invalid.
    #[error(transparent)]
    Codec(#[from] CampaignCodecError),
    /// Fixed semantic-worker construction failed.
    #[error(transparent)]
    Pool(#[from] LocalExecutorPoolConfigError),
    /// Internal initial-runner construction did not cover every fixed worker.
    #[error("packaged QEMU initial runner count is {actual}, expected {expected}")]
    InitialRunnerCount {
        /// Fixed semantic-worker count.
        expected: usize,
        /// Constructed initial-runner count.
        actual: usize,
    },
    /// Managed endpoint acquisition failed.
    #[error(transparent)]
    Endpoint(#[from] LocalComponentEndpointError),
    /// Fixed listener construction failed.
    #[error(transparent)]
    Listener(#[from] ExecutorLoopbackListenerError),
}

impl From<PackagedExactPinMaterializerError> for PackagedQemuExecutorError {
    fn from(source: PackagedExactPinMaterializerError) -> Self {
        Self::ExactPinMaterializer(Box::new(source))
    }
}

/// Failure to reconcile abandoned packaged-worker native checkpoint state.
#[derive(Debug, thiserror::Error)]
pub enum PackagedNativeCatalogRecoveryError {
    /// Active and retired generations appeared together under exclusive ownership.
    #[error("packaged native namespace `{namespace}` has conflicting generations")]
    ConflictingGeneration {
        /// Dedicated worker namespace with conflicting generations.
        namespace: &'static str,
    },
    /// A dedicated namespace path was replaced by another filesystem type.
    #[error("packaged native namespace path is not a directory: {path}")]
    InvalidPath {
        /// Path that violated the worker-state namespace contract.
        path: PathBuf,
    },
    /// Durable namespace reconciliation failed.
    #[error("{operation} packaged native namespace {path}: {source}")]
    Io {
        /// Stable filesystem operation label.
        operation: &'static str,
        /// Exact path involved in the failed operation.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
}
