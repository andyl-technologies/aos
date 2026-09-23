//! Offline production replay capture access for imported campaign archives.
//!
//! An executable archive authenticates the selected finding, candidate bundle,
//! and replay capture closure. This module reuses the live capture decoder and
//! keeps the imported store read-only while preparing a fresh private replay.

use crucible::{Checkpoint, Configuration, ReproductionArtifact, ScenarioDefForm};
use crucible_api::{
    DestroySessionRequest, InProcessLifecycleClient, LifecycleApiError, LifecycleControlPlane,
    LifecycleLoopFactory, ProductionVmLifecycleConfig, ProductionVmLifecycleLoop,
    SessionLifetimeRetention, SessionRef,
};
use crucible_campaign::{
    AttemptResourceLimits, CampaignArchiveManifestId, CampaignFindingTriageReplayRole,
    CampaignRepository, CampaignRepositoryError, CampaignServiceFailure, ExactCheckpointId,
    FindingId,
};
use crucible_session::{DebugControllerLease, DebugRole};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

use crucible::{ContentHash, VmArchitecture};
use crucible_qemu::{QemuLaunchArtifactIdentity, QemuLaunchArtifactIdentityError};

use crate::campaign_debug_session::select_finding_debug_checkpoint;
use crate::crucible_artifact::{
    campaign_configuration_id, campaign_scenario_id,
    decode_crucible_configuration_artifact_from_repository,
};
use crate::finding_production_replay::{
    FindingProductionReplayAsset, FindingProductionReplayCapture,
    FindingProductionReplayCaptureError, FindingProductionReplayCaptureLimits,
    FindingProductionReplayDeployment, FindingProductionReplayRootImageFormat,
};
use crate::finding_replay_capture_store::{
    FindingReplayCaptureStore, FindingReplayCaptureStoreError, LoadedFindingReplayCapture,
};
use crate::{
    CampaignDebugCheckpointRole, CampaignDebugQemuCapability, CrucibleArtifactError,
    ExactCheckpointStore, ExactCheckpointStoreError, LinuxQemuAttemptHostConfig,
    LinuxQemuAttemptHostResourceFactory, LoadedProductionExactCheckpoint,
    PreparedCampaignDebugLifecycle, SharedQemuAttemptHostResourceFactory,
    decode_crucible_scenario_artifact,
};

/// Authenticated, read-only exact midpoint from one executable finding archive.
///
/// Its production closure and semantic checkpoint are retained in memory. A
/// caller may admit them through the existing guarded QEMU lifecycle and debug
/// relay; no campaign ref or retained checkpoint is rewritten by preparation.
#[derive(Clone)]
pub struct ArchivedFindingDebugMidpoint {
    source: ScenarioDefForm,
    configuration: Configuration,
    modeled_checkpoint: Checkpoint,
    loaded_checkpoint: Arc<LoadedProductionExactCheckpoint>,
    checkpoint: ExactCheckpointId,
    role: CampaignDebugCheckpointRole,
    restore_bytes: u64,
}

/// One private control plane owning an imported finding's read-only QEMU session.
pub type ArchivedFindingDebugControlPlane = LifecycleControlPlane<
    ProductionVmLifecycleLoop,
    LifecycleLoopFactory<ProductionVmLifecycleLoop>,
>;

/// An admitted, paused exact-midpoint session independent of a campaign daemon.
pub struct ArchivedFindingDebugSession {
    control_plane: Arc<tokio::sync::Mutex<ArchivedFindingDebugControlPlane>>,
    session: SessionRef,
}

/// Two private restorations of one authenticated midpoint with separate QEMU runs.
///
/// Both sessions begin read-only. Only `branch` may receive the explicit
/// non-canonical fork report and become writable; `canonical` remains a
/// separate, unmodified process and lifecycle actor.
pub struct ArchivedFindingDebugSessionPair {
    control_plane: Arc<tokio::sync::Mutex<ArchivedFindingDebugControlPlane>>,
    canonical: SessionRef,
    branch: SessionRef,
}

impl ArchivedFindingDebugSessionPair {
    /// Returns the original read-only session.
    #[must_use]
    pub const fn canonical(&self) -> SessionRef {
        self.canonical
    }

    /// Returns the independent session reserved for debugger mutation.
    #[must_use]
    pub const fn branch(&self) -> SessionRef {
        self.branch
    }

    /// Returns the shared control plane for the existing local debug relay.
    #[must_use]
    pub fn shared_control_plane(
        &self,
    ) -> Arc<tokio::sync::Mutex<ArchivedFindingDebugControlPlane>> {
        Arc::clone(&self.control_plane)
    }

    /// Returns an in-process client for exact lifecycle teardown.
    #[must_use]
    pub fn in_process_client(
        &self,
    ) -> InProcessLifecycleClient<
        ProductionVmLifecycleLoop,
        LifecycleLoopFactory<ProductionVmLifecycleLoop>,
    > {
        InProcessLifecycleClient::from_shared_control_plane(Arc::clone(&self.control_plane))
    }

    /// Records a branch-local register edit intent before its GDB write.
    ///
    /// The caller must write the same bytes through the branch's writable
    /// relay and verify a register readback before publishing success. The
    /// original session is checked for unchanged read-only classification.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] if attachment, actor fork, provenance
    /// admission, or canonical isolation fails.
    pub async fn fork_branch_for_register_write(
        &self,
        lease: &DebugControllerLease,
        role: &DebugRole,
        node: crucible::NodeId,
        register: String,
        bytes: Vec<u8>,
    ) -> Result<crucible::DebugNonCanonicalBranchReport, LifecycleApiError> {
        if register.is_empty() || bytes.is_empty() || bytes.len() > 4096 {
            return Err(LifecycleApiError::SessionCommandRejected {
                message: String::from("debug register edit has invalid target or byte length"),
            });
        }
        let dispatch = {
            let plane = self.control_plane.lock().await;
            plane.authorize_debug_branch_fork(self.branch, lease, role)?;
            let (attached, _) = plane.debug_operator_target(self.branch).await?;
            if attached != node {
                return Err(LifecycleApiError::SessionCommandRejected {
                    message: String::from("debug register edit targets another attached node"),
                });
            }
            plane.debug_branch_fork_dispatch(self.branch)?
        };
        let report = dispatch
            .fork_guest_edit(
                node,
                crucible::DebugGuestEditKind::RegisterWrite,
                register,
                bytes,
            )
            .await?;
        let mut plane = self.control_plane.lock().await;
        plane.commit_writable_debug_branch(self.branch, &report)?;
        if plane.writable_debug_branch(self.canonical)?.is_some() {
            return Err(LifecycleApiError::SessionCommandRejected {
                message: String::from("canonical finding midpoint became writable"),
            });
        }
        Ok(report)
    }
}

impl ArchivedFindingDebugSession {
    /// Returns the admitted read-only lifecycle session identity.
    #[must_use]
    pub const fn session(&self) -> SessionRef {
        self.session
    }

    /// Returns the shared control plane used by the local debug relay server.
    #[must_use]
    pub fn shared_control_plane(
        &self,
    ) -> Arc<tokio::sync::Mutex<ArchivedFindingDebugControlPlane>> {
        Arc::clone(&self.control_plane)
    }

    /// Returns an in-process client for session queries and lifecycle teardown.
    #[must_use]
    pub fn in_process_client(
        &self,
    ) -> InProcessLifecycleClient<
        ProductionVmLifecycleLoop,
        LifecycleLoopFactory<ProductionVmLifecycleLoop>,
    > {
        InProcessLifecycleClient::from_shared_control_plane(Arc::clone(&self.control_plane))
    }
}

impl ArchivedFindingDebugMidpoint {
    /// Returns the selected exact checkpoint root.
    #[must_use]
    pub const fn checkpoint(&self) -> ExactCheckpointId {
        self.checkpoint
    }

    /// Returns the finding role of the selected checkpoint.
    #[must_use]
    pub const fn role(&self) -> CampaignDebugCheckpointRole {
        self.role
    }

    /// Returns the authenticated size of the selected complete restore closure.
    #[must_use]
    pub const fn restore_bytes(&self) -> u64 {
        self.restore_bytes
    }

    /// Returns the authenticated scenario source used to decode the midpoint.
    #[must_use]
    pub const fn source(&self) -> &ScenarioDefForm {
        &self.source
    }

    /// Returns the exact semantic configuration at the midpoint.
    #[must_use]
    pub const fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    /// Returns the modeled checkpoint passed to read-only lifecycle admission.
    #[must_use]
    pub const fn modeled_checkpoint(&self) -> &Checkpoint {
        &self.modeled_checkpoint
    }

    /// Returns the authenticated production closure retained for guarded restore.
    #[must_use]
    pub fn loaded_checkpoint(&self) -> &LoadedProductionExactCheckpoint {
        &self.loaded_checkpoint
    }

    fn prepare_read_only_lifecycle(
        self,
        qemu: &CampaignDebugQemuCapability,
    ) -> PreparedCampaignDebugLifecycle {
        let Self {
            source,
            configuration,
            modeled_checkpoint,
            loaded_checkpoint,
            checkpoint,
            ..
        } = self;
        let build_resume = Arc::clone(&qemu.build_resume);
        let build_source = source.clone();
        let build_configuration = configuration.clone();
        let build_scenario = source.scenario_def();
        let retention = SessionLifetimeRetention::new(loaded_checkpoint);

        PreparedCampaignDebugLifecycle {
            source,
            configuration,
            checkpoint: modeled_checkpoint,
            retention,
            build_loop: Box::new(move || {
                build_resume(
                    &build_scenario,
                    &build_source,
                    &build_configuration,
                    checkpoint,
                )
            }),
        }
    }

    /// Opens private Linux resources and prepares guarded QEMU exact restore.
    ///
    /// The checkpoint store must be the same imported archive store used to
    /// select this midpoint. Its root and production identity are checked again
    /// before the guarded lifecycle is returned. The caller supplies packaged
    /// QEMU/plugin paths and authenticated guest assets in `lifecycle`.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignFindingHandoffError`] if the private exact store
    /// differs from the selected archive closure or Linux resource admission
    /// fails.
    pub fn prepare_guarded_read_only_lifecycle(
        self,
        checkpoints: Arc<ExactCheckpointStore>,
        lifecycle: ProductionVmLifecycleConfig,
        host: LinuxQemuAttemptHostConfig,
        resources: AttemptResourceLimits,
    ) -> Result<PreparedCampaignDebugLifecycle, CampaignFindingHandoffError> {
        let reloaded = checkpoints.load_attempt_checkpoint(self.checkpoint)?;
        if reloaded.production_identity() != self.loaded_checkpoint.production_identity()
            || reloaded.configuration() != self.configuration.id()
        {
            return Err(CampaignFindingHandoffError::CheckpointStoreMismatch);
        }

        let host = LinuxQemuAttemptHostResourceFactory::open(host)?;
        let qemu = CampaignDebugQemuCapability::new(
            checkpoints,
            lifecycle,
            SharedQemuAttemptHostResourceFactory::new(host),
            resources,
        );
        Ok(self.prepare_read_only_lifecycle(&qemu))
    }

    /// Admits the imported midpoint into a private paused QEMU debug session.
    ///
    /// This is the daemon-free owner composition for a bundle consumer. It
    /// reuses the ordinary guarded exact resume and shared lifecycle registry,
    /// whose `ReadOnlyDebug` access forbids canonical mutation. The returned
    /// control plane may be served by the existing local debug relay server.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignFindingHandoffError`] when archive checkpoint
    /// reauthentication, private host admission, guarded QEMU restore, or
    /// read-only lifecycle admission fails.
    pub async fn admit_guarded_read_only_session(
        self,
        checkpoints: Arc<ExactCheckpointStore>,
        lifecycle: ProductionVmLifecycleConfig,
        host: LinuxQemuAttemptHostConfig,
        resources: AttemptResourceLimits,
    ) -> Result<ArchivedFindingDebugSession, CampaignFindingHandoffError> {
        let prepared =
            self.prepare_guarded_read_only_lifecycle(checkpoints, lifecycle, host, resources)?;
        let control_plane = ArchivedFindingDebugControlPlane::new_with_fallible_source_factory(
            "crucible-finding-bundle-debug",
            Vec::new(),
            |_scenario, _source, _seed| {
                Err(LifecycleApiError::LoopFactory {
                    message: String::from("finding bundle admits only its authenticated midpoint"),
                })
            },
        )
        .with_max_sessions(1);
        let control_plane = Arc::new(tokio::sync::Mutex::new(control_plane));
        let client =
            InProcessLifecycleClient::from_shared_control_plane(Arc::clone(&control_plane));
        let admitted = prepared.admit(&client).await?;

        Ok(ArchivedFindingDebugSession {
            control_plane,
            session: admitted.session,
        })
    }

    /// Restores the same authenticated midpoint into two independent QEMU runs.
    ///
    /// The guarded host allocator gives each admission its own process,
    /// writable overlay, cgroup, and run directory. The immutable checkpoint
    /// closure remains shared by content address and is reauthenticated before
    /// either process starts.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignFindingHandoffError`] for checkpoint drift, guarded
    /// host admission, or either independent lifecycle restore failure.
    pub async fn admit_guarded_debug_session_pair(
        self,
        checkpoints: Arc<ExactCheckpointStore>,
        lifecycle: ProductionVmLifecycleConfig,
        host: LinuxQemuAttemptHostConfig,
        resources: AttemptResourceLimits,
    ) -> Result<ArchivedFindingDebugSessionPair, CampaignFindingHandoffError> {
        let reloaded = checkpoints.load_attempt_checkpoint(self.checkpoint)?;
        if reloaded.production_identity() != self.loaded_checkpoint.production_identity()
            || reloaded.configuration() != self.configuration.id()
        {
            return Err(CampaignFindingHandoffError::CheckpointStoreMismatch);
        }

        let host = LinuxQemuAttemptHostResourceFactory::open(host)?;
        let shared_host = SharedQemuAttemptHostResourceFactory::new(host);
        let run_root = lifecycle.run_state_root().to_path_buf();
        let canonical_qemu = CampaignDebugQemuCapability::new(
            Arc::clone(&checkpoints),
            lifecycle
                .clone()
                .with_run_state_root(run_root.join("canonical")),
            shared_host.clone(),
            resources,
        );
        let branch_qemu = CampaignDebugQemuCapability::new(
            checkpoints,
            lifecycle.with_run_state_root(run_root.join("branch")),
            shared_host,
            resources,
        );
        let canonical = self.clone().prepare_read_only_lifecycle(&canonical_qemu);
        let branch = self.prepare_read_only_lifecycle(&branch_qemu);
        let control_plane = ArchivedFindingDebugControlPlane::new_with_fallible_source_factory(
            "crucible-finding-bundle-debug-pair",
            Vec::new(),
            |_scenario, _source, _seed| {
                Err(LifecycleApiError::LoopFactory {
                    message: String::from("finding bundle admits only its authenticated midpoint"),
                })
            },
        )
        .with_max_sessions(2);
        let control_plane = Arc::new(tokio::sync::Mutex::new(control_plane));
        let client =
            InProcessLifecycleClient::from_shared_control_plane(Arc::clone(&control_plane));
        let canonical = canonical.admit(&client).await?;
        let branch = match branch.admit(&client).await {
            Ok(branch) => branch,
            Err(restore_error) => {
                let cleanup = control_plane
                    .lock()
                    .await
                    .destroy_session(DestroySessionRequest::new(canonical.session))
                    .await;
                if let Err(cleanup_error) = cleanup {
                    return Err(LifecycleApiError::ActorFailed {
                        message: format!(
                            "branch restore failed: {restore_error}; canonical cleanup failed: {cleanup_error}"
                        ),
                    }
                    .into());
                }
                return Err(restore_error.into());
            }
        };
        Ok(ArchivedFindingDebugSessionPair {
            control_plane,
            canonical: canonical.session,
            branch: branch.session,
        })
    }
}

/// Selects the live controller's exact midpoint from an imported finding archive.
///
/// The archive inspection authenticates the complete executable snapshot and
/// every finding-retained pin. Scenario and configuration artifacts are then
/// decoded from that repository, and every candidate checkpoint is validated
/// before the lowest restore-byte cost and role tie break are applied.
///
/// # Errors
///
/// Returns [`CampaignFindingHandoffError`] for partial or corrupt archives,
/// missing exact pins, invalid artifacts, inconsistent schedule prefixes, or
/// any candidate production closure that cannot be authenticated.
pub fn prepare_archived_finding_debug_midpoint(
    repository: &CampaignRepository,
    archive: CampaignArchiveManifestId,
    finding_id: FindingId,
    checkpoints: &ExactCheckpointStore,
) -> Result<ArchivedFindingDebugMidpoint, CampaignFindingHandoffError> {
    let finding = repository.inspect_archived_exact_finding(archive, finding_id)?;
    let reproduction = repository.load_reproduction_artifact(finding.reproduction())?;
    let scenario_artifact = repository.load_scenario_artifact(reproduction.scenario_artifact())?;
    let source = decode_crucible_scenario_artifact(&scenario_artifact)?;
    let configuration_artifact =
        repository.load_configuration_artifact(reproduction.configuration_artifact())?;
    let reproduction_configuration = decode_crucible_configuration_artifact_from_repository(
        &source,
        &scenario_artifact,
        &configuration_artifact,
        repository,
    )?;
    if reproduction.scenario() != campaign_scenario_id(source.id())
        || reproduction.configuration()
            != campaign_configuration_id(reproduction_configuration.id())
    {
        return Err(CampaignFindingHandoffError::ReproductionArtifactMismatch);
    }

    let selected = select_finding_debug_checkpoint(
        &source,
        &reproduction_configuration,
        finding.exact_pin_retention(),
        checkpoints,
    )?;
    Ok(ArchivedFindingDebugMidpoint {
        source,
        configuration: selected.configuration,
        modeled_checkpoint: selected.modeled_checkpoint,
        loaded_checkpoint: selected.loaded,
        checkpoint: selected.checkpoint,
        role: selected.role,
        restore_bytes: selected.restore_bytes,
    })
}

/// Loads one fully authenticated production capture from an imported archive.
///
/// The archive must contain a complete campaign snapshot with retained exact
/// pins. The capture remains bound to the selected candidate reproduction and
/// finding signature; an incomplete role cannot be treated as a replay recipe.
///
/// # Errors
///
/// Returns [`CampaignFindingHandoffError`] when archive membership, candidate
/// evidence, capture bytes, model reproduction, or durable bindings disagree.
pub fn load_archived_finding_production_capture(
    repository: &CampaignRepository,
    archive: CampaignArchiveManifestId,
    finding_id: FindingId,
    role: CampaignFindingTriageReplayRole,
) -> Result<FindingProductionReplayCapture, CampaignFindingHandoffError> {
    let finding = repository.inspect_archived_exact_finding(archive, finding_id)?;
    let candidate_id = finding
        .latest_candidate_bundle()
        .ok_or(CampaignFindingHandoffError::MissingCandidateBundle)?;
    let candidate = repository.load_finding_candidate_bundle(candidate_id)?;
    let references = candidate
        .replay_captures()
        .ok_or(CampaignFindingHandoffError::MissingCaptureSet)?;
    let captures = FindingReplayCaptureStore::load_set_from_repository(repository, references)?;

    let (index, reproduction_id) = match role {
        CampaignFindingTriageReplayRole::MinimizationOriginal => (0, candidate.reproduction()),
        CampaignFindingTriageReplayRole::MinimizationSelected => (1, candidate.minimized()),
        CampaignFindingTriageReplayRole::VerificationOriginal => (2, candidate.reproduction()),
        CampaignFindingTriageReplayRole::VerificationSelected => (3, candidate.minimized()),
    };
    let selected = captures
        .into_iter()
        .nth(index)
        .ok_or(CampaignFindingHandoffError::MissingCaptureSet)?;
    let bytes = match selected {
        LoadedFindingReplayCapture::Complete { bytes, .. } => bytes,
        LoadedFindingReplayCapture::Incomplete(reason) => {
            return Err(CampaignFindingHandoffError::IncompleteCapture { reason });
        }
    };

    let reproduction = repository.load_reproduction_artifact(reproduction_id)?;
    let model = ReproductionArtifact::from_compact_binary(reproduction.payload())?;
    let limits = FindingProductionReplayCaptureLimits::for_reproduction(&model);
    let capture = FindingProductionReplayCapture::from_canonical_bytes(&bytes, limits)?;
    capture.validate_binding(reproduction_id, finding.signature())?;
    if capture.model_reproduction() != reproduction.payload() {
        return Err(CampaignFindingHandoffError::ModelReproductionMismatch);
    }
    Ok(capture)
}

/// Private guest paths for one architecture of a retained production replay.
#[derive(Debug)]
pub struct MaterializedFindingReplayGuest {
    architecture: VmArchitecture,
    kernel: PathBuf,
    root_image: PathBuf,
    kernel_cmdline_prefix: Option<String>,
}

impl MaterializedFindingReplayGuest {
    /// Returns the architecture selected by the captured scenario.
    #[must_use]
    pub const fn architecture(&self) -> VmArchitecture {
        self.architecture
    }

    /// Returns the private kernel path.
    #[must_use]
    pub fn kernel(&self) -> &Path {
        &self.kernel
    }

    /// Returns the private root-image path.
    #[must_use]
    pub fn root_image(&self) -> &Path {
        &self.root_image
    }

    /// Returns the captured kernel command-line prefix, when present.
    #[must_use]
    pub fn kernel_cmdline_prefix(&self) -> Option<&str> {
        self.kernel_cmdline_prefix.as_deref()
    }
}

/// Owned private files needed by a standalone production replay.
///
/// The temporary directory and every file disappear when this owner drops.
#[derive(Debug)]
pub struct MaterializedFindingReplayGuestAssets {
    directory: tempfile::TempDir,
    guest_assets: Vec<MaterializedFindingReplayGuest>,
    initrd: Option<PathBuf>,
    root_image_format: FindingProductionReplayRootImageFormat,
}

impl MaterializedFindingReplayGuestAssets {
    /// Returns the private directory that owns all materialized files.
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }

    /// Returns the captured guest kernel and root paths by architecture.
    #[must_use]
    pub fn guest_assets(&self) -> &[MaterializedFindingReplayGuest] {
        &self.guest_assets
    }

    /// Returns the shared captured initrd path, when configured.
    #[must_use]
    pub fn initrd(&self) -> Option<&Path> {
        self.initrd.as_deref()
    }

    /// Returns the captured root-image format.
    #[must_use]
    pub const fn root_image_format(&self) -> FindingProductionReplayRootImageFormat {
        self.root_image_format
    }
}

/// Materializes embedded guest assets under a new private temporary directory.
///
/// The installed QEMU/plugin pair must match the capture's marker-derived
/// runtime identity. Equal content hashes share one file; every file is
/// rehashed before it is written and created with owner-only permissions.
///
/// # Errors
///
/// Returns [`CampaignFindingHandoffError`] when the installed runtime differs,
/// a retained asset disagrees with its identity, or private file creation fails.
pub fn materialize_finding_replay_guest_assets(
    deployment: &FindingProductionReplayDeployment,
    qemu: &Path,
    plugin: &Path,
    parent: &Path,
) -> Result<MaterializedFindingReplayGuestAssets, CampaignFindingHandoffError> {
    let installed = QemuLaunchArtifactIdentity::authenticate(qemu, plugin)?;
    let required = deployment.runtime();
    if installed.qemu_build_id() != required.qemu_build_id()
        || installed.qemu_atomic_patch_hash() != required.qemu_atomic_patch_hash()
        || installed.plugin_abi() != required.plugin_abi()
        || installed.shmem_abi_version() != required.shmem_abi_version()
    {
        return Err(CampaignFindingHandoffError::RuntimeIdentityMismatch);
    }

    let directory = tempfile::Builder::new()
        .prefix("crucible-finding-replay-")
        .tempdir_in(parent)?;
    let mut paths = BTreeMap::new();
    let guest_assets = deployment
        .guest_assets()
        .iter()
        .map(|asset| {
            Ok(MaterializedFindingReplayGuest {
                architecture: asset.architecture(),
                kernel: materialize_asset(directory.path(), asset.kernel(), &mut paths)?,
                root_image: materialize_asset(directory.path(), asset.root_image(), &mut paths)?,
                kernel_cmdline_prefix: asset.kernel_cmdline_prefix().map(ToOwned::to_owned),
            })
        })
        .collect::<Result<Vec<_>, CampaignFindingHandoffError>>()?;
    let initrd = deployment
        .initrd()
        .map(|asset| materialize_asset(directory.path(), asset, &mut paths))
        .transpose()?;

    Ok(MaterializedFindingReplayGuestAssets {
        directory,
        guest_assets,
        initrd,
        root_image_format: deployment.root_image_format(),
    })
}

fn materialize_asset(
    directory: &Path,
    asset: &FindingProductionReplayAsset,
    paths: &mut BTreeMap<ContentHash, PathBuf>,
) -> Result<PathBuf, CampaignFindingHandoffError> {
    let identity = asset.identity();
    if ContentHash::from_bytes(asset.bytes()) != identity {
        return Err(CampaignFindingHandoffError::GuestAssetHashMismatch);
    }
    if let Some(path) = paths.get(&identity) {
        return Ok(path.clone());
    }

    let path = directory.join(identity.to_hex());
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(asset.bytes())?;
    file.sync_all()?;
    paths.insert(identity, path.clone());
    Ok(path)
}

/// Failure to authenticate or reconstruct one imported finding capture.
#[derive(Debug, Error)]
pub enum CampaignFindingHandoffError {
    /// The private exact store differs from the selected archive closure.
    #[error("private exact checkpoint store differs from selected archive midpoint")]
    CheckpointStoreMismatch,
    /// The private exact checkpoint store failed root authentication.
    #[error(transparent)]
    CheckpointStore(#[from] ExactCheckpointStoreError),
    /// Private Linux process or storage resource admission failed.
    #[error(transparent)]
    HostResources(#[from] crucible_qemu::QemuVmRealizationError),
    /// Guarded QEMU restore or read-only lifecycle admission failed.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleApiError),
    /// The retained reproduction disagrees with its decoded source artifacts.
    #[error("archived finding reproduction disagrees with source artifacts")]
    ReproductionArtifactMismatch,
    /// No valid exact midpoint could be selected from the authenticated pins.
    #[error("archived finding exact midpoint selection failed: {0}")]
    DebugSelection(#[from] CampaignServiceFailure),
    /// A retained execution-model artifact failed semantic decoding.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The selected finding has no retained candidate bundle.
    #[error("archived finding has no candidate bundle")]
    MissingCandidateBundle,
    /// The candidate bundle has no portable production capture outcomes.
    #[error("archived finding candidate has no production capture set")]
    MissingCaptureSet,
    /// The selected capture role was durably marked incomplete.
    #[error("archived finding capture role is incomplete: {reason:?}")]
    IncompleteCapture {
        /// Stable retained reason for the incomplete role.
        reason: crucible_campaign::FindingReplayCaptureIncomplete,
    },
    /// The embedded model reproduction differs from the retained record.
    #[error("archived production capture model reproduction differs from candidate")]
    ModelReproductionMismatch,
    /// The installed QEMU/plugin pair differs from the capture requirement.
    #[error("installed QEMU/plugin identity differs from archived replay")]
    RuntimeIdentityMismatch,
    /// An embedded guest asset differs from its committed content identity.
    #[error("archived guest asset content hash mismatch")]
    GuestAssetHashMismatch,
    /// The installed QEMU/plugin marker pair failed authentication.
    #[error(transparent)]
    RuntimeAuthentication(#[from] QemuLaunchArtifactIdentityError),
    /// A private materialized guest file could not be created or persisted.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An archive, finding, candidate, or reproduction object failed validation.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// A retained capture manifest or chunk failed validation.
    #[error(transparent)]
    CaptureStore(#[from] FindingReplayCaptureStoreError),
    /// The model reproduction payload was malformed.
    #[error(transparent)]
    Model(#[from] crucible::EngineError),
    /// The decoded production capture failed validation.
    #[error(transparent)]
    ProductionCapture(#[from] FindingProductionReplayCaptureError),
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixture setup and exact filesystem assertions.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn embedded_guest_asset_materializes_once_with_private_permissions() {
        let directory = tempfile::tempdir().expect("private materialization directory");
        let asset = FindingProductionReplayAsset::from_bytes(b"guest kernel".to_vec());
        let mut paths = BTreeMap::new();

        let first = materialize_asset(directory.path(), &asset, &mut paths)
            .expect("materialize authenticated asset");
        let second = materialize_asset(directory.path(), &asset, &mut paths)
            .expect("deduplicate authenticated asset");

        assert_eq!(first, second);
        assert_eq!(paths.len(), 1);
        assert_eq!(
            std::fs::read(&first).expect("read materialized asset"),
            asset.bytes()
        );
        assert_eq!(
            std::fs::metadata(&first)
                .expect("materialized asset metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
