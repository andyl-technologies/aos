//! Durable single-host bootstrap for the local campaign service.
//!
//! This module composes the managed Unix endpoint, strict peer policy, fixed
//! listener, and directory-backed campaign repository behind one lifecycle.
//! The state root is an operator-owned namespace with a lifetime exclusive
//! lock, preventing two cooperating daemon incarnations from claiming the sole
//! writer repository through different socket paths. Startup may install a
//! fixed runtime set; an embedded owner can also retain a weak bounded handle
//! for post-bind attachment without exposing repository or component-authority
//! capabilities.

use std::fs::{self, File, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crucible::{ScenarioDefForm, Schedule};
use crucible_campaign::{
    CampaignAuthorizationError, CampaignHash, CampaignName, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignRepository, CampaignServiceOperation,
    CandidateGeneratorSpec, CandidateGeneratorSpecId, ConfigurationArtifactId,
    DebuggerAuthorityKey, PlannerAuthorityKey,
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use rustix::fs::{FlockOperation, Mode, OFlags, flock};

use crate::{
    AttachedCanonicalCampaignRuntime, AttachedPackagedQemuExecutor, CampaignLoopbackEndpointConfig,
    CampaignLoopbackEndpointError, CampaignLoopbackListenerError, CampaignLoopbackServer,
    CampaignLoopbackServerConfig, CampaignLoopbackServerReport, CampaignLoopbackServerShutdown,
    CanonicalCampaignRuntimeConfig, CanonicalCampaignRuntimeError, CrucibleArtifactError,
    CrucibleCampaignArtifactStore, MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES,
    MAX_CAMPAIGN_POLICY_BYTES, PackagedQemuExecutor, PackagedQemuExecutorConfig,
    PackagedQemuExecutorError, PackagedQemuExecutorJoinError, PackagedQemuExecutorStartError,
    PreparedCanonicalCampaignRuntime, UnixPeerCampaignPolicy, UnixPeerCampaignPolicyLoadError,
    prepare_canonical_campaign_runtime, prepare_packaged_qemu_executor,
};

const STATE_LOCK_FILE: &str = ".crucible-campaign-repository.lock";
const OBJECT_DIRECTORY: &str = "objects";
const REF_DIRECTORY: &str = "refs";
const MAX_DEPLOYMENT_PATH_BYTES: usize = 4_095;
const COMPONENT_AUTHORITY_MAGIC: &[u8; 8] = b"CRUCCA01";
const COMPONENT_AUTHORITY_FILE_BYTES: usize = 8 + 32 + 32;

mod runtime_registry;
mod service;

pub use runtime_registry::CampaignRuntimeAttachmentHandle;
use runtime_registry::CampaignRuntimeRegistryOwner;

/// Complete deployment contract for one durable local campaign service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignLocalServiceConfig {
    endpoint: CampaignLoopbackEndpointConfig,
    state_directory: PathBuf,
    policy_path: PathBuf,
    component_authority_path: Option<PathBuf>,
    mode: CampaignLocalServiceMode,
    server: CampaignLoopbackServerConfig,
}

/// Mutation policy applied by one local campaign service incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignLocalServiceMode {
    /// Permits every operation granted by the strict deployment policy.
    ReadWrite,
    /// Denies every mutation even when the deployment policy grants it.
    ReadOnly,
}

impl CampaignLocalServiceMode {
    const fn permits(self, operation: CampaignServiceOperation) -> bool {
        match self {
            Self::ReadWrite => true,
            Self::ReadOnly => match operation {
                CampaignServiceOperation::CreateCampaign
                | CampaignServiceOperation::DeriveCampaign
                | CampaignServiceOperation::ApplyCampaignCommand
                | CampaignServiceOperation::PinCampaign
                | CampaignServiceOperation::SubmitBranchRequest
                | CampaignServiceOperation::AttachCampaignRuntime => false,
                CampaignServiceOperation::ListCampaigns
                | CampaignServiceOperation::GetCampaign
                | CampaignServiceOperation::GetCampaignSnapshot
                | CampaignServiceOperation::WatchCampaign
                | CampaignServiceOperation::QueryCampaignGraph
                | CampaignServiceOperation::QueryCampaignFindings
                | CampaignServiceOperation::GetCampaignFindingObject
                | CampaignServiceOperation::ExplainCampaignAttempt
                | CampaignServiceOperation::GetCampaignPlannerRankings
                | CampaignServiceOperation::GetCampaignGraphObject
                | CampaignServiceOperation::QueryCampaignChoices
                | CampaignServiceOperation::QueryCampaignFrontier
                | CampaignServiceOperation::GetCampaignFrontierObject
                | CampaignServiceOperation::GetCampaignChoiceObject => true,
            },
        }
    }
}

impl CampaignLocalServiceConfig {
    /// Builds one exact local service deployment contract.
    ///
    /// The state directory and policy file must already exist. Their exact
    /// owner is inherited from `endpoint`; both paths must be absolute, free of
    /// dot components and NUL, and bounded to 4,095 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::InvalidStatePath`] or
    /// [`CampaignLocalServiceError::InvalidPolicyPath`] when a deployment path
    /// is not structurally admissible.
    pub fn new(
        endpoint: CampaignLoopbackEndpointConfig,
        state_directory: impl Into<PathBuf>,
        policy_path: impl Into<PathBuf>,
        mode: CampaignLocalServiceMode,
        server: CampaignLoopbackServerConfig,
    ) -> Result<Self, CampaignLocalServiceError> {
        let state_directory = state_directory.into();
        if !valid_deployment_path(&state_directory) {
            return Err(CampaignLocalServiceError::InvalidStatePath);
        }
        let policy_path = policy_path.into();
        if !valid_deployment_path(&policy_path) {
            return Err(CampaignLocalServiceError::InvalidPolicyPath);
        }
        Ok(Self {
            endpoint,
            state_directory,
            policy_path,
            component_authority_path: None,
            mode,
            server,
        })
    }

    /// Configures one exact planner/debugger component-authority file.
    ///
    /// The file is a 72-byte version-one binary record containing the eight
    /// bytes `CRUCCA01`, one 32-byte planner key, and one distinct 32-byte
    /// debugger key. It must be an absolute, canonical deployment path. File
    /// ownership, mode, identity, and contents are authenticated during
    /// [`Self::prepare`] before repository state is opened.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::InvalidComponentAuthorityPath`]
    /// when the path is relative, noncanonical, empty, contains NUL, or
    /// exceeds 4,095 bytes.
    pub fn with_component_authority_path(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, CampaignLocalServiceError> {
        let path = path.into();
        if !valid_deployment_path(&path) {
            return Err(CampaignLocalServiceError::InvalidComponentAuthorityPath);
        }
        self.component_authority_path = Some(path);
        Ok(self)
    }

    /// Returns the managed Unix endpoint contract.
    #[must_use]
    pub const fn endpoint(&self) -> &CampaignLoopbackEndpointConfig {
        &self.endpoint
    }

    /// Returns the exact durable repository root.
    #[must_use]
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    /// Returns the exact strict deployment-policy path.
    #[must_use]
    pub fn policy_path(&self) -> &Path {
        &self.policy_path
    }

    /// Returns the configured component-authority file, when present.
    #[must_use]
    pub fn component_authority_path(&self) -> Option<&Path> {
        self.component_authority_path.as_deref()
    }

    /// Returns the exact read-only or read-write service mode.
    #[must_use]
    pub const fn mode(&self) -> CampaignLocalServiceMode {
        self.mode
    }

    /// Returns the bounded listener configuration.
    #[must_use]
    pub const fn server(&self) -> CampaignLoopbackServerConfig {
        self.server
    }

    /// Authenticates deployment input and acquires one exclusive repository.
    ///
    /// Policy authentication is read-only and precedes any state-directory or
    /// socket mutation. The returned owner retains the repository lock and has
    /// not yet created or bound the managed endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] when the policy, state namespace,
    /// durable subdirectories, or repository lock cannot be authenticated and
    /// acquired exactly.
    pub fn prepare(&self) -> Result<PreparedCampaignLocalService, CampaignLocalServiceError> {
        let policy = Arc::new(load_policy(
            &self.policy_path,
            self.endpoint.owner_user_id(),
            self.endpoint.owner_group_id(),
        )?);
        let component_authorities = self
            .component_authority_path
            .as_deref()
            .map(|path| {
                load_component_authorities(
                    path,
                    self.endpoint.owner_user_id(),
                    self.endpoint.owner_group_id(),
                )
            })
            .transpose()?;
        let state = CampaignStateOwner::open(
            &self.state_directory,
            self.endpoint.owner_user_id(),
            self.endpoint.owner_group_id(),
        )?;

        let blobs = Arc::new(DirectoryBlobBackend::new(
            "campaign-primary",
            state.object_directory.clone(),
        ));
        let refs = Arc::new(DirectoryRefBackend::new(state.ref_directory.clone()));
        let (repository, planner_authority) = match component_authorities {
            Some((planner, debugger)) => {
                let retained_planner = planner.clone();
                (
                    Arc::new(
                        CampaignRepository::with_component_authorities(
                            blobs, refs, planner, debugger,
                        )
                        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?,
                    ),
                    Some(retained_planner),
                )
            }
            None => (Arc::new(CampaignRepository::new(blobs, refs)), None),
        };
        Ok(PreparedCampaignLocalService {
            endpoint: self.endpoint.clone(),
            server: self.server,
            repository,
            planner_authority,
            policy,
            mode: self.mode,
            state,
        })
    }

    /// Authenticates deployment input and opens one exclusive local service.
    ///
    /// This is equivalent to [`Self::prepare`] followed immediately by
    /// [`PreparedCampaignLocalService::bind`].
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] when preparation or managed
    /// endpoint binding fails.
    pub fn open(&self) -> Result<CampaignLocalService, CampaignLocalServiceError> {
        self.prepare()?.bind()
    }
}

/// Exclusive pre-bind owner of one durable campaign repository.
///
/// This type state permits narrow, verifier-backed immutable imports while the
/// repository lock is held and before any service endpoint exists. Binding
/// consumes the owner, so import authority cannot be retained through this API
/// after request serving begins.
pub struct PreparedCampaignLocalService {
    endpoint: CampaignLoopbackEndpointConfig,
    server: CampaignLoopbackServerConfig,
    repository: Arc<CampaignRepository>,
    planner_authority: Option<PlannerAuthorityKey>,
    policy: Arc<UnixPeerCampaignPolicy>,
    mode: CampaignLocalServiceMode,
    state: CampaignStateOwner,
}

impl PreparedCampaignLocalService {
    /// Prepares one packaged QEMU executor against this exact repository.
    ///
    /// No executor thread is created. The returned owner binds its managed
    /// endpoint and can be started before [`Self::prepare_runtime`] connects to
    /// it, while retaining exact repository-incarnation identity for the final
    /// service composition.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::RuntimeReadOnly`] in read-only
    /// mode or [`CampaignLocalServiceError::PackagedExecutor`] when durable,
    /// host-resource, worker, or endpoint preparation fails.
    pub fn prepare_packaged_executor(
        &self,
        config: PackagedQemuExecutorConfig,
    ) -> Result<PackagedQemuExecutor, CampaignLocalServiceError> {
        if self.mode == CampaignLocalServiceMode::ReadOnly {
            return Err(CampaignLocalServiceError::RuntimeReadOnly);
        }
        prepare_packaged_qemu_executor(Arc::clone(&self.repository), config).map_err(Into::into)
    }

    /// Verifies and imports one exact Crucible scenario and configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::ArtifactImportReadOnly`] when the
    /// service was configured read-only, or
    /// [`CampaignLocalServiceError::Artifact`] when verification or immutable
    /// publication fails.
    pub fn import_configuration(
        &self,
        scenario: &ScenarioDefForm,
        schedule: &Schedule,
    ) -> Result<ConfigurationArtifactId, CampaignLocalServiceError> {
        self.require_artifact_import()?;
        CrucibleCampaignArtifactStore::new(Arc::clone(&self.repository))
            .import_configuration(scenario, schedule)
            .map_err(Into::into)
    }

    /// Verifies and imports one closed candidate-generator specification.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::ArtifactImportReadOnly`] when the
    /// service was configured read-only, or
    /// [`CampaignLocalServiceError::Artifact`] when verification or immutable
    /// publication fails.
    pub fn import_generator(
        &self,
        generator: &CandidateGeneratorSpec,
    ) -> Result<CandidateGeneratorSpecId, CampaignLocalServiceError> {
        self.require_artifact_import()?;
        CrucibleCampaignArtifactStore::new(Arc::clone(&self.repository))
            .import_generator(generator)
            .map_err(Into::into)
    }

    /// Prepares one named canonical runtime against an authenticated executor.
    ///
    /// The supplied stream must already be connected to and authenticated as
    /// the intended local executor by the deployment owner. Capability and
    /// lineage negotiation complete before the deterministic planner basis is
    /// published. The returned owner has not started a runtime thread.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError::RuntimeReadOnly`] in read-only
    /// mode, [`CampaignLocalServiceError::RuntimeAuthorityUnavailable`] when
    /// no component-authority file was configured, or
    /// [`CampaignLocalServiceError::Runtime`] for attachment failure.
    pub fn prepare_runtime(
        &self,
        executor_stream: UnixStream,
        config: &CanonicalCampaignRuntimeConfig,
    ) -> Result<PreparedCanonicalCampaignRuntime, CampaignLocalServiceError> {
        if self.mode == CampaignLocalServiceMode::ReadOnly {
            return Err(CampaignLocalServiceError::RuntimeReadOnly);
        }
        let planner_authority = self
            .planner_authority
            .as_ref()
            .ok_or(CampaignLocalServiceError::RuntimeAuthorityUnavailable)?;
        prepare_canonical_campaign_runtime(
            Arc::clone(&self.repository),
            planner_authority.clone(),
            executor_stream,
            config,
        )
        .map_err(Into::into)
    }

    /// Binds the managed endpoint and consumes pre-bind import authority.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] when endpoint acquisition or
    /// listener construction fails.
    pub fn bind(self) -> Result<CampaignLocalService, CampaignLocalServiceError> {
        self.bind_inner(Vec::new(), None)
    }

    /// Binds the managed endpoint and starts one prepared canonical runtime.
    ///
    /// The runtime must have been prepared by this exact repository owner.
    /// Endpoint binding completes before the runtime thread starts. Runtime
    /// exit subsequently stops the service listener, and service shutdown
    /// cancels and joins the runtime before repository ownership is released.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] when the runtime belongs to
    /// another repository, endpoint binding fails, or the fixed runtime thread
    /// cannot start.
    pub fn bind_with_runtime(
        self,
        runtime: PreparedCanonicalCampaignRuntime,
    ) -> Result<CampaignLocalService, CampaignLocalServiceError> {
        self.bind_with_runtimes(vec![runtime])
    }

    /// Binds the managed endpoint and starts multiple prepared runtimes.
    ///
    /// Runtime identities are sorted by canonical campaign name before any
    /// thread starts. Every runtime must belong to this exact repository,
    /// campaign names must be unique, and the fixed attachment ceiling applies
    /// before endpoint binding. A terminal result from any runtime stops the
    /// shared service; shutdown joins every runtime before repository release.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] when the set is empty, exceeds the
    /// attachment ceiling, repeats a campaign, contains another repository's
    /// runtime, endpoint binding fails, or a runtime thread cannot start.
    pub fn bind_with_runtimes(
        self,
        mut runtimes: Vec<PreparedCanonicalCampaignRuntime>,
    ) -> Result<CampaignLocalService, CampaignLocalServiceError> {
        self.validate_and_order_runtimes(&mut runtimes)?;
        self.bind_inner(runtimes, None)
    }

    /// Binds the endpoint with one runtime and its packaged executor owner.
    ///
    /// Both prepared values must name this exact repository incarnation.
    /// Runtime or executor termination closes the CampaignService listener;
    /// listener shutdown then joins both owners before repository release.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignLocalServiceError`] for repository mismatch, endpoint
    /// acquisition failure, or fixed runtime startup failure.
    pub fn bind_with_runtime_and_executor(
        self,
        runtime: PreparedCanonicalCampaignRuntime,
        executor: AttachedPackagedQemuExecutor,
    ) -> Result<CampaignLocalService, CampaignLocalServiceError> {
        if !runtime.uses_repository(&self.repository) || !executor.uses_repository(&self.repository)
        {
            return Err(CampaignLocalServiceError::RuntimeRepositoryMismatch);
        }
        self.bind_inner(vec![runtime], Some(executor))
    }

    fn bind_inner(
        self,
        runtimes: Vec<PreparedCanonicalCampaignRuntime>,
        mut executor: Option<AttachedPackagedQemuExecutor>,
    ) -> Result<CampaignLocalService, CampaignLocalServiceError> {
        let Self {
            endpoint,
            server: server_config,
            repository,
            planner_authority,
            policy,
            mode,
            state,
        } = self;
        let listener = endpoint.bind()?;
        let server = CampaignLoopbackServer::from_managed_listener(
            listener,
            Arc::clone(&repository),
            Arc::clone(&policy),
            Arc::new(CampaignLocalAuthorizer { policy, mode }),
            server_config,
        )?;
        let runtime_registry = CampaignRuntimeRegistryOwner::new(
            repository,
            planner_authority,
            mode,
            server.shutdown_handle(),
            state,
        );
        for runtime in runtimes {
            if let Err(source) = runtime_registry.attach_prepared(runtime) {
                let runtime_result = runtime_registry.close_and_join();
                let executor_result = executor
                    .take()
                    .map(AttachedPackagedQemuExecutor::shutdown_and_join)
                    .transpose()
                    .map(|_| ())
                    .map_err(CampaignLocalServiceError::PackagedExecutorJoin);
                executor_result?;
                runtime_result?;
                return Err(source);
            }
        }
        Ok(CampaignLocalService {
            server,
            runtime_registry,
            executor,
        })
    }

    fn validate_and_order_runtimes(
        &self,
        runtimes: &mut [PreparedCanonicalCampaignRuntime],
    ) -> Result<(), CampaignLocalServiceError> {
        if runtimes.is_empty() || runtimes.len() > MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES {
            return Err(CampaignLocalServiceError::InvalidRuntimeCount);
        }
        if runtimes
            .iter()
            .any(|runtime| !runtime.uses_repository(&self.repository))
        {
            return Err(CampaignLocalServiceError::RuntimeRepositoryMismatch);
        }

        runtimes.sort_by(|left, right| left.campaign().cmp(right.campaign()));
        if runtimes
            .windows(2)
            .any(|pair| pair[0].campaign() == pair[1].campaign())
        {
            return Err(CampaignLocalServiceError::DuplicateRuntimeCampaign);
        }
        Ok(())
    }

    fn require_artifact_import(&self) -> Result<(), CampaignLocalServiceError> {
        if self.mode == CampaignLocalServiceMode::ReadOnly {
            Err(CampaignLocalServiceError::ArtifactImportReadOnly)
        } else {
            Ok(())
        }
    }
}

/// Exclusive owner of one durable local CampaignService incarnation.
pub struct CampaignLocalService {
    server: CampaignLoopbackServer<UnixPeerCampaignPolicy, CampaignLocalAuthorizer>,
    executor: Option<AttachedPackagedQemuExecutor>,
    // This owner is last so its repository lock outlives runtime and executor
    // cleanup even when the containing service is dropped without `serve`.
    runtime_registry: CampaignRuntimeRegistryOwner,
}

impl CampaignLocalService {
    /// Returns a weak capability for bounded post-bind runtime attachment.
    ///
    /// The handle exposes no repository or component-authority access and
    /// becomes permanently closed when this service begins shutdown or is
    /// dropped. An attachment already in progress is allowed to finish or fail
    /// before repository namespace ownership is released.
    #[must_use]
    pub fn runtime_attachment_handle(&self) -> CampaignRuntimeAttachmentHandle {
        self.runtime_registry.handle()
    }
}

struct CampaignLocalAuthorizer {
    policy: Arc<UnixPeerCampaignPolicy>,
    mode: CampaignLocalServiceMode,
}

impl CampaignPrincipalAuthorizer for CampaignLocalAuthorizer {
    fn authorize_all_campaigns(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if !self.mode.permits(operation) {
            return Err(CampaignAuthorizationError::Unauthorized);
        }
        self.policy
            .authorize_all_campaigns(principal, operation, request_digest)
    }

    fn authorize(
        &self,
        principal: &CampaignPrincipal,
        operation: CampaignServiceOperation,
        campaign: &CampaignName,
        request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        if !self.mode.permits(operation) {
            return Err(CampaignAuthorizationError::Unauthorized);
        }
        self.policy
            .authorize(principal, operation, campaign, request_digest)
    }
}

/// Failure to authenticate, acquire, or serve one local campaign deployment.
#[derive(Debug, thiserror::Error)]
pub enum CampaignLocalServiceError {
    /// The durable state path was relative, noncanonical, unbounded, or empty.
    #[error("campaign service state path is invalid")]
    InvalidStatePath,
    /// The deployment-policy path was relative, noncanonical, unbounded, or empty.
    #[error("campaign service policy path is invalid")]
    InvalidPolicyPath,
    /// The component-authority path was relative, noncanonical, unbounded, or empty.
    #[error("campaign service component-authority path is invalid")]
    InvalidComponentAuthorityPath,
    /// The state root was not a secure exact-owner directory.
    #[error("campaign service state directory is invalid")]
    InvalidStateDirectory,
    /// Another cooperating daemon owns the durable repository lock.
    #[error("campaign service repository is already in use")]
    StateInUse,
    /// The durable repository lock was not an owner-only regular file.
    #[error("campaign service repository lock is invalid")]
    InvalidStateLock,
    /// A required object/ref subdirectory was not a secure exact-owner directory.
    #[error("campaign service repository subdirectory is invalid")]
    InvalidStateSubdirectory,
    /// The policy was not a secure exact-owner regular file.
    #[error("campaign service policy file is invalid")]
    InvalidPolicyFile,
    /// The component-authority file failed ownership, mode, identity, or body validation.
    #[error("campaign service component-authority file is invalid")]
    InvalidComponentAuthorityFile,
    /// The strict policy body was malformed or violated a policy invariant.
    #[error(transparent)]
    Policy(#[from] UnixPeerCampaignPolicyLoadError),
    /// The managed Unix endpoint could not be acquired.
    #[error(transparent)]
    Endpoint(#[from] CampaignLoopbackEndpointError),
    /// A pre-bind artifact import was attempted in read-only mode.
    #[error("campaign artifact import is unavailable in read-only mode")]
    ArtifactImportReadOnly,
    /// Verifier-backed immutable artifact import failed.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// Runtime attachment was requested in read-only service mode.
    #[error("campaign runtime attachment is unavailable in read-only mode")]
    RuntimeReadOnly,
    /// Runtime attachment was requested without a planner authority.
    #[error("campaign runtime attachment requires component authorities")]
    RuntimeAuthorityUnavailable,
    /// A prepared runtime belongs to another repository instance.
    #[error("campaign runtime belongs to another repository instance")]
    RuntimeRepositoryMismatch,
    /// No runtime or more than the fixed attachment ceiling was supplied.
    #[error("campaign runtime attachment count is outside 1..=256")]
    InvalidRuntimeCount,
    /// More than one runtime named the same campaign.
    #[error("campaign runtime attachments contain a duplicate campaign")]
    DuplicateRuntimeCampaign,
    /// Runtime attachment was attempted after the service began shutdown.
    #[error("campaign runtime attachment owner is closed")]
    RuntimeAttachmentClosed,
    /// A runtime-registry invariant panic poisoned shared operational state.
    #[error("campaign runtime attachment registry is poisoned")]
    RuntimeRegistryPoisoned,
    /// Canonical planner/executor runtime preparation, start, or execution failed.
    #[error(transparent)]
    Runtime(#[from] CanonicalCampaignRuntimeError),
    /// Packaged executor preparation failed before its owner thread started.
    #[error(transparent)]
    PackagedExecutor(#[from] PackagedQemuExecutorError),
    /// The fixed packaged executor owner thread could not be created.
    #[error(transparent)]
    PackagedExecutorStart(#[from] PackagedQemuExecutorStartError),
    /// The packaged executor listener or semantic workers failed while joined.
    #[error(transparent)]
    PackagedExecutorJoin(#[from] PackagedQemuExecutorJoinError),
    /// The bounded runtime monitor thread could not be created.
    #[error("campaign runtime monitor thread could not be created")]
    RuntimeMonitorSpawn {
        /// Underlying operating-system failure.
        source: io::Error,
    },
    /// The bounded runtime monitor thread escaped through an invariant panic.
    #[error("campaign runtime monitor thread panicked")]
    RuntimeMonitorPanicked,
    /// The packaged-executor completion monitor could not be created.
    #[error("packaged executor monitor thread could not be created")]
    PackagedExecutorMonitorSpawn {
        /// Underlying operating-system failure.
        source: io::Error,
    },
    /// The packaged-executor completion monitor escaped through a panic.
    #[error("packaged executor monitor thread panicked")]
    PackagedExecutorMonitorPanicked,
    /// The fixed listener could not be configured or failed while serving.
    #[error(transparent)]
    Listener(#[from] CampaignLoopbackListenerError),
    /// A deployment filesystem operation failed.
    #[error("campaign service {operation} failed for {}: {source}", path.display())]
    Io {
        /// Stable operation category.
        operation: &'static str,
        /// Exact affected deployment path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: io::Error,
    },
}

struct CampaignStateOwner {
    object_directory: PathBuf,
    ref_directory: PathBuf,
    _root: File,
    _lock: File,
}

impl CampaignStateOwner {
    fn open(path: &Path, user_id: u32, group_id: u32) -> Result<Self, CampaignLocalServiceError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| io_error("stat-state-directory", path, source))?;
        validate_secure_directory(&metadata, user_id, group_id)
            .map_err(|()| CampaignLocalServiceError::InvalidStateDirectory)?;
        let root =
            File::open(path).map_err(|source| io_error("open-state-directory", path, source))?;
        require_same_file(&root, &metadata, path, "state-directory")?;

        let lock_path = path.join(STATE_LOCK_FILE);
        let lock: File = rustix::fs::open(
            &lock_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| {
            io_error(
                "open-state-lock",
                &lock_path,
                io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?
        .into();
        let lock_metadata = lock
            .metadata()
            .map_err(|source| io_error("stat-state-lock", &lock_path, source))?;
        if !lock_metadata.is_file()
            || lock_metadata.uid() != user_id
            || lock_metadata.gid() != group_id
        {
            return Err(CampaignLocalServiceError::InvalidStateLock);
        }
        rustix::fs::fchmod(&lock, Mode::RUSR | Mode::WUSR).map_err(|source| {
            io_error(
                "set-state-lock-mode",
                &lock_path,
                io::Error::from_raw_os_error(source.raw_os_error()),
            )
        })?;
        if lock
            .metadata()
            .map_err(|source| io_error("restat-state-lock", &lock_path, source))?
            .mode()
            & 0o777
            != 0o600
        {
            return Err(CampaignLocalServiceError::InvalidStateLock);
        }
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|source| {
            if source == rustix::io::Errno::WOULDBLOCK {
                CampaignLocalServiceError::StateInUse
            } else {
                io_error(
                    "lock-state-directory",
                    &lock_path,
                    io::Error::from_raw_os_error(source.raw_os_error()),
                )
            }
        })?;
        revalidate_state_path(&root, &metadata, path, user_id, group_id)?;

        let object_directory = prepare_subdirectory(path, OBJECT_DIRECTORY, user_id, group_id)?;
        let ref_directory = prepare_subdirectory(path, REF_DIRECTORY, user_id, group_id)?;
        revalidate_state_path(&root, &metadata, path, user_id, group_id)?;
        root.sync_all()
            .map_err(|source| io_error("sync-state-directory", path, source))?;
        Ok(Self {
            object_directory,
            ref_directory,
            _root: root,
            _lock: lock,
        })
    }
}

fn load_policy(
    path: &Path,
    user_id: u32,
    group_id: u32,
) -> Result<UnixPeerCampaignPolicy, CampaignLocalServiceError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("stat-policy-file", path, source))?;
    if !path_metadata.is_file()
        || path_metadata.uid() != user_id
        || path_metadata.gid() != group_id
        || path_metadata.mode() & 0o022 != 0
    {
        return Err(CampaignLocalServiceError::InvalidPolicyFile);
    }
    let mut file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            "open-policy-file",
            path,
            io::Error::from_raw_os_error(source.raw_os_error()),
        )
    })?
    .into();
    let file_metadata = file
        .metadata()
        .map_err(|source| io_error("stat-open-policy-file", path, source))?;
    if file_metadata.dev() != path_metadata.dev()
        || file_metadata.ino() != path_metadata.ino()
        || !file_metadata.is_file()
        || file_metadata.uid() != user_id
        || file_metadata.gid() != group_id
        || file_metadata.mode() & 0o022 != 0
    {
        return Err(CampaignLocalServiceError::InvalidPolicyFile);
    }
    if file_metadata.len() > MAX_CAMPAIGN_POLICY_BYTES as u64 {
        return Err(UnixPeerCampaignPolicyLoadError::TooLarge.into());
    }

    let mut bytes = Vec::with_capacity(file_metadata.len() as usize);
    file.by_ref()
        .take((MAX_CAMPAIGN_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read-policy-file", path, source))?;
    if bytes.len() > MAX_CAMPAIGN_POLICY_BYTES {
        return Err(UnixPeerCampaignPolicyLoadError::TooLarge.into());
    }
    UnixPeerCampaignPolicy::from_toml_bytes(&bytes).map_err(Into::into)
}

fn load_component_authorities(
    path: &Path,
    user_id: u32,
    group_id: u32,
) -> Result<(PlannerAuthorityKey, DebuggerAuthorityKey), CampaignLocalServiceError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("stat-component-authority-file", path, source))?;
    if !path_metadata.is_file()
        || path_metadata.uid() != user_id
        || path_metadata.gid() != group_id
        || path_metadata.mode() & 0o777 != 0o600
        || path_metadata.len() != COMPONENT_AUTHORITY_FILE_BYTES as u64
    {
        return Err(CampaignLocalServiceError::InvalidComponentAuthorityFile);
    }

    let mut file: File = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| {
        io_error(
            "open-component-authority-file",
            path,
            io::Error::from_raw_os_error(source.raw_os_error()),
        )
    })?
    .into();
    let file_metadata = file
        .metadata()
        .map_err(|source| io_error("stat-open-component-authority-file", path, source))?;
    if file_metadata.dev() != path_metadata.dev()
        || file_metadata.ino() != path_metadata.ino()
        || !file_metadata.is_file()
        || file_metadata.uid() != user_id
        || file_metadata.gid() != group_id
        || file_metadata.mode() & 0o777 != 0o600
        || file_metadata.len() != COMPONENT_AUTHORITY_FILE_BYTES as u64
    {
        return Err(CampaignLocalServiceError::InvalidComponentAuthorityFile);
    }

    let mut bytes = [0_u8; COMPONENT_AUTHORITY_FILE_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read-component-authority-file", path, source))?;
    if &bytes[..COMPONENT_AUTHORITY_MAGIC.len()] != COMPONENT_AUTHORITY_MAGIC {
        return Err(CampaignLocalServiceError::InvalidComponentAuthorityFile);
    }
    let planner_bytes: [u8; 32] = bytes[8..40]
        .try_into()
        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?;
    let debugger_bytes: [u8; 32] = bytes[40..72]
        .try_into()
        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?;
    let planner = PlannerAuthorityKey::from_bytes(planner_bytes)
        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?;
    let debugger = DebuggerAuthorityKey::from_bytes(debugger_bytes)
        .map_err(|_| CampaignLocalServiceError::InvalidComponentAuthorityFile)?;
    if planner_bytes == debugger_bytes {
        return Err(CampaignLocalServiceError::InvalidComponentAuthorityFile);
    }
    Ok((planner, debugger))
}

fn prepare_subdirectory(
    root: &Path,
    name: &'static str,
    user_id: u32,
    group_id: u32,
) -> Result<PathBuf, CampaignLocalServiceError> {
    let path = root.join(name);
    match fs::create_dir(&path) {
        Ok(()) => fs::set_permissions(&path, Permissions::from_mode(0o700))
            .map_err(|source| io_error("set-state-subdirectory-mode", &path, source))?,
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(io_error("create-state-subdirectory", &path, source)),
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|source| io_error("stat-state-subdirectory", &path, source))?;
    if validate_secure_directory(&metadata, user_id, group_id).is_err()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(CampaignLocalServiceError::InvalidStateSubdirectory);
    }
    Ok(path)
}

fn validate_secure_directory(
    metadata: &fs::Metadata,
    user_id: u32,
    group_id: u32,
) -> Result<(), ()> {
    if metadata.is_dir()
        && metadata.uid() == user_id
        && metadata.gid() == group_id
        && metadata.mode() & 0o022 == 0
    {
        Ok(())
    } else {
        Err(())
    }
}

fn require_same_file(
    file: &File,
    path_metadata: &fs::Metadata,
    path: &Path,
    operation: &'static str,
) -> Result<(), CampaignLocalServiceError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error(operation, path, source))?;
    if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
        return Err(match operation {
            "policy-file" => CampaignLocalServiceError::InvalidPolicyFile,
            _ => CampaignLocalServiceError::InvalidStateDirectory,
        });
    }
    Ok(())
}

fn revalidate_state_path(
    root: &File,
    original: &fs::Metadata,
    path: &Path,
    user_id: u32,
    group_id: u32,
) -> Result<(), CampaignLocalServiceError> {
    require_same_file(root, original, path, "state-directory")?;
    let current = fs::symlink_metadata(path)
        .map_err(|source| io_error("restat-state-directory", path, source))?;
    if current.dev() != original.dev()
        || current.ino() != original.ino()
        || validate_secure_directory(&current, user_id, group_id).is_err()
    {
        return Err(CampaignLocalServiceError::InvalidStateDirectory);
    }
    Ok(())
}

fn valid_deployment_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
        && !bytes.contains(&0)
        && bytes.len() <= MAX_DEPLOYMENT_PATH_BYTES
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> CampaignLocalServiceError {
    CampaignLocalServiceError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests;
