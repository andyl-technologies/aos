//! Installed node actor, exclusive persistent namespace, and retained GC owner.
//!
//! ```text
//! NodeDaemonPolicyV1 = {format:"crucible.node-daemon-policy", version:1,
//!   state_directory:absolute-private-directory, socket:owned-child-path,
//!   device_executable:installed-path, expected_device:ContentRef,
//!   control_timeout_ms:1..60000, maximum_worlds:1..64,
//!   maximum_pending_requests:1..64}
//! ```

use std::{
    collections::BTreeSet,
    fs::{self, File},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crucible_campaign::CampaignRepository;
use crucible_cas::content_store::{
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};
use crucible_node_contract::{Bytes, ContentRef, Validate, canonical};
use serde::{Deserialize, Serialize};

use super::{
    NodeControlCommand, NodeControlError, NodeControlReply, NodeControlRequest, NodeControlResult,
    execution_id,
    host_state_service::{NodeHostStateRetention, NodeHostStateService},
    refused, transport,
};
use crate::node_observed_executor::{
    InstalledIoArtifact, NativeWorldRetention, NativeWorldService, NodeObservationRetention,
    NodeObservationService, NodeObservationServiceConfig,
};

/// Binds private operator policy to an independently expected immutable source.
///
/// Path entries preserve the original policy representation. Archive-only
/// entries require policy edition two and authorize authenticated source-closure
/// lookup only; they never authorize construction of a fresh native source.
/// Remote requests cannot enroll either form.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum NodeImmutableArtifactPolicy {
    /// Measures the actual installed file before admitting the local endpoint.
    Path {
        /// Names the absolute source file enrolled before endpoint admission.
        path: PathBuf,
        /// Gives the independently authenticated complete content identity.
        expected: ContentRef,
    },
    /// Requires source bytes from an authenticated complete host archive.
    ArchiveOnly {
        /// Explicitly selects archive-only source enrollment.
        mode: NodeArchiveArtifactMode,
        /// Gives the independently authenticated complete content identity.
        expected: ContentRef,
    },
}

/// Explicitly selects source-closure lookup without path or native authority.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeArchiveArtifactMode {
    /// Permits only authenticated original archive materialization.
    ArchiveOnly,
}

/// Selects a private local daemon and independently expected installed companion.
///
/// This host policy is loaded before the endpoint exists. The expected artifact
/// must come from the operator's authenticated source-package inventory; a client
/// request cannot supply or replace installation policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDaemonPolicy {
    /// Names the exact installed-policy format.
    pub format: String,
    /// Selects the supported policy edition.
    pub version: u32,
    /// Names an existing absolute owned directory with mode 0700.
    pub state_directory: PathBuf,
    /// Names the new endpoint inside the private state directory.
    pub socket: PathBuf,
    /// Names the actual source-built native device companion.
    pub device_executable: PathBuf,
    /// Requires independently expected complete executable artifact bytes.
    pub expected_device: ContentRef,
    /// Bounds one native control exchange, in milliseconds (1 through 60000).
    pub control_timeout_ms: u64,
    /// Bounds retained native worlds and cleanup capacity (1 through 64).
    pub maximum_worlds: usize,
    /// Bounds queued actor requests (1 through 64).
    pub maximum_pending_requests: usize,
    /// Enables edition-two exact-state custody with its own finite quota (2 through 64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_host_state_worlds: Option<usize>,
    /// Enables edition-three installed native state requests (1 through 64 queued).
    ///
    /// Native custody has eight fixed process-lifetime slots. Kernel reclamation
    /// retains original journals; this quota never resets that native capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_native_state_requests: Option<usize>,
    /// Enrolls immutable sources from private operator policy, never remote requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub immutable_artifacts: Vec<NodeImmutableArtifactPolicy>,
}

impl NodeDaemonPolicy {
    /// Decodes a bounded closed local installation policy.
    ///
    /// # Errors
    /// Refuses malformed JSON, duplicate keys, unsupported fields or editions,
    /// inconsistent paths, and excessive finite capacity.
    pub fn from_json(bytes: &[u8]) -> Result<Self, NodeControlError> {
        let value = canonical::parse_json(bytes, 64 * 1024)?;
        let policy: Self =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        policy.validate()?;
        Ok(policy)
    }

    fn installed_artifacts(&self) -> Vec<InstalledIoArtifact> {
        self.immutable_artifacts
            .iter()
            .map(|artifact| match artifact {
                NodeImmutableArtifactPolicy::Path { path, expected } => {
                    InstalledIoArtifact::path(path.clone(), expected.clone())
                }
                NodeImmutableArtifactPolicy::ArchiveOnly { expected, .. } => {
                    InstalledIoArtifact::archive_only(expected.clone())
                }
            })
            .collect()
    }

    fn validate(&self) -> Result<(), NodeControlError> {
        if self.format != "crucible.node-daemon-policy"
            || !matches!(self.version, 1..=3)
            || !self.device_executable.is_absolute()
            || !self.socket.is_absolute()
            || self.socket.parent() != Some(self.state_directory.as_path())
            || self.control_timeout_ms == 0
            || self.control_timeout_ms > 60_000
            || !(1..=64).contains(&self.maximum_worlds)
            || !(1..=64).contains(&self.maximum_pending_requests)
        {
            return Err(refused("invalid installed node daemon policy"));
        }
        match (
            self.version,
            self.maximum_host_state_worlds,
            self.maximum_native_state_requests,
        ) {
            (1, None, None) => {}
            (2, Some(capacity), None) if (2..=64).contains(&capacity) => {}
            (3, host, Some(native))
                if (1..=64).contains(&native)
                    && host.is_none_or(|capacity| (2..=64).contains(&capacity)) => {}
            _ => {
                return Err(refused(
                    "state policy requires the exact supported edition and explicit actor quotas",
                ));
            }
        }
        if self.immutable_artifacts.len() > 64 {
            return Err(refused("too many installed immutable artifacts"));
        }
        for artifact in &self.immutable_artifacts {
            match artifact {
                NodeImmutableArtifactPolicy::Path { path, expected } => {
                    if !path.is_absolute() {
                        return Err(refused("installed artifact path must be absolute"));
                    }
                    expected.validate()?;
                }
                NodeImmutableArtifactPolicy::ArchiveOnly { expected, .. } => {
                    if !matches!(self.version, 2 | 3) {
                        return Err(refused(
                            "archive-only enrollment requires policy edition two",
                        ));
                    }
                    expected.validate()?;
                }
            }
        }
        self.expected_device.validate()?;
        transport::private_directory(&self.state_directory)
    }
}

/// Owns the production local observation actor and its separate retention fence.
///
/// Installation, exclusive state ownership, and GC-owner registration precede
/// endpoint admission. The exposed protocol provides no deletion authority.
/// Shutdown keeps the original state lock and retention owner alive until every
/// native world is authentically reclaimed; uncertain cleanup cannot silently
/// unregister roots or permit another actor to dispatch the same execution.
pub struct NodeControlDaemon {
    listener: UnixListener,
    socket: PathBuf,
    socket_identity: (u64, u64),
    service: Option<NodeObservationService>,
    retention: NodeObservationRetention,
    state_service: Option<NodeHostStateService>,
    state_retention: Option<NodeHostStateRetention>,
    native_service: Option<NativeWorldService>,
    native_retention: Option<NativeWorldRetention>,
    repository: Arc<CampaignRepository>,
    _state_lock: File,
}

impl NodeControlDaemon {
    /// Verifies installation and starts an exclusive durable local node daemon.
    ///
    /// # Errors
    /// Refuses unsupported policy, unprivate state paths, existing socket names,
    /// competing owners, changed executable artifacts, or actor startup failure.
    pub fn start(policy: NodeDaemonPolicy) -> Result<Self, NodeControlError> {
        Self::start_inner(policy, None)
    }

    pub(super) fn start_inner(
        policy: NodeDaemonPolicy,
        transcripts: Option<crucible::node_adapters::transcript::TranscriptArchive>,
    ) -> Result<Self, NodeControlError> {
        policy.validate()?;
        let lock_path = policy.state_directory.join("node-daemon.lock");
        let fd = rustix::fs::open(
            &lock_path,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )
        .map_err(std::io::Error::from)?;
        let state_lock = File::from(fd);
        let metadata = state_lock.metadata()?;
        if !metadata.is_file()
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(refused("node daemon state lock is not privately owned"));
        }
        rustix::fs::flock(
            &state_lock,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(std::io::Error::from)?;

        let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
            "node-observations",
            policy.state_directory.join("blobs"),
        ));
        let refs: Arc<dyn MutableRefBackend> = Arc::new(DirectoryRefBackend::new(
            policy.state_directory.join("refs"),
        ));
        let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
        let service_configuration = NodeObservationServiceConfig {
            installed_artifacts: policy.installed_artifacts(),
            device_executable: policy.device_executable.clone(),
            expected_device: policy.expected_device.clone(),
            socket_parent: policy.state_directory.clone(),
            control_timeout: Duration::from_millis(policy.control_timeout_ms),
            maximum_worlds: policy.maximum_worlds,
            maximum_pending_requests: policy.maximum_pending_requests,
        };
        let service = if let Some(archive) = transcripts {
            NodeObservationService::start_with_transcript_archive(
                service_configuration,
                archive,
                repository.clone(),
                Arc::clone(&blobs),
                Arc::clone(&refs),
            )
        } else {
            NodeObservationService::start(
                service_configuration,
                repository.clone(),
                Arc::clone(&blobs),
                Arc::clone(&refs),
            )
        }
        .map_err(refused)?;

        // Register the separately owned retention fence before exposing admission.
        let retention = service.retention_owner();
        let state_service = policy
            .maximum_host_state_worlds
            .map(|maximum_worlds| {
                NodeHostStateService::start(
                    NodeObservationServiceConfig {
                        installed_artifacts: policy.installed_artifacts(),
                        device_executable: policy.device_executable.clone(),
                        expected_device: policy.expected_device.clone(),
                        socket_parent: policy.state_directory.clone(),
                        control_timeout: Duration::from_millis(policy.control_timeout_ms),
                        maximum_worlds,
                        maximum_pending_requests: policy.maximum_pending_requests,
                    },
                    policy.state_directory.join("host-state-archives"),
                    Arc::clone(&blobs),
                    Arc::clone(&refs),
                )
            })
            .transpose()?;
        let state_retention = state_service
            .as_ref()
            .map(NodeHostStateService::retention_owner);
        let native_service = policy
            .maximum_native_state_requests
            .map(|capacity| {
                let realm = policy.state_directory.join("native-state");
                match fs::DirBuilder::new().mode(0o700).create(&realm) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(NodeControlError::Io(error)),
                }
                // The actor independently checks canonical private ownership and
                // holds its exclusive realm lock through actual native reclamation.
                NativeWorldService::start(realm, capacity, Arc::clone(&blobs), Arc::clone(&refs))
                    .map_err(refused)
            })
            .transpose()?;
        let native_retention = native_service
            .as_ref()
            .map(NativeWorldService::retention_owner);
        let listener = UnixListener::bind(&policy.socket)?;
        fs::set_permissions(&policy.socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let metadata = fs::symlink_metadata(&policy.socket)?;
        Ok(Self {
            listener,
            socket: policy.socket,
            socket_identity: (metadata.dev(), metadata.ino()),
            service: Some(service),
            retention,
            state_service,
            state_retention,
            native_service,
            native_retention,
            repository,
            _state_lock: state_lock,
        })
    }

    /// Serves bounded authenticated exchanges until operational shutdown is set.
    ///
    /// Malformed/foreign connections are individually fenced. A request failure
    /// cannot replace a durable original reservation or reexecute retained work.
    /// After shutdown, the actor stops admission and complete original cleanup
    /// finishes before this method returns.
    ///
    /// # Errors
    /// Refuses listener failures or poisoned retention inventory; original cleanup
    /// remains owned even when service transport fails.
    pub fn serve(&mut self, stopping: &AtomicBool) -> Result<(), NodeControlError> {
        let serving = loop {
            if stopping.load(Ordering::Acquire) {
                break Ok(());
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = self.connection(&mut stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => break Err(error.into()),
            }
        };
        self.stop_and_reclaim();
        serving
    }

    /// Inventories active and cleanup-only roots under the repository GC fence.
    ///
    /// # Errors
    /// Refuses unavailable ref exclusion or poisoned operational ownership.
    pub fn retention_roots(&self) -> Result<BTreeSet<ContentId>, NodeControlError> {
        let _fence = self
            .repository
            .acquire_gc_exclusion_guard()
            .map_err(refused)?;
        let mut roots = self.retention.retention_roots().map_err(refused)?;
        if let Some(retention) = &self.state_retention {
            roots.extend(retention.retention_roots()?);
        }
        if let Some(retention) = &self.native_retention {
            roots.extend(retention.retention_roots().map_err(refused)?);
        }
        Ok(roots)
    }

    /// Copies the independently registered GC owner without granting deletion.
    ///
    /// A containing daemon inventories this owner under its existing exclusive
    /// ref fence and retains registration until `is_retired()` is true. This
    /// avoids reacquiring shared publication exclusion during GC inventory.
    #[must_use]
    pub fn retention_owner(&self) -> NodeObservationRetention {
        self.retention.clone()
    }

    /// Copies the separately registered exact-state retention owner, when enabled.
    ///
    /// The collector keeps it registered until authentic native retirement.
    #[must_use]
    pub fn host_state_retention_owner(&self) -> Option<NodeHostStateRetention> {
        self.state_retention.clone()
    }

    /// Copies the independent native-state root owner when installed policy enables it.
    ///
    /// The collector retains this owner until actual native-group reclamation.
    #[must_use]
    pub fn native_state_retention_owner(&self) -> Option<NativeWorldRetention> {
        self.native_retention.clone()
    }

    fn connection(&self, stream: &mut UnixStream) -> Result<(), NodeControlError> {
        transport::same_uid(stream)?;
        let deadline = transport::operational_now() + transport::EXCHANGE_TIMEOUT;
        let request: NodeControlRequest = transport::read(stream, deadline)?;
        request.validate()?;
        let result = match self.dispatch(request.command) {
            Ok(result) => result,
            Err(error) => NodeControlResult::Refused {
                // Peer-authored schema values and storage diagnostics may contain
                // sensitive material. Wire refusals retain only fixed classes.
                reason: match error {
                    NodeControlError::Io(_) => "node operation storage or custody is unavailable",
                    NodeControlError::Schema(_) => "portable node schema was rejected",
                    NodeControlError::Refused(_) => {
                        "node actor refused; read original retained execution state"
                    }
                }
                .into(),
            },
        };
        transport::write(
            stream,
            &NodeControlReply {
                format: request.format,
                version: request.version,
                request_id: request.request_id,
                result,
            },
            deadline,
        )
    }

    fn dispatch(&self, command: NodeControlCommand) -> Result<NodeControlResult, NodeControlError> {
        let service = self
            .service
            .as_ref()
            .ok_or_else(|| refused("node actor admission stopped"))?;
        match command {
            NodeControlCommand::DebugStart { request } => Ok(NodeControlResult::DebugState {
                record: Box::new(service.start_debug(*request).map_err(refused)?),
            }),
            NodeControlCommand::DebugResume { request } => Ok(NodeControlResult::DebugState {
                record: Box::new(service.resume_debug(*request).map_err(refused)?),
            }),
            NodeControlCommand::DebugStatus { execution } => Ok(NodeControlResult::DebugState {
                record: Box::new(service.debug_state(&execution).map_err(refused)?),
            }),
            NodeControlCommand::RootPreparation { request } => {
                let record = service
                    .submit_root_preparation(*request)
                    .map_err(super::refused)?;
                Ok(NodeControlResult::RootPreparation {
                    record: Bytes::new(record.canonical_bytes().map_err(super::refused)?),
                })
            }
            NodeControlCommand::RootDiagnostic { execution } => {
                let record = service
                    .root_preparation_diagnostic(&execution)
                    .map_err(super::refused)?;
                Ok(NodeControlResult::RootDiagnostic {
                    record: Bytes::new(record.canonical_bytes().map_err(super::refused)?),
                })
            }
            NodeControlCommand::RootPreparationStatus { execution } => {
                let record = service
                    .root_preparation_status(&execution)
                    .map_err(super::refused)?;
                Ok(NodeControlResult::RootPreparation {
                    record: Bytes::new(record.canonical_bytes().map_err(super::refused)?),
                })
            }
            NodeControlCommand::CapabilityPreparation { request } => {
                let record = service
                    .submit_capability_preparation(*request)
                    .map_err(super::refused)?;
                Ok(NodeControlResult::CapabilityPreparation {
                    record: Bytes::new(record.canonical_bytes().map_err(super::refused)?),
                })
            }
            NodeControlCommand::CapabilityPreparationStatus { execution } => {
                let record = service
                    .capability_preparation_status(&execution)
                    .map_err(super::refused)?;
                Ok(NodeControlResult::CapabilityPreparation {
                    record: Bytes::new(record.canonical_bytes().map_err(super::refused)?),
                })
            }
            NodeControlCommand::CacheReuse { request } => {
                let receipt = service.reuse_cache(*request).map_err(refused)?;
                Ok(NodeControlResult::CacheReused {
                    receipt: Box::new(receipt),
                })
            }
            NodeControlCommand::TerminalState { request } => {
                let state = self
                    .state_service
                    .as_ref()
                    .ok_or_else(|| refused("terminal state is not enabled by installed policy"))?
                    .submit(super::host_state::NodeHostStateRequest::Terminal { request })?;
                if state.version != 2 {
                    return Err(refused(
                        "terminal control cannot relabel a legacy state record",
                    ));
                }
                Ok(NodeControlResult::HostState {
                    record: Box::new(state),
                })
            }
            NodeControlCommand::NativeState { request } => {
                let record = self
                    .native_service
                    .as_ref()
                    .ok_or_else(|| refused("native state is not enabled by installed policy"))?
                    .submit(*request)
                    .map_err(refused)?;
                Ok(NodeControlResult::NativeState {
                    record: Box::new(record),
                })
            }
            NodeControlCommand::ConditionalReplay { request } => {
                let record = service
                    .submit_conditional_preparation(
                        crate::node_observed_executor::ConditionalPreparationRequest {
                            ledger: request.ledger,
                            execution: request.execution,
                            sources: request.sources,
                            configuration: request.configuration,
                        },
                    )
                    .map_err(refused)?;
                Ok(NodeControlResult::ConditionalPreparation {
                    record: Bytes::new(record.canonical_bytes().map_err(refused)?),
                })
            }
            NodeControlCommand::ConditionalReplayStatus { execution } => {
                let record = service
                    .conditional_preparation_status(&execution)
                    .map_err(refused)?;
                Ok(NodeControlResult::ConditionalPreparation {
                    record: Bytes::new(record.canonical_bytes().map_err(refused)?),
                })
            }
            NodeControlCommand::HostState { request } => {
                let state = self
                    .state_service
                    .as_ref()
                    .ok_or_else(|| refused("exact state is not enabled by installed policy"))?
                    .submit(*request)?;
                if state.version != 1 {
                    return Err(refused(
                        "legacy host-state wire cannot expose terminal records",
                    ));
                }
                Ok(NodeControlResult::HostState {
                    record: Box::new(state),
                })
            }
            NodeControlCommand::Compile { selections } => Ok(NodeControlResult::Compiled {
                scenario: Bytes::new(service.compile(selections).map_err(refused)?),
            }),
            NodeControlCommand::Observe {
                ledger,
                execution,
                selections,
                scenario,
                configuration,
            } => {
                let state = service
                    .submit(
                        ledger,
                        execution_id(&execution)?,
                        selections,
                        scenario.as_slice().to_vec(),
                        configuration.as_slice().to_vec(),
                    )
                    .map_err(refused)?;
                Ok(NodeControlResult::State {
                    state: Bytes::new(state.canonical_bytes()),
                })
            }
            NodeControlCommand::Status { execution } => {
                let state = service.state(execution_id(&execution)?).map_err(refused)?;
                Ok(NodeControlResult::State {
                    state: Bytes::new(state.canonical_bytes()),
                })
            }
        }
    }

    fn stop_and_reclaim(&mut self) {
        drop(self.service.take());
        drop(self.state_service.take());
        drop(self.native_service.take());
        while !self.retention.is_retired()
            || self
                .state_retention
                .as_ref()
                .is_some_and(|owner| !owner.is_retired())
            || self
                .native_retention
                .as_ref()
                .is_some_and(|owner| !owner.is_retired())
        {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for NodeControlDaemon {
    fn drop(&mut self) {
        self.stop_and_reclaim();
        if fs::symlink_metadata(&self.socket)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.socket_identity)
        {
            let _ = fs::remove_file(&self.socket);
        }
    }
}
