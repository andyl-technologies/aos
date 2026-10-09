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
        fs::{MetadataExt, PermissionsExt},
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
    execution_id, refused, transport,
};
use crate::node_observed_executor::{
    NodeObservationRetention, NodeObservationService, NodeObservationServiceConfig,
};

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

    fn validate(&self) -> Result<(), NodeControlError> {
        if self.format != "crucible.node-daemon-policy"
            || self.version != 1
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
        let service = NodeObservationService::start(
            NodeObservationServiceConfig {
                device_executable: policy.device_executable,
                expected_device: policy.expected_device,
                socket_parent: policy.state_directory.clone(),
                control_timeout: Duration::from_millis(policy.control_timeout_ms),
                maximum_worlds: policy.maximum_worlds,
                maximum_pending_requests: policy.maximum_pending_requests,
            },
            repository.clone(),
            blobs,
            refs,
        )
        .map_err(refused)?;

        // Register the separately owned retention fence before exposing admission.
        let retention = service.retention_owner();
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
        self.retention.retention_roots().map_err(refused)
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
        while !self.retention.is_retired() {
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
