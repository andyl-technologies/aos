//! Branch-private plugin control and wake endpoint staging.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use thiserror::Error;

use super::*;

const ENDPOINT_FDINFO_MAX_BYTES: u64 = 4_096;

/// QMP ownership state for one node-retained plugin endpoint pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkPluginEndpointStageState {
    /// QEMU duplicated and authenticated both standard-QMP descriptors.
    Installed,
    /// Transfer began but QMP ownership could not be determined safely.
    TransferUncertain,
}

/// Bounded evidence for one node-retained branch-private plugin endpoint stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkPluginEndpointStageProof {
    state: QemuHotForkPluginEndpointStageState,
    control_name: crate::QmpDescriptorName,
    wake_name: crate::QmpDescriptorName,
    identity: crate::QmpHotForkPluginEndpointIdentity,
    private_ring_generation: u64,
}

impl QemuHotForkPluginEndpointStageProof {
    /// Returns whether installation was acknowledged or became uncertain.
    #[must_use]
    pub const fn state(&self) -> QemuHotForkPluginEndpointStageState {
        self.state
    }

    /// Returns the standard-QMP name of the child control endpoint.
    #[must_use]
    pub const fn control_name(&self) -> &crate::QmpDescriptorName {
        &self.control_name
    }

    /// Returns the standard-QMP name of the child wake endpoint.
    #[must_use]
    pub const fn wake_name(&self) -> &crate::QmpDescriptorName {
        &self.wake_name
    }

    /// Returns the authenticated kernel-object identities.
    #[must_use]
    pub const fn identity(&self) -> crate::QmpHotForkPluginEndpointIdentity {
        self.identity
    }

    /// Returns the exact retained private-ring generation bound at staging.
    #[must_use]
    pub const fn private_ring_generation(&self) -> u64 {
        self.private_ring_generation
    }
}

pub(super) struct QemuHotForkPluginEndpointPair {
    // Both sides remain owned until a complete fork-child handoff consumes the
    // host continuation and QEMU's retained duplicates.
    _host_control: UnixStream,
    child_control: UnixStream,
    _host_wake: OwnedFd,
    child_wake: OwnedFd,
    control_name: crate::QmpDescriptorName,
    wake_name: crate::QmpDescriptorName,
    identity: crate::QmpHotForkPluginEndpointIdentity,
    private_ring_generation: u64,
}

impl std::fmt::Debug for QemuHotForkPluginEndpointPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkPluginEndpointPair")
            .field("control_name", &self.control_name)
            .field("wake_name", &self.wake_name)
            .field("identity", &self.identity)
            .field("private_ring_generation", &self.private_ring_generation)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkPluginEndpointPair {
    fn proof(
        &self,
        state: QemuHotForkPluginEndpointStageState,
    ) -> QemuHotForkPluginEndpointStageProof {
        QemuHotForkPluginEndpointStageProof {
            state,
            control_name: self.control_name.clone(),
            wake_name: self.wake_name.clone(),
            identity: self.identity,
            private_ring_generation: self.private_ring_generation,
        }
    }
}

#[derive(Debug)]
pub(super) enum QemuHotForkPluginEndpointStage {
    Installed(QemuHotForkPluginEndpointPair),
    TransferUncertain(QemuHotForkPluginEndpointPair),
}

impl QemuHotForkPluginEndpointStage {
    pub(super) fn proof(&self) -> QemuHotForkPluginEndpointStageProof {
        match self {
            Self::Installed(endpoints) => {
                endpoints.proof(QemuHotForkPluginEndpointStageState::Installed)
            }
            Self::TransferUncertain(endpoints) => {
                endpoints.proof(QemuHotForkPluginEndpointStageState::TransferUncertain)
            }
        }
    }
}

#[derive(Debug, Error)]
enum QemuHotForkPluginEndpointError {
    #[error("create branch-private plugin control socket pair failed: {source}")]
    ControlPair { source: io::Error },
    #[error("create branch-private plugin wake eventfd failed: {source}")]
    WakeEvent { source: io::Error },
    #[error("duplicate branch-private plugin wake eventfd failed: {source}")]
    DuplicateWake { source: io::Error },
    #[error("read branch-private plugin endpoint identity failed: {source}")]
    Identity { source: io::Error },
    #[error("branch-private plugin endpoint identity is invalid")]
    InvalidIdentity,
    #[error("branch-private plugin endpoint name is invalid: {source}")]
    DescriptorName { source: crate::QmpError },
}

/// Failure to stage one plugin endpoint pair in a retained QEMU template.
#[derive(Debug, Error)]
pub enum QemuHotForkPluginEndpointStageError {
    /// Validation or endpoint creation failed before descriptor transfer began.
    #[error("hot-fork plugin endpoint staging was rejected before transfer: {source}")]
    Rejected {
        /// Exact pre-transfer or endpoint-preparation failure.
        source: QemuNodeChannelError,
    },
    /// Transfer began, so the node retained ownership and quarantined itself.
    #[error("hot-fork plugin endpoint transfer is ownership-ambiguous: {source}")]
    TransferUncertain {
        /// QMP transfer or acknowledgement failure.
        source: QemuNodeChannelError,
    },
}

impl QemuNode {
    /// Stages fresh plugin control and wake endpoints in the retained template.
    ///
    /// This operation requires one acknowledged private-ring stage, reproduces
    /// its exact held plugin and host barriers, creates a fresh connected/empty
    /// Unix stream plus empty nonblocking eventfd, and transfers both child
    /// endpoints through typed QMP. It retains the corresponding host endpoints
    /// but exposes no host-continuation or child-release authority yet.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkPluginEndpointStageError::Rejected`] before transfer
    /// when the node, ring generation, or barrier basis is not exact, or endpoint
    /// creation fails. Once transfer begins, every failure quarantines the node
    /// and returns [`QemuHotForkPluginEndpointStageError::TransferUncertain`].
    pub fn stage_hot_fork_plugin_endpoints(
        &mut self,
    ) -> Result<QemuHotForkPluginEndpointStageProof, QemuHotForkPluginEndpointStageError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(endpoint_rejected(
                "endpoint staging requires a running node",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(endpoint_rejected(
                "node already retains a plugin endpoint stage",
            ));
        }

        let ring = match self.hot_fork_private_ring_stage.as_ref() {
            Some(QemuHotForkPrivateRingStage::Installed(ring)) => ring,
            Some(QemuHotForkPrivateRingStage::TransferUncertain(_)) => {
                return Err(endpoint_rejected(
                    "private-ring descriptor ownership is uncertain",
                ));
            }
            None => {
                return Err(endpoint_rejected(
                    "plugin endpoints require an installed private-ring descriptor",
                ));
            }
        };
        let ring_name = ring.descriptor_name().clone();
        let ring_identity = ring.backing_identity();
        let source_plugin = ring.source_plugin_barrier();
        let source_host = ring.host_barrier();

        let qemu_ring = self
            .channels
            .qmp_machine_control
            .query_hot_fork_private_rings()
            .map_err(endpoint_rejected_source)?;
        let ring_basis_matches = qemu_ring.staged()
            && qemu_ring.descriptor_name() == Some(&ring_name)
            && qemu_ring.device() == ring_identity.device()
            && qemu_ring.inode() == ring_identity.inode()
            && qemu_ring.length() == ring_identity.length()
            && qemu_ring.shrink_sealed()
            && qemu_ring.generation() != 0;
        if !ring_basis_matches {
            return Err(endpoint_rejected(
                "QEMU private-ring stage no longer matches the node-owned mapping",
            ));
        }

        let plugin = self
            .channels
            .qmp_machine_control
            .query_hot_fork_plugin_barrier()
            .map_err(endpoint_rejected_source)?;
        let host = self
            .channels
            .shmem_hot_path
            .hot_fork_ring_io_snapshot()
            .map_err(endpoint_rejected_source)?;
        if plugin != source_plugin || host != source_host || !plugin.quiescent() {
            return Err(endpoint_rejected(
                "plugin or host ring barrier changed before endpoint staging",
            ));
        }

        let endpoints = create_plugin_endpoint_pair(qemu_ring.generation()).map_err(|source| {
            endpoint_rejected_source(QemuNodeChannelError::new(
                "prepare hot-fork plugin endpoints",
                source.to_string(),
            ))
        })?;
        let transfer = self
            .channels
            .qmp_machine_control
            .install_hot_fork_plugin_endpoints(
                &endpoints.control_name,
                endpoints.child_control.as_fd(),
                &endpoints.wake_name,
                endpoints.child_wake.as_fd(),
                endpoints.identity,
                endpoints.private_ring_generation,
            );
        if let Err(source) = transfer {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            self.hot_fork_plugin_endpoint_stage =
                Some(QemuHotForkPluginEndpointStage::TransferUncertain(endpoints));
            return Err(QemuHotForkPluginEndpointStageError::TransferUncertain { source });
        }

        let proof = endpoints.proof(QemuHotForkPluginEndpointStageState::Installed);
        self.hot_fork_plugin_endpoint_stage =
            Some(QemuHotForkPluginEndpointStage::Installed(endpoints));
        Ok(proof)
    }

    /// Returns evidence for the plugin endpoint stage retained by this node.
    #[must_use]
    pub fn hot_fork_plugin_endpoint_stage(&self) -> Option<QemuHotForkPluginEndpointStageProof> {
        self.hot_fork_plugin_endpoint_stage
            .as_ref()
            .map(QemuHotForkPluginEndpointStage::proof)
    }

    /// Releases one acknowledged plugin endpoint stage in exact ownership order.
    ///
    /// QEMU closes its duplicates first, followed by the two monitor-owned
    /// names. The node drops both original endpoint pairs only after every close
    /// is acknowledged.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the node is not running, transfer
    /// ownership is uncertain, no stage exists, or any exact close fails. A
    /// close failure quarantines the node and retains the endpoint owner.
    pub fn release_hot_fork_plugin_endpoints(&mut self) -> Result<(), QemuNodeChannelError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                "release hot-fork plugin endpoints",
                "endpoint release requires a running node",
            ));
        }
        let (control_name, wake_name, identity) = match self.hot_fork_plugin_endpoint_stage.as_ref()
        {
            Some(QemuHotForkPluginEndpointStage::Installed(endpoints)) => (
                endpoints.control_name.clone(),
                endpoints.wake_name.clone(),
                endpoints.identity,
            ),
            Some(QemuHotForkPluginEndpointStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork plugin endpoints",
                    "plugin endpoint transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork plugin endpoints",
                    "node retains no plugin endpoint stage",
                ));
            }
        };
        if let Err(source) = self
            .channels
            .qmp_machine_control
            .close_hot_fork_plugin_endpoints(&control_name, &wake_name, identity)
        {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(source);
        }
        match self.hot_fork_plugin_endpoint_stage.take() {
            Some(QemuHotForkPluginEndpointStage::Installed(_)) => Ok(()),
            Some(QemuHotForkPluginEndpointStage::TransferUncertain(_)) | None => {
                Err(QemuNodeChannelError::new(
                    "release hot-fork plugin endpoints",
                    "plugin endpoint stage changed after acknowledged close",
                ))
            }
        }
    }
}

fn endpoint_rejected(message: impl Into<String>) -> QemuHotForkPluginEndpointStageError {
    endpoint_rejected_source(QemuNodeChannelError::new(
        "stage hot-fork plugin endpoints",
        message,
    ))
}

fn endpoint_rejected_source(source: QemuNodeChannelError) -> QemuHotForkPluginEndpointStageError {
    QemuHotForkPluginEndpointStageError::Rejected { source }
}

fn create_plugin_endpoint_pair(
    private_ring_generation: u64,
) -> Result<QemuHotForkPluginEndpointPair, QemuHotForkPluginEndpointError> {
    let (host_control, child_control) = UnixStream::pair()
        .map_err(|source| QemuHotForkPluginEndpointError::ControlPair { source })?;
    let host_wake = create_nonblocking_eventfd()
        .map_err(|source| QemuHotForkPluginEndpointError::WakeEvent { source })?;
    let child_wake = host_wake
        .try_clone()
        .map_err(|source| QemuHotForkPluginEndpointError::DuplicateWake { source })?;
    let control_socket_cookie = socket_cookie(child_control.as_raw_fd())
        .map_err(|source| QemuHotForkPluginEndpointError::Identity { source })?;
    let wake_eventfd_id = eventfd_id(child_wake.as_raw_fd())
        .map_err(|source| QemuHotForkPluginEndpointError::Identity { source })?;
    let identity =
        crate::QmpHotForkPluginEndpointIdentity::new(control_socket_cookie, wake_eventfd_id)
            .ok_or(QemuHotForkPluginEndpointError::InvalidIdentity)?;
    let control_name = crate::QmpDescriptorName::new(format!(
        "crucible-hfork-control-v1-{control_socket_cookie:016x}"
    ))
    .map_err(|source| QemuHotForkPluginEndpointError::DescriptorName { source })?;
    let wake_name =
        crate::QmpDescriptorName::new(format!("crucible-hfork-wake-v1-{wake_eventfd_id:016x}"))
            .map_err(|source| QemuHotForkPluginEndpointError::DescriptorName { source })?;

    Ok(QemuHotForkPluginEndpointPair {
        _host_control: host_control,
        child_control,
        _host_wake: host_wake,
        child_wake,
        control_name,
        wake_name,
        identity,
        private_ring_generation,
    })
}

fn create_nonblocking_eventfd() -> io::Result<OwnedFd> {
    let descriptor =
        // SAFETY: `eventfd` has no pointer arguments and returns one new fd.
        unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful `eventfd` returned a uniquely owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn socket_cookie(descriptor: RawFd) -> io::Result<u64> {
    let mut cookie = 0_u64;
    let mut length = std::mem::size_of::<u64>() as libc::socklen_t;
    let status =
        // SAFETY: `cookie` and `length` are valid output buffers for SO_COOKIE.
        unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                std::ptr::from_mut(&mut cookie).cast(),
                &mut length,
            )
        };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<u64>() || cookie == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control socket returned an invalid SO_COOKIE",
        ));
    }
    Ok(cookie)
}

fn eventfd_id(descriptor: RawFd) -> io::Result<u64> {
    let path = format!("/proc/self/fdinfo/{descriptor}");
    let mut bytes = Vec::new();
    File::open(path)?
        .take(ENDPOINT_FDINFO_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > ENDPOINT_FDINFO_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "eventfd fdinfo exceeds its fixed bound",
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("eventfd fdinfo is not UTF-8: {error}"),
        )
    })?;
    let mut identity = None;
    for line in text.lines() {
        let Some(value) = line.strip_prefix("eventfd-id:") else {
            continue;
        };
        if identity.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "eventfd fdinfo repeats eventfd-id",
            ));
        }
        let parsed = value.trim().parse::<u64>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("eventfd-id is invalid: {error}"),
            )
        })?;
        if parsed == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "eventfd-id is zero",
            ));
        }
        identity = Some(parsed);
    }
    identity.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor fdinfo contains no eventfd-id",
        )
    })
}
