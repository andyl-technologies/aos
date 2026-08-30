//! Branch-private diagnostics endpoint staging for a retained QEMU template.

use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;

use thiserror::Error;

use super::hot_fork_plugin_endpoints::socket_cookie;
use super::*;

/// Ownership state for one node-retained branch-private diagnostics stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkChildDiagnosticStageState {
    /// QEMU duplicated and authenticated the stream.
    Installed,
    /// Transfer began but QMP ownership could not be determined safely.
    TransferUncertain,
}

/// Bounded evidence for one node-retained branch-private diagnostics stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildDiagnosticStageProof {
    state: QemuHotForkChildDiagnosticStageState,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    replacement_plan_bound: bool,
}

impl QemuHotForkChildDiagnosticStageProof {
    /// Returns whether installation was acknowledged or became uncertain.
    #[must_use]
    pub const fn state(&self) -> QemuHotForkChildDiagnosticStageState {
        self.state
    }

    /// Returns the standard-QMP descriptor name of the child endpoint.
    #[must_use]
    pub const fn descriptor_name(&self) -> &crate::QmpDescriptorName {
        &self.descriptor_name
    }

    /// Returns the exact Linux `SO_COOKIE` of the child endpoint.
    #[must_use]
    pub const fn socket_cookie(&self) -> u64 {
        self.socket_cookie
    }

    /// Returns the exact template generation that admitted the stream.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns whether the stream is present in the sealed child resource plan.
    #[must_use]
    pub const fn replacement_plan_bound(&self) -> bool {
        self.replacement_plan_bound
    }
}

pub(super) struct QemuHotForkChildDiagnosticPair {
    // The host endpoint stays owned for the eventual bounded diagnostics
    // consumer. The child endpoint stays owned until QEMU and the monitor have
    // released both transferred copies.
    _host: UnixStream,
    child: UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    replacement_plan_bound: bool,
}

impl std::fmt::Debug for QemuHotForkChildDiagnosticPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkChildDiagnosticPair")
            .field("descriptor_name", &self.descriptor_name)
            .field("socket_cookie", &self.socket_cookie)
            .field("template_generation", &self.template_generation)
            .field("replacement_plan_bound", &self.replacement_plan_bound)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkChildDiagnosticPair {
    fn proof(
        &self,
        state: QemuHotForkChildDiagnosticStageState,
    ) -> QemuHotForkChildDiagnosticStageProof {
        QemuHotForkChildDiagnosticStageProof {
            state,
            descriptor_name: self.descriptor_name.clone(),
            socket_cookie: self.socket_cookie,
            template_generation: self.template_generation,
            replacement_plan_bound: self.replacement_plan_bound,
        }
    }
}

#[derive(Debug)]
pub(super) enum QemuHotForkChildDiagnosticStage {
    Installed(QemuHotForkChildDiagnosticPair),
    TransferUncertain(QemuHotForkChildDiagnosticPair),
}

impl QemuHotForkChildDiagnosticStage {
    pub(super) fn proof(&self) -> QemuHotForkChildDiagnosticStageProof {
        match self {
            Self::Installed(endpoint) => {
                endpoint.proof(QemuHotForkChildDiagnosticStageState::Installed)
            }
            Self::TransferUncertain(endpoint) => {
                endpoint.proof(QemuHotForkChildDiagnosticStageState::TransferUncertain)
            }
        }
    }

    pub(super) const fn replacement_plan_bound(&self) -> bool {
        match self {
            Self::Installed(endpoint) | Self::TransferUncertain(endpoint) => {
                endpoint.replacement_plan_bound
            }
        }
    }

    pub(super) fn bind_replacement_plan(
        &mut self,
        state: &crate::QmpHotForkChildDiagnosticState,
    ) -> Result<(), QemuNodeChannelError> {
        let endpoint = match self {
            Self::Installed(endpoint) => endpoint,
            Self::TransferUncertain(_) => {
                return Err(QemuNodeChannelError::new(
                    "bind hot-fork child diagnostics",
                    "diagnostic transfer ownership is uncertain",
                ));
            }
        };
        let exact = state.staged()
            && state.descriptor_name() == Some(&endpoint.descriptor_name)
            && state.socket_cookie() == Some(endpoint.socket_cookie)
            && state.template_generation() == endpoint.template_generation
            && state.target_descriptor() == Some(crate::QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD)
            && state.replacement_plan_bound();
        if !exact {
            return Err(QemuNodeChannelError::new(
                "bind hot-fork child diagnostics",
                "QEMU did not bind the exact diagnostics contribution into the sealed plan",
            ));
        }
        endpoint.replacement_plan_bound = true;
        Ok(())
    }

    pub(super) fn unbind_replacement_plan(&mut self) {
        if let Self::Installed(endpoint) = self {
            endpoint.replacement_plan_bound = false;
        }
    }
}

#[derive(Debug, Error)]
enum QemuHotForkChildDiagnosticError {
    #[error("create branch-private diagnostics socket pair failed: {source}")]
    Pair { source: io::Error },
    #[error("configure branch-private diagnostics stream failed: {source}")]
    Configure { source: io::Error },
    #[error("read branch-private diagnostics identity failed: {source}")]
    Identity { source: io::Error },
    #[error("branch-private diagnostics descriptor name is invalid: {source}")]
    DescriptorName { source: crate::QmpError },
}

/// Failure to stage one branch-private diagnostics stream in a QEMU template.
#[derive(Debug, Error)]
pub enum QemuHotForkChildDiagnosticStageError {
    /// Validation or endpoint creation failed before descriptor transfer began.
    #[error("hot-fork child diagnostics staging was rejected before transfer: {source}")]
    Rejected {
        /// Exact pre-transfer or endpoint-preparation failure.
        source: QemuNodeChannelError,
    },
    /// Transfer began, so the node retained ownership and quarantined itself.
    #[error("hot-fork child diagnostics transfer is ownership-ambiguous: {source}")]
    TransferUncertain {
        /// QMP transfer or acknowledgement failure.
        source: QemuNodeChannelError,
    },
}

impl QemuNode {
    /// Stages a fresh branch-private diagnostics stream in the retained template.
    ///
    /// The operation requires one acknowledged private-ring stage and must
    /// precede plugin endpoint staging, which seals the complete child resource
    /// plan. The host retains one nonblocking stream endpoint while QEMU owns an
    /// authenticated duplicate of the child endpoint. No fork occurs here.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkChildDiagnosticStageError::Rejected`] before
    /// transfer when the node or template basis is invalid. Once transfer
    /// begins, every failure quarantines the node and returns
    /// [`QemuHotForkChildDiagnosticStageError::TransferUncertain`].
    pub fn stage_hot_fork_child_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticStageProof, QemuHotForkChildDiagnosticStageError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(diagnostic_rejected(
                "diagnostic staging requires a running node",
            ));
        }
        if self.hot_fork_child_diagnostic_stage.is_some() {
            return Err(diagnostic_rejected(
                "node already retains a child diagnostics stage",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(diagnostic_rejected(
                "child diagnostics must precede plugin endpoint staging",
            ));
        }
        let (ring_name, ring_identity) = match self.hot_fork_private_ring_stage.as_ref() {
            Some(QemuHotForkPrivateRingStage::Installed(ring)) => {
                (ring.descriptor_name().clone(), ring.backing_identity())
            }
            Some(QemuHotForkPrivateRingStage::TransferUncertain(_)) => {
                return Err(diagnostic_rejected(
                    "private-ring descriptor ownership is uncertain",
                ));
            }
            None => {
                return Err(diagnostic_rejected(
                    "child diagnostics require an installed private-ring descriptor",
                ));
            }
        };
        let qemu_ring = self
            .channels
            .qmp_machine_control
            .query_hot_fork_private_rings()
            .map_err(diagnostic_rejected_source)?;
        let ring_basis_matches = qemu_ring.staged()
            && qemu_ring.descriptor_name() == Some(&ring_name)
            && qemu_ring.device() == ring_identity.device()
            && qemu_ring.inode() == ring_identity.inode()
            && qemu_ring.length() == ring_identity.length()
            && qemu_ring.shrink_sealed()
            && qemu_ring.source_mapping_bound()
            && qemu_ring.generation() != 0;
        if !ring_basis_matches {
            return Err(diagnostic_rejected(
                "QEMU private-ring stage no longer matches the node-owned mapping",
            ));
        }
        let template_generation = qemu_ring.template_generation();
        if template_generation == 0 {
            return Err(diagnostic_rejected(
                "child diagnostics require a template-bound private ring",
            ));
        }

        let mut endpoint = create_diagnostic_pair(template_generation).map_err(|source| {
            diagnostic_rejected_source(QemuNodeChannelError::new(
                "prepare hot-fork child diagnostics",
                source.to_string(),
            ))
        })?;
        let transfer = self
            .channels
            .qmp_machine_control
            .install_hot_fork_child_diagnostics(
                &endpoint.descriptor_name,
                endpoint.child.as_fd(),
                endpoint.socket_cookie,
                template_generation,
            );
        let qemu_state = match transfer {
            Ok(state) => state,
            Err(source) => {
                self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
                self.hot_fork_child_diagnostic_stage =
                    Some(QemuHotForkChildDiagnosticStage::TransferUncertain(endpoint));
                return Err(QemuHotForkChildDiagnosticStageError::TransferUncertain { source });
            }
        };
        let exact = qemu_state.staged()
            && qemu_state.descriptor_name() == Some(&endpoint.descriptor_name)
            && qemu_state.socket_cookie() == Some(endpoint.socket_cookie)
            && qemu_state.template_generation() == template_generation
            && qemu_state.target_descriptor()
                == Some(crate::QMP_HOT_FORK_CHILD_DIAGNOSTICS_TARGET_FD)
            && !qemu_state.replacement_plan_bound();
        if !exact {
            let source = QemuNodeChannelError::new(
                "install hot-fork child diagnostics",
                "QEMU did not retain the exact unsealed diagnostics contribution",
            );
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            self.hot_fork_child_diagnostic_stage =
                Some(QemuHotForkChildDiagnosticStage::TransferUncertain(endpoint));
            return Err(QemuHotForkChildDiagnosticStageError::TransferUncertain { source });
        }
        endpoint.replacement_plan_bound = false;
        let proof = endpoint.proof(QemuHotForkChildDiagnosticStageState::Installed);
        self.hot_fork_child_diagnostic_stage =
            Some(QemuHotForkChildDiagnosticStage::Installed(endpoint));
        Ok(proof)
    }

    /// Returns evidence for the child diagnostics stream retained by this node.
    #[must_use]
    pub fn hot_fork_child_diagnostic_stage(&self) -> Option<QemuHotForkChildDiagnosticStageProof> {
        self.hot_fork_child_diagnostic_stage
            .as_ref()
            .map(QemuHotForkChildDiagnosticStage::proof)
    }

    /// Releases one acknowledged diagnostics stage in exact ownership order.
    ///
    /// Plugin endpoints and their sealed plan must be released first. QEMU
    /// closes its retained duplicate, then the monitor name, before the node
    /// drops both original stream endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the stage is absent or uncertain,
    /// plugin resources remain retained, or either exact close fails.
    pub fn release_hot_fork_child_diagnostics(&mut self) -> Result<(), QemuNodeChannelError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child diagnostics",
                "diagnostic release requires a running node",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child diagnostics",
                "plugin endpoints must release their sealed plan first",
            ));
        }
        let (name, socket_cookie) = match self.hot_fork_child_diagnostic_stage.as_ref() {
            Some(QemuHotForkChildDiagnosticStage::Installed(endpoint)) => {
                (endpoint.descriptor_name.clone(), endpoint.socket_cookie)
            }
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "diagnostic transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "node retains no child diagnostics stage",
                ));
            }
        };
        if let Err(source) = self
            .channels
            .qmp_machine_control
            .close_hot_fork_child_diagnostics(&name, socket_cookie)
        {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(source);
        }
        match self.hot_fork_child_diagnostic_stage.take() {
            Some(QemuHotForkChildDiagnosticStage::Installed(_)) => Ok(()),
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) | None => {
                Err(QemuNodeChannelError::new(
                    "release hot-fork child diagnostics",
                    "diagnostic stage changed after acknowledged close",
                ))
            }
        }
    }
}

fn diagnostic_rejected(message: impl Into<String>) -> QemuHotForkChildDiagnosticStageError {
    diagnostic_rejected_source(QemuNodeChannelError::new(
        "stage hot-fork child diagnostics",
        message,
    ))
}

fn diagnostic_rejected_source(
    source: QemuNodeChannelError,
) -> QemuHotForkChildDiagnosticStageError {
    QemuHotForkChildDiagnosticStageError::Rejected { source }
}

fn create_diagnostic_pair(
    template_generation: u64,
) -> Result<QemuHotForkChildDiagnosticPair, QemuHotForkChildDiagnosticError> {
    let (host, child) =
        UnixStream::pair().map_err(|source| QemuHotForkChildDiagnosticError::Pair { source })?;
    host.set_nonblocking(true)
        .map_err(|source| QemuHotForkChildDiagnosticError::Configure { source })?;
    child
        .set_nonblocking(true)
        .map_err(|source| QemuHotForkChildDiagnosticError::Configure { source })?;
    let socket_cookie = socket_cookie(child.as_raw_fd())
        .map_err(|source| QemuHotForkChildDiagnosticError::Identity { source })?;
    let descriptor_name = crate::QmpDescriptorName::new(format!(
        "crucible-hfork-diagnostics-v1-{socket_cookie:016x}"
    ))
    .map_err(|source| QemuHotForkChildDiagnosticError::DescriptorName { source })?;

    Ok(QemuHotForkChildDiagnosticPair {
        _host: host,
        child,
        descriptor_name,
        socket_cookie,
        template_generation,
        replacement_plan_bound: false,
    })
}
