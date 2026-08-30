//! Branch-private QMP endpoint staging for a retained QEMU template.

use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;

use thiserror::Error;

use super::hot_fork_plugin_endpoints::socket_cookie;
use super::*;

/// Ownership state for one node-retained branch-private QMP stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkChildQmpStageState {
    /// QEMU duplicated and authenticated the stream.
    Installed,
    /// Transfer began but QMP ownership could not be determined safely.
    TransferUncertain,
}

/// Bounded evidence for one node-retained branch-private QMP stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildQmpStageProof {
    state: QemuHotForkChildQmpStageState,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    resource_plan_bound: bool,
}

impl QemuHotForkChildQmpStageProof {
    /// Returns whether installation was acknowledged or became uncertain.
    #[must_use]
    pub const fn state(&self) -> QemuHotForkChildQmpStageState {
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

    /// Returns whether the stream is retained in the sealed child plan.
    #[must_use]
    pub const fn resource_plan_bound(&self) -> bool {
        self.resource_plan_bound
    }
}

pub(super) struct QemuHotForkChildQmpPair {
    // Both endpoints remain node-owned until a later monitor reinitializer
    // consumes them or exact cleanup releases the staged contribution.
    _host: UnixStream,
    child: UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    resource_plan_bound: bool,
}

impl std::fmt::Debug for QemuHotForkChildQmpPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkChildQmpPair")
            .field("descriptor_name", &self.descriptor_name)
            .field("socket_cookie", &self.socket_cookie)
            .field("template_generation", &self.template_generation)
            .field("resource_plan_bound", &self.resource_plan_bound)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkChildQmpPair {
    fn proof(&self, state: QemuHotForkChildQmpStageState) -> QemuHotForkChildQmpStageProof {
        QemuHotForkChildQmpStageProof {
            state,
            descriptor_name: self.descriptor_name.clone(),
            socket_cookie: self.socket_cookie,
            template_generation: self.template_generation,
            resource_plan_bound: self.resource_plan_bound,
        }
    }
}

#[derive(Debug)]
pub(super) enum QemuHotForkChildQmpStage {
    Installed(QemuHotForkChildQmpPair),
    TransferUncertain(QemuHotForkChildQmpPair),
}

impl QemuHotForkChildQmpStage {
    pub(super) fn proof(&self) -> QemuHotForkChildQmpStageProof {
        match self {
            Self::Installed(endpoint) => endpoint.proof(QemuHotForkChildQmpStageState::Installed),
            Self::TransferUncertain(endpoint) => {
                endpoint.proof(QemuHotForkChildQmpStageState::TransferUncertain)
            }
        }
    }

    pub(super) const fn resource_plan_bound(&self) -> bool {
        match self {
            Self::Installed(endpoint) | Self::TransferUncertain(endpoint) => {
                endpoint.resource_plan_bound
            }
        }
    }

    pub(super) fn bind_resource_plan(
        &mut self,
        state: &crate::QmpHotForkChildQmpState,
    ) -> Result<(), QemuNodeChannelError> {
        let endpoint = match self {
            Self::Installed(endpoint) => endpoint,
            Self::TransferUncertain(_) => {
                return Err(QemuNodeChannelError::new(
                    "bind hot-fork child QMP",
                    "child QMP transfer ownership is uncertain",
                ));
            }
        };
        let exact = state.staged()
            && state.descriptor_name() == Some(&endpoint.descriptor_name)
            && state.socket_cookie() == Some(endpoint.socket_cookie)
            && state.template_generation() == endpoint.template_generation
            && state.retained_descriptor().is_some()
            && state.resource_plan_bound();
        if !exact {
            return Err(QemuNodeChannelError::new(
                "bind hot-fork child QMP",
                "QEMU did not retain the exact child QMP contribution in the sealed plan",
            ));
        }
        endpoint.resource_plan_bound = true;
        Ok(())
    }

    pub(super) fn unbind_resource_plan(&mut self) {
        if let Self::Installed(endpoint) = self {
            endpoint.resource_plan_bound = false;
        }
    }
}

#[derive(Debug, Error)]
enum QemuHotForkChildQmpError {
    #[error("create branch-private child QMP socket pair failed: {source}")]
    Pair { source: io::Error },
    #[error("configure branch-private child QMP stream failed: {source}")]
    Configure { source: io::Error },
    #[error("read branch-private child QMP identity failed: {source}")]
    Identity { source: io::Error },
    #[error("branch-private child QMP descriptor name is invalid: {source}")]
    DescriptorName { source: crate::QmpError },
}

/// Failure to stage one branch-private QMP stream in a retained template.
#[derive(Debug, Error)]
pub enum QemuHotForkChildQmpStageError {
    /// Validation or endpoint creation failed before descriptor transfer began.
    #[error("hot-fork child QMP staging was rejected before transfer: {source}")]
    Rejected {
        /// Exact pre-transfer or endpoint-preparation failure.
        source: QemuNodeChannelError,
    },
    /// Transfer began, so the node retained ownership and quarantined itself.
    #[error("hot-fork child QMP transfer is ownership-ambiguous: {source}")]
    TransferUncertain {
        /// QMP transfer or acknowledgement failure.
        source: QemuNodeChannelError,
    },
}

impl QemuNode {
    /// Stages a fresh branch-private QMP stream in the retained template.
    ///
    /// The operation requires acknowledged private-ring and diagnostics stages
    /// and must precede plugin endpoint staging, which seals the complete child
    /// resource plan. The host and node retain the fresh socket pair while QEMU
    /// owns an authenticated duplicate of the child endpoint. No inherited
    /// monitor is closed or reconstructed and no fork occurs here.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkChildQmpStageError::Rejected`] before transfer when
    /// the node or template basis is invalid. Once transfer begins, every
    /// failure quarantines the node and returns
    /// [`QemuHotForkChildQmpStageError::TransferUncertain`].
    pub fn stage_hot_fork_child_qmp(
        &mut self,
    ) -> Result<QemuHotForkChildQmpStageProof, QemuHotForkChildQmpStageError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(qmp_rejected("child QMP staging requires a running node"));
        }
        if self.hot_fork_child_qmp_stage.is_some() {
            return Err(qmp_rejected("node already retains a child QMP stage"));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(qmp_rejected(
                "child QMP must precede plugin endpoint staging",
            ));
        }
        let diagnostics = match self.hot_fork_child_diagnostic_stage.as_ref() {
            Some(stage @ QemuHotForkChildDiagnosticStage::Installed(_)) => stage,
            Some(QemuHotForkChildDiagnosticStage::TransferUncertain(_)) => {
                return Err(qmp_rejected(
                    "child diagnostics transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(qmp_rejected(
                    "child QMP requires installed branch-private diagnostics",
                ));
            }
        };
        let template_generation = diagnostics.template_generation();
        if template_generation == 0 {
            return Err(qmp_rejected(
                "child QMP requires template-bound diagnostics",
            ));
        }

        let mut endpoint = create_qmp_pair(template_generation).map_err(|source| {
            qmp_rejected_source(QemuNodeChannelError::new(
                "prepare hot-fork child QMP",
                source.to_string(),
            ))
        })?;
        let transfer = self
            .channels
            .qmp_machine_control
            .install_hot_fork_child_qmp(
                &endpoint.descriptor_name,
                endpoint.child.as_fd(),
                endpoint.socket_cookie,
                template_generation,
            );
        let qemu_state = match transfer {
            Ok(state) => state,
            Err(source) => {
                self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
                self.hot_fork_child_qmp_stage =
                    Some(QemuHotForkChildQmpStage::TransferUncertain(endpoint));
                return Err(QemuHotForkChildQmpStageError::TransferUncertain { source });
            }
        };
        let exact = qemu_state.staged()
            && qemu_state.descriptor_name() == Some(&endpoint.descriptor_name)
            && qemu_state.socket_cookie() == Some(endpoint.socket_cookie)
            && qemu_state.template_generation() == template_generation
            && qemu_state.retained_descriptor().is_some()
            && !qemu_state.resource_plan_bound();
        if !exact {
            let source = QemuNodeChannelError::new(
                "install hot-fork child QMP",
                "QEMU did not retain the exact unsealed child QMP contribution",
            );
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            self.hot_fork_child_qmp_stage =
                Some(QemuHotForkChildQmpStage::TransferUncertain(endpoint));
            return Err(QemuHotForkChildQmpStageError::TransferUncertain { source });
        }
        endpoint.resource_plan_bound = false;
        let proof = endpoint.proof(QemuHotForkChildQmpStageState::Installed);
        self.hot_fork_child_qmp_stage = Some(QemuHotForkChildQmpStage::Installed(endpoint));
        Ok(proof)
    }

    /// Returns evidence for the child QMP stream retained by this node.
    #[must_use]
    pub fn hot_fork_child_qmp_stage(&self) -> Option<QemuHotForkChildQmpStageProof> {
        self.hot_fork_child_qmp_stage
            .as_ref()
            .map(QemuHotForkChildQmpStage::proof)
    }

    /// Releases one acknowledged child QMP stage in exact ownership order.
    ///
    /// Plugin endpoints and their sealed plan must be released first. QEMU
    /// closes its retained duplicate, then the monitor name, before the node
    /// drops both original stream endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the stage is absent or uncertain,
    /// plugin resources remain retained, or either exact close fails.
    pub fn release_hot_fork_child_qmp(&mut self) -> Result<(), QemuNodeChannelError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child QMP",
                "child QMP release requires a running node",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child QMP",
                "plugin endpoints must release their sealed plan first",
            ));
        }
        let (name, socket_cookie) = match self.hot_fork_child_qmp_stage.as_ref() {
            Some(QemuHotForkChildQmpStage::Installed(endpoint)) => {
                (endpoint.descriptor_name.clone(), endpoint.socket_cookie)
            }
            Some(QemuHotForkChildQmpStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child QMP",
                    "child QMP transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child QMP",
                    "node retains no child QMP stage",
                ));
            }
        };
        if let Err(source) = self
            .channels
            .qmp_machine_control
            .close_hot_fork_child_qmp(&name, socket_cookie)
        {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(source);
        }
        match self.hot_fork_child_qmp_stage.take() {
            Some(QemuHotForkChildQmpStage::Installed(_)) => Ok(()),
            Some(QemuHotForkChildQmpStage::TransferUncertain(_)) | None => {
                Err(QemuNodeChannelError::new(
                    "release hot-fork child QMP",
                    "child QMP stage changed after acknowledged close",
                ))
            }
        }
    }
}

fn qmp_rejected(message: impl Into<String>) -> QemuHotForkChildQmpStageError {
    qmp_rejected_source(QemuNodeChannelError::new(
        "stage hot-fork child QMP",
        message,
    ))
}

fn qmp_rejected_source(source: QemuNodeChannelError) -> QemuHotForkChildQmpStageError {
    QemuHotForkChildQmpStageError::Rejected { source }
}

fn create_qmp_pair(
    template_generation: u64,
) -> Result<QemuHotForkChildQmpPair, QemuHotForkChildQmpError> {
    let (host, child) =
        UnixStream::pair().map_err(|source| QemuHotForkChildQmpError::Pair { source })?;
    host.set_nonblocking(true)
        .map_err(|source| QemuHotForkChildQmpError::Configure { source })?;
    child
        .set_nonblocking(true)
        .map_err(|source| QemuHotForkChildQmpError::Configure { source })?;
    let socket_cookie = socket_cookie(child.as_raw_fd())
        .map_err(|source| QemuHotForkChildQmpError::Identity { source })?;
    let descriptor_name =
        crate::QmpDescriptorName::new(format!("crucible-hfork-qmp-v1-{socket_cookie:016x}"))
            .map_err(|source| QemuHotForkChildQmpError::DescriptorName { source })?;

    Ok(QemuHotForkChildQmpPair {
        _host: host,
        child,
        descriptor_name,
        socket_cookie,
        template_generation,
        resource_plan_bound: false,
    })
}
