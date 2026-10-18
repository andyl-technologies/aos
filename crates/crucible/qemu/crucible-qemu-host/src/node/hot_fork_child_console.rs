//! Branch-private console endpoint staging for a retained QEMU template.

use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;

use thiserror::Error;

use super::hot_fork_plugin_endpoints::socket_cookie;
use super::*;
use crate::console_observation::{QemuConsoleObservationReader, QemuConsoleObservationSpool};

/// Ownership state for one node-retained branch-private console stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkChildConsoleStageState {
    /// QEMU duplicated and authenticated the stream.
    Installed,
    /// Transfer began but QMP ownership could not be determined safely.
    TransferUncertain,
}

/// Bounded evidence for one node-retained branch-private console stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildConsoleStageProof {
    state: QemuHotForkChildConsoleStageState,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    console_generation: u64,
    resource_plan_bound: bool,
}

impl QemuHotForkChildConsoleStageProof {
    /// Returns whether installation was acknowledged or became uncertain.
    #[must_use]
    pub const fn state(&self) -> QemuHotForkChildConsoleStageState {
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

    /// Returns the exact child-console mutation generation.
    #[must_use]
    pub const fn console_generation(&self) -> u64 {
        self.console_generation
    }

    /// Returns whether the stream is retained in the sealed child plan.
    #[must_use]
    pub const fn resource_plan_bound(&self) -> bool {
        self.resource_plan_bound
    }
}

/// Linear console reader and scheduler-boundary spool for one fork child.
///
/// The source node creates this value from a duplicate of its retained host
/// endpoint before the fork command. Dropping it after an explicit pre-fork
/// rejection leaves the original endpoint available for an exact retry. A
/// successful fork moves the reader into the child host-I/O runtime and keeps
/// the paired spool for the child [`QemuNode`].
pub struct QemuHotForkChildConsoleObservation {
    reader: QemuConsoleObservationReader,
    spool: QemuConsoleObservationSpool,
}

impl std::fmt::Debug for QemuHotForkChildConsoleObservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkChildConsoleObservation")
            .finish_non_exhaustive()
    }
}

impl QemuHotForkChildConsoleObservation {
    pub(crate) fn from_stream(output: UnixStream) -> Result<Self, io::Error> {
        let spool = QemuConsoleObservationSpool::new();
        let reader = QemuConsoleObservationReader::new(output, spool.clone())?;
        Ok(Self { reader, spool })
    }

    pub(crate) fn spool(&self) -> QemuConsoleObservationSpool {
        self.spool.clone()
    }

    pub(crate) fn into_reader(self) -> QemuConsoleObservationReader {
        self.reader
    }
}

pub(super) struct QemuHotForkChildConsolePair {
    host: Option<UnixStream>,
    child: UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    console_generation: u64,
    resource_plan_bound: bool,
}

impl std::fmt::Debug for QemuHotForkChildConsolePair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkChildConsolePair")
            .field("descriptor_name", &self.descriptor_name)
            .field("socket_cookie", &self.socket_cookie)
            .field("template_generation", &self.template_generation)
            .field("console_generation", &self.console_generation)
            .field("host_endpoint_available", &self.host.is_some())
            .field("resource_plan_bound", &self.resource_plan_bound)
            .finish_non_exhaustive()
    }
}

impl QemuHotForkChildConsolePair {
    fn proof(&self, state: QemuHotForkChildConsoleStageState) -> QemuHotForkChildConsoleStageProof {
        QemuHotForkChildConsoleStageProof {
            state,
            descriptor_name: self.descriptor_name.clone(),
            socket_cookie: self.socket_cookie,
            template_generation: self.template_generation,
            console_generation: self.console_generation,
            resource_plan_bound: self.resource_plan_bound,
        }
    }
}

#[derive(Debug)]
pub(super) enum QemuHotForkChildConsoleStage {
    Installed(QemuHotForkChildConsolePair),
    TransferUncertain(QemuHotForkChildConsolePair),
}

impl QemuHotForkChildConsoleStage {
    pub(super) fn proof(&self) -> QemuHotForkChildConsoleStageProof {
        match self {
            Self::Installed(endpoint) => {
                endpoint.proof(QemuHotForkChildConsoleStageState::Installed)
            }
            Self::TransferUncertain(endpoint) => {
                endpoint.proof(QemuHotForkChildConsoleStageState::TransferUncertain)
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

    pub(super) const fn host_endpoint_available(&self) -> bool {
        match self {
            Self::Installed(endpoint) | Self::TransferUncertain(endpoint) => {
                endpoint.host.is_some()
            }
        }
    }

    pub(super) fn bind_resource_plan(
        &mut self,
        state: &crate::QmpHotForkChildConsoleState,
    ) -> Result<(), QemuNodeChannelError> {
        let endpoint = match self {
            Self::Installed(endpoint) => endpoint,
            Self::TransferUncertain(_) => {
                return Err(QemuNodeChannelError::new(
                    "bind hot-fork child console",
                    "child console transfer ownership is uncertain",
                ));
            }
        };
        let exact = state.staged()
            && state.descriptor_name() == Some(&endpoint.descriptor_name)
            && state.socket_cookie() == Some(endpoint.socket_cookie)
            && state.template_generation() == endpoint.template_generation
            && state.generation() == endpoint.console_generation
            && state.retained_descriptor().is_some()
            && state.console_basis_bound()
            && state.reinitializer_prepared()
            && !state.reinitialized()
            && !state.disposition_complete()
            && state.resource_plan_bound();
        if !exact {
            return Err(QemuNodeChannelError::new(
                "bind hot-fork child console",
                "QEMU did not retain the exact child console contribution in the sealed plan",
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
enum QemuHotForkChildConsoleError {
    #[error("create branch-private child console socket pair failed: {source}")]
    Pair { source: io::Error },
    #[error("configure branch-private child console stream failed: {source}")]
    Configure { source: io::Error },
    #[error("read branch-private child console identity failed: {source}")]
    Identity { source: io::Error },
    #[error("branch-private child console descriptor name is invalid: {source}")]
    DescriptorName { source: crate::QmpError },
}

/// Failure to stage one branch-private console stream in a retained template.
#[derive(Debug, Error)]
pub enum QemuHotForkChildConsoleStageError {
    /// Validation or endpoint creation failed before descriptor transfer began.
    #[error("hot-fork child console staging was rejected before transfer: {source}")]
    Rejected {
        /// Exact pre-transfer or endpoint-preparation failure.
        source: QemuNodeChannelError,
    },
    /// Transfer began, so the node retained ownership and quarantined itself.
    #[error("hot-fork child console transfer is ownership-ambiguous: {source}")]
    TransferUncertain {
        /// QMP transfer or acknowledgement failure.
        source: QemuNodeChannelError,
    },
}

impl QemuNode {
    /// Stages a fresh branch-private console stream in the retained template.
    ///
    /// The operation requires an acknowledged child-QMP stage and must precede
    /// plugin endpoint staging, which seals the complete child resource plan.
    /// QEMU binds the stream to the exact connected `crucible-console` chardev
    /// and retains its one-shot child reinitializer.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkChildConsoleStageError::Rejected`] before transfer
    /// when the node or template basis is invalid. Once transfer begins, every
    /// failure quarantines the node and returns
    /// [`QemuHotForkChildConsoleStageError::TransferUncertain`].
    pub fn stage_hot_fork_child_console(
        &mut self,
    ) -> Result<QemuHotForkChildConsoleStageProof, QemuHotForkChildConsoleStageError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(console_rejected(
                "child console staging requires a running node",
            ));
        }
        if self.hot_fork_child_console_stage.is_some() {
            return Err(console_rejected(
                "node already retains a child console stage",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(console_rejected(
                "child console must precede plugin endpoint staging",
            ));
        }
        let child_qmp = match self.hot_fork_child_qmp_stage.as_ref() {
            Some(stage @ QemuHotForkChildQmpStage::Installed(_))
                if !stage.resource_plan_bound() =>
            {
                stage
            }
            Some(QemuHotForkChildQmpStage::Installed(_)) => {
                return Err(console_rejected(
                    "child QMP is already bound to another sealed plan",
                ));
            }
            Some(QemuHotForkChildQmpStage::TransferUncertain(_)) => {
                return Err(console_rejected(
                    "child QMP transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(console_rejected(
                    "child console requires an installed child QMP stream",
                ));
            }
        };
        let template_generation = child_qmp.proof().template_generation();
        if template_generation == 0 {
            return Err(console_rejected(
                "child console requires a template-bound child QMP stream",
            ));
        }

        let mut endpoint = create_console_pair(template_generation).map_err(|source| {
            console_rejected_source(QemuNodeChannelError::new(
                "prepare hot-fork child console",
                source.to_string(),
            ))
        })?;
        let transfer = self
            .channels
            .qmp_machine_control
            .install_hot_fork_child_console(
                &endpoint.descriptor_name,
                endpoint.child.as_fd(),
                endpoint.socket_cookie,
                template_generation,
            );
        let qemu_state = match transfer {
            Ok(state) => state,
            Err(source) => {
                self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
                self.hot_fork_child_console_stage =
                    Some(QemuHotForkChildConsoleStage::TransferUncertain(endpoint));
                return Err(QemuHotForkChildConsoleStageError::TransferUncertain { source });
            }
        };
        let exact = qemu_state.staged()
            && qemu_state.descriptor_name() == Some(&endpoint.descriptor_name)
            && qemu_state.socket_cookie() == Some(endpoint.socket_cookie)
            && qemu_state.template_generation() == template_generation
            && qemu_state.generation() != 0
            && qemu_state.retained_descriptor().is_some()
            && qemu_state.console_basis_bound()
            && qemu_state.reinitializer_prepared()
            && !qemu_state.reinitialized()
            && !qemu_state.disposition_complete()
            && !qemu_state.resource_plan_bound();
        if !exact {
            let source = QemuNodeChannelError::new(
                "install hot-fork child console",
                "QEMU did not retain the exact unsealed child console contribution",
            );
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            self.hot_fork_child_console_stage =
                Some(QemuHotForkChildConsoleStage::TransferUncertain(endpoint));
            return Err(QemuHotForkChildConsoleStageError::TransferUncertain { source });
        }
        endpoint.console_generation = qemu_state.generation();
        let proof = endpoint.proof(QemuHotForkChildConsoleStageState::Installed);
        self.hot_fork_child_console_stage = Some(QemuHotForkChildConsoleStage::Installed(endpoint));
        Ok(proof)
    }

    /// Returns evidence for the child console retained by this node.
    #[must_use]
    pub fn hot_fork_child_console_stage(&self) -> Option<QemuHotForkChildConsoleStageProof> {
        self.hot_fork_child_console_stage
            .as_ref()
            .map(QemuHotForkChildConsoleStage::proof)
    }

    pub(super) fn clone_hot_fork_child_console_observation(
        &self,
    ) -> Result<QemuHotForkChildConsoleObservation, QemuNodeChannelError> {
        let endpoint = match self.hot_fork_child_console_stage.as_ref() {
            Some(QemuHotForkChildConsoleStage::Installed(endpoint)) => endpoint,
            Some(QemuHotForkChildConsoleStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "clone hot-fork child console observation",
                    "child console transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "clone hot-fork child console observation",
                    "node retains no child console stage",
                ));
            }
        };
        if !endpoint.resource_plan_bound {
            return Err(QemuNodeChannelError::new(
                "clone hot-fork child console observation",
                "child console is not retained by a sealed resource plan",
            ));
        }
        let host = endpoint.host.as_ref().ok_or_else(|| {
            QemuNodeChannelError::new(
                "clone hot-fork child console observation",
                "child console host endpoint was already transferred",
            )
        })?;
        let output = host.try_clone().map_err(|source| {
            QemuNodeChannelError::new(
                "clone hot-fork child console observation",
                source.to_string(),
            )
        })?;
        QemuHotForkChildConsoleObservation::from_stream(output).map_err(|source| {
            QemuNodeChannelError::new(
                "configure hot-fork child console observation",
                source.to_string(),
            )
        })
    }

    pub(super) fn consume_hot_fork_child_console_host_endpoint(
        &mut self,
    ) -> Result<(), QemuNodeChannelError> {
        let endpoint = match self.hot_fork_child_console_stage.as_mut() {
            Some(QemuHotForkChildConsoleStage::Installed(endpoint)) => endpoint,
            Some(QemuHotForkChildConsoleStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "consume hot-fork child console host endpoint",
                    "child console transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "consume hot-fork child console host endpoint",
                    "node retains no child console stage",
                ));
            }
        };
        if endpoint.host.take().is_none() {
            return Err(QemuNodeChannelError::new(
                "consume hot-fork child console host endpoint",
                "child console host endpoint was already transferred",
            ));
        }
        Ok(())
    }

    /// Releases one acknowledged child-console stage in exact ownership order.
    ///
    /// Plugin endpoints and their sealed plan must be released first. QEMU
    /// closes its retained duplicate, then the monitor name, before the node
    /// drops both original stream endpoints.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the stage is absent or uncertain,
    /// plugin resources remain retained, or either exact close fails.
    pub fn release_hot_fork_child_console(&mut self) -> Result<(), QemuNodeChannelError> {
        if self.lifecycle_state != crate::QemuNodeLifecycleState::Running {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child console",
                "child console release requires a running node",
            ));
        }
        if self.hot_fork_plugin_endpoint_stage.is_some() {
            return Err(QemuNodeChannelError::new(
                "release hot-fork child console",
                "plugin endpoints must release their sealed plan first",
            ));
        }
        let (name, socket_cookie) = match self.hot_fork_child_console_stage.as_ref() {
            Some(QemuHotForkChildConsoleStage::Installed(endpoint)) => {
                (endpoint.descriptor_name.clone(), endpoint.socket_cookie)
            }
            Some(QemuHotForkChildConsoleStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child console",
                    "child console transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "release hot-fork child console",
                    "node retains no child console stage",
                ));
            }
        };
        if let Err(source) = self
            .channels
            .qmp_machine_control
            .close_hot_fork_child_console(&name, socket_cookie)
        {
            self.lifecycle_state = crate::QemuNodeLifecycleState::Quarantined;
            return Err(source);
        }
        match self.hot_fork_child_console_stage.take() {
            Some(QemuHotForkChildConsoleStage::Installed(_)) => Ok(()),
            Some(QemuHotForkChildConsoleStage::TransferUncertain(_)) | None => {
                Err(QemuNodeChannelError::new(
                    "release hot-fork child console",
                    "child console stage changed after acknowledged close",
                ))
            }
        }
    }
}

fn console_rejected(message: impl Into<String>) -> QemuHotForkChildConsoleStageError {
    console_rejected_source(QemuNodeChannelError::new(
        "stage hot-fork child console",
        message,
    ))
}

fn console_rejected_source(source: QemuNodeChannelError) -> QemuHotForkChildConsoleStageError {
    QemuHotForkChildConsoleStageError::Rejected { source }
}

fn create_console_pair(
    template_generation: u64,
) -> Result<QemuHotForkChildConsolePair, QemuHotForkChildConsoleError> {
    let (host, child) =
        UnixStream::pair().map_err(|source| QemuHotForkChildConsoleError::Pair { source })?;
    host.set_nonblocking(true)
        .map_err(|source| QemuHotForkChildConsoleError::Configure { source })?;
    child
        .set_nonblocking(true)
        .map_err(|source| QemuHotForkChildConsoleError::Configure { source })?;
    let socket_cookie = socket_cookie(child.as_raw_fd())
        .map_err(|source| QemuHotForkChildConsoleError::Identity { source })?;
    let descriptor_name =
        crate::QmpDescriptorName::new(format!("crucible-hfork-console-v1-{socket_cookie:016x}"))
            .map_err(|source| QemuHotForkChildConsoleError::DescriptorName { source })?;

    Ok(QemuHotForkChildConsolePair {
        host: Some(host),
        child,
        descriptor_name,
        socket_cookie,
        template_generation,
        console_generation: 0,
        resource_plan_bound: false,
    })
}
