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
    qmp_generation: u64,
    monitor_generation: u64,
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

    /// Returns the exact child-QMP mutation generation.
    #[must_use]
    pub const fn qmp_generation(&self) -> u64 {
        self.qmp_generation
    }

    /// Returns the exact supported parent-monitor lifecycle generation.
    #[must_use]
    pub const fn monitor_generation(&self) -> u64 {
        self.monitor_generation
    }

    /// Returns whether the stream is retained in the sealed child plan.
    #[must_use]
    pub const fn resource_plan_bound(&self) -> bool {
        self.resource_plan_bound
    }
}

/// Linear host endpoint for one future hot-fork child's private QMP channel.
///
/// The endpoint carries the complete retained basis established while the
/// template was quiescent. Connecting consumes the endpoint, negotiates QMP,
/// and authenticates the child process's query before returning a control
/// channel. It grants no authority over the template parent's QMP connection.
#[derive(Debug)]
pub struct QemuHotForkChildQmpHostEndpoint {
    host: UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    qmp_generation: u64,
    monitor_generation: u64,
}

impl QemuHotForkChildQmpHostEndpoint {
    /// Returns the retained child-QMP descriptor name.
    #[must_use]
    pub const fn descriptor_name(&self) -> &crate::QmpDescriptorName {
        &self.descriptor_name
    }

    /// Returns the retained child endpoint's Linux `SO_COOKIE`.
    #[must_use]
    pub const fn socket_cookie(&self) -> u64 {
        self.socket_cookie
    }

    /// Returns the template generation that admitted this endpoint.
    #[must_use]
    pub const fn template_generation(&self) -> u64 {
        self.template_generation
    }

    /// Returns the retained child-QMP mutation generation.
    #[must_use]
    pub const fn qmp_generation(&self) -> u64 {
        self.qmp_generation
    }

    /// Returns the supported parent-monitor generation bound at staging.
    #[must_use]
    pub const fn monitor_generation(&self) -> u64 {
        self.monitor_generation
    }

    /// Negotiates and authenticates the private child QMP connection.
    ///
    /// The first post-negotiation operation queries the child's inherited
    /// retained state. The returned channel is exposed only when QEMU reports
    /// the exact descriptor name, socket identity, template/QMP generations,
    /// sealed resource contribution, and accepted complete disposition.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkChildQmpHandshakeError`] when QMP negotiation or
    /// the exact child-state query fails. The consumed stream is not reusable
    /// after any failure.
    pub fn connect(
        self,
    ) -> Result<crate::QemuQmpVmStateControlChannel<UnixStream>, QemuHotForkChildQmpHandshakeError>
    {
        self.host
            .set_nonblocking(false)
            .map_err(|source| QemuHotForkChildQmpHandshakeError::Configure { source })?;
        let mut client = crate::QmpClient::connect(self.host)
            .map_err(|source| QemuHotForkChildQmpHandshakeError::Qmp { source })?;
        let state = client
            .query_hot_fork_child_qmp()
            .map_err(|source| QemuHotForkChildQmpHandshakeError::Qmp { source })?;
        let exact = state.staged()
            && state.descriptor_name() == Some(&self.descriptor_name)
            && state.socket_cookie() == Some(self.socket_cookie)
            && state.template_generation() == self.template_generation
            && state.generation() == self.qmp_generation
            && state.monitor_generation() == self.monitor_generation
            && state.retained_descriptor().is_some()
            && state.resource_plan_bound()
            && state.monitor_basis_bound()
            && state.monitor_disposition_bound()
            && state.monitor_socket_resources_bound()
            && state.reinitializer_prepared()
            && state.reinitialized()
            && state.disposition_complete();
        if !exact {
            return Err(QemuHotForkChildQmpHandshakeError::BasisMismatch);
        }

        Ok(crate::QemuQmpVmStateControlChannel::new(client))
    }
}

/// Failure to authenticate one private hot-fork child QMP channel.
#[derive(Debug, Error)]
pub enum QemuHotForkChildQmpHandshakeError {
    /// The retained host stream could not enter blocking QMP mode.
    #[error("configure private hot-fork child QMP stream failed: {source}")]
    Configure {
        /// Exact socket configuration failure.
        #[source]
        source: io::Error,
    },
    /// QMP greeting, negotiation, query, or strict decoding failed.
    #[error("private hot-fork child QMP exchange failed: {source}")]
    Qmp {
        /// Exact typed QMP failure.
        #[source]
        source: crate::QmpError,
    },
    /// The child query did not match the retained template endpoint basis.
    #[error("private hot-fork child QMP basis did not match the retained template endpoint")]
    BasisMismatch,
}

pub(super) struct QemuHotForkChildQmpPair {
    // The node retains both endpoints until the sealed plan permits one linear
    // host-end transfer; the child endpoint remains for exact stage cleanup.
    host: Option<UnixStream>,
    child: UnixStream,
    descriptor_name: crate::QmpDescriptorName,
    socket_cookie: u64,
    template_generation: u64,
    qmp_generation: u64,
    monitor_generation: u64,
    resource_plan_bound: bool,
}

impl std::fmt::Debug for QemuHotForkChildQmpPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkChildQmpPair")
            .field("descriptor_name", &self.descriptor_name)
            .field("socket_cookie", &self.socket_cookie)
            .field("template_generation", &self.template_generation)
            .field("qmp_generation", &self.qmp_generation)
            .field("monitor_generation", &self.monitor_generation)
            .field("host_endpoint_available", &self.host.is_some())
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
            qmp_generation: self.qmp_generation,
            monitor_generation: self.monitor_generation,
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
            && state.generation() == endpoint.qmp_generation
            && state.monitor_generation() == endpoint.monitor_generation
            && state.retained_descriptor().is_some()
            && state.monitor_basis_bound()
            && state.monitor_disposition_bound()
            && state.monitor_socket_resources_bound()
            && state.reinitializer_prepared()
            && !state.reinitialized()
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
    /// monitor is closed or reconstructed and no fork occurs here. QEMU does
    /// prepare a one-shot adapter and retain the exact supported monitor,
    /// I/O-thread, dispatcher, and lifecycle-generation basis that a future
    /// child runtime must consume with this endpoint and transaction.
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
            && qemu_state.generation() != 0
            && qemu_state.monitor_generation() != 0
            && qemu_state.retained_descriptor().is_some()
            && qemu_state.monitor_basis_bound()
            && qemu_state.monitor_disposition_bound()
            && qemu_state.monitor_socket_resources_bound()
            && qemu_state.reinitializer_prepared()
            && !qemu_state.reinitialized()
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
        endpoint.qmp_generation = qemu_state.generation();
        endpoint.monitor_generation = qemu_state.monitor_generation();
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

    /// Transfers the linear host endpoint for the future child's QMP channel.
    ///
    /// The complete child resource plan must already retain the exact endpoint.
    /// The template continues to own its QEMU-side stage and can release that
    /// contribution independently after the fork owner has consumed this host
    /// endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the stage is absent, ownership is
    /// uncertain, the resource plan is not sealed, or the endpoint was already
    /// transferred.
    pub fn take_hot_fork_child_qmp_host_endpoint(
        &mut self,
    ) -> Result<QemuHotForkChildQmpHostEndpoint, QemuNodeChannelError> {
        let endpoint = match self.hot_fork_child_qmp_stage.as_mut() {
            Some(QemuHotForkChildQmpStage::Installed(endpoint)) => endpoint,
            Some(QemuHotForkChildQmpStage::TransferUncertain(_)) => {
                return Err(QemuNodeChannelError::new(
                    "take hot-fork child QMP host endpoint",
                    "child QMP transfer ownership is uncertain",
                ));
            }
            None => {
                return Err(QemuNodeChannelError::new(
                    "take hot-fork child QMP host endpoint",
                    "node retains no child QMP stage",
                ));
            }
        };
        if !endpoint.resource_plan_bound {
            return Err(QemuNodeChannelError::new(
                "take hot-fork child QMP host endpoint",
                "child QMP endpoint is not retained by a sealed resource plan",
            ));
        }
        let host = endpoint.host.take().ok_or_else(|| {
            QemuNodeChannelError::new(
                "take hot-fork child QMP host endpoint",
                "child QMP host endpoint was already transferred",
            )
        })?;

        Ok(QemuHotForkChildQmpHostEndpoint {
            host,
            descriptor_name: endpoint.descriptor_name.clone(),
            socket_cookie: endpoint.socket_cookie,
            template_generation: endpoint.template_generation,
            qmp_generation: endpoint.qmp_generation,
            monitor_generation: endpoint.monitor_generation,
        })
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
        host: Some(host),
        child,
        descriptor_name,
        socket_cookie,
        template_generation,
        qmp_generation: 0,
        monitor_generation: 0,
        resource_plan_bound: false,
    })
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- unit fixtures use panic shortcuts for exact failure localization.
    #![allow(clippy::expect_used)]

    use std::io::{BufRead, BufReader, Write};
    use std::thread;

    use serde_json::json;

    use super::*;

    fn scripted_child_qmp(
        mut stream: UnixStream,
        descriptor_name: &crate::QmpDescriptorName,
        socket_cookie: u64,
        template_generation: u64,
        qmp_generation: u64,
        monitor_generation: u64,
        disposition_complete: bool,
    ) -> thread::JoinHandle<()> {
        let descriptor_name = descriptor_name.as_str().to_owned();
        thread::spawn(move || {
            stream
                .write_all(b"{\"QMP\":{\"version\":{},\"capabilities\":[\"oob\"]}}\r\n")
                .expect("write child QMP greeting");
            let reader_stream = stream.try_clone().expect("clone scripted QMP stream");
            let mut reader = BufReader::new(reader_stream);
            let mut request = String::new();
            reader
                .read_line(&mut request)
                .expect("read QMP capabilities request");
            assert!(request.contains("qmp_capabilities"));
            stream
                .write_all(b"{\"return\":{}}\r\n")
                .expect("write QMP capabilities response");

            request.clear();
            reader
                .read_line(&mut request)
                .expect("read child QMP state query");
            assert!(request.contains("crucible-hot-fork-child-qmp"));
            let response = json!({
                "return": {
                    "schema-version": 6,
                    "generation": qmp_generation,
                    "template-generation": template_generation,
                    "monitor-generation": monitor_generation,
                    "staged": true,
                    "fdname": descriptor_name,
                    "socket-cookie": socket_cookie,
                    "retained-fd": 33,
                    "resource-plan-bound": true,
                    "nonblocking-unix-stream": true,
                    "monitor-basis-bound": true,
                    "monitor-disposition-bound": true,
                    "monitor-socket-resources-bound": true,
                    "reinitializer-prepared": true,
                    "reinitialized": disposition_complete,
                    "disposition-complete": disposition_complete,
                    "readiness-proof-acknowledged": false,
                }
            });
            writeln!(stream, "{response}").expect("write child QMP state response");
        })
    }

    fn endpoint(
        host: UnixStream,
        descriptor_name: crate::QmpDescriptorName,
    ) -> QemuHotForkChildQmpHostEndpoint {
        QemuHotForkChildQmpHostEndpoint {
            host,
            descriptor_name,
            socket_cookie: 41,
            template_generation: 7,
            qmp_generation: 11,
            monitor_generation: 13,
        }
    }

    #[test]
    fn child_qmp_host_endpoint_authenticates_complete_generation_basis() {
        let (host, child) = UnixStream::pair().expect("child QMP socket pair");
        let name = crate::QmpDescriptorName::new("crucible-hfork-qmp-v1-0000000000000029")
            .expect("child QMP descriptor name");
        let server = scripted_child_qmp(child, &name, 41, 7, 11, 13, true);

        let channel = endpoint(host, name).connect();
        assert!(channel.is_ok());
        server.join().expect("scripted child QMP server");
    }

    #[test]
    fn child_qmp_host_endpoint_rejects_a_foreign_generation() {
        let (host, child) = UnixStream::pair().expect("child QMP socket pair");
        let name = crate::QmpDescriptorName::new("crucible-hfork-qmp-v1-0000000000000029")
            .expect("child QMP descriptor name");
        let server = scripted_child_qmp(child, &name, 41, 7, 12, 13, true);

        assert!(matches!(
            endpoint(host, name).connect(),
            Err(QemuHotForkChildQmpHandshakeError::BasisMismatch)
        ));
        server.join().expect("scripted child QMP server");
    }

    #[test]
    fn child_qmp_host_endpoint_rejects_a_foreign_monitor_generation() {
        let (host, child) = UnixStream::pair().expect("child QMP socket pair");
        let name = crate::QmpDescriptorName::new("crucible-hfork-qmp-v1-0000000000000029")
            .expect("child QMP descriptor name");
        let server = scripted_child_qmp(child, &name, 41, 7, 11, 14, true);

        assert!(matches!(
            endpoint(host, name).connect(),
            Err(QemuHotForkChildQmpHandshakeError::BasisMismatch)
        ));
        server.join().expect("scripted child QMP server");
    }

    #[test]
    fn child_qmp_host_endpoint_rejects_an_incomplete_disposition() {
        let (host, child) = UnixStream::pair().expect("child QMP socket pair");
        let name = crate::QmpDescriptorName::new("crucible-hfork-qmp-v1-0000000000000029")
            .expect("child QMP descriptor name");
        let server = scripted_child_qmp(child, &name, 41, 7, 11, 13, false);

        assert!(matches!(
            endpoint(host, name).connect(),
            Err(QemuHotForkChildQmpHandshakeError::BasisMismatch)
        ));
        server.join().expect("scripted child QMP server");
    }
}
