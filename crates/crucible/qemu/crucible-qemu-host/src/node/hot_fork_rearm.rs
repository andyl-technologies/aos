//! Safe source-side detachment and rearming after one successful hot fork.
//!
//! A stopped source can fork several simultaneous siblings only after each
//! successful child owns every inherited capability and the source has closed
//! its copies of that child's one-shot setup. This module authenticates the
//! source-parent status record before releasing those copies, preserves a
//! linear receipt for final child reconciliation, and prepares fresh setup
//! slots before another fork can borrow the source.

use thiserror::Error;

use super::*;

/// Linear proof that one child's source-side setup copies were detached.
#[derive(Debug)]
#[must_use = "retain the detached setup receipt through child reconciliation"]
pub struct QemuHotForkDetachedChildResources {
    request: crate::QmpHotForkRequest,
    child_process_id: u32,
    diagnostic_descriptor_name: crate::QmpDescriptorName,
    diagnostic_socket_cookie: u64,
    diagnostic_template_generation: u64,
    process_contract: crate::QmpHotForkChildProcessContractState,
    child_files: crate::QmpHotForkChildFilesState,
}

impl QemuHotForkDetachedChildResources {
    /// Returns the exact successful fork request whose setup was detached.
    #[must_use]
    pub const fn request(&self) -> crate::QmpHotForkRequest {
        self.request
    }

    /// Returns the positive child PID authenticated before detachment.
    #[must_use]
    pub const fn child_process_id(&self) -> u32 {
        self.child_process_id
    }

    /// Finishes the bounded diagnostic capture after every child writer exits.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the consumer differs from the
    /// detached stream, a writer remains live, capture exceeds its bound, or
    /// this consumer was already captured.
    pub fn finish_diagnostics(
        &self,
        consumer: &mut QemuHotForkChildDiagnosticConsumer,
    ) -> Result<QemuHotForkChildDiagnosticCapture, QemuNodeChannelError> {
        if consumer.descriptor_name() != &self.diagnostic_descriptor_name
            || consumer.socket_cookie() != self.diagnostic_socket_cookie
            || consumer.template_generation() != self.diagnostic_template_generation
        {
            return Err(QemuNodeChannelError::new(
                "finish detached hot-fork child diagnostics",
                "diagnostic consumer does not match the detached child receipt",
            ));
        }
        consumer.finish_detached_capture()
    }

    /// Checks this receipt against the final reconciliation basis.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the supplied request or PID does
    /// not match the successful child, or the detached process-contract and
    /// child-file releases do not match that request.
    pub fn verify_final_basis(
        &self,
        request: crate::QmpHotForkRequest,
        child_process_id: u32,
    ) -> Result<(), QemuNodeChannelError> {
        let exact = self.request == request
            && self.child_process_id == child_process_id
            && !self.process_contract.staged()
            && !self.process_contract.consumed()
            && self.process_contract.generation() == request.child_process_contract_generation()
            && !self.child_files.staged()
            && !self.child_files.consumed()
            && self.child_files.generation() == request.child_files_generation();
        if !exact {
            return Err(QemuNodeChannelError::new(
                "verify detached hot-fork child resources",
                "detached source setup does not match the final child basis",
            ));
        }
        Ok(())
    }
}

/// Failure after a successful child fork while making its source reusable.
#[derive(Debug, Error)]
pub enum QemuHotForkSourceRearmError {
    /// The launch and source-local consumed stages did not name one child.
    #[error("successful hot-fork child does not match the source's consumed setup")]
    BasisMismatch,
    /// One source-side setup close or status query failed.
    #[error("detach consumed hot-fork child setup failed: {0}")]
    Detach(#[source] QemuNodeChannelError),
    /// Fresh branch-private setup could not be prepared.
    #[error("prepare the next hot-fork child setup failed: {0}")]
    Prepare(#[source] QemuHotForkChildResourcePreparationError),
}

impl QemuNode {
    /// Detaches one proven child setup and prepares fresh slots atomically.
    ///
    /// The successful fork result must still match every source-local consumed
    /// stage. Before any close, the source parent must report the exact
    /// process-contract generation and PID retained by the launch. The child
    /// keeps its pidfd/cgroup authority, private QMP and console endpoints,
    /// diagnostics reader, plugin continuation, private ring descriptor, and
    /// installed files. This method closes only source-parent copies, then
    /// prepares a new branch-private setup in the same retained transaction.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkSourceRearmError`] when the exact launch basis is
    /// absent, any ordered source close fails, the retained template is not
    /// empty afterward, or fresh setup cannot be prepared. Every failure
    /// quarantines the source because the child already exists.
    pub fn rearm_after_hot_fork_child<A>(
        &mut self,
        launch: &mut QemuHotForkChildLaunch<A>,
        maximum_ring_image_bytes: usize,
    ) -> Result<QemuHotForkDetachedChildResources, QemuHotForkSourceRearmError> {
        let result = self.rearm_after_hot_fork_child_inner(launch, maximum_ring_image_bytes);
        if result.is_err() {
            self.lifecycle_state = QemuNodeLifecycleState::Quarantined;
        }
        result
    }

    fn rearm_after_hot_fork_child_inner<A>(
        &mut self,
        launch: &mut QemuHotForkChildLaunch<A>,
        maximum_ring_image_bytes: usize,
    ) -> Result<QemuHotForkDetachedChildResources, QemuHotForkSourceRearmError> {
        let parent = launch.parent_state();
        let request = parent.request();
        let child_process_id = launch.child_process_id();
        let status = self
            .query_hot_fork_child_process(request.child_process_contract_generation())
            .map_err(QemuHotForkSourceRearmError::Detach)?;
        if parent.outcome() != crate::QmpHotForkOutcome::Forked
            || status.generation() != request.child_process_contract_generation()
            || status.child_process_id() != child_process_id
            || !status.retained()
            || !self.consumed_stages_match(request)
        {
            return Err(QemuHotForkSourceRearmError::BasisMismatch);
        }

        let diagnostic_descriptor_name = launch.diagnostics().descriptor_name().clone();
        let diagnostic_socket_cookie = launch.diagnostics().socket_cookie();
        let diagnostic_template_generation = launch.diagnostics().template_generation();

        self.release_hot_fork_plugin_endpoints()
            .map_err(QemuHotForkSourceRearmError::Detach)?;
        self.release_hot_fork_child_console()
            .map_err(QemuHotForkSourceRearmError::Detach)?;
        self.release_hot_fork_child_qmp()
            .map_err(QemuHotForkSourceRearmError::Detach)?;
        self.detach_hot_fork_child_diagnostics_with_consumer(launch.diagnostics_mut())
            .map_err(QemuHotForkSourceRearmError::Detach)?;
        self.release_hot_fork_private_ring_mapping()
            .map(drop)
            .map_err(QemuHotForkSourceRearmError::Detach)?;

        let process_contract = self
            .release_hot_fork_child_process_contract()
            .map_err(QemuHotForkSourceRearmError::Detach)?;
        let child_files = self
            .release_hot_fork_child_files()
            .map_err(QemuHotForkSourceRearmError::Detach)?;
        if process_contract.staged()
            || process_contract.consumed()
            || process_contract.generation() != request.child_process_contract_generation()
            || child_files.staged()
            || child_files.consumed()
            || child_files.generation() != request.child_files_generation()
        {
            return Err(QemuHotForkSourceRearmError::BasisMismatch);
        }

        let empty = self
            .query_hot_fork_template()
            .map_err(QemuHotForkSourceRearmError::Detach)?;
        if !super::hot_fork_preparation::initial_template_state_is_exact(&empty) {
            return Err(QemuHotForkSourceRearmError::BasisMismatch);
        }
        self.prepare_hot_fork_child_resources(maximum_ring_image_bytes)
            .map_err(QemuHotForkSourceRearmError::Prepare)?;

        Ok(QemuHotForkDetachedChildResources {
            request,
            child_process_id,
            diagnostic_descriptor_name,
            diagnostic_socket_cookie,
            diagnostic_template_generation,
            process_contract,
            child_files,
        })
    }

    fn consumed_stages_match(&self, request: crate::QmpHotForkRequest) -> bool {
        self.hot_fork_private_ring_stage()
            .is_some_and(|stage| stage.state() == QemuHotForkPrivateRingStageState::Installed)
            && self.hot_fork_child_diagnostic_stage().is_some_and(|stage| {
                stage.state() == QemuHotForkChildDiagnosticStageState::Installed
                    && stage.template_generation() == request.template_generation()
                    && !self
                        .hot_fork_child_diagnostic_stage
                        .as_ref()
                        .is_some_and(QemuHotForkChildDiagnosticStage::consumer_available)
            })
            && self.hot_fork_child_qmp_stage().is_some_and(|stage| {
                stage.state() == QemuHotForkChildQmpStageState::Installed
                    && stage.template_generation() == request.template_generation()
                    && stage.qmp_generation() == request.qmp_generation()
                    && !self
                        .hot_fork_child_qmp_stage
                        .as_ref()
                        .is_some_and(QemuHotForkChildQmpStage::host_endpoint_available)
            })
            && self.hot_fork_child_console_stage().is_some_and(|stage| {
                stage.state() == QemuHotForkChildConsoleStageState::Installed
                    && stage.template_generation() == request.template_generation()
                    && stage.console_generation() == request.console_generation()
                    && !self
                        .hot_fork_child_console_stage
                        .as_ref()
                        .is_some_and(QemuHotForkChildConsoleStage::host_endpoint_available)
            })
            && self.hot_fork_plugin_endpoint_stage().is_some_and(|stage| {
                stage.state() == QemuHotForkPluginEndpointStageState::Installed
                    && stage.template_generation() == request.template_generation()
                    && stage.generation() == request.plugin_endpoint_generation()
                    && !self
                        .hot_fork_plugin_endpoint_stage
                        .as_ref()
                        .is_some_and(QemuHotForkPluginEndpointStage::host_endpoint_available)
            })
            && self
                .hot_fork_child_process_contract_stage()
                .is_some_and(|stage| {
                    stage.consumed()
                        && stage.template_generation() == request.template_generation()
                        && stage.generation() == request.child_process_contract_generation()
                })
            && self.hot_fork_child_files_stage().is_some_and(|stage| {
                stage.consumed()
                    && stage.template_generation() == request.template_generation()
                    && stage.generation() == request.child_files_generation()
            })
    }
}
