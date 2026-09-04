//! Composite branch-private resource preparation for one retained template.
//!
//! A hot-fork child needs a private plugin ring, diagnostic stream, QMP
//! channel, console stream, and plugin control/wake pair. Their individual
//! operations remain useful protocol primitives, but production preparation
//! must perform them in one reviewed order and authenticate the resulting QEMU
//! resource stage before a target process contract can be installed.

use thiserror::Error;

use super::{
    QemuHotForkChildConsoleStageError, QemuHotForkChildConsoleStageProof,
    QemuHotForkChildConsoleStageState, QemuHotForkChildDiagnosticStageError,
    QemuHotForkChildDiagnosticStageProof, QemuHotForkChildDiagnosticStageState,
    QemuHotForkChildQmpStageError, QemuHotForkChildQmpStageProof, QemuHotForkChildQmpStageState,
    QemuHotForkPluginEndpointStageError, QemuHotForkPluginEndpointStageProof,
    QemuHotForkPluginEndpointStageState, QemuHotForkPrivateRingStageError,
    QemuHotForkPrivateRingStageProof, QemuHotForkPrivateRingStageState, QemuNode,
    QemuNodeChannelError, QemuNodeLifecycleState,
};
use crate::{
    QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS, QmpHotForkTemplateOutcome,
    QmpHotForkTemplateResourceStageState, QmpHotForkTemplateState,
};

const PLUGIN_RING_PROOF: u64 = 1_u64 << 6;

/// Exact child-private host resources retained by one source template.
///
/// This value is evidence, not an independently usable capability. The source
/// [`QemuNode`] remains the sole owner of every descriptor and endpoint. A
/// later launch must still install the target process contract and rederive the
/// complete fork request from QEMU's retained state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkPreparedChildResources {
    template: QmpHotForkTemplateState,
    private_ring: QemuHotForkPrivateRingStageProof,
    diagnostics: QemuHotForkChildDiagnosticStageProof,
    child_qmp: QemuHotForkChildQmpStageProof,
    child_console: QemuHotForkChildConsoleStageProof,
    plugin_endpoints: QemuHotForkPluginEndpointStageProof,
}

impl QemuHotForkPreparedChildResources {
    /// Returns the prepared QEMU template state after all child resources were sealed.
    #[must_use]
    pub const fn template(&self) -> &QmpHotForkTemplateState {
        &self.template
    }

    /// Returns the node-retained private-ring stage proof.
    #[must_use]
    pub const fn private_ring(&self) -> &QemuHotForkPrivateRingStageProof {
        &self.private_ring
    }

    /// Returns the node-retained diagnostic-stream stage proof.
    #[must_use]
    pub const fn diagnostics(&self) -> &QemuHotForkChildDiagnosticStageProof {
        &self.diagnostics
    }

    /// Returns the node-retained child-QMP stage proof.
    #[must_use]
    pub const fn child_qmp(&self) -> &QemuHotForkChildQmpStageProof {
        &self.child_qmp
    }

    /// Returns the node-retained child-console stage proof.
    #[must_use]
    pub const fn child_console(&self) -> &QemuHotForkChildConsoleStageProof {
        &self.child_console
    }

    /// Returns the sealed plugin endpoint and worker-plan proof.
    #[must_use]
    pub const fn plugin_endpoints(&self) -> &QemuHotForkPluginEndpointStageProof {
        &self.plugin_endpoints
    }
}

/// Failure while preparing all branch-private child resources.
///
/// The caller retains the source node on every variant. A pre-transfer failure
/// leaves no authority outside the node; a descriptor-bearing ambiguous
/// failure leaves the affected resource inside its quarantined node stage.
#[derive(Debug, Error)]
pub enum QemuHotForkChildResourcePreparationError {
    /// The source was not an empty active template awaiting only plugin resources.
    #[error("retained hot-fork template is not ready for child resource preparation")]
    InvalidTemplateState,
    /// Capturing or materializing the private ring failed before transfer.
    #[error(transparent)]
    Ring(#[from] QemuNodeChannelError),
    /// Private-ring descriptor staging failed.
    #[error(transparent)]
    RingStage(#[from] QemuHotForkPrivateRingStageError),
    /// Diagnostic-stream staging failed.
    #[error(transparent)]
    Diagnostics(#[from] QemuHotForkChildDiagnosticStageError),
    /// Child-QMP staging failed.
    #[error(transparent)]
    ChildQmp(#[from] QemuHotForkChildQmpStageError),
    /// Child-console staging failed.
    #[error(transparent)]
    ChildConsole(#[from] QemuHotForkChildConsoleStageError),
    /// Plugin endpoint and worker-plan sealing failed.
    #[error(transparent)]
    PluginEndpoints(#[from] QemuHotForkPluginEndpointStageError),
    /// QEMU's final resource report contradicted the node-owned stages.
    #[error("QEMU retained a child resource basis different from the node-owned stages")]
    ResourceBasisMismatch,
}

impl QemuNode {
    /// Prepares and seals every branch-private host resource for one hot-fork child.
    ///
    /// The source must retain an otherwise empty template transaction whose six
    /// non-plugin-ring proofs are already acknowledged. The operation captures
    /// and materializes one private ring, then stages diagnostics, child QMP,
    /// child console, and plugin endpoints in dependency order. It finally
    /// authenticates one complete QEMU resource report. No process is forked
    /// and no target cgroup capability is installed by this method.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkChildResourcePreparationError`] when the source is
    /// not in the exact initial state, ring capture or materialization fails,
    /// any descriptor stage fails, or QEMU's final report differs from the
    /// node-owned resources. The source retains every transferred authority.
    pub fn prepare_hot_fork_child_resources(
        &mut self,
        maximum_ring_image_bytes: usize,
    ) -> Result<QemuHotForkPreparedChildResources, QemuHotForkChildResourcePreparationError> {
        let initial = self.query_hot_fork_template()?;
        if self.lifecycle_state != QemuNodeLifecycleState::Running
            || !initial_template_state_is_exact(&initial)
            || self.hot_fork_private_ring_stage.is_some()
            || self.hot_fork_child_diagnostic_stage.is_some()
            || self.hot_fork_child_qmp_stage.is_some()
            || self.hot_fork_child_console_stage.is_some()
            || self.hot_fork_plugin_endpoint_stage.is_some()
            || self.hot_fork_child_process_contract_stage.is_some()
        {
            return Err(QemuHotForkChildResourcePreparationError::InvalidTemplateState);
        }

        let capture = self.capture_hot_fork_plugin_ring_image(maximum_ring_image_bytes)?;
        let private = self.materialize_hot_fork_private_ring_mapping(capture)?;
        self.stage_hot_fork_private_ring_mapping(private)?;
        self.stage_hot_fork_child_diagnostics()?;
        self.stage_hot_fork_child_qmp()?;
        self.stage_hot_fork_child_console()?;
        self.stage_hot_fork_plugin_endpoints()?;

        let prepared = self.query_hot_fork_template()?;
        let private_ring = self
            .hot_fork_private_ring_stage()
            .ok_or(QemuHotForkChildResourcePreparationError::ResourceBasisMismatch)?;
        let diagnostics = self
            .hot_fork_child_diagnostic_stage()
            .ok_or(QemuHotForkChildResourcePreparationError::ResourceBasisMismatch)?;
        let child_qmp = self
            .hot_fork_child_qmp_stage()
            .ok_or(QemuHotForkChildResourcePreparationError::ResourceBasisMismatch)?;
        let child_console = self
            .hot_fork_child_console_stage()
            .ok_or(QemuHotForkChildResourcePreparationError::ResourceBasisMismatch)?;
        let plugin_endpoints = self
            .hot_fork_plugin_endpoint_stage()
            .ok_or(QemuHotForkChildResourcePreparationError::ResourceBasisMismatch)?;
        if !prepared_resources_match(
            &prepared,
            initial.generation(),
            &private_ring,
            &diagnostics,
            &child_qmp,
            &child_console,
            &plugin_endpoints,
        ) {
            return Err(QemuHotForkChildResourcePreparationError::ResourceBasisMismatch);
        }

        Ok(QemuHotForkPreparedChildResources {
            template: prepared,
            private_ring,
            diagnostics,
            child_qmp,
            child_console,
            plugin_endpoints,
        })
    }

    /// Stages one target process contract and forks the exact prepared template.
    ///
    /// This is the only production composition of process-contract staging and
    /// retained-template fork. The method derives the template generation from
    /// QEMU, retains the target descriptors before requesting a child, and
    /// rolls the stage back after every explicit pre-fork rejection. Ambiguous
    /// and post-fork failures retain the complete staged authority in this
    /// node for reconciliation or quarantine.
    ///
    /// # Errors
    ///
    /// Returns [`crate::QemuHotForkLaunchError::Rejected`] when the template is
    /// not exactly prepared, descriptor staging fails before child creation,
    /// or QEMU explicitly rejects the fork. Other launch-error variants mean a
    /// child exists or may exist and leave the source quarantined.
    pub fn fork_prepared_hot_fork_template_into<O, F>(
        &mut self,
        process_owner: &mut O,
        contract_for: F,
    ) -> Result<crate::QemuHotForkChildLaunch<O::Authority>, crate::QemuHotForkLaunchError>
    where
        O: crate::QemuHotForkChildProcessOwner,
        F: for<'a> FnOnce(
            &'a O,
        )
            -> Result<&'a crate::QemuChildProcessContract, QemuNodeChannelError>,
    {
        let prepared = self
            .query_hot_fork_template()
            .map_err(|source| crate::QemuHotForkLaunchError::Rejected { source })?;
        if prepared.generation() == 0
            || prepared.outcome() != QmpHotForkTemplateOutcome::Prepared
            || !prepared.transaction_active()
            || !prepared.ready()
        {
            return Err(crate::QemuHotForkLaunchError::Rejected {
                source: QemuNodeChannelError::new(
                    "stage target hot-fork process contract",
                    "source template is not in the exact prepared state",
                ),
            });
        }
        let contract = contract_for(process_owner)
            .map_err(|source| crate::QemuHotForkLaunchError::Rejected { source })?;
        let process_contract = self
            .stage_hot_fork_child_process_contract(contract, prepared.generation())
            .map_err(|source| crate::QemuHotForkLaunchError::Rejected { source })?;

        match self.fork_prepared_hot_fork_template(process_owner) {
            Err(source @ crate::QemuHotForkLaunchError::Rejected { .. }) => {
                let source = match self.release_hot_fork_child_process_contract() {
                    Ok(released)
                        if !released.staged()
                            && !released.consumed()
                            && released.generation() == process_contract.generation() =>
                    {
                        source
                    }
                    Ok(_released) => crate::QemuHotForkLaunchError::Rejected {
                        source: QemuNodeChannelError::new(
                            "roll back target hot-fork process contract",
                            "QEMU contradicted the exact released contract generation",
                        ),
                    },
                    Err(rollback) => crate::QemuHotForkLaunchError::Rejected {
                        source: QemuNodeChannelError::new(
                            "roll back target hot-fork process contract",
                            format!("{source}; rollback failed: {rollback}"),
                        ),
                    },
                };
                Err(source)
            }
            result => result,
        }
    }
}

fn initial_template_state_is_exact(state: &QmpHotForkTemplateState) -> bool {
    state.generation() != 0
        && state.outcome() == QmpHotForkTemplateOutcome::Draining
        && state.transaction_active()
        && !state.ready()
        && state.acknowledged_proofs()
            == (QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS & !PLUGIN_RING_PROOF)
        && state.missing_proofs() == PLUGIN_RING_PROOF
        && resource_stage_is_empty(state.resource_stage())
}

fn resource_stage_is_empty(state: QmpHotForkTemplateResourceStageState) -> bool {
    state.template_generation() == 0
        && !state.private_ring_staged()
        && state.private_ring_generation() == 0
        && !state.diagnostics_staged()
        && state.diagnostic_generation() == 0
        && !state.diagnostics_resource_plan_bound()
        && !state.qmp_staged()
        && state.qmp_generation() == 0
        && !state.qmp_resource_plan_bound()
        && !state.console_staged()
        && state.console_generation() == 0
        && !state.console_resource_plan_bound()
        && !state.plugin_endpoints_staged()
        && state.plugin_endpoint_generation() == 0
        && state.plugin_private_ring_generation() == 0
        && state.plugin_barrier_generation() == 0
        && state.worker_mask() == 0
        && state.parent_resume_worker_mask() == 0
        && state.child_reinitialize_worker_mask() == 0
        && !state.worker_disposition_bound()
        && !state.transaction_bound()
        && state.parent_process_generation() == 0
        && state.child_process_generation() == 0
        && !state.plugin_child_plan_bound()
        && !state.plugin_child_resource_plan_bound()
        && !state.readiness_proof_acknowledged()
}

// crucible-lint: allow rust-allow -- every independent source/QEMU basis is checked explicitly.
#[allow(clippy::too_many_arguments)]
fn prepared_resources_match(
    state: &QmpHotForkTemplateState,
    generation: u64,
    private_ring: &QemuHotForkPrivateRingStageProof,
    diagnostics: &QemuHotForkChildDiagnosticStageProof,
    child_qmp: &QemuHotForkChildQmpStageProof,
    child_console: &QemuHotForkChildConsoleStageProof,
    endpoints: &QemuHotForkPluginEndpointStageProof,
) -> bool {
    let resource = state.resource_stage();
    state.generation() == generation
        && state.outcome() == QmpHotForkTemplateOutcome::Prepared
        && state.transaction_active()
        && state.ready()
        && state.acknowledged_proofs() == QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS
        && state.missing_proofs() == 0
        && private_ring.state() == QemuHotForkPrivateRingStageState::Installed
        && diagnostics.state() == QemuHotForkChildDiagnosticStageState::Installed
        && diagnostics.template_generation() == generation
        && diagnostics.replacement_plan_bound()
        && child_qmp.state() == QemuHotForkChildQmpStageState::Installed
        && child_qmp.template_generation() == generation
        && child_qmp.resource_plan_bound()
        && child_console.state() == QemuHotForkChildConsoleStageState::Installed
        && child_console.template_generation() == generation
        && child_console.resource_plan_bound()
        && endpoints.state() == QemuHotForkPluginEndpointStageState::Installed
        && endpoints.template_generation() == generation
        && resource.template_generation() == generation
        && resource.private_ring_staged()
        && resource.private_ring_generation() == endpoints.private_ring_generation()
        && resource.diagnostics_staged()
        && resource.diagnostic_generation() != 0
        && resource.diagnostics_resource_plan_bound()
        && resource.qmp_staged()
        && resource.qmp_generation() == child_qmp.qmp_generation()
        && resource.qmp_resource_plan_bound()
        && resource.console_staged()
        && resource.console_generation() == child_console.console_generation()
        && resource.console_resource_plan_bound()
        && resource.plugin_endpoints_staged()
        && resource.plugin_endpoint_generation() == endpoints.generation()
        && resource.plugin_private_ring_generation() == endpoints.private_ring_generation()
        && resource.plugin_barrier_generation() == endpoints.plugin_barrier_generation()
        && resource.worker_mask() == endpoints.worker_mask()
        && resource.parent_resume_worker_mask() == endpoints.worker_mask()
        && resource.child_reinitialize_worker_mask() == endpoints.worker_mask()
        && resource.worker_disposition_bound()
        && resource.transaction_bound()
        && resource.plugin_child_plan_bound()
        && resource.plugin_child_resource_plan_bound()
        && resource.readiness_proof_acknowledged()
}
