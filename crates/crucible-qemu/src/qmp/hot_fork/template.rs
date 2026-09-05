//! Retained QEMU-owned hot-fork template preparation transaction.

#[cfg(test)]
mod native_worker_tests;
mod preparation;
#[cfg(test)]
mod preparation_tests;
#[cfg(test)]
mod source_proof_tests;

mod parse;
pub(crate) use parse::parse_hot_fork_template_state;

use super::{
    QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS, QmpHotForkBhTimerBarrierState,
    QmpHotForkBlockBarrierState, QmpHotForkPluginBarrierState, QmpHotForkProof,
    QmpHotForkRcuBarrierState,
};

/// QMP command name used for QEMU's retained template-preparation coordinator.
pub const QMP_HOT_FORK_TEMPLATE_COMMAND: &str = "crucible-hot-fork-template";
/// Version of the QEMU-owned template-preparation transaction contract.
pub const QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION: u32 = 25;

const QMP_HOT_FORK_AIO_PROOF: u64 = 1_u64 << 3;
const QMP_HOT_FORK_RCU_PROOF: u64 = 1_u64 << 4;
const QMP_HOT_FORK_BLOCK_PROOF: u64 = 1_u64 << 5;
const QMP_HOT_FORK_PLUGIN_RING_PROOF: u64 = 1_u64 << 6;

/// Exact outcome of one hot-fork template coordinator operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmpHotForkTemplateOutcome {
    /// No transaction or acquired subsystem barrier exists.
    Idle,
    /// The retained transaction is waiting for admitted work, exact resource
    /// staging, or reevaluation.
    Draining,
    /// A preparation failure caused every acquired barrier to roll back.
    Blocked,
    /// Every proof is present and the retained transaction remains prepared.
    Prepared,
    /// An active transaction was explicitly rolled back.
    Aborted,
}

/// Exact transaction binding for resources retained beside a template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkTemplateResourceStageState {
    template_generation: u64,
    private_ring_staged: bool,
    private_ring_generation: u64,
    diagnostics_staged: bool,
    diagnostic_generation: u64,
    diagnostics_resource_plan_bound: bool,
    qmp_staged: bool,
    qmp_generation: u64,
    qmp_resource_plan_bound: bool,
    console_staged: bool,
    console_generation: u64,
    console_resource_plan_bound: bool,
    plugin_endpoints_staged: bool,
    plugin_endpoint_generation: u64,
    plugin_private_ring_generation: u64,
    plugin_barrier_generation: u64,
    worker_mask: u64,
    parent_resume_worker_mask: u64,
    child_reinitialize_worker_mask: u64,
    worker_disposition_bound: bool,
    transaction_bound: bool,
    parent_process_generation: u64,
    child_process_generation: u64,
    plugin_child_plan_bound: bool,
    plugin_child_resource_plan_bound: bool,
    readiness_proof_acknowledged: bool,
}

impl QmpHotForkTemplateResourceStageState {
    #[cfg(test)]
    const fn empty() -> Self {
        Self {
            template_generation: 0,
            private_ring_staged: false,
            private_ring_generation: 0,
            diagnostics_staged: false,
            diagnostic_generation: 0,
            diagnostics_resource_plan_bound: false,
            qmp_staged: false,
            qmp_generation: 0,
            qmp_resource_plan_bound: false,
            console_staged: false,
            console_generation: 0,
            console_resource_plan_bound: false,
            plugin_endpoints_staged: false,
            plugin_endpoint_generation: 0,
            plugin_private_ring_generation: 0,
            plugin_barrier_generation: 0,
            worker_mask: 0,
            parent_resume_worker_mask: 0,
            child_reinitialize_worker_mask: 0,
            worker_disposition_bound: false,
            transaction_bound: false,
            parent_process_generation: 0,
            child_process_generation: 0,
            plugin_child_plan_bound: false,
            plugin_child_resource_plan_bound: false,
            readiness_proof_acknowledged: false,
        }
    }

    /// Returns the template generation that admitted the retained resources.
    #[must_use]
    pub const fn template_generation(self) -> u64 {
        self.template_generation
    }

    /// Returns whether QEMU retains one branch-private ring descriptor.
    #[must_use]
    pub const fn private_ring_staged(self) -> bool {
        self.private_ring_staged
    }

    /// Returns the current private-ring mutation generation.
    #[must_use]
    pub const fn private_ring_generation(self) -> u64 {
        self.private_ring_generation
    }

    /// Returns whether QEMU retains one branch-private diagnostics stream.
    #[must_use]
    pub const fn diagnostics_staged(self) -> bool {
        self.diagnostics_staged
    }

    /// Returns the current child-diagnostics mutation generation.
    #[must_use]
    pub const fn diagnostic_generation(self) -> u64 {
        self.diagnostic_generation
    }

    /// Returns whether the diagnostics contribution is in the sealed plan.
    #[must_use]
    pub const fn diagnostics_resource_plan_bound(self) -> bool {
        self.diagnostics_resource_plan_bound
    }

    /// Returns whether QEMU retains one branch-private child QMP stream.
    #[must_use]
    pub const fn qmp_staged(self) -> bool {
        self.qmp_staged
    }

    /// Returns the current child-QMP mutation generation.
    #[must_use]
    pub const fn qmp_generation(self) -> u64 {
        self.qmp_generation
    }

    /// Returns whether the child-QMP contribution is in the sealed plan.
    #[must_use]
    pub const fn qmp_resource_plan_bound(self) -> bool {
        self.qmp_resource_plan_bound
    }

    /// Returns whether QEMU retains one branch-private child console stream.
    #[must_use]
    pub const fn console_staged(self) -> bool {
        self.console_staged
    }

    /// Returns the current child-console mutation generation.
    #[must_use]
    pub const fn console_generation(self) -> u64 {
        self.console_generation
    }

    /// Returns whether the child-console contribution is in the sealed plan.
    #[must_use]
    pub const fn console_resource_plan_bound(self) -> bool {
        self.console_resource_plan_bound
    }

    /// Returns whether QEMU retains one branch-private plugin endpoint pair.
    #[must_use]
    pub const fn plugin_endpoints_staged(self) -> bool {
        self.plugin_endpoints_staged
    }

    /// Returns the current plugin-endpoint mutation generation.
    #[must_use]
    pub const fn plugin_endpoint_generation(self) -> u64 {
        self.plugin_endpoint_generation
    }

    /// Returns the private-ring generation captured by the endpoint pair.
    #[must_use]
    pub const fn plugin_private_ring_generation(self) -> u64 {
        self.plugin_private_ring_generation
    }

    /// Returns the plugin-barrier generation captured by the endpoint stage.
    #[must_use]
    pub const fn plugin_barrier_generation(self) -> u64 {
        self.plugin_barrier_generation
    }

    /// Returns the exact sealed process-lifetime worker classes.
    #[must_use]
    pub const fn worker_mask(self) -> u64 {
        self.worker_mask
    }

    /// Returns the worker classes the template parent must resume.
    #[must_use]
    pub const fn parent_resume_worker_mask(self) -> u64 {
        self.parent_resume_worker_mask
    }

    /// Returns the worker classes a future fork child must reinitialize.
    #[must_use]
    pub const fn child_reinitialize_worker_mask(self) -> u64 {
        self.child_reinitialize_worker_mask
    }

    /// Returns whether the worker plan matches the current retained barrier.
    #[must_use]
    pub const fn worker_disposition_bound(self) -> bool {
        self.worker_disposition_bound
    }

    /// Returns whether every staged resource belongs to the active transaction.
    #[must_use]
    pub const fn transaction_bound(self) -> bool {
        self.transaction_bound
    }

    /// Returns the process generation copied into the retained child plan.
    #[must_use]
    pub const fn parent_process_generation(self) -> u64 {
        self.parent_process_generation
    }

    /// Returns the checked immediate-successor child process generation.
    #[must_use]
    pub const fn child_process_generation(self) -> u64 {
        self.child_process_generation
    }

    /// Returns whether QEMU retains the exact unconsumed plugin child plan.
    #[must_use]
    pub const fn plugin_child_plan_bound(self) -> bool {
        self.plugin_child_plan_bound
    }

    /// Returns whether QEMU holds the exact plugin child resource tables.
    #[must_use]
    pub const fn plugin_child_resource_plan_bound(self) -> bool {
        self.plugin_child_resource_plan_bound
    }

    /// Returns whether the complete retained pair acknowledges plugin-ring proof bit 6.
    #[must_use]
    pub const fn readiness_proof_acknowledged(self) -> bool {
        self.readiness_proof_acknowledged
    }
}

/// Exact state returned by QEMU's retained template-preparation coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpHotForkTemplateState {
    generation: u64,
    outcome: QmpHotForkTemplateOutcome,
    transaction_active: bool,
    acknowledged_proofs: u64,
    missing_proofs: u64,
    plugin_barrier: QmpHotForkPluginBarrierState,
    rcu_barrier: QmpHotForkRcuBarrierState,
    bh_timer_barrier: QmpHotForkBhTimerBarrierState,
    block_barrier: QmpHotForkBlockBarrierState,
    resource_stage: QmpHotForkTemplateResourceStageState,
    rollback_complete: bool,
    ready: bool,
}

impl QmpHotForkTemplateState {
    #[cfg(test)]
    pub(crate) fn one_draining_without_resources(request: super::QmpHotForkRequest) -> Self {
        let plugin_barrier =
            QmpHotForkPluginBarrierState::one_quiescent(request.plugin_barrier_generation(), 1);
        Self {
            generation: request.template_generation(),
            outcome: QmpHotForkTemplateOutcome::Draining,
            transaction_active: true,
            acknowledged_proofs: QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS
                & !QMP_HOT_FORK_PLUGIN_RING_PROOF,
            missing_proofs: QMP_HOT_FORK_PLUGIN_RING_PROOF,
            plugin_barrier,
            rcu_barrier: QmpHotForkRcuBarrierState::one_quiescent(request.rcu_barrier_generation()),
            bh_timer_barrier: QmpHotForkBhTimerBarrierState::one_quiescent(
                request.bh_timer_barrier_generation(),
            ),
            block_barrier: QmpHotForkBlockBarrierState::one_quiescent(
                request.block_barrier_generation(),
            ),
            resource_stage: QmpHotForkTemplateResourceStageState::empty(),
            rollback_complete: false,
            ready: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn one_prepared(request: super::QmpHotForkRequest) -> Self {
        let plugin_barrier =
            QmpHotForkPluginBarrierState::one_quiescent(request.plugin_barrier_generation(), 1);
        let worker_mask = plugin_barrier.worker_mask();
        Self {
            generation: request.template_generation(),
            outcome: QmpHotForkTemplateOutcome::Prepared,
            transaction_active: true,
            acknowledged_proofs: QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS,
            missing_proofs: 0,
            plugin_barrier,
            rcu_barrier: QmpHotForkRcuBarrierState::one_quiescent(request.rcu_barrier_generation()),
            bh_timer_barrier: QmpHotForkBhTimerBarrierState::one_quiescent(
                request.bh_timer_barrier_generation(),
            ),
            block_barrier: QmpHotForkBlockBarrierState::one_quiescent(
                request.block_barrier_generation(),
            ),
            resource_stage: QmpHotForkTemplateResourceStageState {
                template_generation: request.template_generation(),
                private_ring_staged: true,
                private_ring_generation: request.private_ring_generation(),
                diagnostics_staged: true,
                diagnostic_generation: request.diagnostic_generation(),
                diagnostics_resource_plan_bound: true,
                qmp_staged: true,
                qmp_generation: request.qmp_generation(),
                qmp_resource_plan_bound: true,
                console_staged: true,
                console_generation: request.console_generation(),
                console_resource_plan_bound: true,
                plugin_endpoints_staged: true,
                plugin_endpoint_generation: request.plugin_endpoint_generation(),
                plugin_private_ring_generation: request.private_ring_generation(),
                plugin_barrier_generation: request.plugin_barrier_generation(),
                worker_mask,
                parent_resume_worker_mask: worker_mask,
                child_reinitialize_worker_mask: worker_mask,
                worker_disposition_bound: true,
                transaction_bound: true,
                parent_process_generation: request.parent_process_generation(),
                child_process_generation: request.child_process_generation(),
                plugin_child_plan_bound: true,
                plugin_child_resource_plan_bound: true,
                readiness_proof_acknowledged: true,
            },
            rollback_complete: false,
            ready: true,
        }
    }

    /// Returns the process-local transaction generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact result of the requested coordinator operation.
    #[must_use]
    pub const fn outcome(&self) -> QmpHotForkTemplateOutcome {
        self.outcome
    }

    /// Returns whether QEMU still owns acquired subsystem-barrier state.
    #[must_use]
    pub const fn transaction_active(&self) -> bool {
        self.transaction_active
    }

    /// Returns the exact currently acknowledged proof bitmap.
    #[must_use]
    pub const fn acknowledged_proofs(&self) -> u64 {
        self.acknowledged_proofs
    }

    /// Returns whether this retained transaction acknowledges one proof.
    #[must_use]
    pub const fn acknowledges(&self, proof: QmpHotForkProof) -> bool {
        self.acknowledged_proofs & proof.mask() != 0
    }

    /// Returns the exact required proof bits QEMU could not acknowledge.
    #[must_use]
    pub const fn missing_proofs(&self) -> u64 {
        self.missing_proofs
    }

    /// Returns the plugin callback barrier after the operation and any rollback.
    #[must_use]
    pub const fn plugin_barrier(&self) -> QmpHotForkPluginBarrierState {
        self.plugin_barrier
    }

    /// Returns the retained RCU admission/drain barrier state.
    #[must_use]
    pub const fn rcu_barrier(&self) -> QmpHotForkRcuBarrierState {
        self.rcu_barrier
    }

    /// Returns the retained asynchronous-source barrier state.
    #[must_use]
    pub const fn bh_timer_barrier(&self) -> QmpHotForkBhTimerBarrierState {
        self.bh_timer_barrier
    }

    /// Returns the retained block-graph writer and native drain state.
    #[must_use]
    pub const fn block_barrier(&self) -> &QmpHotForkBlockBarrierState {
        &self.block_barrier
    }

    /// Returns the exact resource generations bound beside this transaction.
    #[must_use]
    pub const fn resource_stage(&self) -> QmpHotForkTemplateResourceStageState {
        self.resource_stage
    }

    /// Returns whether QEMU attests that no transaction barrier remains acquired.
    #[must_use]
    pub const fn rollback_complete(&self) -> bool {
        self.rollback_complete
    }

    /// Returns whether every proof is present in one retained prepared transaction.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.ready
    }
}
