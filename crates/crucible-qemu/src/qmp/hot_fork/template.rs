//! Retained QEMU-owned hot-fork template preparation transaction.

use serde_json::Value;

use super::{
    QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS, QmpHotForkBhTimerBarrierState,
    QmpHotForkBlockBarrierState, QmpHotForkPluginBarrierState, QmpHotForkProof,
    QmpHotForkRcuBarrierState, bh_timer_barrier::parse_hot_fork_bh_timer_barrier_state_for,
    block_barrier::parse_hot_fork_block_barrier_state_for,
    plugin::parse_hot_fork_plugin_barrier_state_for,
    rcu_barrier::parse_hot_fork_rcu_barrier_state_for,
};
use crate::qmp::{QmpCommandKind, QmpError};

/// QMP command name used for QEMU's retained template-preparation coordinator.
pub const QMP_HOT_FORK_TEMPLATE_COMMAND: &str = "crucible-hot-fork-template";
/// Version of the QEMU-owned template-preparation transaction contract.
pub const QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION: u32 = 24;

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

pub(crate) fn parse_hot_fork_template_state(
    value: &Value,
) -> Result<QmpHotForkTemplateState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::HotForkTemplate,
        response: value.to_string(),
    };
    let object = value.as_object().ok_or_else(&malformed)?;
    let fields = [
        "schema-version",
        "generation",
        "outcome",
        "transaction-active",
        "required-proofs",
        "acknowledged-proofs",
        "missing-proofs",
        "plugin-barrier",
        "rcu-barrier",
        "bh-timer-barrier",
        "block-barrier",
        "resource-stage",
        "rollback-complete",
        "ready",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let schema_version = object
        .get("schema-version")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let generation = object
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let outcome = match object.get("outcome").and_then(Value::as_str) {
        Some("idle") => QmpHotForkTemplateOutcome::Idle,
        Some("draining") => QmpHotForkTemplateOutcome::Draining,
        Some("blocked") => QmpHotForkTemplateOutcome::Blocked,
        Some("prepared") => QmpHotForkTemplateOutcome::Prepared,
        Some("aborted") => QmpHotForkTemplateOutcome::Aborted,
        _ => return Err(malformed()),
    };
    let transaction_active = object
        .get("transaction-active")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let required_proofs = object
        .get("required-proofs")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let acknowledged_proofs = object
        .get("acknowledged-proofs")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let missing_proofs = object
        .get("missing-proofs")
        .and_then(Value::as_u64)
        .ok_or_else(&malformed)?;
    let plugin_barrier = parse_hot_fork_plugin_barrier_state_for(
        QmpCommandKind::HotForkTemplate,
        object.get("plugin-barrier").ok_or_else(&malformed)?,
    )?;
    let rcu_barrier = parse_hot_fork_rcu_barrier_state_for(
        QmpCommandKind::HotForkTemplate,
        object.get("rcu-barrier").ok_or_else(&malformed)?,
    )?;
    let bh_timer_barrier = parse_hot_fork_bh_timer_barrier_state_for(
        QmpCommandKind::HotForkTemplate,
        object.get("bh-timer-barrier").ok_or_else(&malformed)?,
    )?;
    let block_barrier = parse_hot_fork_block_barrier_state_for(
        QmpCommandKind::HotForkTemplate,
        object.get("block-barrier").ok_or_else(&malformed)?,
    )?;
    let resource_stage = parse_hot_fork_template_resource_stage(
        object.get("resource-stage").ok_or_else(&malformed)?,
        generation,
        transaction_active,
        plugin_barrier,
        &malformed,
    )?;
    let rollback_complete = object
        .get("rollback-complete")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;
    let ready = object
        .get("ready")
        .and_then(Value::as_bool)
        .ok_or_else(&malformed)?;

    let proofs_valid = schema_version == u64::from(QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION)
        && required_proofs == QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS
        && acknowledged_proofs & !required_proofs == 0
        && missing_proofs == required_proofs & !acknowledged_proofs;
    let expected_ready = outcome == QmpHotForkTemplateOutcome::Prepared
        && transaction_active
        && plugin_barrier.quiescent()
        && rcu_barrier.quiescent()
        && bh_timer_barrier.quiescent()
        && block_barrier.quiescent()
        && block_barrier.snapshot_complete()
        && missing_proofs == 0;
    let expected_rollback = !transaction_active
        && !plugin_barrier.held()
        && !rcu_barrier.held()
        && !bh_timer_barrier.held()
        && !block_barrier.held()
        && !block_barrier.snapshot_bound();
    let rcu_proof_valid = (acknowledged_proofs & QMP_HOT_FORK_RCU_PROOF != 0)
        == (transaction_active && rcu_barrier.quiescent());
    let aio_proof_valid = (acknowledged_proofs & QMP_HOT_FORK_AIO_PROOF != 0)
        == (transaction_active && bh_timer_barrier.quiescent());
    let block_proof_valid = (acknowledged_proofs & QMP_HOT_FORK_BLOCK_PROOF != 0)
        == (transaction_active && block_barrier.snapshot_complete());
    let plugin_ring_proof_valid =
        plugin_ring_proof_shape_valid(acknowledged_proofs, resource_stage);
    let ordinary_barriers_unheld =
        !plugin_barrier.held() && !rcu_barrier.held() && !bh_timer_barrier.held();
    let all_barriers_held = plugin_barrier.held()
        && !plugin_barrier.teardown_closed()
        && rcu_barrier.held()
        && bh_timer_barrier.held()
        && block_barrier.held()
        && block_barrier.snapshot_complete();
    let shape_valid = match outcome {
        QmpHotForkTemplateOutcome::Idle => {
            !transaction_active
                && rollback_complete
                && ordinary_barriers_unheld
                && !block_barrier.held()
                && !ready
        }
        QmpHotForkTemplateOutcome::Draining => {
            generation != 0
                && transaction_active
                && !rollback_complete
                && (all_barriers_held || ordinary_barriers_unheld)
                && !ready
        }
        QmpHotForkTemplateOutcome::Blocked => {
            generation != 0
                && !transaction_active
                && rollback_complete
                && ordinary_barriers_unheld
                && !block_barrier.held()
                && missing_proofs != 0
                && !ready
        }
        QmpHotForkTemplateOutcome::Prepared => {
            generation != 0
                && transaction_active
                && !rollback_complete
                && plugin_barrier.quiescent()
                && rcu_barrier.quiescent()
                && bh_timer_barrier.quiescent()
                && block_barrier.quiescent()
                && block_barrier.snapshot_complete()
                && ready
        }
        QmpHotForkTemplateOutcome::Aborted => {
            generation != 0
                && !transaction_active
                && rollback_complete
                && ordinary_barriers_unheld
                && !block_barrier.held()
                && !ready
        }
    };
    if !proofs_valid
        || ready != expected_ready
        || rollback_complete != expected_rollback
        || !rcu_proof_valid
        || !aio_proof_valid
        || !block_proof_valid
        || !plugin_ring_proof_valid
        || !shape_valid
    {
        return Err(malformed());
    }

    Ok(QmpHotForkTemplateState {
        generation,
        outcome,
        transaction_active,
        acknowledged_proofs,
        missing_proofs,
        plugin_barrier,
        rcu_barrier,
        bh_timer_barrier,
        block_barrier,
        resource_stage,
        rollback_complete,
        ready,
    })
}

fn plugin_ring_proof_shape_valid(
    acknowledged_proofs: u64,
    resource_stage: QmpHotForkTemplateResourceStageState,
) -> bool {
    (acknowledged_proofs & QMP_HOT_FORK_PLUGIN_RING_PROOF != 0)
        == resource_stage.readiness_proof_acknowledged()
}

fn parse_hot_fork_template_resource_stage(
    value: &Value,
    template_generation: u64,
    transaction_active: bool,
    plugin_barrier: QmpHotForkPluginBarrierState,
    malformed: &impl Fn() -> QmpError,
) -> Result<QmpHotForkTemplateResourceStageState, QmpError> {
    let object = value.as_object().ok_or_else(malformed)?;
    let fields = [
        "schema-version",
        "template-generation",
        "private-ring-staged",
        "private-ring-generation",
        "diagnostics-staged",
        "diagnostic-generation",
        "diagnostics-resource-plan-bound",
        "qmp-staged",
        "qmp-generation",
        "qmp-resource-plan-bound",
        "console-staged",
        "console-generation",
        "console-resource-plan-bound",
        "plugin-endpoints-staged",
        "plugin-endpoint-generation",
        "plugin-private-ring-generation",
        "plugin-barrier-generation",
        "worker-mask",
        "parent-resume-worker-mask",
        "child-reinitialize-worker-mask",
        "pending-worker-mask",
        "worker-disposition-bound",
        "transaction-bound",
        "parent-process-generation",
        "child-process-generation",
        "plugin-child-plan-bound",
        "plugin-child-resource-plan-bound",
        "readiness-proof-acknowledged",
    ];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) {
        return Err(malformed());
    }

    let u64_field = |field| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(malformed)
    };
    let bool_field = |field| {
        object
            .get(field)
            .and_then(Value::as_bool)
            .ok_or_else(malformed)
    };
    let schema_version = u64_field("schema-version")?;
    let resource_template_generation = u64_field("template-generation")?;
    let private_ring_staged = bool_field("private-ring-staged")?;
    let private_ring_generation = u64_field("private-ring-generation")?;
    let diagnostics_staged = bool_field("diagnostics-staged")?;
    let diagnostic_generation = u64_field("diagnostic-generation")?;
    let diagnostics_resource_plan_bound = bool_field("diagnostics-resource-plan-bound")?;
    let qmp_staged = bool_field("qmp-staged")?;
    let qmp_generation = u64_field("qmp-generation")?;
    let qmp_resource_plan_bound = bool_field("qmp-resource-plan-bound")?;
    let console_staged = bool_field("console-staged")?;
    let console_generation = u64_field("console-generation")?;
    let console_resource_plan_bound = bool_field("console-resource-plan-bound")?;
    let plugin_endpoints_staged = bool_field("plugin-endpoints-staged")?;
    let plugin_endpoint_generation = u64_field("plugin-endpoint-generation")?;
    let plugin_private_ring_generation = u64_field("plugin-private-ring-generation")?;
    let plugin_barrier_generation = u64_field("plugin-barrier-generation")?;
    let worker_mask = u64_field("worker-mask")?;
    let parent_resume_worker_mask = u64_field("parent-resume-worker-mask")?;
    let child_reinitialize_worker_mask = u64_field("child-reinitialize-worker-mask")?;
    let pending_worker_mask = u64_field("pending-worker-mask")?;
    let worker_disposition_bound = bool_field("worker-disposition-bound")?;
    let transaction_bound = bool_field("transaction-bound")?;
    let parent_process_generation = u64_field("parent-process-generation")?;
    let child_process_generation = u64_field("child-process-generation")?;
    let plugin_child_plan_bound = bool_field("plugin-child-plan-bound")?;
    let plugin_child_resource_plan_bound = bool_field("plugin-child-resource-plan-bound")?;
    let readiness_proof_acknowledged = bool_field("readiness-proof-acknowledged")?;
    let state = QmpHotForkTemplateResourceStageState {
        template_generation: resource_template_generation,
        private_ring_staged,
        private_ring_generation,
        diagnostics_staged,
        diagnostic_generation,
        diagnostics_resource_plan_bound,
        qmp_staged,
        qmp_generation,
        qmp_resource_plan_bound,
        console_staged,
        console_generation,
        console_resource_plan_bound,
        plugin_endpoints_staged,
        plugin_endpoint_generation,
        plugin_private_ring_generation,
        plugin_barrier_generation,
        worker_mask,
        parent_resume_worker_mask,
        child_reinitialize_worker_mask,
        worker_disposition_bound,
        transaction_bound,
        parent_process_generation,
        child_process_generation,
        plugin_child_plan_bound,
        plugin_child_resource_plan_bound,
        readiness_proof_acknowledged,
    };
    if !resource_stage_shape_valid(
        schema_version,
        state,
        template_generation,
        transaction_active,
        plugin_barrier,
        pending_worker_mask,
        readiness_proof_acknowledged,
    ) {
        return Err(malformed());
    }
    Ok(state)
}

fn resource_stage_shape_valid(
    schema_version: u64,
    state: QmpHotForkTemplateResourceStageState,
    template_generation: u64,
    transaction_active: bool,
    plugin_barrier: QmpHotForkPluginBarrierState,
    pending_worker_mask: u64,
    readiness_proof_acknowledged: bool,
) -> bool {
    let resources_staged = state.private_ring_staged
        || state.diagnostics_staged
        || state.qmp_staged
        || state.console_staged
        || state.plugin_endpoints_staged;
    let disposition_shape = if state.plugin_endpoints_staged && state.template_generation != 0 {
        state.plugin_barrier_generation != 0
            && state.worker_mask != 0
            && state.parent_resume_worker_mask == state.worker_mask
            && state.child_reinitialize_worker_mask == state.worker_mask
            && pending_worker_mask == 0
    } else {
        state.plugin_barrier_generation == 0
            && state.worker_mask == 0
            && state.parent_resume_worker_mask == 0
            && state.child_reinitialize_worker_mask == 0
            && pending_worker_mask == 0
    };
    let expected_disposition_bound = transaction_active
        && state.plugin_endpoints_staged
        && state.template_generation == template_generation
        && disposition_shape
        && plugin_barrier.quiescent()
        && state.plugin_barrier_generation == plugin_barrier.generation()
        && state.worker_mask == plugin_barrier.worker_mask()
        && state.worker_mask == plugin_barrier.parked_worker_mask()
        && plugin_barrier.pending_worker_mask() == 0
        && plugin_barrier.worker_operations_in_flight() == 0;
    let expected_bound = transaction_active
        && resources_staged
        && state.template_generation == template_generation
        && (!state.plugin_endpoints_staged || expected_disposition_bound);
    let expected_readiness_proof = expected_bound
        && state.private_ring_staged
        && state.diagnostics_staged
        && state.qmp_staged
        && state.console_staged
        && state.plugin_endpoints_staged
        && expected_disposition_bound
        && plugin_barrier.quiescent();
    let child_plan_shape = if state.plugin_child_plan_bound {
        expected_readiness_proof
            && state.parent_process_generation != 0
            && state.parent_process_generation != u64::MAX
            && state.child_process_generation == state.parent_process_generation + 1
    } else {
        state.parent_process_generation == 0 && state.child_process_generation == 0
    };

    schema_version == 13
        && readiness_proof_acknowledged == expected_readiness_proof
        && child_plan_shape
        && state.diagnostics_resource_plan_bound == state.plugin_child_plan_bound
        && state.qmp_resource_plan_bound == state.plugin_child_plan_bound
        && state.console_resource_plan_bound == state.plugin_child_plan_bound
        && state.plugin_child_resource_plan_bound == state.plugin_child_plan_bound
        && disposition_shape
        && (!state.private_ring_staged || state.private_ring_generation != 0)
        && (!state.diagnostics_staged || state.diagnostic_generation != 0)
        && (!state.diagnostics_staged || state.private_ring_staged)
        && (!state.qmp_staged || state.qmp_generation != 0)
        && (!state.qmp_staged || state.diagnostics_staged)
        && (!state.console_staged || state.console_generation != 0)
        && (!state.console_staged || state.qmp_staged)
        && (!state.plugin_endpoints_staged || state.console_staged)
        && (state.diagnostics_staged || !state.diagnostics_resource_plan_bound)
        && (state.qmp_staged || !state.qmp_resource_plan_bound)
        && (state.console_staged || !state.console_resource_plan_bound)
        && (!state.plugin_endpoints_staged
            || (state.private_ring_staged
                && state.plugin_endpoint_generation != 0
                && state.plugin_private_ring_generation == state.private_ring_generation))
        && (state.plugin_endpoints_staged || state.plugin_private_ring_generation == 0)
        && (resources_staged || state.template_generation == 0)
        && (!resources_staged
            || state.template_generation == 0
            || state.template_generation == template_generation)
        && (!transaction_active || !resources_staged || expected_bound)
        && state.worker_disposition_bound == expected_disposition_bound
        && state.transaction_bound == expected_bound
}

#[cfg(test)]
mod tests {
    use super::{
        QMP_HOT_FORK_PLUGIN_RING_PROOF, QmpHotForkPluginBarrierState,
        QmpHotForkTemplateResourceStageState, plugin_ring_proof_shape_valid,
        resource_stage_shape_valid,
    };

    #[test]
    fn resource_stage_requires_exact_template_and_private_ring_generations() {
        let plugin_barrier = QmpHotForkPluginBarrierState::one_quiescent(6, 9);
        let worker_mask = plugin_barrier.worker_mask();
        let schema_version = 13;
        let bound = QmpHotForkTemplateResourceStageState {
            template_generation: 4,
            private_ring_staged: true,
            private_ring_generation: 11,
            diagnostics_staged: true,
            diagnostic_generation: 13,
            diagnostics_resource_plan_bound: true,
            qmp_staged: true,
            qmp_generation: 14,
            qmp_resource_plan_bound: true,
            console_staged: true,
            console_generation: 15,
            console_resource_plan_bound: true,
            plugin_endpoints_staged: true,
            plugin_endpoint_generation: 12,
            plugin_private_ring_generation: 11,
            plugin_barrier_generation: 6,
            worker_mask,
            parent_resume_worker_mask: worker_mask,
            child_reinitialize_worker_mask: worker_mask,
            worker_disposition_bound: true,
            transaction_bound: true,
            parent_process_generation: 21,
            child_process_generation: 22,
            plugin_child_plan_bound: true,
            plugin_child_resource_plan_bound: true,
            readiness_proof_acknowledged: true,
        };
        assert!(resource_stage_shape_valid(
            schema_version,
            bound,
            4,
            true,
            plugin_barrier,
            0,
            true
        ));

        let foreign_template = QmpHotForkTemplateResourceStageState {
            template_generation: 3,
            ..bound
        };
        assert!(!resource_stage_shape_valid(
            schema_version,
            foreign_template,
            4,
            true,
            plugin_barrier,
            0,
            true
        ));

        let foreign_ring = QmpHotForkTemplateResourceStageState {
            plugin_private_ring_generation: 10,
            ..bound
        };
        assert!(!resource_stage_shape_valid(
            schema_version,
            foreign_ring,
            4,
            true,
            plugin_barrier,
            0,
            true
        ));

        let unbound = QmpHotForkTemplateResourceStageState {
            transaction_bound: false,
            ..bound
        };
        assert!(!resource_stage_shape_valid(
            schema_version,
            unbound,
            4,
            true,
            plugin_barrier,
            0,
            true
        ));

        let unbound_resource_plan = QmpHotForkTemplateResourceStageState {
            plugin_child_resource_plan_bound: false,
            ..bound
        };
        assert!(!resource_stage_shape_valid(
            schema_version,
            unbound_resource_plan,
            4,
            true,
            plugin_barrier,
            0,
            true
        ));

        let retained_after_abort = QmpHotForkTemplateResourceStageState {
            worker_disposition_bound: false,
            transaction_bound: false,
            parent_process_generation: 0,
            child_process_generation: 0,
            plugin_child_plan_bound: false,
            diagnostics_resource_plan_bound: false,
            qmp_resource_plan_bound: false,
            console_resource_plan_bound: false,
            plugin_child_resource_plan_bound: false,
            readiness_proof_acknowledged: false,
            ..bound
        };
        assert!(resource_stage_shape_valid(
            schema_version,
            retained_after_abort,
            4,
            false,
            plugin_barrier,
            0,
            false
        ));
        assert!(!resource_stage_shape_valid(
            schema_version,
            retained_after_abort,
            7,
            false,
            plugin_barrier,
            0,
            false
        ));

        let stale_barrier = QmpHotForkTemplateResourceStageState {
            plugin_barrier_generation: 5,
            ..bound
        };
        assert!(!resource_stage_shape_valid(
            schema_version,
            stale_barrier,
            4,
            true,
            plugin_barrier,
            0,
            true
        ));
        assert!(!resource_stage_shape_valid(
            schema_version,
            bound,
            4,
            true,
            plugin_barrier,
            worker_mask,
            true
        ));

        let forged_proof = QmpHotForkTemplateResourceStageState {
            readiness_proof_acknowledged: false,
            ..bound
        };
        assert!(!resource_stage_shape_valid(
            5,
            forged_proof,
            4,
            true,
            plugin_barrier,
            0,
            false
        ));

        assert!(plugin_ring_proof_shape_valid(
            QMP_HOT_FORK_PLUGIN_RING_PROOF,
            bound
        ));
        assert!(!plugin_ring_proof_shape_valid(0, bound));
        assert!(plugin_ring_proof_shape_valid(0, forged_proof));
        assert!(!plugin_ring_proof_shape_valid(
            QMP_HOT_FORK_PLUGIN_RING_PROOF,
            forged_proof
        ));
    }
}
