//! Decodes retained-template reports and validates their subsystem proofs.
//!
//! The versioned envelope records withheld proofs explicitly:
//!
//! ```text
//! { "schema-version": 24, "generation": N, "outcome": "draining",
//!   "acknowledged-proofs": A, "missing-proofs": M, ... }
//! ```
//!
//! The complete report includes separately versioned barrier and resource
//! states. Only their consistent, complete proof mask authorizes Prepared.

#[cfg(test)]
mod tests;

use serde_json::Value;

use super::{
    QMP_HOT_FORK_AIO_PROOF, QMP_HOT_FORK_BLOCK_PROOF, QMP_HOT_FORK_PLUGIN_RING_PROOF,
    QMP_HOT_FORK_RCU_PROOF, QMP_HOT_FORK_TEMPLATE_SCHEMA_VERSION, QmpHotForkTemplateOutcome,
    QmpHotForkTemplateResourceStageState, QmpHotForkTemplateState,
};
use crate::qmp::hot_fork::{
    QMP_HOT_FORK_TEMPLATE_REQUIRED_PROOFS, QmpHotForkPluginBarrierState,
    bh_timer_barrier::parse_hot_fork_bh_timer_barrier_state_for,
    block_barrier::parse_hot_fork_block_barrier_state_for,
    plugin::parse_hot_fork_plugin_barrier_state_for,
    rcu_barrier::parse_hot_fork_rcu_barrier_state_for,
};
use crate::qmp::{QmpCommandKind, QmpError};

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
    // Quiescent admission is necessary, but native pools must also be retired.
    // QEMU may withhold this proof after a pool is recreated before admission
    // closes. Preserve that draining state; only the complete proof mask can
    // authorize Prepared.
    let aio_proof_valid = acknowledged_proofs & QMP_HOT_FORK_AIO_PROOF == 0
        || (transaction_active && bh_timer_barrier.quiescent());
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
