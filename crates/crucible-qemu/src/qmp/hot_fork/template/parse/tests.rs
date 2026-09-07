//! Checks retained child-resource proof relationships and stale generations.

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
