//! Structural body/sealed-plan comparisons; no owner or signature is fabricated.

use super::host_worker::compare_worker_request;
use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, PrepareHostFuseWorkerSessionRequestV1, RequestHeader,
};
use aos_sandbox_protocol::fuse_worker_preparation::WorkerPreparationPlanV1;
use buffa::Message as _;

fn fixture() -> (
    PrepareHostFuseWorkerSessionRequestV1,
    WorkerPreparationPlanV1,
) {
    let plan = WorkerPreparationPlanV1 {
        worker_instance: [1; 16],
        kernel_boot: [2; 16],
        challenge: [3; 32],
        controller_request: [4; 32],
        mount_reservation: [5; 32],
        assignment: [6; 32],
        attachment: [7; 32],
        original_view_descriptor: [8; 32],
        resolved_policy_descriptor: [9; 32],
        mount_slot: [10; 32],
        ownership_lease: [11; 16],
        ownership_lease_expires_boottime_ns: 200,
        preparation_deadline_boottime_ns: 100,
    };
    let body = PrepareHostFuseWorkerSessionRequestV1 {
        header: Some(RequestHeader {
            protocol_major: 1,
            audience: aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_ROOT_MOUNT.into(),
            request_id: vec![12; 16],
            deadline_boottime_nanoseconds: 90,
            maximum_response_bytes: 4096,
            ..Default::default()
        })
        .into(),
        fence: Some(AssignmentFence {
            sandbox_id: vec![13; 16],
            incarnation_id: vec![14; 16],
            assignment_epoch: 1,
            desired_generation: 1,
            assignment_digest: vec![6; 32],
            ..Default::default()
        })
        .into(),
        worker_instance_id: plan.worker_instance.to_vec(),
        preparation_plan_digest: plan.digest().unwrap().to_vec(),
        mount_reservation_commitment: plan.mount_reservation.to_vec(),
        ..Default::default()
    };
    (body, plan)
}

#[test]
fn exact_body_cannot_select_another_worker_plan_or_extend_preparation() {
    let (body, plan) = fixture();
    compare_worker_request(&body.encode_to_vec(), &plan, 1).unwrap();
    for case in 0..4 {
        let mut changed = body.clone();
        match case {
            0 => changed.worker_instance_id[0] ^= 1,
            1 => changed.preparation_plan_digest[0] ^= 1,
            2 => changed.mount_reservation_commitment[0] ^= 1,
            3 => {
                changed
                    .header
                    .get_or_insert_default()
                    .deadline_boottime_nanoseconds = 101
            }
            _ => unreachable!(),
        }
        assert!(compare_worker_request(&changed.encode_to_vec(), &plan, 1).is_err());
    }
    let mut changed_plan = plan;
    changed_plan.challenge[0] ^= 1;
    assert!(compare_worker_request(&body.encode_to_vec(), &changed_plan, 1).is_err());
    assert!(compare_worker_request(&body.encode_to_vec(), &changed_plan, 90).is_err());
}
