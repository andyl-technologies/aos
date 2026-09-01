//! Tests extracted from the adjacent production module.

use super::*;

fn class(id: u8, operation: BlockOp, priority: u16, weight: u64) -> ResolvedBlockServiceClass {
    ResolvedBlockServiceClass {
        class: [id; 32],
        operations: vec![operation],
        priority,
        weight,
    }
}

fn rule(discipline: BlockServiceDiscipline) -> ResolvedBlockServiceRule {
    ResolvedBlockServiceRule {
        contributor: [1; 32],
        bytes_per_second: 1_000_000_000,
        iops: Some(1_000_000_000),
        queue_depth: 8,
        discipline,
        classes: vec![
            class(1, BlockOp::Read, 1, 2),
            class(2, BlockOp::Write, 0, 1),
        ],
        rebuild_shares_service: true,
    }
}

fn job(sequence: u64, operation: BlockOp, bytes: u64) -> BlockServiceJob {
    BlockServiceJob {
        sequence,
        operation,
        bytes,
        admitted_nanos: 0,
    }
}

#[test]
fn cumulative_busy_epoch_has_no_per_request_rounding_drift() {
    let mut state = BlockServiceState::default();
    let mut service = rule(BlockServiceDiscipline::Fifo);
    service.bytes_per_second = 3;
    service.iops = None;
    state
        .admit(job(1, BlockOp::Read, 1), &[service.clone()])
        .unwrap_or_else(|error| panic!("first job should admit: {error}"));
    state
        .admit(job(2, BlockOp::Read, 1), &[service.clone()])
        .unwrap_or_else(|error| panic!("second job should admit: {error}"));
    state
        .admit(job(3, BlockOp::Read, 1), &[service])
        .unwrap_or_else(|error| panic!("third job should admit: {error}"));

    assert_eq!(state.next_completion_nanos(), Some(333_333_334));
    assert_eq!(state.advance_to(333_333_334).unwrap_or_default().len(), 1);
    assert_eq!(state.next_completion_nanos(), Some(666_666_667));
    assert_eq!(state.advance_to(1_000_000_000).unwrap_or_default().len(), 2);
}

#[test]
fn strict_priority_reorders_only_requests_waiting_behind_active_work() {
    let mut state = BlockServiceState::default();
    let service = rule(BlockServiceDiscipline::StrictPriority);
    state
        .admit(job(1, BlockOp::Read, 10), std::slice::from_ref(&service))
        .unwrap_or_else(|error| panic!("active read should admit: {error}"));
    state
        .admit(job(2, BlockOp::Read, 1), std::slice::from_ref(&service))
        .unwrap_or_else(|error| panic!("queued read should admit: {error}"));
    state
        .admit(job(3, BlockOp::Write, 1), &[service])
        .unwrap_or_else(|error| panic!("queued write should admit: {error}"));

    let first = state.advance_to(10).unwrap_or_default();
    assert_eq!(first[0].sequence, 1);
    let second = state.advance_to(11).unwrap_or_default();
    assert_eq!(second[0].sequence, 3);
    let third = state.advance_to(12).unwrap_or_default();
    assert_eq!(third[0].sequence, 2);
}

#[test]
fn weighted_round_robin_uses_canonical_class_weights() {
    let mut state = BlockServiceState::default();
    let service = rule(BlockServiceDiscipline::WeightedRoundRobin);
    state
        .admit(job(0, BlockOp::Write, 1), std::slice::from_ref(&service))
        .unwrap_or_else(|error| panic!("active seed should admit: {error}"));
    for (sequence, operation) in [
        (1, BlockOp::Read),
        (2, BlockOp::Write),
        (3, BlockOp::Read),
        (4, BlockOp::Write),
    ] {
        state
            .admit(job(sequence, operation, 1), std::slice::from_ref(&service))
            .unwrap_or_else(|error| panic!("queued job should admit: {error}"));
    }
    let completed = state.advance_to(10).unwrap_or_default();
    assert_eq!(
        completed
            .iter()
            .map(|completion| completion.sequence)
            .collect::<Vec<_>>(),
        vec![0, 1, 3, 2, 4]
    );
}

#[test]
fn admission_is_atomic_across_contributors() {
    let mut state = BlockServiceState::default();
    let first = rule(BlockServiceDiscipline::Fifo);
    let mut full = first.clone();
    full.contributor = [2; 32];
    full.queue_depth = 1;
    state
        .admit(job(1, BlockOp::Read, 1), &[first.clone(), full.clone()])
        .unwrap_or_else(|error| panic!("first job should admit: {error}"));
    let before = state.clone();
    assert!(
        state
            .admit(job(2, BlockOp::Read, 1), &[first, full])
            .is_err()
    );
    assert_eq!(state, before);
}
