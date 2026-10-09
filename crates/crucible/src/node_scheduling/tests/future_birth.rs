//! Original future-publication custody across a split exact cut and restoration.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn original_evaluation_transfers_future_birth_once_before_publication_cut() {
    let (mut scheduler, endpoint) = routed_fixture();
    let start = position(10, 0, Phase::BoundaryControl);
    let cut = position(10, 1, Phase::BoundaryControl);
    scheduler.owners.get_mut(&id("owner/Z")).unwrap().cursor = start;
    scheduler.owners.get_mut(&id("owner/A")).unwrap().cursor = start;
    let grant = scheduler
        .admit_boundary_settlement(&id("Z"), id("run/birth"), cut)
        .unwrap();
    let mut observation = publication_observation(&scheduler, &endpoint, b"future");
    observation.reached = cut;
    observation.closed_prefix = cut;
    let receipt = SchedulingReceipt::new(
        scheduler.activation.clone(),
        id("Z"),
        id("run/birth"),
        ProgressEvidence::Exact {
            reached: cut,
            stop: StopReason::HorizonPark,
        },
        vec![id("output/1")],
        Some(observation),
    );
    let commit = scheduler.accept_receipt(receipt).unwrap();
    assert_eq!(grant.limit(), cut);
    assert_eq!(commit.retained_outputs(), &[id("output/1")]);
    let original = scheduler.pending.values().next().unwrap().clone();
    assert_eq!(original.evaluation, Some(position(10, 0, Phase::Reaction)));
    assert_eq!(original.publication, position(10, 1, Phase::Publication));
    assert!(original.publication > cut);

    // No reevaluation is needed: the first original operation already transferred
    // the immutable payload, FIFO identity, and authentic future publication birth.
    let snapshot = scheduler.snapshot(cut, U64::new(1)).unwrap();
    super::super::snapshot_impl::validate_structure(&snapshot).unwrap();
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    let decoded = serde_json::from_slice(&encoded).unwrap();
    let (mut restored, _) = routed_fixture();
    restored.load_snapshot(decoded).unwrap();
    assert_eq!(restored.pending, scheduler.pending);
    assert_eq!(restored.payloads, scheduler.payloads);
    assert_eq!(restored.sequences, scheduler.sequences);
    let batch = restored
        .prepare_input_batch(
            &id("A"),
            id("stage/future"),
            id("batch/future"),
            position(12, 0, Phase::BoundaryControl),
        )
        .unwrap();
    assert_eq!(batch.deliveries(), &[original]);
    assert_eq!(batch.payloads()[0].bytes, b"future");
    assert_eq!(restored.pending.len(), 1);
}
