//! Real ancestry Issue read sharing and independent fresh closure refusal.

use super::*;

fn assert_no_checkpoint(repository: &CampaignRepository, head: ContentId) {
    assert!(
        !repository
            .validated_heads
            .lock()
            .expect("validated head cache")
            .contains_key(&head)
    );
}

#[test]
fn ancestry_merkle_reads_preserve_sixteen_admissions_and_complete_paging() {
    // Each complete scan issues the original two-proposal Boolean vector.
    let corpus = corpus_with_scan_limit(8, 8);
    assert_eq!(corpus.steps.len(), 8);
    for step in &corpus.steps {
        let validated = corpus
            .repository
            .read_planner_step_with_request(*step)
            .expect("authenticated planner Issue");
        assert!(matches!(
            validated.step.disposition(),
            PlannerDisposition::Issue { issued_proposals, .. } if issued_proposals.len() == 2
        ));
        assert_eq!(validated.step.accounting().attempts, 2);
    }
    corpus.backend.reset();
    let disabled = corpus.cold();
    let mut planner = PlannerValidationContext::default();
    let mut uncached = MerkleValidationReads::disabled();
    let original = disabled
        .load_validation_checkpoint_with_contexts(corpus.head, &mut planner, &mut uncached)
        .expect("original complete validation");
    let original_reads = corpus.backend.total();
    let original_positions = positions(&disabled, corpus.head);
    let original_queue = queue(&disabled);
    assert_eq!(original_queue.len(), 16);
    assert!(!original_positions.is_empty());

    corpus.backend.reset();
    let enabled = corpus.cold();
    let mut retained = MerkleValidationReads::default();
    let shared = enabled
        .load_validation_checkpoint_with_contexts(corpus.head, &mut planner, &mut retained)
        .expect("shared complete validation");
    let shared_reads = corpus.backend.total();

    assert_eq!(shared.ancestry_depth, original.ancestry_depth);
    assert_eq!(shared.closure_objects, original.closure_objects);
    assert_eq!(shared.genesis, original.genesis);
    assert_eq!(shared.lifecycle.visible, original.lifecycle.visible);
    assert_eq!(positions(&enabled, corpus.head), original_positions);
    assert_eq!(queue(&enabled), original_queue);
    assert_eq!(
        enabled
            .head("planner-validation-reuse")
            .expect("head")
            .snapshot_id()
            .content_id(),
        corpus.head
    );
    assert_eq!(retained.retained_usage(), (0, 0));
    assert_eq!(planner.retained_usage(), (0, 0));
    eprintln!(
        "ancestry-merkle-reads: original={original_reads} shared={shared_reads} attempts={} closure_objects={}",
        original_queue.len(),
        shared.closure_objects,
    );
    assert!(shared_reads < original_reads);
}

#[test]
fn fresh_closure_refuses_missing_or_corrupt_nodes_retained_by_ancestry() {
    for fault in [ReadFault::Missing, ReadFault::Corrupt] {
        let corpus = corpus(2);
        let cold = corpus.cold();
        let mut choices = ChoiceValidationCache::default();
        let mut planner = PlannerValidationContext::default();
        let mut nodes = MerkleValidationReads::default();
        cold.validate_snapshot_ancestry_with_validation_reads(
            corpus.head,
            &mut choices,
            MAX_SNAPSHOT_ANCESTRY,
            Some(&mut planner),
            Some(&mut nodes),
        )
        .expect("genuine ancestry validation");
        let target = nodes.retained_id().expect("authenticated ancestry node");
        let ancestry_reads = corpus.backend.count(target);
        assert!(ancestry_reads > 0);

        // Repeat the same complete loader from an empty read counter. Its
        // ancestry may consume exactly the observed successful reads, but
        // the next mandatory fresh fetch must refuse the changed object.
        corpus.backend.reset();
        corpus.backend.fail_after(target, ancestry_reads, fault);
        let complete = corpus.cold();
        assert!(
            complete
                .load_validation_checkpoint_with_contexts(corpus.head, &mut planner, &mut nodes)
                .is_err()
        );
        assert_eq!(corpus.backend.count(target), ancestry_reads + 1);
        assert_no_checkpoint(&complete, corpus.head);
        assert_eq!(nodes.retained_usage(), (0, 0));
        assert_eq!(planner.retained_usage(), (0, 0));
    }
}

#[test]
fn initial_merkle_read_fault_never_promotes_or_retains_a_failed_validation() {
    let corpus = corpus(2);
    let cold = corpus.cold();
    let root = cold
        .read_snapshot(corpus.head)
        .expect("snapshot")
        .snapshot
        .roots()
        .exploration;
    for fault in [ReadFault::Missing, ReadFault::Corrupt] {
        for enabled in [false, true] {
            corpus.backend.reset();
            corpus.backend.fail_after(root, 0, fault);
            let repository = corpus.cold();
            let mut planner = PlannerValidationContext::default();
            let mut nodes = if enabled {
                MerkleValidationReads::default()
            } else {
                MerkleValidationReads::disabled()
            };
            assert!(
                repository
                    .load_validation_checkpoint_with_contexts(corpus.head, &mut planner, &mut nodes)
                    .is_err()
            );
            assert_no_checkpoint(&repository, corpus.head);
            assert_eq!(nodes.retained_usage(), (0, 0));
            assert_eq!(planner.retained_usage(), (0, 0));
        }
    }
}
