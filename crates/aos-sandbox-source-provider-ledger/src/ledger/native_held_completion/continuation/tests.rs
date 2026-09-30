//! UNRUN finite-predicate, expensive-family, dependency and counter vectors.
//!
//! These pure DATA tests do not exercise a writer, signer, dispatch or custody.

use super::*;
use transition::DispositionShape;

fn successor(facts: CheckpointFacts, step: Step) -> CheckpointFacts {
    transition::checkpoint_successors(facts)
        .into_iter()
        .find_map(|(kind, after)| (kind == step).then_some(after))
        .unwrap()
}

fn permits(facts: CheckpointFacts, step: Step) -> bool {
    transition::checkpoint_successors(facts)
        .iter()
        .any(|(kind, _)| *kind == step)
}

fn complete() -> CheckpointFacts {
    let issued = successor(requested_facts(), Step::ChallengeIssued);
    let prepared = successor(issued, Step::StoragePrepared);
    let spent = successor(prepared, Step::ChallengeSpent);
    successor(spent, Step::CompletionCommitted)
}

#[test]
fn shared_case_a_replaces_only_unescaped_relay_after_first_recovery() {
    let held = successor(complete(), Step::HeldPrepared);
    let stored = successor(held, Step::HeldStored);
    let disposition = successor(stored, Step::RootDispositionPrepared);
    let recovery = successor(disposition, Step::RootRecoveryRecorded);

    assert_eq!(recovery.prepared, Some(Kind::ProviderRelay));
    assert!(!permits(recovery, Step::RelayStored));
    assert!(transition::permits_preparation_rotation(
        &recovery,
        Step::StorageRecoveryPrepared,
        (7, 7),
    ));
    let rotated = successor(recovery, Step::StorageRecoveryPrepared);
    assert_eq!(rotated.prepared, Some(Kind::ProviderStorageRecoveryQuery));
    assert!(!rotated.has(Kind::ProviderRelay));

    let mut missing_root = recovery;
    missing_root.stored &= !((1 << Kind::RootAccepted as u8) | (1 << Kind::RootClosed as u8));
    assert!(!permits(missing_root, Step::StorageRecoveryPrepared));
    assert!(!permits(disposition, Step::StorageRecoveryPrepared));
}

#[test]
fn shared_case_b_clears_unescaped_held_without_manufacturing_artifact() {
    let held = successor(complete(), Step::HeldPrepared);
    let recovery = successor(held, Step::RootRecoveryRecorded);

    assert_eq!(recovery.phase, 7);
    assert_eq!(recovery.prepared, None);
    assert_eq!(recovery.disposition, Some(DispositionShape::RootOnlyPreparedClosed));
    assert!(recovery.completed);
    assert!(!recovery.artifact_claim);
    assert!(!recovery.has(Kind::ProviderHeld));
    assert!(!permits(recovery, Step::HeldStored));
    assert!(!permits(recovery, Step::RootRecoveryRecorded));
}

#[test]
fn unescaped_settled_rotation_requires_real_recovery_and_child() {
    let held = successor(complete(), Step::HeldPrepared);
    let stored = successor(held, Step::HeldStored);
    let disposition = successor(stored, Step::RootDispositionPrepared);
    let relay = successor(disposition, Step::RelayStored);
    let settled = successor(relay, Step::StorageSettlementRecorded);
    let prepared = successor(settled, Step::ProviderSettledPrepared);
    let recovery = successor(prepared, Step::RootRecoveryRecorded);

    assert_eq!(recovery.prepared, Some(Kind::ProviderSettled));
    assert!(!permits(recovery, Step::ProviderSettledStored));
    assert!(!permits(recovery, Step::StorageRecoveryPrepared));
    assert!(permits(recovery, Step::ProviderRecoveryPrepared));

    let mut no_child = recovery;
    no_child.settlement = false;
    assert!(!permits(no_child, Step::ProviderRecoveryPrepared));
    let rotated = successor(recovery, Step::ProviderRecoveryPrepared);
    assert_eq!(rotated.prepared, Some(Kind::ProviderRecoveryState));
    assert!(!rotated.has(Kind::ProviderSettled));
}

#[test]
fn complete_without_hot_artifact_must_recover_before_terminal() {
    let disposition = successor(complete(), Step::RootDispositionPrepared);
    let relay = successor(disposition, Step::RelayStored);
    let settled = successor(relay, Step::StorageSettlementRecorded);
    let prepared = successor(settled, Step::ProviderSettledPrepared);
    let hot = successor(prepared, Step::ProviderSettledStored);

    assert!(!hot.artifact_claim);
    assert!(!permits(hot, Step::RootTerminalRecorded));
    let too_late = successor(hot, Step::RootRecoveryRecorded);
    assert!(!permits(too_late, Step::ProviderRecoveryPrepared));

    // Before zero-artifact hot7 escapes, actual recovery10 can bind Complete A.
    let recovery = successor(prepared, Step::RootRecoveryRecorded);
    let recovery = successor(recovery, Step::ProviderRecoveryPrepared);
    let recovery = successor(recovery, Step::ProviderRecoveryStored);
    assert!(recovery.artifact_claim);
    assert!(permits(recovery, Step::RootTerminalRecorded));
}

#[test]
fn first_recovery_metadata_and_two_terminal_shapes_remain_distinct() {
    let held = successor(complete(), Step::HeldPrepared);
    let stored = successor(held, Step::HeldStored);
    let disposition = successor(stored, Step::RootDispositionPrepared);
    let relay = successor(disposition, Step::RelayStored);
    let settled = successor(relay, Step::StorageSettlementRecorded);
    let prepared = successor(settled, Step::ProviderSettledPrepared);
    let hot = successor(prepared, Step::ProviderSettledStored);
    let recovery = successor(hot, Step::RootRecoveryRecorded);
    let query = successor(recovery, Step::StorageRecoveryPrepared);
    let query = successor(query, Step::StorageRecoveryQueryStored);
    let child = successor(query, Step::StorageRecoveryRecorded);

    assert_eq!(child.phase, 9);
    assert!(permits(child, Step::ProviderRecoveryPrepared));
    assert!(!permits(child, Step::RootRecoveryRecorded));
    let terminals: Vec<_> = transition::checkpoint_successors(child)
        .into_iter()
        .filter(|(kind, _)| *kind == Step::RootTerminalRecorded)
        .collect();
    assert_eq!(terminals.len(), 2);
    assert!(terminals.iter().any(|(_, after)| !after.terminal_recovery));
    assert!(terminals.iter().any(|(_, after)| after.terminal_recovery));
}

#[test]
fn finite_projection_covers_all_eighteen_real_checkpoint_families() {
    fn visit(
        facts: CheckpointFacts,
        depth: usize,
        steps: &mut Vec<Step>,
        maximum: &mut usize,
    ) {
        *maximum = (*maximum).max(depth);
        assert!(depth <= 18, "append-once projection must not loop");
        for (step, next) in transition::checkpoint_successors(facts) {
            if !steps.contains(&step) {
                steps.push(step);
            }
            visit(next, depth + 1, steps, maximum);
        }
    }

    let mut steps = Vec::new();
    let mut maximum = 0;
    visit(requested_facts(), 0, &mut steps, &mut maximum);

    assert_eq!(steps.len(), 18);
    assert_eq!(maximum, 18);
    assert_eq!(maximum + 1 + 1, MAXIMUM_APPENDS); // Requested plus final cleanup.
    assert_eq!(transition::checkpoint_owner_indices(Step::CompletionCommitted, Outer::Prepared), &[0, 1, 2, 3, 4, 5]);
    assert_eq!(transition::checkpoint_owner_indices(Step::RootTerminalRecorded, Outer::Prepared), &[1, 2, 3, 4, 5]);
    assert_eq!(transition::checkpoint_owner_indices(Step::RootTerminalRecorded, Outer::Active), &[5]);
}

#[test]
fn codec_bounds_and_release_cleanup_families_are_not_native_only_labels() {
    assert_eq!(owner_value_bound(96), 2_098_176);
    assert_eq!(owner_value_bound(99), 487_228);
    assert_eq!(owner_value_bound(63), 9_488);
    assert_eq!(owner_value_bound(49), 696);
    assert_eq!(owner_value_bound(103), 9_488);
    assert_eq!(owner_value_bound(40), MAXIMUM_NATIVE_HELD_RECORD_BYTES_V1);
    assert_eq!(owner_value_bound(95), 131_720);
    assert_eq!(SOURCE_PRE_REQUESTED_COLD_ARCHIVE_FIXED_BYTES_V1, [1317, 2602, 3314]);
    assert_eq!(lifecycle::cleanup_key_widths(Lifecycle::ReleaseCompleted, Some(completion::HeldReleaseMutationShape::OrdinaryComplete)), Some(&[49, 63, 95, 96, 99, 103][..]));
    assert_eq!(lifecycle::cleanup_key_widths(Lifecycle::ReleaseStatusCompleted, Some(completion::HeldReleaseMutationShape::StatusOnly)), Some(&[63, 96, 103][..]));
    assert_eq!(lifecycle::cleanup_key_widths(Lifecycle::ReleasedArtifactsCompacted, None), Some(&[95, 99][..]));
    assert_eq!(lifecycle::cleanup_key_widths(Lifecycle::ReleaseAdmitted, None), None);
}

#[test]
fn retired_unleased_cleanup_does_not_invent_release_futures() {
    let mut facts = requested_facts();
    facts.phase = 10;
    facts.outer = Outer::CleanupRequired;
    let keys = std::array::from_fn(|index| vec![index as u8 + 1; 40]);

    assert!(cleanup_edges(&Records::new(), &keys, facts).unwrap().is_empty());
    let mut alternatives = Vec::new();
    enumerate(&Records::new(), &keys, facts, &mut Vec::new(), &mut alternatives).unwrap();
    assert_eq!(alternatives.len(), 1);
    assert!(alternatives[0].edges().is_empty());
}

#[test]
fn release_cleanup_requires_real_completed_status_and_releasing_predecessors() {
    use completion::HeldReleaseMutationShape as Shape;
    use ProviderAcquisitionStateV1::{Faulted, Releasing};

    assert!(release_cleanup_predecessor_missing(Some(Shape::ReceiptOnlyRecovery), Releasing, false));
    assert!(!release_cleanup_predecessor_missing(Some(Shape::ReceiptOnlyRecovery), Releasing, true));
    assert!(release_cleanup_predecessor_missing(Some(Shape::ReceiptOnlyRecovery), Faulted, true));
    assert!(release_cleanup_predecessor_missing(Some(Shape::OrdinaryComplete), Faulted, false));
    assert!(!release_cleanup_predecessor_missing(Some(Shape::OrdinaryComplete), Releasing, false));
    assert!(!release_cleanup_predecessor_missing(Some(Shape::StatusOnly), Faulted, false));
}

#[test]
fn before_dependencies_are_exact_and_independent_cuts_are_not_relabelled() {
    let key = vec![1; 40];
    let mut independent = bound(key.clone(), 20);
    independent.dependency = OriginalSourceBeforeDependencyV5::IndependentlyFundedCut;
    let mut alternative = OriginalSourceContinuationAlternativeV5 {
        edges: vec![
            edge(OriginalSourceContinuationKindV5::FirstRequested, vec![bound(key.clone(), 20)], false, false),
            edge(OriginalSourceContinuationKindV5::Held(Step::ChallengeIssued), vec![bound(key.clone(), 20)], false, false),
            edge(OriginalSourceContinuationKindV5::Cleanup(Lifecycle::OriginalCustodyMarked), vec![independent], true, false),
        ],
        poison: true,
    };
    attach_dependencies(&mut alternative);

    assert_eq!(alternative.edges[0].values[0].dependency, OriginalSourceBeforeDependencyV5::ActualGraph);
    assert_eq!(alternative.edges[1].values[0].dependency, OriginalSourceBeforeDependencyV5::PreviousOutput(0));
    assert_eq!(alternative.edges[2].values[0].dependency, OriginalSourceBeforeDependencyV5::IndependentlyFundedCut);
}

#[test]
fn representable_maximum_counters_are_allowed_but_overflow_is_refused() {
    assert!(checked_counter(u64::MAX - 1, 1).is_ok());
    assert!(checked_counter(u64::MAX, 0).is_ok());
    assert!(checked_counter(u64::MAX, 1).is_err());
}
