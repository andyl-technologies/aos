//! Checks current observation binding with genuine native admission and holders.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::ref_advance::tests::{fixture, request_file, token};
use crate::store::TokioClock;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const SOURCE: &str = "refs/heads/_/main";

#[tokio::test]
async fn ordinary_current_binding_preserves_requested_target_and_actual_scope() -> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let head = repository
        .advance(&mut writer, request_file(Vec::new(), b"current scope"))
        .await?;
    let original = repository.guard().original_commit(&head.commit)?;

    let holder = SingleHeld::acquire_read_only(repository.store()).await?;
    let source = holder.source();
    let identity = source.identity_proof();
    let guard = repository.guard().held_guard(holder.source(), TokioClock)?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let foreign_resolver = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let separately_borrowed_identity = source.identity_proof();

    for ordinary in [
        HistoryObservation::default(),
        HistoryObservation::default().requested_target(),
    ] {
        assert!(ordinary.is_ordinary_unheld());
        let current = ordinary.current_held_from_ordinary(&identity, &consumed)?;
        let expected = if ordinary.requested_target {
            HistoryObservation::held(&identity)
                .tracked(&consumed)
                .requested_target()
        } else {
            HistoryObservation::held(&identity).tracked(&consumed)
        };

        current.same_current_scope(expected)?;
        expected.same_current_scope(current)?;
        assert_eq!(current.requested_target, ordinary.requested_target);
        assert!(!current.is_ordinary_unheld());
        assert!(
            current
                .current_held_from_ordinary(&identity, &consumed)
                .is_err()
        );
        assert!(current.same_current_scope(ordinary).is_err());
        assert!(ordinary.same_current_scope(current).is_err());

        // Matching immutable identity data does not substitute the actual
        // borrowed holder proof or the operation-local resolver allocation.
        let foreign_holder = HistoryObservation {
            held: Some(&separately_borrowed_identity),
            ..current
        };
        let foreign_trace = HistoryObservation {
            consumed: Some(&foreign_resolver),
            ..current
        };
        let changed_interpretation = HistoryObservation {
            requested_target: !current.requested_target,
            ..current
        };
        for foreign in [foreign_holder, foreign_trace, changed_interpretation] {
            assert!(current.same_current_scope(foreign).is_err());
            assert!(foreign.same_current_scope(current).is_err());
        }
    }

    // Binding is ordinary data, never a fabricated history completion.
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn current_scope_refuses_candidate_layer_and_partially_held_observations() -> TestResult {
    let repository = fixture().await;
    let mut writer = repository.begin(SOURCE, &token(), "sdk").await?;
    let head = repository
        .advance(&mut writer, request_file(Vec::new(), b"scope refusal"))
        .await?;
    let admitted = repository
        .guard()
        .admit_policy(SOURCE, None, &token(), "sdk")
        .await?;
    let candidate = repository.guard().capture_candidate_inputs(&admitted)?;
    let original = repository.guard().original_commit(&head.commit)?;

    let holder = SingleHeld::acquire_read_only(repository.store()).await?;
    let source = holder.source();
    let identity = source.identity_proof();
    let guard = repository.guard().held_guard(holder.source(), TokioClock)?;
    let consumed = ConsumedResolver::new(&guard, original.baseline().authority())?;
    let current = HistoryObservation::default().current_held_from_ordinary(&identity, &consumed)?;

    for nonordinary in [
        HistoryObservation::held(&identity),
        HistoryObservation::default().tracked(&consumed),
        HistoryObservation::default().candidate(&candidate),
        HistoryObservation::default().overlay_layer(head.commit, admitted.commit.commit().tree),
    ] {
        assert!(!nonordinary.is_ordinary_unheld());
        assert!(
            nonordinary
                .current_held_from_ordinary(&identity, &consumed)
                .is_err()
        );
        assert!(current.same_current_scope(nonordinary).is_err());
        assert!(nonordinary.same_current_scope(current).is_err());
    }

    for noncurrent in [
        current.candidate(&candidate),
        current.overlay_layer(head.commit, admitted.commit.commit().tree),
    ] {
        assert!(noncurrent.same_current_scope(noncurrent).is_err());
        assert!(current.same_current_scope(noncurrent).is_err());
        assert!(noncurrent.same_current_scope(current).is_err());
    }
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    Ok(())
}
