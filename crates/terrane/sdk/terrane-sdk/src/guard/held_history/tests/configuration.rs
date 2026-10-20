//! Checks caller-selected Recorded history through genuine current and held factories.

use super::fs::ReadFs;
use super::support::{Fixture, REFERENCE, TestResult};
use crate::bucket::FileBucket;
use crate::bucket::held::SingleHeld;
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::ref_advance::tests::{Validator, token};
use crate::store::TokioClock;
use terrane_format::auth::Verb;
use terrane_format::gc::publication::evidence::ViewInterpretationMode;
use terrane_format::identity::Digest;
use terrane_format::properties::semantics::{
    RecordedContext,
    associations::{RecordedAssociation, RecordedAssociations},
};

type Caller = Guard<FileBucket<ReadFs, TokioClock, Validator>, TokioClock>;
const LATER: &str = "held-owner-history-caller-input";

// Only independently chosen ordinary associations change. Protected Original
// callbacks and opaque contexts remain those of the actual production factory.
fn caller(fixture: &Fixture, rows: Vec<RecordedAssociation>) -> TestResult<Caller> {
    let source = fixture.guard();
    let mut guard = Guard::new_with_recorded_views(
        source.store().clone(),
        TokioClock,
        source.keys().to_vec(),
        source.config().clone(),
        RecordedAssociations::new(rows)?,
    );
    guard.configured_current = source.configured_current;
    *guard
        .original_verifier
        .write()
        .map_err(|_| "caller verifier lock poisoned")? = source
        .original_verifier
        .read()
        .map_err(|_| "source verifier lock poisoned")?
        .clone();
    *guard
        .original_baselines
        .write()
        .map_err(|_| "caller baseline lock poisoned")? = source
        .original_baselines
        .read()
        .map_err(|_| "source baseline lock poisoned")?
        .clone();
    *guard
        .original_commits
        .write()
        .map_err(|_| "caller commit lock poisoned")? = source
        .original_commits
        .read()
        .map_err(|_| "source commit lock poisoned")?
        .clone();
    Ok(guard)
}

fn association(view: Digest, root: Digest) -> TestResult<RecordedAssociation> {
    Ok(RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(3, 3, &[LATER])?,
    ))
}

/// Preserves independent historical rows and current configuration across real factories.
///
/// # Errors
/// Preserves genuine fixture reads, association setup, native authorization and ledger errors.
///
/// # Panics
/// Panics when a native factory substitutes historical inputs or accepts missing mappings.
pub(super) async fn check(fixture: &Fixture) -> TestResult {
    let base_root = fixture
        .guard()
        .verified_tree(fixture.base.commit)
        .await?
        .evidence
        .root;
    let head_root = fixture
        .guard()
        .verified_tree(fixture.head.commit)
        .await?
        .evidence
        .root;
    let rows = vec![
        association(fixture.base.commit, base_root)?,
        association(fixture.head.commit, head_root)?,
    ];
    let guard = caller(fixture, rows)?;
    let current = guard.configured_current;
    assert_eq!(current, fixture.guard().configured_current);
    assert_eq!(
        current,
        crate::guard::history::completion::InterpretationSelection::Legacy
    );
    assert!(
        guard
            .original_verifier
            .read()
            .map_err(|_| "caller verifier lock poisoned")?
            .is_some()
    );

    // No holder or resolver is attached: this must exercise ordinary-current
    // native dispatch with the independent caller's full history configuration.
    let authorized = guard
        .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
        .await?;
    assert_eq!(authorized.record(), Some(&fixture.head));
    assert_eq!(guard.configured_current, current);

    {
        let holder = SingleHeld::acquire_read_only(guard.store()).await?;
        let held = holder.source();
        let identity = held.identity_proof();
        let actual = guard.held_guard(holder.source(), TokioClock)?;
        let authority = guard.configured_original_authority()?;
        let consumed = ConsumedResolver::new(&actual, &authority)?;
        let observation = HistoryObservation::held(&identity).tracked(&consumed);
        let authorized = actual
            .authorize_observed(REFERENCE, &token(), Verb::Read, &[], "sdk", observation)
            .await?;
        assert_eq!(authorized.record(), Some(&fixture.head));
        let completed = consumed.observed_completed_view_contexts_for_tests()?;
        let ledger = consumed.finish()?;
        assert_eq!(ledger.view_interpretations.as_ref(), Some(&completed));
        assert_eq!(completed.len(), 2);
        for (view, root) in [
            (fixture.base.commit, base_root),
            (fixture.head.commit, head_root),
        ] {
            let row = completed
                .iter()
                .find(|row| row.view == view)
                .ok_or("caller view context absent")?;
            assert_eq!(row.original_root, root);
            assert_eq!(row.mode, ViewInterpretationMode::Recorded);
            assert_eq!(row.registries.property_revision, 3);
            assert_eq!(row.registries.later_properties, [LATER]);
            assert_eq!(row.registries.attribute_revision, 1);
            let (selection, expected) = guard.selected_view_context_for_tests(view, root)?;
            let terrane_format::properties::selected::Selection::Recorded(context) = selection
            else {
                panic!("caller selected a non-Recorded interpretation");
            };
            assert_eq!(context.revision(), 3);
            assert_eq!(context.current_revision(), 3);
            assert_eq!(row.registries, expected);
        }
        assert_eq!(actual.configured_current, current);
    }

    // Both controls keep the actual head mapping valid. Only a full walk using
    // the caller's ancestor inputs can detect the missing or wrong original root;
    // the enclosing head-only current ACL decision cannot distinguish them.
    assert_ne!(base_root, head_root);
    for (case, rows) in [
        (
            "missing ancestor",
            vec![association(fixture.head.commit, head_root)?],
        ),
        (
            "wrong ancestor original root",
            vec![
                association(fixture.base.commit, head_root)?,
                association(fixture.head.commit, head_root)?,
            ],
        ),
    ] {
        let refused = caller(fixture, rows)?;
        assert!(
            refused
                .authorize(REFERENCE, &token(), Verb::Read, &[], "sdk")
                .await
                .is_err(),
            "ordinary current history accepted {case}"
        );
        {
            let holder = SingleHeld::acquire_read_only(refused.store()).await?;
            let held = holder.source();
            let identity = held.identity_proof();
            let actual = refused.held_guard(holder.source(), TokioClock)?;
            let authority = refused.configured_original_authority()?;
            let consumed = ConsumedResolver::new(&actual, &authority)?;
            assert!(
                actual
                    .authorize_observed(
                        REFERENCE,
                        &token(),
                        Verb::Read,
                        &[],
                        "sdk",
                        HistoryObservation::held(&identity).tracked(&consumed)
                    )
                    .await
                    .is_err(),
                "held owner history accepted {case}"
            );
            assert!(
                consumed
                    .observed_completed_view_contexts_for_tests()?
                    .is_empty(),
                "refused {case} promoted completed history"
            );
            assert_eq!(actual.configured_current, current);
        }
    }
    assert_eq!(guard.configured_current, current);
    Ok(())
}
