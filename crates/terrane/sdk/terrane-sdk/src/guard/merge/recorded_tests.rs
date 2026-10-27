//! Checks ordered native merge dispatch using genuinely published signed inputs.
//!
//! Full native verification owns signature, Original and entry-origin evidence;
//! ordinary installed selections neither manufacture history nor permit admission.

use super::{MergeOperation, PreparedMerge};
use crate::guard::view_selection::historical_tests::{
    Location, Native, REFERENCE, TestResult, graft_request, selected,
};
use crate::guard::{HistoryObservation, ViewSelection};
use crate::store::{LocalFs, RefStore, TokioLocalFs};
use std::collections::BTreeSet;
use terrane_format::identity::Digest;
use terrane_format::properties::selected::Selection;
use terrane_format::properties::semantics::RecordedContext;
use terrane_format::refs::{MergePolicy, RefRecord};

const SOURCE: &str = "refs/heads/_/merge-source";

struct Inputs {
    location: Location,
    repository: Native,
    records: [RefRecord; 3],
    roots: [Digest; 3],
    rows: Vec<ViewSelection>,
}

/// Prints an unchanged setup failure only under explicit diagnostic opt-in.
fn trace_setup_failure(error: &impl core::fmt::Debug, phase: &str) {
    if std::env::var_os("TERRANE_RECORDED_MERGE_PHASE_TRACE").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        eprintln!("recorded merge setup phase={phase}: {error:?}");
    }
}

/// Publishes each differing historical profile under its actual selected authoring inputs.
async fn inputs() -> TestResult<Inputs> {
    let location = Location::open()
        .await
        .inspect_err(|error| trace_setup_failure(error, "Legacy baseline publication"))?;
    let first = location
        .reopen(2, &[], vec![location.baseline_selection()?])
        .await?;
    let mut session = first
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let base = first
        .commit_request(
            &mut session,
            crate::ref_advance::tests::request(vec![location.baseline.commit]),
        )
        .await
        .inspect_err(|error| trace_setup_failure(error, "Recorded2 base publication"))?;
    let base_root = first
        .coordinator()
        .guard()
        .verified_tree(base.commit)
        .await?
        .commit
        .commit()
        .tree;
    let mut fork_request = crate::ref_advance::tests::request(Vec::new());
    fork_request.uploads.clear();
    let forked = first
        .fork(REFERENCE, SOURCE, fork_request)
        .await
        .inspect_err(|error| trace_setup_failure(error, "Recorded2 same-profile fork"))?;
    let fork_root = first
        .coordinator()
        .guard()
        .verified_tree(forked.commit)
        .await?
        .commit
        .commit()
        .tree;
    let mut rows = vec![
        location.baseline_selection()?,
        selected(base.commit, base_root, 2, &[])?,
        selected(forked.commit, fork_root, 2, &[])?,
    ];
    drop(session);
    drop(first);

    let second = location.reopen(3, &[], rows.clone()).await?;
    let mut session = second
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let ours = second
        .commit_request(
            &mut session,
            crate::ref_advance::tests::request_file(vec![base.commit], b"ours"),
        )
        .await
        .inspect_err(|error| trace_setup_failure(error, "Recorded3 ours publication"))?;
    let ours_root = second
        .coordinator()
        .guard()
        .verified_tree(ours.commit)
        .await?
        .commit
        .commit()
        .tree;
    rows.push(selected(ours.commit, ours_root, 3, &[])?);
    drop(session);
    drop(second);

    let third = location.reopen(1, &[], rows.clone()).await?;
    let mut session = third
        .begin(SOURCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let theirs = third
        .commit_request(
            &mut session,
            crate::ref_advance::tests::request_file(vec![forked.commit], b"theirs"),
        )
        .await
        .inspect_err(|error| trace_setup_failure(error, "Recorded1 theirs publication"))?;
    let theirs_root = third
        .coordinator()
        .guard()
        .verified_tree(theirs.commit)
        .await?
        .commit
        .commit()
        .tree;
    rows.push(selected(theirs.commit, theirs_root, 1, &[])?);
    drop(session);
    drop(third);
    let repository = location.reopen(3, &[], rows.clone()).await?;
    Ok(Inputs {
        location,
        repository,
        records: [base, ours, theirs],
        roots: [base_root, ours_root, theirs_root],
        rows,
    })
}

/// Executes the actual synchronous native phase after independent full signed histories.
async fn recompute(
    repository: &Native,
    records: &[RefRecord; 3],
    fold: bool,
) -> TestResult<PreparedMerge> {
    let guard = repository.coordinator().guard();
    let base = guard.verified_tree(records[0].commit).await?;
    let ours = guard.verified_tree(records[1].commit).await?;
    let theirs = guard.verified_tree(records[2].commit).await?;
    let ours_history = guard.verified_history(records[1].commit).await?;
    let theirs_history = guard.verified_history(records[2].commit).await?;
    let authorized = BTreeSet::new();
    Ok(guard.recompute_merge(
        [&base, &ours, &theirs],
        [&ours_history, &theirs_history],
        [records[1].commit, records[2].commit],
        &[MergePolicy::PreferTrusted, MergePolicy::KeepConflict],
        theirs.commit.commit().clone(),
        if fold {
            MergeOperation::Fold(&authorized)
        } else {
            MergeOperation::Merge
        },
    )?)
}

#[tokio::test]
async fn recorded_merge_input_configuration_requires_all_original_view_root_pairs() -> TestResult {
    let inputs = inputs().await?;
    let guard = inputs.repository.coordinator().guard();
    for (index, record) in inputs.records.iter().enumerate() {
        let verified = guard.verified_tree(record.commit).await?;
        assert_eq!(verified.commit.commit().tree, inputs.roots[index]);
        assert_eq!(
            guard
                .historical_evidence_semantics(&verified.evidence, HistoryObservation::default())?,
            Selection::Recorded(RecordedContext::new([2, 3, 1][index], 3, &[])?)
        );
        assert!(guard.original_commit(&record.commit).is_ok());
    }
    let merged = recompute(&inputs.repository, &inputs.records, false).await?;
    assert_eq!(
        merged.commit.parents,
        [inputs.records[1].commit, inputs.records[2].commit]
    );
    assert!(!merged.uploads.is_empty());
    let folded = recompute(&inputs.repository, &inputs.records, true).await?;
    assert_eq!(folded.commit.parents, merged.commit.parents);
    assert!(folded.excluded.contains(&b"file".to_vec()));

    for omitted in 0..3 {
        let absent = selected(
            inputs.records[omitted].commit,
            inputs.roots[omitted],
            [2, 3, 1][omitted],
            &[],
        )?;
        let rows = inputs
            .rows
            .iter()
            .filter(|row| *row != &absent)
            .cloned()
            .collect();
        let missing = inputs.location.reopen(3, &[], rows).await?;
        assert!(recompute(&missing, &inputs.records, false).await.is_err());
    }
    let mut wrong_root = inputs.rows.clone();
    let old_theirs = selected(inputs.records[2].commit, inputs.roots[2], 1, &[])?;
    wrong_root.retain(|row| row != &old_theirs);
    wrong_root.push(selected(inputs.records[2].commit, inputs.roots[1], 1, &[])?);
    let changed = inputs.location.reopen(3, &[], wrong_root).await?;
    assert!(recompute(&changed, &inputs.records, false).await.is_err());

    let path = inputs.location.original_path(inputs.records[2].commit);
    let saved = path.with_extension("held");
    TokioLocalFs.rename(&path, &saved).await?;
    let no_original = recompute(&inputs.repository, &inputs.records, false).await;
    TokioLocalFs.rename(&saved, &path).await?;
    assert!(no_original.is_err());
    recompute(&inputs.repository, &inputs.records, false).await?;
    assert_eq!(
        guard.store().ref_get(REFERENCE).await?,
        Some(inputs.records[1].clone())
    );
    assert_eq!(
        guard.store().ref_get(SOURCE).await?,
        Some(inputs.records[2].clone())
    );
    Ok(())
}

#[tokio::test]
async fn recorded_merge_occurrences_preserve_per_view_fences_and_refuse_domain_ambiguity()
-> TestResult {
    let location = Location::open().await?;
    let repository = location
        .reopen(1, &["index-roots"], vec![location.baseline_selection()?])
        .await?;
    let mut session = repository
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let ours = repository
        .commit_request(
            &mut session,
            graft_request(vec![location.baseline.commit], false)?,
        )
        .await?;
    let root = repository
        .coordinator()
        .guard()
        .verified_tree(ours.commit)
        .await?
        .commit
        .commit()
        .tree;
    let mut rows = vec![
        location.baseline_selection()?,
        selected(ours.commit, root, 1, &["index-roots"])?,
    ];
    drop(session);
    drop(repository);
    let current = location.reopen(3, &[], rows.clone()).await?;
    let mut source = current
        .begin(SOURCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let theirs = current
        .commit_request(&mut source, crate::ref_advance::tests::request(Vec::new()))
        .await?;
    let theirs_root = current
        .coordinator()
        .guard()
        .verified_tree(theirs.commit)
        .await?
        .commit
        .commit()
        .tree;
    rows.push(selected(theirs.commit, theirs_root, 3, &[])?);
    drop(source);
    drop(current);
    let current = location.reopen(3, &[], rows).await?;
    let records = [location.baseline.clone(), ours.clone(), theirs.clone()];
    recompute(&current, &records, false).await?;
    let guard = current.coordinator().guard();
    let verified = guard.verified_tree(ours.commit).await?;
    let semantics =
        guard.historical_evidence_semantics(&verified.evidence, HistoryObservation::default())?;
    assert_eq!(
        semantics,
        Selection::Recorded(RecordedContext::new(1, 3, &["index-roots"])?)
    );
    // Native publication requires every occurrence to match this backend's
    // storage domain. Preserve that earlier admission refusal rather than
    // claiming the candidate reached merge's shared-root ambiguity check.
    // The complementary core owning witness executes exact Ambiguous refusal
    // in both orders; the successful native call above owns real table dispatch.
    let mixed = location
        .reopen(
            1,
            &["index-roots"],
            vec![
                location.baseline_selection()?,
                selected(ours.commit, root, 1, &["index-roots"])?,
                selected(theirs.commit, theirs_root, 3, &[])?,
            ],
        )
        .await?;
    let mut session = mixed
        .begin(REFERENCE, &crate::ref_advance::tests::token(), "sdk")
        .await?;
    let error = mixed
        .commit_request(&mut session, graft_request(vec![ours.commit], true)?)
        .await
        .err()
        .ok_or("native admission accepted a foreign occurrence domain")?;
    let failure = match &error {
        crate::repository::Error::Advance(crate::ref_advance::AdvanceError::Store(failure))
        | crate::repository::Error::Store(failure) => failure,
        _ => return Err("mixed-domain candidate failed outside expected guard admission".into()),
    };
    assert_eq!(
        failure.kind(),
        &crate::store::StoreErrorKind::Denied {
            verb: "commit",
            pattern: REFERENCE.into()
        }
    );
    assert_eq!(
        mixed
            .coordinator()
            .guard()
            .store()
            .ref_get(REFERENCE)
            .await?,
        Some(ours)
    );
    assert_eq!(
        mixed.coordinator().guard().store().ref_get(SOURCE).await?,
        Some(theirs)
    );
    Ok(())
}

/// Checks the registered v3 tuple without deriving any selection from its bytes.
fn assert_recorded_context(bytes: &[u8], view: Digest, root: Digest, revision: u64) -> TestResult {
    let mut decoder = terrane_format::cbor::Decoder::new(bytes);
    assert_eq!(decoder.array(8)?, 8);
    assert_eq!(decoder.uint()?, 3);
    assert_eq!(decoder.bytes(32)?, view);
    assert_eq!(decoder.text(128)?, "public");
    decoder.skip_value(262144)?;
    assert_eq!(decoder.simple()?, 0xf6);
    assert_eq!(decoder.uint()?, 262144);
    decoder.skip_value(262144)?;
    assert_eq!(decoder.array(4)?, 4);
    assert_eq!(decoder.bytes(32)?, root);
    assert_eq!(decoder.uint()?, revision);
    let independently_selected = RecordedContext::new(revision, 3, &[])?;
    let names: Vec<_> = independently_selected.behavioral_names().collect();
    assert_eq!(decoder.array(64)?, names.len());
    for name in names {
        assert_eq!(decoder.text(128)?, name);
    }
    assert_eq!(decoder.array(64)?, 0);
    decoder.finish()?;
    Ok(())
}

#[tokio::test]
async fn recorded_merge_contexts_bind_original_interpretations_through_fold_replay() -> TestResult {
    use terrane_format::algebra::{self, OperationDomains, Recipe};
    use terrane_format::properties::RootLayer;
    use terrane_format::provenance::{Preset, Selector, TrustContext};

    let inputs = inputs().await?;
    let prepared = recompute(&inputs.repository, &inputs.records, true).await?;
    let bytes = prepared
        .commit
        .profile_pair
        .recipe
        .as_ref()
        .ok_or("native Fold omitted its actual recipe")?;
    let filtered_root = match Recipe::decode(bytes)?.as_recipe() {
        Recipe::Merge {
            base, ours, theirs, ..
        } => {
            assert_eq!(base, inputs.roots[0]);
            assert_eq!(ours, inputs.roots[1]);
            theirs
        }
        _ => return Err("native Fold produced another operation".into()),
    };
    assert_ne!(filtered_root, inputs.roots[2]);
    assert_eq!(prepared.excluded, [b"file".to_vec()]);
    drop(inputs.repository);

    // Reopen independently and reauthenticate the actual signed inputs and
    // their protected Originals before binding any decoded recipe evidence.
    let fresh = inputs.location.reopen(3, &[], inputs.rows.clone()).await?;
    let guard = fresh.coordinator().guard();
    let base = guard.verified_tree(inputs.records[0].commit).await?;
    let ours = guard.verified_tree(inputs.records[1].commit).await?;
    let original = guard.verified_tree(inputs.records[2].commit).await?;
    let ours_history = guard.verified_history(inputs.records[1].commit).await?;
    let original_history = guard.verified_history(inputs.records[2].commit).await?;
    for record in &inputs.records {
        assert!(guard.original_commit(&record.commit).is_ok());
    }
    assert_eq!(
        guard.historical_evidence_semantics(&ours.evidence, HistoryObservation::default())?,
        Selection::Recorded(RecordedContext::new(3, 3, &[])?)
    );
    assert_eq!(
        guard.historical_evidence_semantics(&original.evidence, HistoryObservation::default())?,
        Selection::Recorded(RecordedContext::new(1, 3, &[])?)
    );
    let evaluators = vec![
        TrustContext::new(
            &ours_history,
            inputs.records[1].commit,
            Selector::preset(Preset::Any),
            "public",
            None,
        )?,
        TrustContext::new(
            &original_history,
            inputs.records[2].commit,
            Selector::preset(Preset::Any),
            "public",
            None,
        )?,
    ];
    for (index, evaluator) in evaluators.iter().enumerate() {
        assert_eq!(evaluator.view_root(), inputs.roots[index + 1]);
        assert_recorded_context(
            evaluator.canonical_context(),
            inputs.records[index + 1].commit,
            inputs.roots[index + 1],
            [3, 1][index],
        )?;
        assert!(evaluator.accepts_path(b"file"));
    }

    // Inspect the actual native recipe's stored contexts. These comparisons
    // prove exact binding; they never configure the fresh Guard or evaluators.
    let mut wire = terrane_format::cbor::Decoder::new(bytes);
    assert_eq!(wire.map(3)?, 3);
    assert_eq!(wire.uint()?, 1);
    assert_eq!(wire.text(32)?, "merge");
    assert_eq!(wire.uint()?, 2);
    wire.skip_value(262144)?;
    assert_eq!(wire.uint()?, 3);
    assert_eq!(wire.map(3)?, 3);
    assert_eq!(wire.text(32)?, "trust");
    assert_eq!(wire.map(5)?, 4);
    assert_eq!(wire.uint()?, 1);
    wire.skip_value(262144)?;
    assert_eq!(wire.uint()?, 2);
    assert_eq!(wire.text(128)?, "terrane-verified-path/v1");
    assert_eq!(wire.uint()?, 3);
    assert_eq!(wire.array(2)?, 2);
    assert_eq!(wire.array(2)?, 2);
    for evaluator in &evaluators {
        assert_eq!(wire.bytes(262144)?, evaluator.canonical_context());
    }
    assert_eq!(wire.array(5)?, 4);
    assert_eq!(wire.bytes(32)?, inputs.roots[0]);
    assert_eq!(wire.bytes(32)?, inputs.roots[2]);
    assert_eq!(wire.bytes(32)?, filtered_root);
    assert_eq!(wire.array(1)?, 1);
    assert_eq!(wire.bytes(128)?, b"file");

    let mut domains = OperationDomains::new();
    for verified in [&base, &ours, &original] {
        let semantics = guard
            .historical_evidence_semantics(&verified.evidence, HistoryObservation::default())?;
        for occurrence in verified.evidence.occurrences(262144)? {
            let layers = occurrence
                .layers
                .iter()
                .map(|(properties, overrides)| RootLayer {
                    properties,
                    overrides,
                })
                .collect::<Vec<_>>();
            let effective = semantics.resolve(&layers, guard.defaults_for(&verified.evidence))?;
            domains.bind_resolved(occurrence.root, &effective)?;
        }
    }
    let base_tree = base.evidence.tree(base.evidence.root, 262144)?;
    let ours_tree = ours.evidence.tree(ours.evidence.root, 262144)?;
    let original_tree = original.evidence.tree(original.evidence.root, 262144)?;
    let filtered_evidence = crate::guard::TreeEvidence::load_tree(
        guard.store(),
        filtered_root,
        &prepared.uploads,
        262144,
    )
    .await?;
    let filtered_tree = filtered_evidence.tree(filtered_root, 262144)?;
    let rebound = Recipe::decode(bytes)?
        .bind_domains(&domains)?
        .bind_fold_verified_with_domains(
            evaluators.clone(),
            &base_tree,
            &original_tree,
            &filtered_tree,
            &prepared.excluded,
            &domains,
        )?;
    assert_eq!(rebound.as_recipe().encode(), *bytes);
    assert_eq!(
        rebound.as_recipe().identity()?,
        Recipe::decode(bytes)?.as_recipe().identity()?
    );
    let Recipe::Merge {
        trust, policies, ..
    } = rebound.as_recipe()
    else {
        return Err("verified Fold rebound another operation".into());
    };
    let forest = super::Forest(std::collections::BTreeMap::from([
        (base_tree.root_identity(), base_tree.clone()),
        (ours_tree.root_identity(), ours_tree.clone()),
        (original_tree.root_identity(), original_tree.clone()),
        (filtered_tree.root_identity(), filtered_tree.clone()),
    ]));
    let replayed = algebra::merge_with_domains(
        &base_tree,
        &ours_tree,
        &filtered_tree,
        policies,
        trust,
        &forest,
        &domains,
    )?;
    assert_eq!(replayed.tree.root_identity(), prepared.commit.tree);
    assert_eq!(replayed.recipe, *bytes);

    for changed in [
        Vec::new(),
        vec![evaluators[0].clone()],
        vec![evaluators[1].clone(), evaluators[0].clone()],
    ] {
        assert!(
            Recipe::decode(bytes)?
                .bind_domains(&domains)?
                .bind_fold_verified_with_domains(
                    changed,
                    &base_tree,
                    &original_tree,
                    &filtered_tree,
                    &prepared.excluded,
                    &domains
                )
                .is_err()
        );
    }
    assert!(
        Recipe::decode(bytes)?
            .bind_domains(&domains)?
            .bind_fold_verified_with_domains(
                evaluators.clone(),
                &base_tree,
                &filtered_tree,
                &filtered_tree,
                &prepared.excluded,
                &domains
            )
            .is_err()
    );
    let mut changed_rows = inputs.rows.clone();
    let original_row = selected(inputs.records[2].commit, inputs.roots[2], 1, &[])?;
    changed_rows.retain(|row| row != &original_row);
    changed_rows.push(selected(inputs.records[2].commit, inputs.roots[2], 2, &[])?);
    let changed = inputs.location.reopen(3, &[], changed_rows).await?;
    let changed_history = changed
        .coordinator()
        .guard()
        .verified_history(inputs.records[2].commit)
        .await?;
    let changed_context = TrustContext::new(
        &changed_history,
        inputs.records[2].commit,
        Selector::preset(Preset::Any),
        "public",
        None,
    )?;
    assert_eq!(changed_context.view_root(), inputs.roots[2]);
    assert_ne!(
        changed_context.canonical_context(),
        evaluators[1].canonical_context()
    );
    assert!(
        Recipe::decode(bytes)?
            .bind_domains(&domains)?
            .bind_fold_verified_with_domains(
                vec![evaluators[0].clone(), changed_context],
                &base_tree,
                &original_tree,
                &filtered_tree,
                &prepared.excluded,
                &domains
            )
            .is_err()
    );
    let mut absent = inputs.rows.clone();
    let original_selection = selected(inputs.records[2].commit, inputs.roots[2], 1, &[])?;
    absent.retain(|row| row != &original_selection);
    let unavailable = inputs.location.reopen(3, &[], absent).await?;
    assert!(
        unavailable
            .coordinator()
            .guard()
            .verified_history(inputs.records[2].commit)
            .await
            .is_err()
    );
    assert_eq!(
        guard.store().ref_get(REFERENCE).await?,
        Some(inputs.records[1].clone())
    );
    assert_eq!(
        guard.store().ref_get(SOURCE).await?,
        Some(inputs.records[2].clone())
    );
    Ok(())
}

#[path = "recorded_tests/ordinary_contracts.rs"]
mod ordinary_contracts;

#[path = "recorded_tests/native_fold_contracts.rs"]
mod native_fold_contracts;
