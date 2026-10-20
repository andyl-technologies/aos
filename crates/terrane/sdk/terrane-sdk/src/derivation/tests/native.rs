//! Checks ordinary Memo persistence through actual native metadata admission.
//!
//! Literal output oracles remain separate from common replay. Native source
//! factories qualify current policy, Original evidence and checked provenance
//! before optional storage; cache bytes and stored Memo addresses grant none of
//! those authorities. GC association and current index serving remain separate.

mod fixture;
mod overlay;

use std::{collections::BTreeMap, error::Error, io};

use super::wire;
use crate::derivation::Selection;
use crate::derivation::persistence::{
    PersistedOutcome, PersistenceFailure, PersistenceMode, PersistenceStage, replay_and_persist,
};
use crate::pack::EntryKind;
use crate::store::{ContentStore, InvalidReason, StoreErrorKind};
use terrane_format::algebra::{MergePolicy, Recipe, TrustContext};
use terrane_format::derivation::cache::{CacheObservation, CacheRefusal, ReplayError, ReplayMode};
use terrane_format::derivation::evaluation::{EvaluationError, EvaluationInputs};
use terrane_format::identity::{Digest, IdentityKind};
use terrane_format::indexing::carrier::SemanticContext;
use terrane_format::provenance::{Preset, Selector};
use terrane_format::tree_builder::Tree;

use fixture::{Cache, CheckedReplay, InputDefect, ObservedCache, Source, id, native_model, put};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn inputs<'t, 'a>(trees: &'t BTreeMap<Digest, Tree<'a>>) -> TestResult<EvaluationInputs<'t, 'a>> {
    Ok(EvaluationInputs {
        trees,
        minimum: wire::MINIMUM,
        context: SemanticContext::new(3, 2, 1)?,
        domains: None,
        provenance: &[],
        fold: None,
        overlay: None,
    })
}

fn assert_output(actual: &PersistedOutcome, model: &wire::Fixture) {
    assert_eq!(actual.outcome.replay.evaluation.recipe_hash, model.key());
    assert_eq!(actual.outcome.replay.evaluation.root, model.root);
    assert_eq!(actual.outcome.replay.evaluation.nodes, model.output);
    assert_eq!(actual.outcome.replay.memo.encode(), model.record());
}

fn assert_persisted(
    actual: &PersistedOutcome,
    model: &wire::Fixture,
    observed: &ObservedCache<'_>,
) -> TestResult {
    assert_output(actual, model);
    assert!(actual.persistence.requested);
    assert_eq!(actual.persistence.nodes, model.inventory());
    assert_eq!(
        actual.persistence.memo,
        Some(id(IdentityKind::Memo, model.address())?)
    );
    assert!(actual.persistence.stopped.is_none());
    assert!(actual.persistence.failure.is_none());
    let mut order = vec![IdentityKind::Node; model.output.len()];
    order.push(IdentityKind::Memo);
    assert_eq!(observed.attempts()?, order);
    assert_ne!(model.key(), model.address());
    Ok(())
}

// An unexpected positive result fails the witness without replacing the real
// negative backend/evaluator error or requiring its result type to implement Debug.
fn refusal<T, E>(result: Result<T, E>, operation: &str) -> TestResult<E> {
    result
        .err()
        .ok_or_else(|| io::Error::other(format!("{operation} unexpectedly succeeded")).into())
}

#[tokio::test]
async fn common_memo_persists_and_reopens_all_t1_outputs() -> TestResult {
    for model in [
        wire::Fixture::graft(),
        wire::Fixture::overlay(),
        wire::Fixture::merge(),
        wire::Fixture::index(),
    ] {
        let model = native_model(model)?;
        let cache = Cache::new().await?;
        cache.operands(&model).await?;
        let trees = model.trees();
        let observed = ObservedCache::new(&cache.bucket, &model.output);
        let fresh = replay_and_persist(
            &observed,
            &model.recipe,
            &inputs(&trees)?,
            ReplayMode::Check,
            Selection::EnabledNoSelection,
            PersistenceMode::Store,
        )
        .await?;
        assert_eq!(
            fresh.outcome.replay.cache.observation,
            CacheObservation::Miss
        );
        assert_persisted(&fresh, &model, &observed)?;

        // A fresh backend instance reads the actual admitted m and every literal
        // Node. Explicit inventory selection remains ordinary untrusted data.
        let reopened = cache.reopen().await?;
        assert_eq!(
            reopened
                .get(&id(IdentityKind::Memo, model.address())?, None)
                .await?,
            model.record()
        );
        for (root, bytes) in &model.output {
            assert_eq!(
                reopened.get(&id(IdentityKind::Node, *root)?, None).await?,
                *bytes
            );
        }
        let inventory = model.inventory();
        let measured = ObservedCache::new(&reopened, &model.output);
        let hit = replay_and_persist(
            &measured,
            &model.recipe,
            &inputs(&trees)?,
            ReplayMode::Check,
            Selection::Selected {
                memo: model.address(),
                nodes: Some(&inventory),
            },
            PersistenceMode::Omit,
        )
        .await?;
        assert_output(&hit, &model);
        assert_eq!(hit.outcome.replay.cache.observation, CacheObservation::Hit);
        assert!(!hit.persistence.requested);
        assert!(hit.persistence.memo.is_none());
        assert!(measured.attempts()?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn common_memo_optional_loss_preserves_disabled_results() -> TestResult {
    // Disabled selection and omitted persistence establish the same literal
    // semantic result without any optional put or claimed durable Memo.
    let model = native_model(wire::Fixture::index())?;
    let cache = Cache::new().await?;
    cache.operands(&model).await?;
    let trees = model.trees();
    let observed = ObservedCache::new(&cache.bucket, &model.output);
    let disabled = replay_and_persist(
        &observed,
        &model.recipe,
        &inputs(&trees)?,
        ReplayMode::Check,
        Selection::Disabled,
        PersistenceMode::Omit,
    )
    .await?;
    assert_output(&disabled, &model);
    assert_eq!(
        disabled.outcome.replay.cache.observation,
        CacheObservation::Disabled
    );
    assert!(observed.attempts()?.is_empty());
    assert!(!disabled.persistence.requested);

    // Genuine schema admission rejects malformed data under DRV-21. A canonical
    // wrong-key record remains valid data and is refused only by common replay.
    let malformed = refusal(
        put(&cache.bucket, IdentityKind::Memo, &[0xa0]).await,
        "malformed Memo admission",
    )?;
    assert_eq!(
        malformed.kind(),
        &StoreErrorKind::Invalid(InvalidReason::Upload { rule_id: "DRV-21" })
    );
    let wrong_key = wire::memo([0xa5; 32], model.root);
    let wrong_address = put(&cache.bucket, IdentityKind::Memo, &wrong_key)
        .await?
        .terrane_v1_digest()?;
    let wrong = replay_and_persist(
        &observed,
        &model.recipe,
        &inputs(&trees)?,
        ReplayMode::Check,
        Selection::Selected {
            memo: wrong_address,
            nodes: None,
        },
        PersistenceMode::Omit,
    )
    .await?;
    assert_output(&wrong, &model);
    assert_eq!(
        wrong.outcome.replay.cache.observation,
        CacheObservation::Refused(CacheRefusal::WrongKey)
    );
    assert!(observed.attempts()?.is_empty());

    // Optional persistence itself can fail in the actual backend. This does not
    // excuse a source-policy failure, and no Memo acknowledgment is reported.
    cache.permissions(0o777).await?;
    let refused = replay_and_persist(
        &observed,
        &model.recipe,
        &inputs(&trees)?,
        ReplayMode::Check,
        Selection::Disabled,
        PersistenceMode::Store,
    )
    .await?;
    assert_output(&refused, &model);
    assert!(refused.persistence.requested);
    assert!(refused.persistence.nodes.is_empty());
    assert!(refused.persistence.memo.is_none());
    assert!(matches!(
        refused.persistence.stopped,
        Some(PersistenceStage::Node(_))
    ));
    assert!(matches!(
        refused.persistence.failure.as_deref(),
        Some(PersistenceFailure::Store { failure, .. })
            if failure.kind() == &StoreErrorKind::Unsupported
    ));
    assert_eq!(observed.attempts()?, vec![IdentityKind::Node]);
    cache.permissions(0o700).await?;

    // Actual native refusal after a real acknowledged prefix is distinct from
    // a first-put refusal. A final Memo failure retains every acknowledged Node
    // but still cannot report durable success for the record.
    for acknowledged in [1, model.output.len()] {
        let cache = Cache::new().await?;
        cache.operands(&model).await?;
        let observed = ObservedCache::refuse_after(&cache.bucket, &model.output, acknowledged);
        let partial = replay_and_persist(
            &observed,
            &model.recipe,
            &inputs(&trees)?,
            ReplayMode::Check,
            Selection::Disabled,
            PersistenceMode::Store,
        )
        .await?;
        assert_output(&partial, &model);
        let prefix = model.output.keys().take(acknowledged).copied().collect();
        assert_eq!(partial.persistence.nodes, prefix);
        assert!(partial.persistence.memo.is_none());
        assert!(matches!(
            partial.persistence.failure.as_deref(),
            Some(PersistenceFailure::Store { failure, .. })
            if failure.kind() == &StoreErrorKind::Unsupported
        ));
        if acknowledged == model.output.len() {
            assert_eq!(partial.persistence.stopped, Some(PersistenceStage::Memo));
            assert_eq!(observed.attempts()?.last(), Some(&IdentityKind::Memo));
        } else {
            assert!(matches!(
                partial.persistence.stopped,
                Some(PersistenceStage::Node(_))
            ));
            assert_eq!(
                observed.attempts()?,
                vec![IdentityKind::Node; acknowledged + 1]
            );
        }
        cache.permissions(0o700).await?;
        assert_eq!(
            cache
                .bucket
                .has(&[id(IdentityKind::Memo, model.address())?])
                .await?,
            vec![false]
        );
        for root in &partial.persistence.nodes {
            assert_eq!(
                cache
                    .bucket
                    .get(&id(IdentityKind::Node, *root)?, None)
                    .await?,
                model.output[root]
            );
        }
    }

    // Missing and physically corrupt actual admitted packs are advisory loss.
    // Inputs retain independently checked immutable owners; no claimed cached
    // output becomes an operand and no native damage is silently repaired here.
    for (kind, corrupt) in [
        (EntryKind::Memo, false),
        (EntryKind::Memo, true),
        (EntryKind::Node, false),
        (EntryKind::Node, true),
    ] {
        let cache = Cache::new().await?;
        cache.operands(&model).await?;
        let stored = replay_and_persist(
            &cache.bucket,
            &model.recipe,
            &inputs(&trees)?,
            ReplayMode::Check,
            Selection::Disabled,
            PersistenceMode::Store,
        )
        .await?;
        assert!(stored.persistence.failure.is_none());
        let digest = if kind == EntryKind::Memo {
            model.address()
        } else {
            model.root
        };
        cache.damage(kind, digest, corrupt).await?;
        let inventory = model.inventory();
        let observed = ObservedCache::new(&cache.bucket, &model.output);
        let loss = replay_and_persist(
            &observed,
            &model.recipe,
            &inputs(&trees)?,
            ReplayMode::Check,
            Selection::Selected {
                memo: model.address(),
                nodes: Some(&inventory),
            },
            PersistenceMode::Omit,
        )
        .await?;
        assert_output(&loss, &model);
        assert_eq!(
            loss.outcome.replay.cache.observation,
            CacheObservation::Refused(if kind == EntryKind::Memo {
                CacheRefusal::Unavailable
            } else {
                CacheRefusal::MissingOutput
            })
        );
        assert!(!loss.outcome.loading.diagnostics.is_empty());
        assert!(observed.attempts()?.is_empty());
        assert!(loss.persistence.memo.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn common_memo_divergence_refuses_until_complete_persisted_rebuild() -> TestResult {
    let model = native_model(wire::Fixture::index())?;
    let cache = Cache::new().await?;
    cache.operands(&model).await?;
    let trees = model.trees();
    let divergent_bytes = wire::memo(model.key(), model.first_operand);
    let divergent = put(&cache.bucket, IdentityKind::Memo, &divergent_bytes)
        .await?
        .terrane_v1_digest()?;
    let observed = ObservedCache::new(&cache.bucket, &model.output);
    let failure = refusal(
        replay_and_persist(
            &observed,
            &model.recipe,
            &inputs(&trees)?,
            ReplayMode::Check,
            Selection::Selected {
                memo: divergent,
                nodes: None,
            },
            PersistenceMode::Store,
        )
        .await,
        "divergent Check association",
    )?;
    assert_eq!(
        failure.replay,
        ReplayError::Divergent {
            recipe: model.key(),
            claimed: model.first_operand,
            actual: model.root,
        }
    );
    assert!(observed.attempts()?.is_empty());

    let rebuilt = replay_and_persist(
        &observed,
        &model.recipe,
        &inputs(&trees)?,
        ReplayMode::Rebuild,
        Selection::Selected {
            memo: divergent,
            nodes: None,
        },
        PersistenceMode::Store,
    )
    .await?;
    assert_persisted(&rebuilt, &model, &observed)?;
    assert!(rebuilt.outcome.replay.cache.rebuilt);
    assert_eq!(
        rebuilt.outcome.replay.cache.observation,
        CacheObservation::Refused(CacheRefusal::Divergent(model.first_operand))
    );
    // Rebuild stores the complete independently modeled P/G/route graph, and
    // leaves the older immutable divergent record as ordinary data.
    assert!(model.output.len() > 3);
    let reopened = cache.reopen().await?;
    assert_eq!(
        reopened
            .get(&id(IdentityKind::Memo, divergent)?, None)
            .await?,
        divergent_bytes
    );
    let inventory = model.inventory();
    let hit = replay_and_persist(
        &reopened,
        &model.recipe,
        &inputs(&trees)?,
        ReplayMode::Check,
        Selection::Selected {
            memo: model.address(),
            nodes: Some(&inventory),
        },
        PersistenceMode::Omit,
    )
    .await?;
    assert_eq!(hit.outcome.replay.cache.observation, CacheObservation::Hit);
    assert_output(&hit, &model);
    Ok(())
}

#[tokio::test]
async fn common_memo_replay_preserves_actual_current_original_and_trust_checks() -> TestResult {
    let source = Source::new().await?;
    let recorded = source.recorded(false).await?;
    let guard = recorded.coordinator().guard();
    let snapshots = source.snapshots(guard).await?;
    let provenance = snapshots[1..]
        .iter()
        .map(|snapshot| {
            snapshot.interpretation.evaluator(
                &snapshot.history,
                (snapshot.commit.identity(), snapshot.commit.commit().tree),
                Selector::preset(Preset::Any),
                &snapshot.storage_domain,
                None,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trust = TrustContext::from_verified(provenance.clone())?;
    let policies = [
        MergePolicy::PreferTrusted,
        MergePolicy::PreferNewer,
        MergePolicy::PreferTheirs,
    ];
    let recipe = Recipe::Merge {
        base: source.roots[0],
        ours: source.roots[1],
        theirs: source.roots[2],
        policies: &policies,
        trust: &trust,
        domains: None,
    }
    .encode();
    let expected = snapshots[2].evidence.nodes.clone();
    let cache = Cache::new().await?;
    let observed = ObservedCache::new(&cache.bucket, &expected);
    let stored = source
        .replay(
            &observed,
            CheckedReplay {
                recipe: &recipe,
                mode: ReplayMode::Check,
                selection: Selection::Disabled,
                persistence: PersistenceMode::Store,
                wrong_root: false,
                defect: InputDefect::None,
            },
        )
        .await?;
    assert_eq!(stored.outcome.replay.evaluation.root, source.roots[2]);
    assert_eq!(stored.outcome.replay.evaluation.nodes, expected);
    assert!(stored.persistence.failure.is_none());
    let memo = stored
        .persistence
        .memo
        .as_ref()
        .ok_or_else(|| io::Error::other("successful persistence lacked its Memo acknowledgment"))?
        .terrane_v1_digest()?;
    let inventory = expected.keys().copied().collect();
    let measured = ObservedCache::new(&cache.bucket, &expected);
    let selection = Selection::Selected {
        memo,
        nodes: Some(&inventory),
    };

    let hit = source
        .replay(
            &measured,
            CheckedReplay {
                recipe: &recipe,
                mode: ReplayMode::Check,
                selection,
                persistence: PersistenceMode::Omit,
                wrong_root: false,
                defect: InputDefect::None,
            },
        )
        .await?;
    assert_eq!(hit.outcome.replay.cache.observation, CacheObservation::Hit);
    assert_eq!(hit.outcome.replay.evaluation.nodes, expected);
    assert!(measured.attempts()?.is_empty());

    for defect in [
        InputDefect::MissingTrust,
        InputDefect::ReversedTrust,
        InputDefect::MissingTrees,
    ] {
        let failure = refusal(
            source
                .replay(
                    &measured,
                    CheckedReplay {
                        recipe: &recipe,
                        mode: ReplayMode::Check,
                        selection,
                        persistence: PersistenceMode::Store,
                        wrong_root: false,
                        defect,
                    },
                )
                .await,
            "mandatory checked inputs",
        )?;
        let mandatory = failure.downcast::<crate::derivation::Error>()?;
        match defect {
            InputDefect::MissingTrees => assert_eq!(
                mandatory.replay,
                ReplayError::Evaluation(EvaluationError::MissingRoot(source.roots[0]))
            ),
            InputDefect::MissingTrust | InputDefect::ReversedTrust => assert!(matches!(
                mandatory.replay,
                ReplayError::Evaluation(EvaluationError::Recipe(_))
            )),
            InputDefect::None => unreachable!("negative fixture inventory"),
        }
        assert!(measured.attempts()?.is_empty());
    }

    // Independently installed wrong original-root configuration never yields
    // genuine history contexts, even while a valid cached Memo remains readable.
    let wrong = source
        .replay(
            &measured,
            CheckedReplay {
                recipe: &recipe,
                mode: ReplayMode::Check,
                selection,
                persistence: PersistenceMode::Store,
                wrong_root: true,
                defect: InputDefect::None,
            },
        )
        .await;
    assert!(wrong.is_err());
    assert!(measured.attempts()?.is_empty());
    assert_eq!(
        cache
            .bucket
            .get(&id(IdentityKind::Memo, memo)?, None)
            .await?,
        stored.outcome.replay.memo.encode()
    );

    // Remove the actual owning Original association, not a fabricated trust row.
    // Fresh history qualification refuses before optional persistence is invoked.
    let original = source.original_row(source.records[1].commit).await?;
    let saved = original.with_extension("saved");
    tokio::fs::rename(&original, &saved).await?;
    let missing_original = source
        .replay(
            &measured,
            CheckedReplay {
                recipe: &recipe,
                mode: ReplayMode::Check,
                selection,
                persistence: PersistenceMode::Store,
                wrong_root: false,
                defect: InputDefect::None,
            },
        )
        .await;
    assert!(missing_original.is_err());
    assert!(measured.attempts()?.is_empty());
    tokio::fs::rename(saved, original).await?;
    source.snapshots(guard).await?;

    // Actual checked publication narrows the live ACL. Full immutable evidence
    // and admitted Memo remain present, but fresh current authorization refuses.
    source.revoke_read().await?;
    let refused = source
        .replay(
            &measured,
            CheckedReplay {
                recipe: &recipe,
                mode: ReplayMode::Check,
                selection,
                persistence: PersistenceMode::Store,
                wrong_root: false,
                defect: InputDefect::None,
            },
        )
        .await;
    let refused =
        refusal(refused, "changed current ACL")?.downcast::<crate::store::StoreFailure>()?;
    assert!(matches!(
        refused.kind(),
        StoreErrorKind::Denied { verb: "read", .. }
    ));
    assert!(measured.attempts()?.is_empty());
    assert_eq!(
        cache
            .bucket
            .get(&id(IdentityKind::Memo, memo)?, None)
            .await?,
        stored.outcome.replay.memo.encode()
    );
    Ok(())
}
