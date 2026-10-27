//! Reopens genuine native Memo storage and replays complete nested overlays.
//!
//! Raw namespace oracles and independently selected property context remain
//! separate from advisory Memo selection and physical metadata admission.

use super::*;
use terrane_format::algebra::{Error as AlgebraError, OverlayPolicy};
use terrane_format::derivation::evaluation::OverlayReplayContext;
use terrane_format::properties::{Defaults, RootLayer, selected::Selection as Interpretation};
use terrane_format::tree_format::EntryKind as NamespaceEntry;

struct Context<'t, 'a> {
    trees: &'t BTreeMap<Digest, Tree<'a>>,
    available: bool,
}

impl Context<'_, '_> {
    fn resolve(&self, layers: &[RootLayer<'_>]) -> Result<OverlayPolicy, AlgebraError> {
        if !self.available {
            return Err(AlgebraError::Boundary);
        }
        // This interpretation and its defaults are configured before any Memo
        // is selected. They certify no serving or committing authority.
        let effective = Interpretation::Active
            .resolve(
                layers,
                Defaults {
                    store: "native-memo-store",
                    private_domain: "private:memo-test",
                    home: "native-memo-home",
                },
            )
            .map_err(|_| AlgebraError::Boundary)?;
        OverlayPolicy::from_effective(&effective)
    }
}

impl OverlayReplayContext for Context<'_, '_> {
    fn source_policy(&self, view: &Digest, at: &[u8]) -> Result<OverlayPolicy, AlgebraError> {
        let mut tree = self.trees.get(view).ok_or(AlgebraError::MissingRoot)?;
        let mut layers = vec![RootLayer {
            properties: tree.props().unwrap_or_default(),
            overrides: &[],
        }];
        let mut remaining = at;
        while !remaining.is_empty() {
            let descriptor = tree
                .iter()
                .find(|item| {
                    matches!(item.entry.kind, NamespaceEntry::Tree { .. })
                        && (remaining == item.key
                            || remaining
                                .strip_prefix(item.key.as_slice())
                                .is_some_and(|suffix| suffix.starts_with(b"/")))
                })
                .ok_or(AlgebraError::Boundary)?;
            let NamespaceEntry::Tree { root, props } = &descriptor.entry.kind else {
                return Err(AlgebraError::Boundary);
            };
            tree = self.trees.get(root).ok_or(AlgebraError::MissingRoot)?;
            layers.push(RootLayer {
                properties: tree.props().unwrap_or_default(),
                overrides: props.as_deref().unwrap_or_default(),
            });
            remaining = if remaining.len() == descriptor.key.len() {
                &[]
            } else {
                &remaining[descriptor.key.len() + 1..]
            };
        }
        self.resolve(&layers)
    }

    fn result_policy(
        &self,
        view: &Digest,
        layers: &[RootLayer<'_>],
    ) -> Result<OverlayPolicy, AlgebraError> {
        if !self.trees.contains_key(view) {
            return Err(AlgebraError::MissingRoot);
        }
        self.resolve(layers)
    }
}

#[tokio::test]
async fn native_nested_overlay_reopens_closure_and_rechecks_policy() -> TestResult {
    let mut model = native_model(wire::Fixture::nested_overlay())?;
    let cache = Cache::new().await?;
    cache.operands(&model).await?;
    // Mandatory operands use actual independently fetched immutable Node bytes.
    for (root, bytes) in &mut model.source {
        *bytes = cache
            .bucket
            .get(&id(IdentityKind::Node, *root)?, None)
            .await?;
    }
    let trees = model.trees();
    let context = Context {
        trees: &trees,
        available: true,
    };
    let mut input = inputs(&trees)?;
    input.overlay = Some(&context);
    let observed = ObservedCache::new(&cache.bucket, &model.output);
    let fresh = replay_and_persist(
        &observed,
        &model.recipe,
        &input,
        ReplayMode::Check,
        Selection::EnabledNoSelection,
        PersistenceMode::Store,
    )
    .await?;
    assert_persisted(&fresh, &model, &observed)?;
    assert_eq!(fresh.outcome.replay.evaluation.closure_roots, 3);

    let reopened = cache.reopen().await?;
    let inventory = model.inventory();
    let selected = Selection::Selected {
        memo: model.address(),
        nodes: Some(&inventory),
    };
    let hit = replay_and_persist(
        &reopened,
        &model.recipe,
        &input,
        ReplayMode::Check,
        selected,
        PersistenceMode::Omit,
    )
    .await?;
    assert_output(&hit, &model);
    assert_eq!(hit.outcome.replay.cache.observation, CacheObservation::Hit);

    let unavailable = Context {
        trees: &trees,
        available: false,
    };
    input.overlay = Some(&unavailable);
    for mode in [ReplayMode::Check, ReplayMode::Rebuild] {
        let error = refusal(
            replay_and_persist(
                &reopened,
                &model.recipe,
                &input,
                mode,
                selected,
                PersistenceMode::Omit,
            )
            .await,
            "unavailable independent overlay policy",
        )?;
        assert_eq!(
            error.replay,
            ReplayError::Evaluation(EvaluationError::Algebra(AlgebraError::Boundary))
        );
    }
    Ok(())
}
