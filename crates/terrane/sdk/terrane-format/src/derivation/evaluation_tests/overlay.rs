//! Exercises complete grafted overlay replay against independent namespace models.
//!
//! Source policy follows each original graft occurrence; emitted policy uses
//! independently selected view interpretation and defaults, never recipe fields.

use super::*;
use crate::identity::Digest;
use crate::properties::{Defaults, RootLayer, selected::Selection};
use crate::tree_format::Entry;
use core::cell::Cell;

struct Context<'t> {
    trees: &'t BTreeMap<Digest, Tree<'static>>,
    interpretation: Selection,
    available: bool,
    result_available: bool,
    source_calls: Cell<usize>,
    result_calls: Cell<usize>,
}

impl<'t> Context<'t> {
    fn new(trees: &'t BTreeMap<Digest, Tree<'static>>) -> Self {
        Self {
            trees,
            interpretation: Selection::Active,
            available: true,
            result_available: true,
            source_calls: Cell::new(0),
            result_calls: Cell::new(0),
        }
    }

    fn policy(&self, layers: &[RootLayer<'_>]) -> Result<algebra::OverlayPolicy, algebra::Error> {
        if !self.available {
            return Err(algebra::Error::Boundary);
        }
        let effective = self
            .interpretation
            .resolve(
                layers,
                Defaults {
                    store: "memo-fixture-store",
                    private_domain: "private:verified",
                    home: "memo-fixture-home",
                },
            )
            .map_err(|_| algebra::Error::Boundary)?;
        algebra::OverlayPolicy::from_effective(&effective)
    }
}

impl OverlayReplayContext for Context<'_> {
    fn source_policy(
        &self,
        view: &Digest,
        at: &[u8],
    ) -> Result<algebra::OverlayPolicy, algebra::Error> {
        self.source_calls.set(self.source_calls.get() + 1);
        let mut tree = self.trees.get(view).ok_or(algebra::Error::MissingRoot)?;
        let mut layers = alloc::vec![RootLayer {
            properties: tree.props().unwrap_or_default(),
            overrides: &[],
        }];
        let mut remaining = at;
        while !remaining.is_empty() {
            let descriptor = tree
                .iter()
                .find(|item| {
                    matches!(item.entry.kind, EntryKind::Tree { .. })
                        && (remaining == item.key
                            || remaining
                                .strip_prefix(item.key.as_slice())
                                .is_some_and(|suffix| suffix.starts_with(b"/")))
                })
                .ok_or(algebra::Error::Boundary)?;
            let EntryKind::Tree { root, props } = &descriptor.entry.kind else {
                return Err(algebra::Error::Boundary);
            };
            tree = self.trees.get(root).ok_or(algebra::Error::MissingRoot)?;
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
        self.policy(&layers)
    }

    fn result_policy(
        &self,
        view: &Digest,
        layers: &[RootLayer<'_>],
    ) -> Result<algebra::OverlayPolicy, algebra::Error> {
        self.result_calls.set(self.result_calls.get() + 1);
        if !self.result_available {
            return Err(algebra::Error::Boundary);
        }
        if !self.trees.contains_key(view) {
            return Err(algebra::Error::MissingRoot);
        }
        self.policy(layers)
    }
}

struct Fixture {
    trees: BTreeMap<Digest, Tree<'static>>,
    recipe: Vec<u8>,
    expected: BTreeMap<Digest, Vec<u8>>,
    root: Digest,
    required: Digest,
}

fn overridden_graft(root: Digest) -> Entry<'static> {
    let mut entry = graft(root);
    if let EntryKind::Tree { props, .. } = &mut entry.kind {
        *props = Some(alloc::vec![Property {
            name: "store",
            value: b"\x64pool"
        }]);
    }
    entry
}

fn fixture() -> Fixture {
    let upper_leaf = Tree::build(
        alloc::vec![
            item(b"gone", entry(EntryKind::Whiteout)),
            symlink(b"x", b"upper")
        ],
        Some(alloc::vec![Property {
            name: "domain",
            value: DOMAIN
        }]),
        MINIMUM,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let lower_leaf = namespace(alloc::vec![
        symlink(b"gone", b"hidden"),
        symlink(b"x", b"lower"),
        symlink(b"y", b"retained")
    ]);
    let upper_child = namespace(alloc::vec![
        item(b"nested", graft(upper_leaf.root_identity())),
        symlink(b"same", b"upper")
    ]);
    let lower_child = namespace(alloc::vec![
        item(b"nested", graft(lower_leaf.root_identity())),
        symlink(b"same", b"lower"),
        symlink(b"stay", b"retained")
    ]);
    let top = namespace(alloc::vec![
        item(b"g", overridden_graft(upper_child.root_identity())),
        symlink(b"top", b"visible")
    ]);
    let bottom = namespace(alloc::vec![
        symlink(b"bottom", b"visible"),
        item(b"g", overridden_graft(lower_child.root_identity()))
    ]);
    let mut recipe = Vec::new();
    // Frame the expected original recipe directly; no evaluator codec supplies it.
    crate::cbor::write_map(&mut recipe, 2);
    crate::cbor::write_uint(&mut recipe, 1);
    crate::cbor::write_text(&mut recipe, "overlay");
    crate::cbor::write_uint(&mut recipe, 2);
    crate::cbor::write_array(&mut recipe, 2);
    crate::cbor::write_bytes(&mut recipe, &top.root_identity());
    crate::cbor::write_bytes(&mut recipe, &bottom.root_identity());

    let expected_leaf = namespace(alloc::vec![
        symlink(b"x", b"upper"),
        symlink(b"y", b"retained")
    ]);
    let expected_child = namespace(alloc::vec![
        item(b"nested", graft(expected_leaf.root_identity())),
        symlink(b"same", b"upper"),
        symlink(b"stay", b"retained")
    ]);
    let expected_root = namespace(alloc::vec![
        symlink(b"bottom", b"visible"),
        item(b"g", overridden_graft(expected_child.root_identity())),
        symlink(b"top", b"visible")
    ]);
    let mut expected = nodes(&expected_root);
    expected.extend(nodes(&expected_child));
    expected.extend(nodes(&expected_leaf));
    let root = expected_root.root_identity();
    let required = lower_leaf.root_identity();
    let trees = [
        top,
        bottom,
        upper_child,
        lower_child,
        upper_leaf,
        lower_leaf,
    ]
    .into_iter()
    .map(|tree| (tree.root_identity(), tree))
    .collect();
    Fixture {
        trees,
        recipe,
        expected,
        root,
        required,
    }
}

#[test]
fn complete_nested_overlay_uses_same_evaluator_for_disabled_miss_hit_and_rebuild() {
    let model = fixture();
    let context = Context::new(&model.trees);
    let mut input = inputs(&model.trees);
    input.overlay = Some(&context);
    let mut cache = MemoryCache::new();

    for (expected, enabled) in [
        (CacheObservation::Disabled, false),
        (CacheObservation::Miss, true),
        (CacheObservation::Hit, true),
    ] {
        let before = (context.source_calls.get(), context.result_calls.get());
        let result = replay(
            &model.recipe,
            &input,
            ReplayMode::Check,
            if enabled { Some(&mut cache) } else { None },
        )
        .unwrap();
        assert_eq!(result.cache.observation, expected);
        assert_eq!(result.evaluation.root, model.root);
        assert_eq!(result.evaluation.nodes, model.expected);
        assert_eq!(result.evaluation.closure_roots, 3);
        assert_eq!(
            result.memo.recipe_hash(),
            digest(IdentityKind::Memo, &model.recipe)
        );
        assert_eq!(result.memo.result_root(), model.root);
        assert!(context.source_calls.get() > before.0);
        assert!(context.result_calls.get() > before.1);
    }

    let key = digest(IdentityKind::Memo, &model.recipe);
    let divergent = Memo::new(key, [0x99; 32]);
    cache
        .replace(
            key,
            CacheRecord {
                identity: divergent.identity().unwrap(),
                encoded: divergent.encode(),
                nodes: Some(model.expected.clone()),
            },
        )
        .unwrap();
    assert_eq!(
        replay(&model.recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap_err(),
        ReplayError::Divergent {
            recipe: key,
            claimed: [0x99; 32],
            actual: model.root
        }
    );
    let result = replay(&model.recipe, &input, ReplayMode::Rebuild, Some(&mut cache)).unwrap();
    assert!(result.cache.rebuilt);
    assert_eq!(
        result.cache.observation,
        CacheObservation::Refused(CacheRefusal::Divergent([0x99; 32]))
    );
    assert_eq!(result.evaluation.nodes, model.expected);
    assert_eq!(
        replay(&model.recipe, &input, ReplayMode::Check, Some(&mut cache))
            .unwrap()
            .cache
            .observation,
        CacheObservation::Hit
    );
}

#[test]
fn cached_nested_overlay_cannot_bypass_missing_roots_or_independent_policy() {
    let model = fixture();
    let context = Context::new(&model.trees);
    let mut input = inputs(&model.trees);
    input.overlay = Some(&context);
    let mut cache = MemoryCache::new();
    replay(&model.recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap();

    let mut missing = model.trees.clone();
    missing.remove(&model.required);
    let missing_context = Context::new(&missing);
    let mut incomplete = inputs(&missing);
    incomplete.overlay = Some(&missing_context);
    for mode in [ReplayMode::Check, ReplayMode::Rebuild] {
        assert_eq!(
            replay(&model.recipe, &incomplete, mode, Some(&mut cache)).unwrap_err(),
            ReplayError::Evaluation(EvaluationError::Algebra(algebra::Error::MissingRoot))
        );
    }

    input.overlay = None;
    assert_eq!(
        replay(&model.recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap_err(),
        ReplayError::Evaluation(EvaluationError::Algebra(algebra::Error::Boundary))
    );
    let unavailable = Context {
        available: false,
        ..Context::new(&model.trees)
    };
    input.overlay = Some(&unavailable);
    for mode in [ReplayMode::Check, ReplayMode::Rebuild] {
        assert_eq!(
            replay(&model.recipe, &input, mode, Some(&mut cache)).unwrap_err(),
            ReplayError::Evaluation(EvaluationError::Algebra(algebra::Error::Boundary))
        );
    }
}

#[test]
fn every_cache_mode_rechecks_projected_policy_independently_of_source_policy() {
    let model = fixture();
    let valid = Context::new(&model.trees);
    let mut input = inputs(&model.trees);
    input.overlay = Some(&valid);
    let mut hit = MemoryCache::new();
    replay(&model.recipe, &input, ReplayMode::Check, Some(&mut hit)).unwrap();
    let unavailable = Context {
        result_available: false,
        ..Context::new(&model.trees)
    };
    input.overlay = Some(&unavailable);

    for mode in [ReplayMode::Check, ReplayMode::Rebuild] {
        let mut missing = MemoryCache::new();
        for cache in [None, Some(&mut missing), Some(&mut hit)] {
            assert_eq!(
                replay(
                    &model.recipe,
                    &input,
                    mode,
                    cache.map(|cache| cache as &mut dyn AdvisoryCache)
                )
                .unwrap_err(),
                ReplayError::Evaluation(EvaluationError::Algebra(algebra::Error::Boundary))
            );
        }
    }
    assert!(unavailable.source_calls.get() > 0);
    assert!(unavailable.result_calls.get() > 0);
}

#[test]
fn shared_overlay_target_retains_distinct_original_occurrence_policies() {
    let target = namespace(alloc::vec![symlink(b"inside", b"visible")]);
    let top = namespace(alloc::vec![
        item(b"first", overridden_graft(target.root_identity())),
        item(b"second", graft(target.root_identity())),
    ]);
    let recipe = Recipe::Overlay(&[top.root_identity()]).encode();
    let mut expected = nodes(&top);
    expected.extend(nodes(&target));
    let root = top.root_identity();
    let trees = BTreeMap::from([(root, top), (target.root_identity(), target)]);
    let context = Context::new(&trees);
    assert_ne!(
        context.source_policy(&root, b"first").unwrap(),
        context.source_policy(&root, b"second").unwrap()
    );
    let mut input = inputs(&trees);
    input.overlay = Some(&context);

    let result = evaluate(&recipe, &input).unwrap();
    assert_eq!(result.root, root);
    assert_eq!(result.nodes, expected);
    assert_eq!(result.closure_roots, 2);
}

#[test]
fn nested_overlay_rebinds_recorded_domains_without_using_them_as_policy_context() {
    let model = fixture();
    let context = Context::new(&model.trees);
    let ownership = domains(
        &model.trees.keys().copied().collect::<Vec<_>>(),
        "private:verified",
    );
    let decoded = Recipe::decode(&model.recipe).unwrap();
    let Recipe::Overlay(roots) = decoded.as_recipe() else {
        panic!("fixture must retain ordered overlay operands");
    };
    let recipe = Recipe::OverlayWithDomains {
        roots,
        domains: &ownership,
    }
    .encode();
    let mut input = inputs(&model.trees);
    input.domains = Some(&ownership);
    input.overlay = Some(&context);
    let mut cache = MemoryCache::new();

    let result = replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap();
    assert_eq!(result.evaluation.root, model.root);
    assert_eq!(result.evaluation.nodes, model.expected);
    input.overlay = None;
    assert_eq!(
        replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap_err(),
        ReplayError::Evaluation(EvaluationError::Algebra(algebra::Error::Boundary))
    );
    input.overlay = Some(&context);
    input.domains = None;
    assert_eq!(
        replay(&recipe, &input, ReplayMode::Rebuild, Some(&mut cache)).unwrap_err(),
        ReplayError::Evaluation(EvaluationError::Recipe(algebra::RecipeError::Schema))
    );
}
