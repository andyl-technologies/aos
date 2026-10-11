//! Independently witnesses common T1 replay, checked evidence and cache outcomes.

#![allow(
    clippy::unwrap_used,
    reason = "independent test witnesses require complete ordinary data"
)]

mod fixtures;
mod overlay;
mod signed;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::Memo;
use super::cache::*;
use super::evaluation::*;
use crate::algebra::{self, MergePolicy, Recipe, TrustContext};
use crate::identity::IdentityKind;
use crate::indexing::{IndexEvaluationRecipe, carrier, evaluation as index};
use crate::tree_builder::Tree;
use crate::tree_format::{self, Attribute, ContentRef, EntryKind, NodeItems, Property, TreeUse};
use fixtures::*;

fn checked(recipe: &[u8], inputs: &EvaluationInputs<'_, '_>) -> Evaluation {
    replay(recipe, inputs, ReplayMode::Check, None)
        .unwrap()
        .evaluation
}

#[test]
fn memo_replays_graft_complete_recipe() {
    let target = namespace(alloc::vec![symlink(b"inside", b"target")]);
    let parent = namespace(alloc::vec![
        item(b"mount", entry(EntryKind::Directory { mode: 0o755 })),
        symlink(b"mount/removed", b"old"),
        symlink(b"stay", b"original"),
    ]);
    let mut graft_entry = graft(target.root_identity());
    graft_entry.attrs = alloc::vec![Attribute {
        name: "uid",
        value: b"\x18\x2a"
    }];
    graft_entry.attrs_present = true;
    graft_entry.provenance = Some([0x81; 32]);
    if let EntryKind::Tree { props, .. } = &mut graft_entry.kind {
        *props = Some(alloc::vec![Property {
            name: "domain",
            value: b"\x6eprivate:target"
        }]);
    }
    let expected = namespace(alloc::vec![
        item(b"mount", graft_entry.clone()),
        symlink(b"stay", b"original")
    ]);
    let encoded_entry = tree_format::encode_entry(&graft_entry, MINIMUM).unwrap();
    let recipe = Recipe::Graft {
        parent: parent.root_identity(),
        target: target.root_identity(),
        at: b"mount",
        entry: &encoded_entry,
        replace: true,
        domains: None,
    }
    .encode();
    let trees = BTreeMap::from([
        (parent.root_identity(), parent.clone()),
        (target.root_identity(), target.clone()),
    ]);

    let result = checked(&recipe, &inputs(&trees));
    assert_eq!(result.root, expected.root_identity());
    let mut expected_nodes = nodes(&expected);
    expected_nodes.extend(nodes(&target));
    assert_eq!(result.nodes, expected_nodes);
    assert_eq!(result.closure_roots, 2);
    assert_eq!(result.recipe_hash, digest(IdentityKind::Memo, &recipe));
    assert!(matches!(result.work, EvaluationWork::Graft { .. }));

    let blocked = Recipe::Graft {
        parent: parent.root_identity(),
        target: target.root_identity(),
        at: b"mount",
        entry: &encoded_entry,
        replace: false,
        domains: None,
    }
    .encode();
    assert_eq!(
        evaluate(&blocked, &inputs(&trees)).unwrap_err(),
        EvaluationError::Algebra(algebra::Error::InlineChildren)
    );

    // Replacing a group's canonical member must retain and relabel survivors.
    let linked = |key: &[u8]| {
        item(
            key,
            entry(EntryKind::File {
                mode: 0o644,
                size: 1,
                content: ContentRef::Inline([0x31; 32]),
                link_id: Some(b"a"),
            }),
        )
    };
    let hardlinks = namespace(alloc::vec![linked(b"a"), linked(b"b")]);
    let link_recipe = Recipe::Graft {
        parent: hardlinks.root_identity(),
        target: target.root_identity(),
        at: b"a",
        entry: &tree_format::encode_entry(&graft(target.root_identity()), MINIMUM).unwrap(),
        replace: true,
        domains: None,
    }
    .encode();
    let expected = namespace(alloc::vec![
        item(b"a", graft(target.root_identity())),
        item(
            b"b",
            entry(EntryKind::File {
                mode: 0o644,
                size: 1,
                content: ContentRef::Inline([0x31; 32]),
                link_id: Some(b"b")
            })
        )
    ]);
    let trees = BTreeMap::from([
        (hardlinks.root_identity(), hardlinks),
        (target.root_identity(), target),
    ]);
    assert_eq!(
        checked(&link_recipe, &inputs(&trees)).root,
        expected.root_identity()
    );
}

#[test]
fn memo_replays_ordered_overlay_with_whiteouts() {
    let bottom = namespace(alloc::vec![
        symlink(b"hidden", b"bottom"),
        symlink(b"same", b"bottom"),
        symlink(b"stay", b"bottom")
    ]);
    let top = Tree::build(
        alloc::vec![
            item(b"hidden", entry(EntryKind::Whiteout)),
            symlink(b"same", b"top")
        ],
        Some(alloc::vec![Property {
            name: "domain",
            value: DOMAIN
        }]),
        MINIMUM,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let roots = [top.root_identity(), bottom.root_identity()];
    let recipe = Recipe::Overlay(&roots).encode();
    let trees = BTreeMap::from([(top.root_identity(), top), (bottom.root_identity(), bottom)]);
    let expected = namespace(alloc::vec![
        symlink(b"same", b"top"),
        symlink(b"stay", b"bottom")
    ]);

    let actual = checked(&recipe, &inputs(&trees));
    assert_eq!(actual.root, expected.root_identity());
    assert_eq!(actual.nodes, nodes(&expected));
    let reversed = Recipe::Overlay(&[roots[1], roots[0]]).encode();
    assert_ne!(checked(&reversed, &inputs(&trees)).root, actual.root);
    assert_ne!(digest(IdentityKind::Memo, &reversed), actual.recipe_hash);
}

#[test]
fn memo_replays_merge_policies_and_checked_contexts() {
    use crate::provenance::{Preset, Selector};
    use signed::{SignedSide, signed_history};

    let base = namespace(alloc::vec![symlink(b"file", b"base")]);
    let ours = namespace(alloc::vec![symlink(b"file", b"ours")]);
    let theirs = namespace(alloc::vec![symlink(b"file", b"theirs")]);
    let (history, [our_view, their_view]) = signed_history(
        [
            SignedSide {
                tree: &ours,
                child: None,
                baseline: true,
                time: 100,
            },
            SignedSide {
                tree: &theirs,
                child: None,
                baseline: false,
                time: 200,
            },
        ],
        "private:verified",
    );
    let context = |view| {
        crate::provenance::TrustContext::new(
            &history,
            view,
            Selector::preset(Preset::Strict),
            "private:verified",
            Some("baseline"),
        )
        .unwrap()
    };
    let provenance = [context(our_view), context(their_view)];
    let trust = TrustContext::from_verified(provenance.to_vec()).unwrap();
    let trees = BTreeMap::from([
        (base.root_identity(), base.clone()),
        (ours.root_identity(), ours.clone()),
        (theirs.root_identity(), theirs.clone()),
    ]);
    let mut input = inputs(&trees);
    input.provenance = &provenance;

    for (policies, expected) in [
        (
            alloc::vec![MergePolicy::PreferTrusted, MergePolicy::PreferNewer],
            ours.root_identity(),
        ),
        (
            alloc::vec![MergePolicy::PreferNewer, MergePolicy::PreferTrusted],
            theirs.root_identity(),
        ),
    ] {
        let recipe = Recipe::Merge {
            base: base.root_identity(),
            ours: ours.root_identity(),
            theirs: theirs.root_identity(),
            policies: &policies,
            trust: &trust,
            domains: None,
        }
        .encode();
        let mut cache = MemoryCache::new();
        let result = replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap();
        assert_eq!(result.evaluation.root, expected);
        assert_eq!(
            replay(&recipe, &input, ReplayMode::Check, Some(&mut cache))
                .unwrap()
                .cache
                .observation,
            CacheObservation::Hit
        );
        let mut absent = inputs(&trees);
        assert!(matches!(
            replay(&recipe, &absent, ReplayMode::Check, Some(&mut cache)),
            Err(ReplayError::Evaluation(EvaluationError::Recipe(_)))
        ));
        let reversed = [provenance[1].clone(), provenance[0].clone()];
        absent.provenance = &reversed;
        assert!(matches!(
            replay(&recipe, &absent, ReplayMode::Check, Some(&mut cache)),
            Err(ReplayError::Evaluation(EvaluationError::Recipe(_)))
        ));
    }

    // Fold is encoded as merge plus recorded preprocessing, and binds genuine
    // original-side evidence only after deterministic exclusions replay exactly.
    let ownership = domains(
        &[ours.root_identity(), theirs.root_identity()],
        "private:verified",
    );
    let folded = algebra::fold_with_domains(
        &base,
        &ours,
        &theirs,
        [our_view, their_view],
        &[MergePolicy::PreferTrusted, MergePolicy::KeepConflict],
        &trust,
        &Forest(&trees),
        |_, _| false,
        algebra::Retirement::Delete,
        &ownership,
    )
    .unwrap();
    let filtered = folded.merged.derived_roots.first().unwrap().clone();
    let mut fold_trees = trees.clone();
    fold_trees.insert(filtered.root_identity(), filtered);
    let mut fold_inputs = inputs(&fold_trees);
    fold_inputs.provenance = &provenance;
    fold_inputs.domains = Some(&ownership);
    fold_inputs.fold = Some(FoldReplay {
        original: theirs.root_identity(),
        excluded: &folded.excluded,
        domains: Some(&ownership),
    });
    assert_eq!(
        checked(&folded.merged.recipe, &fold_inputs).root,
        folded.merged.tree.root_identity()
    );
    fold_inputs.fold = None;
    assert!(evaluate(&folded.merged.recipe, &fold_inputs).is_err());
    fold_inputs.fold = Some(FoldReplay {
        original: theirs.root_identity(),
        excluded: &[],
        domains: Some(&ownership),
    });
    assert!(evaluate(&folded.merged.recipe, &fold_inputs).is_err());
}

#[test]
fn memo_replays_closed_index_and_complete_carriers() {
    let file = |value| {
        let mut entry = entry(EntryKind::File {
            mode: 0o644,
            size: 1,
            content: ContentRef::Inline([0x11; 32]),
            link_id: None,
        });
        if let Some(value) = value {
            entry.attrs = alloc::vec![Attribute { name: "uid", value }];
            entry.attrs_present = true;
        }
        entry
    };
    let child = namespace(alloc::vec![
        item(b"missing", file(None)),
        item(b"present", file(Some(b"\x01")))
    ]);
    let owner = namespace(alloc::vec![
        item(b"first", graft(child.root_identity())),
        item(b"second", graft(child.root_identity()))
    ]);
    let trees = BTreeMap::from([
        (child.root_identity(), child),
        (owner.root_identity(), owner.clone()),
    ]);
    let recipe = IndexEvaluationRecipe::new(owner.root_identity(), "uid")
        .unwrap()
        .encode();
    let mut input = inputs(&trees);
    input.minimum = 262_144;
    // Index geometry is a mandatory independently selected context.
    assert!(matches!(
        evaluate(&recipe, &input),
        Err(EvaluationError::Index(index::Error::Source))
    ));
    let trees: BTreeMap<_, _> = trees
        .into_values()
        .map(|tree| {
            let rebuilt = Tree::build(
                tree.iter().cloned().collect(),
                tree.props().map(<[_]>::to_vec),
                262_144,
                TreeUse::Ordinary,
            )
            .unwrap();
            (rebuilt.root_identity(), rebuilt)
        })
        .collect();
    input = inputs(&trees);
    input.minimum = 262_144;

    let result = checked(&recipe, &input);
    let EvaluationWork::Index {
        construction,
        verification,
    } = &result.work
    else {
        panic!("index work")
    };
    assert_eq!(
        (verification.candidates, verification.missing_objects),
        (1, 1)
    );
    assert!(construction.source_roots >= 5);
    assert!(verification.physical_work.node_bytes_hashed > 0);
    let primary = tree_format::decode_node_for(
        &result.nodes[&result.root],
        true,
        input.minimum,
        TreeUse::Index,
    )
    .unwrap();
    assert!(
        carrier::validate_node(input.context, carrier::Role::Primary, &primary, true)
            .unwrap()
            .is_some()
    );
    let NodeItems::Leaf(rows) = primary.items else {
        panic!("small primary leaf")
    };
    assert_eq!(rows.len(), 1);
    let mut expected_key = alloc::vec![1];
    expected_key.extend_from_slice(&[0x11; 32]);
    assert_eq!(rows[0].key, expected_key);
    for key in [b"present".as_slice(), b"missing".as_slice()] {
        let expected_wire = terminal_route_wire(key, [0x11; 32]);
        assert_eq!(
            result.nodes[&digest(IdentityKind::Node, &expected_wire)],
            expected_wire
        );
    }
    assert_eq!(
        carrier::validate_row(
            input.context,
            carrier::Role::Primary,
            &rows[0].key,
            &rows[0].entry
        )
        .unwrap()
        .object(),
        [0x11; 32]
    );
    assert_eq!(result.nodes.len(), 6); // primary, gap, two parent and two child routes
    let mut cache = MemoryCache::new();
    for observation in [CacheObservation::Miss, CacheObservation::Hit] {
        let cached = replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap();
        assert_eq!(cached.cache.observation, observation);
        assert_eq!(cached.evaluation.nodes, result.nodes);
    }
    let reconstructed = index::IndexData {
        root: result.root,
        nodes: result.nodes.clone(),
        work: *construction,
    };
    assert!(
        index::verify(
            &IndexEvaluationRecipe::decode(&recipe).unwrap(),
            &trees,
            input.minimum,
            input.context,
            &reconstructed
        )
        .is_ok()
    );
    let mut truncated = reconstructed;
    let auxiliary = digest(
        IdentityKind::Node,
        &terminal_route_wire(b"missing", [0x11; 32]),
    );
    truncated.nodes.remove(&auxiliary);
    assert!(
        index::verify(
            &IndexEvaluationRecipe::decode(&recipe).unwrap(),
            &trees,
            input.minimum,
            input.context,
            &truncated
        )
        .is_err()
    );
}

#[test]
fn memo_rejects_wrong_key_and_divergent_result_until_rebuilt() {
    let tree = namespace(alloc::vec![symlink(b"file", b"actual")]);
    let trees = BTreeMap::from([(tree.root_identity(), tree.clone())]);
    let recipe = Recipe::Overlay(&[tree.root_identity()]).encode();
    let actual = checked(&recipe, &inputs(&trees));
    let mut cache = MemoryCache::new();
    let wrong = Memo::new([0x99; 32], actual.root);
    cache
        .replace(
            actual.recipe_hash,
            CacheRecord {
                identity: wrong.identity().unwrap(),
                encoded: wrong.encode(),
                nodes: Some(actual.nodes.clone()),
            },
        )
        .unwrap();

    let wrong_result = replay(
        &recipe,
        &inputs(&trees),
        ReplayMode::Check,
        Some(&mut cache),
    )
    .unwrap();
    assert_eq!(
        wrong_result.cache.observation,
        CacheObservation::Refused(CacheRefusal::WrongKey)
    );
    assert_eq!(wrong_result.evaluation.nodes, actual.nodes);
    let divergent = Memo::new(actual.recipe_hash, [0x88; 32]);
    cache
        .replace(
            actual.recipe_hash,
            CacheRecord {
                identity: divergent.identity().unwrap(),
                encoded: divergent.encode(),
                nodes: Some(BTreeMap::new()),
            },
        )
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            replay(
                &recipe,
                &inputs(&trees),
                ReplayMode::Check,
                Some(&mut cache)
            )
            .unwrap_err(),
            ReplayError::Divergent {
                recipe: actual.recipe_hash,
                claimed: [0x88; 32],
                actual: actual.root
            }
        );
    }
    let rebuilt = replay(
        &recipe,
        &inputs(&trees),
        ReplayMode::Rebuild,
        Some(&mut cache),
    )
    .unwrap();
    assert!(rebuilt.cache.rebuilt);
    assert_eq!(
        rebuilt.cache.observation,
        CacheObservation::Refused(CacheRefusal::Divergent([0x88; 32]))
    );
    assert_eq!(rebuilt.evaluation.nodes, actual.nodes);
    assert_eq!(
        replay(
            &recipe,
            &inputs(&trees),
            ReplayMode::Check,
            Some(&mut cache)
        )
        .unwrap()
        .cache
        .observation,
        CacheObservation::Hit
    );
}

#[test]
fn memo_cache_states_preserve_disabled_results() {
    let tree = namespace(alloc::vec![symlink(b"file", b"data")]);
    let trees = BTreeMap::from([(tree.root_identity(), tree)]);
    let recipe = Recipe::Overlay(&trees.keys().copied().collect::<Vec<_>>()).encode();
    let input = inputs(&trees);
    let disabled = replay(&recipe, &input, ReplayMode::Check, None).unwrap();
    assert_eq!(disabled.cache.observation, CacheObservation::Disabled);
    let mut cache = MemoryCache::new();
    for expected in [CacheObservation::Miss, CacheObservation::Hit] {
        let result = replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap();
        assert_eq!(result.cache.observation, expected);
        assert_eq!(result.evaluation.nodes, disabled.evaluation.nodes);
    }
    let root = *trees.keys().next().unwrap();
    let graft_bytes = tree_format::encode_entry(&graft(root), MINIMUM).unwrap();
    let graft_recipe = Recipe::Graft {
        parent: root,
        target: root,
        at: b"file",
        entry: &graft_bytes,
        replace: false,
        domains: None,
    }
    .encode();
    let merge_recipe = Recipe::Merge {
        base: root,
        ours: root,
        theirs: root,
        policies: &[MergePolicy::KeepConflict],
        trust: &TrustContext::any(),
        domains: None,
    }
    .encode();
    for recipe in [graft_recipe, merge_recipe] {
        let disabled = replay(&recipe, &input, ReplayMode::Check, None).unwrap();
        for observation in [CacheObservation::Miss, CacheObservation::Hit] {
            let cached = replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap();
            assert_eq!(cached.cache.observation, observation);
            assert_eq!(cached.evaluation.nodes, disabled.evaluation.nodes);
        }
    }

    let valid = CacheRecord {
        identity: disabled.memo.identity().unwrap(),
        encoded: disabled.memo.encode(),
        nodes: Some(disabled.evaluation.nodes.clone()),
    };
    let mut corrupt = valid.clone();
    corrupt.encoded.push(0);
    let mut wrong_identity = valid.clone();
    wrong_identity.identity = disabled.memo.recipe_hash();
    let mut missing = valid.clone();
    missing.nodes = None;
    let mut incomplete = valid.clone();
    incomplete.nodes = Some(BTreeMap::new());
    for (record, refusal) in [
        (corrupt, CacheRefusal::CorruptRecord),
        (wrong_identity, CacheRefusal::CorruptRecord),
        (missing, CacheRefusal::MissingOutput),
        (incomplete, CacheRefusal::InvalidOutput),
    ] {
        cache
            .replace(disabled.evaluation.recipe_hash, record)
            .unwrap();
        let result = replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap();
        assert_eq!(result.cache.observation, CacheObservation::Refused(refusal));
        assert_eq!(result.evaluation.nodes, disabled.evaluation.nodes);
    }
    let result = replay(&recipe, &input, ReplayMode::Rebuild, Some(&mut Unavailable)).unwrap();
    assert_eq!(
        result.cache.observation,
        CacheObservation::Refused(CacheRefusal::Unavailable)
    );
    assert!(result.cache.write_unavailable && result.cache.rebuilt);
    assert_eq!(result.evaluation.nodes, disabled.evaluation.nodes);
}

#[test]
fn memo_rebuild_returns_complete_output_closure() {
    let base_child = namespace(alloc::vec![
        symlink(b"left", b"base"),
        symlink(b"right", b"base")
    ]);
    let our_child = namespace(alloc::vec![
        symlink(b"left", b"ours"),
        symlink(b"right", b"base")
    ]);
    let their_child = namespace(alloc::vec![
        symlink(b"left", b"base"),
        symlink(b"right", b"theirs")
    ]);
    let base = namespace(alloc::vec![item(
        b"mount",
        graft(base_child.root_identity())
    )]);
    let ours = namespace(alloc::vec![item(
        b"mount",
        graft(our_child.root_identity())
    )]);
    let theirs = namespace(alloc::vec![item(
        b"mount",
        graft(their_child.root_identity())
    )]);
    let expected_child = namespace(alloc::vec![
        symlink(b"left", b"ours"),
        symlink(b"right", b"theirs")
    ]);
    let expected = namespace(alloc::vec![item(
        b"mount",
        graft(expected_child.root_identity())
    )]);
    let recipe = Recipe::Merge {
        base: base.root_identity(),
        ours: ours.root_identity(),
        theirs: theirs.root_identity(),
        policies: &[MergePolicy::KeepConflict],
        trust: &TrustContext::any(),
        domains: None,
    }
    .encode();
    let trees = [base, ours, theirs, base_child, our_child, their_child]
        .into_iter()
        .map(|tree| (tree.root_identity(), tree))
        .collect();
    let mut cache = MemoryCache::new();
    let key = digest(IdentityKind::Memo, &recipe);
    let divergent = Memo::new(key, [0xee; 32]);
    cache
        .replace(
            key,
            CacheRecord {
                identity: divergent.identity().unwrap(),
                encoded: divergent.encode(),
                nodes: None,
            },
        )
        .unwrap();

    let rebuilt = replay(
        &recipe,
        &inputs(&trees),
        ReplayMode::Rebuild,
        Some(&mut cache),
    )
    .unwrap();
    let mut expected_nodes = nodes(&expected);
    expected_nodes.extend(nodes(&expected_child));
    assert_eq!(rebuilt.evaluation.root, expected.root_identity());
    assert_eq!(rebuilt.evaluation.nodes, expected_nodes);
    assert_eq!(rebuilt.evaluation.closure_roots, 2);
    assert_eq!(
        rebuilt.evaluation.closure_bytes,
        expected_nodes.values().map(Vec::len).sum()
    );
    assert_eq!(
        cache.lookup(key).unwrap().unwrap().nodes.unwrap(),
        expected_nodes
    );

    deep_conflict_base_rebuild_retains_all_roots();
}

fn deep_conflict_base_rebuild_retains_all_roots() {
    let ours = namespace(alloc::vec![symlink(b"candidate", b"ours")]);
    let theirs = namespace(alloc::vec![symlink(b"candidate", b"theirs")]);
    let base = namespace(alloc::vec![symlink(b"full-base", b"base")]);
    let depth = tree_format::MAX_GRAFT_DEPTH + 32;
    assert!(depth > tree_format::MAX_GRAFT_DEPTH);

    // Independent CDDL frames place Tree references in both candidates and
    // the terminal full base. This ordinary bounded witness runs only after
    // the closure implementation uses an explicit entry work stack.
    let tree_entry = |root: crate::identity::Digest| {
        let mut encoded = alloc::vec![0xa2, 1, 4, 6];
        crate::cbor::write_bytes(&mut encoded, &root);
        encoded
    };
    let mut encoded = Vec::new();
    for _ in 0..depth {
        encoded.extend_from_slice(&[0xa3, 1, 6, 12, 0x82]);
        encoded.extend_from_slice(&tree_entry(ours.root_identity()));
        encoded.extend_from_slice(&tree_entry(theirs.root_identity()));
        encoded.push(13);
    }
    encoded.extend_from_slice(&tree_entry(base.root_identity()));
    assert!(encoded.len() < tree_format::MAX_NODE_ITEMS_BYTES);
    let conflict = tree_format::decode_entry_bytes(&encoded, MINIMUM).unwrap();
    assert_eq!(
        tree_format::encode_entry(&conflict, MINIMUM).unwrap(),
        encoded
    );
    let owner = namespace(alloc::vec![item(b"conflict", conflict)]);
    let recipe = Recipe::Overlay(&[owner.root_identity()]).encode();
    let mut expected_nodes = nodes(&owner);
    for target in [&ours, &theirs, &base] {
        expected_nodes.extend(nodes(target));
    }
    let trees = [owner.clone(), ours, theirs, base]
        .into_iter()
        .map(|tree| (tree.root_identity(), tree))
        .collect();
    let key = digest(IdentityKind::Memo, &recipe);
    let divergent = Memo::new(key, [0xee; 32]);
    let mut cache = MemoryCache::new();
    cache
        .replace(
            key,
            CacheRecord {
                identity: divergent.identity().unwrap(),
                encoded: divergent.encode(),
                nodes: None,
            },
        )
        .unwrap();

    let rebuilt = replay(
        &recipe,
        &inputs(&trees),
        ReplayMode::Rebuild,
        Some(&mut cache),
    )
    .unwrap();
    assert_eq!(rebuilt.evaluation.root, owner.root_identity());
    assert_eq!(rebuilt.evaluation.nodes, expected_nodes);
    assert_eq!(rebuilt.evaluation.closure_roots, 4);
    assert_eq!(
        rebuilt.evaluation.closure_bytes,
        expected_nodes.values().map(Vec::len).sum()
    );
    assert_eq!(
        cache.lookup(key).unwrap().unwrap().nodes.unwrap(),
        expected_nodes
    );
}

#[test]
fn memo_rejects_missing_inputs_and_unsupported_recipes() {
    let tree = namespace(alloc::vec![symlink(b"file", b"data")]);
    let recipe = Recipe::Overlay(&[tree.root_identity()]).encode();
    let empty = BTreeMap::new();
    assert_eq!(
        replay(
            &recipe,
            &inputs(&empty),
            ReplayMode::Check,
            Some(&mut Unavailable)
        )
        .unwrap_err(),
        ReplayError::Evaluation(EvaluationError::MissingRoot(tree.root_identity()))
    );
    let wrong = BTreeMap::from([([0; 32], tree.clone())]);
    assert_eq!(
        evaluate(&Recipe::Overlay(&[[0; 32]]).encode(), &inputs(&wrong)).unwrap_err(),
        EvaluationError::Input([0; 32])
    );
    let nested = namespace(alloc::vec![item(b"mount", graft([0xaa; 32]))]);
    let incomplete = BTreeMap::from([(nested.root_identity(), nested.clone())]);
    assert!(matches!(
        evaluate(
            &Recipe::Overlay(&[nested.root_identity()]).encode(),
            &inputs(&incomplete)
        ),
        Err(EvaluationError::Algebra(algebra::Error::MissingRoot))
    ));
    for operation in ["filter", "map", "realize", "union"] {
        assert!(matches!(
            evaluate(
                &retained(operation, tree.root_identity(), None),
                &inputs(&empty)
            ),
            Err(EvaluationError::Unsupported(_))
        ));
    }
    let historical_index = retained("index", tree.root_identity(), Some(("attribute", "uid")));
    assert!(matches!(
        evaluate(&historical_index, &inputs(&empty)),
        Err(EvaluationError::Unsupported(_))
    ));
    assert!(matches!(
        evaluate(b"\xa2\x01", &inputs(&empty)),
        Err(EvaluationError::Encoding(_))
    ));
}

#[test]
fn memo_preserves_context_and_operand_configuration() {
    let first = Tree::build(
        alloc::vec![symlink(b"file", b"one")],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let second = Tree::build(
        alloc::vec![symlink(b"file", b"two")],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let roots = [first.root_identity(), second.root_identity()];
    let ownership = domains(&roots, "private:verified");
    let wrong_ownership = domains(&roots, "private:other");
    let recipe = Recipe::OverlayWithDomains {
        roots: &roots,
        domains: &ownership,
    }
    .encode();
    let trees = BTreeMap::from([
        (first.root_identity(), first),
        (second.root_identity(), second),
    ]);
    let mut input = inputs(&trees);
    input.domains = Some(&ownership);
    let mut cache = MemoryCache::new();
    let result = replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)).unwrap();
    assert_eq!(
        result.evaluation.root,
        namespace(alloc::vec![symlink(b"file", b"one")]).root_identity()
    );
    assert_ne!(result.memo.recipe_hash(), result.memo.identity().unwrap());
    assert_eq!(
        result.memo.identity().unwrap(),
        digest(IdentityKind::Memo, &result.memo.encode())
    );

    input.domains = None;
    assert!(matches!(
        replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)),
        Err(ReplayError::Evaluation(EvaluationError::Recipe(_)))
    ));
    input.domains = Some(&wrong_ownership);
    assert!(matches!(
        replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)),
        Err(ReplayError::Evaluation(EvaluationError::Recipe(_)))
    ));
    input.domains = Some(&ownership);
    input.minimum = MINIMUM * 2;
    assert!(matches!(
        replay(&recipe, &input, ReplayMode::Check, Some(&mut cache)),
        Err(ReplayError::Evaluation(EvaluationError::Input(_)))
    ));
    assert!(carrier::SemanticContext::new(2, 2, 1).is_err());
}
