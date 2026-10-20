//! Checks exact historical evaluator contexts, fold replay and typed memo keys.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use crate::algebra::{MergePolicy, Recipe, Retirement, Roots, fold, merge};
use crate::identity::Digest;
use crate::properties::{Defaults, RootLayer, selected::Selection, semantics::RecordedContext};
use crate::provenance::{Preset, Selector, TrustContext, VerifiedHistory, verify};
use crate::refs::Commit;
use crate::tree_builder::Tree;
use crate::tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse};
use alloc::{vec, vec::Vec};
mod fixtures;
use fixtures::*;
const DOMAIN: &str = "private:fold";

const PROPERTIES: &[Property<'static>] = &[
    Property {
        name: "domain",
        value: b"\x6cprivate:fold",
    },
    Property {
        name: "future.value",
        value: b"\x00",
    },
];

/// Reports no graft roots because these independently supplied models are flat.
struct FlatRoots;

impl<'a> Roots<'a> for FlatRoots {
    fn resolve(&self, _: &Digest) -> Option<&Tree<'a>> {
        None
    }
}

fn entry(target: &'static [u8]) -> Entry<'static> {
    Entry {
        kind: EntryKind::Symlink { target },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn input(rows: &[(&[u8], &'static [u8])]) -> Tree<'static> {
    let tree = Tree::build(
        rows.iter()
            .map(|(key, target)| LeafItem {
                key: key.to_vec(),
                entry: entry(target),
            })
            .collect(),
        Some(PROPERTIES.to_vec()),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let raw_rows = rows
        .iter()
        .map(|(key, target)| {
            (
                *key,
                map(vec![(uint(1), uint(3)), (uint(5), bytes(target))]),
            )
        })
        .collect::<Vec<_>>();
    let independent = node(
        &raw_rows,
        &[("domain", text(DOMAIN)), ("future.value", uint(0))],
    );
    assert_eq!(tree.root().encoded(), independent);
    let mut preimage = b"terrane-node-v1\0".to_vec();
    preimage.extend(&independent);
    assert_eq!(tree.root_identity(), *blake3::hash(&preimage).as_bytes());
    assert_eq!(tree.props(), Some(PROPERTIES));
    tree
}

fn retain_tree(history: &mut VerifiedHistory, tree: &Tree<'_>) {
    let nodes = tree
        .nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect::<Vec<_>>();
    history.insert_tree(tree.root_identity(), &nodes).unwrap();
}

// These inputs are checked again through production verification on each replay;
// no decoded memo claims or fixture verification flags construct this history.
fn fresh_history(trees: [&Tree<'_>; 3], records: &[Commit; 3]) -> (VerifiedHistory, [Digest; 3]) {
    let mut history = VerifiedHistory::new(MINIMUM);
    for tree in trees {
        retain_tree(&mut history, tree);
    }
    let mut views = [[0; 32]; 3];
    for (index, record) in records.iter().enumerate() {
        let verified = with_request(|request| verify(record, &issuer_keys(), request, 4)).unwrap();
        views[index] = verified.identity();
        history
            .insert_commit_selected(verified, selection(index))
            .unwrap();
    }
    (history, views)
}

fn contexts(history: &VerifiedHistory, views: [Digest; 3], _: [&Tree<'_>; 3]) -> Vec<TrustContext> {
    [1, 2]
        .map(|i| {
            TrustContext::new(
                history,
                views[i],
                Selector::preset(Preset::Any),
                DOMAIN,
                Some("baseline"),
            )
            .unwrap()
        })
        .to_vec()
}

fn selection(index: usize) -> Selection {
    let later: &[&str] = if index == 2 {
        &["future.value", "index-roots"]
    } else {
        &["future.value"]
    };
    Selection::Recorded(RecordedContext::new([2, 3, 1][index], 3, later).unwrap())
}

fn context_model(view: Digest, root: Digest, revision: u64, later: &[&str]) -> Vec<u8> {
    let behavioral = vocabulary(revision)
        .iter()
        .map(|name| text(name))
        .collect::<Vec<_>>();
    let mut later = later.to_vec();
    later.sort_unstable();
    let later = later.iter().map(|name| text(name)).collect::<Vec<_>>();
    array(&[
        uint(3),
        bytes(&view),
        text(DOMAIN),
        bytes(&array(&[text("preset"), text("any")])),
        text("baseline"),
        uint(MINIMUM),
        vec![0xf6],
        array(&[
            bytes(&root),
            uint(revision),
            array(&behavioral),
            array(&later),
        ]),
    ])
}

fn recipe_model(
    roots: [Digest; 3],
    original: Digest,
    contexts: &[Vec<u8>; 2],
    excluded: &[Vec<u8>],
) -> Vec<u8> {
    let configuration = array(&[
        array(&[bytes(&contexts[0]), bytes(&contexts[1])]),
        array(&[
            bytes(&roots[0]),
            bytes(&original),
            bytes(&roots[2]),
            array(&excluded.iter().map(|path| bytes(path)).collect::<Vec<_>>()),
        ]),
    ]);
    let trust = map(vec![
        (uint(1), array(&[text("preset"), text("any")])),
        (uint(2), text("terrane-verified-path/v1")),
        (uint(3), configuration),
        (uint(4), array(&[])),
    ]);
    map(vec![
        (uint(1), text("merge")),
        (
            uint(2),
            array(&roots.iter().map(|root| bytes(root)).collect::<Vec<_>>()),
        ),
        (
            uint(3),
            map(vec![
                (text("trust"), trust),
                (
                    text("policy"),
                    array(&[text("prefer-trusted"), text("keep-conflict")]),
                ),
            ]),
        ),
    ])
}

#[test]
fn recorded_fold_recipe_binds_original_root_and_exact_contexts_on_verified_replay() {
    let base = input(&[(b"file", b"base")]);
    let ours = input(&[(b"file", b"ours")]);
    let original = input(&[(b"file", b"incoming"), (b"new", b"addition")]);
    let roots = [
        base.root_identity(),
        ours.root_identity(),
        original.root_identity(),
    ];
    let mut history = VerifiedHistory::new(MINIMUM);
    for tree in [&base, &ours, &original] {
        retain_tree(&mut history, tree);
    }
    let all_views = [
        retain_selected(&mut history, roots[0], "base", selection(0)),
        retain_selected(&mut history, roots[1], "ours", selection(1)),
        retain_selected(&mut history, roots[2], "theirs", selection(2)),
    ];
    let views = [all_views[1], all_views[2]];
    let records = all_views.map(|view| history.commit(&view).unwrap().commit().clone());
    let evaluated = contexts(&history, all_views, [&base, &ours, &original]);
    let models = [
        context_model(views[0], roots[1], 3, &["future.value"]),
        context_model(views[1], roots[2], 1, &["future.value", "index-roots"]),
    ];
    for (index, evaluator) in evaluated.iter().enumerate() {
        assert_eq!(evaluator.canonical_context(), models[index]);
        assert_eq!(evaluator.view_root(), roots[index + 1]);
        assert!(evaluator.accepts_path(b"file"));
        // The complete literal tuple includes every field and the frozen
        // vocabulary, not merely a version or context hash.
    }

    let policy = crate::algebra::TrustContext::from_verified(evaluated).unwrap();
    let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
    // Caller exclusion decisions restore a changed entry and remove an addition.
    // This pure operation neither advances refs nor performs retirement actions.
    let result = fold(
        &base,
        &ours,
        &original,
        views,
        &policies,
        &policy,
        &FlatRoots,
        |_, _| false,
        Retirement::Tag,
    )
    .unwrap();
    let excluded = vec![b"file".to_vec(), b"new".to_vec()];
    assert_eq!(result.excluded, excluded);
    assert_eq!(result.parents, views);
    assert_eq!(result.retirement, Retirement::Tag);
    let filtered = result.merged.derived_roots.first().unwrap();
    assert_ne!(filtered.root_identity(), roots[2]);
    assert_eq!(filtered.root_identity(), roots[0]);
    assert_eq!(filtered.get(b"file"), base.get(b"file"));
    assert!(filtered.get(b"new").is_none());
    assert_eq!(filtered.props(), original.props());
    assert_eq!(result.merged.tree.root_identity(), roots[1]);
    assert!(!result.merged.conflicted);
    let operands = [roots[0], roots[1], filtered.root_identity()];
    let expected = recipe_model(operands, roots[2], &models, &excluded);
    assert_eq!(result.merged.recipe, expected);
    let mut preimage = b"terrane-memo-v1\0".to_vec();
    preimage.extend(&expected);
    let expected_key = *blake3::hash(&preimage).as_bytes();
    let decoded = Recipe::decode(&expected).unwrap();
    assert_eq!(decoded.as_recipe().identity().unwrap(), expected_key);

    let (fresh, fresh_views) = fresh_history([&base, &ours, &original], &records);
    assert_eq!(fresh_views, all_views);
    let matching = contexts(&fresh, all_views, [&base, &ours, &original]);
    let rebound = Recipe::decode(&result.merged.recipe)
        .unwrap()
        .bind_fold_verified(matching.clone(), &base, &original, filtered, &excluded)
        .unwrap();
    assert_eq!(rebound.as_recipe().encode(), expected);
    assert_eq!(rebound.as_recipe().identity().unwrap(), expected_key);
    let Recipe::Merge {
        base: bound_base,
        ours: bound_ours,
        theirs: bound_filtered,
        trust,
        policies: bound_policies,
        domains,
    } = rebound.as_recipe()
    else {
        panic!("complete merge model");
    };
    assert_eq!([bound_base, bound_ours, bound_filtered], operands);
    assert_eq!(bound_policies, policies);
    assert!(domains.is_none());
    let replayed = merge(&base, &ours, filtered, &policies, trust, &FlatRoots).unwrap();
    assert_eq!(
        replayed.tree.root_identity(),
        result.merged.tree.root_identity()
    );
    assert_eq!(replayed.recipe, expected);

    // A complete ordinary memo may claim a different original root without
    // establishing that association. Actual fresh checked inputs must refuse it.
    let wrong_models = [
        models[0].clone(),
        context_model(
            views[1],
            filtered.root_identity(),
            1,
            &["future.value", "index-roots"],
        ),
    ];
    let wrong_original = recipe_model(operands, filtered.root_identity(), &wrong_models, &excluded);
    let wrong_decoded = Recipe::decode(&wrong_original).unwrap();
    assert_ne!(wrong_decoded.as_recipe().identity().unwrap(), expected_key);
    assert!(
        wrong_decoded
            .bind_fold_verified(matching.clone(), &base, &original, filtered, &excluded)
            .is_err()
    );

    assert!(
        TrustContext::new(
            &fresh,
            [9; 32],
            Selector::preset(Preset::Any),
            DOMAIN,
            Some("baseline")
        )
        .is_err()
    );
    assert!(
        TrustContext::new(
            &VerifiedHistory::new(MINIMUM),
            views[1],
            Selector::preset(Preset::Any),
            DOMAIN,
            Some("baseline")
        )
        .is_err()
    );
    for (revision, later) in [
        (2, vec!["future.value"]),
        (3, vec!["future.value"]),
        (1, vec!["future.value", "future.other", "index-roots"]),
    ] {
        let mut changed_history = VerifiedHistory::new(MINIMUM);
        for tree in [&base, &ours, &original] {
            retain_tree(&mut changed_history, tree);
        }
        for (i, record) in records.iter().enumerate() {
            let verified =
                with_request(|request| verify(record, &issuer_keys(), request, 4)).unwrap();
            let selected = if i == 2 {
                Selection::Recorded(RecordedContext::new(revision, 3, &later).unwrap())
            } else {
                selection(i)
            };
            changed_history
                .insert_commit_selected(verified, selected)
                .unwrap();
        }
        let changed = TrustContext::new(
            &changed_history,
            views[1],
            Selector::preset(Preset::Any),
            DOMAIN,
            Some("baseline"),
        )
        .unwrap();
        assert!(changed.accepts_path(b"file"));
        assert_ne!(changed.canonical_context(), models[1]);
        assert!(
            decoded
                .clone()
                .bind_fold_verified(
                    vec![matching[0].clone(), changed],
                    &base,
                    &original,
                    filtered,
                    &excluded
                )
                .is_err()
        );
    }
    let mut legacy_history = VerifiedHistory::new(MINIMUM);
    for tree in [&base, &ours, &original] {
        retain_tree(&mut legacy_history, tree);
    }
    for record in &records {
        let verified = with_request(|request| verify(record, &issuer_keys(), request, 4)).unwrap();
        legacy_history.insert_commit(verified).unwrap();
    }
    let legacy = views.map(|view| {
        TrustContext::new(
            &legacy_history,
            view,
            Selector::preset(Preset::Any),
            DOMAIN,
            Some("baseline"),
        )
        .unwrap()
    });
    assert!(
        decoded
            .clone()
            .bind_fold_verified(legacy.to_vec(), &base, &original, filtered, &excluded)
            .is_err()
    );
    assert!(
        decoded
            .clone()
            .bind_fold_verified(
                vec![matching[1].clone(), matching[0].clone()],
                &base,
                &original,
                filtered,
                &excluded
            )
            .is_err()
    );
    for wrong_exclusions in [
        vec![],
        vec![b"file".to_vec()],
        vec![b"new".to_vec(), b"file".to_vec()],
        vec![b"file".to_vec(), b"file".to_vec()],
    ] {
        assert!(
            decoded
                .clone()
                .bind_fold_verified(
                    matching.clone(),
                    &base,
                    &original,
                    filtered,
                    &wrong_exclusions
                )
                .is_err()
        );
    }
    assert!(
        decoded
            .bind_fold_verified(matching, &base, &original, &original, &excluded)
            .is_err()
    );
}

fn retain_shared_context_entries(
    history: &mut VerifiedHistory,
    root: Digest,
    selected: Selection,
) -> Digest {
    let original = retain_selected(history, root, "same signed view", selected.clone());
    let mut record = history.commit(&original).unwrap().commit().clone();
    record
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .push(crate::refs::EntryReceipt {
            root,
            path: b"twin".to_vec(),
            origin: crate::refs::EntryOrigin::Current,
            attributes: None,
            reintroduced_from: None,
            disclosure_proof: None,
        });
    record.signature = None;
    let signed = with_request(|request| {
        crate::provenance::sign(record, &[9; 32], &issuer_keys(), request, 4)
    })
    .unwrap();
    let verified =
        with_request(|request| verify(signed.commit(), &issuer_keys(), request, 4)).unwrap();
    assert_eq!(signed.identity(), verified.identity());
    let view = verified.identity();
    history.insert_commit_selected(verified, selected).unwrap();
    view
}

#[test]
fn recorded_current_selection_has_distinct_memo_keys_with_identical_registered_bytes() {
    let tree = input(&[(b"file", b"target"), (b"twin", b"target")]);
    let mut histories = Vec::new();
    let mut views = Vec::new();
    for current in [2, 3] {
        let mut history = VerifiedHistory::new(MINIMUM);
        retain_tree(&mut history, &tree);
        let view = retain_shared_context_entries(
            &mut history,
            tree.root_identity(),
            Selection::Recorded(RecordedContext::new(1, current, &["future.value"]).unwrap()),
        );
        histories.push(history);
        views.push(view);
    }
    assert_eq!(views[0], views[1]);
    let a = TrustContext::new(
        &histories[0],
        views[0],
        Selector::preset(Preset::Any),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    let b = TrustContext::new(
        &histories[1],
        views[1],
        Selector::preset(Preset::Any),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert_eq!(a.canonical_context(), b.canonical_context());
    assert!(a.memo.borrow().is_empty());
    assert!(b.memo.borrow().is_empty());
    assert!(a.accepts_path(b"file"));
    assert!(b.accepts_path(b"file"));
    assert!(a.accepts_path(b"twin"));
    assert!(b.accepts_path(b"twin"));
    let identical = TrustContext::new(
        &histories[0],
        views[0],
        Selector::preset(Preset::Any),
        DOMAIN,
        Some("baseline"),
    )
    .unwrap();
    assert_eq!(identical.canonical_context(), a.canonical_context());
    assert!(identical.accepts_path(b"twin"));
    let am = a.memo.borrow();
    let bm = b.memo.borrow();
    assert_eq!(am.len(), 1);
    assert_eq!(bm.len(), 1);
    let (ak, av) = am.first_key_value().unwrap();
    let (bk, bv) = bm.first_key_value().unwrap();
    assert_ne!(ak, bk);
    assert_eq!(identical.memo.borrow().first_key_value().unwrap().0, ak);
    assert_ne!(a.selection, b.selection);
    assert_eq!(a.selection, identical.selection);
    assert_eq!(av, bv);
    assert!(a.accepts_path(b"file"));
    assert_eq!(a.memo.borrow().len(), 1);
    assert!(!a.accepts_path(b"missing"));
    assert_eq!(a.memo.borrow().len(), 1);
}

#[test]
fn recorded_canonical_graft_domains_refuse_shared_root_ambiguity_in_both_orders() {
    let shared = Tree::build(vec![], None, MINIMUM, TreeUse::Ordinary).unwrap();
    let defaults = Defaults {
        store: "ordinary",
        private_domain: "private:caller",
        home: "local",
    };
    let names = ["private:left", "private:right"];
    for order in [[0, 1], [1, 0]] {
        let mut domains = crate::algebra::OperationDomains::new();
        for (step, i) in order.into_iter().enumerate() {
            let domain = text(names[i]);
            let parent = Tree::build(
                vec![LeafItem {
                    key: b"graft".to_vec(),
                    entry: Entry {
                        kind: EntryKind::Tree {
                            root: shared.root_identity(),
                            props: None,
                        },
                        attrs: vec![],
                        attrs_present: false,
                        xattrs: vec![],
                        xattrs_present: false,
                        provenance: None,
                    },
                }],
                Some(vec![Property {
                    name: "domain",
                    value: &domain,
                }]),
                MINIMUM,
                TreeUse::Ordinary,
            )
            .unwrap();
            let parent_props = parent.props().unwrap();
            let selected = Selection::Recorded(
                RecordedContext::new(if step == 0 { 1 } else { 3 }, 3, &[]).unwrap(),
            );
            let layers = [
                RootLayer {
                    properties: parent_props,
                    overrides: &[],
                },
                RootLayer {
                    properties: shared.props().unwrap_or(&[]),
                    overrides: &[],
                },
            ];
            let effective = selected.resolve(&layers, defaults).unwrap();
            assert_eq!(
                effective.get(crate::properties::PropertyName::Domain),
                Some(&crate::properties::Value::Text(names[i]))
            );
            let bound = domains.bind_resolved(shared.root_identity(), &effective);
            if step == 0 {
                bound.unwrap();
                domains
                    .bind_resolved(shared.root_identity(), &effective)
                    .unwrap();
            } else {
                assert!(
                    matches!(bound, Err(crate::algebra::DomainError::Ambiguous(root)) if root == shared.root_identity())
                );
            }
        }
    }
}
