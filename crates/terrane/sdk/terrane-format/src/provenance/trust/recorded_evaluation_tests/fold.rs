//! Replays recorded interpretation and original-root bindings through executable folds.
//!
//! Independent caller configuration accompanies actual signed/verified histories.
//! Literal complete context/recipe models do not supply executable authority.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture failures intentionally panic in tests."
)]

use super::*;
use crate::algebra::{MergePolicy, Recipe, Retirement, Roots, fold, merge};
use crate::tree_builder::Tree;
use crate::tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse};

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
fn fresh_history(trees: [&Tree<'_>; 3], records: &[Commit; 2]) -> (VerifiedHistory, [Digest; 2]) {
    let mut history = VerifiedHistory::new(MINIMUM);
    for tree in trees {
        retain_tree(&mut history, tree);
    }
    let mut views = [[0; 32]; 2];
    for (index, record) in records.iter().enumerate() {
        let verified = with_request(|request| verify(record, &issuer_keys(), request, 4)).unwrap();
        views[index] = verified.identity();
        history.insert_commit(verified).unwrap();
    }
    (history, views)
}

fn contexts(
    history: &VerifiedHistory,
    views: [Digest; 2],
    roots: [Digest; 2],
) -> Vec<TrustContext> {
    let selections = BTreeMap::from([
        (
            views[0],
            Selection::Recorded(RecordedContext::new(3, 3, &["future.value"]).unwrap()),
        ),
        (
            views[1],
            Selection::Recorded(
                RecordedContext::new(1, 3, &["index-roots", "future.value"]).unwrap(),
            ),
        ),
    ]);
    let history = history.fixture_with_selections(&selections).unwrap();
    [
        (3, &["future.value"][..]),
        (1, &["index-roots", "future.value"][..]),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (revision, later))| {
        TrustContext::new_with_recorded(
            &history,
            views[index],
            Selector::preset(Preset::Any),
            DOMAIN,
            Some("baseline"),
            Some((
                views[index],
                roots[index],
                RecordedContext::new(revision, 3, later).unwrap(),
            )),
        )
        .unwrap()
    })
    .collect()
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
fn recorded_fold_replays_original_view_interpretations_before_recipe_rebinding() {
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
    let views = [
        retain_view(&mut history, roots[1]),
        retain_view(&mut history, roots[2]),
    ];
    let records = views.map(|view| history.commit(&view).unwrap().commit().clone());
    let evaluated = contexts(&history, views, [roots[1], roots[2]]);
    let models = [
        context_model(views[0], roots[1], 3, &["future.value"]),
        context_model(views[1], roots[2], 1, &["future.value", "index-roots"]),
    ];
    for (index, evaluator) in evaluated.iter().enumerate() {
        assert_eq!(evaluator.canonical_context(), models[index]);
        assert_eq!(evaluator.view_root(), roots[index + 1]);
        assert!(evaluator.accepts_path(b"file"));
        let fields = super::super::context::decode(evaluator.canonical_context()).unwrap();
        assert_eq!(fields.version, 3);
        assert_eq!(fields.view, views[index]);
        assert_eq!(fields.domain, DOMAIN);
        assert_eq!(fields.selector, array(&[text("preset"), text("any")]));
        assert_eq!(fields.baseline, Some("baseline"));
        assert_eq!(fields.minimum, MINIMUM);
        assert_eq!(fields.selected, None);
        let recorded = fields.recorded.unwrap();
        assert_eq!(recorded.root, roots[index + 1]);
        assert_eq!(recorded.revision, if index == 0 { 3 } else { 1 });
        assert_eq!(
            recorded.behavioral,
            vocabulary(if index == 0 { 3 } else { 1 })
        );
        assert_eq!(
            recorded.later,
            if index == 0 {
                vec!["future.value"]
            } else {
                vec!["future.value", "index-roots"]
            }
        );
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
    assert_eq!(fresh_views, views);
    let matching = contexts(&fresh, views, [roots[1], roots[2]]);
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

    // Missing/wrong/changed original associations fail before any legacy fallback.
    let recorded = RecordedContext::new(1, 3, &["future.value", "index-roots"]).unwrap();
    for association in [
        None,
        Some((views[0], roots[2], recorded.clone())),
        Some((views[1], filtered.root_identity(), recorded.clone())),
    ] {
        assert!(
            TrustContext::new_with_recorded(
                &fresh,
                views[1],
                Selector::preset(Preset::Any),
                DOMAIN,
                Some("baseline"),
                association
            )
            .is_err()
        );
    }
    assert!(
        TrustContext::new_with_recorded(
            &VerifiedHistory::new(MINIMUM),
            views[1],
            Selector::preset(Preset::Any),
            DOMAIN,
            Some("baseline"),
            Some((views[1], roots[2], recorded.clone()))
        )
        .is_err()
    );
    for (revision, later) in [
        (2, vec!["future.value"]),
        (3, vec!["future.value"]),
        (1, vec!["future.value", "future.other", "index-roots"]),
    ] {
        let changed_context = RecordedContext::new(revision, 3, &later).unwrap();
        let changed_history = fresh
            .fixture_with_selections(&BTreeMap::from([
                (
                    views[0],
                    Selection::Recorded(RecordedContext::new(3, 3, &["future.value"]).unwrap()),
                ),
                (views[1], Selection::Recorded(changed_context.clone())),
            ]))
            .unwrap();
        let changed = TrustContext::new_with_recorded(
            &changed_history,
            views[1],
            Selector::preset(Preset::Any),
            DOMAIN,
            Some("baseline"),
            Some((views[1], roots[2], changed_context)),
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
    let legacy_history = fresh
        .fixture_with_selections(&BTreeMap::from([
            (views[0], Selection::Legacy),
            (views[1], Selection::Legacy),
        ]))
        .unwrap();
    let legacy = views.map(|view| {
        assert_eq!(
            legacy_history.property_selection(view).unwrap(),
            Selection::Legacy
        );
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
