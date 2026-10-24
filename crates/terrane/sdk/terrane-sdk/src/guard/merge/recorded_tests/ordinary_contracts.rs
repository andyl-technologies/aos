//! Checks ordinary merge selection and actual core evaluator/fold replay.
//!
//! Independently supplied interpretation data cannot establish native protected
//! history or admission. Core fixtures use actual token/signature verification.
#![allow(
    clippy::unwrap_used,
    reason = "fixture refusal is an assertion failure"
)]

use crate::guard::merge::*;
use std::sync::Arc;
use terrane_format::algebra::{MergePolicy, Recipe, Retirement, fold, merge};
use terrane_format::identity::TERRANE_V1;
use terrane_format::properties::selected::Selection;
use terrane_format::properties::semantics::{
    RecordedContext,
    associations::{RecordedAssociation, RecordedAssociations},
};
use terrane_format::properties::{PropertyName, Value};
use terrane_format::provenance::{TrustContext, verify};
use terrane_format::refs::Commit;
use terrane_format::tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse};

#[path = "fixtures.rs"]
mod fixtures;
use fixtures::*;

const DOMAIN: &str = "private:fold";

fn evidence(root: Digest, wires: &[(Digest, Vec<u8>)]) -> TreeEvidence {
    TreeEvidence {
        usage: TreeUse::Ordinary,
        ordinary_roots: wires.iter().map(|(root, _)| *root).collect(),
        commit: None,
        root,
        default_domain: "private:ordinary".to_owned(),
        nodes: wires.iter().cloned().collect(),
        roots: wires.iter().map(|(root, _)| *root).collect(),
        grafts: None,
    }
}

fn digest(wire: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(IdentityKind::Node, wire)
        .unwrap()
        .terrane_v1_digest()
        .unwrap()
}

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "ordinary-store",
        private_domain: "private:ordinary",
        home: "local",
    }
}

fn association(view: Digest, root: Digest, revision: u64, later: &[&str]) -> RecordedAssociation {
    RecordedAssociation::new(
        view,
        root,
        RecordedContext::new(revision, 3, later).unwrap(),
    )
}

fn historical_selection(index: usize) -> Selection {
    let (revision, later): (u64, &[&str]) = match index {
        0 => (2, &["future.value"]),
        1 => (3, &["future.value"]),
        2 => (1, &["future.value", "index-roots"]),
        _ => panic!("fixed three-input fixture"),
    };
    Selection::Recorded(RecordedContext::new(revision, 3, later).unwrap())
}

fn installed(views: [Digest; 3], roots: [Digest; 3]) -> ReadInterpretations {
    ReadInterpretations::Recorded(Arc::new(
        RecordedAssociations::new([
            association(views[0], roots[0], 2, &["future.value"]),
            association(views[1], roots[1], 3, &["future.value"]),
            association(views[2], roots[2], 1, &["future.value", "index-roots"]),
        ])
        .unwrap(),
    ))
}

fn select(
    mode: &ReadInterpretations,
    views: [Digest; 3],
    inputs: [&TreeEvidence; 3],
) -> Result<[SelectedReadInterpretation; 3], StoreFailure> {
    select_inputs(
        mode,
        std::array::from_fn(|i| (views[i], inputs[i].root, inputs[i])),
        [views[1], views[2]],
    )
}

#[test]
fn recorded_merge_input_configuration_requires_all_original_view_root_pairs() {
    let wire = node(&[(b"file", file())], &[]);
    let root = digest(&wire);
    let mut ordinary_history = VerifiedHistory::new(MINIMUM);
    assert_eq!(store(&mut ordinary_history, wire.clone()), root);
    let input = evidence(root, &[(root, wire.clone())]);
    let views = std::array::from_fn(|index| {
        retain_view_selected(
            &mut ordinary_history,
            root,
            ["base", "ours", "theirs"][index],
            historical_selection(index),
        )
    });

    // Legacy evaluation needs its own immutable selection, even for identical
    // signed views and canonical nodes.
    let mut legacy_history = VerifiedHistory::new(MINIMUM);
    assert_eq!(store(&mut legacy_history, wire), root);
    let legacy_views =
        ["base", "ours", "theirs"].map(|message| retain_view(&mut legacy_history, root, message));
    assert_eq!(legacy_views, views);
    assert_ne!(views[0], views[1]);
    assert_ne!(views[1], views[2]);
    let mode = installed(views, [root; 3]);
    let chosen = select(&mode, views, [&input; 3]).unwrap();
    for (index, selected) in chosen.iter().enumerate() {
        let SelectedReadInterpretation::Recorded(entry) = selected else {
            panic!("explicit selection")
        };
        assert_eq!(entry.view(), views[index]);
        assert_eq!(entry.original_root(), root);
        assert_eq!(entry.revision(), [2, 3, 1][index]);
        let evaluator = selected
            .evaluator(
                &ordinary_history,
                (views[index], root),
                Selector::preset(Preset::Any),
                DOMAIN,
                Some("baseline"),
            )
            .unwrap();
        let later: &[&str] = if index == 2 {
            &["future.value", "index-roots"]
        } else {
            &["future.value"]
        };
        assert_eq!(
            evaluator.canonical_context(),
            context_model(views[index], root, [2, 3, 1][index], later)
        );
        assert!(evaluator.accepts_path(b"file"));

        let legacy = SelectedReadInterpretation::Legacy
            .evaluator(
                &legacy_history,
                (views[index], root),
                Selector::preset(Preset::Any),
                DOMAIN,
                Some("baseline"),
            )
            .unwrap();
        let legacy_model = array(&[
            uint(1),
            bytes(&views[index]),
            text(DOMAIN),
            bytes(&array(&[text("preset"), text("any")])),
            text("baseline"),
            uint(MINIMUM),
        ]);
        assert_eq!(legacy.canonical_context(), legacy_model);
        assert_ne!(legacy.canonical_context(), evaluator.canonical_context());
        assert!(legacy.accepts_path(b"file"));
    }
    for missing in 0..3 {
        let table = RecordedAssociations::new(
            (0..3)
                .filter(|i| *i != missing)
                .map(|i| association(views[i], root, 3, &[])),
        )
        .unwrap();
        assert!(
            select(
                &ReadInterpretations::Recorded(Arc::new(table)),
                views,
                [&input; 3]
            )
            .is_err()
        );
    }
    for wrong in 0..3 {
        let mut pairs = views.map(|view| (view, root, &input));
        pairs[wrong].1 = [9; 32];
        assert!(select_inputs(&mode, pairs, [views[1], views[2]]).is_err());
        let table = RecordedAssociations::new(
            (0..3).map(|i| association(views[i], if i == wrong { [9; 32] } else { root }, 3, &[])),
        )
        .unwrap();
        assert!(
            select(
                &ReadInterpretations::Recorded(Arc::new(table)),
                views,
                [&input; 3]
            )
            .is_err()
        );
    }
    assert!(
        select_inputs(
            &mode,
            views.map(|view| (view, root, &input)),
            [views[2], views[1]]
        )
        .is_err()
    );
    assert!(
        select(
            &ReadInterpretations::Recorded(Arc::new(RecordedAssociations::default())),
            views,
            [&input; 3]
        )
        .is_err()
    );
    assert!(
        RecordedAssociations::new([
            association(views[0], root, 1, &[]),
            association(views[0], root, 3, &[])
        ])
        .is_err()
    );
    assert_eq!(
        select(&ReadInterpretations::Legacy, views, [&input; 3]).unwrap(),
        std::array::from_fn(|_| SelectedReadInterpretation::Legacy)
    );
}

#[test]
fn recorded_merge_occurrences_preserve_per_view_fences_and_refuse_domain_ambiguity() {
    let child_wire = node(&[(b"file", file())], &[("index-roots", uint(0))]);
    let child = digest(&child_wire);
    let parent_wire = node(
        &[
            (b"a", graft(child, &[("retain", text("forever"))])),
            (b"b", graft(child, &[("retain", text("gc"))])),
        ],
        &[],
    );
    let root = digest(&parent_wire);
    let input = evidence(root, &[(root, parent_wire), (child, child_wire.clone())]);
    let mode = ReadInterpretations::Recorded(Arc::new(
        RecordedAssociations::new([
            association([1; 32], root, 1, &["index-roots"]),
            association([2; 32], root, 2, &[]),
            association([3; 32], root, 3, &[]),
        ])
        .unwrap(),
    ));
    let selected = select(&mode, [[1; 32], [2; 32], [3; 32]], [&input; 3]).unwrap();
    let occurrences = input.occurrences(MINIMUM).unwrap();
    let mut paths = BTreeSet::new();
    for occurrence in occurrences.iter().filter(|o| o.root == child) {
        paths.insert(occurrence.path.clone());
        let layers: Vec<_> = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect();
        assert_eq!(layers.last().unwrap().properties[0].value, b"\x00");
        let resolved = selected[0].resolve(&layers, defaults()).unwrap();
        let expected = if occurrence.path == b"/a" {
            "forever"
        } else {
            "gc"
        };
        assert_eq!(
            resolved.get(PropertyName::Retain),
            Some(&Value::Text(expected))
        );
        for active in &selected[1..] {
            assert!(active.resolve(&layers, defaults()).is_err());
        }
    }
    assert_eq!(paths, BTreeSet::from([b"/a".to_vec(), b"/b".to_vec()]));
    bind_occurrence_domains(
        &mut OperationDomains::new(),
        &input,
        &selected[0],
        defaults(),
        MINIMUM,
    )
    .unwrap();
    assert!(
        bind_occurrence_domains(
            &mut OperationDomains::new(),
            &input,
            &selected[1],
            defaults(),
            MINIMUM
        )
        .is_err()
    );
    assert_eq!(input.nodes[&child], child_wire);

    // Equal physical storage does not select a view's fence. Distinct inherited
    // labels for that physical root must refuse in either insertion order.
    let shared_wire = node(&[(b"file", file())], &[]);
    let shared = digest(&shared_wire);
    let make = |label: &str| {
        let wire = node(
            &[(b"graft", graft(shared, &[]))],
            &[("domain", text(label))],
        );
        let root = digest(&wire);
        evidence(root, &[(root, wire), (shared, shared_wire.clone())])
    };
    let left = make("private:left");
    let right = make("private:right");
    for inputs in [[&left, &right], [&right, &left]] {
        let mut domains = OperationDomains::new();
        let selections = [
            SelectedReadInterpretation::Recorded(Arc::new(association(
                [4; 32],
                inputs[0].root,
                1,
                &[],
            ))),
            SelectedReadInterpretation::Recorded(Arc::new(association(
                [5; 32],
                inputs[1].root,
                3,
                &[],
            ))),
        ];
        bind_occurrence_domains(&mut domains, inputs[0], &selections[0], defaults(), MINIMUM)
            .unwrap();
        assert!(
            bind_occurrence_domains(&mut domains, inputs[1], &selections[1], defaults(), MINIMUM)
                .is_err()
        );
    }
    let mut domains = OperationDomains::new();
    for revision in [1, 3] {
        let selected = SelectedReadInterpretation::Recorded(Arc::new(association(
            [revision as u8; 32],
            left.root,
            revision,
            &[],
        )));
        bind_occurrence_domains(&mut domains, &left, &selected, defaults(), MINIMUM).unwrap();
    }
    // A recognized later structural name on a graft remains raw/inert only in
    // the independently configured legacy revision, never active by spelling.
    let pointer = map(vec![
        (
            text("value"),
            map(vec![(text("uid"), text(&"ab".repeat(32)))]),
        ),
        (text("inherit"), vec![0xf4]),
    ]);
    let owner = [Property {
        name: "index-roots",
        value: &pointer,
    }];
    let graft_layer = [RootLayer {
        properties: &[],
        overrides: &owner,
    }];
    assert!(selected[0].resolve(&graft_layer, defaults()).is_ok());
    assert!(selected[1].resolve(&graft_layer, defaults()).is_err());
}

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
fn fresh_history(
    trees: [&Tree<'_>; 3],
    records: &[Commit; 3],
    selections: [Selection; 3],
) -> (VerifiedHistory, [Digest; 3]) {
    let mut history = VerifiedHistory::new(MINIMUM);
    for tree in trees {
        retain_tree(&mut history, tree);
    }
    let mut views = [[0; 32]; 3];
    for (index, (record, selection)) in records.iter().zip(selections).enumerate() {
        let verified = with_request(|request| verify(record, &issuer_keys(), request, 4)).unwrap();
        views[index] = verified.identity();
        history.insert_commit_selected(verified, selection).unwrap();
    }
    (history, views)
}

fn contexts(
    history: &VerifiedHistory,
    views: [Digest; 3],
    trees: [&Tree<'_>; 3],
) -> Vec<TrustContext> {
    let roots = trees.map(Tree::root_identity);
    let inputs = trees.map(|tree| {
        evidence(
            tree.root_identity(),
            &tree
                .nodes()
                .map(|node| (node.identity(), node.encoded().to_vec()))
                .collect::<Vec<_>>(),
        )
    });
    let selected = select(
        &installed(views, roots),
        views,
        [&inputs[0], &inputs[1], &inputs[2]],
    )
    .unwrap();
    [1, 2]
        .map(|i| {
            selected[i]
                .evaluator(
                    history,
                    (views[i], roots[i]),
                    Selector::preset(Preset::Any),
                    DOMAIN,
                    Some("baseline"),
                )
                .unwrap()
        })
        .to_vec()
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
fn recorded_merge_contexts_bind_original_interpretations_through_fold_replay() {
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
        retain_view_selected(&mut history, roots[0], "base", historical_selection(0)),
        retain_view_selected(&mut history, roots[1], "ours", historical_selection(1)),
        retain_view_selected(&mut history, roots[2], "theirs", historical_selection(2)),
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

    let policy = terrane_format::algebra::TrustContext::from_verified(evaluated).unwrap();
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

    let (fresh, fresh_views) = fresh_history(
        [&base, &ours, &original],
        &records,
        std::array::from_fn(historical_selection),
    );
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
            Some((views[1], roots[2], recorded))
        )
        .is_err()
    );
    for (revision, later) in [
        (2, vec!["future.value"]),
        (3, vec!["future.value"]),
        (1, vec!["future.value", "future.other", "index-roots"]),
    ] {
        let changed_context = RecordedContext::new(revision, 3, &later).unwrap();
        let mut selections = std::array::from_fn(historical_selection);
        selections[2] = Selection::Recorded(changed_context.clone());
        let (changed_history, changed_views) =
            fresh_history([&base, &ours, &original], &records, selections);
        assert_eq!(changed_views, all_views);

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
        assert_eq!(
            changed.canonical_context(),
            context_model(views[1], roots[2], revision, &later)
        );
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
    let (legacy_history, legacy_views) = fresh_history(
        [&base, &ours, &original],
        &records,
        std::array::from_fn(|_| Selection::Legacy),
    );
    assert_eq!(legacy_views, all_views);
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
    for (index, context) in legacy.iter().enumerate() {
        assert_eq!(
            context.canonical_context(),
            array(&[
                uint(1),
                bytes(&views[index]),
                text(DOMAIN),
                bytes(&array(&[text("preset"), text("any")])),
                text("baseline"),
                uint(MINIMUM),
            ])
        );
    }
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
