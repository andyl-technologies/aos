//! Checks explicit snapshot interpretation against fixed ordinary property models.

#![allow(clippy::unwrap_used)]

use super::*;
use crate::properties::semantics::RecordedContext;
use crate::{
    auth::PrincipalKind,
    provenance::root_context::RootChangePlan,
    refs::{Commit, CommitSource, ProfilePair, Provenance},
    tree_builder::Tree,
    tree_format::{Entry, LeafItem, TreeUse},
};

const MINIMUM: u64 = 262144;

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "local",
        home: "west",
        private_domain: "private:test",
    }
}

fn context(revision: u64) -> RecordedContext {
    RecordedContext::new(revision, 3, &[]).unwrap()
}

fn text(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    crate::cbor::write_text(&mut bytes, value);
    bytes
}

fn binding(value: &[u8], inherit: bool) -> Vec<u8> {
    let mut bytes = b"\xa2\x65value".to_vec();
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(b"\x67inherit");
    bytes.push(if inherit { 0xf5 } else { 0xf4 });
    bytes
}

fn owner_binding() -> Vec<u8> {
    let mut value = b"\xa1\x63uid".to_vec();
    value.extend_from_slice(&text(&"ab".repeat(32)));
    binding(&value, false)
}

fn property<'a>(name: &'a str, value: &'a [u8]) -> Property<'a> {
    Property { name, value }
}

fn graft<'a>(key: &[u8], root: Digest, overrides: Option<Vec<Property<'a>>>) -> LeafItem<'a> {
    LeafItem {
        key: key.to_vec(),
        entry: Entry {
            kind: EntryKind::Tree {
                root,
                props: overrides,
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        },
    }
}

fn store_tree(
    history: &mut VerifiedHistory,
    rows: Vec<LeafItem<'_>>,
    props: Vec<Property<'_>>,
) -> Digest {
    let tree = Tree::build(rows, Some(props), MINIMUM, TreeUse::Ordinary).unwrap();
    let root = tree.root_identity();
    let nodes = tree
        .nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect::<Vec<_>>();
    history.insert_tree(root, &nodes).unwrap();
    root
}

fn unsigned(tree: Digest) -> Commit {
    Commit {
        tree,
        parents: Vec::new(),
        timestamp: 1,
        message: String::new(),
        packs: None,
        signature: None,
        provenance: Provenance {
            issuer: "ordinary".into(),
            token_id: [0; 16],
            subject: "writer".into(),
            kind: PrincipalKind::Human,
            workload_identity: None,
            process: "fixture".into(),
            observed_at: 1,
            writer_epoch: 0,
            source: CommitSource::Built,
            embedded_token: None,
        },
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
    }
}

// Fixed original 33 defaults; no compiled registry or resolver is an oracle.
fn historical_defaults() -> Vec<(&'static str, PolicyValue)> {
    use PolicyValue::*;
    vec![
        ("acl", Grants(vec![])),
        ("baseline", Unset),
        ("chunk", Text("cdc-1m".into())),
        ("classify", Names(vec![])),
        ("compaction_threshold", Unsigned(5000)),
        ("compression", Text("zstd".into())),
        ("dedup", Text("domain".into())),
        ("degraded", Text("refuse".into())),
        ("domain", Text("private:test".into())),
        ("durability", Text("region".into())),
        ("encryption", Text("none".into())),
        ("gap_merge_bytes", Unsigned(262144)),
        ("hashes", Names(vec![])),
        ("home", Text("west".into())),
        ("index", Names(vec![])),
        (
            "merge",
            Names(vec!["prefer-trusted".into(), "keep-conflict".into()]),
        ),
        ("on-release", Text("keep".into())),
        ("passthrough", Text("auto".into())),
        ("prefetch", Text("profile".into())),
        ("quota", Unset),
        ("reassembly", Text("smart".into())),
        ("redundancy", Text("none".into())),
        ("reflog_retain", Unsigned(7776000)),
        ("replicate", Text("async".into())),
        ("retain", Text("gc".into())),
        ("span_max_bytes", Unsigned(16777216)),
        ("store", Text("local".into())),
        ("strict-attrs", Boolean(false)),
        ("trust", Text("any".into())),
        ("warm", Names(vec![])),
        ("whole_pack_threshold", Unsigned(5000)),
        ("wipe", Text("zero".into())),
        ("writers", Text("one".into())),
    ]
}

#[test]
fn snapshot_recorded_revisions_preserve_defaults_and_inert_names() {
    for revision in 1..=3 {
        let root = state(
            [1; 32],
            b"/".to_vec(),
            &[vec![]],
            defaults(),
            crate::properties::selected::Selection::Recorded(context(revision)),
        )
        .unwrap();
        let mut expected = historical_defaults();
        if revision >= 2 {
            expected.push(("index-roots", PolicyValue::IndexRoots(vec![])));
        }
        expected.sort_by_key(|(name, _)| *name);
        let mut actual = root
            .effective
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect::<Vec<_>>();
        actual.sort_by_key(|(name, _)| *name);
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), if revision == 1 { 33 } else { 34 });
    }

    let invalid_roots = binding(&[0], true);
    let invalid_gaps = [0];
    let layers = [vec![
        property("index-gaps", &invalid_gaps),
        property("index-roots", &invalid_roots),
    ]];
    let old = RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap();
    let root = state(
        [1; 32],
        b"/".to_vec(),
        &layers,
        defaults(),
        crate::properties::selected::Selection::Recorded(old),
    )
    .unwrap();
    assert_eq!(
        root.local,
        vec![
            ("index-gaps".into(), vec![0]),
            ("index-roots".into(), invalid_roots.clone())
        ]
    );
    assert_eq!(root.effective.len(), 33);
    let second = RecordedContext::new(2, 3, &["index-gaps"]).unwrap();
    let root = state(
        [1; 32],
        b"/".to_vec(),
        &[vec![property("index-gaps", &invalid_gaps)]],
        defaults(),
        crate::properties::selected::Selection::Recorded(second),
    )
    .unwrap();
    assert_eq!(root.local, vec![("index-gaps".into(), vec![0])]);
    assert_eq!(root.effective.len(), 34);
}

#[test]
fn snapshot_recorded_revisions_follow_full_and_parent_graft_paths() {
    let domain = text("public");
    let local_owner = owner_binding();
    let left = [0];
    let right = [1];
    let mut history = VerifiedHistory::new(MINIMUM);
    let child = store_tree(
        &mut history,
        vec![],
        vec![property("index-roots", &local_owner)],
    );
    let parent = store_tree(
        &mut history,
        vec![
            graft(b"left", child, Some(vec![property("index-gaps", &left)])),
            graft(b"right", child, Some(vec![property("index-gaps", &right)])),
        ],
        vec![
            property("domain", &domain),
            property("index-roots", &local_owner),
        ],
    );
    let second = RecordedContext::new(2, 3, &["index-gaps"]).unwrap();
    let snapshot = complete_with_properties(&history, parent, defaults(), &second).unwrap();
    assert_eq!(snapshot.roots.len(), 3);
    for (path, value) in [
        (b"/left".as_slice(), &left[..]),
        (b"/right".as_slice(), &right[..]),
    ] {
        let selected =
            at_path_with_properties(&history, parent, path, defaults(), &second).unwrap();
        assert_eq!(selected.identity, child);
        assert!(selected.same_policy(&snapshot.roots[path]));
        assert!(
            selected
                .local
                .contains(&("index-gaps".into(), value.to_vec()))
        );
        assert_eq!(selected.domain, "public");
        assert!(selected.effective.contains(&(
            PropertyName::IndexRoots,
            PolicyValue::IndexRoots(vec![("uid".into(), [0xab; 32])])
        )));
    }
    assert!(
        !snapshot.roots[b"/left".as_slice()].same_policy(&snapshot.roots[b"/right".as_slice()])
    );

    // A noninheriting parent binding must not fill an unbound child.
    let empty_child = store_tree(&mut history, vec![], vec![]);
    let owner = store_tree(
        &mut history,
        vec![graft(b"child", empty_child, None)],
        vec![
            property("domain", &domain),
            property("index-roots", &local_owner),
        ],
    );
    let selected =
        at_path_with_properties(&history, owner, b"/child", defaults(), &context(2)).unwrap();
    assert!(
        selected
            .effective
            .contains(&(PropertyName::IndexRoots, PolicyValue::IndexRoots(vec![])))
    );

    // Both the full path and its independently resolved parent accept these
    // malformed active bindings only under the same trusted legacy context.
    let inert = binding(&[0], true);
    let owner = store_tree(
        &mut history,
        vec![graft(b"child", empty_child, None)],
        vec![property("domain", &domain), property("index-roots", &inert)],
    );
    let legacy = RecordedContext::new(1, 3, &["index-roots"]).unwrap();
    let full = complete_with_properties(&history, owner, defaults(), &legacy).unwrap();
    let path = at_path_with_properties(&history, owner, b"/child", defaults(), &legacy).unwrap();
    assert!(path.same_policy(&full.roots[b"/child".as_slice()]));
    assert_eq!(path.effective.len(), 33);
    assert!(at_path_with_properties(&history, owner, b"/child", defaults(), &context(2)).is_err());
}

#[test]
fn snapshot_recorded_revisions_reject_untrusted_names_and_placement() {
    assert!(RecordedContext::new(4, 3, &[]).is_err());
    assert!(RecordedContext::new(1, 3, &["index-gaps", "index-gaps"]).is_err());
    assert!(RecordedContext::new(2, 3, &["index-roots"]).is_err());
    let owner = owner_binding();
    let gap = binding(&text(&"ab".repeat(32)), false);
    for (revision, name, bytes) in [
        (1, "index-roots", &owner),
        (2, "index-gaps", &gap),
        (3, "index-gaps", &gap),
    ] {
        assert!(
            state(
                [1; 32],
                b"/".to_vec(),
                &[vec![property(name, bytes)]],
                defaults(),
                crate::properties::selected::Selection::Recorded(context(revision))
            )
            .is_err()
        );
    }
    assert!(
        state(
            [1; 32],
            b"/".to_vec(),
            &[vec![property("future", &[0])]],
            defaults(),
            crate::properties::selected::Selection::Recorded(context(3))
        )
        .is_err()
    );

    let domain = text("public");
    let mut history = VerifiedHistory::new(MINIMUM);
    let child = store_tree(&mut history, vec![], vec![]);
    for (name, bytes) in [("index-roots", &owner), ("index-gaps", &gap)] {
        let root = store_tree(
            &mut history,
            vec![graft(b"child", child, Some(vec![property(name, bytes)]))],
            vec![property("domain", &domain)],
        );
        assert!(complete_with_properties(&history, root, defaults(), &context(3)).is_err());
        assert!(
            at_path_with_properties(&history, root, b"/child", defaults(), &context(3)).is_err()
        );
        let old = RecordedContext::new(1, 3, &["index-roots", "index-gaps"]).unwrap();
        let selected =
            at_path_with_properties(&history, root, b"/child", defaults(), &old).unwrap();
        assert_eq!(selected.local, vec![(name.into(), bytes.clone())]);
    }
    assert!(at_path_with_properties(&history, child, b"child", defaults(), &context(1)).is_err());
}

#[test]
fn authoring_plans_use_explicit_recorded_property_context() {
    let invalid_later = binding(&[0], true);
    let domain = text("public");
    let mut history = VerifiedHistory::new(MINIMUM);
    let child = store_tree(
        &mut history,
        vec![],
        vec![property("index-roots", &invalid_later)],
    );
    let root = store_tree(
        &mut history,
        vec![graft(b"child", child, None)],
        vec![property("domain", &domain)],
    );
    let candidate = unsigned(root);
    let old = RecordedContext::new(1, 3, &["index-roots"]).unwrap();
    let fresh =
        RootChangePlan::derive_fresh_with_properties(&history, &candidate, defaults(), &old)
            .unwrap();
    let ordinary =
        RootChangePlan::derive_with_properties(&history, &candidate, defaults(), &old).unwrap();
    assert_eq!(ordinary, fresh);
    assert_eq!(fresh.candidate_tree(), root);
    assert_eq!(fresh.first_parent(), None);
    assert!(fresh.fresh());
    assert!(fresh.required_admin().is_empty());
    assert_eq!(
        fresh
            .affected()
            .iter()
            .map(|root| (
                root.path(),
                root.root(),
                root.domain(),
                root.properties_changed()
            ))
            .collect::<Vec<_>>(),
        vec![
            (b"/".as_slice(), root, "public", true),
            (b"/child".as_slice(), child, "public", true)
        ]
    );
    assert!(
        RootChangePlan::derive_fresh_with_properties(&history, &candidate, defaults(), &context(2))
            .is_err()
    );
    assert!(super::super::derive_fresh_roots(&history, &candidate, defaults()).is_err());
    assert!(super::super::derive_root_changes(&history, &candidate, defaults()).is_err());
    assert_eq!(candidate.signature, None);
    assert_eq!(candidate.provenance.embedded_token, None);

    // Retained unsigned parent records exercise the same first-parent branch
    // used by the public history wrapper, without signing or scope admission.
    let previous_tree = store_tree(
        &mut history,
        vec![graft(b"child", child, None)],
        vec![
            property("domain", &domain),
            property("index-roots", &invalid_later),
        ],
    );
    let second_tree = store_tree(&mut history, vec![], vec![property("domain", &domain)]);
    let previous = unsigned(previous_tree);
    let second = unsigned(second_tree);
    let first_parent = previous.identity().unwrap();
    let second_parent = second.identity().unwrap();
    let parents = BTreeMap::from([(first_parent, previous), (second_parent, second)]);
    let mut changed = candidate.clone();
    changed.parents = vec![first_parent, second_parent];
    let mut requested = Vec::new();
    let plan = super::super::derive_with_selected_parent_tree(
        &history,
        &changed,
        defaults(),
        &old,
        |identity| {
            requested.push(identity);
            parents.get(&identity).map(|record| record.tree)
        },
    )
    .unwrap();

    assert_ne!(previous_tree, root);
    assert_eq!(requested, vec![first_parent]);
    assert_eq!(plan.first_parent(), Some(first_parent));
    assert_eq!(plan.candidate_tree(), root);
    assert!(!plan.fresh());
    assert!(plan.required_admin().is_empty());
    let mut expected_changes = vec![
        (
            b"/".as_slice(),
            root,
            super::super::RootSide::Candidate,
            "public",
            true,
        ),
        (
            b"/".as_slice(),
            previous_tree,
            super::super::RootSide::Previous,
            "public",
            true,
        ),
    ];
    // Both units share path/domain; canonical ordering compares root identity
    // before side. Sorting these literal expected fields preserves that order.
    expected_changes.sort_unstable_by_key(|change| change.1);
    assert_eq!(
        plan.affected()
            .iter()
            .map(|affected| (
                affected.path(),
                affected.root(),
                affected.side(),
                affected.domain(),
                affected.properties_changed(),
            ))
            .collect::<Vec<_>>(),
        expected_changes
    );
    assert!(
        super::super::derive_with_selected_parent_tree(
            &history,
            &changed,
            defaults(),
            &context(3),
            |identity| parents.get(&identity).map(|record| record.tree),
        )
        .is_err()
    );
    assert!(
        super::super::derive_with_selected_parent_tree(
            &history,
            &changed,
            defaults(),
            &context(1),
            |identity| parents.get(&identity).map(|record| record.tree),
        )
        .is_err()
    );

    // A missing first parent cannot silently select the available second one.
    let mut requested = Vec::new();
    assert!(
        super::super::derive_with_selected_parent_tree(
            &history,
            &changed,
            defaults(),
            &old,
            |identity| {
                requested.push(identity);
                parents
                    .get(&identity)
                    .filter(|_| identity == second_parent)
                    .map(|record| record.tree)
            },
        )
        .is_err()
    );
    assert_eq!(requested, vec![first_parent]);

    let mut copied = changed.clone();
    copied.tree = previous_tree;
    let copied = super::super::derive_with_selected_parent_tree(
        &history,
        &copied,
        defaults(),
        &context(3),
        |identity| parents.get(&identity).map(|record| record.tree),
    )
    .unwrap();
    assert!(!copied.fresh());
    assert_eq!(copied.first_parent(), Some(first_parent));
    assert!(copied.affected().is_empty());

    // Inert metadata cannot bypass the existing implicit-owner identity rule.
    let implicit = store_tree(
        &mut history,
        vec![],
        vec![property("index-roots", &invalid_later)],
    );
    let different = store_tree(&mut history, vec![], vec![property("index-roots", &[1])]);
    let implicit_parent = unsigned(implicit);
    let implicit_id = implicit_parent.identity().unwrap();
    let mut implicit_candidate = unsigned(different);
    implicit_candidate.parents = vec![implicit_id];
    assert!(
        super::super::derive_with_selected_parent_tree(
            &history,
            &implicit_candidate,
            defaults(),
            &old,
            |identity| (identity == implicit_id).then_some(implicit_parent.tree),
        )
        .is_err()
    );

    let retained_owner = text(&private_owner(implicit).unwrap());
    let materialized = store_tree(
        &mut history,
        vec![],
        vec![
            property("domain", &retained_owner),
            property("index-roots", &[1]),
        ],
    );
    implicit_candidate.tree = materialized;
    let materialized_plan = super::super::derive_with_selected_parent_tree(
        &history,
        &implicit_candidate,
        defaults(),
        &old,
        |identity| (identity == implicit_id).then_some(implicit_parent.tree),
    )
    .unwrap();
    assert!(!materialized_plan.fresh());
    assert_eq!(materialized_plan.affected().len(), 2);
    assert!(
        materialized_plan
            .affected()
            .iter()
            .all(|affected| affected.domain() == private_owner(implicit).unwrap())
    );
    assert!(
        parents
            .values()
            .all(|record| record.signature.is_none() && record.provenance.embedded_token.is_none())
    );
}

#[test]
fn namespace_snapshot_has_complete_policy_without_auxiliary_gap_default() {
    let root = state(
        [1; 32],
        Vec::new(),
        &[Vec::new()],
        defaults(),
        crate::properties::selected::Selection::Recorded(context(3)),
    )
    .unwrap();
    assert_eq!(root.effective.len(), 34);
    assert!(
        !root
            .effective
            .iter()
            .any(|(name, _)| *name == PropertyName::IndexGaps)
    );
    let gap = binding(&text(&"ab".repeat(32)), false);
    assert!(
        state(
            [1; 32],
            Vec::new(),
            &[vec![property("index-gaps", &gap)]],
            defaults(),
            crate::properties::selected::Selection::Recorded(context(3))
        )
        .is_err()
    );
}
