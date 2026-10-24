//! Exercises exact selected snapshot execution on actual canonical Merkle trees.

#![allow(
    clippy::unwrap_used,
    reason = "invalid canonical test fixtures must fail their assertions"
)]

use super::*;
use crate::{
    auth::PrincipalKind,
    properties::{selected::Selection, semantics::RecordedContext},
    refs::{Commit, CommitSource, ProfilePair, Provenance},
    tree_builder::Tree,
    tree_format::{Entry, LeafItem, TreeUse},
};

const MINIMUM: u64 = 262144;

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "local",
        private_domain: "private:caller",
        home: "west",
    }
}

fn selected(revision: u64, later: &[&str]) -> Selection {
    Selection::Recorded(RecordedContext::new(revision, 3, later).unwrap())
}

fn store(
    history: &mut VerifiedHistory,
    entries: Vec<LeafItem<'_>>,
    properties: Vec<Property<'_>>,
) -> Digest {
    let tree = Tree::build(entries, Some(properties), MINIMUM, TreeUse::Ordinary).unwrap();
    let root = tree.root_identity();
    let nodes: Vec<_> = tree
        .nodes()
        .map(|node| (node.identity(), node.encoded().to_vec()))
        .collect();
    history.insert_tree(root, &nodes).unwrap();
    root
}

fn graft(root: Digest, overrides: Option<Vec<Property<'_>>>) -> LeafItem<'_> {
    LeafItem {
        key: b"child".to_vec(),
        entry: Entry {
            kind: EntryKind::Tree {
                root,
                props: overrides,
            },
            attrs: vec![],
            attrs_present: false,
            xattrs: vec![],
            xattrs_present: false,
            provenance: None,
        },
    }
}

fn home(root: &Root) -> &str {
    match root
        .effective
        .iter()
        .find(|(name, _)| *name == PropertyName::Home)
    {
        Some((_, PolicyValue::Text(value))) => value,
        _ => panic!("actual resolved home default"),
    }
}

fn candidate(root: Digest) -> Commit {
    Commit {
        tree: root,
        parents: vec![],
        timestamp: 1,
        message: String::new(),
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
        packs: None,
        signature: None,
    }
}

// Fixed namespace values exclude auxiliary gap defaults and retain owner-local empty bindings.
fn expected_namespace_defaults(root: Digest, revision: u64) -> Vec<(&'static str, PolicyValue)> {
    use PolicyValue::*;
    let mut values = vec![
        ("acl", Grants(vec![])),
        ("baseline", Unset),
        ("chunk", Text("cdc-1m".into())),
        ("classify", Names(vec![])),
        ("compaction_threshold", Unsigned(5000)),
        ("compression", Text("zstd".into())),
        ("dedup", Text("domain".into())),
        ("degraded", Text("refuse".into())),
        ("domain", Text(private_owner(root).unwrap())),
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
    ];
    if revision >= 2 {
        values.push(("index-roots", PolicyValue::IndexRoots(vec![])));
    }
    values.sort_by_key(|(name, _)| *name);
    values
}

#[test]
fn snapshot_recorded_revisions_preserve_defaults_and_inert_names() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let root = store(&mut history, vec![], vec![]);
    for revision in [1, 2, 3] {
        let snapshot = complete(&history, root, defaults(), selected(revision, &[])).unwrap();
        let policy = snapshot.roots.get(b"/".as_slice()).unwrap();
        assert_eq!(policy.domain, private_owner(root).unwrap());
        assert_eq!(home(policy), "west");
        let mut actual: Vec<_> = policy
            .effective
            .iter()
            .map(|(name, value)| (name.as_str(), value.clone()))
            .collect();
        actual.sort_by_key(|(name, _)| *name);
        assert_eq!(actual, expected_namespace_defaults(root, revision));
        assert_eq!(policy.effective.len(), if revision == 1 { 33 } else { 34 });
        assert!(!actual.iter().any(|(name, _)| *name == "index-gaps"));
    }
    let inert = store(
        &mut history,
        vec![],
        vec![
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "index-roots",
                value: b"\x81\x00",
            },
            Property {
                name: "index-gaps",
                value: b"\x81\x01",
            },
        ],
    );

    let snapshot = complete(
        &history,
        inert,
        defaults(),
        selected(1, &["index-roots", "index-gaps"]),
    )
    .unwrap();

    let policy = snapshot.roots.get(b"/".as_slice()).unwrap();
    assert_eq!(policy.domain, "public");
    assert!(
        policy
            .local
            .contains(&("index-roots".into(), b"\x81\x00".to_vec()))
    );
    assert!(
        policy
            .local
            .contains(&("index-gaps".into(), b"\x81\x01".to_vec()))
    );
}

#[test]
fn snapshot_recorded_revisions_follow_full_and_parent_graft_paths() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let child = store(&mut history, vec![], vec![]);
    let middle = store(
        &mut history,
        vec![graft(child, None)],
        vec![Property {
            name: "home",
            value: b"\x65child",
        }],
    );
    let local = b"\xa2\x65value\x65local\x67inherit\xf4";
    let root = store(
        &mut history,
        vec![graft(
            middle,
            Some(vec![Property {
                name: "home",
                value: local,
            }]),
        )],
        vec![
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "home",
                value: b"\x68ancestor",
            },
        ],
    );
    for revision in [1, 2, 3] {
        let interpretation = selected(revision, &[]);
        let full = complete(&history, root, defaults(), interpretation.clone()).unwrap();
        let local = at_path(
            &history,
            root,
            b"/child",
            defaults(),
            interpretation.clone(),
        )
        .unwrap();
        let nested = at_path(&history, root, b"/child/child", defaults(), interpretation).unwrap();
        assert_eq!(home(&local), "local");
        assert_eq!(home(&nested), "ancestor");
        assert_eq!(home(full.roots.get(b"/child".as_slice()).unwrap()), "local");
        assert_eq!(
            home(full.roots.get(b"/child/child".as_slice()).unwrap()),
            "ancestor"
        );
        assert_eq!(nested.identity, child);
    }
}

#[test]
fn snapshot_recorded_revisions_reject_untrusted_names_and_placement() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let root = store(
        &mut history,
        vec![],
        vec![Property {
            name: "future",
            value: b"\x00",
        }],
    );
    assert!(complete(&history, root, defaults(), selected(1, &[])).is_err());
    assert!(complete(&history, root, defaults(), selected(1, &["future"])).is_ok());
    let gap = store(
        &mut history,
        vec![],
        vec![Property {
            name: "index-gaps",
            value: b"\x00",
        }],
    );
    assert!(complete(&history, gap, defaults(), selected(2, &["index-gaps"])).is_ok());
    assert!(complete(&history, gap, defaults(), selected(3, &[])).is_err());
    let mut value = Vec::new();
    crate::cbor::write_map(&mut value, 0);
    let binding = crate::indexing::IndexRoots::decode_value(&value)
        .unwrap()
        .encode_binding()
        .unwrap();
    let child = store(&mut history, vec![], vec![]);
    let root = store(
        &mut history,
        vec![graft(
            child,
            Some(vec![Property {
                name: "index-roots",
                value: &binding,
            }]),
        )],
        vec![],
    );
    assert!(complete(&history, root, defaults(), selected(2, &[])).is_err());
    assert!(at_path(&history, root, b"/child", defaults(), selected(2, &[])).is_err());
}

#[test]
fn authoring_plans_use_explicit_recorded_property_context() {
    let interpretation = selected(1, &["index-roots", "index-gaps"]);
    let mut history = VerifiedHistory::new_selected(MINIMUM, interpretation);
    let root = store(
        &mut history,
        vec![],
        vec![
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "index-roots",
                value: b"\x81\x00",
            },
            Property {
                name: "index-gaps",
                value: b"\x81\x01",
            },
        ],
    );
    let record = candidate(root);

    let plan =
        crate::provenance::root_context::derive_fresh_roots(&history, &record, defaults()).unwrap();

    assert!(plan.fresh);
    assert!(plan.first_parent.is_none());
    assert_eq!(plan.affected.len(), 1);
    assert_eq!(plan.affected[0].root, root);
    assert_eq!(plan.affected[0].domain, "public");
    let mut active = VerifiedHistory::new_selected(MINIMUM, Selection::Active);
    let active_root = store(
        &mut active,
        vec![],
        vec![
            Property {
                name: "domain",
                value: b"\x66public",
            },
            Property {
                name: "index-roots",
                value: b"\x81\x00",
            },
            Property {
                name: "index-gaps",
                value: b"\x81\x01",
            },
        ],
    );
    assert_eq!(active_root, root);
    assert!(
        crate::provenance::root_context::derive_fresh_roots(&active, &record, defaults()).is_err()
    );
}

/// Captures a canonical namespace occurrence without manufacturing checked scope.
fn owner_policy_snapshot(history: &VerifiedHistory, root: Digest, revision: u64) -> Root {
    complete(
        history,
        root,
        defaults(),
        selected(revision, if revision == 1 { &["index-roots"] } else { &[] }),
    )
    .unwrap()
    .roots
    .remove(b"/".as_slice())
    .unwrap()
}

#[test]
fn owner_policy_empty_default_matches_legacy_absence_without_erasing_snapshot() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let root = store(
        &mut history,
        vec![],
        vec![Property {
            name: "domain",
            value: b"\x66public",
        }],
    );
    let legacy = complete(&history, root, defaults(), Selection::Legacy)
        .unwrap()
        .roots
        .remove(b"/".as_slice())
        .unwrap();
    for revision in [2, 3] {
        let registered = owner_policy_snapshot(&history, root, revision);
        assert_eq!(legacy.effective.len(), 33);
        assert_eq!(registered.effective.len(), 34);
        assert!(legacy.same_policy(&registered));
        assert!(registered.same_policy(&legacy));
        assert_ne!(selected(1, &["index-roots"]), selected(revision, &[]));
    }
}

#[test]
fn owner_policy_nonempty_bindings_and_explicit_raw_empty_changes_remain_changes() {
    let mut history = VerifiedHistory::new(MINIMUM);
    let absent = store(
        &mut history,
        vec![],
        vec![Property {
            name: "domain",
            value: b"\x66public",
        }],
    );
    // These actual canonical node identities test policy comparison only; this
    // fixture does not claim admission of an auxiliary index relationship.
    let target = store(
        &mut history,
        vec![],
        vec![Property {
            name: "domain",
            value: b"\x6dprivate:other",
        }],
    );
    let binding = |identity: Digest| {
        let mut value = Vec::new();
        crate::cbor::write_map(&mut value, 1);
        crate::cbor::write_text(&mut value, "uid");
        let hex: String = identity
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect();
        crate::cbor::write_text(&mut value, &hex);
        crate::indexing::IndexRoots::decode_value(&value)
            .unwrap()
            .encode_binding()
            .unwrap()
    };
    let first_value = binding(absent);
    let second_value = binding(target);
    let mut with_binding = |value: &[u8]| {
        store(
            &mut history,
            vec![],
            vec![
                Property {
                    name: "domain",
                    value: b"\x66public",
                },
                Property {
                    name: "index-roots",
                    value,
                },
            ],
        )
    };
    let first = with_binding(&first_value);
    let second = with_binding(&second_value);
    let empty = with_binding(b"\xa2\x65value\xa0\x67inherit\xf4");
    let inert = owner_policy_snapshot(&history, first, 1);
    let active = owner_policy_snapshot(&history, first, 2);
    assert_eq!(inert.local, active.local);
    assert!(!inert.same_policy(&active));
    assert!(!active.same_policy(&inert));
    let other = owner_policy_snapshot(&history, second, 2);
    assert_eq!(active.domain, other.domain);
    assert!(!active.same_policy(&other));
    assert!(!other.same_policy(&active));
    let absent = owner_policy_snapshot(&history, absent, 2);
    let empty = owner_policy_snapshot(&history, empty, 2);
    assert_eq!(absent.effective, empty.effective);
    assert_ne!(absent.local, empty.local);
    assert!(!absent.same_policy(&empty));
    assert!(!empty.same_policy(&absent));
}
