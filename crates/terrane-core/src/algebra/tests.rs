//! Exercises composition semantics and observed Merkle traversal work.
//!
//! Cases remain in this shared namespace because conformance gates select its
//! operation prefixes and exact depth-limit cases. The common forest, canonical
//! entries, commit templates, and signed views make cross-operation invariants
//! visible without duplicating fixtures in separately selected test modules.

#![allow(clippy::unwrap_used)]

use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::tree_builder::Tree;
use crate::tree_format::{ContentRef, Entry, EntryKind, LeafItem, TreeUse};

fn entry(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn untrusted() -> TrustContext {
    TrustContext::verified(
        b"\x82\x66preset\x66strict".to_vec(),
        alloc::string::String::from("test-verifier/v1"),
        vec![0xf6],
        vec![],
    )
    .unwrap()
}

fn trusted_theirs() -> TrustContext {
    TrustContext::verified(
        b"\x82\x66preset\x66strict".to_vec(),
        alloc::string::String::from("test-verifier/v1"),
        vec![0xf6],
        vec![[b't'; 32]],
    )
    .unwrap()
}

fn value(target: &'static [u8]) -> Entry<'static> {
    let mut result = entry(EntryKind::Symlink { target });
    result.provenance = target.first().copied().map(|byte| [byte; 32]);
    result
}

fn tree(items: &[(&[u8], Entry<'static>)]) -> Tree<'static> {
    Tree::build(
        items
            .iter()
            .map(|(key, entry)| LeafItem {
                key: key.to_vec(),
                entry: entry.clone(),
            })
            .collect(),
        fixture_properties(),
        4096,
        TreeUse::OverlayLayer,
    )
    .unwrap()
}

fn fixture_properties() -> Option<Vec<crate::tree_format::Property<'static>>> {
    Some(vec![crate::tree_format::Property {
        name: "domain",
        value: b"\x6fprivate:fixture",
    }])
}

fn effective_properties(domain: &'static str) -> crate::properties::EffectiveProperties<'static> {
    crate::properties::resolve(
        &[],
        crate::properties::Defaults {
            store: "authority",
            private_domain: domain,
            home: "local",
        },
    )
    .unwrap()
}

struct Forest(Vec<Tree<'static>>);

impl<'a> Roots<'a> for Forest {
    fn resolve(&self, identity: &crate::identity::Digest) -> Option<&Tree<'a>> {
        self.0.iter().find(|tree| tree.root_identity() == *identity)
    }
}

fn graft_entry(target: &Tree<'static>) -> Entry<'static> {
    entry(EntryKind::Tree {
        root: target.root_identity(),
        props: None,
    })
}

#[test]
fn graft_reuses_target_and_nested_lookup_resolves() {
    let target = tree(&[(b"file", value(b"bytes"))]);
    let parent = tree(&[]);
    let grafted = graft(
        &parent,
        b"mount",
        graft_entry(&target),
        false,
        &Forest(vec![target.clone()]),
    )
    .unwrap();
    let roots = Forest(vec![target]);

    assert_eq!(
        lookup(&grafted, b"mount/file", &roots).unwrap(),
        Some(&value(b"bytes"))
    );
    assert_eq!(
        split(&grafted, b"mount", &roots).unwrap().root_identity(),
        roots.0[0].root_identity()
    );
    validate_acyclic(&grafted, &roots).unwrap();
}

#[test]
fn graft_requires_explicit_inline_replacement() {
    let parent = tree(&[
        (b"mount", entry(EntryKind::Directory { mode: 0o755 })),
        (b"mount/file", value(b"old")),
    ]);
    let target = tree(&[]);

    assert_eq!(
        graft(
            &parent,
            b"mount",
            graft_entry(&target),
            false,
            &Forest(vec![target.clone()])
        )
        .unwrap_err(),
        Error::InlineChildren
    );
    let grafted = graft(
        &parent,
        b"mount",
        graft_entry(&target),
        true,
        &Forest(vec![target.clone()]),
    )
    .unwrap();
    assert!(grafted.get(b"mount/file").is_none());
}

#[test]
fn split_inline_matches_direct_construction() {
    let parent = tree(&[
        (b"mount", entry(EntryKind::Directory { mode: 0o755 })),
        (b"mount/file", value(b"data")),
        (b"other", value(b"other")),
    ]);
    let expected = tree(&[(b"file", value(b"data"))]);

    assert_eq!(
        split(&parent, b"mount", &Forest(vec![]))
            .unwrap()
            .root_identity(),
        expected.root_identity()
    );
}

#[test]
fn split_graft_shares_the_target_without_walking_its_nodes() {
    let items: Vec<_> = (0..4096)
        .map(|index| LeafItem {
            key: alloc::format!("file-{index:04}").into_bytes(),
            entry: value(b"unchanged"),
        })
        .collect();
    let target = Tree::build(items, fixture_properties(), 4096, TreeUse::Ordinary).unwrap();
    assert!(target.root().level() > 0);

    let parent = tree(&[(b"mount", graft_entry(&target))]);
    let roots = Forest(vec![target]);
    let extracted = split(&parent, b"mount", &roots).unwrap();

    assert_eq!(extracted.root_identity(), roots.0[0].root_identity());
    assert!(core::ptr::eq(extracted.root(), roots.0[0].root()));
    assert_eq!(extracted.props(), roots.0[0].props());
}

#[test]
fn split_relabels_hardlinks_within_and_across_prefix() {
    let linked = entry(EntryKind::File {
        mode: 0o644,
        size: 1,
        content: ContentRef::Inline([1; 32]),
        link_id: Some(b"a"),
    });
    let parent = tree(&[
        (b"a", linked.clone()),
        (b"mount", entry(EntryKind::Directory { mode: 0o755 })),
        (b"mount/b", linked.clone()),
        (b"mount/c", linked),
    ]);
    let prepared = prepare_split(&parent, b"mount").unwrap();
    let result = prepared.materialize().unwrap();
    let relative = entry(EntryKind::File {
        mode: 0o644,
        size: 1,
        content: ContentRef::Inline([1; 32]),
        link_id: Some(b"b"),
    });
    let expected = tree(&[(b"b", relative.clone()), (b"c", relative)]);

    assert_eq!(result.root_identity(), expected.root_identity());

    let inside = entry(EntryKind::File {
        mode: 0o644,
        size: 1,
        content: ContentRef::Inline([1; 32]),
        link_id: Some(b"mount/b"),
    });
    let parent = tree(&[
        (b"mount", entry(EntryKind::Directory { mode: 0o755 })),
        (b"mount/b", inside.clone()),
        (b"mount/c", inside),
    ]);
    assert_eq!(
        split(&parent, b"mount", &Forest(vec![]))
            .unwrap()
            .root_identity(),
        expected.root_identity()
    );
}

#[test]
fn flatten_checks_authority_and_preserves_lookup() {
    let target = tree(&[(b"file", value(b"bytes"))]);
    let parent = graft(
        &tree(&[]),
        b"mount",
        graft_entry(&target),
        false,
        &Forest(vec![target.clone()]),
    )
    .unwrap();
    let roots = Forest(vec![target]);
    let parent_properties = effective_properties("private:parent");
    let other_properties = effective_properties("private:other");

    assert_eq!(
        flatten(
            &parent,
            b"mount",
            &roots,
            &parent_properties,
            &other_properties
        )
        .unwrap_err(),
        Error::Boundary
    );
    let prepared = flatten(
        &parent,
        b"mount",
        &roots,
        &parent_properties,
        &parent_properties,
    )
    .unwrap();
    let flattened = prepared.materialize(&parent).unwrap();
    assert_eq!(flattened.get(b"mount/file"), Some(&value(b"bytes")));
}

#[test]
fn flatten_prefixes_hardlink_identity() {
    let linked = entry(EntryKind::File {
        mode: 0o644,
        size: 1,
        content: ContentRef::Inline([1; 32]),
        link_id: Some(b"a"),
    });
    let target = tree(&[(b"a", linked.clone()), (b"b", linked)]);
    let parent = graft(
        &tree(&[]),
        b"mount",
        graft_entry(&target),
        false,
        &Forest(vec![target.clone()]),
    )
    .unwrap();
    let roots = Forest(vec![target]);
    let properties = effective_properties("private:fixture");
    let prepared = flatten(&parent, b"mount", &roots, &properties, &properties).unwrap();
    let flattened = prepared.materialize(&parent).unwrap();
    let expected_link = entry(EntryKind::File {
        mode: 0o644,
        size: 1,
        content: ContentRef::Inline([1; 32]),
        link_id: Some(b"mount/a"),
    });
    let expected = tree(&[
        (b"mount", entry(EntryKind::Directory { mode: 0o755 })),
        (b"mount/a", expected_link.clone()),
        (b"mount/b", expected_link),
    ]);

    assert_eq!(flattened.root_identity(), expected.root_identity());
}

#[test]
fn flatten_rejects_changed_effective_trust() {
    let target = tree(&[]);
    let parent = graft(
        &tree(&[]),
        b"mount",
        graft_entry(&target),
        false,
        &Forest(vec![target.clone()]),
    )
    .unwrap();
    let roots = Forest(vec![target]);
    let parent_properties = effective_properties("private:parent");
    let strict = [crate::tree_format::Property {
        name: "trust",
        value: b"\x66strict",
    }];
    let target_properties = crate::properties::resolve(
        &[crate::properties::RootLayer {
            properties: &strict,
            overrides: &[],
        }],
        crate::properties::Defaults {
            store: "authority",
            private_domain: "private:parent",
            home: "local",
        },
    )
    .unwrap();

    assert_eq!(
        flatten(
            &parent,
            b"mount",
            &roots,
            &parent_properties,
            &target_properties,
        )
        .unwrap_err(),
        Error::Boundary,
    );
}

#[test]
fn graft_relabels_surviving_hardlink_identity_atomically() {
    let linked = entry(EntryKind::File {
        mode: 0o644,
        size: 1,
        content: ContentRef::Inline([1; 32]),
        link_id: Some(b"mount/a"),
    });
    let parent = tree(&[
        (b"mount", entry(EntryKind::Directory { mode: 0o755 })),
        (b"mount/a", linked.clone()),
        (b"outside", linked),
    ]);
    let target = tree(&[]);
    let roots = Forest(vec![target.clone()]);

    // Removing the canonical member cannot leave an invalid identity reachable.
    assert_eq!(
        graft(&parent, b"mount", graft_entry(&target), true, &roots).unwrap_err(),
        Error::Build(crate::tree_format::Error::Tree),
    );
    let prepared = prepare_graft(&parent, b"mount", &graft_entry(&target), true).unwrap();
    let result = prepared
        .materialize(&parent, &roots, &mut RootGraph::new())
        .unwrap();
    assert!(result.tree.get(b"mount/a").is_none());
    assert!(matches!(
        result.tree.get(b"outside").unwrap().kind,
        EntryKind::File {
            link_id: Some(b"outside"),
            ..
        },
    ));
}

#[test]
fn overlay_precedence_whiteouts_and_materialization_agree() {
    let bottom = tree(&[(b"a", value(b"old")), (b"b", value(b"visible"))]);
    let top = tree(&[(b"a", entry(EntryKind::Whiteout)), (b"c", value(b"new"))]);
    let layers = [&top, &bottom];
    let overlay = Overlay::new(&layers);

    assert!(overlay.get(b"a").is_none());
    assert_eq!(overlay.get(b"b"), Some(&value(b"visible")));
    assert_eq!(
        overlay
            .entries()
            .iter()
            .map(|item| item.key.as_slice())
            .collect::<Vec<_>>(),
        vec![b"b".as_slice(), b"c".as_slice()]
    );
    let expected = tree(&[(b"b", value(b"visible")), (b"c", value(b"new"))]);
    assert_eq!(
        overlay.materialize().unwrap().root_identity(),
        expected.root_identity()
    );
}

#[test]
fn overlay_ranges_match_independent_point_updates_and_canonical_roots() {
    let bottom = tree(&[
        (b"a", value(b"bottom-a")),
        (b"b", value(b"bottom-b")),
        (b"c", value(b"bottom-c")),
        (b"d", value(b"bottom-d")),
        (b"z", value(b"bottom-z")),
        (b"\xff", value(b"bottom-high")),
    ]);
    let middle = tree(&[
        (b"b", value(b"middle-b")),
        (b"c", entry(EntryKind::Whiteout)),
        (b"e", value(b"middle-e")),
        (b"z", value(b"middle-z")),
    ]);
    let top = tree(&[
        (b"b", value(b"top-b")),
        (b"d", entry(EntryKind::Whiteout)),
        (b"f", value(b"top-f")),
        (b"z", entry(EntryKind::Whiteout)),
    ]);
    let layers = [&top, &middle, &bottom];
    let overlay = Overlay::new(&layers);
    let mut expected = bottom.clone();

    // Point updates provide an independent oracle for ordered range merging.
    for layer in [&middle, &top] {
        for item in layer.iter() {
            expected = if matches!(item.entry.kind, EntryKind::Whiteout) {
                expected.remove(&item.key).unwrap().tree
            } else {
                expected.insert(item.clone()).unwrap().tree
            };
        }
    }

    let materialized = overlay.materialize_with_recipe().unwrap();
    assert_eq!(materialized.tree.root_identity(), expected.root_identity());
    assert_eq!(
        overlay.entries(),
        expected.iter().cloned().collect::<Vec<_>>()
    );
    assert_eq!(
        overlay.range(b"b", Some(b"z")),
        expected
            .iter()
            .filter(|item| item.key.as_slice() >= b"b" && item.key.as_slice() < b"z")
            .cloned()
            .collect::<Vec<_>>()
    );
    assert!(overlay.range(b"b", Some(b"b")).is_empty());
    assert_eq!(overlay.range(b"z", None).len(), 1);

    for key in [b"a".as_slice(), b"b", b"c", b"d", b"e", b"f", b"z", b"\xff"] {
        assert_eq!(overlay.get(key), expected.get(key), "key {key:?}");
    }
    assert_eq!(
        Recipe::decode(&materialized.recipe)
            .unwrap()
            .as_recipe()
            .encode(),
        materialized.recipe
    );
}

#[test]
fn diff_is_ordered_and_skips_equal_root() {
    let old = tree(&[(b"a", value(b"old")), (b"c", value(b"removed"))]);
    let new = tree(&[(b"a", value(b"new")), (b"b", value(b"added"))]);
    let changes = diff(&old, &new);

    assert_eq!(
        changes.iter().map(Change::path).collect::<Vec<_>>(),
        vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
    );
    assert!(matches!(changes[0], Change::Modified { .. }));
    assert!(matches!(changes[1], Change::Added(_)));
    assert!(matches!(changes[2], Change::Removed(_)));
    assert_eq!(diff_with_work(&old, &old).expanded_nodes, 0);
}

#[test]
fn merge_rules_and_fast_forward() {
    let base = tree(&[(b"a", value(b"base")), (b"b", value(b"base"))]);
    let ours = tree(&[(b"a", value(b"ours")), (b"b", value(b"base"))]);
    let theirs = tree(&[(b"a", value(b"base")), (b"b", value(b"theirs"))]);
    let roots = Forest(vec![]);
    let merged = merge(&base, &ours, &theirs, &[], &untrusted(), &roots).unwrap();

    assert_eq!(merged.tree.get(b"a"), Some(&value(b"ours")));
    assert_eq!(merged.tree.get(b"b"), Some(&value(b"theirs")));
    assert!(!merged.conflicted);
    let forwarded = merge(&base, &base, &theirs, &[], &untrusted(), &roots).unwrap();
    assert!(forwarded.fast_forward);
    assert_eq!(forwarded.tree.root_identity(), theirs.root_identity());
}

#[test]
fn merge_conflicts_and_ordered_policies() {
    let base = tree(&[(b"a", value(b"base"))]);
    let ours = tree(&[(b"a", value(b"ours"))]);
    let theirs = tree(&[(b"a", value(b"theirs"))]);
    let roots = Forest(vec![]);
    let kept = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::KeepConflict],
        &untrusted(),
        &roots,
    )
    .unwrap();

    assert!(kept.conflicted);
    match &kept.tree.get(b"a").unwrap().kind {
        EntryKind::Conflict {
            candidates,
            base: Some(Some(base)),
        } => {
            assert_eq!(candidates, &[value(b"ours"), value(b"theirs")]);
            assert_eq!(**base, value(b"base"));
        }
        _ => panic!("expected ordered conflict"),
    }
    assert_eq!(
        merge(
            &base,
            &ours,
            &theirs,
            &[MergePolicy::Error],
            &untrusted(),
            &roots
        )
        .unwrap_err(),
        Error::Conflict
    );
    let selected = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::PreferTrusted, MergePolicy::PreferOurs],
        &trusted_theirs(),
        &roots,
    )
    .unwrap();
    assert_eq!(selected.tree.root_identity(), theirs.root_identity());
    let fallback = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::PreferTrusted, MergePolicy::PreferTheirs],
        &untrusted(),
        &roots,
    )
    .unwrap();
    assert_eq!(fallback.tree.root_identity(), theirs.root_identity());
}

#[test]
fn deletion_conflict_is_representable_without_nested_conflicts() {
    let base = tree(&[(b"a", value(b"base"))]);
    let ours = tree(&[]);
    let theirs = tree(&[(b"a", value(b"changed"))]);
    let kept = merge(&base, &ours, &theirs, &[], &untrusted(), &Forest(vec![])).unwrap();

    let EntryKind::Conflict { candidates, .. } = &kept.tree.get(b"a").unwrap().kind else {
        panic!("missing conflict");
    };
    assert!(matches!(candidates[0].kind, EntryKind::Whiteout));
    assert_eq!(candidates[1], value(b"changed"));
}

#[test]
fn fork_and_fold_preserve_parents_and_report_exclusions() {
    let base = tree(&[(b"a", value(b"base")), (b"b", value(b"base"))]);
    let child = tree(&[(b"a", value(b"changed")), (b"b", value(b"forbidden"))]);
    let plan = fork(base.root_identity(), [1; 32], 7);
    let result = fold(
        &base,
        &base,
        &child,
        [[1; 32], [2; 32]],
        &[],
        &untrusted(),
        &Forest(vec![]),
        |path, _| path == b"a",
        Retirement::Delete,
    )
    .unwrap();

    assert_eq!(plan.root, base.root_identity());
    assert_eq!(plan.sequence, 7);
    assert_eq!(result.parents, [[1; 32], [2; 32]]);
    assert_eq!(result.excluded, vec![b"b".to_vec()]);
    assert_eq!(result.merged.tree.get(b"b"), Some(&value(b"base")));
    assert!(result.merged.fast_forward);
}

#[test]
fn diff_local_change_skips_shared_nodes() {
    let items = (0..5000)
        .map(|index| LeafItem {
            key: alloc::format!("key-{index:08}").into_bytes(),
            entry: value(b"unchanged content stored without allocating object bytes"),
        })
        .collect();
    let old = Tree::build(items, fixture_properties(), 4096, TreeUse::Ordinary).unwrap();
    let new = old
        .insert(LeafItem {
            key: b"key-00002500".to_vec(),
            entry: value(b"changed"),
        })
        .unwrap()
        .tree;
    let result = diff_with_work(&old, &new);

    assert_eq!(result.changes.len(), 1);
    assert_eq!(result.changes[0].path(), b"key-00002500");
    assert!(
        result.expanded_nodes < old.nodes().count(),
        "expanded {} of {} old nodes",
        result.expanded_nodes,
        old.nodes().count()
    );
}

#[test]
fn merge_randomized_reference_model_and_symmetric_policy() {
    fn sample(state: &mut u64) -> Option<Entry<'static>> {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        match (*state >> 32) % 4 {
            0 => None,
            1 => Some(value(b"one")),
            2 => Some(value(b"two")),
            _ => Some(value(b"three")),
        }
    }
    fn single(value: &Option<Entry<'static>>) -> Tree<'static> {
        match value {
            Some(value) => tree(&[(b"key", value.clone())]),
            None => tree(&[]),
        }
    }
    fn alternatives(entry: Option<&Entry<'_>>) -> Vec<Vec<u8>> {
        match entry {
            Some(Entry {
                kind: EntryKind::Conflict { candidates, .. },
                ..
            }) => {
                let mut values: Vec<_> = candidates
                    .iter()
                    .map(|value| crate::tree_format::encode_entry(value, 4096).unwrap())
                    .collect();
                values.sort();
                values
            }
            Some(entry) => vec![crate::tree_format::encode_entry(entry, 4096).unwrap()],
            None => vec![],
        }
    }

    let mut state = 0x74657272616e65;
    for _ in 0..500 {
        let values = [sample(&mut state), sample(&mut state), sample(&mut state)];
        let trees = [single(&values[0]), single(&values[1]), single(&values[2])];
        let roots = Forest(vec![]);
        let merged = merge(
            &trees[0],
            &trees[1],
            &trees[2],
            &[MergePolicy::KeepConflict],
            &untrusted(),
            &roots,
        )
        .unwrap();
        let expected = if values[1] == values[2] {
            Some(&values[1])
        } else if values[1] == values[0] {
            Some(&values[2])
        } else if values[2] == values[0] {
            Some(&values[1])
        } else {
            None
        };

        match expected {
            Some(value) => assert_eq!(merged.tree.get(b"key"), value.as_ref()),
            None => {
                let EntryKind::Conflict { candidates, .. } = &merged.tree.get(b"key").unwrap().kind
                else {
                    panic!("model expected conflict");
                };
                for (candidate, side) in candidates.iter().zip(&values[1..]) {
                    match side {
                        Some(value) => assert_eq!(candidate, value),
                        None => assert!(matches!(candidate.kind, EntryKind::Whiteout)),
                    }
                }
            }
        }
        let reversed = merge(
            &trees[0],
            &trees[2],
            &trees[1],
            &[MergePolicy::KeepConflict],
            &untrusted(),
            &roots,
        )
        .unwrap();
        assert_eq!(
            alternatives(merged.tree.get(b"key")),
            alternatives(reversed.tree.get(b"key"))
        );
        let identical = merge(&trees[0], &trees[0], &trees[0], &[], &untrusted(), &roots).unwrap();
        assert_eq!(identical.expanded_nodes, 0);
    }
}

#[test]
fn merge_changed_grafts_returns_materialized_targets() {
    let base_target = tree(&[(b"a", value(b"base")), (b"b", value(b"base"))]);
    let ours_target = tree(&[(b"a", value(b"ours")), (b"b", value(b"base"))]);
    let theirs_target = tree(&[(b"a", value(b"base")), (b"b", value(b"theirs"))]);
    let base = tree(&[(b"mount", graft_entry(&base_target))]);
    let ours = tree(&[(b"mount", graft_entry(&ours_target))]);
    let theirs = tree(&[(b"mount", graft_entry(&theirs_target))]);
    let roots = Forest(vec![base_target, ours_target, theirs_target]);
    let result = merge(&base, &ours, &theirs, &[], &untrusted(), &roots).unwrap();

    assert_eq!(result.derived_roots.len(), 1);
    assert_eq!(result.derived_roots[0].get(b"a"), Some(&value(b"ours")));
    assert_eq!(result.derived_roots[0].get(b"b"), Some(&value(b"theirs")));
    let changed = diff_descend(&base, &theirs, &roots).unwrap();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].path(), b"mount/b");
}

#[test]
fn acyclic_validation_rejects_missing_targets() {
    let root = tree(&[(
        b"missing",
        entry(EntryKind::Tree {
            root: [3; 32],
            props: None,
        }),
    )]);

    assert_eq!(
        validate_acyclic(&root, &Forest(vec![])),
        Err(Error::MissingRoot)
    );
    assert_eq!(
        lookup(&root, b"missing/file", &Forest(vec![])).unwrap_err(),
        Error::MissingRoot
    );
}

fn commit_template() -> crate::refs::Commit {
    use crate::refs::{Commit, CommitSource, PrincipalKind, ProfilePair, Provenance};
    use alloc::string::String;

    Commit {
        tree: [0; 32],
        parents: vec![],
        provenance: Provenance {
            issuer: String::from("issuer"),
            token_id: [0; 16],
            subject: String::from("subject"),
            kind: PrincipalKind::Human,
            workload_identity: None,
            process: String::from("test"),
            observed_at: 0,
            writer_epoch: 1,
            source: CommitSource::Built,
            embedded_token: None,
        },
        timestamp: 0,
        message: String::new(),
        profile_pair: ProfilePair {
            entry_receipts: None,
            commit_context: None,
            tree_format: 1,
            chunk_profile: String::from("cdc-1m"),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
        },
        packs: None,
        signature: Some([1; 64]),
    }
}

#[test]
fn merge_commit_binding_records_order_recipe_and_conflict_profile() {
    let base = tree(&[(b"a", value(b"base"))]);
    let ours = tree(&[(b"a", value(b"ours"))]);
    let theirs = tree(&[(b"a", value(b"theirs"))]);
    let result = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::KeepConflict],
        &untrusted(),
        &Forest(vec![]),
    )
    .unwrap();
    let mut commit = commit_template();

    result.bind_commit(&mut commit, [[1; 32], [2; 32]]);
    assert_eq!(commit.tree, result.tree.root_identity());
    assert_eq!(commit.parents, vec![[1; 32], [2; 32]]);
    assert_eq!(commit.profile_pair.conflicted, Some(true));
    assert_eq!(commit.profile_pair.recipe, Some(result.recipe.clone()));
    assert!(commit.signature.is_none());
    assert_eq!(
        crate::refs::Commit::decode(&commit.encode().unwrap()).unwrap(),
        commit
    );
}

#[test]
fn graft_recipe_retains_metadata_and_binds_materialized_commit() {
    let parent = tree(&[]);
    let target = tree(&[(b"file", value(b"target"))]);
    let roots = Forest(vec![target.clone()]);
    let mut graph = RootGraph::new();
    let result = graft_certified(
        &parent,
        b"mount",
        graft_entry(&target),
        false,
        &roots,
        &mut graph,
    )
    .unwrap();
    let decoded = Recipe::decode(&result.recipe).unwrap();
    assert_eq!(decoded.as_recipe().encode(), result.recipe);
    assert!(matches!(
        decoded.as_recipe(),
        Recipe::Graft {
            at: b"mount",
            replace: false,
            ..
        }
    ));

    let mut commit = commit_template();
    result.bind_commit(&mut commit, &graph).unwrap();
    assert_eq!(commit.tree, result.tree.root_identity());
    assert_eq!(commit.profile_pair.recipe, Some(result.recipe));
    assert_eq!(commit.profile_pair.conflicted, Some(false));
    assert!(commit.signature.is_none());
}

#[test]
fn fork_and_fold_binding_inherits_origins_without_reintroduction() {
    let inherited = [3; 32];
    let mut commit = commit_template();
    commit.profile_pair.entry_receipts = Some(vec![crate::refs::EntryReceipt {
        root: inherited,
        path: b"file".to_vec(),
        origin: crate::refs::EntryOrigin::Current,
        attributes: None,
        reintroduced_from: None,
        disclosure_proof: None,
    }]);

    fork(inherited, [4; 32], 1).bind_commit(&mut commit);

    assert_eq!(commit.tree, inherited);
    assert_eq!(commit.parents, vec![[4; 32]]);
    assert!(commit.profile_pair.entry_receipts.is_none());
    assert!(commit.signature.is_none());
}

#[test]
fn trusted_recipe_binds_verifier_configuration_and_receipts() {
    let trust = trusted_theirs();
    let empty = untrusted();
    let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
    let recipe = |trust| Recipe::Merge {
        base: [1; 32],
        ours: [2; 32],
        theirs: [3; 32],
        policies: &policies,
        trust,
        domains: None,
    };

    assert_ne!(
        recipe(&trust).identity().unwrap(),
        recipe(&empty).identity().unwrap()
    );
    let mut commit = commit_template();
    commit.profile_pair.recipe = Some(recipe(&trust).encode());
    assert_eq!(
        crate::refs::Commit::decode(&commit.encode().unwrap()).unwrap(),
        commit
    );
    assert!(!empty.accepts(&entry(EntryKind::Directory { mode: 0o755 })));
    assert!(!TrustContext::any().accepts(&entry(EntryKind::Directory { mode: 0o755 })));
}

#[test]
fn root_properties_diff_and_three_way_merge_are_explicit() {
    use crate::tree_format::Property;
    let empty = tree(&[]);
    let base = empty
        .with_properties(Some(vec![
            Property {
                name: "trust",
                value: b"\x63any",
            },
            crate::tree_format::Property {
                name: "domain",
                value: b"\x6fprivate:fixture",
            },
        ]))
        .unwrap()
        .tree;
    let ours = base
        .with_properties(Some(vec![
            Property {
                name: "trust",
                value: b"\x66strict",
            },
            crate::tree_format::Property {
                name: "domain",
                value: b"\x6fprivate:fixture",
            },
        ]))
        .unwrap()
        .tree;
    let theirs = base
        .with_properties(Some(vec![
            Property {
                name: "trust",
                value: b"\x68attested",
            },
            crate::tree_format::Property {
                name: "domain",
                value: b"\x6fprivate:fixture",
            },
        ]))
        .unwrap()
        .tree;
    let delta = diff_with_work(&base, &ours);

    assert!(delta.changes.is_empty());
    assert!(delta.properties.is_some());
    assert!(matches!(
        merge(
            &base,
            &ours,
            &theirs,
            &[MergePolicy::KeepConflict],
            &untrusted(),
            &Forest(vec![])
        ),
        Err(Error::RootPropertiesConflict(_))
    ));
    let resolved = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::PreferTheirs],
        &untrusted(),
        &Forest(vec![]),
    )
    .unwrap();
    assert_eq!(resolved.tree.root_identity(), theirs.root_identity());
}

#[test]
fn directory_conflicts_retain_children_until_nondirectory_resolution() {
    let base = tree(&[
        (b"a", entry(EntryKind::Directory { mode: 0o755 })),
        (b"a/b", value(b"base")),
    ]);
    let ours = tree(&[(b"a", value(b"file"))]);
    let theirs = tree(&[
        (b"a", entry(EntryKind::Directory { mode: 0o700 })),
        (b"a/b", value(b"changed")),
    ]);
    let roots = Forest(vec![]);
    let kept = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::KeepConflict],
        &untrusted(),
        &roots,
    )
    .unwrap();

    assert!(kept.conflicted);
    assert!(kept.tree.get(b"a/b").is_some());
    let resolved = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::PreferOurs],
        &untrusted(),
        &roots,
    )
    .unwrap();
    assert_eq!(resolved.tree.root_identity(), ours.root_identity());
    assert!(resolved.tree.get(b"a/b").is_none());
}

#[test]
fn surface_inputs_can_produce_an_ordinary_conflicted_tree() {
    let convert = |tree: Tree<'static>| tree.with_usage(TreeUse::Surface).unwrap();
    let base = convert(tree(&[(b"a", value(b"base"))]));
    let ours = convert(tree(&[(b"a", value(b"ours"))]));
    let theirs = convert(tree(&[(b"a", value(b"theirs"))]));
    let result = merge(&base, &ours, &theirs, &[], &untrusted(), &Forest(vec![])).unwrap();

    assert!(result.conflicted);
    assert_eq!(result.tree.usage(), TreeUse::Ordinary);
}

#[test]
fn trusted_context_rejects_bad_syntax_and_handles_deep_configuration() {
    use alloc::string::String;
    let invalid = TrustContext::verified(
        b"\x82\x67unknown\x63any".to_vec(),
        String::from("verifier/v1"),
        vec![0xf6],
        vec![],
    );
    assert_eq!(invalid.unwrap_err(), TrustError::Selector);

    let mut configuration = vec![0x81; 128];
    configuration.push(0xf6);
    let context = TrustContext::verified(
        b"\x82\x66preset\x66strict".to_vec(),
        String::from("verifier/v1"),
        configuration,
        vec![[2; 32], [1; 32], [2; 32]],
    )
    .unwrap();
    assert!(context.accepts(&Entry {
        provenance: Some([1; 32]),
        ..value(b"value")
    }));
}

#[test]
fn trusted_context_decoding_checks_registered_attribute_names() {
    let selector = |name: &str| {
        let mut bytes = Vec::new();
        crate::cbor::write_array(&mut bytes, 3);
        crate::cbor::write_text(&mut bytes, "attr-by");
        crate::cbor::write_text(&mut bytes, name);
        bytes.extend_from_slice(b"\x82\x66preset\x63any");
        bytes
    };

    for name in ["hash.sha256", "tag.custom", "tag.λ!"] {
        let context = decode_trust_evidence(&selector(name), &[0xf6]).unwrap();
        assert_eq!(context.selector(), selector(name));
    }
    let longest = alloc::format!("tag.{}", "x".repeat(251));
    assert!(decode_trust_evidence(&selector(&longest), &[0xf6]).is_ok());

    for name in ["", "tag.", "unknown", "unknown.custom", "class.unknown"] {
        assert_eq!(
            decode_trust_evidence(&selector(name), &[0xf6]).unwrap_err(),
            TrustError::Selector,
            "{name:?}",
        );
    }
    let oversized = alloc::format!("tag.{}", "x".repeat(252));
    assert!(matches!(
        decode_trust_evidence(&selector(&oversized), &[0xf6]),
        Err(TrustError::Encoding(_)),
    ));

    let mut invalid_utf8 = b"\x83\x67attr-by\x61\xff".to_vec();
    invalid_utf8.extend_from_slice(b"\x82\x66preset\x63any");
    assert!(matches!(
        decode_trust_evidence(&invalid_utf8, &[0xf6]),
        Err(TrustError::Encoding(_)),
    ));
}

#[test]
fn trusted_context_decoding_checks_encoded_byte_map_order() {
    let selector = b"\x82\x66preset\x63any";
    let mut configuration = vec![0xa2, 0x58, 24];
    configuration.extend_from_slice(&[0; 24]);
    configuration.extend_from_slice(&[0xf6, 0x60, 0xf6]);

    // TREE-25 orders encoded bytes, so the longer byte-string key precedes
    // the shorter text-string key. Length-first ordering would reverse them.
    assert!(decode_trust_evidence(selector, &configuration).is_ok());
    let mut reversed = vec![0xa2, 0x60, 0xf6];
    reversed.extend_from_slice(&configuration[1..configuration.len() - 2]);
    assert_eq!(
        decode_trust_evidence(selector, &reversed).unwrap_err(),
        TrustError::Encoding(crate::cbor::Error::NonCanonical),
    );

    for malformed in [
        &[0xa2, 0x40, 0xf6, 0x40, 0xf6][..],
        &[0x81, 0xa2, 0x60, 0xf6, 0x40, 0xf6][..],
        &[0xa1, 0x58, 0, 0xf6][..],
    ] {
        assert_eq!(
            decode_trust_evidence(selector, malformed).unwrap_err(),
            TrustError::Encoding(crate::cbor::Error::NonCanonical),
        );
    }
    for malformed in [&[0xa1, 0xf5, 0xf6][..], &[0xa1, 0x61, 0xff, 0xf6][..]] {
        assert!(matches!(
            decode_trust_evidence(selector, malformed),
            Err(TrustError::Encoding(_)),
        ));
    }
}

fn decode_trust_evidence(
    selector: &[u8],
    configuration: &[u8],
) -> Result<TrustContext, TrustError> {
    let mut bytes = Vec::new();
    crate::cbor::write_map(&mut bytes, 4);
    crate::cbor::write_uint(&mut bytes, 1);
    bytes.extend_from_slice(selector);
    crate::cbor::write_uint(&mut bytes, 2);
    crate::cbor::write_text(&mut bytes, "test-evidence/v1");
    crate::cbor::write_uint(&mut bytes, 3);
    bytes.extend_from_slice(configuration);
    crate::cbor::write_uint(&mut bytes, 4);
    crate::cbor::write_array(&mut bytes, 0);

    let mut decoder = crate::cbor::Decoder::new(&bytes);
    let context = TrustContext::decode_from(&mut decoder, &bytes)?;
    decoder.finish().map_err(TrustError::Encoding)?;
    Ok(context)
}

#[test]
fn trusted_context_decoding_cannot_authorize_merge() {
    let base = tree(&[(b"key", value(b"base"))]);
    let ours = tree(&[(b"key", value(b"ours"))]);
    let theirs = tree(&[(b"key", value(b"theirs"))]);
    let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
    let context = trusted_theirs();
    let encoded = Recipe::Merge {
        base: base.root_identity(),
        ours: ours.root_identity(),
        theirs: theirs.root_identity(),
        policies: &policies,
        trust: &context,
        domains: None,
    }
    .encode();
    let decoded = Recipe::decode(&encoded).unwrap();
    let Recipe::Merge { trust, .. } = decoded.as_recipe() else {
        panic!("expected merge recipe");
    };

    assert_eq!(
        merge(&base, &ours, &theirs, &policies, trust, &Forest(vec![])).unwrap_err(),
        Error::Trust(TrustError::Unverified),
    );
    assert_eq!(
        merge(
            &base,
            &ours,
            &theirs,
            &policies,
            &TrustContext::any(),
            &Forest(vec![])
        )
        .unwrap_err(),
        Error::Trust(TrustError::Unverified),
    );
}

#[test]
fn trusted_merge_binds_signed_sides_and_reverifies_recipe() {
    use super::signed_fixture::{SignedSide, signed_history};
    use crate::provenance::{Preset, Selector};

    let input = |target: &'static [u8]| {
        Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: entry(EntryKind::Symlink { target }),
            }],
            Some(vec![crate::tree_format::Property {
                name: "domain",
                value: b"\x70private:verified",
            }]),
            1024,
            TreeUse::Ordinary,
        )
        .unwrap()
    };
    let base = input(b"base");
    let ours = input(b"target");
    let theirs = input(b"untrusted");
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
                time: 100,
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
    let evaluators = vec![context(our_view), context(their_view)];
    let trust = TrustContext::from_verified(evaluators.clone()).unwrap();
    let mut domains = OperationDomains::new();
    domains
        .bind_resolved(
            ours.root_identity(),
            &effective_properties("private:verified"),
        )
        .unwrap();
    domains
        .bind_resolved(
            theirs.root_identity(),
            &effective_properties("private:verified"),
        )
        .unwrap();
    let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
    let result = merge_with_domains(
        &base,
        &ours,
        &theirs,
        &policies,
        &trust,
        &Forest(vec![]),
        &domains,
    )
    .unwrap();
    assert_eq!(result.tree.get(b"file"), ours.get(b"file"));
    assert_eq!(
        result.tree.props().unwrap()[0].value,
        b"\x70private:verified"
    );

    let same_time = merge_with_domains(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::PreferNewer, MergePolicy::KeepConflict],
        &trust,
        &Forest(vec![]),
        &domains,
    )
    .unwrap();
    assert!(same_time.conflicted);

    let decoded = Recipe::decode(&result.recipe).unwrap();
    let rebound = decoded.bind_verified(evaluators.clone()).unwrap();
    let Recipe::Merge { trust, .. } = rebound.as_recipe() else {
        panic!("expected merge recipe");
    };
    let replayed = merge_with_domains(
        &base,
        &ours,
        &theirs,
        &policies,
        trust,
        &Forest(vec![]),
        &domains,
    )
    .unwrap();
    assert_eq!(replayed.tree.root_identity(), result.tree.root_identity());

    let reversed =
        TrustContext::from_verified(vec![evaluators[1].clone(), evaluators[0].clone()]).unwrap();
    assert_eq!(
        merge(&base, &ours, &theirs, &policies, &reversed, &Forest(vec![])).unwrap_err(),
        Error::Trust(TrustError::Context),
    );
    let fabricated = input(b"fabricated");
    assert_eq!(
        merge(&base, &ours, &fabricated, &policies, trust, &Forest(vec![])).unwrap_err(),
        Error::Trust(TrustError::Context),
    );
}

#[test]
fn trusted_fold_replays_exclusions_before_rebinding_signed_input() {
    use super::signed_fixture::{SignedSide, signed_history};
    use crate::provenance::{Preset, Selector};

    let input = |target: &'static [u8]| {
        Tree::build(
            vec![LeafItem {
                key: b"file".to_vec(),
                entry: entry(EntryKind::Symlink { target }),
            }],
            Some(vec![crate::tree_format::Property {
                name: "domain",
                value: b"\x70private:verified",
            }]),
            1024,
            TreeUse::Ordinary,
        )
        .unwrap()
    };
    let base = Tree::build(vec![], None, 1024, TreeUse::Ordinary).unwrap();
    let ours = input(b"target");
    let theirs = input(b"untrusted");
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
                time: 100,
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
    let evaluators = vec![context(our_view), context(their_view)];
    let trust = TrustContext::from_verified(evaluators.clone()).unwrap();
    let mut domains = OperationDomains::new();
    domains
        .bind_resolved(
            ours.root_identity(),
            &effective_properties("private:verified"),
        )
        .unwrap();
    domains
        .bind_resolved(
            theirs.root_identity(),
            &effective_properties("private:verified"),
        )
        .unwrap();
    let policies = [MergePolicy::PreferTrusted, MergePolicy::KeepConflict];
    let result = fold_with_domains(
        &base,
        &ours,
        &theirs,
        [our_view, their_view],
        &policies,
        &trust,
        &Forest(vec![]),
        |_, _| false,
        Retirement::Delete,
        &domains,
    )
    .unwrap();
    assert_eq!(result.excluded, vec![b"file".to_vec()]);
    assert_eq!(result.merged.tree.get(b"file"), ours.get(b"file"));
    let filtered = result.merged.derived_roots.first().unwrap();

    let decoded = Recipe::decode(&result.merged.recipe).unwrap();
    let rebound = decoded
        .clone()
        .bind_fold_verified_with_domains(
            evaluators.clone(),
            &base,
            &theirs,
            filtered,
            &result.excluded,
            &domains,
        )
        .unwrap();
    let Recipe::Merge { trust, .. } = rebound.as_recipe() else {
        panic!("expected merge recipe");
    };
    assert_eq!(
        merge_with_domains(
            &base,
            &ours,
            filtered,
            &policies,
            trust,
            &Forest(vec![]),
            &domains
        )
        .unwrap()
        .tree
        .root_identity(),
        result.merged.tree.root_identity(),
    );

    for exclusions in [
        vec![b"file".to_vec(), b"file".to_vec()],
        vec![b"z".to_vec(), b"a".to_vec()],
    ] {
        assert!(
            decoded
                .clone()
                .bind_fold_verified(evaluators.clone(), &base, &theirs, &base, &exclusions,)
                .is_err()
        );
    }
    assert!(
        decoded
            .bind_fold_verified(evaluators, &base, &theirs, &base, &[],)
            .is_err()
    );
}

#[test]
fn acyclic_checked_graft_and_reader_reject_alias_cycles() {
    struct Alias(Tree<'static>);
    impl Roots<'static> for Alias {
        fn resolve(&self, _: &crate::identity::Digest) -> Option<&Tree<'static>> {
            Some(&self.0)
        }
    }
    let target = tree(&[(
        b"again",
        entry(EntryKind::Tree {
            root: [3; 32],
            props: None,
        }),
    )]);
    let roots = Alias(target.clone());

    assert_eq!(
        graft(&tree(&[]), b"mount", graft_entry(&target), false, &roots).unwrap_err(),
        Error::RootIdentity
    );
    assert_eq!(
        lookup(&target, b"again/again/file", &roots).unwrap_err(),
        Error::RootIdentity
    );
}

#[test]
fn graft_certificates_skip_large_unchanged_parent_nodes() {
    let items = (0..5000)
        .map(|index| LeafItem {
            key: alloc::format!("key-{index:08}").into_bytes(),
            entry: value(b"long shared namespace value"),
        })
        .collect();
    let parent = Tree::build(items, fixture_properties(), 4096, TreeUse::Ordinary).unwrap();
    let target = tree(&[]);
    let roots = Forest(vec![target.clone()]);
    let mut graph = RootGraph::new();
    let first = graph.admit(&parent, &roots).unwrap();
    assert!(first.nodes > 10);

    let first_graft = graft_certified(
        &parent,
        b"key-00002500",
        graft_entry(&target),
        false,
        &roots,
        &mut graph,
    )
    .unwrap();
    let second_graft = graft_certified(
        &first_graft.tree,
        b"key-00002501",
        graft_entry(&target),
        false,
        &roots,
        &mut graph,
    )
    .unwrap();
    assert!(first_graft.admission.nodes < first.nodes);
    assert!(second_graft.admission.nodes < first.nodes);
    assert!(second_graft.mutation.node_reads < parent.nodes().count());
    assert_eq!(
        graph.admit(&second_graft.tree, &roots).unwrap(),
        GraphWork::default()
    );
}

#[test]
fn acyclic_boundary_accepts_64_edges_with_cached_frontiers() {
    let mut layers = vec![tree(&[])];
    for _ in 0..63 {
        layers.push(tree(&[(b"child", graft_entry(layers.last().unwrap()))]));
    }
    let mut items = (0..5000)
        .map(|index| LeafItem {
            key: alloc::format!("own-{index:08}").into_bytes(),
            entry: value(b"retained"),
        })
        .collect::<Vec<_>>();
    items.insert(
        0,
        LeafItem {
            key: b"child".to_vec(),
            entry: graft_entry(layers.last().unwrap()),
        },
    );
    let boundary = Tree::build(items, fixture_properties(), 4096, TreeUse::OverlayLayer).unwrap();
    let changed = boundary
        .edit_entries(&[(b"own-00004999".to_vec(), Some(value(b"changed")))])
        .unwrap()
        .tree;
    let shares_node = boundary
        .nodes()
        .any(|before| changed.nodes().any(|after| core::ptr::eq(before, after)));
    assert!(shares_node);

    layers.push(boundary.clone());
    layers.push(changed.clone());
    let roots = Forest(layers);
    validate_acyclic(&boundary, &roots).unwrap();
    let mut graph = RootGraph::new();
    graph.admit(&boundary, &roots).unwrap();
    let admitted = graph.admit(&changed, &roots).unwrap();
    assert_eq!(admitted.roots, 1);
    assert!(admitted.nodes < changed.nodes().count());
    assert_eq!(graph.admit(&changed, &roots).unwrap(), GraphWork::default());

    let excessive = tree(&[(b"child", graft_entry(&changed))]);
    assert_eq!(validate_acyclic(&excessive, &roots), Err(Error::Cycle));
    assert_eq!(graph.admit(&excessive, &roots), Err(Error::Cycle));

    // A changed root must enforce the cap when its shared leaf certificate
    // is reused at a greater depth, before that new root is itself cached.
    let mut shared_nodes = RootGraph::new();
    shared_nodes.admit(&boundary, &roots).unwrap();
    assert_eq!(shared_nodes.admit(&excessive, &roots), Err(Error::Cycle));
}

#[test]
fn graft_certificates_replace_deep_targets_using_exact_height() {
    let empty = tree(&[]);
    let mut layers = vec![empty.clone()];
    for _ in 0..62 {
        let target = layers.last().unwrap();
        layers.push(tree(&[(b"child", graft_entry(target))]));
    }
    let deepest = layers.last().unwrap();
    let parent = tree(&[
        (b"child", graft_entry(deepest)),
        (b"own", value(b"retained")),
    ]);
    let roots = Forest(layers);
    let mut graph = RootGraph::new();
    graph.admit(&parent, &roots).unwrap();

    let result = graft_certified(
        &parent,
        b"child",
        graft_entry(&empty),
        false,
        &roots,
        &mut graph,
    )
    .unwrap();
    assert_eq!(result.tree.get(b"own"), parent.get(b"own"));
    assert_eq!(result.admission.roots, 1);
    validate_acyclic(&result.tree, &roots).unwrap();
}

#[test]
fn graft_and_split_seek_separator_range_past_punctuation_siblings() {
    let parent = tree(&[
        (b"a", entry(EntryKind::Directory { mode: 0o755 })),
        (b"a!", value(b"sibling")),
        (b"a/b", value(b"child")),
    ]);
    let target = tree(&[]);
    let roots = Forest(vec![target.clone()]);

    assert_eq!(
        graft(&parent, b"a", graft_entry(&target), false, &roots).unwrap_err(),
        Error::InlineChildren
    );
    let split = split(&parent, b"a", &roots).unwrap();
    assert_eq!(split.get(b"b"), Some(&value(b"child")));
    let grafted = graft(&parent, b"a", graft_entry(&target), true, &roots).unwrap();
    assert_eq!(grafted.get(b"a!"), Some(&value(b"sibling")));
    assert!(grafted.get(b"a/b").is_none());
}

#[test]
fn merge_prefer_newer_binds_verified_timestamps_and_falls_back_on_ties() {
    let base = tree(&[(b"a", value(b"base"))]);
    let ours = tree(&[(b"a", value(b"ours"))]);
    let theirs = tree(&[(b"a", value(b"theirs"))]);
    let context = untrusted()
        .with_verified_timestamps(vec![([b'o'; 32], 10), ([b't'; 32], 20)])
        .unwrap();
    let policies = [MergePolicy::PreferNewer, MergePolicy::KeepConflict];
    let result = merge(&base, &ours, &theirs, &policies, &context, &Forest(vec![])).unwrap();
    assert_eq!(result.tree.root_identity(), theirs.root_identity());
    let decoded = Recipe::decode(&result.recipe).unwrap();
    assert_eq!(decoded.as_recipe().encode(), result.recipe);

    let tied = untrusted()
        .with_verified_timestamps(vec![([b'o'; 32], 20), ([b't'; 32], 20)])
        .unwrap();
    let result = merge(&base, &ours, &theirs, &policies, &tied, &Forest(vec![])).unwrap();
    assert!(result.conflicted);
    assert!(
        untrusted()
            .with_verified_timestamps(vec![([1; 32], 1), ([1; 32], 2)])
            .is_err()
    );
}

#[test]
fn merge_adopts_unchanged_base_ranges_from_incoming_subtrees() {
    let entries: Vec<_> = (0..10000)
        .map(|number| LeafItem {
            key: alloc::format!("{number:08}").into_bytes(),
            entry: value(b"base"),
        })
        .collect();
    let base = Tree::build(entries, fixture_properties(), 4096, TreeUse::Ordinary).unwrap();
    let ours = base
        .insert(LeafItem {
            key: b"00000001".to_vec(),
            entry: value(b"ours"),
        })
        .unwrap()
        .tree;
    let theirs = base
        .insert(LeafItem {
            key: b"00005001".to_vec(),
            entry: value(b"theirs"),
        })
        .unwrap()
        .tree;
    let result = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::KeepConflict],
        &untrusted(),
        &Forest(vec![]),
    )
    .unwrap();
    let expected = ours
        .insert(LeafItem {
            key: b"00005001".to_vec(),
            entry: value(b"theirs"),
        })
        .unwrap()
        .tree;
    assert_eq!(result.tree.root_identity(), expected.root_identity());
    assert!(result.reused_subtrees > 0);
    let target = theirs
        .nodes()
        .find(|node| {
            node.identity() != base.root_identity()
                && node.first_key().is_some_and(|first| first <= b"00005001")
                && node.last_key().is_some_and(|last| last >= b"00005001")
                && node.level() == 0
        })
        .unwrap();
    let retained = result
        .tree
        .nodes()
        .find(|node| node.identity() == target.identity())
        .unwrap();
    assert!(core::ptr::eq(target, retained));
    assert!(result.expanded_nodes < 100);
}

#[test]
fn merge_certificates_track_nested_conflicts_without_rescanning_fast_forward() {
    let conflicted_target = tree(&[(
        b"a",
        entry(EntryKind::Conflict {
            candidates: vec![value(b"ours"), value(b"theirs")],
            base: Some(Some(alloc::boxed::Box::new(value(b"base")))),
        }),
    )]);
    let incoming = tree(&[(b"graft", graft_entry(&conflicted_target))]);
    let base = tree(&[]);
    let roots = Forest(vec![conflicted_target]);
    let mut graph = RootGraph::new();
    let first = merge_certified(
        &base,
        &base,
        &incoming,
        &[MergePolicy::KeepConflict],
        &untrusted(),
        &roots,
        &mut graph,
    )
    .unwrap();
    assert!(first.conflicted);
    assert!(first.admission_work.nodes > 0);
    let second = merge_certified(
        &base,
        &base,
        &incoming,
        &[MergePolicy::KeepConflict],
        &untrusted(),
        &roots,
        &mut graph,
    )
    .unwrap();
    assert!(second.conflicted);
    assert_eq!(second.admission_work, GraphWork::default());
    assert_eq!(second.expanded_nodes, 0);
}

#[test]
fn diff_descent_reports_nested_implied_root_properties() {
    let target = tree(&[(b"a", value(b"value"))]);
    let changed = target
        .with_properties(Some(vec![
            crate::tree_format::Property {
                name: "trust",
                value: b"\x63any",
            },
            crate::tree_format::Property {
                name: "domain",
                value: b"\x6fprivate:fixture",
            },
        ]))
        .unwrap()
        .tree;
    let before = tree(&[(b"mount", graft_entry(&target))]);
    let after = tree(&[(b"mount", graft_entry(&changed))]);
    let roots = Forest(vec![target, changed]);
    let report = diff_descend_with_work(&before, &after, &roots).unwrap();
    assert!(report.changes.is_empty());
    assert_eq!(report.properties.len(), 1);
    assert_eq!(report.properties[0].path, b"mount");
    assert_eq!(report.properties[0].properties.old, fixture_properties());
}

#[test]
fn merge_updates_complete_hardlink_sets_atomically() {
    let linked = |content| {
        entry(EntryKind::File {
            mode: 0o644,
            size: 1,
            content: ContentRef::Inline([content; 32]),
            link_id: Some(b"a"),
        })
    };
    let base = tree(&[(b"a", linked(1)), (b"b", linked(1)), (b"c", value(b"base"))]);
    let ours = tree(&[(b"a", linked(1)), (b"b", linked(1)), (b"c", value(b"ours"))]);
    let theirs = tree(&[(b"a", linked(2)), (b"b", linked(2)), (b"c", value(b"base"))]);
    let expected = tree(&[(b"a", linked(2)), (b"b", linked(2)), (b"c", value(b"ours"))]);
    let result = merge(
        &base,
        &ours,
        &theirs,
        &[MergePolicy::KeepConflict],
        &untrusted(),
        &Forest(vec![]),
    )
    .unwrap();
    assert_eq!(result.tree.root_identity(), expected.root_identity());
    assert!(!result.conflicted);
}

fn graft_chain(leaf: Tree<'static>, edges: usize) -> Vec<Tree<'static>> {
    let mut layers = vec![leaf];
    for _ in 0..edges {
        layers.push(tree(&[(b"child", graft_entry(layers.last().unwrap()))]));
    }
    layers
}

#[test]
fn graft_lookup_accepts_64_edges_and_rejects_65() {
    let layers = graft_chain(tree(&[(b"value", value(b"leaf"))]), 65);
    let roots = Forest(layers.clone());
    let mut path = b"child/".repeat(64);
    path.extend_from_slice(b"value");

    assert_eq!(
        lookup(&layers[64], &path, &roots).unwrap(),
        layers[0].get(b"value")
    );

    path.splice(0..0, b"child/".iter().copied());
    assert_eq!(lookup(&layers[65], &path, &roots), Err(Error::Cycle));
}

#[test]
fn diff_descent_accepts_64_edges_and_rejects_65() {
    let before = graft_chain(tree(&[(b"value", value(b"before"))]), 65);
    let after = graft_chain(tree(&[(b"value", value(b"after"))]), 65);
    let roots = Forest(before.iter().chain(&after).cloned().collect());
    let mut path = b"child/".repeat(64);
    path.extend_from_slice(b"value");

    let changes = diff_descend(&before[64], &after[64], &roots).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path(), path);

    assert_eq!(
        diff_descend(&before[65], &after[65], &roots),
        Err(Error::Cycle)
    );
}

#[test]
fn merge_recurses_through_64_graft_edges() {
    let base = graft_chain(tree(&[(b"value", value(b"base"))]), 64);
    let ours = graft_chain(tree(&[(b"value", value(b"ours"))]), 64);
    let theirs = graft_chain(tree(&[(b"value", value(b"theirs"))]), 64);
    let roots = Forest(base.iter().chain(&ours).chain(&theirs).cloned().collect());

    let result = merge(
        &base[64],
        &ours[64],
        &theirs[64],
        &[MergePolicy::PreferOurs],
        &TrustContext::any(),
        &roots,
    )
    .unwrap();

    assert_eq!(result.tree.root_identity(), ours[64].root_identity());
    assert!(!result.conflicted);
}

#[test]
fn diff_and_graft_lookup_reject_resolver_identity_mismatch() {
    struct Alias(Tree<'static>);

    impl<'a> Roots<'a> for Alias {
        fn resolve(&self, _: &crate::identity::Digest) -> Option<&Tree<'a>> {
            Some(&self.0)
        }
    }

    let before = tree(&[(b"value", value(b"before"))]);
    let after = tree(&[(b"value", value(b"after"))]);
    let old_root = tree(&[(b"child", graft_entry(&before))]);
    let new_root = tree(&[(b"child", graft_entry(&after))]);
    let roots = Alias(tree(&[]));

    assert_eq!(
        lookup(&old_root, b"child/value", &roots),
        Err(Error::RootIdentity)
    );
    assert_eq!(
        diff_descend(&old_root, &new_root, &roots),
        Err(Error::RootIdentity)
    );
}
