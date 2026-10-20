//! Exercises signed path evaluation when pruning overlaps an incoming subtree.

#![allow(clippy::unwrap_used)]

use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::algebra::signed_fixture::{SignedSide, signed_history};
use crate::algebra::{RootGraph, TrustContext, merge_certified};
use crate::identity::Digest;
use crate::provenance::{Preset, Selector};
use crate::tree_format::{ExtendedAttribute, LeafItem, TreeUse};

fn plain<'a>(kind: EntryKind<'a>) -> Entry<'a> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn padded<'a>(kind: EntryKind<'a>, padding: &'a [u8]) -> Entry<'a> {
    Entry {
        xattrs: vec![ExtendedAttribute {
            name: b"user.padding",
            value: padding,
        }],
        xattrs_present: true,
        ..plain(kind)
    }
}

fn build<'a>(entries: Vec<(&[u8], Entry<'a>)>) -> Tree<'a> {
    Tree::build(
        entries
            .into_iter()
            .map(|(key, entry)| LeafItem {
                key: key.to_vec(),
                entry,
            })
            .collect(),
        Some(vec![crate::tree_format::Property {
            name: "domain",
            value: b"\x6fprivate:fixture",
        }]),
        1024,
        TreeUse::Ordinary,
    )
    .unwrap()
}

#[test]
fn trusted_nested_graft_pruning_retains_full_path_on_splice_fallback() {
    // Large attributes force cuts after `a` and `a1`. The shared incoming
    // frontier spans the removed `a/child` range without containing that key.
    let padding = [0; 16384];
    let child = |kind, target, keep_descendant| {
        let mut entries = vec![
            (b"a".as_slice(), padded(kind, &padding)),
            (
                b"a-".as_slice(),
                plain(EntryKind::Symlink { target: b"shared" }),
            ),
        ];
        if keep_descendant {
            entries.push((b"a/child", plain(EntryKind::Symlink { target: b"child" })));
        }
        entries.extend([
            (
                b"a1".as_slice(),
                padded(EntryKind::Symlink { target: b"shared" }, &padding),
            ),
            (b"z".as_slice(), plain(EntryKind::Symlink { target })),
        ]);
        build(entries)
    };
    let base_child = child(EntryKind::Directory { mode: 0o755 }, b"base", true);
    let our_child = child(EntryKind::Directory { mode: 0o700 }, b"ours", true);
    let their_child = child(
        EntryKind::Symlink {
            target: b"replacement",
        },
        b"theirs",
        false,
    );
    let mount = |target: &Tree<'_>| {
        build(vec![(
            b"mount",
            plain(EntryKind::Tree {
                root: target.root_identity(),
                props: None,
            }),
        )])
    };
    let base = mount(&base_child);
    let ours = mount(&our_child);
    let theirs = mount(&their_child);
    let patch_frontier = |tree: &Tree<'_>| {
        tree.nodes()
            .find(|node| {
                node.level() == 0
                    && node.first_key() == Some(b"a-")
                    && node.last_key() == Some(b"a1")
            })
            .unwrap()
            .identity()
    };
    assert_eq!(patch_frontier(&base_child), patch_frontier(&our_child));
    assert_ne!(patch_frontier(&base_child), patch_frontier(&their_child));

    let (history, views) = signed_history(
        [
            SignedSide {
                tree: &ours,
                child: Some(&our_child),
                baseline: false,
                time: 100,
            },
            SignedSide {
                tree: &theirs,
                child: Some(&their_child),
                baseline: true,
                time: 101,
            },
        ],
        "private:fixture",
    );
    let evaluators = views
        .into_iter()
        .map(|view| {
            crate::provenance::TrustContext::new(
                &history,
                view,
                Selector::preset(Preset::Strict),
                "private:fixture",
                Some("baseline"),
            )
            .unwrap()
        })
        .collect();
    let trust = TrustContext::from_verified(evaluators).unwrap();

    struct Forest<'a>(Vec<Tree<'a>>);
    impl<'a> Roots<'a> for Forest<'a> {
        fn resolve(&self, identity: &Digest) -> Option<&Tree<'a>> {
            self.0.iter().find(|tree| tree.root_identity() == *identity)
        }
    }
    let roots = Forest(vec![base_child, our_child, their_child.clone()]);
    for policy in [MergePolicy::PreferTrusted, MergePolicy::PreferNewer] {
        let result = merge_certified(
            &base,
            &ours,
            &theirs,
            &[policy, MergePolicy::KeepConflict],
            &trust,
            &roots,
            &mut RootGraph::new(),
        )
        .unwrap();

        assert!(!result.conflicted, "{policy:?}");
        assert_eq!(result.reused_subtrees, 0);
        assert_eq!(result.derived_roots.len(), 1);
        assert_eq!(
            result.derived_roots[0].root_identity(),
            their_child.root_identity()
        );
        assert_eq!(result.tree.root_identity(), theirs.root_identity());
    }
}
