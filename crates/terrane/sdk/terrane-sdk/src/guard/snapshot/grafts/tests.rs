//! Exercises physical graft placements and validator-owned depth certificates.
//!
//! Digest labels describe already captured graphs. Canonical namespace loading
//! and contextual authority are exercised separately by the snapshot tests.

#![allow(clippy::unwrap_used)]

use terrane_format::identity::Digest;
use terrane_format::tree_format::{Entry, EntryKind, MAX_GRAFT_DEPTH, TreeUse};

use super::Capture;

const MINIMUM: u64 = 262_144;

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

fn graft(root: Digest) -> Entry<'static> {
    entry(EntryKind::Tree { root, props: None })
}

fn captured_graph(owners: &[Digest], edges: &[(Digest, &[u8], Digest)]) -> Capture {
    let mut capture = Capture::default();
    for &owner in owners {
        capture.begin(owner).unwrap();
        capture.node().unwrap();
    }

    for &(owner, key, target) in edges {
        capture.item(owner, key, &graft(target)).unwrap();
    }

    capture
}

fn chain(graft_depth: usize) -> (Capture, Vec<Digest>) {
    let owners: Vec<_> = (0..=graft_depth)
        .map(|label| [u8::try_from(label).unwrap(); 32])
        .collect();
    let edges: Vec<_> = owners
        .windows(2)
        .map(|pair| (pair[0], b"next".as_slice(), pair[1]))
        .collect();

    (captured_graph(&owners, &edges), owners)
}

#[test]
fn longest_shared_path_is_independent_of_graft_visitation_order() {
    let root = [0; 32];
    let shared = [3; 32];
    let tail = [4; 32];

    // Child digests control the ordered edge walk. These labels visit the shared
    // child first through the short path, then first through the long path.
    for (long_start, long_inner, expected_edge_visits) in
        [([1; 32], [2; 32], 6), ([5; 32], [6; 32], 5)]
    {
        let capture = captured_graph(
            &[root, long_start, long_inner, shared, tail],
            &[
                (root, b"short", shared),
                (root, b"long", long_start),
                (long_start, b"next", long_inner),
                (long_inner, b"shared", shared),
                (shared, b"tail", tail),
            ],
        );

        let validated = capture.finish(root, MINIMUM, TreeUse::Ordinary).unwrap();

        assert_eq!(validated.owner(root), Some((1, 2)));
        assert_eq!(validated.owner(long_start), Some((2, 1)));
        assert_eq!(validated.owner(long_inner), Some((3, 1)));
        assert_eq!(validated.owner(shared), Some((4, 1)));
        assert_eq!(validated.owner(tail), Some((5, 0)));
        assert_eq!(validated.work().depth_edges, expected_edge_visits);

        let placements: Vec<_> = validated
            .locations(shared)
            .iter()
            .map(|address| (address.owner, address.key.as_slice()))
            .collect();
        assert_eq!(
            placements,
            [
                (root, b"short".as_slice()),
                (long_inner, b"shared".as_slice())
            ]
        );
    }
}

#[test]
fn physical_graft_depth_limit_accepts_boundary_and_withholds_invalid_certificates() {
    let (capture, owners) = chain(MAX_GRAFT_DEPTH);
    let validated = capture
        .finish(owners[0], MINIMUM, TreeUse::Ordinary)
        .unwrap();

    assert_eq!(validated.owner(owners[0]), Some((1, 1)));
    assert_eq!(
        validated.owner(*owners.last().unwrap()),
        Some((MAX_GRAFT_DEPTH + 1, 0))
    );
    for (position, &owner) in owners.iter().enumerate() {
        let expected_slots = usize::from(position < MAX_GRAFT_DEPTH);
        assert_eq!(validated.owner(owner), Some((position + 1, expected_slots)));
    }

    let (capture, owners) = chain(MAX_GRAFT_DEPTH + 1);
    let overdepth = capture
        .finish(owners[0], MINIMUM, TreeUse::Ordinary)
        .unwrap();

    assert!(owners.iter().all(|&owner| overdepth.owner(owner).is_none()));
    assert_eq!(overdepth.locations(owners[1]).len(), 1);
    assert!(overdepth.matches(owners[0], MINIMUM, TreeUse::Ordinary));

    // This captured graph exercises certificate refusal, without claiming that
    // a cyclic graph of digest labels is a canonical Merkle namespace.
    let root = [0; 32];
    let child = [1; 32];
    let cycle = captured_graph(
        &[root, child],
        &[(root, b"child", child), (child, b"back", root)],
    )
    .finish(root, MINIMUM, TreeUse::Ordinary)
    .unwrap();

    assert_eq!(cycle.owner(root), None);
    assert_eq!(cycle.owner(child), None);
    assert_eq!(cycle.locations(root).len(), 1);
    assert_eq!(cycle.locations(child).len(), 1);
}

#[test]
fn conflict_candidates_and_present_base_preserve_distinct_graft_slots() {
    let root = [0; 32];
    let target = [1; 32];

    for (base, expected_slots) in [
        (None, 2),
        (Some(None), 2),
        (Some(Some(Box::new(graft(target)))), 3),
    ] {
        let conflict = entry(EntryKind::Conflict {
            candidates: vec![graft(target), graft(target)],
            base,
        });
        let mut capture = captured_graph(&[root, target], &[]);
        let mut containing_key = b"mount".to_vec();
        capture.item(root, &containing_key, &conflict).unwrap();
        containing_key.fill(b'x');

        let validated = capture.finish(root, MINIMUM, TreeUse::Ordinary).unwrap();

        assert_eq!(validated.owner(root), Some((1, expected_slots)));
        assert_eq!(validated.owner(target), Some((2, 0)));
        assert_eq!(validated.locations(target).len(), expected_slots);
        assert!(
            validated
                .locations(target)
                .iter()
                .all(|address| { address.owner == root && address.key.as_slice() == b"mount" })
        );

        let work = validated.work();
        assert_eq!(work.graft_slots, expected_slots);
        assert_eq!(work.addresses, expected_slots);
        assert_eq!(work.key_bytes, expected_slots * b"mount".len());
        assert_eq!(work.nested_entry_visits, expected_slots + 1);
        assert_eq!(work.depth_edges, 1);
    }
}

#[test]
fn retained_graft_validation_requires_exact_root_usage_and_minimum() {
    let root = [0; 32];
    let child = [1; 32];
    let absent = [2; 32];
    let validated = captured_graph(&[root, child], &[(root, b"child", child)])
        .finish(root, MINIMUM, TreeUse::Ordinary)
        .unwrap();

    assert_eq!(validated.root(), root);
    assert!(validated.matches(root, MINIMUM, TreeUse::Ordinary));
    assert!(!validated.matches(child, MINIMUM, TreeUse::Ordinary));
    assert!(!validated.matches(absent, MINIMUM, TreeUse::Ordinary));
    assert!(!validated.matches(root, MINIMUM + 1, TreeUse::Ordinary));
    for usage in [
        TreeUse::OverlayLayer,
        TreeUse::Index,
        TreeUse::Surface,
        TreeUse::ConflictSurface,
    ] {
        assert!(!validated.matches(root, MINIMUM, usage));
    }

    // Captured child addresses remain root-local selectors. Finding an owner
    // does not grant that child the cached namespace's interpretation.
    assert_eq!(validated.owner(child), Some((2, 0)));
    assert_eq!(validated.locations(child).len(), 1);
    assert_eq!(validated.owner(absent), None);
    assert!(validated.locations(absent).is_empty());
}
