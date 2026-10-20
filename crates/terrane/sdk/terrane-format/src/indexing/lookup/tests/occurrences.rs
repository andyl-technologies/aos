//! Checks complete local hop models, shared contexts and distinct missing occurrences.

use super::*;

/// Checks complete present/missing occurrence fields across repeated and deep grafts.
///
/// # Panics
/// Panics if fixture construction or an asserted lookup contract fails.
pub(super) fn check() {
    super::internal::check();
    let (data, _, missing, _) = model();
    let (old, original) = sources();
    let child = original[&old].get(b"g").unwrap();
    let EntryKind::Tree {
        root: child_root, ..
    } = child.kind
    else {
        panic!("graft")
    };
    let bytes = binding("uid", data.root);
    let (owner, trees) = bind(old, &original, &bytes);
    let prepared = Prepared::prepare(
        IndexEvaluationRecipe::new(owner, "uid").unwrap(),
        &trees,
        MINIMUM,
        context(),
        &data,
    )
    .unwrap();
    let present = prepared.candidates(b"\x01").unwrap();
    super::traversal::assert_independent_active_limits(&present.rows[0]);
    let occurrences = present.rows[0].occurrences().unwrap();
    let first = present.rows[0].first_occurrence().unwrap();
    assert_eq!(first.occurrence.as_ref(), occurrences.rows.first());
    assert_eq!(
        (
            first.work.occurrences,
            first.work.route_rows,
            first.work.route_nodes,
            first.work.source_roots
        ),
        (1, 1, 1, 1)
    );
    let actual: Vec<_> = occurrences
        .rows
        .iter()
        .map(|row| {
            (
                row.hops
                    .iter()
                    .map(|hop| (hop.source_root, hop.key.clone(), hop.target))
                    .collect::<Vec<_>>(),
                row.source_root,
                row.key.clone(),
                row.content,
                row.size,
                row.value,
            )
        })
        .collect();
    let expected = alloc::vec![
        (
            Vec::new(),
            owner,
            b"f".to_vec(),
            ContentRef::Inline(ONE),
            1,
            Some(b"\x01".as_slice())
        ),
        (
            alloc::vec![(owner, b"g".to_vec(), child_root)],
            child_root,
            b"a".to_vec(),
            ContentRef::Inline(ONE),
            1,
            Some(b"\x01".as_slice())
        ),
        (
            alloc::vec![(owner, b"h".to_vec(), child_root)],
            child_root,
            b"a".to_vec(),
            ContentRef::Inline(ONE),
            1,
            Some(b"\x01".as_slice())
        ),
    ];
    assert_eq!(actual, expected);
    assert_eq!(
        (
            occurrences.work.occurrences,
            occurrences.work.route_rows,
            occurrences.work.route_nodes,
            occurrences.work.source_roots,
            occurrences.work.source_nodes
        ),
        (3, 5, 3, 3, 5)
    );
    assert_eq!(occurrences.work.source_comparisons, 12);
    for occurrence in &occurrences.rows {
        assert_eq!(occurrence.entry, &file(ONE, Some(b"\x01"), "uid", false));
        for hop in &occurrence.hops {
            assert_eq!(hop.entry, &graft(child_root));
        }
    }
    let gaps = prepared.missing(ONE).unwrap();
    assert_eq!(gaps.rows[0].route(), missing);
    let gap_probe = gaps.rows[0].first_occurrence().unwrap();
    let gaps = gaps.rows[0].occurrences().unwrap();
    for row in &gaps.rows {
        assert_eq!(row.entry, &file(ONE, None, "uid", false));
        for hop in &row.hops {
            assert_eq!(hop.entry, &graft(hop.target));
        }
    }
    assert_eq!(gap_probe.occurrence.as_ref(), gaps.rows.first());
    assert_eq!(
        (
            gap_probe.work.occurrences,
            gap_probe.work.route_rows,
            gap_probe.work.route_nodes,
            gap_probe.work.source_roots
        ),
        (1, 2, 2, 2)
    );
    let actual: Vec<_> = gaps
        .rows
        .iter()
        .map(|row| {
            (
                row.hops
                    .iter()
                    .map(|hop| hop.key.clone())
                    .collect::<Vec<_>>(),
                row.source_root,
                row.key.clone(),
                row.content,
                row.value,
            )
        })
        .collect();
    assert_eq!(
        actual,
        alloc::vec![
            (
                alloc::vec![b"g".to_vec()],
                child_root,
                b"b".to_vec(),
                ContentRef::Inline(ONE),
                None
            ),
            (
                alloc::vec![b"h".to_vec()],
                child_root,
                b"b".to_vec(),
                ContentRef::Inline(ONE),
                None
            ),
            (
                Vec::new(),
                owner,
                b"m".to_vec(),
                ContentRef::Inline(ONE),
                None
            ),
        ]
    );
    assert_eq!(
        (
            gaps.work.occurrences,
            gaps.work.route_rows,
            gaps.work.route_nodes
        ),
        (3, 5, 3)
    );
    assert_eq!(gaps.work.source_comparisons, 9);
    assert!(prepared.missing([0x44; 32]).unwrap().rows.is_empty());

    let manifest_rows = prepared.missing(THREE).unwrap();
    assert_eq!(manifest_rows.work.candidates, 0);
    assert_eq!(manifest_rows.work.missing_rows, 1);
    let manifest_rows = manifest_rows.rows[0].occurrences().unwrap();
    let child_route = id(&wire(&[terminal(b"d", THREE)], None));
    let child_entry = file(THREE, None, "uid", true);
    let graft_entry = graft(child_root);
    let expected: Vec<_> = [b"g".as_slice(), b"h".as_slice()]
        .into_iter()
        .map(|key| Occurrence {
            hops: alloc::vec![Hop {
                source_root: owner,
                key: key.to_vec(),
                target: child_root,
                route: child_route,
                entry: &graft_entry
            }],
            source_root: child_root,
            key: b"d".to_vec(),
            content: ContentRef::Manifest(THREE),
            size: MINIMUM + 1,
            value: None,
            entry: &child_entry,
        })
        .collect();
    assert_eq!(manifest_rows.rows, expected);
    assert_eq!(
        (
            manifest_rows.work.occurrences,
            manifest_rows.work.route_rows,
            manifest_rows.work.source_roots
        ),
        (2, 4, 3)
    );

    // Shared I/P bytes must retain the bound view. Consumption belongs to the
    // Candidate itself: there is no Prepared::occurrences(other_candidate) API.
    let mut distinct_original = original.clone();
    let distinct = tree(alloc::vec![
        leaf(b"f", file(ONE, Some(b"\x01"), "uid", false)),
        leaf(b"g", graft(child_root)),
        leaf(b"h", graft(child_root)),
        leaf(b"m", file(ONE, None, "uid", false)),
        leaf(
            b"z",
            Entry {
                kind: EntryKind::Symlink { target: b"target" },
                attrs: Vec::new(),
                attrs_present: false,
                xattrs: Vec::new(),
                xattrs_present: false,
                provenance: None
            }
        )
    ]);
    let other_old = distinct.root_identity();
    distinct_original.insert(other_old, distinct);
    let (other_owner, other_trees) = bind(other_old, &distinct_original, &bytes);
    let other = Prepared::prepare(
        IndexEvaluationRecipe::new(other_owner, "uid").unwrap(),
        &other_trees,
        MINIMUM,
        context(),
        &data,
    )
    .unwrap();
    let other_candidates = other.candidates(b"\x01").unwrap();
    assert_eq!(other_candidates.rows[0].route(), present.rows[0].route());
    assert_ne!(other.owner(), prepared.owner());
    assert_eq!(
        other_candidates.rows[0].occurrences().unwrap().rows[0].source_root,
        other_owner
    );
    assert_eq!(
        present.rows[0].occurrences().unwrap().rows[0].source_root,
        owner
    );

    // Seventeen legal 250-byte local hops exceed the public composed-key limit.
    // The literal two predicates share source grafts, but not route contexts.
    let long = alloc::vec![b'x'; 250];
    let mut graph = BTreeMap::new();
    let bottom = tree(alloc::vec![
        leaf(b"a", file(ONE, Some(b"\x01"), "uid", false)),
        leaf(b"b", file(ONE, None, "uid", false))
    ]);
    let bottom_root = bottom.root_identity();
    graph.insert(bottom_root, bottom);
    let mut nodes = BTreeMap::new();
    let mut present_route = add(&mut nodes, &[terminal(b"a", ONE)], None);
    let mut missing_route = add(&mut nodes, &[terminal(b"b", ONE)], None);
    let mut root = bottom_root;
    let mut expected_chain = Vec::new();
    for _ in 0..16 {
        let parent = tree(alloc::vec![leaf(&long, graft(root))]);
        let parent_root = parent.root_identity();
        let new_present = add(&mut nodes, &[forward(&long, ONE, present_route)], None);
        let new_missing = add(&mut nodes, &[forward(&long, ONE, missing_route)], None);
        expected_chain.push((
            parent_root,
            long.clone(),
            root,
            present_route,
            missing_route,
        ));
        graph.insert(parent_root, parent);
        root = parent_root;
        present_route = new_present;
        missing_route = new_missing;
    }
    let mut left = long.clone();
    left[0] = b'a';
    let mut right = long.clone();
    right[0] = b'b';
    let top = tree(alloc::vec![
        leaf(&left, graft(root)),
        leaf(&right, graft(root))
    ]);
    let old = top.root_identity();
    graph.insert(old, top);
    let primary_route = add(
        &mut nodes,
        &[
            forward(&left, ONE, present_route),
            forward(&right, ONE, present_route),
        ],
        None,
    );
    let gap_route = add(
        &mut nodes,
        &[
            forward(&left, ONE, missing_route),
            forward(&right, ONE, missing_route),
        ],
        None,
    );
    let gap = add(&mut nodes, &[forward(&ONE, ONE, gap_route)], None);
    let primary = add(
        &mut nodes,
        &[forward(&value_key(b"\x01", ONE), ONE, primary_route)],
        Some(gap),
    );
    let data = IndexData {
        root: primary,
        nodes,
        work: evaluation::Work::default(),
    };
    let bytes = binding("uid", primary);
    let (owner, graph) = bind(old, &graph, &bytes);
    let prepared = Prepared::prepare(
        IndexEvaluationRecipe::new(owner, "uid").unwrap(),
        &graph,
        MINIMUM,
        context(),
        &data,
    )
    .unwrap();
    assert!(prepared.candidates(b"\x02").unwrap().rows.is_empty());
    assert_eq!(prepared.all_missing().unwrap().rows.len(), 1);
    for (selection, is_missing) in [
        (prepared.candidates(b"\x01").unwrap(), false),
        (prepared.missing(ONE).unwrap(), true),
    ] {
        let actual = selection.rows[0].occurrences().unwrap();
        assert_eq!(actual.rows.len(), 2);
        assert_eq!(
            (
                actual.work.occurrences,
                actual.work.route_rows,
                actual.work.route_nodes,
                actual.work.source_roots
            ),
            (2, 36, 35, 35)
        );
        assert_eq!(actual.work.source_cycle_comparisons, 2 * (17 * 18 / 2));
        assert_eq!(actual.work.route_cycle_comparisons, 0);
        assert_eq!(actual.work.key_bytes_copied, 17_002);
        assert_eq!(actual.work.hop_records_copied, 68);
        assert_eq!(actual.work.source_cache_lookups, 35);
        assert_eq!(actual.work.physical_cache_lookups, 35);
        for (row, first_key) in actual.rows.iter().zip([&left, &right]) {
            let mut expected = alloc::vec![(
                owner,
                first_key.clone(),
                root,
                if is_missing {
                    missing_route
                } else {
                    present_route
                }
            )];
            expected.extend(expected_chain.iter().rev().map(
                |(source, key, target, present, missing)| {
                    (
                        *source,
                        key.clone(),
                        *target,
                        if is_missing { *missing } else { *present },
                    )
                },
            ));
            let actual: Vec<_> = row
                .hops
                .iter()
                .map(|hop| (hop.source_root, hop.key.clone(), hop.target, hop.route))
                .collect();
            assert_eq!(actual, expected);
            assert_eq!(row.hops.len(), 17);
            for hop in &row.hops {
                assert_eq!(hop.entry, &graft(hop.target));
            }
            assert_eq!(
                row.entry,
                &file(
                    ONE,
                    if is_missing { None } else { Some(b"\x01") },
                    "uid",
                    false
                )
            );
            assert!(row.hops.iter().map(|hop| hop.key.len()).sum::<usize>() > 4096);
            assert_eq!(
                (
                    row.source_root,
                    row.key.as_slice(),
                    row.content,
                    row.size,
                    row.value
                ),
                (
                    bottom_root,
                    if is_missing {
                        b"b".as_slice()
                    } else {
                        b"a".as_slice()
                    },
                    ContentRef::Inline(ONE),
                    1,
                    if is_missing {
                        None
                    } else {
                        Some(b"\x01".as_slice())
                    }
                )
            );
        }
    }
}
