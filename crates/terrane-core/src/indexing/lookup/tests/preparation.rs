//! Refuses independently malformed and divergent immutable inputs before query use.

use super::*;

/// Checks preparation reuse and refusal of malformed or divergent immutable inputs.
///
/// # Panics
/// Panics if fixture construction or an asserted lookup contract fails.
pub(super) fn check() {
    let (data, present, missing, gap) = model();
    let (old, original) = sources();
    let bytes = binding("uid", data.root);
    let (owner, trees) = bind(old, &original, &bytes);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let prepared = Prepared::prepare(recipe, &trees, MINIMUM, context(), &data).unwrap();
    let before = prepared.preparation();
    assert!(before.verification.work.source_entries > 4);
    assert!(before.verification.work.source_roots > 1);
    assert_eq!(before.loaded_nodes, data.nodes.len());
    assert_eq!(
        before.loaded_bytes,
        data.nodes.values().map(Vec::len).sum::<usize>()
    );
    assert_eq!(before.indexed_rows, 4);
    for _ in 0..16 {
        let result = prepared.candidates(b"\x01").unwrap();
        assert_eq!(result.work.candidates, 1);
        assert_eq!(result.work.route_nodes + result.work.source_nodes, 0);
        assert_eq!(result.rows[0].occurrences().unwrap().work.occurrences, 3);
    }
    assert_eq!(before, prepared.preparation());
    assert!(Prepared::prepare(recipe, &trees, MINIMUM + 1, context(), &data).is_err());
    assert!(
        Prepared::prepare(
            IndexEvaluationRecipe::new(old, "uid").unwrap(),
            &original,
            MINIMUM,
            context(),
            &data
        )
        .is_err()
    );
    assert!(
        Prepared::prepare(
            IndexEvaluationRecipe::new(owner, "gid").unwrap(),
            &trees,
            MINIMUM,
            context(),
            &data
        )
        .is_err()
    );
    assert!(SemanticContext::new(2, 2, 1).is_err());

    let mut inherited = bytes.clone();
    *inherited.last_mut().unwrap() = 0xf5;
    let empty_binding = [
        0xa2, 0x65, b'v', b'a', b'l', b'u', b'e', 0xa0, 0x67, b'i', b'n', b'h', b'e', b'r', b'i',
        b't', 0xf4,
    ];
    for invalid_binding in [inherited.as_slice(), empty_binding.as_slice(), b"\xa0"] {
        let (owner, graph) = bind(old, &original, invalid_binding);
        assert!(
            Prepared::prepare(
                IndexEvaluationRecipe::new(owner, "uid").unwrap(),
                &graph,
                MINIMUM,
                context(),
                &data
            )
            .is_err()
        );
    }
    let wrong_bytes = binding("uid", [0x77; 32]);
    let (wrong_owner, graph) = bind(old, &original, &wrong_bytes);
    assert!(matches!(
        Prepared::prepare(
            IndexEvaluationRecipe::new(wrong_owner, "uid").unwrap(),
            &graph,
            MINIMUM,
            context(),
            &data
        ),
        Err(Error::Relationship)
    ));
    let mut wrong_key_graph = trees.clone();
    let actual_owner = wrong_key_graph.remove(&owner).unwrap();
    wrong_key_graph.insert([0x88; 32], actual_owner);
    assert!(matches!(
        Prepared::prepare(
            IndexEvaluationRecipe::new([0x88; 32], "uid").unwrap(),
            &wrong_key_graph,
            MINIMUM,
            context(),
            &data
        ),
        Err(Error::Source)
    ));
    let mut overlay_graph = trees.clone();
    let mut whiteout = graft([0; 32]);
    whiteout.kind = EntryKind::Whiteout;
    let overlay_owner = overlay_graph[&owner]
        .with_usage(TreeUse::OverlayLayer)
        .unwrap()
        .insert(leaf(b"zz", whiteout))
        .unwrap()
        .tree;
    let overlay_root = overlay_owner.root_identity();
    overlay_graph.insert(overlay_root, overlay_owner);
    let layer_prepared = Prepared::prepare(
        IndexEvaluationRecipe::new(overlay_root, "uid").unwrap(),
        &overlay_graph,
        MINIMUM,
        context(),
        &data,
    )
    .unwrap();
    assert_eq!(layer_prepared.root(), prepared.root());
    assert_eq!(
        layer_prepared.preparation().verification.candidates,
        before.verification.candidates
    );
    assert_eq!(
        layer_prepared.preparation().verification.missing_objects,
        before.verification.missing_objects
    );
    let layer_candidates = layer_prepared.candidates(b"\x01").unwrap();
    assert_eq!(layer_candidates.rows.len(), 1);
    assert_eq!(
        layer_candidates.rows[0].occurrences().unwrap().rows.len(),
        3
    );

    let valid_rows = alloc::vec![
        forward(&value_key(b"\x01", ONE), ONE, present),
        forward(&value_key(b"\x02", TWO), TWO, {
            let root = crate::tree_format::decode_node_for(
                &data.nodes[&data.root],
                true,
                MINIMUM,
                TreeUse::Index,
            )
            .unwrap();
            let NodeItems::Leaf(rows) = root.items else {
                panic!("leaf")
            };
            validate_row(context(), Role::Primary, &rows[1].key, &rows[1].entry)
                .unwrap()
                .route()
                .unwrap()
        })
    ];
    let mut cases: Vec<(&str, IndexData)> = Vec::new();
    for (name, rows, gaps) in [
        (
            "omitted primary",
            alloc::vec![valid_rows[0].clone()],
            Some(gap),
        ),
        (
            "zero candidates with sources present",
            Vec::new(),
            Some(gap),
        ),
        ("absent gap", valid_rows.clone(), None),
        (
            "wrong object suffix",
            alloc::vec![
                forward(&value_key(b"\x01", ONE), TWO, present),
                valid_rows[1].clone()
            ],
            Some(gap),
        ),
        (
            "wrong value",
            alloc::vec![
                forward(&value_key(b"\x00", ONE), ONE, present),
                valid_rows[1].clone()
            ],
            Some(gap),
        ),
        (
            "wrong predicate route",
            alloc::vec![
                forward(&value_key(b"\x01", ONE), ONE, missing),
                valid_rows[1].clone()
            ],
            Some(gap),
        ),
        (
            "terminal primary",
            alloc::vec![
                terminal(&value_key(b"\x01", ONE), ONE),
                valid_rows[1].clone()
            ],
            Some(gap),
        ),
        ("wrong gap role", valid_rows.clone(), Some(present)),
        (
            "missing route closure",
            alloc::vec![
                forward(&value_key(b"\x01", ONE), ONE, [0x77; 32]),
                valid_rows[1].clone()
            ],
            Some(gap),
        ),
    ] {
        let mut witness = data.clone();
        witness.nodes.remove(&witness.root);
        witness.root = add(&mut witness.nodes, &rows, gaps);
        cases.push((name, witness));
    }
    let mut extra = data.clone();
    add(&mut extra.nodes, &[terminal(b"unreachable", TWO)], None);
    cases.push(("extra closure", extra));
    let mut unavailable = data.clone();
    unavailable.nodes.remove(&present);
    cases.push(("unavailable physical node", unavailable));
    let mut wrong_hash = data.clone();
    wrong_hash.nodes.get_mut(&present).unwrap().push(0);
    cases.push(("wrong hash/trailing bytes", wrong_hash));
    let mut raw = data.clone();
    let raw_bytes = alloc::vec![0xa2, 1, 0, 2, 0x81, 0x83, 0x41, 0, 0, 0xa2, 1, 7, 14, 0x80];
    raw.nodes.remove(&raw.root);
    raw.root = id(&raw_bytes);
    raw.nodes.insert(raw.root, raw_bytes);
    cases.push(("fresh raw zero-target malformed row", raw));
    for (name, witness) in cases {
        let binding = binding("uid", witness.root);
        let (owner, sources) = bind(old, &original, &binding);
        let result = Prepared::prepare(
            IndexEvaluationRecipe::new(owner, "uid").unwrap(),
            &sources,
            MINIMUM,
            context(),
            &witness,
        );
        assert!(result.is_err(), "{name}");
    }
    // Full local route models expose omissions even when object rows remain.
    let local = tree(alloc::vec![
        leaf(b"a", file(ONE, Some(b"\x01"), "uid", false)),
        leaf(b"b", file(ONE, Some(b"\x01"), "uid", false)),
        leaf(b"c", file(ONE, None, "uid", false)),
        leaf(b"d", file(ONE, None, "uid", false)),
    ]);
    let local_root = local.root_identity();
    let local_graph = BTreeMap::from([(local_root, local)]);
    for (name, present_rows, missing_rows) in [
        (
            "omitted present occurrence",
            alloc::vec![terminal(b"a", ONE)],
            alloc::vec![terminal(b"c", ONE), terminal(b"d", ONE)],
        ),
        (
            "omitted missing occurrence",
            alloc::vec![terminal(b"a", ONE), terminal(b"b", ONE)],
            alloc::vec![terminal(b"c", ONE)],
        ),
        (
            "extra route key",
            alloc::vec![
                terminal(b"a", ONE),
                terminal(b"b", ONE),
                terminal(b"z", ONE)
            ],
            alloc::vec![terminal(b"c", ONE), terminal(b"d", ONE)],
        ),
        (
            "wrong terminal object",
            alloc::vec![terminal(b"a", TWO), terminal(b"b", ONE)],
            alloc::vec![terminal(b"c", ONE), terminal(b"d", ONE)],
        ),
        (
            "empty forwarding route",
            Vec::new(),
            alloc::vec![terminal(b"c", ONE), terminal(b"d", ONE)],
        ),
    ] {
        let mut nodes = BTreeMap::new();
        let present = add(&mut nodes, &present_rows, None);
        let missing = add(&mut nodes, &missing_rows, None);
        let gap = add(&mut nodes, &[forward(&ONE, ONE, missing)], None);
        let root = add(
            &mut nodes,
            &[forward(&value_key(b"\x01", ONE), ONE, present)],
            Some(gap),
        );
        let witness = IndexData {
            root,
            nodes,
            work: evaluation::Work::default(),
        };
        let bytes = binding("uid", root);
        let (owner, graph) = bind(local_root, &local_graph, &bytes);
        assert!(
            Prepared::prepare(
                IndexEvaluationRecipe::new(owner, "uid").unwrap(),
                &graph,
                MINIMUM,
                context(),
                &witness
            )
            .is_err(),
            "{name}"
        );
    }

    let mut count = usize::MAX;
    assert_eq!(increment(&mut count, 1), Err(Error::Limit));
    assert_eq!(count, usize::MAX);
    let mut depth_graph = BTreeMap::new();
    let bottom = tree(alloc::vec![leaf(
        b"a",
        file(ONE, Some(b"\x01"), "uid", false)
    )]);
    let mut depth_root = bottom.root_identity();
    depth_graph.insert(depth_root, bottom);
    for _ in 0..65 {
        let source = tree(alloc::vec![leaf(b"g", graft(depth_root))]);
        depth_root = source.root_identity();
        depth_graph.insert(depth_root, source);
    }
    let (depth_owner, depth_graph) = bind(depth_root, &depth_graph, &bytes);
    assert!(matches!(
        Prepared::prepare(
            IndexEvaluationRecipe::new(depth_owner, "uid").unwrap(),
            &depth_graph,
            MINIMUM,
            context(),
            &data
        ),
        Err(Error::Limit)
    ));

    let mut missing_sources = trees.clone();
    let child = trees[&owner].get(b"g").unwrap();
    let EntryKind::Tree { root, .. } = child.kind else {
        panic!("graft")
    };
    missing_sources.remove(&root);
    assert!(matches!(
        Prepared::prepare(recipe, &missing_sources, MINIMUM, context(), &data),
        Err(Error::MissingSource)
    ));

    // Generic physical validity does not grant a registered hash value type.
    let unsupported = tree(alloc::vec![leaf(
        b"a",
        file(ONE, Some(b"\x61x"), "hash.sha256", false)
    )]);
    assert_eq!(unsupported.len(), 1);
    let unsupported_root = unsupported.root_identity();
    let original = BTreeMap::from([(unsupported_root, unsupported)]);
    let bytes = binding("hash.sha256", data.root);
    let (owner, sources) = bind(unsupported_root, &original, &bytes);
    assert!(matches!(
        Prepared::prepare(
            IndexEvaluationRecipe::new(owner, "hash.sha256").unwrap(),
            &sources,
            MINIMUM,
            context(),
            &data
        ),
        Err(Error::Attribute(_))
    ));

    // Empty primary plus a real gap is verified from complete source evidence.
    let source = tree(alloc::vec![leaf(b"a", file(ONE, None, "uid", true))]);
    let old = source.root_identity();
    let original = BTreeMap::from([(old, source)]);
    let mut nodes = BTreeMap::new();
    let route = add(&mut nodes, &[terminal(b"a", ONE)], None);
    let gap = add(&mut nodes, &[forward(&ONE, ONE, route)], None);
    let root = add(&mut nodes, &[], Some(gap));
    let data = IndexData {
        root,
        nodes,
        work: evaluation::Work::default(),
    };
    let bytes = binding("uid", root);
    let (owner, sources) = bind(old, &original, &bytes);
    let prepared = Prepared::prepare(
        IndexEvaluationRecipe::new(owner, "uid").unwrap(),
        &sources,
        MINIMUM,
        context(),
        &data,
    )
    .unwrap();
    assert_eq!(prepared.preparation().verification.candidates, 0);
    assert!(prepared.candidates(b"\x01").unwrap().rows.is_empty());
    let missing = prepared.all_missing().unwrap();
    assert_eq!(missing.rows.len(), 1);
    let occurrences = missing.rows[0].occurrences().unwrap();
    assert_eq!(occurrences.rows.len(), 1);
    assert_eq!(
        (occurrences.rows[0].content, occurrences.rows[0].value),
        (ContentRef::Manifest(ONE), None)
    );
    assert_eq!(occurrences.work.occurrences, 1);
    assert!(occurrences.work.route_nodes > 0);
}
