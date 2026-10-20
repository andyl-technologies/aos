//! Proves bounded connected-cut tracking and multilevel immutable reuse.

use super::*;

static FILL: [u8; 65536] = [0x77; 65536];

// A six-byte local key contributes nine bytes to a first leaf-item encoding:
// array header, byte-string header/key, and zero shared-prefix integer.
fn maximum_entry() -> Entry<'static> {
    for size in 65000..65536 {
        let mut entry = file(O, Some(&[1]), false);
        entry.xattrs = vec![crate::tree_format::ExtendedAttribute {
            name: b"user.fill",
            value: &FILL[..size],
        }];
        entry.xattrs_present = true;
        if crate::tree_format::encode_entry(&entry, MIN).unwrap().len() + 9
            == crate::tree_format::MAX_NODE_ITEMS_BYTES
        {
            return entry;
        }
    }
    panic!("exact-cap ordinary entry must exist");
}

/// Proves one connected region survives increasing interleaved leaf cuts.
///
/// # Panics
/// Panics when canonical construction, independently observed cuts or bounds fail.
pub(super) fn connected_cut_growth() {
    let entry = maximum_entry();
    for population in [4, 8, 16, 32] {
        let build = |parity| {
            let mut entries: Vec<_> = (0..population)
                .map(|n| {
                    item(
                        alloc::format!("f{:05}", n * 2 + parity).as_bytes(),
                        entry.clone(),
                    )
                })
                .collect();
            entries.push(item(b"z00000", entry.clone()));
            tree(entries)
        };
        let old = build(0);
        let new = build(1);
        for source in [&old, &new] {
            let leaves: Vec<_> = source.nodes().filter(|node| node.level() == 0).collect();
            assert_eq!(leaves.len(), population + 1);
            for leaf in leaves {
                assert_eq!(leaf.first_key(), leaf.last_key());
            }
        }
        let result_old_graph = single(&old);
        let result_new_graph = single(&new);
        let result = compare(
            old.root_identity(),
            &result_old_graph,
            new.root_identity(),
            &result_new_graph,
        );
        assert_eq!(result.delta_input(), population * 2);
        assert_eq!(result.delta_data(), population * 2);
        let regions: Vec<_> = result
            .boundaries
            .iter()
            .filter(|region| region.old.level == 0)
            .collect();
        assert_eq!(
            regions.len(),
            1,
            "successive cuts retain their first connected owner"
        );
        let region = regions[0];
        assert_eq!(region.old.last.as_deref(), Some(b"f00000".as_slice()));
        assert_eq!(region.new.last.as_deref(), Some(b"f00001".as_slice()));
        assert!(
            matches!(&region.resynchronization, Resynchronization::Equal(cut) if cut.last.as_deref() == Some(b"z00000".as_slice()))
        );
        assert!(result.work.boundary_checks <= population * 8 + 32);
        assert!(result.work.node_reads <= population * 16 + 32);
        assert!(result.work.item_reads <= population * 16 + 32);
        conserve(&result);
    }
}

/// Proves changed root bindings reuse every identical multilevel child.
///
/// # Panics
/// Panics if independently checked geometry or immutable reuse is lost.
pub(super) fn multilevel_property_reuse() {
    let entry = maximum_entry();
    let old = tree(
        (0..1200)
            .map(|n| item(alloc::format!("f{n:05}").as_bytes(), entry.clone()))
            .collect(),
    );
    assert!(old.root().level() >= 2);
    let new = old
        .with_properties(Some(vec![Property {
            name: "store",
            value: b"\x61s",
        }]))
        .unwrap()
        .tree;
    let result_old_graph = single(&old);
    let result_new_graph = single(&new);
    let result = compare(
        old.root_identity(),
        &result_old_graph,
        new.root_identity(),
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 1);
    assert_eq!(result.delta_data(), 0);
    assert!(result.inputs.is_empty());
    assert!(result.data.is_empty());
    assert!(result.boundaries.is_empty());
    assert_eq!(
        result.work.item_reads, 2,
        "only the two measured root-first bounds reach a leaf"
    );
    assert!(result.work.skipped_subtrees >= 2);
    assert_eq!(
        result.properties,
        vec![PropertyChange {
            old_root: Some(old.root_identity()),
            new_root: Some(new.root_identity()),
            old_hops: Some(vec![]),
            new_hops: Some(vec![]),
            old: None,
            new: Some(Property {
                name: "store",
                value: b"\x61s"
            }),
        }]
    );
    assert_eq!(
        result.envelopes,
        vec![RootEnvelopeChange {
            old_root: old.root_identity(),
            new_root: new.root_identity(),
            old_hops: vec![],
            new_hops: vec![],
            old_present: false,
            new_present: true,
        }]
    );
    conserve(&result);
}

/// Refuses fresh invalid associations before any immutable-equality shortcut.
///
/// # Panics
/// Panics if unsupported source associations or placement become admissible.
pub(super) fn fresh_refusals() {
    let valid = tree(vec![item(b"f", file(O, Some(&[1]), false))]);
    let sources = single(&valid);
    let uid = IndexEvaluationRecipe::new(valid.root_identity(), "uid").unwrap();
    let gid = IndexEvaluationRecipe::new(valid.root_identity(), "gid").unwrap();
    let before = PreparedSource::new(&uid, &sources, MIN, context()).unwrap();
    let after = PreparedSource::new(&gid, &sources, MIN, context()).unwrap();
    assert!(matches!(discover(&before, &after), Err(Error::Source)));

    let gaps = valid
        .with_properties(Some(vec![Property {
            name: "index-gaps",
            value: b"\xa0",
        }]))
        .unwrap()
        .tree;
    let recipe = IndexEvaluationRecipe::new(gaps.root_identity(), "uid").unwrap();
    assert!(matches!(
        PreparedSource::new(&recipe, &single(&gaps), MIN, context()),
        Err(Error::Source)
    ));
    let mut graft_entry = graft(valid.root_identity());
    if let EntryKind::Tree { props, .. } = &mut graft_entry.kind {
        *props = Some(vec![Property {
            name: "index-roots",
            value: b"\xa2\x65value\xa0\x67inherit\xf4",
        }]);
    }
    let misplaced = tree(vec![item(b"g", graft_entry)]);
    let recipe = IndexEvaluationRecipe::new(misplaced.root_identity(), "uid").unwrap();
    assert!(matches!(
        PreparedSource::new(&recipe, &graph(&[misplaced, valid.clone()]), MIN, context()),
        Err(Error::Source)
    ));

    let unrelated = Tree::build(
        vec![item(b"w", bare(EntryKind::Whiteout))],
        None,
        MIN,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let sources = graph(&[valid.clone(), unrelated]);
    let source = PreparedSource::new(&uid, &sources, MIN, context()).unwrap();
    assert_eq!(source.preparation_work().roots, 1);
    assert_eq!(discover(&source, &source).unwrap().delta_input(), 0);

    let mut malformed = file(O, None, false);
    malformed.attrs = vec![Attribute {
        name: "hash.sha256",
        value: b"\x00",
    }];
    malformed.attrs_present = true;
    let source = tree(vec![item(b"f", malformed)]);
    let recipe = IndexEvaluationRecipe::new(source.root_identity(), "hash.sha256").unwrap();
    assert!(PreparedSource::new(&recipe, &single(&source), MIN, context()).is_err());
}

/// Preserves nested repeated populations and override-only file-state equality.
///
/// # Panics
/// Panics if complete independent transitions or population initialization differ.
pub(super) fn nested_and_override_changes() {
    let old_leaf = tree(vec![item(b"f", file(O, Some(&[1]), false))]);
    let new_leaf = tree(vec![
        item(b"f", file(OTHER, None, true)),
        item(b"m", file(O, None, false)),
    ]);
    let old_middle = tree(vec![
        item(b"a", graft(old_leaf.root_identity())),
        item(b"b", graft(old_leaf.root_identity())),
    ]);
    let new_middle = tree(vec![
        item(b"a", graft(new_leaf.root_identity())),
        item(b"b", graft(new_leaf.root_identity())),
    ]);
    let old = tree(vec![
        item(b"g", graft(old_middle.root_identity())),
        item(b"h", graft(old_middle.root_identity())),
    ]);
    let new = tree(vec![
        item(b"g", graft(new_middle.root_identity())),
        item(b"h", graft(new_middle.root_identity())),
    ]);
    let before = graph(&[old.clone(), old_middle, old_leaf]);
    let after = graph(&[new.clone(), new_middle, new_leaf.clone()]);
    let result = compare(old.root_identity(), &before, new.root_identity(), &after);
    assert_eq!(result.delta_data(), 8);
    let old_recipe = IndexEvaluationRecipe::new(old.root_identity(), "uid").unwrap();
    let new_recipe = IndexEvaluationRecipe::new(new.root_identity(), "uid").unwrap();
    let old_source = PreparedSource::new(&old_recipe, &before, MIN, context()).unwrap();
    let new_source = PreparedSource::new(&new_recipe, &after, MIN, context()).unwrap();
    let initialized =
        discover_with_mode(&old_source, &new_source, PopulationMode::NewlyEnabled).unwrap();
    super::expected::complete(
        &initialized,
        old.root_identity(),
        &before,
        new.root_identity(),
        &after,
    );
    conserve(&initialized);

    let before = tree(vec![
        item(b"g", graft(new_leaf.root_identity())),
        item(b"h", graft(new_leaf.root_identity())),
    ]);
    let mut changed = graft(new_leaf.root_identity());
    if let EntryKind::Tree { props, .. } = &mut changed.kind {
        *props = Some(vec![Property {
            name: "store",
            value: b"\x61s",
        }]);
    }
    let after = tree(vec![item(b"g", changed.clone()), item(b"h", changed)]);
    let result_old_graph = graph(&[before.clone(), new_leaf.clone()]);
    let result_new_graph = graph(&[after.clone(), new_leaf]);
    let result = compare(
        before.root_identity(),
        &result_old_graph,
        after.root_identity(),
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 2);
    assert_eq!(result.delta_data(), 0);
    assert!(result.work.skipped_subtrees >= 2);
}

/// Proves recovered sparse divergences retain separate exclusive regions.
///
/// # Panics
/// Panics if independently placed equal separators fail to recover both cuts.
pub(super) fn sparse_cut_recovery() {
    let entry = maximum_entry();
    let old = tree(
        [
            b"f00000", b"f00002", b"m00000", b"n00000", b"n00002", b"z00000",
        ]
        .iter()
        .map(|key| item(*key, entry.clone()))
        .collect(),
    );
    let new = tree(
        [
            b"f00001", b"f00003", b"m00000", b"n00001", b"n00003", b"z00000",
        ]
        .iter()
        .map(|key| item(*key, entry.clone()))
        .collect(),
    );
    let result_old_graph = single(&old);
    let result_new_graph = single(&new);
    let result = compare(
        old.root_identity(),
        &result_old_graph,
        new.root_identity(),
        &result_new_graph,
    );
    let regions: Vec<_> = result
        .boundaries
        .iter()
        .filter(|region| region.old.level == 0)
        .collect();
    assert_eq!(regions.len(), 2);
    for (region, old_cut, new_cut, suffix) in [
        (regions[0], b"f00000", b"f00001", b"m00000"),
        (regions[1], b"n00000", b"n00001", b"z00000"),
    ] {
        assert_eq!(region.old.last.as_deref(), Some(old_cut.as_slice()));
        assert_eq!(region.new.last.as_deref(), Some(new_cut.as_slice()));
        assert!(
            matches!(&region.resynchronization, Resynchronization::Equal(cut) if cut.last.as_deref() == Some(suffix.as_slice()))
        );
    }
    assert_eq!(result.delta_data(), 8);
    conserve(&result);
}

/// Contains closing and finishing events for Equal, Aligned and Tail recovery.
///
/// # Panics
/// Panics if a literal recovery mode or independently accumulated interval fails.
pub(super) fn recovery_intervals() {
    let entry = maximum_entry();
    for recovery in 0..3 {
        let mut old_entries: Vec<_> = (0..4)
            .map(|n| item(alloc::format!("f{:05}", n * 2).as_bytes(), entry.clone()))
            .collect();
        let mut new_entries: Vec<_> = (0..4)
            .map(|n| {
                item(
                    alloc::format!("f{:05}", n * 2 + 1).as_bytes(),
                    entry.clone(),
                )
            })
            .collect();
        if recovery != 2 {
            old_entries.push(item(b"z00000", entry.clone()));
            let mut suffix = entry.clone();
            if recovery == 1
                && let EntryKind::File { mode, .. } = &mut suffix.kind
            {
                *mode = 0o600;
            }
            new_entries.push(item(b"z00000", suffix));
        }
        let old = tree(old_entries);
        let new = tree(new_entries);
        let result_old_graph = single(&old);
        let result_new_graph = single(&new);
        let result = compare(
            old.root_identity(),
            &result_old_graph,
            new.root_identity(),
            &result_new_graph,
        );
        let regions: Vec<_> = result
            .boundaries
            .iter()
            .filter(|region| region.old.level == 0)
            .collect();
        assert_eq!(regions.len(), 1);
        assert!(matches!(
            (&regions[0].resynchronization, recovery),
            (Resynchronization::Equal(_), 0)
                | (Resynchronization::Aligned { .. }, 1)
                | (Resynchronization::Tail, 2)
        ));
        // The common conservation helper independently accumulates prefixes
        // before/after every event and checks component-wise interval inclusion.
        conserve(&result);
    }
}
