//! Owns exhaustive test-only reference models and physical accounting witnesses.

use super::*;

type FileModel = BTreeMap<Vec<Vec<u8>>, (ContentRef, Option<Vec<u8>>)>;

// This deliberately exhaustive model is outside measured production discovery.
// It compares local-key sequences, never source digests or physical partitions.
fn model(
    root: Digest,
    sources: &BTreeMap<Digest, Tree<'static>>,
    hops: &[Vec<u8>],
    entries: &mut BTreeMap<Vec<Vec<u8>>, Entry<'static>>,
    files: &mut FileModel,
) {
    for leaf in sources[&root].iter() {
        let mut path = hops.to_vec();
        path.push(leaf.key.clone());
        entries.insert(path.clone(), leaf.entry.clone());
        match &leaf.entry.kind {
            EntryKind::Tree { root, .. } => model(*root, sources, &path, entries, files),
            EntryKind::File { content, .. } => {
                let value = leaf
                    .entry
                    .attrs
                    .iter()
                    .find(|attribute| attribute.name == "uid")
                    .map(|attribute| attribute.value.to_vec());
                files.insert(path, (*content, value));
            }
            _ => {}
        }
    }
}

/// Compares expanded repeated populations with exhaustive independent source models.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn independent_population_oracle() {
    for population in [1, 2, 8, 32] {
        let before_child = tree(
            (0..population)
                .map(|n| {
                    item(
                        alloc::format!("f{n:03}").as_bytes(),
                        file(O, Some(&[1]), false),
                    )
                })
                .collect(),
        );
        let after_child = tree(
            (0..population)
                .map(|n| {
                    item(
                        alloc::format!("f{n:03}").as_bytes(),
                        file(
                            if n % 2 == 0 { OTHER } else { O },
                            if n % 3 == 0 { None } else { Some(&[2]) },
                            n % 4 == 0,
                        ),
                    )
                })
                .collect(),
        );
        let old = tree(vec![
            item(b"g", graft(before_child.root_identity())),
            item(b"h", graft(before_child.root_identity())),
        ]);
        let new = tree(vec![
            item(b"g", graft(after_child.root_identity())),
            item(b"h", graft(after_child.root_identity())),
        ]);
        let old_graph = graph(&[old.clone(), before_child]);
        let new_graph = graph(&[new.clone(), after_child]);
        let mut old_entries = BTreeMap::new();
        let mut old_files = BTreeMap::new();
        let mut new_entries = BTreeMap::new();
        let mut new_files = BTreeMap::new();
        model(
            old.root_identity(),
            &old_graph,
            &[],
            &mut old_entries,
            &mut old_files,
        );
        model(
            new.root_identity(),
            &new_graph,
            &[],
            &mut new_entries,
            &mut new_files,
        );
        let expected_input = old_entries
            .keys()
            .chain(new_entries.keys())
            .collect::<alloc::collections::BTreeSet<_>>()
            .iter()
            .filter(|path| old_entries.get(**path) != new_entries.get(**path))
            .count();
        let expected_data = old_files
            .keys()
            .chain(new_files.keys())
            .collect::<alloc::collections::BTreeSet<_>>()
            .iter()
            .filter(|path| old_files.get(**path) != new_files.get(**path))
            .count();
        let result = compare(
            old.root_identity(),
            &old_graph,
            new.root_identity(),
            &new_graph,
        );
        assert_eq!(result.delta_input(), expected_input);
        assert_eq!(result.delta_data(), expected_data);
        assert_eq!(result.delta_data(), population * 2);
        assert!(result.work.item_reads >= population * 4);
    }
}

/// Distinguishes metadata cut divergence from unchanged participating file states.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn physical_cut_witness() {
    let old = tree(
        (0..3000)
            .map(|n| {
                item(
                    alloc::format!("f{n:05}").as_bytes(),
                    file(O, Some(&[1]), false),
                )
            })
            .collect(),
    );
    // Large nonparticipating metadata changes stored item size and real hash cuts,
    // while preserving the participating value and actual file object.
    let mut changed_entry = file(O, Some(&[1]), false);
    changed_entry.xattrs = vec![crate::tree_format::ExtendedAttribute {
        name: b"user.large",
        value: &[0x77; 32000],
    }];
    changed_entry.xattrs_present = true;
    let new = old.insert(item(b"f01500", changed_entry)).unwrap().tree;
    let old_cuts: Vec<_> = old
        .nodes()
        .filter(|node| node.level() == 0)
        .map(|node| node.last_key().unwrap().to_vec())
        .collect();
    let new_cuts: Vec<_> = new
        .nodes()
        .filter(|node| node.level() == 0)
        .map(|node| node.last_key().unwrap().to_vec())
        .collect();
    assert_ne!(
        old_cuts, new_cuts,
        "actual independently observed physical leaf cuts must differ"
    );
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
    assert!(!result.boundaries.is_empty());
    for region in &result.boundaries {
        assert!(region.old.level != region.new.level || region.old.last != region.new.last);
        assert!(old.nodes().any(|node| node.identity() == region.old.node));
        assert!(new.nodes().any(|node| node.identity() == region.new.node));
        assert!(region.end.node_reads >= region.start.node_reads);
        assert!(region.end.frontier_checks >= region.start.frontier_checks);
        match &region.resynchronization {
            Resynchronization::Equal(cut) => {
                assert!(old.nodes().any(|node| node.identity() == cut.node));
                assert!(new.nodes().any(|node| node.identity() == cut.node));
                assert_eq!(region.old.level, cut.level);
                assert_eq!(region.new.level, cut.level);
            }
            Resynchronization::Aligned {
                old: old_cut,
                new: new_cut,
            } => {
                assert_eq!(old_cut.level, new_cut.level);
                assert_eq!(old_cut.last, new_cut.last);
                let old_node = old
                    .nodes()
                    .find(|node| node.identity() == old_cut.node)
                    .unwrap();
                let new_node = new
                    .nodes()
                    .find(|node| node.identity() == new_cut.node)
                    .unwrap();
                assert_eq!(old_node.first_key(), new_node.first_key());
            }
            Resynchronization::Tail => {}
        }
    }
    assert!(result.work.skipped_subtrees > 0);
    assert!(result.work.item_reads < 6000);
}

/// Refuses incompatible canonical source contexts and namespace placement.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn contextual_refusals() {
    let conflict = bare(EntryKind::Conflict {
        candidates: vec![file(O, None, false), file(OTHER, None, false)],
        base: None,
    });
    let conflicted = tree(vec![item(b"f", conflict)]);
    let recipe = IndexEvaluationRecipe::new(conflicted.root_identity(), "uid").unwrap();
    assert!(matches!(
        PreparedSource::new(&recipe, &graph(&[conflicted]), MIN, context()),
        Err(Error::Incomplete)
    ));

    contextual_layer_inputs();

    let child = tree(vec![item(b"f", file(O, None, false))]);
    let mut g = graft(child.root_identity());
    if let EntryKind::Tree { props, .. } = &mut g.kind {
        *props = Some(vec![Property {
            name: "index-gaps",
            value: b"\xa2\x65value\x78\x400000000000000000000000000000000000000000000000000000000000000000\x67inherit\xf4",
        }]);
    }
    let misplaced = tree(vec![item(b"g", g)]);
    let recipe = IndexEvaluationRecipe::new(misplaced.root_identity(), "uid").unwrap();
    assert!(matches!(
        PreparedSource::new(&recipe, &graph(&[misplaced, child]), MIN, context()),
        Err(Error::Source)
    ));

    let structural = Entry {
        attrs: vec![Attribute {
            name: "index.occurrences",
            value: b"\x58\x20abcdefghijklmnopqrstuvwxyzABCDEF",
        }],
        attrs_present: true,
        ..file(O, None, false)
    };
    let namespace = tree(vec![item(b"f", structural)]);
    let recipe = IndexEvaluationRecipe::new(namespace.root_identity(), "uid").unwrap();
    assert!(PreparedSource::new(&recipe, &graph(&[namespace]), MIN, context()).is_err());
}

// Layer context admits whiteouts without making them files or missing-value gaps.
// The exhaustive oracle still inventories them as namespace inputs.
fn contextual_layer_inputs() {
    let child = Tree::build(
        vec![
            item(b"hidden", bare(EntryKind::Whiteout)),
            item(b"missing", file(OTHER, None, false)),
            item(b"present", file(O, Some(&[2]), true)),
        ],
        None,
        MIN,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let owner = Tree::build(
        vec![
            item(b"g", graft(child.root_identity())),
            item(b"h", graft(child.root_identity())),
            item(b"hidden", bare(EntryKind::Whiteout)),
            item(b"missing", file(OTHER, None, false)),
            item(b"present", file(O, Some(&[1]), false)),
        ],
        None,
        MIN,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let sources = graph(&[owner.clone(), child.clone()]);
    let recipe = IndexEvaluationRecipe::new(owner.root_identity(), "uid").unwrap();
    let prepared = PreparedSource::new(&recipe, &sources, MIN, context()).unwrap();

    assert_eq!(prepared.preparation_work().roots, 3);
    assert_eq!(prepared.preparation_work().nodes, 3);
    assert_eq!(prepared.preparation_work().entries, 11);
    assert_eq!(prepared.preparation_work().cached_roots, 2);
    for root in [owner.root_identity(), child.root_identity()] {
        let mut work = SourceLookupWork::default();
        assert_eq!(
            prepared.lookup().tree(root, &mut work).unwrap().usage(),
            TreeUse::OverlayLayer
        );
    }

    let initialized =
        discover_with_mode(&prepared, &prepared, PopulationMode::NewlyEnabled).unwrap();
    conserve(&initialized);
    super::expected::complete(
        &initialized,
        owner.root_identity(),
        &sources,
        owner.root_identity(),
        &sources,
    );
    assert_eq!(initialized.delta_input(), 0);
    assert_eq!(initialized.delta_data(), 6);
    assert_eq!(
        initialized
            .data
            .iter()
            .filter(|change| change.new.as_ref().unwrap().value.is_none())
            .count(),
        3,
        "only the three regular-file occurrences without inline values are gaps"
    );
    // Eleven entries plus one root-bound read per visited single-leaf root.
    assert_eq!(initialized.initialization.work.item_reads, 14);
    assert_eq!(initialized.work.item_reads, 0);

    let changed = owner
        .edit_entries(&[
            (b"hidden".to_vec(), Some(file(OTHER, None, false))),
            (b"present".to_vec(), Some(bare(EntryKind::Whiteout))),
        ])
        .unwrap()
        .tree;
    let changed_sources = graph(&[changed.clone(), child]);
    let result = compare(
        owner.root_identity(),
        &sources,
        changed.root_identity(),
        &changed_sources,
    );
    assert_eq!(result.delta_input(), 2);
    assert_eq!(result.delta_data(), 2);
    assert_eq!(result.data[0].old, None);
    assert_eq!(
        result.data[0].new,
        Some(FileState {
            content: ContentRef::Inline(OTHER),
            value: None,
        })
    );
    assert_eq!(
        result.data[1].old,
        Some(FileState {
            content: ContentRef::Inline(O),
            value: Some(vec![1]),
        })
    );
    assert_eq!(result.data[1].new, None);

    // The same canonical bytes cannot acquire ordinary namespace semantics.
    let ordinary = Tree::build(
        owner.iter().cloned().collect(),
        None,
        MIN,
        TreeUse::Ordinary,
    );
    assert!(matches!(ordinary, Err(crate::tree_format::Error::Tree)));
    assert!(matches!(
        owner.with_usage(TreeUse::Ordinary),
        Err(crate::tree_format::Error::Tree)
    ));
    assert!(matches!(
        crate::tree_format::decode_node_for(owner.root().encoded(), true, MIN, TreeUse::Ordinary),
        Err(crate::tree_format::Error::Tree)
    ));

    for usage in [TreeUse::Surface, TreeUse::ConflictSurface] {
        let surface = Tree::build(
            vec![item(b"present", file(O, Some(&[1]), false))],
            None,
            MIN,
            usage,
        )
        .unwrap();
        let recipe = IndexEvaluationRecipe::new(surface.root_identity(), "uid").unwrap();
        assert!(matches!(
            PreparedSource::new(&recipe, &single(&surface), MIN, context()),
            Err(Error::Source)
        ));
    }
}

/// Conserves every physical event across local streams and region ownership.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn conserve(result: &Discovery<'_, '_>) {
    fn accumulate(work: &mut DiscoveryWork, event: &PhysicalEvent) {
        match event.kind {
            PhysicalEventKind::BoundaryCheck => work.boundary_checks += event.amount,
            PhysicalEventKind::PropertyRead => work.property_reads += event.amount,
            PhysicalEventKind::NodeRead => work.node_reads += event.amount,
            PhysicalEventKind::ItemRead => work.item_reads += event.amount,
            PhysicalEventKind::ChildRead => work.child_reads += event.amount,
            PhysicalEventKind::Comparison => work.comparisons += event.amount,
            PhysicalEventKind::FrontierCheck => work.frontier_checks += event.amount,
            PhysicalEventKind::SkippedSubtree => work.skipped_subtrees += event.amount,
        }
    }

    fn components(work: DiscoveryWork) -> [usize; 8] {
        [
            work.node_reads,
            work.item_reads,
            work.child_reads,
            work.comparisons,
            work.frontier_checks,
            work.skipped_subtrees,
            work.boundary_checks,
            work.property_reads,
        ]
    }

    fn sum(streams: &[StreamWork]) -> DiscoveryWork {
        let mut total = DiscoveryWork::default();
        for stream in streams {
            let mut independently_counted = DiscoveryWork::default();
            for event in &stream.events {
                accumulate(&mut independently_counted, event);
            }
            assert_eq!(stream.work, independently_counted);
            total.node_reads += independently_counted.node_reads;
            total.item_reads += independently_counted.item_reads;
            total.boundary_checks += independently_counted.boundary_checks;
            total.property_reads += independently_counted.property_reads;
            total.child_reads += independently_counted.child_reads;
            total.comparisons += independently_counted.comparisons;
            total.frontier_checks += independently_counted.frontier_checks;
            total.skipped_subtrees += independently_counted.skipped_subtrees;
        }
        total
    }
    assert_eq!(sum(&result.streams), result.work);
    assert_eq!(
        sum(&result.initialization.streams),
        result.initialization.work
    );
    for stream in &result.streams {
        let mut prefix = DiscoveryWork::default();
        for event in &stream.events {
            let before = components(prefix);
            accumulate(&mut prefix, event);
            let after = components(prefix);
            if let Some(index) = event.boundary {
                let region = &result.boundaries[index];
                for ((start, end), (before, after)) in components(region.start)
                    .into_iter()
                    .zip(components(region.end))
                    .zip(before.into_iter().zip(after))
                {
                    assert!(start <= before, "owned event precedes its region start");
                    assert!(after <= end, "owned event exceeds its region end");
                }
                assert!(event.level == region.old.level || event.level == region.new.level);
                assert_eq!(stream.old_hops.as_ref(), Some(&region.old_hops));
                assert_eq!(stream.new_hops.as_ref(), Some(&region.new_hops));
            }
        }
    }
}

/// Proves named bindings and initialization.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn named_bindings_and_initialization() {
    let old = tree(vec![
        item(b"f", file(O, Some(&[0x18, 0x18]), false)),
        item(b"m", file(O, None, false)),
    ]);
    let new = old
        .with_properties(Some(vec![
            Property {
                name: "store",
                value: b"\x61s",
            },
            Property {
                name: "retain",
                value: b"\x62gc",
            },
        ]))
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
    assert_eq!(result.delta_input(), 2);
    assert_eq!(result.delta_data(), 0);
    assert_eq!(
        result
            .properties
            .iter()
            .map(|change| change.new.unwrap().name)
            .collect::<Vec<_>>(),
        vec!["store", "retain"]
    );
    let empty_map = old.with_properties(Some(vec![])).unwrap().tree;
    let result_old_graph = single(&old);
    let result_new_root = empty_map.root_identity();
    let result_new_graph = graph(&[empty_map]);
    let result = compare(
        old.root_identity(),
        &result_old_graph,
        result_new_root,
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 0);
    assert_eq!(result.delta_data(), 0);
    assert_eq!(result.envelopes.len(), 1);
    assert!(!result.envelopes[0].old_present);
    assert!(result.envelopes[0].new_present);

    let old_graph = single(&old);
    let new_graph = single(&new);
    let old_recipe = IndexEvaluationRecipe::new(old.root_identity(), "uid").unwrap();
    let new_recipe = IndexEvaluationRecipe::new(new.root_identity(), "uid").unwrap();
    let old_source = PreparedSource::new(&old_recipe, &old_graph, MIN, context()).unwrap();
    let new_source = PreparedSource::new(&new_recipe, &new_graph, MIN, context()).unwrap();
    assert_eq!(old_source.preparation_work().entries, 2);
    let initialized =
        discover_with_mode(&old_source, &new_source, PopulationMode::NewlyEnabled).unwrap();
    conserve(&initialized);
    super::expected::complete(
        &initialized,
        old.root_identity(),
        &old_graph,
        new.root_identity(),
        &new_graph,
    );
    assert_eq!(initialized.delta_input(), 2);
    assert_eq!(initialized.delta_data(), 2);
    assert!(initialized.data.iter().all(|change| change.old.is_none()));
    assert_eq!(
        initialized.data[0].new.as_ref().unwrap().value,
        Some(vec![0x18, 0x18])
    );
    assert_eq!(initialized.data[1].new.as_ref().unwrap().value, None);
    assert_eq!(initialized.initialization.work.item_reads, 3);
    assert!(
        initialized
            .initialization
            .streams
            .iter()
            .flat_map(|stream| &stream.events)
            .all(|event| event.boundary.is_none())
    );
}

/// Proves literal transitions and stable cuts.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn literal_transitions_and_stable_cuts() {
    let before = tree(vec![item(b"f", file(O, Some(&[0x18, 0x18]), false))]);
    let after = tree(vec![item(b"f", file(O, Some(&[0x18, 0x19]), false))]);
    let result_old_graph = single(&before);
    let result_new_graph = single(&after);
    let result = compare(
        before.root_identity(),
        &result_old_graph,
        after.root_identity(),
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 1);
    assert_eq!(result.delta_data(), 1);
    assert_eq!(
        result.data[0].old.as_ref().unwrap().value,
        Some(vec![0x18, 0x18])
    );
    assert_eq!(
        result.data[0].new.as_ref().unwrap().value,
        Some(vec![0x18, 0x19])
    );
    assert_eq!(
        result.work,
        DiscoveryWork {
            node_reads: 6,
            item_reads: 8,
            boundary_checks: 2,
            property_reads: 0,
            comparisons: 4,
            frontier_checks: 3,
            ..DiscoveryWork::default()
        }
    );
    assert!(result.boundaries.is_empty());
    assert!(
        result
            .streams
            .iter()
            .flat_map(|stream| &stream.events)
            .all(|event| event.boundary.is_none())
    );

    let mut mode_only = file(O, Some(&[0x18, 0x18]), false);
    if let EntryKind::File { mode, .. } = &mut mode_only.kind {
        *mode = 0o600;
    }
    let mode_tree = tree(vec![item(b"f", mode_only)]);
    let result_old_graph = single(&before);
    let result_new_root = mode_tree.root_identity();
    let result_new_graph = graph(&[mode_tree]);
    let result = compare(
        before.root_identity(),
        &result_old_graph,
        result_new_root,
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 1);
    assert_eq!(result.delta_data(), 0);

    let large = tree(
        (0..2000)
            .map(|n| {
                item(
                    alloc::format!("f{n:05}").as_bytes(),
                    file(O, Some(&[0x18, 0x18]), false),
                )
            })
            .collect(),
    );
    // Search only outside production discovery for a real stable-cut witness.
    let old_endpoints: Vec<_> = large
        .nodes()
        .map(|node| (node.level(), node.last_key().unwrap().to_vec()))
        .collect();
    let stable = (0..2000)
        .find_map(|n| {
            let changed = large
                .insert(item(
                    alloc::format!("f{n:05}").as_bytes(),
                    file(O, Some(&[0x18, 0x19]), false),
                ))
                .unwrap()
                .tree;
            let endpoints: Vec<_> = changed
                .nodes()
                .map(|node| (node.level(), node.last_key().unwrap().to_vec()))
                .collect();
            (old_endpoints == endpoints).then_some(changed)
        })
        .unwrap();
    let result_old_graph = single(&large);
    let result_new_root = stable.root_identity();
    let result_new_graph = graph(&[stable]);
    let result = compare(
        large.root_identity(),
        &result_old_graph,
        result_new_root,
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 1);
    assert_eq!(result.delta_data(), 1);
    assert!(result.boundaries.is_empty());
    assert!(result.work.skipped_subtrees > 0);
    assert!(
        result
            .streams
            .iter()
            .flat_map(|stream| &stream.events)
            .all(|event| event.boundary.is_none())
    );
}

/// Proves membership and growth.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn membership_and_growth() {
    let child = tree(vec![
        item(b"d", bare(EntryKind::Directory { mode: 0o755 })),
        item(b"d/a", file(O, Some(&[0x18, 0x18]), false)),
        item(b"d/b", file(O, None, false)),
    ]);
    let empty = tree(vec![]);
    let added = tree(vec![item(b"g", graft(child.root_identity()))]);
    let result_old_graph = single(&empty);
    let result_new_graph = graph(&[added.clone(), child.clone()]);
    let result = compare(
        empty.root_identity(),
        &result_old_graph,
        added.root_identity(),
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 4);
    assert_eq!(result.delta_data(), 2);
    let renamed = tree(vec![item(b"h", graft(child.root_identity()))]);
    let result_old_graph = graph(&[added.clone(), child.clone()]);
    let result_new_graph = graph(&[renamed.clone(), child.clone()]);
    let result = compare(
        added.root_identity(),
        &result_old_graph,
        renamed.root_identity(),
        &result_new_graph,
    );
    assert_eq!(result.delta_input(), 8);
    assert_eq!(result.delta_data(), 4);
    assert_eq!(
        result
            .data
            .iter()
            .filter(|change| change.old.is_some())
            .count(),
        2
    );
    assert_eq!(
        result
            .data
            .iter()
            .filter(|change| change.new.is_some())
            .count(),
        2
    );
    let direct = tree(vec![item(b"g", file(OTHER, Some(&[0x18, 0x19]), true))]);
    for (before, after) in [(&added, &direct), (&direct, &added)] {
        let result_old_graph = graph(&[before.clone(), child.clone()]);
        let result_new_graph = graph(&[after.clone(), child.clone()]);
        let result = compare(
            before.root_identity(),
            &result_old_graph,
            after.root_identity(),
            &result_new_graph,
        );
        assert_eq!(result.delta_input(), 4);
        assert_eq!(result.delta_data(), 3);
    }
    let populated = tree(
        (0..2000)
            .map(|n| item(alloc::format!("f{n:05}").as_bytes(), file(O, None, false)))
            .collect(),
    );
    let tiny = tree(vec![item(b"f00000", file(O, None, false))]);
    assert!(populated.root().level() > tiny.root().level());
    for (before, after) in [(&tiny, &populated), (&populated, &tiny)] {
        let result_old_graph = single(before);
        let result_new_graph = single(after);
        let result = compare(
            before.root_identity(),
            &result_old_graph,
            after.root_identity(),
            &result_new_graph,
        );
        assert_eq!(result.delta_input(), 1999);
        assert_eq!(result.delta_data(), 1999);
        assert!(
            result
                .boundaries
                .iter()
                .any(|region| region.old.level != region.new.level)
        );
    }
}

/// Proves fixed delta growth.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn fixed_delta_growth() {
    let mut prior_reads = 0;
    for size in [2000, 4000, 8000] {
        let old = tree(
            (0..size)
                .map(|n| {
                    item(
                        alloc::format!("f{n:05}").as_bytes(),
                        file(O, Some(&[1]), false),
                    )
                })
                .collect(),
        );
        let new = old
            .edit_entries(&[
                (b"f00050".to_vec(), Some(file(OTHER, Some(&[2]), false))),
                (
                    alloc::format!("f{:05}", size - 50).into_bytes(),
                    Some(file(OTHER, None, false)),
                ),
            ])
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
        assert_eq!(result.delta_input(), 2);
        assert_eq!(result.delta_data(), 2);
        // Independently inspect only changed physical leaf populations. Each
        // exposed changed item is read once by expansion and once by key
        // comparison; first-bound walks add at most one item per side/level
        // of each changed physical Node. Equal interiors expose no entries.
        let mut affected_items = 0;
        let mut bound_reads = 0;
        for (source, other) in [(&old, &new), (&new, &old)] {
            for node in source.nodes() {
                if other
                    .nodes()
                    .any(|candidate| candidate.identity() == node.identity())
                {
                    continue;
                }
                bound_reads += usize::from(node.level()) + 2;
                if let crate::tree_format::NodeItems::Leaf(items) = node.items() {
                    affected_items += items.len();
                }
            }
        }
        assert!(affected_items < size / 2);
        assert!(result.work.item_reads <= affected_items * 2 + bound_reads);
        assert!(result.work.item_reads < size);
        assert!(result.work.skipped_subtrees > 0);
        assert!(result.work.item_reads < 2000);
        prior_reads = prior_reads.max(result.work.item_reads);
    }
    assert!(prior_reads > 0);
}

/// Checks independently supplied canonical structural owner bindings.
///
/// # Panics
/// Panics if canonical fixtures or independently asserted proof conditions fail.
pub(super) fn owner_binding_refusals() {
    for binding in [
        b"\xa2\x65value\xa0\x67inherit\xf5".as_slice(),
        b"\xa0".as_slice(),
    ] {
        let source = tree(vec![item(b"f", file(O, Some(&[1]), false))])
            .with_properties(Some(vec![Property {
                name: "index-roots",
                value: binding,
            }]))
            .unwrap()
            .tree;
        let recipe = IndexEvaluationRecipe::new(source.root_identity(), "uid").unwrap();
        assert!(matches!(
            PreparedSource::new(&recipe, &single(&source), MIN, context()),
            Err(Error::Carrier(_))
        ));
    }
    let valid = tree(vec![item(b"f", file(O, None, false))])
        .with_properties(Some(vec![Property {
            name: "index-roots",
            value: b"\xa2\x65value\xa0\x67inherit\xf4",
        }]))
        .unwrap()
        .tree;
    let sources = single(&valid);
    let recipe = IndexEvaluationRecipe::new(valid.root_identity(), "uid").unwrap();
    let prepared = PreparedSource::new(&recipe, &sources, MIN, context()).unwrap();
    assert_eq!(prepared.preparation_work().bindings, 1);
    super::super::prepared::assert_active_cycle(&prepared);
    let result = discover(&prepared, &prepared).unwrap();
    assert_eq!(result.sources().old_root(), valid.root_identity());
    assert_eq!(result.sources().new_root(), valid.root_identity());
    assert_eq!(result.sources().attribute(), "uid");
    assert_eq!(result.sources().profile(), "terrane-index/v1");
    assert_eq!(result.sources().context(), context());
    assert_eq!(result.sources().mode(), PopulationMode::Existing);
}
