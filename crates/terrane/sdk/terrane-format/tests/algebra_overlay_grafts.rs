//! Checks overlay materialization against independently constructed namespaces.
//!
//! Fixtures retain root boundaries and exercise both graft and inline sources.

#![allow(clippy::unwrap_used, reason = "fixture construction and assertions")]

use terrane_format::algebra::{Error, Overlay, OverlayPolicy, Recipe, Roots, lookup};
use terrane_format::identity::Digest;
use terrane_format::properties::{Defaults, EffectiveProperties, PropertyName, RootLayer};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{ContentRef, Entry, EntryKind, LeafItem, Property, TreeUse};

const DOMAIN: Property<'static> = Property {
    name: "domain",
    value: b"\x6fprivate:fixture",
};

struct Forest(Vec<Tree<'static>>);

impl Roots<'static> for Forest {
    fn resolve(&self, identity: &Digest) -> Option<&Tree<'static>> {
        self.0.iter().find(|tree| tree.root_identity() == *identity)
    }
}

fn entry(kind: EntryKind<'static>) -> Entry<'static> {
    Entry {
        kind,
        attrs: vec![],
        attrs_present: false,
        xattrs: vec![],
        xattrs_present: false,
        provenance: None,
    }
}

fn value(target: &'static [u8]) -> Entry<'static> {
    entry(EntryKind::Symlink { target })
}

fn linked(id: &'static [u8]) -> Entry<'static> {
    entry(EntryKind::File {
        mode: 0o644,
        size: 1,
        content: ContentRef::Inline([1; 32]),
        link_id: Some(id),
    })
}

fn graft(target: &Tree<'static>) -> Entry<'static> {
    entry(EntryKind::Tree {
        root: target.root_identity(),
        props: None,
    })
}

fn tree(items: &[(&[u8], Entry<'static>)], usage: TreeUse) -> Tree<'static> {
    tree_with_properties(items, usage, vec![DOMAIN])
}

fn tree_with_properties(
    items: &[(&[u8], Entry<'static>)],
    usage: TreeUse,
    properties: Vec<Property<'static>>,
) -> Tree<'static> {
    Tree::build(
        items
            .iter()
            .map(|(key, entry)| LeafItem {
                key: key.to_vec(),
                entry: entry.clone(),
            })
            .collect(),
        Some(properties),
        4096,
        usage,
    )
    .unwrap()
}

fn compatible(_: &Digest, _: &[u8]) -> Result<OverlayPolicy, Error> {
    OverlayPolicy::from_effective(&effective(&[DOMAIN]))
}

fn result_policy(_: &Digest, layers: &[RootLayer<'_>]) -> Result<OverlayPolicy, Error> {
    let effective = terrane_format::properties::resolve(
        layers,
        Defaults {
            store: "authority",
            private_domain: "private:fixture",
            home: "region",
        },
    )
    .map_err(|_| Error::Boundary)?;
    OverlayPolicy::from_effective(&effective)
}

fn effective<'a>(properties: &'a [Property<'a>]) -> EffectiveProperties<'a> {
    terrane_format::properties::resolve(
        &[RootLayer {
            properties,
            overrides: &[],
        }],
        Defaults {
            store: "authority",
            private_domain: "private:fixture",
            home: "region",
        },
    )
    .unwrap()
}

#[test]
fn overlay_overlapping_grafts_preserve_lower_children_and_recipe_inputs() {
    let upper_target = tree(&[(b"x", value(b"upper"))], TreeUse::Ordinary);
    let lower_target = tree(
        &[(b"x", value(b"lower")), (b"y", value(b"retained"))],
        TreeUse::Ordinary,
    );
    let upper = tree(&[(b"g", graft(&upper_target))], TreeUse::OverlayLayer);
    let lower = tree(&[(b"g", graft(&lower_target))], TreeUse::OverlayLayer);
    let forest = Forest(vec![upper_target, lower_target]);
    let layers = [&upper, &lower];
    let overlay = Overlay::new(&layers);
    let prepared = overlay
        .prepare_with_roots(&forest, None, compatible, result_policy)
        .unwrap();
    let materialized = prepared.materialize().unwrap();

    for path in [b"g/x".as_slice(), b"g/y", b"g/missing"] {
        assert_eq!(
            lookup(&materialized.tree, path, &materialized).unwrap(),
            overlay.lookup(path, &forest).unwrap()
        );
    }
    let expected_child = tree(
        &[(b"x", value(b"upper")), (b"y", value(b"retained"))],
        TreeUse::Ordinary,
    );
    let expected = tree(&[(b"g", graft(&expected_child))], TreeUse::Ordinary);
    assert_eq!(materialized.tree.root_identity(), expected.root_identity());
    assert_eq!(
        materialized.recipe,
        Recipe::Overlay(&[upper.root_identity(), lower.root_identity()]).encode()
    );
    assert_eq!(overlay.materialize().unwrap_err(), Error::MissingRoot);
}

#[test]
fn overlay_graft_whiteout_suppresses_lower_child_and_emits_only_ordinary_roots() {
    let upper_target = tree(&[(b"x", entry(EntryKind::Whiteout))], TreeUse::OverlayLayer);
    let lower_target = tree(
        &[(b"x", value(b"hidden")), (b"y", value(b"visible"))],
        TreeUse::Ordinary,
    );
    let upper = tree(&[(b"g", graft(&upper_target))], TreeUse::OverlayLayer);
    let lower = tree(&[(b"g", graft(&lower_target))], TreeUse::OverlayLayer);
    let forest = Forest(vec![upper_target, lower_target]);
    let layers = [&upper, &lower];
    let overlay = Overlay::new(&layers);
    let prepared = overlay
        .prepare_with_roots(&forest, None, compatible, result_policy)
        .unwrap();
    let materialized = prepared.materialize().unwrap();

    assert_eq!(overlay.lookup(b"g/x", &forest).unwrap(), None);
    assert_eq!(
        lookup(&materialized.tree, b"g/x", &materialized).unwrap(),
        None
    );
    assert_eq!(
        lookup(&materialized.tree, b"g/y", &materialized).unwrap(),
        Some(&value(b"visible"))
    );
    for root in std::iter::once(&materialized.tree).chain(&materialized.grafts) {
        assert_eq!(root.usage(), TreeUse::Ordinary);
        assert!(
            root.iter()
                .all(|item| !matches!(item.entry.kind, EntryKind::Whiteout))
        );
    }
}

#[test]
fn overlay_repeated_nested_grafts_resolve_each_occurrence() {
    use std::cell::RefCell;

    const STORE: Property<'static> = Property {
        name: "store",
        value: b"\x6blower-store",
    };
    const BASELINE: Property<'static> = Property {
        name: "baseline",
        value: b"\x6abase-lower",
    };
    let upper_overrides = [
        vec![
            Property {
                name: "store",
                value: b"\x67store-a",
            },
            Property {
                name: "baseline",
                value: b"\x66base-a",
            },
        ],
        vec![
            Property {
                name: "store",
                value: b"\x67store-b",
            },
            Property {
                name: "baseline",
                value: b"\x66base-b",
            },
        ],
    ];
    let lower_overrides = [
        vec![
            Property {
                name: "store",
                value: b"\xa2\x65value\x67store-a\x67inherit\xf4",
            },
            Property {
                name: "baseline",
                value: b"\xa2\x65value\x66base-a\x67inherit\xf4",
            },
        ],
        vec![
            Property {
                name: "store",
                value: b"\xa2\x65value\x67store-b\x67inherit\xf4",
            },
            Property {
                name: "baseline",
                value: b"\xa2\x65value\x66base-b\x67inherit\xf4",
            },
        ],
    ];
    let with_overrides = |target: &Tree<'static>, properties: &[Property<'static>]| {
        let mut descriptor = graft(target);
        if let EntryKind::Tree { props, .. } = &mut descriptor.kind {
            *props = Some(properties.to_vec());
        }
        descriptor
    };

    let middle = tree(&[(b"shared", value(b"upper"))], TreeUse::Ordinary);
    let leaf = tree(
        &[(b"x", value(b"first")), (b"y", value(b"second"))],
        TreeUse::Ordinary,
    );
    let lower_middle = tree(&[(b"nested", graft(&leaf))], TreeUse::Ordinary);
    let upper = tree(
        &[
            (b"a", with_overrides(&middle, &upper_overrides[0])),
            (b"b", with_overrides(&middle, &upper_overrides[1])),
        ],
        TreeUse::OverlayLayer,
    );
    let lower = tree_with_properties(
        &[
            (b"a", with_overrides(&lower_middle, &lower_overrides[0])),
            (b"b", with_overrides(&lower_middle, &lower_overrides[1])),
        ],
        TreeUse::OverlayLayer,
        vec![DOMAIN, STORE, BASELINE],
    );
    let forest = Forest(vec![leaf.clone(), middle.clone(), lower_middle.clone()]);
    let layers = [&upper, &lower];
    let overlay = Overlay::new(&layers);

    // The original local overrides agree at each middle root but stop inheriting
    // below it. The emitted upper overrides inherit, requiring deeper projection.
    let source_calls = RefCell::new(Vec::new());
    let emitted_calls = RefCell::new(Vec::new());
    let copied = |properties: &[Property<'_>]| {
        properties
            .iter()
            .map(|property| (property.name.to_owned(), property.value.to_vec()))
            .collect::<Vec<_>>()
    };
    let prepared = overlay
        .prepare_with_roots(
            &forest,
            None,
            |view, path| {
                source_calls.borrow_mut().push((*view, path.to_vec()));
                let mut original = vec![RootLayer {
                    properties: if *view == upper.root_identity() {
                        upper.props().unwrap()
                    } else {
                        assert_eq!(*view, lower.root_identity());
                        lower.props().unwrap()
                    },
                    overrides: &[],
                }];
                if !path.is_empty() {
                    let branch = match path {
                        b"a" | b"a/nested" => 0,
                        b"b" | b"b/nested" => 1,
                        _ => panic!("unexpected original occurrence"),
                    };
                    original.push(RootLayer {
                        properties: if *view == upper.root_identity() {
                            middle.props().unwrap()
                        } else {
                            lower_middle.props().unwrap()
                        },
                        overrides: if *view == upper.root_identity() {
                            &upper_overrides[branch]
                        } else {
                            &lower_overrides[branch]
                        },
                    });
                    if path.ends_with(b"/nested") {
                        assert_eq!(*view, lower.root_identity());
                        original.push(RootLayer {
                            properties: leaf.props().unwrap(),
                            overrides: &[],
                        });
                    }
                }
                result_policy(view, &original)
            },
            |view, emitted| {
                assert_eq!(*view, upper.root_identity());
                emitted_calls.borrow_mut().push(
                    emitted
                        .iter()
                        .map(|layer| (copied(layer.properties), copied(layer.overrides)))
                        .collect::<Vec<_>>(),
                );
                result_policy(view, emitted)
            },
        )
        .unwrap();
    let materialized = prepared.materialize().unwrap();

    for path in [
        b"a/nested/x".as_slice(),
        b"a/nested/y",
        b"b/nested/x",
        b"b/nested/y",
    ] {
        assert_eq!(
            lookup(&materialized.tree, path, &materialized).unwrap(),
            overlay.lookup(path, &forest).unwrap()
        );
    }
    // Projected bindings use canonical map-key order, independent of the
    // construction order retained by the original lower root's property vector.
    let expected_leaf = tree_with_properties(
        &[(b"x", value(b"first")), (b"y", value(b"second"))],
        TreeUse::Ordinary,
        vec![STORE, DOMAIN, BASELINE],
    );
    let expected_middle = tree(
        &[
            (b"nested", graft(&expected_leaf)),
            (b"shared", value(b"upper")),
        ],
        TreeUse::Ordinary,
    );
    let expected = tree(
        &[
            (b"a", with_overrides(&expected_middle, &upper_overrides[0])),
            (b"b", with_overrides(&expected_middle, &upper_overrides[1])),
        ],
        TreeUse::Ordinary,
    );
    assert_eq!(materialized.tree.root_identity(), expected.root_identity());
    assert_eq!(materialized.grafts.len(), 4);
    for pair in materialized.grafts.as_chunks::<2>().0 {
        assert_eq!(pair[0].root_identity(), expected_leaf.root_identity());
        assert_eq!(pair[1].root_identity(), expected_middle.root_identity());
    }

    assert_eq!(
        source_calls.into_inner(),
        vec![
            (upper.root_identity(), b"".to_vec()),
            (upper.root_identity(), b"a".to_vec()),
            (lower.root_identity(), b"a".to_vec()),
            (lower.root_identity(), b"a/nested".to_vec()),
            (upper.root_identity(), b"b".to_vec()),
            (lower.root_identity(), b"b".to_vec()),
            (lower.root_identity(), b"b/nested".to_vec()),
        ]
    );
    let top_layer = (copied(upper.props().unwrap()), vec![]);
    let mut expected_calls = vec![vec![top_layer.clone()]];
    for overrides in &upper_overrides {
        let middle_layer = (copied(middle.props().unwrap()), copied(overrides));
        expected_calls.push(vec![top_layer.clone(), middle_layer.clone()]);
        expected_calls.push(vec![
            top_layer.clone(),
            middle_layer.clone(),
            (copied(leaf.props().unwrap()), vec![]),
        ]);
        expected_calls.push(vec![
            top_layer.clone(),
            middle_layer,
            (copied(expected_leaf.props().unwrap()), vec![]),
        ]);
    }
    assert_eq!(emitted_calls.into_inner(), expected_calls);
}

#[test]
fn overlay_inline_and_grafted_directories_merge_in_both_orders() {
    let target = tree(&[(b"x", value(b"grafted"))], TreeUse::Ordinary);
    let grafted = tree(&[(b"g", graft(&target))], TreeUse::OverlayLayer);
    let inline = tree(
        &[
            (b"g", entry(EntryKind::Directory { mode: 0o700 })),
            (b"g/y", value(b"inline")),
        ],
        TreeUse::OverlayLayer,
    );
    let forest = Forest(vec![target]);

    for layers in [[&grafted, &inline], [&inline, &grafted]] {
        let overlay = Overlay::new(&layers);
        let prepared = overlay
            .prepare_with_roots(&forest, None, compatible, result_policy)
            .unwrap();
        let materialized = prepared.materialize().unwrap();
        for path in [b"g/x".as_slice(), b"g/y"] {
            assert_eq!(
                lookup(&materialized.tree, path, &materialized).unwrap(),
                overlay.lookup(path, &forest).unwrap()
            );
        }
    }
}

#[test]
fn overlay_graft_policy_mismatch_refuses_materialization() {
    for property in [
        Property {
            name: "domain",
            value: b"\x6dprivate:other",
        },
        Property {
            name: "trust",
            value: b"\x66strict",
        },
    ] {
        let upper_target = tree(&[(b"x", value(b"upper"))], TreeUse::Ordinary);
        let lower_target = tree(&[(b"y", value(b"lower"))], TreeUse::Ordinary);
        let upper = tree(&[(b"g", graft(&upper_target))], TreeUse::OverlayLayer);
        let mut lower_graft = graft(&lower_target);
        if let EntryKind::Tree { props, .. } = &mut lower_graft.kind {
            *props = Some(vec![property]);
        }
        let lower = tree(&[(b"g", lower_graft)], TreeUse::OverlayLayer);
        let forest = Forest(vec![upper_target, lower_target]);
        let layers = [&upper, &lower];
        let upper_properties = [DOMAIN];
        let lower_properties = if property.name == "domain" {
            vec![property]
        } else {
            vec![DOMAIN, property]
        };
        let upper_effective = effective(&upper_properties);
        let lower_effective = effective(&lower_properties);

        let result = Overlay::new(&layers).prepare_with_roots(
            &forest,
            None,
            |source_view, source_path| {
                if *source_view == lower.root_identity() {
                    assert_eq!(source_path, b"g");
                    OverlayPolicy::from_effective(&lower_effective)
                } else {
                    assert_eq!(*source_view, upper.root_identity());
                    OverlayPolicy::from_effective(&upper_effective)
                }
            },
            result_policy,
        );
        assert!(matches!(result, Err(Error::Boundary)), "{}", property.name);
    }
}

#[test]
fn overlay_flat_preparation_retains_existing_tree_and_recipe_identity() {
    let upper = tree(&[(b"x", value(b"upper"))], TreeUse::OverlayLayer);
    let lower = tree(
        &[(b"x", value(b"lower")), (b"y", value(b"lower"))],
        TreeUse::OverlayLayer,
    );
    let layers = [&upper, &lower];
    let overlay = Overlay::new(&layers);
    let original = overlay.materialize_with_recipe().unwrap();
    let prepared = overlay
        .prepare_with_roots(&Forest(vec![]), None, compatible, result_policy)
        .unwrap();
    let materialized = prepared.materialize().unwrap();

    assert_eq!(
        materialized.tree.root_identity(),
        original.tree.root_identity()
    );
    assert_eq!(materialized.recipe, original.recipe);
    assert!(materialized.grafts.is_empty());
}

#[test]
fn overlay_missing_graft_target_fails_without_emitting_a_root() {
    let target = tree(&[(b"x", value(b"target"))], TreeUse::Ordinary);
    let layer = tree(&[(b"g", graft(&target))], TreeUse::OverlayLayer);
    let layers = [&layer];

    assert!(matches!(
        Overlay::new(&layers).prepare_with_roots(&Forest(vec![]), None, compatible, result_policy),
        Err(Error::MissingRoot)
    ));
}

#[test]
fn overlay_changed_graft_descriptor_discards_prior_introduction_reference() {
    let target = tree(&[(b"x", entry(EntryKind::Whiteout))], TreeUse::OverlayLayer);
    let mut descriptor = graft(&target);
    descriptor.provenance = Some([7; 32]);
    let layer = tree(&[(b"g", descriptor)], TreeUse::OverlayLayer);
    let layers = [&layer];
    let forest = Forest(vec![target]);
    let prepared = Overlay::new(&layers)
        .prepare_with_roots(&forest, None, compatible, result_policy)
        .unwrap();
    let materialized = prepared.materialize().unwrap();

    assert_eq!(materialized.tree.get(b"g").unwrap().provenance, None);
    assert_eq!(
        lookup(&materialized.tree, b"g/x", &materialized).unwrap(),
        None
    );
    assert!(materialized.grafts[0].iter().next().is_none());
}

#[test]
fn overlay_mismatched_graft_resolution_rejects_another_identity() {
    struct WrongRoot(Tree<'static>);

    impl Roots<'static> for WrongRoot {
        fn resolve(&self, _: &Digest) -> Option<&Tree<'static>> {
            Some(&self.0)
        }
    }

    let target = tree(&[(b"x", value(b"target"))], TreeUse::Ordinary);
    let layer = tree(&[(b"g", graft(&target))], TreeUse::OverlayLayer);
    let layers = [&layer];
    let resolver = WrongRoot(tree(&[(b"y", value(b"other"))], TreeUse::Ordinary));

    assert!(matches!(
        Overlay::new(&layers).prepare_with_roots(&resolver, None, compatible, result_policy),
        Err(Error::RootIdentity)
    ));
}

#[test]
fn overlay_excessive_nested_grafts_rejects_the_complete_input_graph() {
    let mut roots = vec![tree(&[(b"x", value(b"leaf"))], TreeUse::Ordinary)];
    for _ in 0..64 {
        let target = roots.last().unwrap();
        roots.push(tree(&[(b"g", graft(target))], TreeUse::Ordinary));
    }
    let layer = tree(
        &[(b"g", graft(roots.last().unwrap()))],
        TreeUse::OverlayLayer,
    );
    let layers = [&layer];
    let forest = Forest(roots);

    assert!(matches!(
        Overlay::new(&layers).prepare_with_roots(&forest, None, compatible, result_policy),
        Err(Error::Cycle)
    ));
}

#[test]
fn overlay_virtual_listing_orders_graft_children_and_punctuation_siblings() {
    let target = tree(&[(b"x", value(b"target"))], TreeUse::Ordinary);
    let layer = tree(
        &[
            (b"g", graft(&target)),
            (b"g!", graft(&target)),
            (b"g-", value(b"sibling")),
        ],
        TreeUse::OverlayLayer,
    );
    let layers = [&layer];
    let forest = Forest(vec![target]);
    let overlay = Overlay::new(&layers);
    let listed = overlay.entries_with_roots(&forest).unwrap();

    assert_eq!(
        listed
            .iter()
            .map(|item| item.key.as_slice())
            .collect::<Vec<_>>(),
        [b"g".as_slice(), b"g!", b"g!/x", b"g-", b"g/x"]
    );
    for item in &listed {
        assert_eq!(
            overlay.lookup(&item.key, &forest).unwrap(),
            Some(&item.entry)
        );
    }
    let prepared = overlay
        .prepare_with_roots(&forest, None, compatible, result_policy)
        .unwrap();
    let materialized = prepared.materialize().unwrap();
    for item in listed
        .iter()
        .filter(|item| !matches!(item.entry.kind, EntryKind::Tree { .. }))
    {
        assert_eq!(
            lookup(&materialized.tree, &item.key, &materialized).unwrap(),
            Some(&item.entry)
        );
    }
}

#[test]
fn overlay_virtual_range_crosses_nested_grafts_and_hides_whiteouts() {
    let upper_leaf = tree(
        &[(b"x", entry(EntryKind::Whiteout)), (b"z", value(b"upper"))],
        TreeUse::OverlayLayer,
    );
    let lower_leaf = tree(
        &[(b"x", value(b"hidden")), (b"y", value(b"lower"))],
        TreeUse::Ordinary,
    );
    let upper_middle = tree(&[(b"nested", graft(&upper_leaf))], TreeUse::Ordinary);
    let lower_middle = tree(&[(b"nested", graft(&lower_leaf))], TreeUse::Ordinary);
    let upper = tree(&[(b"g", graft(&upper_middle))], TreeUse::OverlayLayer);
    let lower = tree(&[(b"g", graft(&lower_middle))], TreeUse::OverlayLayer);
    let layers = [&upper, &lower];
    let forest = Forest(vec![upper_leaf, lower_leaf, upper_middle, lower_middle]);
    let overlay = Overlay::new(&layers);
    let listed = overlay
        .range_with_roots(b"g/nested/x", Some(b"g/nested/z"), &forest)
        .unwrap();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, b"g/nested/y");
    assert_eq!(listed[0].entry, value(b"lower"));
    let prepared = overlay
        .prepare_with_roots(&forest, None, compatible, result_policy)
        .unwrap();
    let materialized = prepared.materialize().unwrap();
    assert_eq!(
        lookup(&materialized.tree, &listed[0].key, &materialized).unwrap(),
        Some(&listed[0].entry)
    );
}

#[test]
fn overlay_virtual_range_does_not_resolve_disjoint_grafts() {
    let target = tree(&[(b"x", value(b"target"))], TreeUse::Ordinary);
    let unavailable = tree(&[(b"missing", value(b"unavailable"))], TreeUse::Ordinary);
    let layer = tree(
        &[(b"g", graft(&target)), (b"z", graft(&unavailable))],
        TreeUse::OverlayLayer,
    );
    let layers = [&layer];
    let forest = Forest(vec![target]);
    let overlay = Overlay::new(&layers);

    let listed = overlay
        .range_with_roots(b"g/x", Some(b"g0"), &forest)
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, b"g/x");
    assert!(
        overlay
            .range_with_roots(b"g0", Some(b"z"), &forest)
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        overlay.entries_with_roots(&forest),
        Err(Error::MissingRoot)
    ));
}

#[test]
fn overlay_virtual_ranges_match_independent_slices_at_every_endpoint() {
    let target = tree(
        &[(b"a", value(b"first")), (b"z", value(b"last"))],
        TreeUse::Ordinary,
    );
    let descriptor = graft(&target);
    let layer = tree(
        &[
            (b"g", descriptor.clone()),
            (b"g!", descriptor.clone()),
            (b"h", value(b"tail")),
        ],
        TreeUse::OverlayLayer,
    );
    let layers = [&layer];
    let forest = Forest(vec![target]);
    let overlay = Overlay::new(&layers);
    let all = [
        (b"g".as_slice(), descriptor.clone()),
        (b"g!", descriptor),
        (b"g!/a", value(b"first")),
        (b"g!/z", value(b"last")),
        (b"g/a", value(b"first")),
        (b"g/z", value(b"last")),
        (b"h", value(b"tail")),
    ]
    .into_iter()
    .map(|(key, entry)| LeafItem {
        key: key.to_vec(),
        entry,
    })
    .collect::<Vec<_>>();
    assert_eq!(overlay.entries_with_roots(&forest).unwrap(), all);
    let endpoints = [
        b"".as_slice(),
        b"g",
        b"g!",
        b"g!/a",
        b"g!/z",
        b"g/a",
        b"g/z",
        b"g0",
        b"h",
        b"i",
    ];

    for start in endpoints {
        for end in endpoints {
            let expected = all
                .iter()
                .filter(|item| item.key.as_slice() >= start && item.key.as_slice() < end)
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(
                overlay.range_with_roots(start, Some(end), &forest).unwrap(),
                expected,
                "range {:?}..{:?}",
                start,
                end
            );
        }
    }
}

#[test]
fn overlay_nondirectory_or_whiteout_parent_does_not_invent_subtree_hiding() {
    let target = tree(&[(b"x", value(b"child"))], TreeUse::Ordinary);
    let lower = tree(&[(b"g", graft(&target))], TreeUse::OverlayLayer);
    let forest = Forest(vec![target]);

    for parent in [value(b"nondirectory"), entry(EntryKind::Whiteout)] {
        let upper = tree(&[(b"g", parent)], TreeUse::OverlayLayer);
        let layers = [&upper, &lower];
        let overlay = Overlay::new(&layers);

        assert_eq!(
            overlay.lookup(b"g/x", &forest).unwrap(),
            Some(&value(b"child"))
        );
        let listed = overlay
            .range_with_roots(b"g/x", Some(b"g0"), &forest)
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].entry, value(b"child"));
        assert!(matches!(
            overlay.prepare_with_roots(&forest, None, compatible, result_policy),
            Err(Error::Build(terrane_format::tree_format::Error::Tree))
        ));
    }
}

#[test]
fn overlay_descriptor_only_range_does_not_require_its_target() {
    let target = tree(&[(b"x", value(b"child"))], TreeUse::Ordinary);
    let descriptor = graft(&target);
    let layer = tree(&[(b"g", descriptor.clone())], TreeUse::OverlayLayer);
    let layers = [&layer];

    let listed = Overlay::new(&layers)
        .range_with_roots(b"g", Some(b"g!"), &Forest(vec![]))
        .unwrap();
    assert_eq!(
        listed,
        vec![LeafItem {
            key: b"g".to_vec(),
            entry: descriptor
        }]
    );
}

#[test]
fn overlay_grafted_hardlinks_share_namespace_identity_across_layers() {
    let upper_target = tree(&[(b"a", linked(b"a"))], TreeUse::Ordinary);
    let lower_target = tree(
        &[(b"a", linked(b"a")), (b"b", linked(b"a"))],
        TreeUse::Ordinary,
    );
    let expected_child = lower_target.clone();
    let upper = tree(&[(b"g", graft(&upper_target))], TreeUse::OverlayLayer);
    let lower = tree(&[(b"g", graft(&lower_target))], TreeUse::OverlayLayer);
    let layers = [&upper, &lower];
    let forest = Forest(vec![upper_target, lower_target]);
    let prepared = Overlay::new(&layers)
        .prepare_with_roots(&forest, None, compatible, result_policy)
        .unwrap();
    let materialized = prepared.materialize().unwrap();

    assert_eq!(
        materialized.grafts[0].root_identity(),
        expected_child.root_identity()
    );
    assert_eq!(
        lookup(&materialized.tree, b"g/b", &materialized).unwrap(),
        Some(&linked(b"a"))
    );
}

#[test]
fn overlay_inline_and_grafted_hardlinks_preserve_aliases_when_projected() {
    let target = tree(
        &[(b"a", linked(b"a")), (b"b", linked(b"a"))],
        TreeUse::Ordinary,
    );
    let grafted = tree(&[(b"g", graft(&target))], TreeUse::OverlayLayer);
    let inline = tree(
        &[
            (b"g", entry(EntryKind::Directory { mode: 0o755 })),
            (b"g/a", linked(b"g/a")),
        ],
        TreeUse::OverlayLayer,
    );
    let forest = Forest(vec![target]);
    let expected_flat = tree(
        &[
            (b"g", entry(EntryKind::Directory { mode: 0o755 })),
            (b"g/a", linked(b"g/a")),
            (b"g/b", linked(b"g/a")),
        ],
        TreeUse::Ordinary,
    );

    for layers in [[&inline, &grafted], [&grafted, &inline]] {
        let prepared = Overlay::new(&layers)
            .prepare_with_roots(&forest, None, compatible, result_policy)
            .unwrap();
        let materialized = prepared.materialize().unwrap();
        if matches!(
            materialized.tree.get(b"g").unwrap().kind,
            EntryKind::Directory { .. }
        ) {
            assert_eq!(
                materialized.tree.root_identity(),
                expected_flat.root_identity()
            );
        } else {
            assert_eq!(
                lookup(&materialized.tree, b"g/b", &materialized).unwrap(),
                Some(&linked(b"a"))
            );
        }
    }
}

#[test]
fn overlay_bounded_range_resolves_one_of_many_sibling_grafts() {
    struct CountedForest {
        forest: Forest,
        reads: std::cell::Cell<usize>,
    }

    impl Roots<'static> for CountedForest {
        fn resolve(&self, identity: &Digest) -> Option<&Tree<'static>> {
            self.reads.set(self.reads.get() + 1);
            self.forest.resolve(identity)
        }
    }

    let target = tree(&[(b"x", value(b"child"))], TreeUse::Ordinary);
    let items = (0..64)
        .map(|index| LeafItem {
            key: format!("g{index:03}").into_bytes(),
            entry: graft(&target),
        })
        .collect();
    let layer = Tree::build(items, Some(vec![DOMAIN]), 4096, TreeUse::OverlayLayer).unwrap();
    let layers = [&layer];
    let roots = CountedForest {
        forest: Forest(vec![target]),
        reads: std::cell::Cell::new(0),
    };

    let listed = Overlay::new(&layers)
        .range_with_roots(b"g032/x", Some(b"g032/y"), &roots)
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, b"g032/x");
    assert_eq!(roots.reads.get(), 1);
}

#[test]
fn overlay_one_unchanged_graft_retains_both_root_identities() {
    for domain in [
        DOMAIN,
        Property {
            name: "domain",
            value: b"\x66public",
        },
    ] {
        let target =
            tree_with_properties(&[(b"x", value(b"child"))], TreeUse::Ordinary, vec![domain]);
        let layer = tree_with_properties(
            &[(b"g", graft(&target))],
            TreeUse::OverlayLayer,
            vec![domain],
        );
        let expected_target = target.root_identity();
        let policy = OverlayPolicy::from_effective(&effective(layer.props().unwrap())).unwrap();
        let layers = [&layer];
        let forest = Forest(vec![target]);
        let prepared = Overlay::new(&layers)
            .prepare_with_roots(&forest, None, |_, _| Ok(policy.clone()), result_policy)
            .unwrap();
        let materialized = prepared.materialize().unwrap();

        assert_eq!(materialized.tree.root_identity(), layer.root_identity());
        assert_eq!(materialized.grafts[0].root_identity(), expected_target);
    }
}

#[test]
fn overlay_lower_graft_preserves_inherited_trust_under_actual_output_parent() {
    const STRICT: Property<'static> = Property {
        name: "trust",
        value: b"\x66strict",
    };
    let target = tree(&[(b"x", value(b"child"))], TreeUse::Ordinary);
    let lower = tree_with_properties(
        &[(b"g", graft(&target))],
        TreeUse::OverlayLayer,
        vec![STRICT, DOMAIN],
    );
    let upper = tree(&[], TreeUse::OverlayLayer);
    let layers = [&upper, &lower];
    let forest = Forest(vec![target]);
    let expected_child = tree_with_properties(
        &[(b"x", value(b"child"))],
        TreeUse::Ordinary,
        vec![STRICT, DOMAIN],
    );
    let lower_policy = OverlayPolicy::from_effective(&effective(lower.props().unwrap())).unwrap();
    let prepared = Overlay::new(&layers)
        .prepare_with_roots(
            &forest,
            None,
            |view, path| {
                if *view == lower.root_identity() {
                    assert_eq!(path, b"g");
                    Ok(lower_policy.clone())
                } else {
                    assert_eq!(*view, upper.root_identity());
                    compatible(view, path)
                }
            },
            |view, emitted| {
                assert_eq!(*view, upper.root_identity());
                result_policy(view, emitted)
            },
        )
        .unwrap();
    let materialized = prepared.materialize().unwrap();

    assert_eq!(
        materialized.grafts[0].root_identity(),
        expected_child.root_identity()
    );
    let emitted = terrane_format::properties::resolve(
        &[
            RootLayer {
                properties: materialized.tree.props().unwrap(),
                overrides: &[],
            },
            RootLayer {
                properties: materialized.grafts[0].props().unwrap(),
                overrides: &[],
            },
        ],
        Defaults {
            store: "authority",
            private_domain: "private:fixture",
            home: "region",
        },
    )
    .unwrap();
    assert_eq!(
        emitted.get(PropertyName::Trust),
        Some(&terrane_format::properties::Value::Text("strict"))
    );
}

#[test]
fn overlay_lower_graft_override_retains_target_identity_without_snapshot() {
    const STRICT: Property<'static> = Property {
        name: "trust",
        value: b"\x66strict",
    };
    let target = tree(&[(b"x", value(b"child"))], TreeUse::Ordinary);
    let mut descriptor = graft(&target);
    if let EntryKind::Tree { props, .. } = &mut descriptor.kind {
        *props = Some(vec![STRICT]);
    }
    let lower = tree(&[(b"g", descriptor)], TreeUse::OverlayLayer);
    let upper = tree(&[], TreeUse::OverlayLayer);
    let expected_target = target.root_identity();
    let layers = [&upper, &lower];
    let forest = Forest(vec![target]);
    let strict_policy = OverlayPolicy::from_effective(&effective(&[DOMAIN, STRICT])).unwrap();
    let prepared = Overlay::new(&layers)
        .prepare_with_roots(
            &forest,
            None,
            |view, path| {
                if *view == lower.root_identity() {
                    assert_eq!(path, b"g");
                    Ok(strict_policy.clone())
                } else {
                    compatible(view, path)
                }
            },
            result_policy,
        )
        .unwrap();
    let materialized = prepared.materialize().unwrap();

    assert_eq!(materialized.grafts[0].root_identity(), expected_target);
}

#[test]
fn overlay_relocated_graft_cannot_remove_actual_parent_administrator() {
    const ADMIN: Property<'static> = Property {
        name: "acl",
        value: b"\x81\x82\x6aroot-admin\x10",
    };
    let target = tree(&[(b"x", value(b"child"))], TreeUse::Ordinary);
    let lower = tree(&[(b"g", graft(&target))], TreeUse::OverlayLayer);
    let upper = tree_with_properties(&[], TreeUse::OverlayLayer, vec![ADMIN, DOMAIN]);
    let top_policy = OverlayPolicy::from_effective(&effective(upper.props().unwrap())).unwrap();
    let layers = [&upper, &lower];
    let forest = Forest(vec![target]);

    let prepared = Overlay::new(&layers).prepare_with_roots(
        &forest,
        None,
        |view, path| {
            if *view == upper.root_identity() {
                Ok(top_policy.clone())
            } else {
                compatible(view, path)
            }
        },
        result_policy,
    );
    assert!(matches!(prepared, Err(Error::Boundary)));
}

#[test]
fn overlay_policy_acl_comparison_uses_registered_verb_implications() {
    for (left, right) in [
        (
            b"\x81\x82\x61p\x10".as_slice(),
            b"\x81\x82\x61p\x18\x1f".as_slice(),
        ),
        (
            b"\x82\x82\x61p\x01\x82\x61p\x04".as_slice(),
            b"\x81\x82\x61p\x05".as_slice(),
        ),
        (b"\x81\x82\x61p\x00".as_slice(), b"\x80".as_slice()),
    ] {
        let left_properties = [
            Property {
                name: "acl",
                value: left,
            },
            DOMAIN,
        ];
        let right_properties = [
            Property {
                name: "acl",
                value: right,
            },
            DOMAIN,
        ];
        let left = OverlayPolicy::from_effective(&effective(&left_properties)).unwrap();
        let right = OverlayPolicy::from_effective(&effective(&right_properties)).unwrap();

        assert_eq!(left, right);
    }
}
